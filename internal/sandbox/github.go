package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alpha-omega-security/harness/egress"
)

const maxGitHubResponse = 16 << 20

var (
	publicRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	publicRepoRoute  = regexp.MustCompile(`^/(issues(/[1-9][0-9]*(/(comments|events|timeline))?)?|pulls(/[1-9][0-9]*(/(comments|commits|files|reviews))?)?|commits(/[0-9a-fA-F]{7,40})?)$`)
)

type githubAPI struct {
	repository, token, upstream string
	client                      *http.Client
	slots                       chan struct{}
}

func newGitHubAPI(repository string) (*githubAPI, error) {
	if !publicRepository.MatchString(repository) || path.Clean(repository) != repository || strings.HasPrefix(repository, ".") {
		return nil, errors.New("a source repository is required for public GitHub access")
	}
	return &githubAPI{
		repository: repository,
		token:      rand.Text(),
		upstream:   "https://api.github.com",
		client:     &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		slots:      make(chan struct{}, 4),
	}, nil
}

// The agent gets a capability for public reads, never GitHub credentials or a
// general-purpose HTTPS tunnel. Each reader run has its own server and lifetime.
func serveGitHub(ctx context.Context, repository string) (base, port string, close func(), err error) {
	api, err := newGitHubAPI(repository)
	if err != nil {
		return "", "", nil, err
	}
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", "", nil, err
	}
	server := &http.Server{Handler: api, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	go func() { _ = server.Serve(l) }()
	port = strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	return "http://" + net.JoinHostPort(egress.HostGatewayAlias, port) + "/" + api.token, port, func() { _ = server.Close() }, nil
}

func (a *githubAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := strings.CutPrefix(r.URL.Path, "/"+a.token)
	if !ok || r.Method != http.MethodGet || r.ContentLength != 0 || r.URL.RawPath != "" || len(r.URL.RequestURI()) > 8192 || path.Clean(route) != route {
		http.Error(w, "public GitHub request not permitted", http.StatusForbidden)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !a.allowed(route, query) {
		http.Error(w, "public GitHub request not permitted", http.StatusForbidden)
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		http.Error(w, "too many public GitHub requests", http.StatusTooManyRequests)
		return
	}
	if route == "/search/issues" {
		query.Set("q", query.Get("q")+" repo:"+a.repository)
	}
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.upstream+route+"?"+query.Encode(), nil)
	if err != nil {
		http.Error(w, "invalid public GitHub request", http.StatusBadRequest)
		return
	}
	accept := r.Header.Get("Accept")
	if !slices.Contains([]string{"application/vnd.github.diff", "application/vnd.github.patch"}, accept) {
		accept = "application/vnd.github+json"
	}
	upstream.Header.Set("Accept", accept)
	upstream.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := a.client.Do(upstream)
	if err != nil {
		http.Error(w, "public GitHub request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubResponse+1))
	if err != nil || len(body) > maxGitHubResponse || resp.StatusCode >= 300 && resp.StatusCode < 400 {
		http.Error(w, "invalid public GitHub response", http.StatusBadGateway)
		return
	}
	for _, header := range []string{"Content-Type", "Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if value := resp.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	if links := resp.Header.Get("Link"); links != "" {
		w.Header().Set("Link", strings.ReplaceAll(links, a.upstream, "/"+a.token))
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (a *githubAPI) allowed(route string, query url.Values) bool {
	if route != "/search/issues" {
		suffix, ok := strings.CutPrefix(route, "/repos/"+a.repository)
		if !ok || !publicRepoRoute.MatchString(suffix) {
			return false
		}
	}
	for key, values := range query {
		if len(values) != 1 || len(values[0]) > 2000 || !slices.Contains([]string{"page", "per_page", "sort", "order", "direction", "state", "since", "sha", "path", "base", "head"}, key) && !(route == "/search/issues" && key == "q") {
			return false
		}
	}
	return true
}
