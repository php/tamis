package sandbox

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicGitHubReadsIssuesAndPullRequestsWithoutCredentials(t *testing.T) {
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Cookie"))
		assert.Empty(t, r.Header.Get("X-Attacker"))
		assert.Equal(t, "application/vnd.github.diff", r.Header.Get("Accept"))
		if r.URL.Path == "/search/issues" {
			assert.Equal(t, "foo repo:php/tamis", r.URL.Query().Get("q"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "12")
		w.Header().Set("Link", "<http://"+r.Host+r.URL.Path+"?page=2>; rel=\"next\"")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	api, err := newGitHubAPI("php/tamis")
	require.NoError(t, err)
	api.upstream = upstream.URL
	for _, route := range []string{
		"/search/issues?q=foo",
		"/repos/php/tamis/issues?state=all&page=2&per_page=100",
		"/repos/php/tamis/issues/12",
		"/repos/php/tamis/issues/12/comments",
		"/repos/php/tamis/pulls/12",
		"/repos/php/tamis/pulls/12/files",
		"/repos/php/tamis/pulls/12/commits",
		"/repos/php/tamis/pulls/12/reviews",
		"/repos/php/tamis/commits/0123456",
	} {
		r := httptest.NewRequest(http.MethodGet, "/"+api.token+route, nil)
		r.Header.Set("Authorization", "Bearer attacker-token")
		r.Header.Set("Cookie", "secret=value")
		r.Header.Set("X-Attacker", "value")
		r.Header.Set("Accept", "application/vnd.github.diff")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code, route)
		assert.JSONEq(t, `{"ok":true}`, w.Body.String())
		assert.Equal(t, "12", w.Header().Get("X-RateLimit-Remaining"))
		assert.Contains(t, w.Header().Get("Link"), "</"+api.token+"/")
	}
	require.Len(t, calls, 9)
}

func TestPublicGitHubRefusesWritesAndOtherResources(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	api, err := newGitHubAPI("php/tamis")
	require.NoError(t, err)
	api.upstream = upstream.URL
	for _, tc := range []struct{ method, route, body string }{
		{http.MethodPost, "/repos/php/tamis/issues", `{}`},
		{http.MethodGet, "/repos/php/tamis/issues", `{}`},
		{http.MethodConnect, "/repos/php/tamis/issues", ""},
		{http.MethodGet, "/gists", ""},
		{http.MethodGet, "/issues/12", ""},
		{http.MethodGet, "/repos/attacker/repo/issues", ""},
		{http.MethodGet, "/repos/php/tamis/security-advisories", ""},
		{http.MethodGet, "/repos/php/tamis/contents/README.md", ""},
		{http.MethodGet, "/repos/php/tamis/../other/issues", ""},
		{http.MethodGet, "/repos/php/tamis/%69ssues", ""},
		{http.MethodGet, "/search/issues?access_token=attacker", ""},
		{http.MethodGet, "/search/issues?q=one&q=two", ""},
		{http.MethodGet, "/search/issues?q=" + strings.Repeat("x", 2001), ""},
	} {
		r := httptest.NewRequest(tc.method, "/"+api.token+tc.route, strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, tc.route)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/wrong-token/search/issues?q=foo", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, calls.Load())
	for _, repository := range []string{"", "php", "../repo", "php/..", "php/repo/extra", "php/repo?x=1"} {
		_, err := newGitHubAPI(repository)
		require.Error(t, err, repository)
	}
}

func TestPublicGitHubBoundsResponsesAndRefusesRedirects(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, strings.Repeat("x", maxGitHubResponse+1))
			return
		}
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer upstream.Close()
	api, err := newGitHubAPI("php/tamis")
	require.NoError(t, err)
	api.upstream = upstream.URL
	for _, page := range []string{"1", "2"} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+api.token+"/repos/php/tamis/issues?page="+page, nil))
		assert.Equal(t, http.StatusBadGateway, w.Code)
	}
	assert.Zero(t, followed.Load())
	for range cap(api.slots) {
		api.slots <- struct{}{}
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+api.token+"/search/issues?q="+url.QueryEscape("foo"), nil))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
