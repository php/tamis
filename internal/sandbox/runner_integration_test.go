//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
	"github.com/alpha-omega-security/harness/egress"
	"github.com/alpha-omega-security/harness/modelproxy"
	"github.com/alpha-omega-security/harness/modelproxy/modelproxytest"
	"github.com/stretchr/testify/require"
)

func TestIsolatedNetworkReachesTheModelButNotOtherHostServices(t *testing.T) {
	image := os.Getenv("TAMIS_TEST_IMAGE")
	require.NotEmpty(t, image, "TAMIS_TEST_IMAGE is required")
	runtime, ok := container.DetectRuntime("")
	require.True(t, ok, "Docker is unavailable")
	model, modelPort := testServer(t, "model")
	secret, secretPort := testServer(t, "SECRET-PAYLOAD")
	t.Cleanup(func() { _ = model.Close() })
	t.Cleanup(func() { _ = secret.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	hostIP := container.ResolveHostGatewayIPv4(ctx, runtime, image, "")
	require.NotEmpty(t, hostIP, "resolving the real host gateway")
	h, err := harness.ByName("claude")
	require.NoError(t, err)
	reader := &Reader{backend: backends["claude"], harness: h, runtime: runtime, image: image, server: &modelproxy.Server{APIPort: modelPort}}
	env := []string{"MODEL_URL=http://" + egress.HostGatewayAlias + ":" + modelPort, "SECRET_URL=http://" + net.JoinHostPort(hostIP, secretPort), "PROXIED_SECRET_URL=http://" + egress.HostGatewayAlias + ":" + secretPort}
	scope, err := reader.runner(t.TempDir(), t.TempDir(), "proxy-token", allow, env).Open(ctx, &agent{Harness: h})
	require.NoError(t, err)
	t.Cleanup(func() { scope.Close(nil) })

	out, err := exec.CommandContext(ctx, runtime.Bin, "network", "ls", "--filter", "name=harness-hardened-"+strconv.Itoa(os.Getpid())+"-", "--format", "{{.Name}}").Output()
	require.NoError(t, err)
	networks := strings.Fields(string(out))
	require.Len(t, networks, 1)
	out, err = exec.CommandContext(ctx, runtime.Bin, "network", "inspect", "--format", `{{.Internal}} {{.EnableIPv6}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv6"}}`, "--", networks[0]).Output()
	require.NoError(t, err)
	require.Equal(t, "true false isolated isolated", strings.TrimSpace(string(out)))
	workspace := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(workspace, srcDir), 0o700))
	out, err = scope.RunCommand(ctx, harness.Job{Workspace: workspace, OutputFile: outputFile}, container.Command{Args: []string{"sh", "-c", `export http_proxy="$HTTP_PROXY" && test "$(curl -fsS --connect-timeout 5 "$MODEL_URL")" = model && ! curl -fsS --noproxy '*' --connect-timeout 2 "$SECRET_URL" && ! curl -fsS --connect-timeout 2 "$PROXIED_SECRET_URL" && ! curl -fsS --noproxy '*' --connect-timeout 2 'https://1.1.1.1' && ! curl -gfsS --noproxy '*' --connect-timeout 2 'https://[2606:4700:4700::1111]' && ! getent hosts example.com`}})
	require.NoError(t, err, "isolation probe: %s", strings.TrimSpace(string(out)))
}

func TestClaudeCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "claude", "claude-opus-5-5", ":claude")
}

func TestCodexCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex", "gpt-5.5", ":codex")
}

func TestCodexWithAnAccessTokenCanReachTheFilteredModelProxy(t *testing.T) {
	testAgentCanReachTheFilteredModelProxy(t, "codex-token", "gpt-6.1-sol", ":codex")
}

func testAgentCanReachTheFilteredModelProxy(t *testing.T, name, model, imageSuffix string) {
	t.Helper()
	image := os.Getenv("TAMIS_TEST_IMAGE")
	if !strings.HasSuffix(image, imageSuffix) {
		t.Skip("TAMIS_TEST_IMAGE must end in " + imageSuffix)
	}
	var calls atomic.Int32
	var first atomic.Value
	upstream, port := testServerHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if modelproxytest.CodexStartup(w, r) {
			return
		}
		if calls.Add(1) != 1 {
			http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"stop"}}`, http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		first.Store(string(body))
		if name == "claude" {
			modelproxytest.AnthropicToolUse(w, model, "tool_fixture", "Bash", `{"command":"printf fixture"}`)
			return
		}
		modelproxytest.ResponsesFunctionCall(w, model, "call_fixture", "exec_command", `{"cmd":"printf fixture"}`)
	})
	t.Cleanup(func() { _ = upstream.Close() })
	reader := testReader(t, name, model, image, port)
	_, readErr := reader.Read(t.Context(), Request{RepoPath: gitRepo(t), Prompt: "Answer", System: "System", Report: "Report", Schema: []byte(`{}`), Validate: func(json.RawMessage) error { return nil }})
	require.GreaterOrEqual(t, calls.Load(), int32(2), "the legitimate %s request was blocked before the model provider: %v", name, errors.Unwrap(readErr))
	if name != "claude" {
		require.Contains(t, first.Load(), `"effort":"medium"`, "Codex does not request medium reasoning")
	}
}

func TestReaderGetsOneCorrectionRound(t *testing.T) {
	image := os.Getenv("TAMIS_TEST_IMAGE")
	if !strings.HasSuffix(image, ":claude") {
		t.Skip("TAMIS_TEST_IMAGE must end in :claude")
	}
	t.Run("corrected", func(t *testing.T) {
		raw, seen, resumed, err := readWithCorrection(t, image, `{"ok":true}`)
		require.NoError(t, err)
		require.JSONEq(t, `{"ok":true}`, string(raw))
		require.Equal(t, []string{"not json", `{"ok":true}`}, seen)
		require.True(t, resumed, "the correction did not resume the first conversation")
	})
	t.Run("still invalid", func(t *testing.T) {
		_, seen, _, err := readWithCorrection(t, image, "still not json")
		require.ErrorIs(t, err, ErrNoReport)
		require.Equal(t, []string{"not json", "still not json"}, seen)
	})
}

// readWithCorrection runs Claude Code against a model that writes invalid JSON, then corrected once the
// prompt carries the validation error, and returns what the validator saw and whether the correction
// carried the first conversation.
func readWithCorrection(t *testing.T, image, corrected string) (json.RawMessage, []string, bool, error) {
	t.Helper()
	var resumed bool
	var calls atomic.Int32
	_, port := testServerHandler(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Messages []struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &request)
		var called bool
		for _, message := range slices.Backward(request.Messages) {
			if message.Role == "assistant" {
				called = bytes.Contains(message.Content, []byte(`"tool_use"`))
				break
			}
		}
		if called {
			modelproxytest.AnthropicText(w, "claude-opus-5-5", "Done.")
			return
		}
		output := "not json"
		if bytes.Contains(body, []byte("failed validation")) {
			output = corrected
			resumed = bytes.Contains(body, []byte(`"tool_use_id"`))
		}
		command, _ := json.Marshal(map[string]string{"command": "printf '%s' '" + output + "' > /work/" + outputFile})
		// A resumed conversation already holds the first run's tool call, so each call needs its own id.
		modelproxytest.AnthropicToolUse(w, "claude-opus-5-5", fmt.Sprintf("tool_fixture_%d", calls.Add(1)), "Bash", string(command))
	})
	reader := testReader(t, "claude", "claude-opus-5-5", image, port)

	var seen []string
	validate := func(raw json.RawMessage) error {
		seen = append(seen, string(raw))
		if !json.Valid(raw) {
			return errors.New("not JSON")
		}
		return nil
	}
	raw, err := reader.Read(t.Context(), Request{RepoPath: gitRepo(t), Prompt: "Answer", System: "System", Report: "Report", Schema: []byte(`{}`), Validate: validate})

	return raw, seen, resumed, err
}

func testReader(t *testing.T, name, model, image, port string) *Reader {
	t.Helper()
	original := backends[name]
	changed := original
	changed.provider.Upstream = "http://127.0.0.1:" + port
	if changed.provider.Upstreams != nil {
		changed.provider.Upstreams = map[string]string{}
		for prefix := range original.provider.Upstreams {
			changed.provider.Upstreams[prefix] = changed.provider.Upstream
		}
	}
	backends[name] = changed
	t.Cleanup(func() { backends[name] = original })

	reader, err := New(name, model, "test-key", image)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	return reader
}

func testServer(t *testing.T, response string) (*http.Server, string) {
	t.Helper()
	return testServerHandler(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, response) })
}

func testServerHandler(t *testing.T, handler http.HandlerFunc) (*http.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", ":0")
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()

	return server, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}
