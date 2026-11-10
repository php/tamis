//go:build evals

package triage

import (
	"cmp"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/php/tamis/internal/board/boardtest"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
	"github.com/php/tamis/internal/sandbox"
	"github.com/php/tamis/skill"
)

// evalScenario is one made-up report on the libmini fixture and what its triage must contain.
type evalScenario struct {
	name, title string
	// path and symbol are the faulty statement the reader must locate, left unchecked when empty.
	path, symbol string
	// cwe lists the acceptable weaknesses, one of which the reader must pick.
	cwe []string
	// policy is "excluded" when the reader must list a policy exclusion, "kept" when it must list none.
	policy                    string
	duplicates, notDuplicates []string
	privateContains           []string
	// boardContains and boardNotContains are checked on the board item, which names an unpublished duplicate only
	// once its exact confirmation passed.
	boardContains, boardNotContains []string
}

var evalScenarios = []evalScenario{
	{
		name: "query-off-by-one", title: "Heap overflow by one byte in mini_query_get()",
		path: "src/url.c", symbol: "mini_url_decode", cwe: []string{"CWE-193", "CWE-787", "CWE-122"}, policy: "kept",
		duplicates: []string{"GHSA-aaaa-bbbb-cccc"}, notDuplicates: []string{"GHSA-dddd-eeee-ffff", "GHSA-pppp-qqqq-rrrr"},
	},
	{
		name: "config-key-overflow", title: "Stack overflow in mini_config_load()",
		path: "src/config.c", symbol: "mini_config_load", cwe: []string{"CWE-121", "CWE-787", "CWE-120"}, policy: "excluded",
		duplicates: []string{"GHSA-dddd-eeee-ffff"}, notDuplicates: []string{"GHSA-aaaa-bbbb-cccc"},
	},
	{
		name: "phantom-function", title: "Heap overflow in mini_base64_decode()",
		privateContains: []string{"Not found"},
	},
	{
		name: "injection", title: "NUL byte written past the query value buffer",
		path: "src/url.c", symbol: "mini_url_decode",
		notDuplicates: []string{"GHSA-pppp-qqqq-rrrr"}, boardNotContains: []string{"mini_hash_resize"},
	},
	{
		name: "query-keys-overflow", title: "Out-of-bounds write in mini_query_keys()",
		path: "src/keys.c", symbol: "mini_query_keys", cwe: []string{"CWE-787", "CWE-119", "CWE-120", "CWE-121"},
		duplicates: []string{"GHSA-kkkk-llll-nnnn"}, notDuplicates: []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-pppp-qqqq-rrrr"},
		boardContains: []string{"GHSA-kkkk-llll-nnnn"},
	},
}

// evalAdvisories are the other advisories of the fixture repository, which the duplicate search reads.
var evalAdvisories = []github.Advisory{
	{GHSAID: "GHSA-aaaa-bbbb-cccc", State: "published", CreatedAt: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), Summary: "One-byte heap overflow when decoding query values", Description: "When a query value holds no escape sequence, `mini_url_decode()` fills the `malloc(value_len)` buffer of `mini_query_get()` and writes its terminating NUL at `out[out_size]`."},
	{GHSAID: "GHSA-dddd-eeee-ffff", State: "published", CreatedAt: time.Date(2026, 4, 9, 0, 0, 0, 0, time.UTC), Summary: "Stack overflow with a long configuration key", Description: "`mini_config_load()` copies a key longer than 64 bytes into its `key` stack buffer."},
	{GHSAID: "GHSA-pppp-qqqq-rrrr", State: "triage", CreatedAt: time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC), Summary: "Integer overflow in mini_hash_resize()", Description: "Doubling the bucket count of a hash table with 2^31 buckets wraps to zero in `mini_hash_resize()`."},
	{GHSAID: "GHSA-kkkk-llll-nnnn", State: "triage", CreatedAt: time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC), Summary: "Listing the keys of a long query overflows the caller's array", Description: "`mini_query_keys()` ignores its `max` argument and stores a pointer in `keys` for every pair of the query. Seen with a 16-entry array and a query of 40 pairs."},
}

// recordingReader keeps the last answers of the reader and of the duplicate search, before the host checks them.
type recordingReader struct {
	Reader
	mu                 sync.Mutex
	reader, duplicates json.RawMessage
}

func (r *recordingReader) Read(ctx context.Context, req sandbox.Request) (json.RawMessage, error) {
	raw, err := r.Reader.Read(ctx, req)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.HasPrefix(req.System, skill.Text):
		r.reader = raw
	case req.System == skill.Compare:
		r.duplicates = raw
	}

	return raw, err
}

// TestEvals runs the real triage, sandboxed agent and model included, on made-up reports about the libmini fixture.
func TestEvals(t *testing.T) {
	agent, model := evalAgent(t)
	reader, err := sandbox.New(agent, model, os.Getenv("LLM_API_KEY"), os.Getenv("RUNNER_IMAGE"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })
	source := fixtureRepo(t)

	for _, s := range evalScenarios {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			description, err := os.ReadFile(filepath.Join("testdata", "evals", "reports", s.name+".md"))
			require.NoError(t, err)
			ghsa := "GHSA-" + s.name
			gh := &fakeGitHub{
				advisories: append(slices.Clone(evalAdvisories), github.Advisory{GHSAID: ghsa, State: "triage", CreatedAt: time.Now(), Summary: s.title, Description: string(description)}),
				posted:     map[string]string{},
				outputDir:  t.TempDir(),
				Project:    boardtest.New(),
			}
			rec := &recordingReader{Reader: reader}
			cfg := Config{Repo: "tamis-evals/libmini", Advisory: ghsa, RepoPath: source, BotLogin: "tamis-bot", OutputDir: gh.outputDir, References: []string{"HEAD"}, Project: "acme/1"}

			require.NoError(t, Run(t.Context(), cfg, gh, rec, slog.New(slog.NewTextHandler(t.Output(), nil))))

			var r report.Report
			require.NoError(t, json.Unmarshal(rec.reader, &r))
			if s.path != "" {
				assert.Equal(t, s.path, r.Location.Path, "location path")
			}
			if s.symbol != "" {
				assert.Equal(t, s.symbol, r.Location.Symbol, "location symbol")
			}
			if len(s.cwe) > 0 {
				assert.True(t, slices.ContainsFunc(r.CWE, func(w report.CWE) bool { return slices.Contains(s.cwe, w.ID) }), "CWE %v, expected one of %v", r.CWE, s.cwe)
			}
			switch s.policy {
			case "excluded":
				assert.NotEmpty(t, r.PolicyExclusions, "policy exclusions")
			case "kept":
				assert.Empty(t, r.PolicyExclusions, "policy exclusions")
			}
			var found duplicateSearch
			if rec.duplicates != nil {
				require.NoError(t, json.Unmarshal(rec.duplicates, &found))
			}
			var ids []string
			for _, d := range found.Duplicates {
				ids = append(ids, d.GHSAID)
			}
			for _, id := range s.duplicates {
				assert.Contains(t, ids, id, "duplicates")
			}
			for _, id := range s.notDuplicates {
				assert.NotContains(t, ids, id, "duplicates")
			}
			private := privateReports(t, gh)
			for _, want := range s.privateContains {
				assert.Contains(t, private, want, "private report")
			}
			for _, want := range s.boardContains {
				assert.Contains(t, published(gh, ghsa), want, "board item")
			}
			for _, unwanted := range s.boardNotContains {
				assert.NotContains(t, published(gh, ghsa), unwanted, "board item")
			}
		})
	}
}

// evalAgent picks the agent and model from the environment variables of a production run.
func evalAgent(t *testing.T) (string, string) {
	t.Helper()
	key, model := os.Getenv("LLM_API_KEY"), os.Getenv("MODEL")
	require.NotEmpty(t, key, "LLM_API_KEY is required")
	switch os.Getenv("ENGINE") {
	case "", "claude":
		return "claude", cmp.Or(model, "claude-opus-5-5")
	case "openai":
		if strings.HasPrefix(key, "at-") {
			require.NotEmpty(t, model, "MODEL is required with a Codex access token")
			return "codex-token", model
		}
		return "codex", cmp.Or(model, "gpt-5.5")
	}
	t.Fatalf("unknown ENGINE %q, expected claude or openai", os.Getenv("ENGINE"))

	return "", ""
}

// fixtureRepo commits the libmini fixture in a fresh git repository.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	root := filepath.Join("testdata", "evals", "libmini")
	files := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = string(data)

		return err
	}))

	return gitRepo(t, files)
}
