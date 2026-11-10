package triage

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/php/tamis/internal/board"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/repo"
	"github.com/php/tamis/internal/report"
	"github.com/php/tamis/internal/sandbox"
)

func advisoryRevision(a github.Advisory, comments []github.Comment, login string, references []string) string {
	input := struct {
		Advisory   github.Advisory
		Comments   []github.Comment
		References []string
	}{Advisory: a, References: references}
	for _, c := range comments {
		if !strings.EqualFold(c.User.Login, login) {
			input.Comments = append(input.Comments, c)
		}
	}
	slices.SortFunc(input.Comments, func(a, b github.Comment) int { return cmp.Compare(a.ID, b.ID) })
	data, _ := json.Marshal(input)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func triageRevisions(ctx context.Context, cfg Config, gh GitHub, reader Reader, b *board.Board, a github.Advisory, all []github.Advisory, comments []github.Comment, login, revision string, final bool, sourceDir string, log *slog.Logger) (bool, error) {
	var comparisonErr error
	var others []github.Advisory
	byID := map[string]github.Advisory{}
	for _, other := range all {
		if other.GHSAID == a.GHSAID {
			continue
		}
		byID[other.GHSAID] = other
		others = append(others, other)
	}
	input := a
	for _, c := range comments {
		if !strings.EqualFold(c.User.Login, login) {
			input.Description += "\n\nAdditional report comment:\n" + c.Body
		}
	}
	reference := cfg.References[0]
	path := filepath.Join(sourceDir, "analysed")
	if _, err := os.Stat(path); err != nil {
		log.Info("copying the analysed source", "source", reference)
		start := time.Now()
		if err := sandbox.SnapshotSource(ctx, cfg.RepoPath, path, reference); err != nil {
			_ = os.RemoveAll(path)
			return false, err
		}
		log.Info("source ready", "source", reference, "duration", time.Since(start).Round(time.Second))
	}
	code := repo.Repo{Dir: path, Context: ctx}
	commit, err := code.Commit()
	if err != nil {
		return false, err
	}
	sources := fmt.Sprintf("Source: `%s` at `%s`.\n", reference, commit)
	for _, ref := range cfg.References[1:] {
		out, err := exec.CommandContext(ctx, "git", "-C", cfg.RepoPath, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}").Output()
		if err != nil {
			return false, errors.New("resolving a configured source reference")
		}
		sources += fmt.Sprintf("Source: `%s` at `%s`.\n", ref, strings.TrimSpace(string(out)))
	}
	local := cfg
	local.RepoPath = path
	r, err := triage(ctx, local, gh, reader, input, log)
	if err != nil {
		return false, err
	}
	r.Branch, r.CreatedAt = reference, a.CreatedAt
	r.Located = verifiedClues(code, r).Location.Path != ""
	// Bundled code is named from the faulty statement, so an unlocated one names nothing.
	if !r.Located {
		r.Upstream = ""
	}
	var privateNote string
	if r.Incomplete == nil {
		// A failed duplicate search leaves the duplicates out of the triage rather than blocking it.
		duplicates, err := findDuplicates(ctx, path, reader, r, input, others, log)
		if err != nil {
			comparisonErr = err
			r.DuplicateSearchFailed = true
		} else {
			matches := report.Report{Duplicates: duplicates}
			if err := (report.Checker{Advisories: byID}).Verify(ctx, &matches); err != nil {
				return false, err
			}
			if err := confirmPrivateDuplicates(ctx, path, reader, r, input, matches.Duplicates, byID, log); err != nil {
				comparisonErr = errors.Join(comparisonErr, err)
				privateNote += "\nPrivate exact duplicate confirmation could not complete.\n"
			}
			r.Duplicates = matches.Duplicates
		}
	}
	r.Provenance = fmt.Sprintf("\nRepository: `%s`. Advisory: `%s`. Input revision: `%s`.\n%s", cfg.Repo, a.GHSAID, revision, sources)
	body := report.Render(r)
	private := privateNote + report.RenderPrivate(r)
	current, err := gh.GetAdvisory(ctx, cfg.Repo, a.GHSAID)
	if err != nil {
		return false, err
	}
	latestComments, err := gh.ListComments(ctx, cfg.Repo, a.GHSAID)
	if err != nil {
		return false, err
	}
	if advisoryRevision(current, latestComments, login, cfg.References) != revision {
		return false, errors.New("the report changed during triage")
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return false, err
	}
	base := reportBase(cfg, a.GHSAID, revision)
	if keepAgentError(cfg, a.GHSAID, revision, r.Incomplete) != nil {
		log.Error("the agent error could not be kept in the private reports")
	}
	// The report is kept before a board write that may fail.
	if err := os.WriteFile(base+".md", []byte(private), 0o600); err != nil {
		return false, err
	}
	// A published report ends the attempts, so a partial one is only published by the last attempt.
	if r.Incomplete != nil && !final {
		log.Info("the report is incomplete, the advisory will be retried")
		return false, errIncompleteReport
	}
	// The board is where the triage is published, so a failed write gives the item the failed status instead.
	t := board.TriageOf(r)
	if err := b.Put(ctx, a, t.Priority(), &t, body); err != nil {
		return false, err
	}

	return true, comparisonErr
}

// reportBase names the private files of one advisory revision, without the GHSA identifier.
func reportBase(cfg Config, ghsa, revision string) string {
	name := sha256.Sum256([]byte(ghsa))

	return filepath.Join(cfg.OutputDir, hex.EncodeToString(name[:])+"-"+revision)
}
