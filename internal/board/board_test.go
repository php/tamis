package board

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/php/tamis/internal/board/boardtest"
	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
)

var reported = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func TestOpenRequiresTheDocumentedFields(t *testing.T) {
	for name, tc := range map[string]struct {
		project string
		change  func(*boardtest.Project)
		err     string
	}{
		"complete":       {"php/16", func(*boardtest.Project) {}, ""},
		"no number":      {"php", func(*boardtest.Project) {}, `the project must be given as "org/number"`},
		"no org":         {"/16", func(*boardtest.Project) {}, `the project must be given as "org/number"`},
		"missing field":  {"php/16", func(p *boardtest.Project) { p.Fields[1].Name = "Advisory" }, `the project has no text field "GHSA"`},
		"wrong type":     {"php/16", func(p *boardtest.Project) { p.Fields[3].DataType = "text" }, `the project has no number field "Duplicates"`},
		"missing option": {"php/16", func(p *boardtest.Project) { p.Fields[5].Options = p.Fields[5].Options[1:] }, `the "Priority" field has no "To triage" option`},
		"public":         {"php/16", func(p *boardtest.Project) { p.Public = true }, "the project must be private"},
		"unread GHSA":    {"php/16", func(p *boardtest.Project) { p.Add(map[string]any{"GHSA": 5}) }, "the project item 1 has a value in an unexpected format"},
		"unread count":   {"php/16", func(p *boardtest.Project) { p.Add(map[string]any{"GHSA": "GHSA-old", "Duplicates": "two"}) }, "the project item 1 has a value in an unexpected format"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			tc.change(p)
			_, err := Open(t.Context(), p, p, tc.project, "", "php/php-src")
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestTriageOf(t *testing.T) {
	older := report.Duplicate{GHSAID: "GHSA-old", Confidence: "high", Exact: true, Confirmed: true, State: "triage", CreatedAt: reported.Add(-time.Hour)}
	for name, tc := range map[string]struct {
		r           report.Report
		priority    string
		duplicateOf string
	}{
		"severe":           {report.Report{Severity: "high", Located: true}, ToTriage, ""},
		"low":              {report.Report{Severity: "low", Located: true}, ToTriage, ""},
		"not located":      {report.Report{Severity: "high", CodeReferences: []report.CodeReference{{Found: true}}}, ToTriage, ""},
		"policy exclusion": {report.Report{Severity: "critical", Located: true, PolicyExclusions: []report.PolicyPoint{{Point: "p"}}}, ToTriage, ""},
		"open duplicate":   {report.Report{Severity: "critical", Duplicates: []report.Duplicate{older}}, Duplicate, "GHSA-old"},
		"settled duplicate": {report.Report{Duplicates: []report.Duplicate{func() report.Duplicate {
			d := older
			d.State, d.Published, d.Confirmed = "published", true, false
			return d
		}()}}, Duplicate, "GHSA-old"},
		"oldest wins": {report.Report{Duplicates: []report.Duplicate{
			func() report.Duplicate {
				d := older
				d.GHSAID = "GHSA-mid"
				d.CreatedAt = reported.Add(-time.Minute)
				return d
			}(),
			older,
		}}, Duplicate, "GHSA-old"},
		"newer duplicate":     {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.CreatedAt = reported.Add(time.Hour); return d }()}}, ToTriage, ""},
		"unconfirmed":         {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Confirmed = false; return d }()}}, ToTriage, ""},
		"not exact":           {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Exact = false; return d }()}}, ToTriage, ""},
		"not high confidence": {report.Report{Severity: "high", Located: true, Duplicates: []report.Duplicate{func() report.Duplicate { d := older; d.Confidence = "medium"; return d }()}}, ToTriage, ""},
	} {
		t.Run(name, func(t *testing.T) {
			tc.r.CreatedAt = reported
			triage := TriageOf(tc.r)
			require.Equal(t, tc.priority, triage.Priority())
			require.Equal(t, tc.duplicateOf, triage.DuplicateOf)
		})
	}
	require.True(t, TriageOf(report.Report{PolicyExclusions: []report.PolicyPoint{{Point: "p"}}}).Excluded, "a policy exclusion was dropped")
	require.False(t, TriageOf(report.Report{}).Excluded)
}

func TestPutCreatesOneItemPerAdvisory(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow in foo", HTMLURL: "https://x/GHSA-new", State: "triage", CreatedAt: reported}

	require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Excluded: true}, "first comment"))
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "critical", Located: true, Component: "ext/foo", Upstream: "lexbor"}, "second comment"))

	require.Len(t, p.Items, 1, "a second put created another item")
	id := p.Find("GHSA-new")
	require.Equal(t, "Overflow in foo", p.Titles[id])
	require.Equal(t, "https://x/GHSA-new\n\nsecond comment", p.Bodies[id], "the draft body misses the latest comment")
	require.Equal(t, map[string]string{"GHSA": "GHSA-new", "Reported": "2026-10-20", "State": "triage", "Priority": ToTriage, "Severity": "Critical", "Duplicate of": "", "Duplicates": "", "Policy exclusion": "No", "Located": "Yes", "Component": "ext/foo", "Upstream": "lexbor", "Original report": ""}, values(p, id))
}

func TestPutFindsTheItemOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new", "Priority": ToTriage})
	p.Add(map[string]any{"Priority": ToTriage})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "ghsa-NEW", State: "draft"}, ToTriage, &Triage{}, ""))

	require.Len(t, p.Items, 2, "the item of a previous run was not reused")
	require.Equal(t, ToTriage, p.Value(id, "Priority"))
	require.Equal(t, "draft", p.Value(id, "State"))
	require.Empty(t, p.Value(id, "Severity"), "an unknown severity was not cleared")
}

func TestPutReportsAFailedWrite(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	p.Err = errors.New("HTTP 403")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, ToTriage, &Triage{Severity: "high"}, ""))
	require.Empty(t, p.Items)
}

func TestSyncMirrorsStatesAndDuplicates(t *testing.T) {
	p := boardtest.New()
	old := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Priority": ToTriage})
	dup := p.Add(map[string]any{"GHSA": "GHSA-dup", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	other := p.Add(map[string]any{"GHSA": "GHSA-other", "State": "triage", "Priority": Duplicate, "Duplicate of": "GHSA-old"})
	gone := p.Add(map[string]any{"GHSA": "GHSA-gone", "State": "triage", "Priority": ToTriage})
	manual := p.Add(map[string]any{"Priority": ToTriage})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))

	require.Equal(t, map[string]string{"GHSA": "GHSA-old", "State": "published", "Priority": ToTriage, "Duplicates": "2", "Reported": "", "Severity": "", "Duplicate of": "", "Policy exclusion": "", "Located": "", "Component": "", "Upstream": "", "Original report": "GHSA-old"}, values(p, old))
	require.Equal(t, Duplicate, p.Value(dup, "Priority"), "the duplicate of a settled report changed priority")
	require.Equal(t, "closed", p.Value(other, "State"))
	require.Equal(t, "triage", p.Value(gone, "State"), "an advisory missing from the list changed state")
	require.Equal(t, ToTriage, p.Value(manual, "Priority"), "an item added by hand was touched")

	writes := p.Writes
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "published"}, {GHSAID: "GHSA-dup", State: "triage"}, {GHSAID: "GHSA-other", State: "closed"}}))
	require.Equal(t, writes, p.Writes, "an unchanged board was written again")
}

func TestSyncReportsFailedWrites(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	p.Err = errors.New("HTTP 403")

	require.Error(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "closed"}}))
}

func values(p *boardtest.Project, id int64) map[string]string {
	v := map[string]string{}
	for _, f := range []string{"GHSA", "Reported", "State", "Priority", "Severity", "Duplicate of", "Duplicates", "Policy exclusion", "Located", "Component", "Upstream", "Original report"} {
		v[f] = p.Value(id, f)
	}

	return v
}

func TestOpenReportsAFailedRead(t *testing.T) {
	p := boardtest.New()
	p.ListErr = errors.New("HTTP 403")

	_, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")

	require.ErrorIs(t, err, p.ListErr)
}

func TestPutReusesTheDraftWhoseFieldsFailed(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}
	p.UpdateErr = errors.New("HTTP 502")

	require.Error(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "high"}, ""))
	p.UpdateErr = nil
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "high"}, ""))

	require.Len(t, p.Items, 1, "a failed field update left a second draft")
}

func TestSyncReadsBackTheCountsOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2, "Original report": "GHSA-old"})
	p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Duplicate of": "GHSA-old", "Original report": "GHSA-old"})
	p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Duplicate of": "ghsa-OLD", "Original report": "GHSA-old"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}, {GHSAID: "GHSA-a", State: "triage"}, {GHSAID: "GHSA-b", State: "triage"}}))

	require.Zero(t, p.Writes, "an unchanged count was written again")
}

func TestSyncClearsTheCountOfAReportWithoutDuplicates(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-old", "State": "triage", "Duplicates": 2})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-old", State: "triage"}}))

	require.Equal(t, "0", p.Value(id, "Duplicates"))
}

func TestPutKeepsTheDraftBodyWithoutAComment(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", HTMLURL: "https://x/GHSA-new"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, ""))
	id := p.Find("GHSA-new")
	require.Equal(t, "https://x/GHSA-new", p.Bodies[id])
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "high"}, "the comment"))
	require.NoError(t, b.Put(t.Context(), a, AnalysisFailed, nil, ""))

	require.Equal(t, "https://x/GHSA-new\n\nthe comment", p.Bodies[id], "a put without comment erased the body")
}

func TestPutUpdatesTheDraftOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-new"})
	p.Bodies[id] = "https://x/GHSA-new"
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", HTMLURL: "https://x/GHSA-new"}, ToTriage, &Triage{Severity: "high"}, "the comment"))

	require.Equal(t, "https://x/GHSA-new\n\nthe comment", p.Bodies[id])
}

func TestPutReportsAFailedDraftUpdate(t *testing.T) {
	p := boardtest.New()
	p.Add(map[string]any{"GHSA": "GHSA-new"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	p.Err = errors.New("github: GraphQL request failed")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new"}, ToTriage, &Triage{Severity: "high"}, "the comment"))
}

func TestPutClearsTheTriageOfAStatus(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "high", DuplicateOf: "GHSA-old", Located: true, Component: "ext/foo", Upstream: "lexbor"}, ""))
	require.NoError(t, b.Put(t.Context(), a, AnalysisFailed, nil, "note"))

	id := p.Find("GHSA-new")
	for _, f := range []string{"Severity", "Duplicate of", "Policy exclusion", "Located", "Component", "Upstream"} {
		require.Empty(t, p.Value(id, f), "%s outlived the triage", f)
	}
}

func TestSyncMovesAPriorityOfAnOlderLayout(t *testing.T) {
	p := boardtest.New()
	old := p.Fields[5].Options[0]
	old.ID, old.Name.Raw = "opt-Look first", "Look first"
	p.Fields[5].Options = append(p.Fields[5].Options, old)
	ranked := p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Priority": "Look first", "Severity": "Critical", "Policy exclusion": "No", "Located": "Yes"})
	unranked := p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Priority": "Look first"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), nil))

	require.Equal(t, ToTriage, p.Value(ranked, "Priority"))
	require.Equal(t, "Look first", p.Value(unranked, "Priority"), "an item without a triage was ranked")
}

func TestSyncRanksEveryTriageAgain(t *testing.T) {
	p := boardtest.New()
	stale := p.Add(map[string]any{"GHSA": "GHSA-a", "State": "triage", "Priority": Duplicate, "Severity": "Critical", "Policy exclusion": "No", "Located": "Yes"})
	dup := p.Add(map[string]any{"GHSA": "GHSA-b", "State": "triage", "Priority": ToTriage, "Severity": "High", "Policy exclusion": "No", "Located": "Yes", "Duplicate of": "GHSA-a"})
	excluded := p.Add(map[string]any{"GHSA": "GHSA-c", "State": "triage", "Priority": Duplicate, "Severity": "Low", "Policy exclusion": "Yes", "Located": "No"})
	status := p.Add(map[string]any{"GHSA": "GHSA-d", "State": "triage", "Priority": AnalysisFailed})
	older := p.Add(map[string]any{"GHSA": "GHSA-e", "State": "triage", "Priority": Duplicate, "Severity": "Low"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), nil))

	require.Equal(t, ToTriage, p.Value(stale, "Priority"), "a triage ranked by an older rule kept its priority")
	require.Equal(t, Duplicate, p.Value(dup, "Priority"))
	require.Equal(t, ToTriage, p.Value(excluded, "Priority"), "severity, exclusion or location split the reports")
	require.Equal(t, AnalysisFailed, p.Value(status, "Priority"), "a status was ranked as a triage")
	require.Equal(t, Duplicate, p.Value(older, "Priority"), "an item without a triage was ranked")

	writes := p.Writes
	require.NoError(t, b.Sync(t.Context(), nil))
	require.Equal(t, writes, p.Writes, "a ranked board was written again")
}

func TestTriageOfNamesTheComponentOfTheFaultyStatement(t *testing.T) {
	for file, want := range map[string]string{
		"ext/pgsql/pgsql.c":       "ext/pgsql",
		"sapi/fpm/fpm/fpm_main.c": "sapi/fpm",
		"Zend/zend_execute.c":     "Zend",
		"main/streams/streams.c":  "main/streams",
		"main.c":                  "",
	} {
		require.Equal(t, want, TriageOf(report.Report{Location: report.Location{Path: file}, Located: true}).Component, file)
	}
	require.Empty(t, TriageOf(report.Report{Location: report.Location{Path: "ext/pgsql/pgsql.c"}}).Component, "an unlocated statement got a component")
	require.Equal(t, "sapi/fpm", TriageOf(report.Report{Component: "sapi/fpm", Location: report.Location{Path: "main/fastcgi.c"}, Located: true}).Component, "the component the model named lost to the path")
	require.Equal(t, "lexbor", TriageOf(report.Report{Upstream: "lexbor"}).Upstream)
}

func TestSyncGroupsEveryReportUnderItsOldest(t *testing.T) {
	p := boardtest.New()
	root := p.Add(map[string]any{"GHSA": "GHSA-root", "State": "triage"})
	mid := p.Add(map[string]any{"GHSA": "GHSA-mid", "State": "triage", "Duplicate of": "GHSA-root"})
	leaf := p.Add(map[string]any{"GHSA": "GHSA-leaf", "State": "triage", "Duplicate of": "GHSA-mid"})
	typed := p.Add(map[string]any{"GHSA": "GHSA-typed", "State": "triage", "Duplicate of": "ghsa-ROOT"})
	orphan := p.Add(map[string]any{"GHSA": "GHSA-orphan", "State": "triage", "Duplicate of": "GHSA-gone"})
	alone := p.Add(map[string]any{"GHSA": "GHSA-alone", "State": "triage", "Original report": "GHSA-stale"})
	loopA := p.Add(map[string]any{"GHSA": "GHSA-loop-a", "State": "triage", "Duplicate of": "GHSA-loop-b"})
	p.Add(map[string]any{"GHSA": "GHSA-loop-b", "State": "triage", "Duplicate of": "GHSA-loop-a"})
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Sync(t.Context(), nil))

	require.Equal(t, "GHSA-root", p.Value(root, "Original report"), "the oldest report is missing from its group")
	require.Equal(t, "GHSA-root", p.Value(mid, "Original report"))
	require.Equal(t, "GHSA-root", p.Value(leaf, "Original report"), "a chain of duplicates was split")
	require.Equal(t, "GHSA-root", p.Value(typed, "Original report"), "an original typed in another case split the group")
	require.Equal(t, "GHSA-gone", p.Value(orphan, "Original report"), "a report whose oldest has no item lost its group")
	require.Empty(t, p.Value(alone, "Original report"), "a report without duplicates kept a stale group")
	require.NotEmpty(t, p.Value(loopA, "Original report"), "a loop of duplicates did not end")
}

func TestOpenRefusesAnIssuesRepositoryThatCouldPublishReports(t *testing.T) {
	for name, tc := range map[string]struct {
		issues, err string
	}{
		"private":             {"acme/private-issues", ""},
		"public":              {"php/php-src", "the issues repository must not be the repository of the advisories"},
		"public elsewhere":    {"php/web-php", "the issues repository must be private"},
		"advisory repository": {"PHP/PHP-SRC", "the issues repository must not be the repository of the advisories"},
		"unknown":             {"php/missing", "github: HTTP 404"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			p.Repos["php/web-php"] = false
			p.Reached = append(p.Reached, tc.issues)

			_, err := Open(t.Context(), p, p, "php/16", tc.issues, "php/php-src")

			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
			require.Empty(t, p.Issues)
		})
	}
}

func TestPutCreatesAPrivateIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-new", Summary: "Overflow found by @someone", HTMLURL: "https://x/GHSA-new", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, "pending"))
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{Severity: "high", Located: true}, "the comment"))

	id := p.Find("GHSA-new")
	issue := p.IssueOf(id)
	require.NotNil(t, issue, "the item is a draft")
	require.Len(t, p.Issues, 1, "a second put created another issue")
	require.Equal(t, "acme/private-issues", issue.Repo)
	require.Equal(t, "Overflow found by @\u200bsomeone", issue.Title, "a mention in the title would notify")
	require.Equal(t, "https://x/GHSA-new\n\nthe comment\n\n<!-- tamis-issue GHSA-new -->", issue.Body)
	require.Equal(t, "open", issue.State)
	require.Empty(t, p.Titles, "a draft was created next to the issue")
	require.Equal(t, ToTriage, p.Value(id, "Priority"))
}

func TestPutClosesTheIssueOfASettledAdvisory(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "published"}, ToTriage, &Triage{}, ""))

	issue := p.IssueOf(p.Find("GHSA-new"))
	require.Equal(t, "closed", issue.State)
	require.Equal(t, "completed", issue.StateReason)
}

func TestPutReportsAFailedIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	p.IssueErr = errors.New("HTTP 403")

	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))
	require.Empty(t, p.Items, "an item was added without its issue")
}

func TestPutKeepsTheDraftsOfAPreviousRun(t *testing.T) {
	p := boardtest.New()
	id := p.Add(map[string]any{"GHSA": "GHSA-old"})
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-old", HTMLURL: "https://x/GHSA-old", State: "triage"}, ToTriage, &Triage{}, "the comment"))

	require.Nil(t, p.IssueOf(id))
	require.Empty(t, p.Issues, "a draft was turned into a second item")
	require.Equal(t, "https://x/GHSA-old\n\nthe comment", p.Bodies[id])
}

func TestSyncMirrorsTheAdvisoryStateOnItsIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	for _, g := range []string{"GHSA-a", "GHSA-b", "GHSA-c"} {
		require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: g, Summary: g, State: "triage"}, ToTriage, &Triage{}, ""))
	}

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-a", State: "published"}, {GHSAID: "GHSA-b", State: "closed"}, {GHSAID: "GHSA-c", State: "draft"}}))

	require.Equal(t, "completed", p.IssueOf(p.Find("GHSA-a")).StateReason)
	require.Equal(t, "closed", p.IssueOf(p.Find("GHSA-b")).State)
	require.Equal(t, "not_planned", p.IssueOf(p.Find("GHSA-b")).StateReason)
	require.Equal(t, "open", p.IssueOf(p.Find("GHSA-c")).State, "an accepted advisory closed its issue")

	p.IssueErr = errors.New("HTTP 403")
	require.Error(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-c", State: "closed"}}))
	require.Equal(t, "draft", p.Value(p.Find("GHSA-c"), "State"), "the field moved while its issue stayed open")
}

func TestSyncNestsEveryDuplicateUnderItsOriginal(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	put := func(g, dup string) {
		require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: g, Summary: g, State: "triage"}, Duplicate, &Triage{DuplicateOf: dup}, ""))
	}
	put("GHSA-root", "")
	put("GHSA-mid", "GHSA-root")
	put("GHSA-leaf", "GHSA-mid")
	put("GHSA-orphan", "GHSA-gone")
	p.IssueErr = errors.New("HTTP 502")

	require.Error(t, b.Sync(t.Context(), nil))
	require.Empty(t, p.Value(p.Find("GHSA-leaf"), "Original report"), "the group was written before its sub-issue")

	p.IssueErr = nil
	require.NoError(t, b.Sync(t.Context(), nil))

	root := p.IssueOf(p.Find("GHSA-root"))
	require.Zero(t, root.Parent, "the original became a sub-issue of itself")
	for _, g := range []string{"GHSA-mid", "GHSA-leaf"} {
		require.Equal(t, 1, p.IssueOf(p.Find(g)).Parent, "%s is not under its original", g)
	}
	require.Zero(t, p.IssueOf(p.Find("GHSA-orphan")).Parent, "a report whose original has no issue got a parent")
	require.Equal(t, "GHSA-gone", p.Value(p.Find("GHSA-orphan"), "Original report"))
}

func TestPutAttachesTheIssueOfARunThatFailedToAddIt(t *testing.T) {
	p := boardtest.New()
	const ghsa = "GHSA-aaaa-bbbb-cccc"
	a := github.Advisory{GHSAID: ghsa, Summary: "s", HTMLURL: "https://x/" + ghsa, State: "triage"}
	p.Issues[1] = &boardtest.Issue{ID: 1001, Repo: "acme/private-issues", Title: "s", Body: "https://x/" + ghsa + "\n\n<!-- tamis-issue " + ghsa + " -->", State: "open"}
	p.Issues[2] = &boardtest.Issue{ID: 1002, Repo: "acme/private-issues", Title: "by hand", Body: "no marker", State: "open"}

	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{}, "the comment"))

	require.Len(t, p.Issues, 2, "a second issue was created for the same advisory")
	issue := p.IssueOf(p.Find(ghsa))
	require.Equal(t, int64(1001), issue.ID, "the issue of the previous run was not reused")
	require.Contains(t, issue.Body, "the comment")
	require.Contains(t, issue.Body, "<!-- tamis-issue "+ghsa+" -->", "the update dropped the marker")
}

func TestPutMarksEveryIssueWithItsAdvisory(t *testing.T) {
	p := boardtest.New()
	const ghsa = "GHSA-dddd-eeee-ffff"
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: ghsa, Summary: "s", State: "triage"}

	require.NoError(t, b.Put(t.Context(), a, AnalysisPending, nil, "pending"))
	require.Contains(t, p.IssueOf(p.Find(ghsa)).Body, "<!-- tamis-issue "+ghsa+" -->")
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{}, "the comment"))
	require.Contains(t, p.IssueOf(p.Find(ghsa)).Body, "<!-- tamis-issue "+ghsa+" -->", "the update dropped the marker")
}

func TestOpenRefusesAnIssuesTokenThatReachesTheAdvisories(t *testing.T) {
	for name, tc := range map[string]struct {
		reached []string
		err     string
	}{
		"issues repository only":  {[]string{"acme/private-issues"}, ""},
		"advisory repository too": {[]string{"acme/private-issues", "PHP/php-src"}, "the issues token must not reach the repository of the advisories"},
		"another repository":      {[]string{"php/web-php"}, "the issues token does not reach the issues repository"},
		"not an app token":        {nil, "listing the repositories of the issues token: github: HTTP 403"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			p.Reached = tc.reached

			_, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")

			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestOpenRefusesAnIssuesRepositoryWithoutItsToken(t *testing.T) {
	p := boardtest.New()

	_, err := Open(t.Context(), p, nil, "php/16", "acme/private-issues", "php/php-src")

	require.EqualError(t, err, "the issues repository needs a token of its own")
}

func TestOpenFindsTheIssueOfARunWhoseFieldsFailed(t *testing.T) {
	p := boardtest.New()
	const ghsa = "GHSA-aaaa-bbbb-cccc"
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	p.UpdateErr = errors.New("HTTP 404")
	require.Error(t, b.Put(t.Context(), github.Advisory{GHSAID: ghsa, Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))
	p.UpdateErr = nil

	b, err = Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	priority, _ := b.Status(ghsa)
	require.Empty(t, priority, "an item without fields looks triaged")
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: ghsa, Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))

	require.Len(t, p.Items, 1, "the issue was added to the project twice")
	require.Len(t, p.Issues, 1)
	require.Equal(t, ghsa, p.Value(p.Find(ghsa), "GHSA"))
}

func TestSyncLeavesTheIssuesOfAnotherRepositoryAlone(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-a", Summary: "a", State: "triage"}, ToTriage, &Triage{}, ""))
	id := p.Find("GHSA-a")

	b, err = Open(t.Context(), p, nil, "php/16", "", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-a", State: "closed"}}), "a board without issues repository wrote an issue")
	require.Equal(t, "closed", p.Value(id, "State"))

	p.Repos["php/other-security"], p.Reached = true, []string{"php/other-security"}
	b, err = Open(t.Context(), p, p, "php/16", "php/other-security", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-a", State: "published"}}))

	require.Equal(t, "open", p.IssueOf(id).State, "the issue of another repository was written")
	require.Equal(t, "published", p.Value(id, "State"))
}

func TestPutIgnoresAMarkerQuotedByTheTriage(t *testing.T) {
	p := boardtest.New()
	const own, quoted = "GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"
	body := "https://x/" + own + "\n\n`<!-- tamis-issue " + quoted + " -->`\n\n<!-- tamis-issue " + own + " -->"
	p.Issues[1] = &boardtest.Issue{ID: 1001, Repo: "acme/private-issues", Title: own, Body: body, State: "open"}
	_, err := p.AddProjectIssue(t.Context(), "php", 16, 1001)
	require.NoError(t, err)

	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NotNil(t, b.items[strings.ToLower(own)], "the issue lost its own advisory")
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: quoted, Summary: quoted, State: "triage"}, ToTriage, &Triage{}, "the comment"))

	require.Len(t, p.Issues, 2, "the quoted advisory took over the issue of another")
	require.Equal(t, body, p.Issues[1].Body)
}

func TestPutReopensTheIssueOfAnAdvisoryBackInTriage(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-a", Summary: "a", State: "triage"}, AnalysisRetrying, nil, "failed once"))
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-a", State: "closed"}}))
	id := p.Find("GHSA-a")
	b, err = Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	reopened := github.Advisory{GHSAID: "GHSA-a", State: "triage"}

	p.IssueErr = errors.New("HTTP 502")
	require.Error(t, b.Put(t.Context(), reopened, ToTriage, &Triage{}, ""))
	require.Equal(t, "closed", p.Value(id, "State"), "the field moved while its issue stayed closed")
	p.IssueErr = nil
	require.NoError(t, b.Put(t.Context(), reopened, ToTriage, &Triage{}, ""))
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{reopened}))

	require.Equal(t, "open", p.IssueOf(id).State, "the issue stayed closed while its advisory is in triage")
	require.Equal(t, "triage", p.Value(id, "State"))
}

func TestPutWritesTheFieldsOfAnIssueOfAnotherRepository(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	a := github.Advisory{GHSAID: "GHSA-a", Summary: "a", HTMLURL: "https://x/GHSA-a", State: "triage"}
	require.NoError(t, b.Put(t.Context(), a, ToTriage, &Triage{}, "the comment"))
	id := p.Find("GHSA-a")

	b, err = Open(t.Context(), p, nil, "php/16", "", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.PutStatus(t.Context(), a, AnalysisRetrying, "failed once", 1), "the issue was written as a draft")

	require.Equal(t, AnalysisRetrying, p.Value(id, "Priority"))
	require.Equal(t, "https://x/GHSA-a\n\nthe comment\n\n<!-- tamis-issue GHSA-a -->", p.IssueOf(id).Body, "the issue of another repository was written")
}

func TestSyncNestsADuplicateUnderAnOriginalAddedLater(t *testing.T) {
	p := boardtest.New()
	open := func() *Board {
		b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
		require.NoError(t, err)
		return b
	}
	b := open()
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-dup", Summary: "d", State: "triage"}, Duplicate, &Triage{DuplicateOf: "GHSA-old"}, ""))
	require.NoError(t, b.Sync(t.Context(), nil))
	require.Equal(t, "GHSA-old", p.Value(p.Find("GHSA-dup"), "Original report"))

	b = open()
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-old", Summary: "o", State: "triage"}, ToTriage, &Triage{}, ""))
	require.NoError(t, b.Sync(t.Context(), nil))
	original := p.IssueOf(p.Find("GHSA-old"))
	require.Equal(t, int(original.ID-1000), p.IssueOf(p.Find("GHSA-dup")).Parent, "the duplicate stayed out of its original")

	p.IssueErr = errors.New("HTTP 502")
	require.NoError(t, open().Sync(t.Context(), nil), "a linked sub-issue was linked again")
}

func TestPutReopensAClosedIssueItAttachesAgain(t *testing.T) {
	for state, want := range map[string]string{"triage": "open", "published": "closed"} {
		t.Run(state, func(t *testing.T) {
			p := boardtest.New()
			const ghsa = "GHSA-aaaa-bbbb-cccc"
			p.Issues[1] = &boardtest.Issue{ID: 1001, Repo: "acme/private-issues", Title: "s", Body: "<!-- tamis-issue " + ghsa + " -->", State: "closed", StateReason: "not_planned"}
			b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
			require.NoError(t, err)

			require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: ghsa, Summary: "s", State: state}, ToTriage, &Triage{}, "the comment"))

			require.Len(t, p.Issues, 1, "a second issue was created")
			require.Equal(t, want, p.Issues[1].State)
			require.Contains(t, p.Issues[1].Body, "the comment")
		})
	}
}

func TestSyncNestsUnderTheOldestReportThatHasAnIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	put := func(g, dup string) {
		require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: g, Summary: g, State: "triage"}, Duplicate, &Triage{DuplicateOf: dup}, ""))
	}
	put("GHSA-mid", "GHSA-closed")
	put("GHSA-leaf", "GHSA-mid")

	require.NoError(t, b.Sync(t.Context(), nil))

	mid := p.IssueOf(p.Find("GHSA-mid"))
	require.Zero(t, mid.Parent, "the oldest report with an issue got a parent")
	require.Equal(t, 1, p.IssueOf(p.Find("GHSA-leaf")).Parent, "the duplicate of a closed original lost its group")
	require.Equal(t, "GHSA-closed", p.Value(p.Find("GHSA-leaf"), "Original report"))
}

func TestSyncTakesOutAReportThatIsNoLongerADuplicate(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-root", Summary: "r", State: "triage"}, ToTriage, &Triage{}, ""))
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-dup", Summary: "d", State: "triage"}, Duplicate, &Triage{DuplicateOf: "GHSA-root"}, ""))
	require.NoError(t, b.Sync(t.Context(), nil))
	dup := p.IssueOf(p.Find("GHSA-dup"))
	require.Equal(t, 1, dup.Parent)

	p.Items[p.Find("GHSA-dup")][p.Fields[2].ID] = nil
	b, err = Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	p.IssueErr = errors.New("HTTP 502")
	require.Error(t, b.Sync(t.Context(), nil))
	require.Equal(t, 1, dup.Parent, "a failed removal changed the parent")

	p.IssueErr = nil
	require.NoError(t, b.Sync(t.Context(), nil))
	require.Zero(t, dup.Parent, "a report cleared by hand stayed nested")
	require.Empty(t, dup.Comments, "a report that is no longer a duplicate got a note")
}

func TestSyncGathersTheDuplicatesOfAClosedOriginalUnderTheOldestOfThem(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	put := func(g string, day int) {
		a := github.Advisory{GHSAID: g, Summary: g, State: "triage", CreatedAt: reported.AddDate(0, 0, day)}
		require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{DuplicateOf: "GHSA-closed"}, ""))
	}
	put("GHSA-young", 2)
	put("GHSA-first", 0)
	put("GHSA-later", 1)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-alone", Summary: "a", State: "triage"}, Duplicate, &Triage{DuplicateOf: "GHSA-other"}, ""))

	require.NoError(t, b.Sync(t.Context(), nil))

	first := p.IssueOf(p.Find("GHSA-first"))
	require.Zero(t, first.Parent, "the oldest duplicate became a sub-issue")
	for _, g := range []string{"GHSA-young", "GHSA-later"} {
		require.Equal(t, int(first.ID-1000), p.IssueOf(p.Find(g)).Parent, "%s is not under the oldest duplicate of its group", g)
	}
	require.Zero(t, p.IssueOf(p.Find("GHSA-alone")).Parent, "a duplicate alone in its group got a parent")

	b, err = Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	writes := p.Writes
	require.NoError(t, b.Sync(t.Context(), nil))
	require.Equal(t, writes, p.Writes, "a nested group was written again")
}

func TestSyncTakesTheDuplicatesOutOfAnOriginalThatLeftTriage(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	put := func(g, state, dup string, day int) {
		a := github.Advisory{GHSAID: g, Summary: g, State: state, CreatedAt: reported.AddDate(0, 0, day)}
		require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{DuplicateOf: dup}, ""))
	}
	put("GHSA-root", "triage", "", -2)
	put("GHSA-gone", "closed", "GHSA-root", -1)
	put("GHSA-first", "triage", "GHSA-root", 0)
	put("GHSA-later", "triage", "GHSA-root", 1)
	require.NoError(t, b.Sync(t.Context(), nil))
	root, gone, first, later := p.IssueOf(p.Find("GHSA-root")), p.IssueOf(p.Find("GHSA-gone")), p.IssueOf(p.Find("GHSA-first")), p.IssueOf(p.Find("GHSA-later"))
	require.Equal(t, int(root.ID-1000), gone.Parent)
	require.Equal(t, int(root.ID-1000), first.Parent)
	require.Equal(t, int(root.ID-1000), later.Parent)

	closed := []github.Advisory{{GHSAID: "GHSA-root", State: "published"}, {GHSAID: "GHSA-gone", State: "closed"}, {GHSAID: "GHSA-first", State: "triage"}, {GHSAID: "GHSA-later", State: "draft"}}
	p.IssueErr = errors.New("HTTP 502")
	require.Error(t, b.Sync(t.Context(), closed))
	require.Equal(t, int(root.ID-1000), later.Parent, "a failed link changed the parent")
	require.Equal(t, int(root.ID-1000), first.Parent, "a failed note let the issue leave its original")
	require.Empty(t, first.Comments)

	p.IssueErr = nil
	require.NoError(t, b.Sync(t.Context(), closed))
	require.Zero(t, first.Parent, "the oldest waiting duplicate stayed under its published original")
	require.Equal(t, int(first.ID-1000), later.Parent, "the duplicate is not under the oldest waiting one")
	require.Equal(t, "GHSA-root", p.Value(p.Find("GHSA-later"), "Original report"))
	require.Equal(t, int(root.ID-1000), gone.Parent, "a closed duplicate left its published original")
	require.Empty(t, gone.Comments, "a closed duplicate got a note")
	require.Equal(t, "1", p.Value(p.Find("GHSA-root"), "Duplicates"), "the published original kept the count of its waiting duplicates")
	require.Equal(t, "1", p.Value(p.Find("GHSA-first"), "Duplicates"))
	require.Len(t, first.Comments, 1, "the new head of the group got no note")
	require.Contains(t, first.Comments[0], "GHSA-root")
	require.Contains(t, first.Comments[0], "published")
	require.Empty(t, later.Comments, "a duplicate that only changed parent got a note")
	require.NoError(t, b.Sync(t.Context(), closed))
	require.Len(t, first.Comments, 1, "the note was posted again")

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-root", State: "triage"}}))
	require.Equal(t, int(root.ID-1000), first.Parent, "a duplicate stayed out of its original back in triage")
	require.Equal(t, int(root.ID-1000), later.Parent)
}

func TestSyncCountsTheSubIssuesOfEachIssue(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	put := func(g, dup string, day int) {
		a := github.Advisory{GHSAID: g, Summary: g, State: "triage", CreatedAt: reported.AddDate(0, 0, day)}
		require.NoError(t, b.Put(t.Context(), a, Duplicate, &Triage{DuplicateOf: dup}, ""))
	}
	put("GHSA-root", "", 0)
	put("GHSA-mid", "GHSA-root", 1)
	put("GHSA-leaf", "GHSA-mid", 2)
	put("GHSA-first", "GHSA-closed", 0)
	put("GHSA-later", "GHSA-closed", 1)

	require.NoError(t, b.Sync(t.Context(), nil))

	for g, want := range map[string]string{"GHSA-root": "2", "GHSA-mid": "", "GHSA-leaf": "", "GHSA-first": "1", "GHSA-later": ""} {
		require.Equal(t, want, p.Value(p.Find(g), "Duplicates"), "%s does not count its sub-issues", g)
	}
}

func TestCreateLaysOutTheProjectOpenExpects(t *testing.T) {
	p := boardtest.New()
	p.Fields = p.Fields[:1]

	project, err := Create(t.Context(), p, "acme", "tamis")

	require.NoError(t, err)
	require.Equal(t, "acme/16", project)
	_, err = Open(t.Context(), p, p, project, "", "php/php-src")
	require.NoError(t, err)
	require.Equal(t, []github.ProjectView{{
		Name:   "Triage",
		Filter: "State:triage,draft -Priority:Duplicate",
		Fields: []int64{100, 105, 106, 110, 111, 103, 104},
		SortBy: []int64{106, 104},
	}}, p.Views)
	require.Equal(t, []string{"PVTV_default"}, p.Deleted)
}

func TestCreateReportsAFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*boardtest.Project)
		err    string
	}{
		"project": {func(p *boardtest.Project) { p.Err = errors.New("boom") }, "creating a project of acme: boom"},
		"fields":  {func(p *boardtest.Project) { p.ListErr = errors.New("boom") }, "listing the fields of acme/16: boom"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boardtest.New()
			p.Fields = p.Fields[:1]
			tc.change(p)

			_, err := Create(t.Context(), p, "acme", "tamis")

			require.EqualError(t, err, tc.err)
			require.Empty(t, p.Views)
		})
	}
}

type advisories struct {
	byID     map[string]*github.Advisory
	comments map[string][]string
	updates  int
	postErr  error
	closeErr error
}

func (f *advisories) GetAdvisory(_ context.Context, _, ghsa string) (github.Advisory, error) {
	a, ok := f.byID[ghsa]
	if !ok {
		return github.Advisory{}, github.ErrNotFound
	}

	return *a, nil
}

func (f *advisories) UpdateAdvisory(_ context.Context, _, ghsa string, fields map[string]any) error {
	a := f.byID[ghsa]
	if credits, ok := fields["credits"]; ok {
		a.Credits = credits.([]github.Credit)
	}
	if state, ok := fields["state"]; ok {
		if f.closeErr != nil {
			return f.closeErr
		}
		a.State = state.(string)
	}
	f.updates++

	return nil
}

func (f *advisories) ListComments(_ context.Context, _, ghsa string) ([]github.Comment, error) {
	var all []github.Comment
	for _, body := range f.comments[ghsa] {
		all = append(all, github.Comment{Body: body})
	}

	return all, nil
}

func (f *advisories) PostComment(_ context.Context, _, ghsa, body string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.comments[ghsa] = append(f.comments[ghsa], body)

	return nil
}

func (f *advisories) list() []github.Advisory {
	var all []github.Advisory
	for _, a := range f.byID {
		all = append(all, *a)
	}

	return all
}

// closedAsDuplicate puts GHSA-orig and its duplicate GHSA-dup on a board of issues, closes the issue of GHSA-dup
// with reason and opens the board again, as the next run does.
func closedAsDuplicate(t *testing.T, reason string, duplicateOf string) (*boardtest.Project, *Board) {
	t.Helper()
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "acme/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-orig", Summary: "s", State: "triage", CreatedAt: reported}, ToTriage, &Triage{}, ""))
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-dup", Summary: "s", State: "triage", CreatedAt: reported.AddDate(0, 0, 1)}, Duplicate, &Triage{DuplicateOf: duplicateOf}, ""))
	issue := p.IssueOf(p.Find("GHSA-dup"))
	issue.State, issue.StateReason = "closed", reason
	b, err = Open(t.Context(), p, p, "acme/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)

	return p, b
}

func newAdvisories(original github.Advisory) *advisories {
	dup := github.Advisory{GHSAID: "GHSA-dup", HTMLURL: "https://x/GHSA-dup", State: "triage"}
	dup.Author.Login = "bob"

	return &advisories{byID: map[string]*github.Advisory{"GHSA-orig": &original, "GHSA-dup": &dup}, comments: map[string][]string{}}
}

func TestCloseDuplicatesClosesTheReportAndCreditsItsReporterOnTheOriginal(t *testing.T) {
	carol := github.Credit{Login: "carol", Type: "analyst"}
	for name, tc := range map[string]struct {
		state, author string
		credits       []github.Credit
		want          []github.Credit
		comment, note string
	}{
		"original in triage":                         {"triage", "alice", []github.Credit{carol}, []github.Credit{carol, {Login: "bob", Type: "reporter"}}, "This report is closed as a duplicate of GHSA-orig, reported earlier. You are credited on it as a reporter.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1), where `bob` has been credited as a reporter."},
		"original in draft":                          {"draft", "alice", nil, []github.Credit{{Login: "bob", Type: "reporter"}}, "This report is closed as a duplicate of GHSA-orig, reported earlier. You are credited on it as a reporter.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1), where `bob` has been credited as a reporter."},
		"already credited":                           {"triage", "alice", []github.Credit{{Login: "Bob", Type: "finder"}}, []github.Credit{{Login: "Bob", Type: "finder"}}, "This report is closed as a duplicate of GHSA-orig, reported earlier. You are credited on it as a reporter.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1), where `bob` has been credited as a reporter."},
		"same reporter":                              {"triage", "bob", nil, nil, "This report is closed as a duplicate of GHSA-orig, reported earlier.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1)."},
		"original published":                         {"published", "alice", nil, nil, "This report is closed as a duplicate of GHSA-orig, reported earlier.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1)."},
		"original closed":                            {"closed", "alice", nil, nil, "This report is closed as a duplicate of GHSA-orig, reported earlier.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1)."},
		"credited before the original was published": {"published", "alice", []github.Credit{{Login: "bob", Type: "reporter"}}, []github.Credit{{Login: "bob", Type: "reporter"}}, "This report is closed as a duplicate of GHSA-orig, reported earlier. You are credited on it as a reporter.", "Closed [GHSA-dup](https://x/GHSA-dup) as a duplicate of [GHSA-orig](https://x/GHSA-orig) (#1), where `bob` has been credited as a reporter."},
	} {
		t.Run(name, func(t *testing.T) {
			p, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
			original := github.Advisory{GHSAID: "GHSA-orig", HTMLURL: "https://x/GHSA-orig", State: tc.state, Credits: tc.credits}
			original.Author.Login = tc.author
			f := newAdvisories(original)

			require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))

			require.Equal(t, tc.want, f.byID["GHSA-orig"].Credits)
			require.Equal(t, tc.state, f.byID["GHSA-orig"].State, "the original changed state")
			require.Equal(t, "closed", f.byID["GHSA-dup"].State)
			require.Equal(t, []string{tc.comment}, f.comments["GHSA-dup"])
			require.Empty(t, f.comments["GHSA-orig"])
			require.Equal(t, []string{tc.note}, p.IssueOf(p.Find("GHSA-dup")).Comments)
			require.Empty(t, p.IssueOf(p.Find("GHSA-orig")).Comments)
		})
	}
}

// The issue a maintainer closed as a duplicate keeps that reason when a triage puts its closed advisory again,
// and an issue closed for another reason follows its advisory.
func TestPutKeepsTheReasonOfAnIssueClosedAsADuplicate(t *testing.T) {
	for reason, want := range map[string]string{"duplicate": "duplicate", "completed": "not_planned"} {
		t.Run(reason, func(t *testing.T) {
			p, b := closedAsDuplicate(t, reason, "GHSA-orig")

			require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-dup", Summary: "s", State: "closed", CreatedAt: reported}, Duplicate, &Triage{DuplicateOf: "GHSA-orig"}, ""))

			issue := p.IssueOf(p.Find("GHSA-dup"))
			require.Equal(t, "closed", issue.State)
			require.Equal(t, want, issue.StateReason)
		})
	}
}

func TestPutReopensTheIssueOfADuplicateBackInDraft(t *testing.T) {
	p, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")

	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-dup", Summary: "s", State: "draft", CreatedAt: reported}, Duplicate, &Triage{DuplicateOf: "GHSA-orig"}, ""))

	require.Equal(t, "open", p.IssueOf(p.Find("GHSA-dup")).State)
}

func TestCloseDuplicatesCreditsTheOldestReportOfTheChain(t *testing.T) {
	p, b := closedAsDuplicate(t, "duplicate", "GHSA-mid")
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-mid", Summary: "s", State: "triage", CreatedAt: reported}, Duplicate, &Triage{DuplicateOf: "GHSA-orig"}, ""))
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})
	f.byID["GHSA-mid"] = &github.Advisory{GHSAID: "GHSA-mid", State: "triage"}

	require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))

	require.Equal(t, []github.Credit{{Login: "bob", Type: "reporter"}}, f.byID["GHSA-orig"].Credits)
	require.Empty(t, f.byID["GHSA-mid"].Credits, "the reporter was credited on an intermediate duplicate")
	require.Equal(t, "closed", f.byID["GHSA-dup"].State)
	require.Equal(t, "triage", f.byID["GHSA-mid"].State)
	require.Equal(t, "open", p.IssueOf(p.Find("GHSA-mid")).State)
}

func TestCloseDuplicatesLeavesTheOtherReportsAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		reason, duplicateOf, state string
	}{
		"issue open":             {"", "GHSA-orig", "triage"},
		"issue closed otherwise": {"not_planned", "GHSA-orig", "triage"},
		"no original":            {"duplicate", "", "triage"},
		"original is itself":     {"duplicate", "GHSA-dup", "triage"},
		"advisory decided":       {"duplicate", "GHSA-orig", "published"},
	} {
		t.Run(name, func(t *testing.T) {
			p, b := closedAsDuplicate(t, tc.reason, tc.duplicateOf)
			if tc.reason == "" {
				p.IssueOf(p.Find("GHSA-dup")).State = "open"
				var err error
				b, err = Open(t.Context(), p, p, "acme/16", "acme/private-issues", "php/php-src")
				require.NoError(t, err)
			}
			f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})
			f.byID["GHSA-dup"].State = tc.state

			require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))

			require.Zero(t, f.updates)
			require.Empty(t, f.comments)
		})
	}
}

// An advisory reopened by hand after tamis closed it as a duplicate stays open, and its issue opens again.
func TestCloseDuplicatesLeavesAReopenedReportAlone(t *testing.T) {
	p, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-orig", State: "triage"}, {GHSAID: "GHSA-dup", State: "closed"}}))
	b, err := Open(t.Context(), p, p, "acme/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})

	require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))
	require.NoError(t, b.Sync(t.Context(), f.list()))

	require.Zero(t, f.updates)
	require.Empty(t, f.comments)
	require.Equal(t, "triage", f.byID["GHSA-dup"].State)
	require.Equal(t, "open", p.IssueOf(p.Find("GHSA-dup")).State)
}

func TestCloseDuplicatesKeepsTheReportOpenUntilItsCommentIsPosted(t *testing.T) {
	_, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})
	f.postErr = errors.New("HTTP 502")

	require.Error(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))
	require.Equal(t, "triage", f.byID["GHSA-dup"].State, "a report was closed without telling its reporter")

	f.postErr = nil
	require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))
	require.Equal(t, "closed", f.byID["GHSA-dup"].State)
	require.Equal(t, []github.Credit{{Login: "bob", Type: "reporter"}}, f.byID["GHSA-orig"].Credits, "the reporter was credited twice")
	require.Len(t, f.comments["GHSA-dup"], 1)
}

func TestCloseDuplicatesPostsItsCommentOnceWhenTheCloseFails(t *testing.T) {
	_, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})
	f.closeErr = errors.New("HTTP 502")

	dup := func(list []github.Advisory) github.Advisory {
		return list[slices.IndexFunc(list, func(a github.Advisory) bool { return a.GHSAID == "GHSA-dup" })]
	}
	for range 2 {
		list := f.list()
		require.Error(t, b.CloseDuplicates(t.Context(), f, "php/php-src", list))
		require.Equal(t, "triage", f.byID["GHSA-dup"].State)
		require.Equal(t, "triage", dup(list).State, "a report that stayed open was marked closed")
	}
	require.Len(t, f.comments["GHSA-dup"], 1, "the comment was posted again")

	f.closeErr = nil
	list := f.list()
	require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", list))
	require.Equal(t, "closed", f.byID["GHSA-dup"].State)
	require.Len(t, f.comments["GHSA-dup"], 1)
	require.Equal(t, "closed", dup(list).State, "the following Sync would see the report still in triage")
}

func TestCloseDuplicatesLeavesALoopOfDuplicatesAlone(t *testing.T) {
	_, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-orig", Summary: "s", State: "triage", CreatedAt: reported}, Duplicate, &Triage{DuplicateOf: "GHSA-dup"}, ""))
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})

	require.NoError(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()))

	require.Zero(t, f.updates)
	require.Empty(t, f.comments)
}

func TestCloseDuplicatesReportsAFailedNoteOnceTheReportIsClosed(t *testing.T) {
	p, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig", State: "triage"})
	p.IssueErr = errors.New("HTTP 502")
	all := f.list()

	require.ErrorContains(t, b.CloseDuplicates(t.Context(), f, "php/php-src", all), "HTTP 502")

	require.Equal(t, "closed", f.byID["GHSA-dup"].State)
	require.True(t, slices.ContainsFunc(all, func(a github.Advisory) bool { return a.GHSAID == "GHSA-dup" && a.State == "closed" }), "the Sync that follows sees the report in triage")
	require.Empty(t, p.IssueOf(p.Find("GHSA-dup")).Comments)
}

func TestCloseDuplicatesReportsAMissingOriginal(t *testing.T) {
	_, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")
	f := newAdvisories(github.Advisory{GHSAID: "GHSA-orig"})
	delete(f.byID, "GHSA-orig")

	require.ErrorIs(t, b.CloseDuplicates(t.Context(), f, "php/php-src", f.list()), github.ErrNotFound)
	require.Equal(t, "triage", f.byID["GHSA-dup"].State)
	require.Empty(t, f.comments)
}

func TestSyncKeepsTheIssueOfAClosedDuplicateClosedAsSuch(t *testing.T) {
	p, b := closedAsDuplicate(t, "duplicate", "GHSA-orig")

	require.NoError(t, b.Sync(t.Context(), []github.Advisory{{GHSAID: "GHSA-orig", State: "closed"}, {GHSAID: "GHSA-dup", State: "closed"}}))

	require.Equal(t, "duplicate", p.IssueOf(p.Find("GHSA-dup")).StateReason)
	require.Equal(t, "closed", p.Value(p.Find("GHSA-dup"), "State"))
	require.Equal(t, "not_planned", p.IssueOf(p.Find("GHSA-orig")).StateReason)
}

func TestLinkIssuesCommentsOnTheAdvisoriesOfTheIssuesItCreated(t *testing.T) {
	p := boardtest.New()
	p.Issues[1] = &boardtest.Issue{ID: 1001, Repo: "acme/private-issues", Title: "s", Body: "<!-- tamis-issue GHSA-aaaa-bbbb-cccc -->", State: "open"}
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-aaaa-bbbb-cccc", Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))
	f := &advisories{comments: map[string][]string{}}

	require.NoError(t, b.LinkIssues(t.Context(), f, "php/php-src"))

	require.Equal(t, map[string][]string{"GHSA-new": {"Tracked in https://github.com/acme/private-issues/issues/2."}}, f.comments, "an issue found again from a failed run was linked")
}

func TestLinkIssuesReportsAFailedComment(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "acme/private-issues", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))

	require.ErrorContains(t, b.LinkIssues(t.Context(), &advisories{postErr: errors.New("HTTP 502")}, "php/php-src"), "linking the issue of GHSA-new: HTTP 502")
}

func TestLinkIssuesLeavesDraftsAlone(t *testing.T) {
	p := boardtest.New()
	b, err := Open(t.Context(), p, p, "php/16", "", "php/php-src")
	require.NoError(t, err)
	require.NoError(t, b.Put(t.Context(), github.Advisory{GHSAID: "GHSA-new", Summary: "s", State: "triage"}, ToTriage, &Triage{}, ""))
	f := &advisories{comments: map[string][]string{}}

	require.NoError(t, b.LinkIssues(t.Context(), f, "php/php-src"))

	require.Empty(t, f.comments)
}
