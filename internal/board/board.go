// Package board keeps a private GitHub project in sync with the triaged advisories, one draft item each.
package board

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/php/tamis/internal/github"
	"github.com/php/tamis/internal/report"
)

const (
	ToTriage = "To triage"
	// AnalysisPending marks an advisory whose analysis started, AnalysisRetrying and AnalysisFailed one whose
	// analysis failed, with and without another attempt to come. The draft body says more.
	AnalysisPending  = "Analysis pending"
	AnalysisRetrying = "Analysis failed, retrying"
	AnalysisFailed   = "Analysis failed"
	Duplicate        = "Duplicate"
)

const (
	fieldGHSA        = "GHSA"
	fieldDuplicateOf = "Duplicate of"
	fieldDuplicates  = "Duplicates"
	fieldReported    = "Reported"
	fieldPriority    = "Priority"
	fieldSeverity    = "Severity"
	fieldState       = "State"
	fieldExcluded    = "Policy exclusion"
	fieldLocated     = "Located"
	fieldComponent   = "Component"
	fieldUpstream    = "Upstream"
	fieldGroup       = "Original report"
	fieldAttempts    = "Attempts"
)

// layout lists the fields the project must have, created by Create or by hand as docs/setup.md describes.
var layout = []struct {
	name, dataType string
	options        []string
}{
	{fieldGHSA, "text", nil},
	{fieldDuplicateOf, "text", nil},
	{fieldDuplicates, "number", nil},
	{fieldReported, "date", nil},
	{fieldPriority, "single_select", []string{ToTriage, Duplicate, AnalysisFailed, AnalysisRetrying, AnalysisPending}},
	{fieldSeverity, "single_select", []string{"Critical", "High", "Medium", "Low"}},
	{fieldState, "single_select", []string{"triage", "draft", "published", "closed", "withdrawn"}},
	{fieldExcluded, "single_select", []string{"Yes", "No"}},
	{fieldLocated, "single_select", []string{"Yes", "No"}},
	{fieldComponent, "text", nil},
	{fieldUpstream, "text", nil},
	{fieldGroup, "text", nil},
	{fieldAttempts, "number", nil},
}

type GitHub interface {
	GetProject(ctx context.Context, org string, number int) (github.Project, error)
	ListProjectFields(ctx context.Context, org string, number int) ([]github.ProjectField, error)
	ListProjectItems(ctx context.Context, org string, number int, fields []int64) ([]github.ProjectItem, error)
	CreateDraft(ctx context.Context, org string, number int, title, body string) (github.ProjectItem, error)
	UpdateDraft(ctx context.Context, draft, body string) error
	UpdateProjectItem(ctx context.Context, org string, number int, item int64, fields []github.FieldValue) error
}

type Creator interface {
	CreateProject(ctx context.Context, org, title string) (int, string, error)
	CreateProjectField(ctx context.Context, org string, number int, name, dataType string, options []string) error
	ListProjectFields(ctx context.Context, org string, number int) ([]github.ProjectField, error)
	CreateProjectView(ctx context.Context, org string, number int, view github.ProjectView) error
	DeleteProjectView(ctx context.Context, view string) error
}

// Create makes a project of org laid out as Open expects, with one view of the advisories still in triage that
// are no duplicate, sorted by severity, and returns it as "org/number".
func Create(ctx context.Context, gh Creator, org, title string) (string, error) {
	number, view, err := gh.CreateProject(ctx, org, title)
	if err != nil {
		return "", fmt.Errorf("creating a project of %s: %w", org, err)
	}
	project := fmt.Sprintf("%s/%d", org, number)
	for _, f := range layout {
		if err := gh.CreateProjectField(ctx, org, number, f.name, f.dataType, f.options); err != nil {
			return "", fmt.Errorf("creating the %q field of %s: %w", f.name, project, err)
		}
	}
	fields, err := gh.ListProjectFields(ctx, org, number)
	if err != nil {
		return "", fmt.Errorf("listing the fields of %s: %w", project, err)
	}
	ids := map[string]int64{}
	for _, f := range fields {
		ids[f.Name] = f.ID
	}
	triage := github.ProjectView{
		Name:   "Triage",
		Filter: "State:triage,draft -Priority:Duplicate",
		Fields: []int64{ids["Title"], ids[fieldPriority], ids[fieldSeverity], ids[fieldComponent], ids[fieldUpstream], ids[fieldDuplicates], ids[fieldReported]},
		SortBy: []int64{ids[fieldSeverity], ids[fieldReported]},
	}
	if err := gh.CreateProjectView(ctx, org, number, triage); err != nil {
		return "", fmt.Errorf("creating the view of %s: %w", project, err)
	}
	// The view GitHub adds lists every item unsorted, and a view gets its sort only when created.
	if err := gh.DeleteProjectView(ctx, view); err != nil {
		return "", fmt.Errorf("deleting the default view of %s: %w", project, err)
	}

	return project, nil
}

// Issues writes the issues of the board with a token of its own, which only reaches the issues repository.
type Issues interface {
	InstallationRepositories(ctx context.Context) ([]string, error)
	GetRepository(ctx context.Context, repo string) (github.Repository, error)
	ListIssues(ctx context.Context, repo string) ([]github.Issue, error)
	CreateIssue(ctx context.Context, repo, title, body string) (github.Issue, error)
	UpdateIssue(ctx context.Context, repo string, number int, fields map[string]string) error
	CommentIssue(ctx context.Context, repo string, number int, body string) error
	AddSubIssue(ctx context.Context, repo string, parent int, child int64) error
	RemoveSubIssue(ctx context.Context, repo string, parent int, child int64) error
	// AddProjectIssue needs a token that sees the issue, which the token of the advisories does not.
	AddProjectIssue(ctx context.Context, org string, number int, issue int64) (github.ProjectItem, error)
}

type Board struct {
	gh      GitHub
	org     string
	number  int
	ids     map[string]int64
	options map[string]map[string]string
	// items is keyed by lowercase GHSA identifier, items without one were added by hand and stay untouched.
	items map[string]*item
	// issues is the private repository new items are issues of, drafts when empty, written through ig.
	issues string
	ig     Issues
	// unlisted holds the issues of a previous run that never reached the board, by lowercase GHSA identifier.
	unlisted map[string]github.Issue
	// created holds the link of each issue this run created, by GHSA identifier.
	created map[string]string
}

// issueMarker names the advisory of an issue, so an issue created by a run that failed to put it on the board is
// found again instead of created twice, which would notify the watchers of the repository each time.
var issueMarker = regexp.MustCompile(`<!-- tamis-issue (GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}) -->`)

// markedAdvisory reads the last marker of an issue body, since the triage comment before it quotes model text
// that can hold a marker of its own inside a code span.
func markedAdvisory(body string) string {
	m := issueMarker.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return ""
	}

	return m[len(m)-1][1]
}

type item struct {
	id                              int64
	ghsa, draft, duplicateOf, state string
	priority, group                 string
	duplicates, attempts            int
	// reported is the date the advisory was reported, as YYYY-MM-DD, which orders the reports of a group.
	reported string
	// issue and issueID name the issue of an item that is one, zero for a draft, and parent the ID of its parent
	// issue, zero without one.
	issue           int
	issueID, parent int64
	// closedAs is the state reason of a closed issue, such as "duplicate", empty while it is open.
	closedAs string
	// triage is nil for an item without one, whose priority is a status Sync leaves alone.
	triage *Triage
}

// Triage is what the board keeps of a triage, enough to rank it again when the rule changes.
type Triage struct {
	Severity, DuplicateOf string
	Excluded, Located     bool
	// Component is the directory the model named, else the one of the located faulty statement, two levels deep.
	Component string
	// Upstream is the project the faulty code is bundled from, empty when it is the repository's own.
	Upstream string
}

// Open loads the fields and items of project, given as "org/number". With issues set, new items are issues of
// that repository, which must be private and must not be the repository of the advisories. ig writes them, and
// its token must reach the issues repository and not the repository of the advisories.
func Open(ctx context.Context, gh GitHub, ig Issues, project, issues, advisories string) (*Board, error) {
	org, n, _ := strings.Cut(project, "/")
	number, err := strconv.Atoi(n)
	if org == "" || err != nil {
		return nil, errors.New(`the project must be given as "org/number"`)
	}
	p, err := gh.GetProject(ctx, org, number)
	if err != nil {
		return nil, err
	}
	// The items name advisories under embargo, with their title.
	if p.Public {
		return nil, errors.New("the project must be private")
	}
	// An issue carries the title and triage of a report under embargo, so a public repository would publish it.
	if issues != "" {
		if strings.EqualFold(issues, advisories) {
			return nil, errors.New("the issues repository must not be the repository of the advisories")
		}
		if ig == nil {
			return nil, errors.New("the issues repository needs a token of its own")
		}
		// A token that cannot reach the advisory repository cannot publish there, whatever a bug in tamis does.
		reached, err := ig.InstallationRepositories(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the repositories of the issues token: %w", err)
		}
		if slices.ContainsFunc(reached, func(r string) bool { return strings.EqualFold(r, advisories) }) {
			return nil, errors.New("the issues token must not reach the repository of the advisories")
		}
		if !slices.ContainsFunc(reached, func(r string) bool { return strings.EqualFold(r, issues) }) {
			return nil, errors.New("the issues token does not reach the issues repository")
		}
		r, err := ig.GetRepository(ctx, issues)
		if err != nil {
			return nil, err
		}
		if !r.Private {
			return nil, errors.New("the issues repository must be private")
		}
	}
	b := &Board{gh: gh, org: org, number: number, ids: map[string]int64{}, options: map[string]map[string]string{}, items: map[string]*item{}, issues: issues, ig: ig, created: map[string]string{}}
	fields, err := gh.ListProjectFields(ctx, org, number)
	if err != nil {
		return nil, err
	}
	for _, want := range layout {
		i := slices.IndexFunc(fields, func(f github.ProjectField) bool { return f.Name == want.name && f.DataType == want.dataType })
		if i < 0 {
			return nil, fmt.Errorf("the project has no %s field %q", want.dataType, want.name)
		}
		b.ids[want.name] = fields[i].ID
		if want.options == nil {
			continue
		}
		b.options[want.name] = map[string]string{}
		for _, o := range fields[i].Options {
			b.options[want.name][o.Name.Raw] = o.ID
		}
		for _, o := range want.options {
			if b.options[want.name][o] == "" {
				return nil, fmt.Errorf("the %q field has no %q option", want.name, o)
			}
		}
	}

	items, err := gh.ListProjectItems(ctx, org, number, []int64{b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldDuplicates], b.ids[fieldState], b.ids[fieldPriority], b.ids[fieldExcluded], b.ids[fieldLocated], b.ids[fieldGroup], b.ids[fieldAttempts], b.ids[fieldReported]})
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var ghsa, excluded, located string
		entry := &item{id: it.ID, draft: it.Content.NodeID}
		// The issue number only names an issue of the issues repository, the one ig writes.
		if it.ContentType == "Issue" && issues != "" && strings.EqualFold(it.Content.Repository, issues) {
			entry.issue, entry.issueID, entry.parent = it.Content.Number, it.Content.ID, it.Content.Parent
		}
		for _, f := range it.Fields {
			var text struct {
				Raw  string `json:"raw"`
				Name struct {
					Raw string `json:"raw"`
				} `json:"name"`
			}
			var count float64
			var err error
			switch f.ID {
			case b.ids[fieldGHSA], b.ids[fieldDuplicateOf], b.ids[fieldState], b.ids[fieldPriority], b.ids[fieldExcluded], b.ids[fieldLocated], b.ids[fieldGroup]:
				err = json.Unmarshal(f.Value, &text)
			case b.ids[fieldDuplicates], b.ids[fieldAttempts]:
				err = json.Unmarshal(f.Value, &count)
			case b.ids[fieldReported]:
				err = json.Unmarshal(f.Value, &entry.reported)
			}
			// An unread GHSA would make the item look added by hand, and its advisory triaged again on every run.
			if err != nil {
				return nil, fmt.Errorf("the project item %d has a value in an unexpected format", it.ID)
			}
			switch f.ID {
			case b.ids[fieldGHSA]:
				ghsa = text.Raw
			case b.ids[fieldDuplicateOf]:
				entry.duplicateOf = text.Raw
			case b.ids[fieldState]:
				entry.state = text.Name.Raw
			case b.ids[fieldDuplicates]:
				entry.duplicates = int(count)
			case b.ids[fieldAttempts]:
				entry.attempts = int(count)
			case b.ids[fieldPriority]:
				entry.priority = text.Name.Raw
			case b.ids[fieldExcluded]:
				excluded = text.Name.Raw
			case b.ids[fieldLocated]:
				located = text.Name.Raw
			case b.ids[fieldGroup]:
				entry.group = text.Raw
			}
		}
		// An issue added by a run whose field update failed has no GHSA yet, its marker still names the advisory.
		if ghsa == "" && entry.issue != 0 {
			ghsa = markedAdvisory(it.Content.Body)
		}
		if excluded != "" && located != "" {
			entry.triage = &Triage{DuplicateOf: entry.duplicateOf, Excluded: excluded == "Yes", Located: located == "Yes"}
		}
		if ghsa != "" {
			entry.ghsa = ghsa
			b.items[strings.ToLower(ghsa)] = entry
		}
	}
	if issues != "" {
		all, err := ig.ListIssues(ctx, issues)
		if err != nil {
			return nil, err
		}
		b.unlisted = map[string]github.Issue{}
		byIssue := map[int]*item{}
		for _, it := range b.items {
			if it.issue != 0 {
				byIssue[it.issue] = it
			}
		}
		for _, i := range all {
			if it := byIssue[i.Number]; it != nil && i.State == "closed" {
				it.closedAs = i.StateReason
			}
			if ghsa := strings.ToLower(markedAdvisory(i.Body)); ghsa != "" && b.items[ghsa] == nil {
				b.unlisted[ghsa] = i
			}
		}
	}

	return b, nil
}

// TriageOf keeps what the board needs of r, with the oldest high-confidence exact duplicate the triage shows.
func TriageOf(r report.Report) Triage {
	t := Triage{Severity: r.Severity, Excluded: len(r.PolicyExclusions) > 0, Located: r.Located}
	t.Component, t.Upstream = r.Component, r.Upstream
	if dir := path.Dir(r.Location.Path); t.Component == "" && r.Located && dir != "." {
		parts := strings.Split(dir, "/")
		t.Component = strings.Join(parts[:min(len(parts), 2)], "/")
	}
	var oldest *report.Duplicate
	for i, d := range r.Duplicates {
		if d.Exact && d.Confidence == "high" && (d.Published || d.Confirmed) && d.CreatedAt.Before(r.CreatedAt) && (oldest == nil || d.CreatedAt.Before(oldest.CreatedAt)) {
			oldest = &r.Duplicates[i]
		}
	}
	if oldest != nil {
		t.DuplicateOf = oldest.GHSAID
	}

	return t
}

// Priority sets a report apart when it goes behind its oldest duplicate. The views order the others by severity.
func (t Triage) Priority() string {
	if t.DuplicateOf != "" {
		return Duplicate
	}

	return ToTriage
}

// Put creates the item of a, or updates the one it has. A nil t sets priority as a status and clears the
// fields of a triage. The draft body holds the advisory link, then comment when there is one. The title is
// only set on creation.
func (b *Board) Put(ctx context.Context, a github.Advisory, priority string, t *Triage, comment string) error {
	return b.put(ctx, a, priority, t, comment, 0)
}

// PutStatus sets a status without a triage, with the failed attempts so far, which only the board records.
func (b *Board) PutStatus(ctx context.Context, a github.Advisory, priority, note string, attempts int) error {
	return b.put(ctx, a, priority, nil, note, attempts)
}

// Status returns the priority and failed attempts of the item of ghsa, empty and zero without one.
func (b *Board) Status(ghsa string) (priority string, attempts int) {
	if it := b.items[strings.ToLower(ghsa)]; it != nil {
		return it.priority, it.attempts
	}

	return "", 0
}

func (b *Board) put(ctx context.Context, a github.Advisory, priority string, t *Triage, comment string, attempts int) error {
	key := strings.ToLower(a.GHSAID)
	body := a.HTMLURL
	if comment != "" {
		body += "\n\n" + comment
	}
	marker := fmt.Sprintf("\n\n<!-- tamis-issue %s -->", a.GHSAID)
	it := b.items[key]
	switch {
	case it == nil && b.issues != "":
		body += marker
		issue, found := b.unlisted[key]
		if found {
			// A maintainer may have closed the issue left by a failed run, it follows its advisory again.
			fields := issueState(a.State)
			fields["body"] = body
			if err := b.ig.UpdateIssue(ctx, b.issues, issue.Number, fields); err != nil {
				return err
			}
		} else {
			// The title is the reporter's summary, and a mention in it would notify whoever it names.
			var err error
			if issue, err = b.ig.CreateIssue(ctx, b.issues, strings.ReplaceAll(a.Summary, "@", "@\u200b"), body); err != nil {
				return err
			}
			b.unlisted[key] = issue
			b.created[a.GHSAID] = issue.HTMLURL
		}
		added, err := b.ig.AddProjectIssue(ctx, b.org, b.number, issue.ID)
		if err != nil {
			return err
		}
		if !found && a.State != "triage" && a.State != "draft" {
			if err := b.ig.UpdateIssue(ctx, b.issues, issue.Number, issueState(a.State)); err != nil {
				return err
			}
		}
		it = &item{id: added.ID, ghsa: a.GHSAID, issue: issue.Number, issueID: issue.ID}
		b.items[key] = it
		delete(b.unlisted, key)
	case it == nil:
		draft, err := b.gh.CreateDraft(ctx, b.org, b.number, a.Summary, body)
		if err != nil {
			return err
		}
		it = &item{id: draft.ID, draft: draft.Content.NodeID, ghsa: a.GHSAID}
		b.items[key] = it
	case comment != "" && it.issue != 0:
		if err := b.ig.UpdateIssue(ctx, b.issues, it.issue, map[string]string{"body": body + marker}); err != nil {
			return err
		}
	// An issue of another repository is no draft, and the issues token cannot write it.
	case comment != "" && it.draft != "":
		if err := b.gh.UpdateDraft(ctx, it.draft, body); err != nil {
			return err
		}
	}
	// Sync compares the advisory with the state written below, so it would leave the issue as it is.
	if st := issueState(a.State); it.issue != 0 && (it.closedAs != "duplicate" || st["state"] == "open") && it.state != "" && it.state != a.State {
		if err := b.ig.UpdateIssue(ctx, b.issues, it.issue, st); err != nil {
			return err
		}
	}
	var kept Triage
	var excluded, located string
	if t != nil {
		kept, excluded, located = *t, yes(t.Excluded), yes(t.Located)
	}
	values := []github.FieldValue{
		{ID: b.ids[fieldGHSA], Value: a.GHSAID},
		{ID: b.ids[fieldReported], Value: a.CreatedAt.UTC().Format(time.DateOnly)},
		b.option(fieldState, a.State),
		b.option(fieldPriority, priority),
		b.option(fieldSeverity, capitalize(kept.Severity)),
		{ID: b.ids[fieldDuplicateOf], Value: text(kept.DuplicateOf)},
		b.option(fieldExcluded, excluded),
		b.option(fieldLocated, located),
		{ID: b.ids[fieldComponent], Value: text(kept.Component)},
		{ID: b.ids[fieldUpstream], Value: text(kept.Upstream)},
		{ID: b.ids[fieldAttempts], Value: numberValue(attempts)},
	}
	if err := b.gh.UpdateProjectItem(ctx, b.org, b.number, it.id, values); err != nil {
		return err
	}
	it.duplicateOf, it.state, it.priority, it.triage, it.attempts = kept.DuplicateOf, a.State, priority, t, attempts
	it.reported = a.CreatedAt.UTC().Format(time.DateOnly)

	return nil
}

// numberValue sets a number field, or clears it when n is zero.
func numberValue(n int) any {
	if n == 0 {
		return nil
	}

	return n
}

// text sets a text field, or clears it when s is empty.
func text(s string) any {
	if s == "" {
		return nil
	}

	return s
}

func yes(v bool) string {
	if v {
		return "Yes"
	}

	return "No"
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}

	return strings.ToUpper(s[:1]) + s[1:]
}

// issueState keeps an issue open while its advisory waits for a decision.
func issueState(advisory string) map[string]string {
	switch advisory {
	case "triage", "draft":
		return map[string]string{"state": "open"}
	case "published":
		return map[string]string{"state": "closed", "state_reason": "completed"}
	default:
		return map[string]string{"state": "closed", "state_reason": "not_planned"}
	}
}

// oldest follows the Duplicate of chain from ghsa, since the original of a report can itself name an older one.
// It returns the identifier as the item of the original spells it, so a Duplicate of typed in another case
// lands in the same group.
func (b *Board) oldest(ghsa string) string {
	seen := map[*item]bool{}
	for {
		it := b.items[strings.ToLower(ghsa)]
		if it == nil {
			return ghsa
		}
		if it.duplicateOf == "" || seen[it] {
			return it.ghsa
		}
		seen[it] = true
		ghsa = it.duplicateOf
	}
}

// issueItem returns the item of the issue with that ID, nil when the board has none.
func (b *Board) issueItem(id int64) *item {
	for _, it := range b.items {
		if it.issueID == id {
			return it
		}
	}

	return nil
}

// nest returns the item the issue of it goes under: the oldest report of its Duplicate of chain that has an issue
// and waits for a decision. When none has, as for the duplicates of a closed original, the reports of the group
// gather under the oldest of them that has an issue and waits, and nil means it is that one.
func (b *Board) nest(it *item, states map[string]string) *item {
	if parent := b.ancestor(it, states); parent != nil || it.duplicateOf == "" {
		return parent
	}
	group := strings.ToLower(b.oldest(it.duplicateOf))
	head := it
	for _, other := range b.items {
		if other.issue == 0 || other.duplicateOf == "" || !waiting(other, states) || b.ancestor(other, states) != nil || strings.ToLower(b.oldest(other.duplicateOf)) != group {
			continue
		}
		if other.reported < head.reported || other.reported == head.reported && strings.ToLower(other.ghsa) < strings.ToLower(head.ghsa) {
			head = other
		}
	}
	if head == it {
		return nil
	}

	return head
}

// ancestor returns the oldest report of the Duplicate of chain of it that has an issue and waits for a decision,
// nil when none has. A report that no longer waits itself stays under the oldest that has an issue.
func (b *Board) ancestor(it *item, states map[string]string) *item {
	var parent *item
	decided := !waiting(it, states)
	seen := map[*item]bool{it: true}
	for ghsa := it.duplicateOf; ghsa != ""; {
		next := b.items[strings.ToLower(ghsa)]
		if next == nil || seen[next] {
			break
		}
		seen[next] = true
		if next.issue != 0 && (decided || waiting(next, states)) {
			parent = next
		}
		ghsa = next.duplicateOf
	}

	return parent
}

// stateOf returns the state of the advisory of it, the one Sync received when it has one.
func stateOf(it *item, states map[string]string) string {
	if state, ok := states[strings.ToLower(it.ghsa)]; ok {
		return state
	}

	return it.state
}

// waiting tells whether the advisory of it waits for a decision.
func waiting(it *item, states map[string]string) bool {
	state := stateOf(it, states)

	return state == "triage" || state == "draft"
}

// option sets a single select field, or clears it when the value has no option.
func (b *Board) option(field, value string) github.FieldValue {
	v := github.FieldValue{ID: b.ids[field]}
	if id := b.options[field][value]; id != "" {
		v.Value = id
	}

	return v
}

// Advisories writes the advisories, with the token of their repository.
type Advisories interface {
	GetAdvisory(ctx context.Context, repo, ghsa string) (github.Advisory, error)
	UpdateAdvisory(ctx context.Context, repo, ghsa string, fields map[string]any) error
	ListComments(ctx context.Context, repo, ghsa string) ([]github.Comment, error)
	PostComment(ctx context.Context, repo, ghsa, body string) error
}

// CloseDuplicates closes the advisory of each issue a maintainer closed as a duplicate while that advisory waits
// for a decision, and tells its reporter on it. The reporter is credited on the original report of the group when
// that one waits too. An advisory the board names no original for stays as it is. Each advisory it closes is
// marked closed in advisories, so the rest of the run sees it.
func (b *Board) CloseDuplicates(ctx context.Context, gh Advisories, repo string, advisories []github.Advisory) error {
	var errs []error
	for i, a := range advisories {
		it := b.items[strings.ToLower(a.GHSAID)]
		// An advisory whose state changed since the last run was reopened by hand, and Sync then reopens its issue.
		if it == nil || it.closedAs != "duplicate" || it.duplicateOf == "" || a.State != "triage" && a.State != "draft" || it.state != a.State {
			continue
		}
		// A Duplicate of chain edited by hand into a loop has no oldest report, the one it stops at names another.
		original := b.oldest(it.duplicateOf)
		o := b.items[strings.ToLower(original)]
		if o != nil && o.duplicateOf != "" {
			continue
		}
		oa, credited, err := closeDuplicate(ctx, gh, repo, a, original)
		if err != nil {
			errs = append(errs, fmt.Errorf("closing %s as a duplicate of %s: %w", a.GHSAID, original, err))
			continue
		}
		advisories[i].State = "closed"
		// The note comes after the close, so a close that fails again next run never posts it twice.
		note := fmt.Sprintf("Closed [%s](%s) as a duplicate of [%s](%s)", a.GHSAID, a.HTMLURL, oa.GHSAID, oa.HTMLURL)
		if o != nil && o.issue != 0 {
			note += fmt.Sprintf(" (#%d)", o.issue)
		}
		// A login in backticks notifies nobody.
		if credited != "" {
			note += fmt.Sprintf(", where `%s` has been credited as a reporter", credited)
		}
		if err := b.ig.CommentIssue(ctx, b.issues, it.issue, note+"."); err != nil {
			errs = append(errs, fmt.Errorf("noting the close of %s on its issue: %w", a.GHSAID, err))
		}
	}

	return errors.Join(errs...)
}

// LinkIssues tells each advisory whose issue this run created where the maintainers track it. An issue found
// again from a failed run is left out, since that run may have linked it already.
func (b *Board) LinkIssues(ctx context.Context, gh Advisories, repo string) error {
	var errs []error
	for ghsa, link := range b.created {
		if err := gh.PostComment(ctx, repo, ghsa, fmt.Sprintf("Tracked in %s.", link)); err != nil {
			errs = append(errs, fmt.Errorf("linking the issue of %s: %w", ghsa, err))
		}
	}

	return errors.Join(errs...)
}

// closeDuplicate comments before closing, since the next run leaves a closed advisory alone. A close that failed
// after its comment finds that comment on the next run instead of posting it again. It returns the original and
// the login credited on it, empty when the original credits nobody for it.
func closeDuplicate(ctx context.Context, gh Advisories, repo string, a github.Advisory, original string) (github.Advisory, string, error) {
	o, err := gh.GetAdvisory(ctx, repo, original)
	if err != nil {
		return o, "", err
	}
	comment := fmt.Sprintf("This report is closed as a duplicate of %s, reported earlier.", o.GHSAID)
	// A credit added by a run whose close failed keeps its sentence once the original leaves triage, so the comment
	// still matches the one already posted.
	credited := ""
	login := a.Author.Login
	switch {
	case login == "":
	case slices.ContainsFunc(o.Credits, func(c github.Credit) bool { return strings.EqualFold(c.Login, login) }):
		credited = login
	case !strings.EqualFold(login, o.Author.Login) && (o.State == "triage" || o.State == "draft"):
		credits := append(o.Credits, github.Credit{Login: login, Type: "reporter"})
		if err := gh.UpdateAdvisory(ctx, repo, o.GHSAID, map[string]any{"credits": credits}); err != nil {
			return o, "", err
		}
		credited = login
	}
	if credited != "" {
		comment += " You are credited on it as a reporter."
	}
	comments, err := gh.ListComments(ctx, repo, a.GHSAID)
	if err != nil {
		return o, "", err
	}
	if !slices.ContainsFunc(comments, func(c github.Comment) bool { return c.Body == comment }) {
		if err := gh.PostComment(ctx, repo, a.GHSAID, comment); err != nil {
			return o, "", err
		}
	}

	return o, credited, gh.UpdateAdvisory(ctx, repo, a.GHSAID, map[string]any{"state": "closed"})
}

// Sync mirrors the state of every advisory on its item, counts the duplicates of each report, gives every
// report of a duplicate group the identifier of its oldest one and ranks every triage again, so a new priority
// rule reaches the board without a model run. It only writes the items that changed.
func (b *Board) Sync(ctx context.Context, advisories []github.Advisory) error {
	states := map[string]string{}
	for _, a := range advisories {
		states[strings.ToLower(a.GHSAID)] = a.State
	}
	// With issues, Duplicates counts the sub-issues an item gets, the whole chain under it included.
	counts := map[string]int{}
	for _, it := range b.items {
		switch {
		case b.issues == "" && it.duplicateOf != "":
			counts[strings.ToLower(it.duplicateOf)]++
		case b.issues != "" && it.issue != 0:
			if parent := b.nest(it, states); parent != nil {
				counts[strings.ToLower(parent.ghsa)]++
			}
		}
	}

	var errs []error
	for ghsa, it := range b.items {
		var values []github.FieldValue
		if state, ok := states[ghsa]; ok && state != it.state {
			// An issue a maintainer closed as a duplicate keeps that reason once its advisory closes.
			if st := issueState(state); it.issue != 0 && (it.closedAs != "duplicate" || st["state"] == "open") {
				if err := b.ig.UpdateIssue(ctx, b.issues, it.issue, st); err != nil {
					errs = append(errs, err)
					continue
				}
			}
			values = append(values, b.option(fieldState, state))
			it.state = state
		}
		if it.triage != nil && it.triage.Priority() != it.priority {
			it.priority = it.triage.Priority()
			values = append(values, b.option(fieldPriority, it.priority))
		}
		if counts[ghsa] != it.duplicates {
			it.duplicates = counts[ghsa]
			values = append(values, github.FieldValue{ID: b.ids[fieldDuplicates], Value: it.duplicates})
		}
		group := ""
		switch {
		case it.duplicateOf != "":
			group = b.oldest(it.duplicateOf)
		case counts[ghsa] > 0:
			group = it.ghsa
		}
		// The group is only written once the sub-issue is linked, so a failed link is tried again next run.
		// The group can predate the issue of its original, so the link follows the parent the issue has.
		if parent := b.nest(it, states); it.issue != 0 && parent != nil && it.parent != parent.issueID {
			if err := b.ig.AddSubIssue(ctx, b.issues, parent.issue, it.issueID); err != nil {
				errs = append(errs, err)
				group = it.group
			} else {
				it.parent = parent.issueID
			}
		} else if it.issue != 0 && parent == nil && it.parent != 0 {
			// A report that is no longer a duplicate, or now heads a group whose original left triage, leaves the issue
			// it was nested under, when that one is known. The note on this issue comes first, so a failed one is
			// posted again next run.
			if old := b.issueItem(it.parent); old != nil {
				var err error
				if it.duplicateOf != "" && waiting(it, states) && !waiting(old, states) {
					err = b.ig.CommentIssue(ctx, b.issues, it.issue, fmt.Sprintf("%s, the report this issue was a sub-issue of, is now %s. The duplicates of its group still in triage or draft gather under the oldest of them, this issue.", old.ghsa, stateOf(old, states)))
				}
				if err == nil {
					err = b.ig.RemoveSubIssue(ctx, b.issues, old.issue, it.issueID)
				}
				if err != nil {
					errs = append(errs, err)
				} else {
					it.parent = 0
				}
			}
		}
		if group != it.group {
			it.group = group
			values = append(values, github.FieldValue{ID: b.ids[fieldGroup], Value: text(group)})
		}
		if len(values) == 0 {
			continue
		}
		if err := b.gh.UpdateProjectItem(ctx, b.org, b.number, it.id, values); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
