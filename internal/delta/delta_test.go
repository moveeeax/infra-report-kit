package delta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

var (
	march = time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	june  = time.Date(2026, 6, 3, 9, 0, 0, 0, time.UTC)
	july  = time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)
)

func report(label string, at time.Time, fs ...model.Finding) *model.Report {
	r := model.New("Northwind", model.Account{Provider: "aws", ID: "123456789012"},
		model.Period{Label: label}, at)
	r.Findings = fs
	return r
}

func finding(id string, cost float64, firstSeen time.Time, status model.Status) model.Finding {
	return model.Finding{
		ID: id, Source: "aws-sg-audit", Rule: "world-open-ingress",
		Section: model.SectionSecurity, Severity: model.SeverityCritical,
		Title: "finding " + id, MonthlyCostUSD: cost, FirstSeen: firstSeen, Status: status,
	}
}

func TestApplyWithoutPreviousMarksEverythingNew(t *testing.T) {
	cur := report("2026-06", july, finding("a", 0, july, ""), finding("b", 0, july, ""))
	Apply(cur, nil)

	if cur.Delta.New != 2 || cur.Delta.Open != 0 || cur.Delta.Resolved != 0 {
		t.Fatalf("delta = %+v, want 2 new and nothing else", cur.Delta)
	}
	for _, f := range cur.Findings {
		if f.Status != model.StatusNew {
			t.Errorf("%s status = %q, want new", f.ID, f.Status)
		}
	}
}

func TestApplyClassifiesNewOpenAndResolved(t *testing.T) {
	prev := report("2026-05", june,
		finding("still-open", 0, march, model.StatusOpen),
		finding("fixed", 47.30, march, model.StatusOpen),
	)
	cur := report("2026-06", july,
		finding("still-open", 0, july, ""),
		finding("brand-new", 12, july, ""),
	)
	Apply(cur, prev)

	d := cur.Delta
	if d.PreviousPeriod != "2026-05" {
		t.Errorf("previous period = %q, want 2026-05", d.PreviousPeriod)
	}
	if d.New != 1 || d.Open != 1 || d.Resolved != 1 {
		t.Fatalf("delta = %+v, want 1 new, 1 open, 1 resolved", d)
	}
	if d.ResolvedSavings != 47.30 {
		t.Errorf("resolved savings = %.2f, want 47.30", d.ResolvedSavings)
	}
	if len(d.ResolvedList) != 1 || d.ResolvedList[0].ID != "fixed" {
		t.Fatalf("resolved list = %+v", d.ResolvedList)
	}
	if d.ResolvedList[0].Status != model.StatusResolved {
		t.Errorf("resolved finding status = %q, want resolved", d.ResolvedList[0].Status)
	}
}

func TestApplyCarriesFirstSeenForward(t *testing.T) {
	prev := report("2026-05", june, finding("old", 0, march, model.StatusOpen))
	cur := report("2026-06", july, finding("old", 0, july, ""))
	Apply(cur, prev)

	if !cur.Findings[0].FirstSeen.Equal(march) {
		t.Fatalf("first_seen = %v, want the March date carried forward so the age is real",
			cur.Findings[0].FirstSeen)
	}
}

func TestAlreadyResolvedFindingsAreNotResurrected(t *testing.T) {
	// Last month's report carried a resolved entry. It must not come back as
	// "resolved again" this month, and it must not count as a baseline.
	prev := report("2026-05", june,
		finding("open-one", 0, march, model.StatusOpen),
		finding("closed-last-month", 99, march, model.StatusResolved),
	)
	cur := report("2026-06", july, finding("open-one", 0, july, ""))
	Apply(cur, prev)

	if cur.Delta.Resolved != 0 {
		t.Fatalf("resolved = %d, want 0: last month's resolved entry is history",
			cur.Delta.Resolved)
	}
	if cur.Delta.ResolvedSavings != 0 {
		t.Errorf("resolved savings = %.2f, want 0 (double counting a saving inflates the invoice)",
			cur.Delta.ResolvedSavings)
	}
}

func TestResolvedListIsSortedBySaving(t *testing.T) {
	prev := report("2026-05", june,
		finding("small", 3, march, model.StatusOpen),
		finding("large", 300, march, model.StatusOpen),
		finding("medium", 30, march, model.StatusOpen),
	)
	cur := report("2026-06", july)
	Apply(cur, prev)

	want := []string{"large", "medium", "small"}
	for i, id := range want {
		if cur.Delta.ResolvedList[i].ID != id {
			t.Fatalf("position %d = %q, want %q", i, cur.Delta.ResolvedList[i].ID, id)
		}
	}
}

func TestApplyOnNilReportIsSafe(t *testing.T) {
	Apply(nil, report("2026-05", june))
}

func TestNewFindings(t *testing.T) {
	cur := report("2026-06", july,
		finding("a", 0, july, model.StatusNew),
		finding("b", 0, july, model.StatusOpen),
	)
	got := NewFindings(cur)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("NewFindings = %+v, want only a", got)
	}
}

func TestLoadReportRejectsFutureSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	raw, _ := json.Marshal(map[string]any{"schema_version": model.SchemaVersion + 1})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil {
		t.Fatal("want an error for a findings file written by a newer build")
	}
}

func TestLoadReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	orig := report("2026-05", june, finding("a", 12.5, march, model.StatusOpen))
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].MonthlyCostUSD != 12.5 {
		t.Fatalf("round trip lost data: %+v", got.Findings)
	}
	if !got.Findings[0].FirstSeen.Equal(march) {
		t.Errorf("first_seen did not survive the round trip: %v", got.Findings[0].FirstSeen)
	}
}

func accepted(f model.Finding, expires time.Time) model.Finding {
	f.Acceptance = &model.Acceptance{Reason: "intended", AcceptedBy: "J. Okafor", Expires: expires}
	return f
}

func TestNewlyAcceptedFindingIsNotResolved(t *testing.T) {
	// Accepting a finding moves it out of the open list. It must not read as
	// resolved, or the report claims a saving nobody made.
	prev := report("2026-05", june, finding("bucket", 20, march, model.StatusOpen))
	cur := report("2026-06", july)
	cur.Accepted = []model.Finding{accepted(finding("bucket", 20, july, ""), july.AddDate(0, 6, 0))}
	Apply(cur, prev)

	d := cur.Delta
	if d.Resolved != 0 || d.ResolvedSavings != 0 {
		t.Fatalf("delta = %+v, want nothing resolved", d)
	}
	if d.New != 0 || d.Open != 0 || d.Accepted != 1 {
		t.Fatalf("delta = %+v, want 0 new, 0 open, 1 accepted", d)
	}
	if len(d.NewlyAccepted) != 1 || d.NewlyAccepted[0].ID != "bucket" {
		t.Fatalf("newly accepted = %+v", d.NewlyAccepted)
	}
	if cur.Accepted[0].Status != model.StatusOpen || !cur.Accepted[0].FirstSeen.Equal(march) {
		t.Errorf("accepted finding = %+v, want open with first_seen carried forward", cur.Accepted[0])
	}
}

func TestAcceptanceCarriedOverIsNotATransition(t *testing.T) {
	prev := report("2026-05", june)
	prev.Accepted = []model.Finding{accepted(finding("bucket", 0, march, model.StatusOpen), july.AddDate(0, 6, 0))}
	cur := report("2026-06", july)
	cur.Accepted = []model.Finding{accepted(finding("bucket", 0, july, ""), july.AddDate(0, 6, 0))}
	Apply(cur, prev)

	d := cur.Delta
	if d.Accepted != 1 || len(d.NewlyAccepted) != 0 || len(d.Reopened) != 0 || d.Resolved != 0 {
		t.Fatalf("delta = %+v, want 1 accepted and no transitions", d)
	}
}

func TestExpiredAcceptanceReopens(t *testing.T) {
	prev := report("2026-05", june)
	prev.Accepted = []model.Finding{accepted(finding("snapshot", 11.05, march, model.StatusOpen), june.AddDate(0, 0, 12))}
	lapsed := accepted(finding("snapshot", 11.05, july, ""), june.AddDate(0, 0, 12))
	lapsed.Acceptance.Expired = true
	cur := report("2026-06", july, lapsed)
	Apply(cur, prev)

	d := cur.Delta
	if d.Open != 1 || d.New != 0 || d.Accepted != 0 {
		t.Fatalf("delta = %+v, want the finding counted as open, not new", d)
	}
	if len(d.Reopened) != 1 || d.Reopened[0].ID != "snapshot" || !d.Reopened[0].NeedsReReview() {
		t.Fatalf("reopened = %+v, want the lapsed acceptance", d.Reopened)
	}
	if !cur.Findings[0].FirstSeen.Equal(march) {
		t.Errorf("first_seen = %v, want March carried through the accepted months", cur.Findings[0].FirstSeen)
	}
}

func TestWithdrawnAcceptanceReopens(t *testing.T) {
	prev := report("2026-05", june)
	prev.Accepted = []model.Finding{accepted(finding("bucket", 0, march, model.StatusOpen), july.AddDate(0, 6, 0))}
	cur := report("2026-06", july, finding("bucket", 0, july, ""))
	Apply(cur, prev)

	if len(cur.Delta.Reopened) != 1 || cur.Delta.Reopened[0].Acceptance != nil {
		t.Fatalf("reopened = %+v, want the finding with no acceptance attached", cur.Delta.Reopened)
	}
}

func TestAcceptedFindingThatDisappearsIsResolved(t *testing.T) {
	prev := report("2026-05", june)
	prev.Accepted = []model.Finding{accepted(finding("snapshot", 11.05, march, model.StatusOpen), july.AddDate(0, 6, 0))}
	cur := report("2026-06", july)
	Apply(cur, prev)

	if cur.Delta.Resolved != 1 || cur.Delta.ResolvedSavings != 11.05 {
		t.Fatalf("delta = %+v, want the deleted snapshot resolved with its saving", cur.Delta)
	}
}

func TestApplyWithoutPreviousCountsAcceptedSeparately(t *testing.T) {
	cur := report("2026-06", july, finding("a", 0, july, ""))
	cur.Accepted = []model.Finding{accepted(finding("b", 0, july, ""), july.AddDate(0, 6, 0))}
	Apply(cur, nil)

	d := cur.Delta
	if d.New != 1 || d.Accepted != 1 || len(d.NewlyAccepted) != 1 {
		t.Fatalf("delta = %+v, want 1 new and 1 newly accepted", d)
	}
	if cur.Accepted[0].Status != model.StatusNew {
		t.Errorf("accepted status = %q, want new", cur.Accepted[0].Status)
	}
}
