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
