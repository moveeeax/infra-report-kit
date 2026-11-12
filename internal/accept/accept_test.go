package accept

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

var july = time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

func report(at time.Time, ids ...string) *model.Report {
	r := model.New("Northwind", model.Account{Provider: "aws", ID: "123456789012"},
		model.Period{Label: "2026-06"}, at)
	for _, id := range ids {
		r.Add(model.Finding{ID: id, Severity: model.SeverityCritical, Title: "finding " + id})
	}
	return r
}

func mustParse(t *testing.T, doc string) *Register {
	t.Helper()
	reg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return reg
}

func ids(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestParseValid(t *testing.T) {
	reg := mustParse(t, `[
	  {"fingerprint": "a", "reason": "intended", "accepted_by": "J. Okafor", "expires": "2026-12-31"},
	  {"fingerprint": "b", "reason": "audit hold", "accepted_by": "M. Lindqvist", "expires": "2026-06-15"}
	]`)
	if reg.Len() != 2 {
		t.Fatalf("Len = %d, want 2", reg.Len())
	}
}

func TestParseReportsEveryProblemAtOnce(t *testing.T) {
	_, err := Parse([]byte(`[
	  {"fingerprint": "", "reason": "", "accepted_by": "", "expires": "next year"},
	  {"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-12-31"},
	  {"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-12-31"}
	]`))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"[0]: fingerprint", "[0]: reason", "[0]: accepted_by", "[0]: expires", "[2]: fingerprint \"a\" is already accepted by entry [1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestParseRequiresAnExpiry(t *testing.T) {
	// An acceptance with no end date is a finding nobody looks at again.
	_, err := Parse([]byte(`[{"fingerprint": "a", "reason": "r", "accepted_by": "x"}]`))
	if err == nil || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("err = %v, want a missing expiry rejected", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`[{"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-12-31", "expiry": "2027-01-01"}]`))
	if err == nil {
		t.Fatal("want a typo in a field name rejected, not silently ignored")
	}
}

func TestParseRejectsNonArray(t *testing.T) {
	if _, err := Parse([]byte(`{"fingerprint": "a"}`)); err == nil {
		t.Fatal("want an error: the register is a JSON array")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accepted.json")
	doc := `[{"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-12-31"}]`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reg.Len() != 1 {
		t.Errorf("Len = %d, want 1", reg.Len())
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("want an error for a missing register")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`[{"fingerprint": "a"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("err = %v, want it to name the file", err)
	}
}

func TestApplyMovesActiveAcceptancesOut(t *testing.T) {
	rep := report(july, "kept", "accepted", "also-kept")
	reg := mustParse(t, `[{"fingerprint": "accepted", "reason": "intended", "accepted_by": "J. Okafor", "expires": "2026-12-31"}]`)

	if w := Apply(rep, reg); len(w) != 0 {
		t.Errorf("warnings = %v, want none", w)
	}
	if got := ids(rep.Findings); strings.Join(got, ",") != "kept,also-kept" {
		t.Errorf("findings = %v, want kept,also-kept in their original order", got)
	}
	if len(rep.Accepted) != 1 || rep.Accepted[0].ID != "accepted" {
		t.Fatalf("accepted = %v, want only the accepted finding", ids(rep.Accepted))
	}
	a := rep.Accepted[0].Acceptance
	if a == nil || a.Reason != "intended" || a.AcceptedBy != "J. Okafor" || a.Expired {
		t.Fatalf("acceptance = %+v", a)
	}
	if !a.Expires.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("expires = %v, want 31 December 2026 UTC", a.Expires)
	}
	if rep.SeverityCounts()[model.SeverityCritical] != 2 {
		t.Errorf("severity totals still count the accepted finding: %v", rep.SeverityCounts())
	}
}

func TestApplyExpiredAcceptanceStaysOpenForReReview(t *testing.T) {
	rep := report(july, "lapsed")
	reg := mustParse(t, `[{"fingerprint": "lapsed", "reason": "audit hold", "accepted_by": "M. Lindqvist", "expires": "2026-06-15"}]`)
	Apply(rep, reg)

	if len(rep.Accepted) != 0 {
		t.Fatalf("accepted = %v, want none: the acceptance ran out", ids(rep.Accepted))
	}
	if len(rep.Findings) != 1 || !rep.Findings[0].NeedsReReview() {
		t.Fatalf("findings = %+v, want the finding back with a re-review flag", rep.Findings)
	}
	if rep.Findings[0].Acceptance.Reason != "audit hold" {
		t.Error("the expired acceptance lost its reason; the re-review needs it")
	}
}

func TestExpiryDayIsStillCovered(t *testing.T) {
	reg := `[{"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-07-03"}]`
	cases := []struct {
		at      time.Time
		expired bool
	}{
		{time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC), false},
		{time.Date(2026, 7, 3, 23, 59, 59, 0, time.UTC), false},
		{time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC), true},
	}
	for _, c := range cases {
		rep := report(c.at, "a")
		Apply(rep, mustParse(t, reg))
		if got := len(rep.Accepted) == 0; got != c.expired {
			t.Errorf("at %v: expired = %v, want %v", c.at, got, c.expired)
		}
	}
}

func TestApplyWarnsAboutStaleEntries(t *testing.T) {
	rep := report(july, "a")
	reg := mustParse(t, `[
	  {"fingerprint": "a", "reason": "r", "accepted_by": "x", "expires": "2026-12-31"},
	  {"fingerprint": "gone", "reason": "r", "accepted_by": "x", "expires": "2026-12-31"}
	]`)
	w := Apply(rep, reg)
	if len(w) != 1 || !strings.Contains(w[0], `"gone"`) {
		t.Fatalf("warnings = %v, want one naming the stale entry", w)
	}
}

func TestApplyWithNilRegisterIsANoOp(t *testing.T) {
	rep := report(july, "a")
	if w := Apply(rep, nil); w != nil {
		t.Errorf("warnings = %v", w)
	}
	if len(rep.Findings) != 1 || rep.Accepted != nil {
		t.Errorf("report changed: %+v", rep)
	}
	Apply(nil, mustParse(t, `[]`))
}
