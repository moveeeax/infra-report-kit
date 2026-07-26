package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

func load(t *testing.T, name string) (*model.Report, Adapter) {
	t.Helper()
	a, err := Get(name)
	if err != nil {
		t.Fatalf("Get(%q): %v", name, err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	r := model.New("Northwind",
		model.Account{Provider: "aws", ID: "123456789012"},
		model.Period{Label: "2026-06"},
		time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC))
	if err := a.Parse(raw, r); err != nil {
		t.Fatalf("%s.Parse: %v", name, err)
	}
	return r, a
}

// find returns the single finding whose resource ID matches, failing if there
// is not exactly one.
func find(t *testing.T, r *model.Report, resourceID string) model.Finding {
	t.Helper()
	var hits []model.Finding
	for _, f := range r.Findings {
		if f.Resource.ID == resourceID {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 finding for resource %q, got %d", resourceID, len(hits))
	}
	return hits[0]
}

func TestEveryAdapterHandlesEmptyDocument(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			a, err := Get(name)
			if err != nil {
				t.Fatal(err)
			}
			r := model.New("t", model.Account{ID: "1"}, model.Period{}, time.Now())
			if err := a.Parse([]byte(`{}`), r); err != nil {
				t.Fatalf("empty document must not error: %v", err)
			}
			if len(r.Findings) != 0 {
				t.Fatalf("empty document produced %d findings", len(r.Findings))
			}
		})
	}
}

func TestEveryAdapterRejectsGarbage(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			a, _ := Get(name)
			r := model.New("t", model.Account{ID: "1"}, model.Period{}, time.Now())
			if err := a.Parse([]byte(`not json at all`), r); err == nil {
				t.Fatal("want an error for malformed input, got nil")
			}
		})
	}
}

func TestGetUnknownAdapter(t *testing.T) {
	if _, err := Get("prowler"); err == nil {
		t.Fatal("want an error for an unregistered adapter")
	}
}

func TestCostExport(t *testing.T) {
	r, _ := load(t, "cost-export")
	if len(r.Findings) != 0 {
		t.Errorf("cost-export must emit no findings, got %d", len(r.Findings))
	}
	if got, want := r.Cost.CurrentUSD, 7927.43; !approx(got, want) {
		t.Errorf("current spend = %.2f, want %.2f", got, want)
	}
	if got, want := r.Cost.PreviousUSD, 7228.62; !approx(got, want) {
		t.Errorf("previous spend = %.2f, want %.2f", got, want)
	}
	if got, want := r.Cost.DeltaUSD(), 698.81; !approx(got, want) {
		t.Errorf("delta = %.2f, want %.2f", got, want)
	}
	top := r.Cost.TopServicesByDelta(2)
	if top[0].Service != "Amazon EC2" {
		t.Errorf("largest mover = %q, want Amazon EC2 (+430.12)", top[0].Service)
	}
	if top[1].Service != "AWS Data Transfer" {
		t.Errorf("second mover = %q, want AWS Data Transfer (+272.74)", top[1].Service)
	}
}

func TestOrphanFinder(t *testing.T) {
	r, _ := load(t, "aws-orphan-finder")
	if len(r.Findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(r.Findings))
	}
	vol := find(t, r, "vol-0a1b2c3d4e5f60718")
	if vol.Section != model.SectionCost {
		t.Errorf("orphans belong in the cost section, got %q", vol.Section)
	}
	if vol.Severity != model.SeverityHigh {
		t.Errorf("$128.40/month must grade high, got %q", vol.Severity)
	}
	if vol.MonthlyCostUSD != 128.40 {
		t.Errorf("cost = %.2f, want 128.40", vol.MonthlyCostUSD)
	}
	if vol.Resource.Account != "123456789012" {
		t.Errorf("account = %q, want the scanned account", vol.Resource.Account)
	}

	eip := find(t, r, "eipalloc-0f1e2d3c")
	if eip.Severity != model.SeverityLow {
		t.Errorf("$3.60/month must grade low, got %q", eip.Severity)
	}
	alb := find(t, r, "app/legacy-api/6a1f")
	if alb.Severity != model.SeverityMedium {
		t.Errorf("$26.15/month must grade medium, got %q", alb.Severity)
	}

	if got, want := totalCost(r), 169.20; !approx(got, want) {
		t.Errorf("total attached spend = %.2f, want %.2f", got, want)
	}
}

func TestSGAudit(t *testing.T) {
	r, _ := load(t, "aws-sg-audit")
	if len(r.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (the group with no open rules must be silent)", len(r.Findings))
	}
	ssh := find(t, r, "sg-0aa11bb22cc33dd44")
	if ssh.Severity != model.SeverityCritical {
		t.Errorf("world-open SSH must be critical, got %q", ssh.Severity)
	}
	if !strings.Contains(ssh.Detail, "port 22 (SSH)") {
		t.Errorf("detail %q must name the exposed service", ssh.Detail)
	}

	web := find(t, r, "sg-0ee55ff66aa77bb88")
	if web.Severity != model.SeverityHigh {
		t.Errorf("world-open 8080 is high, not critical; got %q", web.Severity)
	}

	db := find(t, r, "sg-0cc99dd00ee11ff22")
	if db.Severity != model.SeverityCritical {
		t.Errorf("a full port range open to the world must be critical, got %q", db.Severity)
	}
	if db.Resource.Region != "eu-central-1" {
		t.Errorf("region = %q, want eu-central-1", db.Resource.Region)
	}
	if db.Evidence["open_rules"] != "2" {
		t.Errorf("evidence open_rules = %q, want 2", db.Evidence["open_rules"])
	}
}

func TestClassifyRule(t *testing.T) {
	cases := []struct {
		proto    string
		from, to int
		wantSev  model.Severity
		wantName string
	}{
		{"tcp", 22, 22, model.SeverityCritical, "port 22 (SSH)"},
		{"tcp", 3389, 3389, model.SeverityCritical, "port 3389 (RDP)"},
		{"tcp", 443, 443, model.SeverityHigh, "port 443"},
		{"tcp", 8000, 9000, model.SeverityCritical, "ports 8000-9000"},
		{"-1", 0, 0, model.SeverityCritical, "all ports"},
		{"all", 100, 100, model.SeverityCritical, "all ports"},
	}
	for _, c := range cases {
		name, sev := classifyRule(c.proto, c.from, c.to)
		if sev != c.wantSev || name != c.wantName {
			t.Errorf("classifyRule(%q,%d,%d) = (%q,%q), want (%q,%q)",
				c.proto, c.from, c.to, name, sev, c.wantName, c.wantSev)
		}
	}
}

func TestS3PublicAudit(t *testing.T) {
	r, _ := load(t, "s3-public-audit")
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (the locked-down bucket must be silent)", len(r.Findings))
	}
	pub := find(t, r, "acme-public-assets")
	if pub.Severity != model.SeverityCritical || pub.Rule != "public-bucket" {
		t.Errorf("public bucket graded %q/%q, want critical/public-bucket", pub.Severity, pub.Rule)
	}
	if pub.Evidence["public_objects"] != "1284" {
		t.Errorf("public_objects = %q, want 1284", pub.Evidence["public_objects"])
	}

	state := find(t, r, "acme-terraform-state")
	if state.Severity != model.SeverityMedium || state.Rule != "block-public-access-off" {
		t.Errorf("BPA-off-but-private bucket graded %q/%q, want medium/block-public-access-off",
			state.Severity, state.Rule)
	}
}

func TestIAMLeastPriv(t *testing.T) {
	r, _ := load(t, "aws-iam-least-priv")
	if len(r.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (the read-only role must be silent)", len(r.Findings))
	}
	dormant := find(t, r, "arn:aws:iam::123456789012:user/contractor-2023")
	if dormant.Severity != model.SeverityCritical || dormant.Rule != "dormant-admin" {
		t.Errorf("411-day dormant admin graded %q/%q, want critical/dormant-admin",
			dormant.Severity, dormant.Rule)
	}
	active := find(t, r, "arn:aws:iam::123456789012:role/DeployRole")
	if active.Severity != model.SeverityHigh || active.Rule != "standing-admin" {
		t.Errorf("recently used admin graded %q/%q, want high/standing-admin", active.Severity, active.Rule)
	}
	unused := find(t, r, "arn:aws:iam::123456789012:role/AppRuntime")
	if unused.Severity != model.SeverityLow || unused.Rule != "unused-permissions" {
		t.Errorf("non-admin with unused services graded %q/%q, want low/unused-permissions",
			unused.Severity, unused.Rule)
	}
	if unused.Evidence["unused_services"] != "rds,kms,sagemaker,redshift" {
		t.Errorf("unused_services evidence = %q", unused.Evidence["unused_services"])
	}
}

func TestCertCheck(t *testing.T) {
	r, _ := load(t, "certcheck")
	if len(r.Findings) != 3 {
		t.Fatalf("got %d findings, want 3 (189 days out is not news)", len(r.Findings))
	}
	expired := find(t, r, "legacy.example.com:443")
	if expired.Severity != model.SeverityCritical {
		t.Errorf("an expired certificate must be critical, got %q", expired.Severity)
	}
	if !strings.Contains(expired.Title, "has expired") {
		t.Errorf("title %q must say the certificate expired, not that it expires in -8 days", expired.Title)
	}
	soon := find(t, r, "api.example.com:443")
	if soon.Severity != model.SeverityCritical {
		t.Errorf("5 days remaining must be critical, got %q", soon.Severity)
	}
	acm := find(t, r, "arn:aws:acm:eu-west-1:123456789012:certificate/EXAMPLEID")
	if acm.Severity != model.SeverityMedium {
		t.Errorf("43 days remaining must be medium, got %q", acm.Severity)
	}
	if acm.Resource.Provider != "aws" {
		t.Errorf("an ACM certificate is an aws resource, got provider %q", acm.Resource.Provider)
	}
}

func TestUptimePing(t *testing.T) {
	r, _ := load(t, "uptime-ping")
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (99.988%% is above target and must be silent)", len(r.Findings))
	}
	api := find(t, r, "https://api.example.com/health")
	if api.Severity != model.SeverityMedium {
		t.Errorf("99.745%% graded %q, want medium", api.Severity)
	}
	checkout := find(t, r, "https://checkout.example.com/health")
	if checkout.Severity != model.SeverityCritical {
		t.Errorf("94.676%% graded %q, want critical", checkout.Severity)
	}
	if checkout.Section != model.SectionReliability {
		t.Errorf("section = %q, want reliability", checkout.Section)
	}
}

func TestUptimeSeverityBands(t *testing.T) {
	cases := []struct {
		pct  float64
		want model.Severity
	}{
		{99.899, model.SeverityMedium},
		{99.500, model.SeverityMedium},
		{99.499, model.SeverityHigh},
		{99.000, model.SeverityHigh},
		{98.999, model.SeverityCritical},
		{94.676, model.SeverityCritical},
	}
	for _, c := range cases {
		if got := uptimeSeverity(c.pct); got != c.want {
			t.Errorf("uptimeSeverity(%.3f) = %q, want %q", c.pct, got, c.want)
		}
	}
}

func TestSLOCalc(t *testing.T) {
	r, _ := load(t, "slo-calc")
	if len(r.SLOs) != 3 {
		t.Fatalf("got %d SLO rows, want all 3 including the one that was met", len(r.SLOs))
	}
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (a met SLO is a table row, not a finding)", len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.Severity != model.SeverityHigh {
			t.Errorf("%s: exhausted error budget must grade high, got %q", f.Resource.ID, f.Severity)
		}
	}
}

func TestK8sCrashloop(t *testing.T) {
	r, _ := load(t, "k8s-crashloop")
	if len(r.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(r.Findings))
	}
	settlement := find(t, r, "acme-prod-eu-west-1/payments/Deployment/settlement")
	if settlement.Severity != model.SeverityHigh {
		t.Errorf("214 restarts graded %q, want high", settlement.Severity)
	}
	if !strings.Contains(settlement.Recommendation, "OOM-killed") {
		t.Errorf("exit code 137 must produce the OOM hint, got %q", settlement.Recommendation)
	}
	indexer := find(t, r, "acme-prod-eu-west-1/search/StatefulSet/indexer")
	if indexer.Severity != model.SeverityMedium {
		t.Errorf("14 restarts graded %q, want medium", indexer.Severity)
	}
	if strings.Contains(indexer.Recommendation, "OOM-killed") {
		t.Error("exit code 1 must not produce the OOM hint")
	}
	frontend := find(t, r, "acme-prod-eu-west-1/web/Deployment/frontend")
	if frontend.Severity != model.SeverityLow {
		t.Errorf("3 restarts graded %q, want low", frontend.Severity)
	}
}

func TestK8sRightsize(t *testing.T) {
	r, _ := load(t, "k8s-rightsize")
	if len(r.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.Section != model.SectionCost {
			t.Errorf("%s: rightsizing is a cost finding, got section %q", f.Resource.ID, f.Section)
		}
	}
	settlement := find(t, r, "acme-prod-eu-west-1/payments/Deployment/settlement")
	if settlement.Severity != model.SeverityHigh {
		t.Errorf("$186.40/month graded %q, want high", settlement.Severity)
	}
	if !strings.Contains(settlement.Title, "11.1x") {
		t.Errorf("title %q must state the over-provisioning ratio (2000m / 180m)", settlement.Title)
	}
	if got, want := totalCost(r), 237.05; !approx(got, want) {
		t.Errorf("total saving = %.2f, want %.2f", got, want)
	}
}

func TestRatioHandlesZeroUsage(t *testing.T) {
	if got := ratio(2000, 0); got != 0 {
		t.Errorf("ratio with zero p95 = %v, want 0 rather than +Inf on a client page", got)
	}
}

func TestCompactDropsEmptyValues(t *testing.T) {
	if got := compact(map[string]string{"a": "", "b": ""}); got != nil {
		t.Errorf("all-empty evidence = %v, want nil so it disappears from the JSON", got)
	}
	got := compact(map[string]string{"a": "1", "b": ""})
	if len(got) != 1 || got["a"] != "1" {
		t.Errorf("compact = %v, want only the non-empty key", got)
	}
}

func totalCost(r *model.Report) float64 {
	var t float64
	for _, f := range r.Findings {
		t += f.MonthlyCostUSD
	}
	return t
}

func approx(a, b float64) bool {
	d := a - b
	return d < 0.005 && d > -0.005
}
