package model

import (
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC) }

func newReport() *Report {
	return New("Northwind", Account{Provider: "aws", ID: "123456789012"},
		Period{Label: "2026-06"}, fixedNow())
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": SeverityCritical,
		"crit":     SeverityCritical,
		"High":     SeverityHigh,
		"error":    SeverityHigh,
		" warn ":   SeverityMedium,
		"minor":    SeverityLow,
		"":         SeverityInfo,
		"banana":   SeverityInfo,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortOrdersBySeverityThenCost(t *testing.T) {
	r := newReport()
	r.Add(Finding{Source: "s", Rule: "cheap", Severity: SeverityHigh, MonthlyCostUSD: 5,
		Resource: Resource{Provider: "aws", Type: "t", ID: "a"}})
	r.Add(Finding{Source: "s", Rule: "expensive", Severity: SeverityHigh, MonthlyCostUSD: 500,
		Resource: Resource{Provider: "aws", Type: "t", ID: "b"}})
	r.Add(Finding{Source: "s", Rule: "worst", Severity: SeverityCritical,
		Resource: Resource{Provider: "aws", Type: "t", ID: "c"}})
	r.Add(Finding{Source: "s", Rule: "quiet", Severity: SeverityLow, MonthlyCostUSD: 9000,
		Resource: Resource{Provider: "aws", Type: "t", ID: "d"}})
	r.Sort()

	want := []string{"worst", "expensive", "cheap", "quiet"}
	for i, rule := range want {
		if r.Findings[i].Rule != rule {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, r.Findings[i].Rule, rule, rules(r))
		}
	}
}

func rules(r *Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestDedupeKeepsHighestCost(t *testing.T) {
	r := newReport()
	res := Resource{Provider: "aws", Region: "eu-west-1", Type: "ec2:volume", ID: "vol-1"}
	r.Add(Finding{Source: "aws-orphan-finder", Rule: "orphaned-resource", Resource: res, MonthlyCostUSD: 12})
	r.Add(Finding{Source: "aws-orphan-finder", Rule: "orphaned-resource", Resource: res, MonthlyCostUSD: 40})
	r.Add(Finding{Source: "aws-orphan-finder", Rule: "orphaned-resource", Resource: res, MonthlyCostUSD: 7})
	r.Add(Finding{Source: "aws-sg-audit", Rule: "orphaned-resource", Resource: res, MonthlyCostUSD: 1})
	r.Dedupe()

	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings after dedupe, want 2", len(r.Findings))
	}
	if r.Findings[0].MonthlyCostUSD != 40 {
		t.Errorf("kept cost %.2f, want the largest (40)", r.Findings[0].MonthlyCostUSD)
	}
}

func TestNewIDIsStableAcrossCostChanges(t *testing.T) {
	res := Resource{Provider: "aws", Region: "eu-west-1", Type: "ec2:volume", ID: "vol-1"}
	a := NewID("aws-orphan-finder", "orphaned-resource", res)
	b := NewID("aws-orphan-finder", "orphaned-resource", res)
	if a != b {
		t.Fatalf("fingerprint is not deterministic: %q vs %q", a, b)
	}
	want := "aws-orphan-finder:orphaned-resource:aws/eu-west-1/ec2:volume/vol-1"
	if a != want {
		t.Errorf("NewID = %q, want %q", a, want)
	}
}

func TestTopWasteExcludesFreeFindings(t *testing.T) {
	r := newReport()
	r.Add(Finding{Source: "s", Rule: "a", MonthlyCostUSD: 10, Resource: Resource{ID: "a"}})
	r.Add(Finding{Source: "s", Rule: "b", MonthlyCostUSD: 0, Resource: Resource{ID: "b"}})
	r.Add(Finding{Source: "s", Rule: "c", MonthlyCostUSD: 99, Resource: Resource{ID: "c"}})

	top := r.TopWaste(5)
	if len(top) != 2 {
		t.Fatalf("got %d waste items, want 2 (the $0 finding must not appear)", len(top))
	}
	if top[0].MonthlyCostUSD != 99 {
		t.Errorf("top waste is $%.2f, want the largest ($99)", top[0].MonthlyCostUSD)
	}
	if got := r.IdentifiedWasteUSD(); got != 109 {
		t.Errorf("IdentifiedWasteUSD = %.2f, want 109", got)
	}
}

func TestTopServicesByDeltaRanksByAbsoluteMovement(t *testing.T) {
	c := CostSummary{Services: []ServiceCost{
		{Service: "EC2", CurrentUSD: 100, PreviousUSD: 90},  // +10
		{Service: "S3", CurrentUSD: 10, PreviousUSD: 90},    // -80
		{Service: "RDS", CurrentUSD: 200, PreviousUSD: 180}, // +20
		{Service: "CW", CurrentUSD: 5, PreviousUSD: 5},      // 0
	}}
	top := c.TopServicesByDelta(2)
	if len(top) != 2 {
		t.Fatalf("got %d services, want 2", len(top))
	}
	if top[0].Service != "S3" || top[1].Service != "RDS" {
		t.Errorf("ranking = %s, %s; want S3 (-80) then RDS (+20)", top[0].Service, top[1].Service)
	}
}

func TestSortMakesTheSpendTableDeterministic(t *testing.T) {
	// Adapters build the spend table from a map, so without an explicit sort
	// findings.json reshuffles between identical runs and cannot be diffed.
	r := newReport()
	r.Cost.Services = []ServiceCost{
		{Service: "Amazon S3"}, {Service: "Amazon EC2"}, {Service: "AWS Data Transfer"},
	}
	r.Sort()
	want := []string{"AWS Data Transfer", "Amazon EC2", "Amazon S3"}
	for i, s := range want {
		if r.Cost.Services[i].Service != s {
			t.Fatalf("position %d = %q, want %q", i, r.Cost.Services[i].Service, s)
		}
	}
}

func TestDeltaPctDoesNotDivideByZero(t *testing.T) {
	s := ServiceCost{Service: "Bedrock", CurrentUSD: 420, PreviousUSD: 0}
	if got := s.DeltaPct(); got != 0 {
		t.Errorf("DeltaPct with no previous spend = %v, want 0 (a brand new service has no percentage)", got)
	}
	if got := s.DeltaUSD(); got != 420 {
		t.Errorf("DeltaUSD = %v, want 420", got)
	}
}

func TestSLOMet(t *testing.T) {
	if !(SLOResult{ObjectivePct: 99.9, AttainmentPct: 99.9}).Met() {
		t.Error("exactly hitting the objective must count as met")
	}
	if (SLOResult{ObjectivePct: 99.9, AttainmentPct: 99.899}).Met() {
		t.Error("missing the objective must not count as met")
	}
}

func TestSectionValid(t *testing.T) {
	if !Section("security").Valid() {
		t.Error("security must be a valid section")
	}
	if Section("compliance").Valid() {
		t.Error("compliance is explicitly out of scope and must not validate")
	}
}
