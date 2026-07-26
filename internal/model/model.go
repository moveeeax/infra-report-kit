// Package model defines the normalised findings document that every adapter
// writes into and that the renderer and the delta engine read from.
//
// The findings JSON is the contract with the customer: the PDF is generated
// from it, and the same file is shipped alongside the PDF so an MSP can feed
// it into their own tooling. Treat SchemaVersion as load bearing.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the version of the findings document produced by this build.
const SchemaVersion = 1

// Section is the top-level chapter of the report a finding belongs to.
type Section string

const (
	SectionCost        Section = "cost"
	SectionSecurity    Section = "security"
	SectionReliability Section = "reliability"
)

// Sections lists every valid section in default report order.
var Sections = []Section{SectionCost, SectionSecurity, SectionReliability}

// Valid reports whether s is a section this tool knows how to render.
func (s Section) Valid() bool {
	for _, known := range Sections {
		if s == known {
			return true
		}
	}
	return false
}

// Title returns the human heading used in the rendered report.
func (s Section) Title() string {
	switch s {
	case SectionCost:
		return "Cost"
	case SectionSecurity:
		return "Security"
	case SectionReliability:
		return "Reliability"
	default:
		return string(s)
	}
}

// Severity is the urgency of a finding. Ordering matters: findings are sorted
// by severity descending before anything else.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

// Rank returns a sortable weight. Unknown severities rank below info so a
// malformed adapter can never push junk to the top of a client-facing page.
func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity normalises the many spellings upstream CLIs use.
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit", "fatal", "severe":
		return SeverityCritical
	case "high", "error", "major":
		return SeverityHigh
	case "medium", "med", "moderate", "warning", "warn":
		return SeverityMedium
	case "low", "minor":
		return SeverityLow
	case "info", "informational", "note", "notice", "":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// Resource identifies the thing a finding is about.
type Resource struct {
	Provider string `json:"provider"`          // aws, azure, k8s, net
	Account  string `json:"account,omitempty"` // account id, subscription id, cluster name
	Region   string `json:"region,omitempty"`
	Type     string `json:"type"` // ec2:volume, s3:bucket, iam:role, ...
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
}

// Ref is the stable, human-readable identity of a resource.
func (r Resource) Ref() string {
	parts := []string{r.Provider}
	if r.Region != "" {
		parts = append(parts, r.Region)
	}
	parts = append(parts, r.Type, r.ID)
	return strings.Join(parts, "/")
}

// Finding is one normalised observation. Every adapter emits these and nothing
// else reaches the report body.
type Finding struct {
	// ID is a deterministic fingerprint (source/rule/resource). It is what the
	// delta engine matches on across months, so it must not embed timestamps,
	// dollar amounts or anything else that legitimately changes.
	ID       string   `json:"id"`
	Source   string   `json:"source"`
	Section  Section  `json:"section"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	// Recommendation is what the MSP should tell the client to do.
	Recommendation string   `json:"recommendation,omitempty"`
	Resource       Resource `json:"resource"`
	// MonthlyCostUSD is the recurring spend attached to this finding. Zero for
	// findings with no dollar figure; the report never invents one.
	MonthlyCostUSD float64           `json:"monthly_cost_usd,omitempty"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	// FirstSeen is carried forward from the previous report when the same ID
	// reappears, which is how "open for 3 months" gets onto the page.
	FirstSeen time.Time `json:"first_seen,omitempty"`
	// Status is filled in by the delta engine: new, open or resolved.
	Status Status `json:"status,omitempty"`
}

// Status describes a finding relative to the previous report.
type Status string

const (
	StatusNew      Status = "new"
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
)

// NewID builds the deterministic fingerprint used to match findings across
// months. Keep the inputs stable or every finding looks new next month.
func NewID(source, rule string, res Resource) string {
	return fmt.Sprintf("%s:%s:%s", source, rule, res.Ref())
}

// ServiceCost is one line of the month-over-month spend table.
type ServiceCost struct {
	Service     string  `json:"service"`
	CurrentUSD  float64 `json:"current_usd"`
	PreviousUSD float64 `json:"previous_usd"`
}

// DeltaUSD is the change in spend versus the previous month.
func (s ServiceCost) DeltaUSD() float64 { return s.CurrentUSD - s.PreviousUSD }

// DeltaPct is the change as a percentage. It returns 0 when the previous month
// was zero, because "+Inf%" on a client-facing page is not a number.
func (s ServiceCost) DeltaPct() float64 {
	if s.PreviousUSD == 0 {
		return 0
	}
	return (s.CurrentUSD - s.PreviousUSD) / s.PreviousUSD * 100
}

// CostSummary is the typed cost block. Findings cannot express a spend table,
// so adapters that produce billing data fill this in directly.
type CostSummary struct {
	Currency    string        `json:"currency"`
	CurrentUSD  float64       `json:"current_usd"`
	PreviousUSD float64       `json:"previous_usd"`
	Services    []ServiceCost `json:"services,omitempty"`
}

// DeltaUSD is the total change in spend versus the previous month.
func (c CostSummary) DeltaUSD() float64 { return c.CurrentUSD - c.PreviousUSD }

// TopServicesByDelta returns the n services whose spend moved most, by
// absolute dollars, largest first.
func (c CostSummary) TopServicesByDelta(n int) []ServiceCost {
	out := append([]ServiceCost(nil), c.Services...)
	sort.SliceStable(out, func(i, j int) bool {
		return abs(out[i].DeltaUSD()) > abs(out[j].DeltaUSD())
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// SLOResult is per-endpoint reliability attainment for the period.
type SLOResult struct {
	Endpoint       string  `json:"endpoint"`
	ObjectivePct   float64 `json:"objective_pct"`
	AttainmentPct  float64 `json:"attainment_pct"`
	ErrorBudgetPct float64 `json:"error_budget_remaining_pct"`
	DowntimeMin    float64 `json:"downtime_minutes"`
	Checks         int     `json:"checks,omitempty"`
}

// Met reports whether the endpoint hit its objective for the period.
func (s SLOResult) Met() bool { return s.AttainmentPct >= s.ObjectivePct }

// Period is the calendar month the report covers.
type Period struct {
	Label string    `json:"label"` // "2026-06"
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Account is the client cloud account the report was generated against.
type Account struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	Label    string `json:"label,omitempty"`
}

// Report is the whole normalised findings document.
type Report struct {
	SchemaVersion int         `json:"schema_version"`
	GeneratedAt   time.Time   `json:"generated_at"`
	Tenant        string      `json:"tenant"`
	Account       Account     `json:"account"`
	Period        Period      `json:"period"`
	Cost          CostSummary `json:"cost"`
	SLOs          []SLOResult `json:"slos,omitempty"`
	Findings      []Finding   `json:"findings"`
	Narrative     string      `json:"narrative,omitempty"`
	Delta         *Delta      `json:"delta,omitempty"`
}

// Delta summarises movement against the previous report.
type Delta struct {
	PreviousPeriod  string    `json:"previous_period"`
	New             int       `json:"new"`
	Open            int       `json:"open"`
	Resolved        int       `json:"resolved"`
	ResolvedSavings float64   `json:"resolved_savings_usd"`
	ResolvedList    []Finding `json:"resolved_findings,omitempty"`
}

// New returns an empty report stamped with the current schema version.
func New(tenant string, acct Account, period Period, now time.Time) *Report {
	return &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.UTC(),
		Tenant:        tenant,
		Account:       acct,
		Period:        period,
		Cost:          CostSummary{Currency: "USD"},
	}
}

// Add appends a finding, filling in the fingerprint and defaulting FirstSeen to
// the report's own timestamp.
func (r *Report) Add(f Finding) {
	if f.ID == "" {
		f.ID = NewID(f.Source, f.Rule, f.Resource)
	}
	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = r.GeneratedAt
	}
	r.Findings = append(r.Findings, f)
}

// Sort puts the whole report into a deterministic order.
//
// Findings go severity descending, then attached dollars descending, then ID.
// The spend table goes alphabetically by service — adapters may build it from a
// map, and Go map iteration order would otherwise reshuffle findings.json on
// every run, making a regenerated report impossible to diff.
func (r *Report) Sort() {
	sort.SliceStable(r.Cost.Services, func(i, j int) bool {
		return r.Cost.Services[i].Service < r.Cost.Services[j].Service
	})
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.MonthlyCostUSD != b.MonthlyCostUSD {
			return a.MonthlyCostUSD > b.MonthlyCostUSD
		}
		return a.ID < b.ID
	})
}

// Dedupe drops findings that share a fingerprint, keeping the first occurrence
// and the largest attached dollar figure seen for it. Two scanners overlapping
// on the same resource is normal; billing the client twice for it is not.
func (r *Report) Dedupe() {
	seen := make(map[string]int, len(r.Findings))
	out := r.Findings[:0]
	for _, f := range r.Findings {
		if idx, ok := seen[f.ID]; ok {
			if f.MonthlyCostUSD > out[idx].MonthlyCostUSD {
				out[idx].MonthlyCostUSD = f.MonthlyCostUSD
			}
			continue
		}
		seen[f.ID] = len(out)
		out = append(out, f)
	}
	r.Findings = out
}

// BySection returns the findings for one section, in current order.
func (r *Report) BySection(s Section) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Section == s {
			out = append(out, f)
		}
	}
	return out
}

// SeverityCounts tallies findings per severity.
func (r *Report) SeverityCounts() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// TopWaste returns the n findings with the largest attached monthly spend.
// Findings with no dollar figure are excluded rather than shown as $0.00.
func (r *Report) TopWaste(n int) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.MonthlyCostUSD > 0 {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].MonthlyCostUSD > out[j].MonthlyCostUSD
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// IdentifiedWasteUSD is the total recurring spend attached to open findings.
func (r *Report) IdentifiedWasteUSD() float64 {
	var total float64
	for _, f := range r.Findings {
		total += f.MonthlyCostUSD
	}
	return total
}
