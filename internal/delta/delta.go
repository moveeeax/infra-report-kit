// Package delta compares this month's findings with last month's.
//
// The delta is the reason an MSP can charge for this every month rather than
// once: "you closed nine things and saved $412" is the product.
package delta

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// LoadReport reads a previously generated findings JSON.
func LoadReport(path string) (*model.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.SchemaVersion > model.SchemaVersion {
		return nil, fmt.Errorf("%s: schema version %d is newer than this build understands (%d)",
			path, r.SchemaVersion, model.SchemaVersion)
	}
	return &r, nil
}

// Apply annotates cur against prev, in place.
//
// It does four things:
//   - marks each current finding, accepted or not, new or open;
//   - carries FirstSeen forward so a finding's real age survives regeneration;
//   - appends findings present last month and absent now as resolved, with the
//     recurring spend they were carrying;
//   - records acceptance transitions: findings accepted this period that were
//     not accepted last period, and findings accepted last period that are
//     back among the open findings.
//
// New and Open count only cur.Findings. Accepted findings are counted in
// Delta.Accepted instead, so the delta line agrees with the severity totals.
// A finding that moves between the open and accepted lists is neither new nor
// resolved: it is the same finding.
//
// Passing a nil prev marks every finding new, which is the correct behaviour
// for a first report.
func Apply(cur, prev *model.Report) {
	if cur == nil {
		return
	}
	if prev == nil {
		for i := range cur.Findings {
			cur.Findings[i].Status = model.StatusNew
		}
		for i := range cur.Accepted {
			cur.Accepted[i].Status = model.StatusNew
		}
		cur.Delta = &model.Delta{
			New:           len(cur.Findings),
			Accepted:      len(cur.Accepted),
			NewlyAccepted: append([]model.Finding(nil), cur.Accepted...),
		}
		return
	}

	prevByID := make(map[string]model.Finding, len(prev.Findings)+len(prev.Accepted))
	for _, f := range prev.Findings {
		// A finding that was resolved last month is history, not a baseline.
		if f.Status == model.StatusResolved {
			continue
		}
		prevByID[f.ID] = f
	}
	prevAccepted := make(map[string]bool, len(prev.Accepted))
	for _, f := range prev.Accepted {
		prevByID[f.ID] = f
		prevAccepted[f.ID] = true
	}

	d := &model.Delta{PreviousPeriod: prev.Period.Label}
	seen := make(map[string]bool, len(cur.Findings)+len(cur.Accepted))
	// mark sets status and FirstSeen and reports whether the finding existed
	// in the previous report.
	mark := func(f *model.Finding) bool {
		seen[f.ID] = true
		old, ok := prevByID[f.ID]
		if !ok {
			f.Status = model.StatusNew
			return false
		}
		f.Status = model.StatusOpen
		if !old.FirstSeen.IsZero() {
			f.FirstSeen = old.FirstSeen
		}
		return true
	}
	for i := range cur.Findings {
		f := &cur.Findings[i]
		if mark(f) {
			d.Open++
		} else {
			d.New++
		}
		if prevAccepted[f.ID] {
			d.Reopened = append(d.Reopened, *f)
		}
	}
	for i := range cur.Accepted {
		f := &cur.Accepted[i]
		mark(f)
		d.Accepted++
		if !prevAccepted[f.ID] {
			d.NewlyAccepted = append(d.NewlyAccepted, *f)
		}
	}

	for _, list := range [][]model.Finding{prev.Findings, prev.Accepted} {
		for _, f := range list {
			if f.Status == model.StatusResolved || seen[f.ID] {
				continue
			}
			f.Status = model.StatusResolved
			d.Resolved++
			d.ResolvedSavings += f.MonthlyCostUSD
			d.ResolvedList = append(d.ResolvedList, f)
		}
	}
	sort.SliceStable(d.ResolvedList, func(i, j int) bool {
		return d.ResolvedList[i].MonthlyCostUSD > d.ResolvedList[j].MonthlyCostUSD
	})

	cur.Delta = d
}

// NewFindings returns the findings that appeared this month.
func NewFindings(r *model.Report) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Status == model.StatusNew {
			out = append(out, f)
		}
	}
	return out
}
