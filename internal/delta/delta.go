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
// It does three things:
//   - marks each current finding new or open;
//   - carries FirstSeen forward so a finding's real age survives regeneration;
//   - appends findings present last month and absent now as resolved, with the
//     recurring spend they were carrying.
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
		cur.Delta = &model.Delta{New: len(cur.Findings)}
		return
	}

	prevByID := make(map[string]model.Finding, len(prev.Findings))
	for _, f := range prev.Findings {
		// A finding that was resolved last month is history, not a baseline.
		if f.Status == model.StatusResolved {
			continue
		}
		prevByID[f.ID] = f
	}

	d := &model.Delta{PreviousPeriod: prev.Period.Label}
	seen := make(map[string]bool, len(cur.Findings))
	for i := range cur.Findings {
		f := &cur.Findings[i]
		seen[f.ID] = true
		if old, ok := prevByID[f.ID]; ok {
			f.Status = model.StatusOpen
			if !old.FirstSeen.IsZero() {
				f.FirstSeen = old.FirstSeen
			}
			d.Open++
		} else {
			f.Status = model.StatusNew
			d.New++
		}
	}

	for _, f := range prev.Findings {
		if f.Status == model.StatusResolved || seen[f.ID] {
			continue
		}
		f.Status = model.StatusResolved
		d.Resolved++
		d.ResolvedSavings += f.MonthlyCostUSD
		d.ResolvedList = append(d.ResolvedList, f)
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
