// Package accept applies a tenant's accepted-risk register to a report.
//
// A client who knowingly keeps a public bucket should not see it as "still
// open, 9 months" in every report. An accepted finding moves to its own
// appendix and out of the severity totals until the acceptance expires; then
// it is back among the open findings, flagged for re-review.
//
// Every acceptance must carry an expiry date. An acceptance with no end is a
// finding nobody looks at again.
package accept

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// Entry is one row of the register file, as written by the operator.
type Entry struct {
	// Fingerprint is the finding ID, exactly as it appears in findings.json.
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
	AcceptedBy  string `json:"accepted_by"`
	// Expires is the last day the acceptance holds, YYYY-MM-DD, UTC.
	Expires string `json:"expires"`

	expires time.Time
}

// Register is a validated set of acceptances keyed by fingerprint.
type Register struct {
	entries []Entry
	byID    map[string]int
}

// Len is the number of entries in the register.
func (r *Register) Len() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// Load reads and validates a register file: a JSON array of entries.
func Load(path string) (*Register, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	reg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return reg, nil
}

// Parse validates a register document. Like the tenant config, it reports
// every problem at once rather than the first one.
func Parse(raw []byte) (*Register, error) {
	var entries []Entry
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}

	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	reg := &Register{byID: make(map[string]int, len(entries))}
	for i, e := range entries {
		e.Fingerprint = strings.TrimSpace(e.Fingerprint)
		if e.Fingerprint == "" {
			add("[%d]: fingerprint is required", i)
		} else if prev, dup := reg.byID[e.Fingerprint]; dup {
			add("[%d]: fingerprint %q is already accepted by entry [%d]", i, e.Fingerprint, prev)
		} else {
			reg.byID[e.Fingerprint] = i
		}
		if strings.TrimSpace(e.Reason) == "" {
			add("[%d]: reason is required: it is printed in the accepted-risks appendix", i)
		}
		if strings.TrimSpace(e.AcceptedBy) == "" {
			add("[%d]: accepted_by is required: an acceptance needs a named owner", i)
		}
		exp, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			add("[%d]: expires %q must be YYYY-MM-DD; every acceptance needs an end date", i, e.Expires)
		}
		e.expires = exp
		reg.entries = append(reg.entries, e)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid accepted-risk register:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return reg, nil
}

// Apply matches the register against rep.Findings, in place.
//
// A finding with an active acceptance moves from rep.Findings to rep.Accepted.
// A finding whose acceptance has expired at rep.GeneratedAt stays in
// rep.Findings with Acceptance.Expired set. Order within both lists is kept.
//
// It returns a warning for every register entry that matched no finding: the
// issue was fixed or the fingerprint is mistyped, and either way the entry
// should come out of the register.
//
// A nil register is a no-op.
func Apply(rep *model.Report, reg *Register) []string {
	if rep == nil || reg == nil {
		return nil
	}
	matched := make(map[string]bool, len(reg.entries))
	kept := rep.Findings[:0]
	for _, f := range rep.Findings {
		idx, ok := reg.byID[f.ID]
		if !ok {
			kept = append(kept, f)
			continue
		}
		e := reg.entries[idx]
		matched[e.Fingerprint] = true
		a := &model.Acceptance{Reason: e.Reason, AcceptedBy: e.AcceptedBy, Expires: e.expires}
		a.Expired = a.ExpiredAt(rep.GeneratedAt)
		f.Acceptance = a
		if a.Expired {
			kept = append(kept, f)
			continue
		}
		rep.Accepted = append(rep.Accepted, f)
	}
	rep.Findings = kept

	var warnings []string
	for _, e := range reg.entries {
		if !matched[e.Fingerprint] {
			warnings = append(warnings, fmt.Sprintf(
				"accepted-risk entry %q matches no finding this period; remove it from the register", e.Fingerprint))
		}
	}
	return warnings
}
