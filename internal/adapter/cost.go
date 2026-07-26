package adapter

import (
	"encoding/json"
	"fmt"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// costExplorer consumes a two-month spend export and fills the typed cost
// block. It emits no findings: a bill is not a finding.
//
// Input shape (aws-cost-explorer / az-cost-export):
//
//	{"currency":"USD",
//	 "current":{"label":"2026-06","services":[{"service":"Amazon EC2","amount_usd":1840.22}]},
//	 "previous":{"label":"2026-05","services":[...]}}
type costExplorer struct{}

func (costExplorer) Name() string { return "cost-export" }

type costMonth struct {
	Label    string `json:"label"`
	Services []struct {
		Service   string  `json:"service"`
		AmountUSD float64 `json:"amount_usd"`
	} `json:"services"`
}

func (costExplorer) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Currency string    `json:"currency"`
		Current  costMonth `json:"current"`
		Previous costMonth `json:"previous"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("cost-export: %w", err)
	}
	if in.Currency != "" {
		r.Cost.Currency = in.Currency
	}

	byService := map[string]*model.ServiceCost{}
	get := func(name string) *model.ServiceCost {
		if sc, ok := byService[name]; ok {
			return sc
		}
		sc := &model.ServiceCost{Service: name}
		byService[name] = sc
		return sc
	}
	for _, s := range in.Current.Services {
		get(s.Service).CurrentUSD += s.AmountUSD
		r.Cost.CurrentUSD += s.AmountUSD
	}
	for _, s := range in.Previous.Services {
		get(s.Service).PreviousUSD += s.AmountUSD
		r.Cost.PreviousUSD += s.AmountUSD
	}
	for _, sc := range byService {
		r.Cost.Services = append(r.Cost.Services, *sc)
	}
	return nil
}

// orphanFinder consumes aws-orphan-finder output: resources that exist, cost
// money and are attached to nothing.
//
// Input shape:
//
//	{"account":"123456789012",
//	 "orphans":[{"type":"ebs-volume","id":"vol-0a1b","region":"eu-west-1",
//	             "monthly_cost_usd":12.40,"age_days":61,"reason":"unattached"}]}
type orphanFinder struct{}

func (orphanFinder) Name() string { return "aws-orphan-finder" }

func (a orphanFinder) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Account string `json:"account"`
		Orphans []struct {
			Type           string  `json:"type"`
			ID             string  `json:"id"`
			Name           string  `json:"name"`
			Region         string  `json:"region"`
			MonthlyCostUSD float64 `json:"monthly_cost_usd"`
			AgeDays        int     `json:"age_days"`
			Reason         string  `json:"reason"`
		} `json:"orphans"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("aws-orphan-finder: %w", err)
	}
	for _, o := range in.Orphans {
		res := model.Resource{
			Provider: "aws",
			Account:  account(in.Account, r),
			Region:   o.Region,
			Type:     o.Type,
			ID:       o.ID,
			Name:     o.Name,
		}
		r.Add(model.Finding{
			Source:         a.Name(),
			Section:        model.SectionCost,
			Rule:           "orphaned-resource",
			Severity:       wasteSeverity(o.MonthlyCostUSD),
			Title:          fmt.Sprintf("Orphaned %s %s costs $%.2f/month", o.Type, o.ID, o.MonthlyCostUSD),
			Detail:         o.Reason,
			Recommendation: fmt.Sprintf("Delete %s after confirming no snapshot or restore depends on it.", o.ID),
			Resource:       res,
			MonthlyCostUSD: o.MonthlyCostUSD,
			Evidence: compact(map[string]string{
				"age_days": itoaIfPositive(o.AgeDays),
				"reason":   o.Reason,
			}),
		})
	}
	return nil
}

// wasteSeverity grades a cost finding by the dollars attached to it. There is
// no security risk here, so severity is purely the size of the cheque.
func wasteSeverity(monthlyUSD float64) model.Severity {
	switch {
	case monthlyUSD >= 100:
		return model.SeverityHigh
	case monthlyUSD >= 25:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
