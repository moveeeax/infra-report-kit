package adapter

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// uptimeTargetPct is the attainment below which uptime-ping results become a
// finding rather than a line in the reliability table.
const uptimeTargetPct = 99.9

// uptimePing consumes uptime-ping output: raw availability per endpoint.
//
// Input shape:
//
//	{"endpoints":[{"url":"https://api.example.com/health","checks":8640,"failures":22,
//	   "uptime_pct":99.745,"downtime_minutes":110.0}]}
type uptimePing struct{}

func (uptimePing) Name() string { return "uptime-ping" }

func (a uptimePing) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Endpoints []struct {
			URL             string  `json:"url"`
			Checks          int     `json:"checks"`
			Failures        int     `json:"failures"`
			UptimePct       float64 `json:"uptime_pct"`
			DowntimeMinutes float64 `json:"downtime_minutes"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("uptime-ping: %w", err)
	}
	for _, e := range in.Endpoints {
		if e.UptimePct >= uptimeTargetPct {
			continue
		}
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionReliability,
			Rule:     "availability-below-target",
			Severity: uptimeSeverity(e.UptimePct),
			Title: fmt.Sprintf("%s was available %.3f%% of the period (target %.1f%%)",
				e.URL, e.UptimePct, uptimeTargetPct),
			Detail: fmt.Sprintf("%d of %d checks failed, %.0f minutes of downtime.",
				e.Failures, e.Checks, e.DowntimeMinutes),
			Recommendation: "Correlate the failed checks with deploys and instance replacements, " +
				"then decide whether this needs redundancy or a slower rollout.",
			Resource: model.Resource{Provider: "net", Type: "http:endpoint", ID: e.URL},
			Evidence: compact(map[string]string{
				"checks":           itoaIfPositive(e.Checks),
				"failures":         itoaIfPositive(e.Failures),
				"downtime_minutes": strconv.FormatFloat(e.DowntimeMinutes, 'f', 1, 64),
			}),
		})
	}
	return nil
}

// uptimeSeverity grades measured availability. The bands are deliberately
// coarse: a monthly report is not a pager, and an MSP needs "which of these do
// I raise with the client" rather than four decimal places of nuance.
func uptimeSeverity(pct float64) model.Severity {
	switch {
	case pct < 99.0:
		return model.SeverityCritical
	case pct < 99.5:
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}

// sloCalc consumes slo-calc output. It fills the typed SLO block that the
// reliability table is drawn from, and raises a finding per missed objective.
//
// Input shape:
//
//	{"slos":[{"endpoint":"https://api.example.com/health","objective_pct":99.9,
//	   "attainment_pct":99.745,"error_budget_remaining_pct":-155.0,
//	   "downtime_minutes":110.0,"checks":8640}]}
type sloCalc struct{}

func (sloCalc) Name() string { return "slo-calc" }

func (a sloCalc) Parse(raw []byte, r *model.Report) error {
	var in struct {
		SLOs []model.SLOResult `json:"slos"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("slo-calc: %w", err)
	}
	for _, s := range in.SLOs {
		r.SLOs = append(r.SLOs, s)
		if s.Met() {
			continue
		}
		sev := model.SeverityMedium
		if s.ErrorBudgetPct < 0 {
			sev = model.SeverityHigh
		}
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionReliability,
			Rule:     "slo-missed",
			Severity: sev,
			Title: fmt.Sprintf("SLO missed for %s: %.3f%% against a %.1f%% objective",
				s.Endpoint, s.AttainmentPct, s.ObjectivePct),
			Detail: fmt.Sprintf("Error budget remaining %.1f%%, %.0f minutes of downtime in the period.",
				s.ErrorBudgetPct, s.DowntimeMin),
			Recommendation: "Freeze risky changes to this service until the error budget is back above " +
				"zero, or agree a lower objective with the client and stop reporting a miss.",
			Resource: model.Resource{Provider: "net", Type: "slo", ID: s.Endpoint},
			Evidence: compact(map[string]string{
				"objective_pct":  strconv.FormatFloat(s.ObjectivePct, 'f', -1, 64),
				"attainment_pct": strconv.FormatFloat(s.AttainmentPct, 'f', -1, 64),
			}),
		})
	}
	return nil
}

// k8sCrashloop consumes k8s-crashloop output.
//
// Input shape:
//
//	{"cluster":"acme-prod","window_hours":720,
//	 "pods":[{"namespace":"payments","pod":"api-7d9","controller":"Deployment/api",
//	   "restarts":214,"reason":"CrashLoopBackOff","last_exit_code":137}]}
type k8sCrashloop struct{}

func (k8sCrashloop) Name() string { return "k8s-crashloop" }

func (a k8sCrashloop) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Cluster     string `json:"cluster"`
		WindowHours int    `json:"window_hours"`
		Pods        []struct {
			Namespace    string `json:"namespace"`
			Pod          string `json:"pod"`
			Controller   string `json:"controller"`
			Restarts     int    `json:"restarts"`
			Reason       string `json:"reason"`
			LastExitCode int    `json:"last_exit_code"`
		} `json:"pods"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("k8s-crashloop: %w", err)
	}
	for _, p := range in.Pods {
		sev := model.SeverityLow
		switch {
		case p.Restarts >= 50:
			sev = model.SeverityHigh
		case p.Restarts >= 10:
			sev = model.SeverityMedium
		}
		hint := ""
		if p.LastExitCode == 137 {
			hint = " Exit code 137 means the container was OOM-killed; raise the memory limit or fix the leak."
		}
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionReliability,
			Rule:     "crashloop",
			Severity: sev,
			Title: fmt.Sprintf("%s/%s restarted %d times in the period",
				p.Namespace, p.Controller, p.Restarts),
			Detail: fmt.Sprintf("Last state %s, exit code %d, observed over %dh.",
				p.Reason, p.LastExitCode, in.WindowHours),
			Recommendation: "Pull the previous container logs and the last termination state before " +
				"the pod is rescheduled again." + hint,
			Resource: model.Resource{
				Provider: "k8s", Account: in.Cluster,
				Type: "k8s:workload", ID: in.Cluster + "/" + p.Namespace + "/" + p.Controller,
				Name: p.Controller,
			},
			Evidence: compact(map[string]string{
				"namespace":      p.Namespace,
				"restarts":       itoaIfPositive(p.Restarts),
				"reason":         p.Reason,
				"last_exit_code": itoaIfPositive(p.LastExitCode),
			}),
		})
	}
	return nil
}

// k8sRightsize consumes k8s-rightsize output. It lands in the cost section
// because the deliverable is a dollar figure, not a reliability risk.
//
// Input shape:
//
//	{"cluster":"acme-prod",
//	 "recommendations":[{"namespace":"payments","workload":"api","kind":"Deployment",
//	   "cpu_request_m":2000,"cpu_p95_m":180,"memory_request_mi":4096,"memory_p95_mi":512,
//	   "monthly_saving_usd":38.20}]}
type k8sRightsize struct{}

func (k8sRightsize) Name() string { return "k8s-rightsize" }

func (a k8sRightsize) Parse(raw []byte, r *model.Report) error {
	var in struct {
		Cluster         string `json:"cluster"`
		Recommendations []struct {
			Namespace        string  `json:"namespace"`
			Workload         string  `json:"workload"`
			Kind             string  `json:"kind"`
			CPURequestM      int     `json:"cpu_request_m"`
			CPUP95M          int     `json:"cpu_p95_m"`
			MemoryRequestMi  int     `json:"memory_request_mi"`
			MemoryP95Mi      int     `json:"memory_p95_mi"`
			MonthlySavingUSD float64 `json:"monthly_saving_usd"`
		} `json:"recommendations"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("k8s-rightsize: %w", err)
	}
	for _, rec := range in.Recommendations {
		id := fmt.Sprintf("%s/%s/%s/%s", in.Cluster, rec.Namespace, rec.Kind, rec.Workload)
		r.Add(model.Finding{
			Source:   a.Name(),
			Section:  model.SectionCost,
			Rule:     "over-provisioned-workload",
			Severity: wasteSeverity(rec.MonthlySavingUSD),
			Title: fmt.Sprintf("%s/%s requests %.1fx the CPU it uses, $%.2f/month",
				rec.Namespace, rec.Workload, ratio(rec.CPURequestM, rec.CPUP95M), rec.MonthlySavingUSD),
			Detail: fmt.Sprintf("CPU request %dm against p95 %dm; memory request %dMi against p95 %dMi.",
				rec.CPURequestM, rec.CPUP95M, rec.MemoryRequestMi, rec.MemoryP95Mi),
			Recommendation: "Set requests near p95 with headroom and keep limits where they are, " +
				"so the scheduler can pack the nodes without changing burst behaviour.",
			Resource: model.Resource{
				Provider: "k8s", Account: in.Cluster,
				Type: "k8s:" + kindOrWorkload(rec.Kind), ID: id, Name: rec.Workload,
			},
			MonthlyCostUSD: rec.MonthlySavingUSD,
			Evidence: compact(map[string]string{
				"namespace":         rec.Namespace,
				"cpu_request_m":     itoaIfPositive(rec.CPURequestM),
				"cpu_p95_m":         itoaIfPositive(rec.CPUP95M),
				"memory_request_mi": itoaIfPositive(rec.MemoryRequestMi),
				"memory_p95_mi":     itoaIfPositive(rec.MemoryP95Mi),
			}),
		})
	}
	return nil
}

// ratio reports how many times larger the request is than actual usage. A p95
// of zero is reported as 0 rather than infinity.
func ratio(request, used int) float64 {
	if used <= 0 {
		return 0
	}
	return float64(request) / float64(used)
}

func kindOrWorkload(kind string) string {
	if kind == "" {
		return "workload"
	}
	return kind
}
