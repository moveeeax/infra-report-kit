package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/config"
	"github.com/moveeeax/infra-report-kit/internal/model"
)

var fixedNow = time.Date(2026, 7, 3, 9, 0, 0, 0, time.UTC)

// tenantDir builds a working tenant directory: a config plus whatever scanner
// output files the case needs.
func tenantDir(t *testing.T, cfg map[string]any, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tenant.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseConfig(sources []any) map[string]any {
	return map[string]any{
		"tenant":  map[string]any{"name": "Northwind"},
		"account": map[string]any{"provider": "aws", "id": "123456789012"},
		"period":  map[string]any{"label": "2026-06", "start": "2026-06-01", "end": "2026-06-30"},
		"sources": sources,
	}
}

const sgJSON = `{"account":"123456789012","security_groups":[
  {"group_id":"sg-1","group_name":"bastion","region":"eu-west-1",
   "open_ingress":[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"0.0.0.0/0"}]}]}`

const orphanJSON = `{"account":"123456789012","orphans":[
  {"type":"ec2:volume","id":"vol-1","region":"eu-west-1","monthly_cost_usd":128.40,"reason":"unattached"}]}`

func TestRunReadsFileSources(t *testing.T) {
	path := tenantDir(t,
		baseConfig([]any{
			map[string]any{"adapter": "aws-sg-audit", "file": "in/sg.json"},
			map[string]any{"adapter": "aws-orphan-finder", "file": "in/orphan.json"},
		}),
		map[string]string{"in/sg.json": sgJSON, "in/orphan.json": orphanJSON})

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, warnings, err := Run(context.Background(), cfg, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(rep.Findings))
	}
	// Critical before high: the report is sorted before it is returned.
	if rep.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("findings are not sorted: first is %q", rep.Findings[0].Severity)
	}
	if rep.Tenant != "Northwind" || rep.Account.ID != "123456789012" {
		t.Errorf("report header not populated: %+v", rep.Account)
	}
	if !rep.GeneratedAt.Equal(fixedNow) {
		t.Errorf("GeneratedAt = %v, want the pinned time", rep.GeneratedAt)
	}
}

func TestRunExecutesCommandSources(t *testing.T) {
	path := tenantDir(t,
		baseConfig([]any{
			map[string]any{"adapter": "aws-sg-audit", "command": []string{"cat", "in/sg.json"}},
		}),
		map[string]string{"in/sg.json": sgJSON})

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, _, err := Run(context.Background(), cfg, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings from the command source, want 1", len(rep.Findings))
	}
}

func TestRunFailsHardOnARequiredSource(t *testing.T) {
	path := tenantDir(t,
		baseConfig([]any{map[string]any{"adapter": "aws-sg-audit", "file": "in/missing.json"}}),
		nil)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Run(context.Background(), cfg, Options{Now: fixedNow}); err == nil {
		t.Fatal("a missing required source must abort the run, not ship a half report")
	}
}

func TestRunWarnsOnAnOptionalSource(t *testing.T) {
	path := tenantDir(t,
		baseConfig([]any{
			map[string]any{"adapter": "aws-sg-audit", "file": "in/sg.json"},
			map[string]any{"adapter": "k8s-rightsize", "file": "in/missing.json", "optional": true},
		}),
		map[string]string{"in/sg.json": sgJSON})

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, warnings, err := Run(context.Background(), cfg, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("an optional source must not fail the run: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "k8s-rightsize") {
		t.Fatalf("warnings = %v, want one naming k8s-rightsize", warnings)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("got %d findings, want the one from the source that did work", len(rep.Findings))
	}
}

func TestRunFailsOnACommandThatProducesNothing(t *testing.T) {
	path := tenantDir(t,
		baseConfig([]any{map[string]any{"adapter": "certcheck", "command": []string{"true"}}}),
		nil)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Run(context.Background(), cfg, Options{Now: fixedNow})
	if err == nil {
		t.Fatal("a scanner that exits 0 with no output must be an error")
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Errorf("error = %v, want it to name the empty output", err)
	}
}

func TestRunDedupesAcrossSources(t *testing.T) {
	// The same scanner wired in twice: a copy-paste an operator will make.
	path := tenantDir(t,
		baseConfig([]any{
			map[string]any{"adapter": "aws-orphan-finder", "file": "in/orphan.json"},
			map[string]any{"adapter": "aws-orphan-finder", "file": "in/orphan-copy.json"},
		}),
		map[string]string{"in/orphan.json": orphanJSON, "in/orphan-copy.json": orphanJSON})

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, _, err := Run(context.Background(), cfg, Options{Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 after dedupe", len(rep.Findings))
	}
	if got := rep.IdentifiedWasteUSD(); got != 128.40 {
		t.Errorf("waste = %.2f, want 128.40 counted once", got)
	}
}
