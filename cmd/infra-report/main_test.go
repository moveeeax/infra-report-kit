package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// exampleConfig is the config shipped in examples/. The end-to-end test runs
// the very command the README tells the reader to run, so a README example that
// stops working breaks the build.
const exampleConfig = "../../examples/acme/acme-2026-06.json"

func genExample(t *testing.T, extraArgs ...string) (string, *model.Report) {
	t.Helper()
	out := t.TempDir()
	args := append([]string{"gen", "-config", exampleConfig, "-out", out,
		"-now", "2026-07-03T09:00:00Z", "-quiet"}, extraArgs...)
	if err := run(args); err != nil {
		t.Fatalf("gen: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "findings.json"))
	if err != nil {
		t.Fatalf("findings.json: %v", err)
	}
	var rep model.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("findings.json is not valid JSON: %v", err)
	}
	return out, &rep
}

func TestGenProducesBothArtefacts(t *testing.T) {
	out, rep := genExample(t)

	for _, name := range []string{"findings.json", "report.html"} {
		st, err := os.Stat(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}

	if rep.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version = %d, want %d", rep.SchemaVersion, model.SchemaVersion)
	}
	if rep.Tenant != "Northwind Cloud Services" {
		t.Errorf("tenant = %q", rep.Tenant)
	}
	if rep.Period.Label != "2026-06" {
		t.Errorf("period = %q", rep.Period.Label)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the example produced no findings")
	}
	if len(rep.SLOs) != 3 {
		t.Errorf("got %d SLO rows, want 3", len(rep.SLOs))
	}
	if rep.Cost.CurrentUSD <= 0 {
		t.Error("cost block was not populated")
	}
	if rep.Narrative == "" {
		t.Error("narrative was not attached to the findings JSON")
	}
}

func TestGenAppliesTheMonthOverMonthDelta(t *testing.T) {
	_, rep := genExample(t)
	if rep.Delta == nil {
		t.Fatal("no delta: the example config points at a previous report")
	}
	if rep.Delta.PreviousPeriod != "2026-05" {
		t.Errorf("previous period = %q, want 2026-05", rep.Delta.PreviousPeriod)
	}
	if rep.Delta.New == 0 || rep.Delta.Open == 0 || rep.Delta.Resolved == 0 {
		t.Fatalf("delta = %+v, want the example to exercise all three states", rep.Delta)
	}
	if rep.Delta.ResolvedSavings <= 0 {
		t.Error("the example must show at least one resolved finding with money attached")
	}
	var statuses = map[model.Status]int{}
	for _, f := range rep.Findings {
		statuses[f.Status]++
	}
	if statuses[model.StatusNew]+statuses[model.StatusOpen] != len(rep.Findings) {
		t.Errorf("every current finding must be new or open, got %v", statuses)
	}
}

func TestGenIsDeterministic(t *testing.T) {
	outA, _ := genExample(t)
	outB, _ := genExample(t)
	for _, name := range []string{"findings.json", "report.html"} {
		a, err := os.ReadFile(filepath.Join(outA, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(outB, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Errorf("%s differs between two identical runs; a monthly report must be reproducible", name)
		}
	}
}

func TestGeneratedHTMLIsSelfContained(t *testing.T) {
	out, _ := genExample(t)
	raw, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if strings.Contains(html, "ZgotmplZ") {
		t.Fatal("html/template refused a value; this report cannot be sent to a client")
	}
	if !strings.Contains(html, "data:image/svg+xml;base64,") &&
		!strings.Contains(html, "data:image/svg&#43;xml;base64,") {
		t.Error("the tenant logo was not inlined; the PDF renderer has no network")
	}
	for _, scheme := range []string{`src="http`, `href="http`, `url(http`} {
		if strings.Contains(html, scheme) {
			t.Errorf("report references an external resource (%s); print-to-PDF must work offline", scheme)
		}
	}
}

func TestGenRejectsPDFWithoutACommand(t *testing.T) {
	err := run([]string{"gen", "-config", exampleConfig, "-out", t.TempDir(),
		"-now", "2026-07-03T09:00:00Z", "-pdf", "-quiet"})
	if err == nil {
		t.Fatal("want an error: the example config configures no PDF renderer")
	}
	if !strings.Contains(err.Error(), "pdf.command") {
		t.Errorf("error = %v, want it to name the missing setting", err)
	}
}

func TestValidateAcceptsTheExample(t *testing.T) {
	if err := run([]string{"validate", "-config", exampleConfig}); err != nil {
		t.Fatalf("the shipped example must validate: %v", err)
	}
}

func TestValidateReportsMissingInputs(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"tenant":{"name":"N"},"account":{"id":"1"},
	  "period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},
	  "sources":[{"adapter":"certcheck","file":"in/certs.json"}]}`
	path := filepath.Join(dir, "tenant.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"validate", "-config", path})
	if err == nil {
		t.Fatal("want an error naming the missing scanner output")
	}
	if !strings.Contains(err.Error(), "certcheck") {
		t.Errorf("error = %v, want it to name the source", err)
	}
}

func TestDiffBetweenTwoGeneratedReports(t *testing.T) {
	out, _ := genExample(t)
	current := filepath.Join(out, "findings.json")
	previous := "../../examples/acme/history/2026-05/findings.json"
	if err := run([]string{"diff", "-current", current, "-previous", previous}); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if err := run([]string{"diff", "-current", current, "-previous", previous, "-json"}); err != nil {
		t.Fatalf("diff -json: %v", err)
	}
}

func TestCLIErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"nonsense"},
		{"gen"},
		{"validate"},
		{"diff"},
		{"diff", "-current", "a.json"},
		{"gen", "-config", "does-not-exist.json"},
	}
	for _, args := range cases {
		if err := run(args); err == nil {
			t.Errorf("run(%v) = nil, want an error", args)
		}
	}
}

func TestVersionAndAdapters(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"adapters"}, {"help"}} {
		if err := run(args); err != nil {
			t.Errorf("run(%v): %v", args, err)
		}
	}
}
