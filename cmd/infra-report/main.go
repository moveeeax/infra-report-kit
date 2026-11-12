// Command infra-report builds a white-label monthly infrastructure report from
// the JSON output of standalone cloud scanners.
//
// It never talks to a cloud provider itself. Scanners hold the credentials;
// this tool only normalises, compares and renders what they produced.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/accept"
	"github.com/moveeeax/infra-report-kit/internal/adapter"
	"github.com/moveeeax/infra-report-kit/internal/collect"
	"github.com/moveeeax/infra-report-kit/internal/config"
	"github.com/moveeeax/infra-report-kit/internal/delta"
	"github.com/moveeeax/infra-report-kit/internal/model"
	"github.com/moveeeax/infra-report-kit/internal/narrative"
	"github.com/moveeeax/infra-report-kit/internal/render"
)

// version is overridden at build time with -ldflags "-X main.version=v0.2.0".
var version = "dev"

const usage = `infra-report — white-label monthly infrastructure reports

Usage:
  infra-report gen      -config tenant.json [-out DIR] [-pdf] [-now RFC3339]
  infra-report validate -config tenant.json
  infra-report diff     -current findings.json -previous findings.json [-json]
  infra-report adapters
  infra-report version

Commands:
  gen       Run every configured source, apply the month-over-month delta and
            write findings.json plus a print-ready report.html.
  validate  Check a tenant config without running anything.
  diff      Compare two findings files and print what changed.
  adapters  List the scanner formats this build understands.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return errors.New("no command given")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "gen":
		return cmdGen(ctx, args[1:])
	case "validate":
		return cmdValidate(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "adapters":
		for _, n := range adapter.Names() {
			fmt.Println(n)
		}
		return nil
	case "version":
		fmt.Printf("infra-report %s (findings schema v%d)\n", version, model.SchemaVersion)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdGen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the tenant config JSON (required)")
	outDir := fs.String("out", "out", "directory to write findings.json and report.html into")
	wantPDF := fs.Bool("pdf", false, "also run the configured pdf.command against the rendered HTML")
	nowRaw := fs.String("now", "", "override the report timestamp, RFC3339 (for reproducible output)")
	quiet := fs.Bool("quiet", false, "only print errors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("gen: -config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if *nowRaw != "" {
		now, err = time.Parse(time.RFC3339, *nowRaw)
		if err != nil {
			return fmt.Errorf("-now: %w", err)
		}
		now = now.UTC()
	}

	rep, warnings, err := collect.Run(ctx, cfg, collect.Options{Now: now})
	if err != nil {
		return err
	}

	// Acceptances are applied before the delta so it can tell a finding that
	// moved into the accepted-risks appendix from one that was resolved.
	if cfg.Accepted != "" {
		reg, err := accept.Load(cfg.Resolve(cfg.Accepted))
		if err != nil {
			return fmt.Errorf("accepted risks: %w", err)
		}
		warnings = append(warnings, accept.Apply(rep, reg)...)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+w)
	}

	var prev *model.Report
	if cfg.PreviousReport != "" {
		prev, err = delta.LoadReport(cfg.Resolve(cfg.PreviousReport))
		if err != nil {
			return fmt.Errorf("previous report: %w", err)
		}
	}
	delta.Apply(rep, prev)

	narr, err := narrative.LoadFile(cfg.Resolve(cfg.NarrativeFile))
	if err != nil {
		return fmt.Errorf("narrative: %w", err)
	}
	rep.Narrative = string(narr)

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return err
	}
	findingsPath := filepath.Join(*outDir, "findings.json")
	if err := writeJSON(findingsPath, rep); err != nil {
		return err
	}

	brand, err := render.BrandingFrom(cfg)
	if err != nil {
		return err
	}
	view := render.BuildView(rep, brand, cfg.Sections(), narr)

	htmlPath := filepath.Join(*outDir, "report.html")
	htmlFile, err := os.Create(htmlPath) // #nosec G304 -- path is built from the operator's -out flag
	if err != nil {
		return err
	}
	if err := render.HTML(htmlFile, view); err != nil {
		htmlFile.Close()
		return err
	}
	if err := htmlFile.Close(); err != nil {
		return err
	}

	pdfPath := ""
	if *wantPDF {
		if len(cfg.PDF.Command) == 0 {
			return errors.New("-pdf given but pdf.command is not set in the config")
		}
		pdfPath = filepath.Join(*outDir, cfg.PDF.Output)
		if err := render.PDF(ctx, cfg.PDF.Command, htmlPath, pdfPath); err != nil {
			return err
		}
	}

	if !*quiet {
		printSummary(os.Stdout, rep, findingsPath, htmlPath, pdfPath)
	}
	return nil
}

func printSummary(w *os.File, rep *model.Report, findingsPath, htmlPath, pdfPath string) {
	counts := rep.SeverityCounts()
	fmt.Fprintf(w, "%s — %s — account %s\n", rep.Tenant, rep.Period.Label, rep.Account.ID)
	fmt.Fprintf(w, "  findings: %d (critical %d, high %d, medium %d, low %d, info %d)\n",
		len(rep.Findings),
		counts[model.SeverityCritical], counts[model.SeverityHigh],
		counts[model.SeverityMedium], counts[model.SeverityLow], counts[model.SeverityInfo])
	if n, reReview := len(rep.Accepted), rep.ReReviewCount(); n > 0 || reReview > 0 {
		fmt.Fprintf(w, "  accepted: %d excluded from the totals, %d expired and due for re-review\n", n, reReview)
	}
	fmt.Fprintf(w, "  spend:    $%.2f (%+.2f vs previous month)\n", rep.Cost.CurrentUSD, rep.Cost.DeltaUSD())
	fmt.Fprintf(w, "  waste:    $%.2f/month attached to open findings\n", rep.IdentifiedWasteUSD())
	if d := rep.Delta; d != nil {
		fmt.Fprintf(w, "  delta:    %d new, %d open, %d resolved ($%.2f/month recovered)\n",
			d.New, d.Open, d.Resolved, d.ResolvedSavings)
	}
	fmt.Fprintf(w, "  wrote:    %s\n", findingsPath)
	fmt.Fprintf(w, "            %s\n", htmlPath)
	if pdfPath != "" {
		fmt.Fprintf(w, "            %s\n", pdfPath)
	}
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the tenant config JSON (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("validate: -config is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	// Loading only proves the config parses. A source file that does not exist
	// is the failure an operator actually hits at 23:00 on the 4th.
	var missing []string
	for _, s := range cfg.Sources {
		if s.File == "" {
			continue
		}
		if _, err := os.Stat(cfg.Resolve(s.File)); err != nil {
			missing = append(missing, fmt.Sprintf("%s: %v", s.Adapter, err))
		}
	}
	if cfg.NarrativeFile != "" {
		if _, err := os.Stat(cfg.Resolve(cfg.NarrativeFile)); err != nil {
			missing = append(missing, fmt.Sprintf("narrative_file: %v", err))
		}
	}
	if cfg.Accepted != "" {
		if _, err := accept.Load(cfg.Resolve(cfg.Accepted)); err != nil {
			missing = append(missing, fmt.Sprintf("accepted: %v", err))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config is valid but inputs are missing or invalid:\n  - %s", strings.Join(missing, "\n  - "))
	}

	fmt.Printf("ok: %s — %s, %d sources, sections %v\n",
		cfg.Tenant.Name, cfg.Period.Label, len(cfg.Sources), cfg.Sections())
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	curPath := fs.String("current", "", "path to this period's findings.json (required)")
	prevPath := fs.String("previous", "", "path to the previous findings.json (required)")
	asJSON := fs.Bool("json", false, "print the delta as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *curPath == "" || *prevPath == "" {
		return errors.New("diff: -current and -previous are both required")
	}
	cur, err := delta.LoadReport(*curPath)
	if err != nil {
		return err
	}
	prev, err := delta.LoadReport(*prevPath)
	if err != nil {
		return err
	}
	delta.Apply(cur, prev)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cur.Delta)
	}

	d := cur.Delta
	fmt.Printf("%s -> %s\n", prev.Period.Label, cur.Period.Label)
	fmt.Printf("  new:      %d\n", d.New)
	fmt.Printf("  open:     %d\n", d.Open)
	fmt.Printf("  resolved: %d ($%.2f/month recovered)\n", d.Resolved, d.ResolvedSavings)
	for _, f := range delta.NewFindings(cur) {
		fmt.Printf("  + [%s] %s\n", f.Severity, f.Title)
	}
	for _, f := range d.ResolvedList {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Title)
	}
	if d.Accepted > 0 || len(d.Reopened) > 0 {
		fmt.Printf("  accepted: %d (%d newly accepted, %d back to open)\n",
			d.Accepted, len(d.NewlyAccepted), len(d.Reopened))
	}
	for _, f := range d.NewlyAccepted {
		// A hand-edited findings file can carry an accepted entry with no
		// acceptance block; print what is there rather than panic.
		if f.Acceptance != nil {
			fmt.Printf("  = [%s] %s (accepted until %s)\n", f.Severity, f.Title, f.Acceptance.Expires.Format("2006-01-02"))
		} else {
			fmt.Printf("  = [%s] %s (accepted)\n", f.Severity, f.Title)
		}
	}
	for _, f := range d.Reopened {
		if f.Acceptance != nil {
			fmt.Printf("  ! [%s] %s (acceptance expired %s)\n", f.Severity, f.Title, f.Acceptance.Expires.Format("2006-01-02"))
		} else {
			fmt.Printf("  ! [%s] %s (acceptance withdrawn)\n", f.Severity, f.Title)
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path) // #nosec G304 -- path is built from the operator's -out flag
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return f.Close()
}
