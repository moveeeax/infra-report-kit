// Package collect runs every configured source and folds the results into one
// normalised report.
package collect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/adapter"
	"github.com/moveeeax/infra-report-kit/internal/config"
	"github.com/moveeeax/infra-report-kit/internal/model"
)

// DefaultTimeout caps how long a single scanner may run. An account scan that
// hangs must not hold up the whole report.
const DefaultTimeout = 10 * time.Minute

// Options tunes a collection run.
type Options struct {
	// Now is the report timestamp. Tests pin it; production passes time.Now.
	Now time.Time
	// Timeout caps each source command. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Run executes every source in config order and returns the assembled report
// plus warnings for optional sources that failed.
//
// A non-optional source that fails aborts the run: shipping a client a report
// with a silently missing security section is worse than shipping nothing.
func Run(ctx context.Context, cfg *config.Config, opts Options) (*model.Report, []string, error) {
	period, err := cfg.ParsePeriod()
	if err != nil {
		return nil, nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	rep := model.New(cfg.Tenant.Name, cfg.Account, period, now)

	var warnings []string
	for i, src := range cfg.Sources {
		a, err := adapter.Get(src.Adapter)
		if err != nil {
			return nil, nil, err
		}
		raw, err := read(ctx, cfg, src, timeout)
		if err == nil {
			err = a.Parse(raw, rep)
		}
		if err != nil {
			if src.Optional {
				warnings = append(warnings, fmt.Sprintf("source %d (%s) skipped: %v", i, src.Adapter, err))
				continue
			}
			return nil, nil, fmt.Errorf("source %d (%s): %w", i, src.Adapter, err)
		}
	}

	rep.Dedupe()
	rep.Sort()
	return rep, warnings, nil
}

// read gets one source's raw JSON, from disk or by running the scanner.
func read(ctx context.Context, cfg *config.Config, src config.Source, timeout time.Duration) ([]byte, error) {
	if src.File != "" {
		return os.ReadFile(cfg.Resolve(src.File))
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, src.Command[0], src.Command[1:]...) // #nosec G204 -- command comes from the operator's own tenant config
	cmd.Dir = cfg.Resolve(".")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running %q: %w: %s", src.Command[0], err, truncate(stderr.String(), 400))
	}
	if stdout.Len() == 0 {
		return nil, fmt.Errorf("running %q: produced no output", src.Command[0])
	}
	return stdout.Bytes(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
