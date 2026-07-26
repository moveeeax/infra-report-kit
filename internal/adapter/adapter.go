// Package adapter turns the JSON output of the standalone scanners into the
// normalised model.Report. One adapter per upstream CLI. Adapters never call
// the cloud themselves — they only parse what a scanner already produced, so
// every one of them is testable from a fixture file with no credentials.
package adapter

import (
	"fmt"
	"sort"

	"github.com/moveeeax/infra-report-kit/internal/model"
)

// Adapter parses one upstream tool's JSON output into a report.
type Adapter interface {
	// Name is the value used in tenant config and in Finding.Source.
	Name() string
	// Parse decodes raw and appends whatever it found to r.
	Parse(raw []byte, r *model.Report) error
}

var registry = map[string]Adapter{}

func register(a Adapter) { registry[a.Name()] = a }

func init() {
	register(costExplorer{})
	register(orphanFinder{})
	register(sgAudit{})
	register(s3PublicAudit{})
	register(iamLeastPriv{})
	register(certCheck{})
	register(uptimePing{})
	register(sloCalc{})
	register(k8sRightsize{})
	register(k8sCrashloop{})
}

// Get returns the adapter registered under name.
func Get(name string) (Adapter, error) {
	a, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown adapter %q (known: %v)", name, Names())
	}
	return a, nil
}

// Names lists every registered adapter, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// account falls back to the report's account when a scanner did not stamp one
// into its output.
func account(scanned string, r *model.Report) string {
	if scanned != "" {
		return scanned
	}
	return r.Account.ID
}
