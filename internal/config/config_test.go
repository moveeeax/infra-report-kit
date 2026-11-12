package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `{
  "tenant": {"name": "Northwind Cloud Services", "primary_color": "#0B2545", "accent_color": "#0B5FFF"},
  "account": {"provider": "aws", "id": "123456789012", "label": "Acme Retail"},
  "period": {"label": "2026-06", "start": "2026-06-01", "end": "2026-06-30"},
  "sources": [{"adapter": "aws-sg-audit", "file": "in/sg.json"}]
}`

// writeConfig drops a config into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenant.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tenant.Name != "Northwind Cloud Services" {
		t.Errorf("tenant = %q", cfg.Tenant.Name)
	}
	p, err := cfg.ParsePeriod()
	if err != nil {
		t.Fatalf("ParsePeriod: %v", err)
	}
	if p.Start.Month() != 6 || p.Start.Day() != 1 {
		t.Errorf("period start = %v, want 1 June", p.Start)
	}
	if got := cfg.Sections(); len(got) != 3 || got[0] != "cost" {
		t.Errorf("default sections = %v, want cost, security, reliability", got)
	}
}

func TestResolveIsRelativeToTheConfigFile(t *testing.T) {
	path := writeConfig(t, validConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(path), "in/sg.json")
	if got := cfg.Resolve("in/sg.json"); got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
	if got := cfg.Resolve("/etc/hosts"); got != "/etc/hosts" {
		t.Errorf("absolute paths must pass through, got %q", got)
	}
	if got := cfg.Resolve(""); got != "" {
		t.Errorf("empty path must stay empty, got %q", got)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"no tenant name",
			`{"tenant":{},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"tenant.name is required"},
		{"bad colour",
			`{"tenant":{"name":"N","primary_color":"blue"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"hex colour"},
		{"unknown adapter",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"prowler","file":"a.json"}]}`,
			"unknown adapter"},
		{"no source input",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck"}]}`,
			"set either file or command"},
		{"both source inputs",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck","file":"a.json","command":["x"]}]}`,
			"not both"},
		{"no sources",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[]}`,
			"at least one source"},
		{"unknown section",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"section_order":["compliance"],"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"unknown section"},
		{"end before start",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-30","end":"2026-06-01"},"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"must be after"},
		{"missing period",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"period.label is required"},
		{"pdf command without placeholders",
			`{"tenant":{"name":"N"},"account":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck","file":"a.json"}],"pdf":{"command":["chrome","--print-to-pdf"],"output":"r.pdf"}}`,
			"{{input}} and {{output}}"},
		{"typo in a key",
			`{"tenant":{"name":"N"},"acount":{"id":"1"},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"certcheck","file":"a.json"}]}`,
			"unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, c.body))
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error %q does not mention %q", err, c.wantSub)
			}
		})
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	body := `{"tenant":{"name":"","primary_color":"nope"},"account":{},"period":{"label":"2026-06","start":"2026-06-01","end":"2026-06-30"},"sources":[{"adapter":"nope"}]}`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"tenant.name", "hex colour", "account.id", "unknown adapter", "set either file or command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must list %q so the operator fixes everything in one pass:\n%v", want, err)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("want an error for a missing config")
	}
}

func TestAcceptedRegisterPathResolvesRelativeToTheConfig(t *testing.T) {
	body := strings.Replace(validConfig, `"sources"`, `"accepted": "accepted.json", "sources"`, 1)
	path := writeConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.Resolve(cfg.Accepted), filepath.Join(filepath.Dir(path), "accepted.json"); got != want {
		t.Errorf("accepted resolves to %q, want %q", got, want)
	}
}
