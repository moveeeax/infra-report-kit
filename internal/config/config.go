// Package config loads the per-tenant report definition: who the report is
// branded for, which account it covers, which scanner outputs feed it and where
// last month's findings live.
//
// Config is JSON on purpose. This binary has no third-party dependencies, and a
// config an MSP can generate from their own tooling with `jq` is worth more
// than YAML niceties.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/moveeeax/infra-report-kit/internal/adapter"
	"github.com/moveeeax/infra-report-kit/internal/model"
)

// Tenant is the white-label block. Everything the client sees on the cover
// comes from here; nothing identifies whoever generated the report.
type Tenant struct {
	Name         string `json:"name"`
	PrimaryColor string `json:"primary_color"`
	AccentColor  string `json:"accent_color,omitempty"`
	// LogoPath points at a PNG or SVG that is inlined as a data URI, so the
	// rendered HTML is a single self-contained file and prints without network.
	LogoPath string `json:"logo_path,omitempty"`
	Contact  string `json:"contact,omitempty"`
	Footer   string `json:"footer,omitempty"`
}

// Source is one scanner feeding the report. Exactly one of File or Command
// must be set: read a JSON file a scanner already wrote, or run the scanner.
type Source struct {
	Adapter string   `json:"adapter"`
	File    string   `json:"file,omitempty"`
	Command []string `json:"command,omitempty"`
	// Optional marks a source whose failure must not fail the whole report.
	Optional bool `json:"optional,omitempty"`
}

// PDF describes how to turn the rendered HTML into a PDF. The command is run
// verbatim with {{input}} and {{output}} substituted; this tool deliberately
// does not bundle a browser.
type PDF struct {
	Command []string `json:"command,omitempty"`
	Output  string   `json:"output,omitempty"`
}

// Period is the month covered, as written in config.
type Period struct {
	Label string `json:"label"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// Config is a whole tenant report definition.
type Config struct {
	Tenant         Tenant        `json:"tenant"`
	Account        model.Account `json:"account"`
	Period         Period        `json:"period"`
	SectionOrder   []string      `json:"section_order,omitempty"`
	NarrativeFile  string        `json:"narrative_file,omitempty"`
	Sources        []Source      `json:"sources"`
	PreviousReport string        `json:"previous_report,omitempty"`
	// Accepted points at the accepted-risk register: a JSON array of
	// {fingerprint, reason, accepted_by, expires}. See package accept.
	Accepted string `json:"accepted,omitempty"`
	PDF      PDF    `json:"pdf,omitempty"`

	// dir is the directory the config was loaded from; all relative paths in
	// the config resolve against it, not against the caller's cwd.
	dir string
}

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Load reads and validates a tenant config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Validate checks everything that can be checked without touching the network
// or the cloud, so a typo fails in a second rather than halfway through a run.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if strings.TrimSpace(c.Tenant.Name) == "" {
		add("tenant.name is required: it is the name printed on the cover")
	}
	if c.Tenant.PrimaryColor != "" && !hexColor.MatchString(c.Tenant.PrimaryColor) {
		add("tenant.primary_color %q must be a #rrggbb hex colour", c.Tenant.PrimaryColor)
	}
	if c.Tenant.AccentColor != "" && !hexColor.MatchString(c.Tenant.AccentColor) {
		add("tenant.accent_color %q must be a #rrggbb hex colour", c.Tenant.AccentColor)
	}
	if c.Account.ID == "" {
		add("account.id is required")
	}
	if _, err := c.ParsePeriod(); err != nil {
		add("%v", err)
	}
	for _, s := range c.SectionOrder {
		if !model.Section(s).Valid() {
			add("section_order contains unknown section %q (known: cost, security, reliability)", s)
		}
	}
	if len(c.Sources) == 0 {
		add("at least one source is required")
	}
	for i, s := range c.Sources {
		if _, err := adapter.Get(s.Adapter); err != nil {
			add("sources[%d]: %v", i, err)
		}
		switch {
		case s.File == "" && len(s.Command) == 0:
			add("sources[%d] (%s): set either file or command", i, s.Adapter)
		case s.File != "" && len(s.Command) > 0:
			add("sources[%d] (%s): set file or command, not both", i, s.Adapter)
		}
	}
	if len(c.PDF.Command) > 0 {
		if !containsPlaceholder(c.PDF.Command, "{{input}}") || !containsPlaceholder(c.PDF.Command, "{{output}}") {
			add("pdf.command must contain both {{input}} and {{output}} placeholders")
		}
		if c.PDF.Output == "" {
			add("pdf.output is required when pdf.command is set")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func containsPlaceholder(args []string, ph string) bool {
	for _, a := range args {
		if strings.Contains(a, ph) {
			return true
		}
	}
	return false
}

// ParsePeriod turns the config period into model.Period. Dates are YYYY-MM-DD
// and interpreted as UTC, because a monthly report that shifts by a timezone is
// a support ticket.
func (c *Config) ParsePeriod() (model.Period, error) {
	if c.Period.Label == "" {
		return model.Period{}, fmt.Errorf("period.label is required (for example 2026-06)")
	}
	start, err := time.Parse("2006-01-02", c.Period.Start)
	if err != nil {
		return model.Period{}, fmt.Errorf("period.start %q must be YYYY-MM-DD", c.Period.Start)
	}
	end, err := time.Parse("2006-01-02", c.Period.End)
	if err != nil {
		return model.Period{}, fmt.Errorf("period.end %q must be YYYY-MM-DD", c.Period.End)
	}
	if !end.After(start) {
		return model.Period{}, fmt.Errorf("period.end %s must be after period.start %s", c.Period.End, c.Period.Start)
	}
	return model.Period{Label: c.Period.Label, Start: start, End: end}, nil
}

// Sections returns the configured section order, or the default order.
func (c *Config) Sections() []model.Section {
	if len(c.SectionOrder) == 0 {
		return model.Sections
	}
	out := make([]model.Section, 0, len(c.SectionOrder))
	for _, s := range c.SectionOrder {
		out = append(out, model.Section(s))
	}
	return out
}

// Resolve turns a config-relative path into an absolute one. Empty stays empty.
func (c *Config) Resolve(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// SetDir overrides the base directory used by Resolve. Tests use it; Load sets
// it from the config file's own location.
func (c *Config) SetDir(dir string) { c.dir = dir }
