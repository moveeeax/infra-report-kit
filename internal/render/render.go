// Package render turns a findings report plus tenant branding into a single
// self-contained HTML file, sized and paginated for A4 print-to-PDF.
package render

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/moveeeax/infra-report-kit/internal/config"
	"github.com/moveeeax/infra-report-kit/internal/model"
)

//go:embed report.html.tmpl
var templates embed.FS

// Branding is everything that makes the report the MSP's rather than anyone
// else's. There is no field here for whoever generated it, by design.
type Branding struct {
	Name         string
	PrimaryColor string
	AccentColor  string
	LogoDataURI  template.URL
	Contact      string
	Footer       string
}

// SectionView is one rendered chapter.
type SectionView struct {
	Key      model.Section
	Title    string
	Findings []model.Finding
}

// View is the complete template input.
type View struct {
	Brand     Branding
	Report    *model.Report
	Sections  []SectionView
	Narrative template.HTML
	TopWaste  []model.Finding
	TopMovers []model.ServiceCost
	Counts    map[model.Severity]int
}

const (
	defaultPrimary = "#1F2937"
	defaultAccent  = "#2563EB"
	topWasteItems  = 5
	topMoverItems  = 10
)

// BrandingFrom builds the branding block, inlining the logo as a data URI so
// the HTML prints identically with no network access.
func BrandingFrom(cfg *config.Config) (Branding, error) {
	b := Branding{
		Name:         cfg.Tenant.Name,
		PrimaryColor: orDefault(cfg.Tenant.PrimaryColor, defaultPrimary),
		AccentColor:  orDefault(cfg.Tenant.AccentColor, defaultAccent),
		Contact:      cfg.Tenant.Contact,
		Footer:       cfg.Tenant.Footer,
	}
	if cfg.Tenant.LogoPath != "" {
		uri, err := logoDataURI(cfg.Resolve(cfg.Tenant.LogoPath))
		if err != nil {
			return b, err
		}
		b.LogoDataURI = uri
	}
	return b, nil
}

func logoDataURI(path string) (template.URL, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("tenant logo: %w", err)
	}
	var mime string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		mime = "image/png"
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	case ".svg":
		mime = "image/svg+xml"
	default:
		return "", fmt.Errorf("tenant logo %s: unsupported type, use png, jpg or svg", path)
	}
	// #nosec G203 -- the value is a base64 data URI built here, not user markup
	return template.URL("data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(raw)), nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// BuildView assembles the template input for a report.
func BuildView(rep *model.Report, brand Branding, sections []model.Section, narr template.HTML) View {
	v := View{
		Brand:     brand,
		Report:    rep,
		Narrative: narr,
		TopWaste:  rep.TopWaste(topWasteItems),
		TopMovers: rep.Cost.TopServicesByDelta(topMoverItems),
		Counts:    rep.SeverityCounts(),
	}
	for _, s := range sections {
		v.Sections = append(v.Sections, SectionView{
			Key:      s,
			Title:    s.Title(),
			Findings: rep.BySection(s),
		})
	}
	return v
}

var funcs = template.FuncMap{
	"usd": func(f float64) string {
		neg := f < 0
		f = math.Abs(f)
		s := fmt.Sprintf("$%s", withThousands(fmt.Sprintf("%.2f", f)))
		if neg {
			return "-" + s
		}
		return s
	},
	// signedUSD returns template.HTML so the leading "+" survives: html/template
	// escapes a bare plus to &#43;, which is correct but reads badly in the
	// findings JSON-to-HTML diffs an operator eyeballs before sending. The value
	// is built here from a float and contains no caller input.
	"signedUSD": func(f float64) template.HTML {
		sign := "+"
		if f < 0 {
			sign = "-"
		}
		// #nosec G203 -- fully generated from a float64, no user input
		return template.HTML(sign + "$" + withThousands(fmt.Sprintf("%.2f", math.Abs(f))))
	},
	"pct":   func(f float64) string { return fmt.Sprintf("%.2f%%", f) },
	"pct3":  func(f float64) string { return fmt.Sprintf("%.3f%%", f) },
	"upper": strings.ToUpper,
	"date":  func(t interface{ Format(string) string }) string { return t.Format("2 January 2006") },
	"trend": func(f float64) string {
		switch {
		case f > 0:
			return "up"
		case f < 0:
			return "down"
		default:
			return "flat"
		}
	},
	"ageDays": func(rep *model.Report, f model.Finding) int {
		if f.FirstSeen.IsZero() {
			return 0
		}
		d := rep.GeneratedAt.Sub(f.FirstSeen).Hours() / 24
		if d < 0 {
			return 0
		}
		return int(d)
	},
	// count reads the severity tally with a plain string key, which the
	// template's untyped constants cannot do against map[model.Severity]int.
	"count": func(m map[model.Severity]int, sev string) int { return m[model.Severity(sev)] },
}

// withThousands inserts thousands separators into a plain "1234.56" string.
func withThousands(s string) string {
	intPart, frac, _ := strings.Cut(s, ".")
	var out []byte
	for i, c := range []byte(intPart) {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if frac == "" {
		return string(out)
	}
	return string(out) + "." + frac
}

// HTML renders the report to w.
func HTML(w io.Writer, v View) error {
	t, err := template.New("report.html.tmpl").Funcs(funcs).ParseFS(templates, "report.html.tmpl")
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}
