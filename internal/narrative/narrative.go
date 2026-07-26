// Package narrative renders the one page of hand-written commentary that turns
// a scan dump into a report someone paid for.
//
// It supports a deliberately tiny Markdown subset — headings, bullets,
// paragraphs, bold and inline code — because the narrative is written by the
// engineer who signs the report, not by a CMS, and every extra feature is a way
// for a client-facing document to render wrong.
package narrative

import (
	"html/template"
	"os"
	"strings"
)

// Render converts the supported Markdown subset to HTML. All input is escaped
// before any markup is applied, so narrative text can never inject HTML.
func Render(src string) template.HTML {
	var b strings.Builder
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")

	var para []string
	var bullets []string

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		b.WriteString("<p>" + inline(strings.Join(para, " ")) + "</p>\n")
		para = nil
	}
	flushBullets := func() {
		if len(bullets) == 0 {
			return
		}
		b.WriteString("<ul>\n")
		for _, item := range bullets {
			b.WriteString("<li>" + inline(item) + "</li>\n")
		}
		b.WriteString("</ul>\n")
		bullets = nil
	}
	flush := func() { flushPara(); flushBullets() }

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "### "):
			flush()
			b.WriteString("<h4>" + inline(strings.TrimPrefix(trimmed, "### ")) + "</h4>\n")
		case strings.HasPrefix(trimmed, "## "):
			flush()
			b.WriteString("<h3>" + inline(strings.TrimPrefix(trimmed, "## ")) + "</h3>\n")
		case strings.HasPrefix(trimmed, "# "):
			flush()
			b.WriteString("<h3>" + inline(strings.TrimPrefix(trimmed, "# ")) + "</h3>\n")
		case strings.HasPrefix(trimmed, "- "), strings.HasPrefix(trimmed, "* "):
			flushPara()
			bullets = append(bullets, trimmed[2:])
		default:
			flushBullets()
			para = append(para, trimmed)
		}
	}
	flush()

	return template.HTML(b.String()) // #nosec G203 -- inline() escapes before any markup is added
}

// LoadFile reads a narrative file and renders it. An empty path renders empty.
func LoadFile(path string) (template.HTML, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Render(string(raw)), nil
}

// inline escapes the text, then applies **bold** and `code`.
func inline(s string) string {
	escaped := template.HTMLEscapeString(s)
	escaped = wrapPairs(escaped, "**", "<strong>", "</strong>")
	escaped = wrapPairs(escaped, "`", "<code>", "</code>")
	return escaped
}

// wrapPairs replaces balanced pairs of marker with open/close tags. An unpaired
// trailing marker is left as literal text rather than swallowing the rest of
// the line.
func wrapPairs(s, marker, openTag, closeTag string) string {
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, marker)
		if i < 0 {
			break
		}
		j := strings.Index(rest[i+len(marker):], marker)
		if j < 0 {
			break
		}
		b.WriteString(rest[:i])
		b.WriteString(openTag)
		b.WriteString(rest[i+len(marker) : i+len(marker)+j])
		b.WriteString(closeTag)
		rest = rest[i+2*len(marker)+j:]
	}
	b.WriteString(rest)
	return b.String()
}
