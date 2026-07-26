package narrative

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderParagraphsAndBullets(t *testing.T) {
	got := string(Render(`## What changed

Spend rose sharply
in June.

- Close the bastion
- Delete the contractor account

That is all.`))

	for _, want := range []string{
		"<h3>What changed</h3>",
		"<p>Spend rose sharply in June.</p>",
		"<ul>\n<li>Close the bastion</li>\n<li>Delete the contractor account</li>\n</ul>",
		"<p>That is all.</p>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderEscapesHTML(t *testing.T) {
	got := string(Render(`A client wrote <script>alert(1)</script> in the notes.`))
	if strings.Contains(got, "<script>") {
		t.Fatalf("narrative text must never reach the page as markup:\n%s", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Fatalf("want the tag escaped, got:\n%s", got)
	}
}

func TestRenderEscapesInsideBulletsAndHeadings(t *testing.T) {
	got := string(Render("## <b>bold heading</b>\n\n- <img src=x onerror=y>"))
	if strings.Contains(got, "<b>") || strings.Contains(got, "<img") {
		t.Fatalf("markup leaked through a heading or bullet:\n%s", got)
	}
}

func TestInlineFormatting(t *testing.T) {
	got := string(Render("Spend rose by **$700.71** in `eu-west-1`."))
	if !strings.Contains(got, "<strong>$700.71</strong>") {
		t.Errorf("bold not applied:\n%s", got)
	}
	if !strings.Contains(got, "<code>eu-west-1</code>") {
		t.Errorf("code not applied:\n%s", got)
	}
}

func TestUnpairedMarkerStaysLiteral(t *testing.T) {
	got := string(Render("The cost is **$40 and rising"))
	if strings.Contains(got, "<strong>") {
		t.Fatalf("an unpaired ** must not open a tag that swallows the rest of the line:\n%s", got)
	}
	if !strings.Contains(got, "**$40 and rising") {
		t.Errorf("literal text lost:\n%s", got)
	}
}

func TestHeadingLevels(t *testing.T) {
	got := string(Render("# One\n\n## Two\n\n### Three"))
	if strings.Count(got, "<h3>") != 2 || !strings.Contains(got, "<h4>Three</h4>") {
		t.Errorf("heading levels wrong (# and ## both map to h3, ### to h4):\n%s", got)
	}
}

func TestCRLFInput(t *testing.T) {
	got := string(Render("Line one\r\n\r\n- bullet\r\n"))
	if !strings.Contains(got, "<p>Line one</p>") || !strings.Contains(got, "<li>bullet</li>") {
		t.Errorf("CRLF input mishandled:\n%s", got)
	}
}

func TestEmptyInput(t *testing.T) {
	if got := string(Render("")); got != "" {
		t.Errorf("empty narrative rendered %q, want empty", got)
	}
}

func TestLoadFile(t *testing.T) {
	if got, err := LoadFile(""); err != nil || got != "" {
		t.Fatalf("empty path: got (%q, %v), want empty and no error", got, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "narrative.md")
	if err := os.WriteFile(path, []byte("## Heading\n\nBody."), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "<h3>Heading</h3>") {
		t.Errorf("LoadFile = %q", got)
	}
	if _, err := LoadFile(filepath.Join(dir, "nope.md")); err == nil {
		t.Error("want an error for a missing narrative file")
	}
}
