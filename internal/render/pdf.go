package render

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PDFTimeout caps how long the external renderer may run.
const PDFTimeout = 5 * time.Minute

// ExpandCommand substitutes {{input}} and {{output}} in a PDF command template.
//
// It is deliberately a plain argv substitution with no shell involved: the
// argument vector is passed to exec as-is, so a path containing spaces or
// shell metacharacters cannot turn into a second command.
func ExpandCommand(argv []string, input, output string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		a = strings.ReplaceAll(a, "{{input}}", input)
		a = strings.ReplaceAll(a, "{{output}}", output)
		out[i] = a
	}
	return out
}

// PDF drives an external headless browser to turn htmlPath into outPath.
//
// This tool does not bundle a renderer. The operator supplies the command in
// tenant config, typically a headless Chrome container:
//
//	["docker","run","--rm","-v","{{dir}}:/work","ghcr.io/example/headless-chrome",
//	 "--print-to-pdf=/work/report.pdf","/work/report.html"]
func PDF(ctx context.Context, argv []string, htmlPath, outPath string) error {
	if len(argv) == 0 {
		return fmt.Errorf("no pdf command configured")
	}
	if _, err := os.Stat(htmlPath); err != nil {
		return fmt.Errorf("pdf input: %w", err)
	}
	args := ExpandCommand(argv, htmlPath, outPath)

	cctx, cancel := context.WithTimeout(ctx, PDFTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, args[0], args[1:]...) // #nosec G204 -- command comes from the operator's own tenant config
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pdf renderer %q: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	if st, err := os.Stat(outPath); err != nil || st.Size() == 0 {
		return fmt.Errorf("pdf renderer %q exited cleanly but wrote no output to %s", args[0], outPath)
	}
	return nil
}
