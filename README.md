# infra-report-kit

Turns the JSON output of a pile of standalone cloud scanners into one
white-label monthly infrastructure report — cost, security, reliability — that
a managed service provider hands to their client under their own logo.

It is the plumbing behind a done-for-you reporting service, not a SaaS. There
is no dashboard, no login, no scheduler. One command produces two files: a
normalised `findings.json` and a print-ready `report.html`.

**`infra-report` never talks to a cloud provider.** The scanners hold the
credentials; this tool only normalises, compares and renders what they already
produced. That is a deliberate boundary: it means the whole pipeline runs, and
is tested, without a single secret.

## What it does

- **Normalises** ten scanner formats into one findings model with a stable
  fingerprint per finding.
- **Grades** every finding — a world-open PostgreSQL port is critical, an
  unattached `$3.60/month` elastic IP is low — with the rules written down in
  [`docs/adapters.md`](docs/adapters.md) rather than buried in a template.
- **Diffs** against last month's `findings.json`: what is new, what is still
  open and how long for, what was resolved and how much recurring spend that
  removed. This is the part an MSP can charge for every month.
- **Sets aside accepted risks.** A finding the client has decided to live with,
  until a date, moves to an appendix and out of the totals instead of reading
  "still open, 9 months" in every report. When the acceptance expires it comes
  back, flagged for re-review.
- **Renders** a single self-contained HTML file with the MSP's logo, colours,
  contact block and footer, sized for A4 and ready for print-to-PDF. No
  external fonts, no CDN, no network at render time.

## Install

```sh
go install github.com/moveeeax/infra-report-kit/cmd/infra-report@latest
```

Or from a clone — no third-party dependencies, so this needs nothing but Go:

```sh
git clone https://github.com/moveeeax/infra-report-kit
cd infra-report-kit
make build      # -> bin/infra-report
```

Requires Go 1.26 or newer.

## Usage example

The repository ships a complete example tenant — a fictional MSP called
Northwind reporting on a fictional client account — with real scanner fixtures,
a hand-written narrative and last month's findings to diff against. This runs
straight after a clone:

```sh
make build
./bin/infra-report gen -config examples/acme/acme-2026-06.json -out out
```

```
Northwind Cloud Services — 2026-06 — account 123456789012
  findings: 24 (critical 6, high 7, medium 6, low 5, info 0)
  accepted: 1 excluded from the totals, 1 expired and due for re-review
  spend:    $7927.43 (+698.81 vs previous month)
  waste:    $406.25/month attached to open findings
  delta:    3 new, 21 open, 2 resolved ($47.30/month recovered)
  wrote:    out/findings.json
            out/report.html
```

Open `out/report.html` in a browser and print it to PDF, or drive a headless
browser (see [PDF output](#pdf-output)).

Ask what moved without rendering anything:

```sh
./bin/infra-report diff \
  -current  out/findings.json \
  -previous examples/acme/history/2026-05/findings.json
```

```
2026-05 -> 2026-06
  new:      3
  open:     21
  resolved: 2 ($47.30/month recovered)
  + [critical] Security group sg-0cc99dd00ee11ff22 (db-temp) accepts traffic from the internet
  + [critical] Certificate for legacy.example.com has expired
  + [high] payments/Deployment/settlement restarted 214 times in the period
  - [high] Orphaned ec2:nat-gateway nat-0a9b8c7d6e5f40312 costs $47.30/month
  - [critical] Bucket acme-invoices-export is readable from the internet
  accepted: 1 (1 newly accepted, 1 back to open)
  = [critical] Bucket acme-public-assets is readable from the internet (accepted until 2026-12-31)
  ! [low] Orphaned rds:snapshot rds:orders-2024-11-02 costs $11.05/month (acceptance expired 2026-06-15)
```

`+` is new, `-` resolved, `=` accepted this period, `!` accepted last period
and back among the open findings because the acceptance expired or was
removed from the register.

Check a config before the scanners run:

```sh
./bin/infra-report validate -config examples/acme/acme-2026-06.json
# ok: Northwind Cloud Services — 2026-06, 10 sources, sections [cost security reliability]
```

## Commands

| Command | What it does |
| --- | --- |
| `gen -config F [-out DIR] [-pdf] [-now RFC3339] [-quiet]` | Run every source, apply the delta, write `findings.json` and `report.html`. |
| `validate -config F` | Check the config and that every input file exists. Touches nothing else. |
| `diff -current A -previous B [-json]` | Compare two findings files. |
| `adapters` | List the scanner formats this build understands. |
| `version` | Binary version and findings schema version. |

`-now` pins the report timestamp, which makes output byte-for-byte
reproducible — useful when regenerating a report someone has already been sent.

## Tenant config

One JSON file per client account per month. Every path in it resolves relative
to the config file, so a tenant directory is self-contained and movable.

```json
{
  "tenant": {
    "name": "Northwind Cloud Services",
    "primary_color": "#0B2545",
    "accent_color": "#0B5FFF",
    "logo_path": "brand/logo.svg",
    "contact": "service-desk@northwind.example",
    "footer": "Prepared under the Northwind Cloud Services managed agreement. Confidential."
  },
  "account": {"provider": "aws", "id": "123456789012", "label": "Acme Retail — Production"},
  "period": {"label": "2026-06", "start": "2026-06-01", "end": "2026-06-30"},
  "section_order": ["cost", "security", "reliability"],
  "narrative_file": "narrative.md",
  "previous_report": "history/2026-05/findings.json",
  "accepted": "accepted.json",
  "sources": [
    {"adapter": "cost-export",   "file": "in/cost-export.json"},
    {"adapter": "aws-sg-audit",  "command": ["aws-sg-audit", "--json"]},
    {"adapter": "k8s-rightsize", "file": "in/k8s-rightsize.json", "optional": true}
  ]
}
```

- A source reads a file a scanner already wrote, **or** runs the scanner and
  reads its stdout. Not both.
- `optional: true` downgrades a failure to a warning. Anything else aborts the
  run — shipping a client a report with a silently missing security section is
  worse than shipping nothing.
- `validate` reports every problem in the config at once, not the first one.

- `accepted` is optional; see [Accepted risks](#accepted-risks).

The logo is inlined as a data URI, so the rendered HTML is one file that prints
identically with no network access.

## Accepted risks

Some findings are deliberate: a bucket that serves public images, a snapshot
kept for an audit. Point `accepted` at a register of them:

```json
[
  {
    "fingerprint": "s3-public-audit:public-bucket:aws/eu-west-1/s3:bucket/acme-public-assets",
    "reason": "Serves the storefront's product images. Public read is intended.",
    "accepted_by": "J. Okafor, Head of Engineering, Acme Retail",
    "expires": "2026-12-31"
  }
]
```

- `fingerprint` is the finding's `id` from `findings.json`
  (see [Finding identity](docs/adapters.md#finding-identity)).
- All four fields are required. There is no open-ended acceptance: every entry
  has an `expires` date, `YYYY-MM-DD`, and holds through the end of that day
  (UTC), judged against the report timestamp (`-now` when given).
- A finding with an active acceptance moves to the "Accepted risks" appendix
  and to `accepted` in `findings.json`. It no longer counts in the severity
  totals, the identified waste, the open-findings figure or the section pages.
- Once the acceptance has expired, the finding is back in its section with a
  "re-review" badge and the original reason and owner next to it.
- Moving into or out of the register is not a fix: the delta never reports an
  accepted finding as resolved, and a finding that comes back keeps its
  original first-seen date.
- An entry that matches no finding this period is reported as a warning, so
  fixed or mistyped entries get cleaned out.
- `validate` parses the register and reports every bad entry at once.

## The narrative

The report's middle section is a page of hand-written commentary — what
changed, what to do about it, what fixing it costs. That is the part a client
is actually paying for, and no generator writes it. Point `narrative_file` at a
Markdown file; a deliberately tiny subset is supported (headings, bullets,
paragraphs, `**bold**`, `` `code` ``) and all of it is HTML-escaped before any
markup is applied.

See [`examples/acme/narrative.md`](examples/acme/narrative.md).

## Supported scanners

| Adapter | Section | Source tool |
| --- | --- | --- |
| `cost-export` | cost | Cost Explorer / Azure cost export |
| `aws-orphan-finder` | cost | aws-orphan-finder |
| `k8s-rightsize` | cost | k8s-rightsize |
| `aws-sg-audit` | security | aws-sg-audit |
| `s3-public-audit` | security | s3-public-audit |
| `aws-iam-least-priv` | security | aws-iam-least-priv |
| `certcheck` | security | certcheck |
| `uptime-ping` | reliability | uptime-ping |
| `slo-calc` | reliability | slo-calc |
| `k8s-crashloop` | reliability | k8s-crashloop |

Input shapes and the full grading rules are documented in
[`docs/adapters.md`](docs/adapters.md), with a fixture for each in
[`internal/adapter/testdata/`](internal/adapter/testdata).

## PDF output

This tool does not bundle a browser. Add a `pdf` block and `gen -pdf` will run
it, substituting `{{input}}` and `{{output}}`:

```json
"pdf": {
  "command": ["docker", "run", "--rm",
              "-v", "{{input}}:/work/report.html:ro",
              "-v", "/tmp/out:/out",
              "example/headless-chrome",
              "--print-to-pdf=/out/report.pdf", "/work/report.html"],
  "output": "report.pdf"
}
```

The argument vector is passed to `exec` verbatim — there is no shell, so a path
with a space in it cannot become a second command. If the renderer exits 0 but
writes nothing, that is an error, not a zero-byte PDF in a client's inbox.

## Development

```sh
make test     # go test ./...
make cover    # coverage summary
make lint     # gofmt -l + go vet
make example  # render the shipped example into out/
```

CI builds and tests on Ubuntu and macOS, then renders the shipped example — so
the usage example above cannot rot without turning the build red.

## Scope

**In:** normalising scanner output, grading, month-over-month deltas, branded
HTML, driving an external PDF renderer.

**Out, on purpose:** a customer portal or login, self-serve signup and billing,
multi-tenant scheduling and email delivery, compliance attestations, anything
that requires this binary to hold a cloud credential.

Findings JSON carries a `schema_version`. A file written by a newer build is
rejected rather than silently misread. Version 2 added the `accepted` list;
version 1 files still load as previous reports.

## License

MIT. See [`LICENSE`](LICENSE).
