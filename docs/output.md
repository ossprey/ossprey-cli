# Output

What the CLI prints, how warnings are grouped, and the JSON verdict CI can act
on.

`ossprey scan` prints `No malware found` on success, or `No malware found in
<scanned> of <total> packages` when the platform did not check everything it
was sent (see [`unscanned`](#machine-readable-verdict---report)). On a malware
verdict it draws an alert box naming every malicious package, followed by one
`Error: WARNING: <pkg>:<ver> contains malware. Remediate this immediately` line
per finding, so anything that greps the old one-line form keeps working. The
forwarders and shims print the same box to stderr before their
`ossprey: blocked ...` line.

```text
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│    ███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗     │
│    ████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝     │
│    ██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗       │
│    ██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝       │
│    ██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗     │
│    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     │
│                                                                      │
│    Ossprey found 2 malicious packages.                               │
│                                                                      │
│    PACKAGE                    VERSION      ECOSYSTEM                 │
│    ───────────────────────────────────────────────────────────────   │
│    requests                   2.31.0       pypi                      │
│    left-pad                   1.3.0        npm                       │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
Error: WARNING: requests:2.31.0 contains malware. Remediate this immediately
Error: WARNING: left-pad:1.3.0 contains malware. Remediate this immediately
```

The box is 72 columns wide and always renders in plain text; colour is added
only where it will display. `NO_COLOR` or `TERM=dumb` turns colour off
everywhere. `FORCE_COLOR=1` (or `CLICOLOR_FORCE=1`) turns it on even when
output is piped. Otherwise colour is used on an interactive terminal and in CI
log viewers that render ANSI (GitHub Actions, GitLab, Azure DevOps,
Buildkite). Truecolor terminals (`COLORTERM=truecolor`) get a red-to-orange
gradient on the lettering; others get bold red. The `Error: WARNING:` lines
are red under every colour profile.

Pass `-o sbom.json` to also write the full OSSBOM JSON (components +
vulnerabilities) to disk, or `--local` to emit it to stdout instead of
calling the API.

## Warnings

Some dependencies cannot be resolved, and some manifests cannot be read. None
of that fails the scan — it is reported and the scan continues. Warnings go to
**stderr** (stdout belongs to `--local` and `-o`), and they are printed before
the verdict so the verdict is the last thing on screen.

Repeated warnings of the same kind arrive as one counted line rather than one
line per package:

```text
ossprey: 4 packages not on the public registry; left unversioned
ossprey: 2 packages could not be resolved (registry unreachable); left unversioned
ossprey: uv: could not resolve /repo (the build backend returned an error)
ossprey: npm: could not resolve 3 manifests
```

The two registry lines are deliberately separate. A private or internal package
answering 404 is expected; an unreachable registry means the scan resolved
almost nothing, and folding the two into one count would hide that.

Set `OSSPREY_VERBOSE=1` (or pass `-v` to `scan`) to list the individual packages
and manifests, along with the full output of any resolver that failed. That
output is quoted behind a gutter so a tool's own `error:` lines are never
mistaken for Ossprey's:

```text
ossprey: 4 packages not on the public registry; left unversioned
ossprey:   npm/@acme/dev-utils (404)
ossprey:   npm/@acme/flyui (404)
ossprey: uv: could not resolve /repo (the build backend returned an error)
ossprey: | error: The build backend returned an error
ossprey: |   Caused by: Call to `setuptools.build_meta:__legacy__.build_wheel` failed
ossprey: (end of uv output)
```

`OSSPREY_VERBOSE` works on every path, including the forwarders and shims,
which parse no flags of their own.

A package left unversioned is still submitted and still checked against what
the registry knows; one dropped by a forwarder (`skipping its check`) is not
checked at all. The wording differs for that reason.

## Machine-readable verdict (`--report`)

`--report report.json` writes the verdict and the malicious packages to a file,
for CI that needs to do something with them — fail a check, open an issue,
comment on a pull request. `scan` and `check` both take it.

```sh
ossprey scan . --report report.json
```

```json
{
  "verdict": "malware",
  "project": "my-service",
  "path": "/home/me/my-service",
  "components": 412,
  "unscanned": 2,
  "findings": [
    {
      "purl": "pkg:npm/@acme/logger@1.4.2",
      "ecosystem": "npm",
      "name": "@acme/logger",
      "version": "1.4.2",
      "id": "OSSPREY-2026-0031",
      "type": "Malware",
      "description": "Exfiltrates environment variables on postinstall.",
      "reference": "https://dashboard.ossprey.com/..."
    }
  ]
}
```

`verdict` is one of:

| Verdict   | Exit code | Meaning |
|-----------|-----------|---------|
| `clean`   | 0         | Scanned, nothing flagged. Check `unscanned` for how much was covered. |
| `malware` | 1         | `findings` lists every flagged package. |
| `skipped` | 0         | **Nothing was checked**: either your quota was exhausted or the SBOM held nothing this platform scans. `skipped.message` and `skipped.reset_at` say why and until when. Do not read this as "clean". |

`unscanned` is how many of `components` the platform did not check: packages in
an ecosystem it does not scan, and packages the registry did not have. It is
omitted when zero, so on a `clean` or `malware` verdict its absence means full
coverage. On a `skipped` verdict nothing was checked at all, so read the verdict
rather than this field.

A `clean` verdict with a non-zero `unscanned` means nothing was flagged in the
part that was scanned, and the summary line says so: `No malware found in 410 of
412 packages`.

`findings` is always present, empty on a clean scan, so
`jq '.findings | length'` works either way. The file is written before the
process exits non-zero, so it is there on exactly the runs you care about.

`--report` is refused alongside `--passive` (and `--monitor`, which implies it):
a passive scan submits without fetching findings, so a report file would claim a
verdict nobody checked. Passive mode coming from the *environment* only warns
and skips the report, because `OSSPREY_PASSIVE` and `OSSPREY_CI_CACHE_SCAN_ONLY`
are set in pipelines that also pass `--report`, and an upgrade must not start
failing their builds.

No file is written when the run never reaches a verdict: `--local`, and the
`--skip-ci` mode above. A consumer should treat a
missing report as "this scan produced no verdict", never as clean.

`--report` never writes to stdout, and it is rejected alongside `--local`:
`--local` owns stdout for the OSSBOM and exits before any verdict exists.

---

[← Back to the docs index](README.md)
