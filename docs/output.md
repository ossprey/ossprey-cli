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
`ossprey: blocked ...` line; otherwise they print nothing unless a platform
error occurs (see
[forwarder output](forwarder.md#shell-aliases--drop-the-ossprey-prefix-in-your-terminal)).

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
which parse no flags of their own. Without it the forwarders print no
warnings at all, and a clean or unchecked install is silent; a malware block
still gets the full report, and platform errors are still shown.

A package left unversioned is still submitted and still checked against what
the registry knows; one dropped by a forwarder (`skipping its check`) is not
checked at all. The wording differs for that reason.

## The local scan cache

Repeating a scan that changed nothing does not reach the platform. When this
machine sent the identical SBOM — the same packages at the same versions, from
the same project path and branch, with the same credential, to the same API —
within the last hour, the CLI reuses what happened last time:

- A **blocking** scan (`scan`, `check`, a forwarded install) whose last
  result was **clean** replays that result locally. Nothing is sent, and one
  line on stderr says so (`ossprey init` is the exception: its scan exists to
  prove the new key works, so it always asks the API):

  ```text
  ossprey: clean result reused from a scan 12m ago (--no-cache or OSSPREY_SCAN_CACHE_TTL=0 to rescan)
  ```

- A **passive** submission (`--passive`, `--monitor`, a watchdog or monitor
  shim) that was already accepted is not sent again:

  ```text
  ossprey: identical scan already sent 12m ago; not sent again
  ```

Only a clean verdict is ever reused. Malware, an informational finding, a
quota skip, a failed scan and any error always go to the platform next time,
so the cache can neither hide nor freeze a detection. The two kinds of entry
are kept apart: a passive acceptance carries no verdict and can never let a
blocking scan pass.

`--no-cache` on `scan` and `check` skips the lookup for one run (the fresh
result is still stored). `OSSPREY_SCAN_CACHE_TTL` sets the window — a Go
duration such as `30m`, capped at `24h`, with `0` or `off` turning the cache
off for every command, including the forwarders and shims, which take no
flags. The forwarders print the reuse line only under `OSSPREY_VERBOSE=1`, as
they do every other non-blocking line.

Entries live under `OSSPREY_CACHE_DIR` (default: your user cache directory,
`~/.cache/ossprey` on Linux), in a `scans/` subdirectory, as one small file per
scan readable only by you. No credential is written: the key is a hash, and
the file holds only the API's answer. A cache that cannot be read or written
is simply not used; nothing about the scan's outcome or exit code changes.

Two things to know. A reused result leaves no new scan in the dashboard — that
is the point, but it means the dashboard's "last scanned" time does not move
on a cache hit. And a passive submission the platform accepted but later
skipped for quota is not retried until the window expires; passive mode never
blocks anything, so nothing is lost but a dashboard row.

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

`cached: true` and `cached_age_seconds` are present when the verdict was
replayed from [the local scan cache](#the-local-scan-cache) rather than fetched:
the identical scan was found clean that many seconds ago. Both are absent on a
live verdict, so a consumer that predates them sees no change. A cached verdict
is always `clean`, because nothing else is ever cached.

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
