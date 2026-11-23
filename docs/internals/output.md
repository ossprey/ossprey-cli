# Malware alert and warnings

Behaviour for users is in [../output.md](../output.md). [Back to the internals index](README.md).

## Malware alert (`internal/alert`, `internal/ansi`)

A malware verdict draws a 72-column boxed banner (block-letter MALWARE and a
package/version/ecosystem table) **before** the existing
`Error: WARNING: <pkg>:<ver> contains malware...` lines, which stay untouched
because the smoke tests and downstream greps key on them (OSS-1981).
`alert.Malware(findings, outcome, profile)` renders it; `scan.MalwareSummary`
carries the structured `Detected` findings it needs. `reportMalware` in
main.go (scan/check/init, stdout, no outcome text) and `reportAndForward` in
forward.go (forwarders, stderr, "Installation blocked.") are the two callers;
precommit deliberately keeps its compact wording. Informational findings never
get the banner. Both callers write through a swappable `io.Writer`
(`verdictOut`, `errOut`) so tests can capture the output.

`ansi.Detect(w)` picks a colour profile: `NO_COLOR`/`TERM=dumb` win, then
`FORCE_COLOR`/`CLICOLOR_FORCE`, then known CI log viewers (GitHub Actions,
GitLab, Azure DevOps, Buildkite) get `Basic`, else colour only if `w` is a TTY.
Depth comes from `COLORTERM` (truecolor) and `TERM` (256color). Escapes wrap
text only, never the box-drawing, so a leaked escape cannot misalign the box;
`TestMalwareColourStripsToPlain` pins that stripping a coloured banner yields
the plain one. `ansi.Enable` switches on virtual-terminal processing on
Windows conhost and is a no-op elsewhere. Tests that assert "no escapes" on a
`bytes.Buffer` must clear the CI env vars first, or they fail on GitHub Actions.

## Warnings (`internal/warn`)

Non-fatal diagnostics are collected, not printed where they happen. A real
customer scan (OSS-2001) buried its malware verdict under twenty-five lines of
uv's raw stderr plus one line per private package; nothing in that output was
wrong and none of it was readable. `warn.Add(ctx, Entry)` records an occurrence,
`warn.Drain(ctx)` renders and clears.

Five things hold it together:

- **Grouping is by `Class`, never by message.** A private package that 404s and
  an unreachable registry both leave a component unversioned, but one is
  expected and the other means the scan resolved almost nothing, so they must
  never share a count. `registry.ErrNotFound` is what separates them — grade the
  error, don't string-match the status. The same split applies to the
  consequence: `left unversioned` (scan path, still submitted and checked) and
  `skipping its check` (forward path, not checked at all) are different classes
  because they are different outcomes.
- **A subprocess's output never prints at the default level, and never
  unprefixed.** `newToolError` (`internal/catalog/toolerror.go`) splits a uv/npm
  failure into the one actionable line — skipping the tool's own leading
  `warning:` advisories — and the rest, which only `OSSPREY_VERBOSE` shows,
  behind an `ossprey: | ` gutter. The gutter is the point: uv's own `error:`
  lines read as ossprey's in the report that prompted this.
- **A warning is never lost.** `Add` outside a collector context falls back to
  stderr, and every drain point sits *before* a verdict, never in a `defer`
  behind one. In `forward.Run` that is enforced by a single `forwardTo` closure:
  **nothing execs the real manager without draining first**. Do not call
  `execFn` directly from `Run` — the manager's output starts immediately and
  never stops, and `newForwardCmd` leaves via `os.Exit(ee.ExitCode())` on a
  non-zero exit, so `main`'s post-`Execute` safety-net drain never runs. An
  earlier revision forwarded the passive/cache-only path straight to `execFn`
  and dropped its warnings outright.
- **A headline is one readable line.** `warn.MaxLine` caps it, and
  `catalog.maxSummary` caps the cause a subprocess contributes: both a manifest
  path and a malformed line can be arbitrarily long, and an unbounded headline
  would rebuild the wall of text this removes. Detail is never truncated.
- **The collector rides on `ctx`** because the catalogers it serves sit behind
  syft's `Catalog(ctx, resolver)` signature, which has nowhere to return one.
  `warn` must stay a leaf (only `internal/env`); `registry.UnresolvedEntry` and
  `catalog.catalogerEntry`/`parseEntry` are where domain wording lives.

Verbosity is an env var (`OSSPREY_VERBOSE`) as well as `scan -v`, because the
forwarders run with `DisableFlagParsing` and cannot accept a `-v` that npm would
not also see. `warn.SetVerbose` exists so cobra can raise a collector built
before flags were parsed; verbosity only ever goes up.

`parseEntry` closes a pre-existing hole: syft's per-cataloger errors were read
as `pkgs, _, _` and discarded, so a malformed requirement went missing from the
SBOM in silence. Those errors are partial by design (OSS-1869) — keep taking the
packages, and now report the rest.
