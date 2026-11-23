# Internals: why the code is the way it is

The pages one level up say what the CLI does, for the people who run it. These
say why it does it that way, for whoever changes it next: the bugs, reviews and
customer reports behind each decision, and the invariants a change must keep.

Read the page for a package before changing that package. When a change makes a
statement here untrue, fix the statement in the same pull request.

| Page | Covers | Code |
|---|---|---|
| [init](init.md) | Login, key minting, the optional scan, why it writes no files | `cmd/ossprey/init.go` |
| [check](check.md) | Spec parsing for named packages, crates in particular | `internal/check`, `internal/registry` |
| [forwarder](forwarder.md) | Verb and flag tables, tool runs, npm's argv ports, quiet output, process handoff, known gaps | `internal/forward` |
| [install-expansion](install-expansion.md) | Resolving a named install or tool run to its dependency tree; npm, uv and pip configuration, caches and installed tools | `internal/forward/expand.go`, `internal/catalog/install_resolve.go` |
| [wrappers](wrappers.md) | The opt-in `git` and `brew` wrappers | `internal/gitscan`, `internal/brewscan` |
| [passive](passive.md) | `--passive`, monitor ids, when a passive install is catalogued | `internal/forward`, `internal/monitor`, `internal/client` |
| [shims](shims.md) | Recursion guards, fail-open, profile blocks, the Claude Code hook | `internal/shim` |
| [trust](trust.md) | Trusted registries and npm scopes, and why each rule is narrow | `internal/trust` |
| [catalog](catalog.md) | Scan data flow, the syft set and custom catalogers, tool lookup, package sinks, lockfile bounds, npm workspaces, timeouts | `internal/scan`, `internal/catalog` |
| [cargo](cargo.md) | Source marks, range folding, `[patch]` targets, the `cargo vendor` filter, source replacement, the pre-commit hook's Cargo handling | `internal/catalog/cargo_*.go`, `internal/precommit` |
| [output](output.md) | The malware alert box and the warning collector | `internal/alert`, `internal/ansi`, `internal/warn` |
| [api](api.md) | The OSSBOM wire model, retries, poll ceiling, credential order | `internal/ossbom`, `internal/client`, `internal/submit` |
| [conventions](conventions.md) | Exit codes, severity, `--report`, progress, untrusted API text, test seams | cross-cutting |
