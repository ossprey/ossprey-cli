# Brew wrapper — check a formula's source before you install it

`ossprey brew` checks the **GitHub repositories** a Homebrew formula, and each
of its runtime dependencies, is built from. Malware blocks the install;
anything else runs the real brew.

```sh
ossprey brew install ripgrep
```

## Opt-in shim

Brew is **not** shimmed by default. Ask for it:

```sh
ossprey shim install --brew              # default shims plus brew
ossprey shim install --managers brew     # brew only
```

A plain `ossprey shim install` keeps an installed brew shim. Remove it with
`ossprey shim uninstall --managers brew`.

## What is checked

| Command | Checked |
|---------|---------|
| `brew install\|reinstall\|upgrade <formula>...` | each formula and its runtime dependencies (recursively, up to 300) |
| `... --HEAD <formula>` | the named formula's `head` repo at its branch, with its head dependencies |
| `... --only-dependencies <formula>` | the dependencies only |
| `... --ignore-dependencies <formula>` | the named formulae only |
| each repo above | its own dependencies (lockfiles: crates, Go modules, npm, PyPI…) |

- Formulae are looked up in the Homebrew API (`formulae.brew.sh`). An alias
  (`python`) is resolved to its formula with the local `brew info`.
- Runtime dependencies include `uses_from_macos` entries (all on Linux; on
  macOS those the OS only supplies from some release on) and every platform
  variation for this OS. This errs toward checking more than is installed.
- The stable source URL is mapped to a GitHub repo and ref:
  `archive/<ref>`, `archive/refs/tags/<tag>`, `releases/download/<tag>/…`,
  `codeload.github.com`, and git URLs with a `tag`/`revision`.
- The ref is pinned to a commit with `git ls-remote` (no GitHub API quota)
  and checked as `pkg:github/<owner>/<repo>@<sha>`. If it cannot be resolved,
  the ref name is checked instead; a source with no ref is checked at `HEAD`.
- Each repo's dependencies come from the Ossprey API (`/tools/sbom`), which
  checks the repo out at that commit and catalogues it. These are what a
  bottle compiles in. All of it goes in one scan.
- Reading those dependencies is capped at 60s per install. A repo that times
  out or fails is still checked by itself, with a warning.
- A monitor id cannot read repo dependencies (submit-only), so a monitor
  shim reports the repos alone.

## What is not checked

- Casks (`--cask`, or a name that is not a core formula), and third-party taps.
- Formulae whose source is not on GitHub (e.g. `node` from nodejs.org). Their
  dependencies are still walked.
- `brew upgrade` with no names, `brew bundle`.
- A release **asset** (`releases/download/…`) is a maintainer upload, not the
  git tree. The tag's commit is checked; a tampered tarball is not.
- Build-only dependencies (bottles do not use them).

## Failure posture

- **Malware → blocked**, exit 1, brew never runs.
- **Fails open** on a Homebrew API or Ossprey API error: a warning, then brew runs.
- Watchdog/monitor shims submit passively after brew runs and never block.
- `OSSPREY_SHIM_BYPASS=1 brew install x` skips the check for one command.

---

[← Back to the docs index](README.md)
