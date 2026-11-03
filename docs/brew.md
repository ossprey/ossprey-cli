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
| `... --HEAD <formula>` | the named formula's `head` repo at its branch |

- Formulae are looked up in the Homebrew API (`formulae.brew.sh`).
- The stable source URL is mapped to `pkg:github/<owner>/<repo>@<sha>`:
  `archive/<ref>`, `archive/refs/tags/<tag>`, `releases/download/<tag>/…`,
  `codeload.github.com`, and git URLs with a `tag`/`revision`.
- Tags resolve to a commit with `git ls-remote` (no GitHub API quota).

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
