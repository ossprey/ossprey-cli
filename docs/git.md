# Git wrapper — check a repo before you clone or pull it

`ossprey git` checks a **public GitHub repository itself** (its code, not its
dependencies) before `git clone` or `git pull` fetches it. Malware blocks the
command; anything else runs the real git.

```sh
ossprey git clone https://github.com/pallets/click
ossprey git pull
```

## Opt-in shim

Git is **not** shimmed by default. Ask for it:

```sh
ossprey shim install --git              # default shims plus git
ossprey shim install --managers git     # git only
```

Installer: `install.sh --git` / `install.ps1 -Git` (or `OSSPREY_SHIM_GIT=1`).
Once installed, a plain `ossprey shim install` keeps the git shim. Remove it
with `ossprey shim uninstall --managers git`.

## What is checked

| Command | Repository checked | Ref |
|---------|--------------------|-----|
| `git clone <url>` | `<url>` | `-b`/`--branch`/`--revision`, else the default branch |
| `git pull` | the current branch's remote (default `origin`) | its upstream branch |
| `git pull <remote> [<refspec>]` | `<remote>` (a name or URL) | the refspec's source |

- The ref is resolved to a commit sha and sent as `pkg:github/<owner>/<repo>@<sha>`.
- Only `github.com` URLs (https, ssh, `git@github.com:`) are checked.
- A repo is public when GitHub's API returns it without credentials. Private
  and unknown repos pass through unchecked, and no token is ever sent.
- Every other git command passes straight through.

## Failure posture

- **Malware → blocked**, exit 1, git never runs.
- **Fails open** on a GitHub lookup error, rate limit (60 unauthenticated
  lookups/hour) or Ossprey API error: a warning, then git runs.
- Watchdog/monitor shims submit passively after git runs and never block.
- `OSSPREY_SHIM_BYPASS=1 git pull` skips the check for one command.

---

[← Back to the docs index](README.md)
