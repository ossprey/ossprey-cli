# Package-manager forwarder

How `ossprey npm install …` decides what to check, what it never checks,
and how to stop typing `ossprey` first.

Wrap an install so packages are checked **before** they hit your machine. A
named install is checked together with everything it brings in — `ossprey npm
install express` checks express and the 64 packages it depends on, not just the
one you typed — because that is where a planted package usually lives. If any
are flagged, the install is blocked (exit `1`) and the real package manager
is never invoked; otherwise the command is forwarded unchanged.

> Everything on this page describes the default, **gating** mode. In
> [passive mode](passive-monitoring.md) nothing is checked in front of the
> install and nothing is ever blocked: the manager runs first (or alongside the
> submission), and a scan that fails to submit is a warning rather than an
> error.

```sh
ossprey npm install foo@1.2.3 bar@2.0.0   # checks both, and their dependencies
ossprey yarn add foo@1.2.3
ossprey pip install foo==1.2.3
ossprey poetry add foo
ossprey uv pip install foo==1.2.3
```

Supported managers: `npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`, `pip`, `pip3`,
`poetry`, `uv`, `uvx`.

## What is checked

Exactly these subcommands. Everything else is forwarded straight through with no
check and no API call.

| Manager | Checked subcommands |
| ------- | ------------------- |
| `npm` | `install`, `ci`, `update`, `install-test`, `install-ci-test` and `exec`, under every name npm accepts for them: aliases (`i`, `add`, `clean-install`, `upgrade`, `it`, `cit`, `x`, …), its built-in typo aliases (`isntall`, `udpate`, …) and unambiguous abbreviations (`insta`, `upd`) |
| `npx` | every invocation (`npx` is `npm exec`) |
| `pnpm` | `install`, `i`, `add`, `update`, `up`, `upgrade`, `install-test`, `it` |
| `yarn` | `add`, `install`, `upgrade`, `up`, bare `yarn` (an install), `global add`, `global upgrade`, and any of these after `workspace <name>` |
| `bun` | `install`, `i`, `ci`, `add`, `a`, `update`, `up`, `x` |
| `bunx` | every invocation (`bunx` is `bun x`) |
| `pip`, `pip3` | `install` |
| `poetry` | `add`, `install`, `sync`, `update`, `lock` |
| `uv` | `add`, `sync`, `lock`, `pip install`, `pip sync`, `tool install`, `tool run` |
| `uvx` | every invocation (`uvx` is `uv tool run`) |

Each manager's global options are understood before the subcommand, so
`pnpm --filter web add x` and `npm --prefix ./app install x` are checked like any
other install.

`uvx` and `uv tool run` fetch a package and run it, so only the package is
checked, never the arguments after the command: `uvx cowsay moo` checks
`cowsay`, not `moo`. `--from` names the package when it differs from the command
(`uvx --from httpie http`), `ruff@0.6.0` pins it, and `--with` packages are
checked too. A run with no registry package (`uvx --from git+https://…`) is
forwarded unchecked.

`npx`, `npm exec`, `bunx` and `bun x` work the same way: `npx cowsay moo` checks
`cowsay`, not `moo`. `--package` / `-p` names what is fetched when it differs
from the command (`npx -p @angular/cli ng new app`), `cowsay@1.5.0` pins it, and
`npx -c '…'` with no `--package` fetches nothing and is forwarded. Which token
is the command follows the tool's own parsing, so `npm exec cowsay --package
left-pad` checks `left-pad` (npm reads options after the command too), and
`bunx tsc` checks `typescript`, the package bunx actually fetches for it.

A bare command that the project already has in `node_modules/.bin` — `npx
eslint .` in a project that depends on eslint — is run from there rather than
fetched, so it is forwarded unchecked: checking the registry package called
`eslint` would check something that is not being run. The project is the
nearest directory up from here with a `package.json` or `node_modules`, as for
npm. A pinned version or a `--package` is always checked.

Bare `bun install` and `bun ci` are manifest installs (below). Ossprey cannot
read `bun.lock` yet, so the scan resolves the project's `package.json` the way
it does for a project with no lockfile.

## What is not checked

Pass-through commands are not checked, which is intended for `npm run`,
`pip list` and friends. Three groups are worth calling out, because they can
still put code on your machine:

- **pnpm and yarn fetch-and-execute, and initializers.** `pnpm dlx` and
  `yarn dlx` download a package and run it, as do `npm init <initializer>`,
  `npm create`, `bun create` and `yarn create`, which fetch `create-<name>`.
  They name a package, but it is not an install verb, so it is forwarded
  unchecked. (`npx`, `npm exec`, `bunx`, `bun x`, `uvx` and `uv tool run` are
  checked; see above.)
- **Script runners.** `npm run`, `pnpm run`, `bun run`, `poetry run`, `uv run`
  and equivalents. The scripts themselves are not inspected. Note that `uv run`
  syncs the project environment before running (as `uv sync` would) and
  installs any `--with` packages, and that `bun` running a file with no
  `node_modules` auto-installs its imports; none of that is checked.
- **A named install whose dependencies could not be resolved.** The
  dependencies of a named install are worked out with a dry run of the
  manager's own kind of resolver (below). When that is not possible — no
  resolver on the machine, the registry unreachable, a Python package that
  can only be resolved by building it — only the named packages are checked,
  and one warning line says so.

For these, run `ossprey scan` on the project afterwards.

Packages from [trusted sources](trust.md) are deliberately not checked. A named
install applies the npm scope rule to the packages typed, and both rules to the
tree its dry run resolves, using the registry that dry run recorded for each
package (npm and pip record one; uv does not, so a uv-resolved package is
always checked). A bare install applies both rules, from the lockfile.

**Two modes, picked automatically:**

- **Named packages** (`ossprey npm install foo bar`, `ossprey pip install
  foo==1 bar`): every package named on the command line is checked, **with the
  dependencies it brings in**. Multiple packages, flags, flag-values, local
  paths, archives and VCS/URL targets are all handled — only the real registry
  packages are checked, the rest are noted and forwarded. `uv tool install`
  counts its `--with`/`-w` and `--with-executables-from` packages as named too
  (comma-separated lists included), and with `--from 'ruff==0.6.0' ruff` checks
  the `--from` package rather than the bare name.

  Before the check, the manager's own kind of resolver is asked what the
  install would put on disk, without installing anything or running any
  package's code:

  - `npm`, `pnpm` and `yarn` installs are resolved by `npm install
    --package-lock-only --ignore-scripts` in a throwaway copy of the project
    (its `package.json`, `.npmrc` and npm lockfile), so your files are never
    touched and the versions your lockfile already pins are kept. Packages
    that lockfile already named are left to a project scan; only what the
    install adds is checked. A `yarn.lock` or `pnpm-lock.yaml` cannot be read
    by npm, so a pnpm or yarn project resolves the named packages on their
    own; so does a global or redirected install.
  - `pip`, `uv` and `poetry` installs are resolved by `uv pip compile` where
    the machine has uv, and by `pip install --dry-run --report` otherwise, for
    this interpreter and platform. Neither is allowed to build a source
    distribution: a package that can only be resolved by running its own
    build code fails the dry run instead, and the install falls back to the
    named packages. `--no-deps` resolves nothing beyond the names.

  The flags that change what gets resolved are passed along (`--legacy-peer-deps`,
  `--omit`, `--registry`, `--tag` for npm; `--index-url`/`-i`,
  `--extra-index-url`, `--find-links`, `--constraint`, `--pre` and friends for
  pip and uv). Index configuration in `.npmrc`, `pip.conf` or `uv.toml` and the
  environment applies as it would to the real install.

  The named package itself is then checked at the release the resolver picked.
  When the dry run fails — no resolver, offline, a build-only package, the
  `OSSPREY_RESOLVE_TIMEOUT` (default 2m) — only the named packages are checked,
  one line says so (`could not resolve the dependencies of foo (…); checking
  the named packages only`), and the install proceeds. The forwarder never
  blocks an install because it could not predict it. With `OSSPREY_VERBOSE=1`
  the clean verdict reports the coverage: `no malware found in 65 packages (1
  requested + 64 dependencies)`, or `(1 requested; dependencies not resolved)`.

  Without the dry run, only an exact pin is taken as the version: `foo@1.2.3`
  for npm, `foo==1.2` or `foo===1.2` for PyPI (also poetry's `foo@1.2`).
  Anything else is resolved from the registry: an npm range (`foo@^4.17.0`,
  `~1`, `1.x`, `>=1 <2`) to the release npm would pick (`latest` if it
  satisfies the range and is not deprecated, otherwise the highest
  non-deprecated match), an npm dist-tag (`foo@next`) to that tag, and a PyPI
  range, wildcard (`==2.*`) or poetry constraint (`foo@^7.0`) to the latest
  release. An npm range nothing satisfies, or a tag the registry does not
  have, falls back to `latest`. PyPI extras and markers (`foo[socks];
  python_version>"3"`) are not part of the name, and an npm alias
  (`foo@npm:bar@1.0.0`) is checked as `bar`, the package actually installed.
- **Named packages plus a requirements file** (`pip install -r
  requirements.txt flask`, `uv pip install -r requirements.txt flask`,
  `uvx --with-requirements r.txt ruff`): both are installed, so both are
  checked in one submission — the requirements files named, with their nested
  `-r` includes, plus the named packages and their dependencies.
- **Manifest install** (bare `ossprey npm install`, `npm ci`, `yarn install`,
  bare `yarn`, `bun install`, `poetry install`, `poetry sync`, `uv sync`,
  `uv pip sync requirements.txt`, or `pip install -r requirements.txt` /
  `uv pip install --requirements requirements.txt`): no
  packages are named, so the manager installs from the project's
  manifest/lockfile. The forwarder checks every declared dependency before
  forwarding — it does **not** fall through unchecked. A requirements-file
  install scans the files it names, whatever they are called; the others scan
  the current directory.

Global options before the subcommand are understood, so the workspace forms are
checked like any other install:

```sh
ossprey pnpm --filter web add left-pad   # checked
ossprey npm --prefix ./app install foo   # checked
ossprey pnpm --filter web run build      # not an install, forwarded
```

If the registry can't be reached to resolve an unpinned named version, that
package is skipped (fail-open) so a registry outage never blocks development.
An install whose only targets are local paths or URLs (nothing checkable and no
manifest to scan) is forwarded with a warning.

> **Known gap (pnpm 9 and earlier):** `pnpm run` and `pnpm exec` install the
> project's declared dependencies as a side effect when `node_modules` is
> missing, which `npm run` does not do. Those are pass-through commands, so the
> packages they pull in are not checked. pnpm 10 no longer appears to do this.
> Either way, run `ossprey pnpm install` (or `ossprey scan`) after a fresh clone
> for coverage.

Flag parsing is disabled so every argument reaches the real manager, which
means the forwarder has no `--api-key` or `--url` of its own. It reads:

- `OSSPREY_API_KEY` — API key
- `OSSPREY_API_URL` — override the API URL (default `https://api.ossprey.com`)
- `OSSPREY_SKIP_CI` — set to `1` to forward every command straight to the real
  manager without any Ossprey check
- `OSSPREY_CI_CACHE_SCAN_ONLY` — set to `1` to still gather and submit the
  packages (results appear in the dashboard) but never block or fail the
  install

A session from `ossprey login` also counts, and takes precedence over
`OSSPREY_API_KEY`, so on your own machine the forwarder usually needs no
environment at all.

## Shell aliases — drop the `ossprey` prefix in your terminal

The forwarder only runs when somebody remembers to type `ossprey` first. One
alias per manager removes that step in your own terminal.

Bash or Zsh, in `~/.bashrc` / `~/.zshrc`:

```sh
for mgr in npm npx pnpm yarn bun bunx pip pip3 poetry uv uvx; do alias "$mgr=ossprey $mgr"; done
```

Fish, in `~/.config/fish/config.fish`:

```fish
for mgr in npm npx pnpm yarn bun bunx pip pip3 poetry uv uvx
    alias $mgr "ossprey $mgr"
end
```

PowerShell, in `$PROFILE` (`Set-Alias` can't carry an argument, so these are
functions):

```powershell
function npm    { ossprey npm    @args }
function npx    { ossprey npx    @args }
function pnpm   { ossprey pnpm   @args }
function yarn   { ossprey yarn   @args }
function bun    { ossprey bun    @args }
function bunx   { ossprey bunx   @args }
function pip    { ossprey pip    @args }
function pip3   { ossprey pip3   @args }
function poetry { ossprey poetry @args }
function uv     { ossprey uv     @args }
function uvx    { ossprey uvx    @args }
```

Open a new shell to pick them up. There's no recursion to worry about:
`ossprey npm` resolves the real `npm` through `PATH` rather than through your
shell, so the alias doesn't apply a second time. Wrap only the managers
listed above, since `ossprey <anything else>` isn't a command.

An intercepted install needs credentials exactly like `ossprey scan` does, so
run `ossprey login` once (or export `OSSPREY_API_KEY`) before relying on the
aliases. With neither, a gating install stops on a credentials error rather
than being quietly forwarded. (A passive install never stops for anything, so
there the same failure is a warning and the install proceeds.)

To check they took, run `type npm`. Non-install commands (`npm run build`, `pip
list`, `poetry run pytest`) go straight through untouched, so an
ordinary-looking `npm --version` means the handoff works. A clean install
prints nothing of its own: stdout and stderr carry only the manager's output,
exactly as they would without Ossprey:

```console
$ npm install left-pad

added 1 package in 525ms
```

By default a forwarder speaks only for a malware block (below) or a platform
error — the API refusing a credential, a passive scan that could not be
posted — each reported on stderr. While the check runs, a terminal gets a live
`ossprey: scan in progress... 4s` indicator that erases itself once the
verdict is in; a CI log or a pipe gets nothing.

If a check comes back dirty you get the full malware report on stderr — the
alert box, an `Error: WARNING:` line per finding, and a blocked line naming
the command (see [Output](output.md)) — and an exit code of `1`. The real
manager never starts.

Set `OSSPREY_VERBOSE=1` for everything else: the clean verdict
(`ossprey: no malware found in 65 packages (1 requested + 64 dependencies),
forwarding to npm`), why an install
was not checked (`skip-ci set`, `found no dependencies to check`, a passive
`scan posted`), what is being scanned, collected warnings (packages that could not be resolved, trusted packages
left out), informational findings, the progress line in a CI log, and the
update notice.

An alias inherits the forwarder's scope: an install that names packages checks
those packages and what they bring in, as described above; the project's other
dependencies are the job of `ossprey scan`.

Skip the check for one command by calling the manager directly:

```sh
command npm install ./local-tarball.tgz    # or \npm install ...
```

In PowerShell, `& (Get-Command npm -CommandType Application) install ...` steps
around the profile function. To undo the whole thing, delete the alias lines
and open a new shell.

The limit of aliases is that they exist only in interactive shells. `make
setup`, a `package.json` script, a CI job, and whatever your editor spawns in
the background all miss them. Covering those takes a real executable earlier on
`PATH`, not a shell feature — see [PATH shims](shims.md).

---

[← Back to the docs index](README.md)
