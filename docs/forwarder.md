# Package-manager forwarder

How `ossprey npm install …` decides what to check, what it never checks,
and how to stop typing `ossprey` first.

Wrap an install so packages are checked **before** they hit your machine. If
any are flagged, the install is blocked (exit `1`) and the real package manager
is never invoked; otherwise the command is forwarded unchanged.

> Everything on this page describes the default, **gating** mode. In
> [passive mode](passive-monitoring.md) nothing is checked in front of the
> install and nothing is ever blocked: the manager runs first (or alongside the
> submission), and a scan that fails to submit is a warning rather than an
> error.

```sh
ossprey npm install foo@1.2.3 bar@2.0.0   # checks each named package
ossprey yarn add foo@1.2.3
ossprey pip install foo==1.2.3
ossprey poetry add foo
ossprey uv pip install foo==1.2.3
ossprey npx create-vite@latest app        # checks create-vite, then runs it
```

Supported managers: `npm`, `npx`, `pnpm`, `yarn`, `pip`, `pip3`, `poetry`, `uv`.

## What is checked

Exactly these subcommands. Everything else is forwarded straight through with no
check and no API call.

| Manager | Checked subcommands |
| ------- | ------------------- |
| `npm` | `install`, `i`, `add`, `ci`, `update`, `up` |
| `pnpm` | `install`, `i`, `add`, `update`, `up` |
| `yarn` | `add`, `install`, `upgrade`, `up` |
| `pip`, `pip3` | `install` |
| `poetry` | `add`, `install`, `update`, `lock` |
| `uv` | `add`, `sync`, `pip install` |
| `npx` | every invocation that fetches a package (see [npx](#npx)) |

Each manager's global options are understood before the subcommand, so
`pnpm --filter web add x` and `npm --prefix ./app install x` are checked like any
other install.

## What is not checked

Pass-through commands are not checked, which is intended for `npm run`,
`pip list` and friends. Three groups are worth calling out, because they can
still put code on your machine:

- **Fetch-and-execute, other than `npx`.** `npm exec`, `pnpm dlx`, `yarn dlx`
  and `uv tool run` download a package and run it. They name a package, but it
  is not an install verb, so it is forwarded unchecked. `uvx` is a separate
  binary and is not shimmed at all, so it bypasses Ossprey entirely.
- **Script runners.** `npm run`, `pnpm run`, `poetry run` and equivalents. The
  scripts themselves are not inspected.
- **Anything the manager resolves that was not named and is not in the
  manifest.** Transitive dependencies of a named install are not resolved here;
  run `ossprey scan` for full-tree coverage.

For these, run `ossprey scan` on the project afterwards.

**Two modes, picked automatically:**

- **Named packages** (`ossprey npm install foo bar`, `ossprey pip install
  foo==1 bar`): every package named on the command line is checked. Multiple
  packages, flags, flag-values, local paths, archives and VCS/URL targets are
  all handled — only the real registry packages are checked, the rest are noted
  and forwarded. Transitive dependencies are **not** resolved here; run `ossprey
  scan` after install for full-tree coverage.
- **Manifest install** (bare `ossprey npm install`, `npm ci`, `yarn install`,
  `poetry install`, `uv sync`, or `pip install -r requirements.txt`): no
  packages are named, so the manager installs from the project's
  manifest/lockfile. The forwarder scans the current directory and checks every
  declared dependency before forwarding — it does **not** fall through
  unchecked.

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

## npx

`npx` downloads a package and runs it, so the package is checked before it
runs. If it is flagged, `npx` never starts.

- **Only the package is checked, never its arguments.** npx reads its own
  options up to the first positional, and everything after that belongs to the
  program: `npx cowsay moo` checks `cowsay`, not `moo`.
- **`--package`/`-p` names the packages.** `npx -p typescript@5.4.0 tsc`
  checks `typescript@5.4.0`; `tsc` is a command it provides, not a package.
  Each `-p` is checked.
- **The version checked is the version npx runs.** An exact version is checked
  as given, an unpinned name at the registry's latest, a dist-tag
  (`npx create-vite@next`) at the release that tag points to, and a range
  (`npx cowsay@^1`) at the release npm would pick for it: the latest tag if the
  range allows it, otherwise the highest non-deprecated match. If a tag or range
  matches nothing, or the registry can't be reached, that package is skipped
  with a warning rather than reported clean.
- **Options are read the way npm reads them.** Which options take a value comes
  from npm's own definitions. A few options mean different things in different
  npm versions: `--allow-scripts` takes a value in npm 12 but is an unknown
  (boolean) flag in npm 10, so `npx --allow-scripts a b` runs `b` on one and
  `a` on the other. For those, and for any option Ossprey doesn't recognise,
  both candidates are checked.
- **A command already in the project is not checked.** An unpinned `npx
  eslint` whose bin is in the nearest project's `node_modules/.bin` (or whose
  package is in its `node_modules`) runs from there and fetches nothing, so it
  forwards straight through. The install that put it there is what the other
  forwarders check. `--prefix`/`-C` points npx at another project, so with
  either the package is always checked.
- **Nothing to fetch, nothing to check.** `npx --version` and `npx -c '<cmd>'`
  with no `-p` forward untouched and scan nothing.
- **Git and URL targets are not checked.** `npx github:user/repo` is forwarded
  with a warning, like a URL install.

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
for mgr in npm npx pnpm yarn pip pip3 poetry uv; do alias "$mgr=ossprey $mgr"; done
```

Fish, in `~/.config/fish/config.fish`:

```fish
for mgr in npm npx pnpm yarn pip pip3 poetry uv
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
function pip    { ossprey pip    @args }
function pip3   { ossprey pip3   @args }
function poetry { ossprey poetry @args }
function uv     { ossprey uv     @args }
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
ordinary-looking `npm --version` means the handoff works. An install prints to
stderr before it forwards:

```console
$ npm install left-pad
ossprey: no malware found, forwarding to npm

added 1 package in 525ms
```

While the check runs, the forwarder holds a live `ossprey: scan in progress...
4s` line on the terminal and erases it once the verdict is in; in a CI log or a
pipe that becomes a single plain line.

If a check comes back dirty you get the finding, a blocked line naming the
command, and an exit code of `1`. The real manager never starts.

An alias inherits the forwarder's scope: an install that names packages checks
those packages, not their dependencies. Run `ossprey scan` afterwards for the
full tree.

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
