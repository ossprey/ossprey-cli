# Package-manager forwarder

How `ossprey npm install …` decides what to check, what it never checks,
and how to stop typing `ossprey` first.

Wrap an install so packages are checked **before** they hit your machine. A
named install is checked together with everything it brings in — `ossprey npm
install express` checks express and the 64 packages it depends on, not just the
one you typed — because that is where a planted package usually lives. If any
are flagged, the install is blocked (exit `1`) and the real package manager
is never invoked; otherwise the command is forwarded unchanged. The cargo
commands that only lock work differently: cargo resolves into a scratch copy,
and only a clean result is written to your project ([below](#cargo)).

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
`poetry`, `uv`, `uvx` and [`cargo`](#cargo). Rust (crates.io) is available on
Teams and Enterprise plans.

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
| `cargo` | `install`, before it runs; `add`, `update`, `generate-lockfile` and `fetch`, before their `Cargo.lock` reaches your project ([below](#cargo)) |

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

In both cases the fetched package is checked together with the dependencies it
brings in, resolved as for a named install (below) but with no project
context: a tool run installs into the tool's own cache, never into the project
beside it, so `npx cowsay moo` checks cowsay and everything cowsay depends on.
npm may rerun what an earlier `npx` of the same package left in its cache
rather than resolve afresh, so that cached tree is checked too, read from
the cache npm's own configuration names. uv likewise reuses a tool
environment it cached for an earlier `uvx` of the same package, so the
packages installed in any cached environment holding it are checked too,
and a bare `uvx <tool>` runs the environment `uv tool install` keeps for
that tool, so that is checked as well.

A bare command that the project already has in `node_modules/.bin` — `npx
eslint .` in a project that depends on eslint — is run from there rather than
fetched, so it is forwarded unchecked: checking the registry package called
`eslint` would check something that is not being run. The project is the
nearest directory up from here with a `package.json` or `node_modules`, as for
npm. A pinned version or a `--package` is always checked.

Bare `bun install` and `bun ci` are manifest installs (below). Ossprey cannot
read `bun.lock` yet, so the scan resolves the project's `package.json` the way
it does for a project with no lockfile.

## cargo

```sh
ossprey cargo add serde          # resolved and checked, then written to your project
ossprey cargo install ripgrep    # ripgrep is checked, then cargo builds it
```

`cargo add`, `cargo update`, `cargo generate-lockfile` and `cargo fetch` need
cargo 1.97 or later. Older versions, and 1.97.0 pre-releases, are refused
before cargo runs, with the version found and a pointer to `rustup update`.

These four commands are checked before anything in your project changes.
Cargo resolves into a scratch copy of your workspace's `Cargo.lock`, ossprey
checks the lock it resolved, and only a clean result is written to your
project. Nothing unchecked is on disk in the project at any point, so an
editor such as rust-analyzer or a file watcher such as cargo-watch never sees
a crate that has not been checked. A clean check prints `ossprey: no malware
found in N packages in Cargo.lock` after cargo's output for `cargo add`,
`update` and `generate-lockfile`, and before cargo's download lines for
`cargo fetch`.

- `Cargo.lock` is written first and then any `Cargo.toml` that `cargo add`
  changed, so your manifests never name a crate the lock does not hold. Each
  file is written the way cargo writes `Cargo.toml`: a new file beside the
  real one (through a symlink, if it is one), given the old file's
  permissions, and renamed over it. Ossprey also syncs the new file to disk
  before the rename, which cargo does not. A new `Cargo.lock` gets the
  permissions cargo would give it. A file whose bytes did not change is not
  touched.
- `cargo add` edits `Cargo.toml` before it resolves, so it runs in a private
  mirror of your workspace under your user cache directory: copies of the
  manifests and the lock, and links to everything else. Its edits are copied
  back as above, and the mirror is deleted.
- `cargo fetch` downloads crates, so the lock is first resolved with `cargo
  update --workspace`, which writes the same lock `cargo fetch` would and
  downloads no crate. Every option you gave `cargo fetch` except `--target` is
  passed along. Once that lock is checked and written, your `cargo fetch` runs
  with `--locked` added, so cargo downloads exactly the checked lock.

If the lock holds malware you get the full malware report, a line saying the
project was not changed, and exit code `1`. Nothing was written to the project
and no crate from a registry was downloaded. Git dependencies are the
exception: to resolve them, cargo fetches each repository and checks out its
source under `CARGO_HOME/git` before the check, as plain cargo does. Nothing is
built. If `Cargo.lock` changes while the check runs, or for `cargo add` any
`Cargo.toml` in the workspace, nothing is written and the command exits `2`;
run it again. This covers `-p <member>`, `--manifest-path`, a member reached
through a symlinked directory, and a member whose `Cargo.lock` sits at the
workspace root.

When cargo itself fails, its exit code is passed through and nothing is
written. Its messages name your `Cargo.lock` and `Cargo.toml`, not the scratch
copies. `cargo update --dry-run` runs against the scratch lock, so it writes
nothing and nothing is checked; `cargo add --dry-run` writes nothing anywhere
and goes to cargo as typed.

Everything else fails closed: the project is left as it was, cargo's changes
are dropped, and the command exits `2` with one line saying why. That happens
when the API cannot be reached, when the platform checked none of the crates
(Rust is checked on Teams and Enterprise plans), when there is no credential
(before cargo runs), and, before cargo runs, for a workspace `cargo metadata`
cannot read (cargo's own error is shown), a cargo script run with `-Zscript`,
a `Cargo.lock` or `Cargo.toml` that is not a regular file or is over 32 MiB,
and a `resolver.lockfile-path` that would put the lock elsewhere. That last
one may come from the environment, a `--config` or a cargo config, and is
assumed for a config ossprey cannot read (a piped `--config /dev/stdin`, say),
one too large or too deeply nested to read, and one with an `include`.
`cargo update --breaking` is refused too, since it edits `Cargo.toml`; raise
the requirement with `cargo add <crate>@<version>`, which is checked first. So
is a `cargo fetch` with an option or argument cargo fetch would reject.
`cargo add` is also refused when a cargo config sits in a directory above the
mirror that cargo would not read for your project. It is refused when the
mirror runs another cargo than your project does: a `rustup override` is set
for your project's directory, so name the toolchain with `cargo +<toolchain>`
or `RUSTUP_TOOLCHAIN`. It is refused when cargo would find another root or
other members in the mirror than in your project before the add, or after it
when a crate the add brings in would be a member only in your project, since
the checked lock would then miss crates your project locks. That happens
when a `Cargo.toml` names the workspace or a member by an absolute path
(`package.workspace`, `workspace.members`, `default-members`, `exclude`, or a
path dependency or `[workspace.dependencies]` entry under a workspace root),
and when a `Cargo.toml` with a `[workspace]` sits in a directory above your
user cache directory; cargo's own error then names it. It is refused when a
`Cargo.toml` would hold a relative path that climbs out of the mirror, as
cargo writes when it rewrites a path dependency you gave by an absolute path.
Make such paths relative to their `Cargo.toml`. A path dependency or `[patch]`
that names a workspace member by an absolute path makes cargo itself fail in
the mirror with a package collision (exit `101`, nothing written); make that
path relative too. On Windows, `cargo add` is refused when the mirror's links
cannot be made (Windows allows them in Developer Mode), for a `--path`
relative to a drive or its root (`\dep`, `C:dep`), and for a `--path` on the
drive of your user cache directory that holds no part of your project. If
`Cargo.lock` or a `Cargo.toml` changes while cargo runs, whether cargo wrote it
or another program did, ossprey puts back what was there before, keeps what it
found beside it as `Cargo.lock.ossprey-found-<n>` (or the `Cargo.toml`
equivalent), and exits `2`.

`cargo install` compiles the crate and runs its build scripts straight away, so
the crates it names are checked first, and a block means cargo never starts.
An exact version given to `--version` (or `--vers`), or `name@1.2.3`, pins a
release; anything else, a range given to `--version` or `name@^1` included, is
checked at the latest release on crates.io. A crate is checked under the name
typed, since `cargo install` takes no other spelling of it (`serde-json` does
not find `serde_json`). Only the
named crates are checked, not their dependencies, and one warning line says so.
An install with `--git`, `--path`, or a `--registry` or `--index` other than
crates.io is not from crates.io and is forwarded unchecked, and so is one that
names no source while cargo's default registry is elsewhere. That is
`registry.default` as cargo reads it for an install: from the last `--config`
that sets it, else `CARGO_REGISTRY_DEFAULT`, else the cargo configs from
`CARGO_HOME` up, nearest first (a relative `CARGO_HOME` counting from where
cargo runs), or possibly set there by an `include` or by a config file too
large or too deeply nested to read. A config that is not a regular file, such
as a piped `--config /dev/stdin`, sets nothing here: `cargo install` reads its
configuration a second time, when the pipe is already empty, and then installs
from crates.io, so the crate is checked. `--registry crates-io` and crates.io's own index
URL are checked like a plain install; an index URL with a non-ASCII host counts
as another registry.
`cargo install --list` is not an install, and nothing is checked for a line
that only prints help or the version: `-h` or `--help` after the subcommand,
or either or `-V`/`--version` before it.

A rustup toolchain (`cargo +nightly add serde`) and cargo's options before the
subcommand (`--config`, `-Z`, `--color`, `-C`) are understood, and so are short
options grouped as cargo groups them (`-qF pcre2` names no crate `pcre2`).
In passive mode nothing is checked in front of cargo, at any version: `cargo
add` and the others run and the `Cargo.lock` they leave is then posted, even
when cargo failed, and `cargo install` posts its crates alongside the build. A
lock that a `resolver.lockfile-path` may have moved, or a cargo script's, is
not posted, and a warning line says so.

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
- **cargo builds and aliases.** `cargo build`, `check`, `run`, `test`, `bench`
  and every other cargo command not listed above are forwarded unchecked,
  though they compile crates and run build scripts. They build what
  `Cargo.lock` names, which `cargo add` and `cargo update` have checked, but a
  build with a missing or out-of-date `Cargo.lock` resolves one on the spot,
  unchecked, and so does an editor such as rust-analyzer after you edit
  `Cargo.toml` by hand: run `ossprey cargo generate-lockfile` (or `ossprey
  cargo fetch`) after editing it. `cargo install` checks only the crates it
  names, not their dependencies. A cargo `[alias]` and an external subcommand
  (such as `cargo upgrade`) are not recognised, so a lock they change is not
  checked.
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
  pip and uv; for `npx` and `npm exec`, every such option npm itself reads,
  wherever it sits on the line, and nothing from the program's own arguments;
  for uv, its global options before the verb as well). Index configuration in
  `.npmrc`, `pip.conf` or `uv.toml` and the environment applies as it would to
  the real command: the dry run reads the `.npmrc` npm itself reads (the
  project's, from any subdirectory, or the `--prefix`; none for a global
  install), and a `uvx` run is resolved with no project configuration, as uvx
  itself runs. A uv or uvx command with a flag pip cannot honour
  (`--index`, `--extra-index-url`, `--overrides`, `--resolution` and the like)
  is resolved by uv only: on a machine without uv such a command is not
  predicted and the named packages are checked, with the warning below.

  The named package itself is then checked at the release the resolver picked.
  When the dry run fails — no resolver, offline, a build-only package, the
  `OSSPREY_RESOLVE_TIMEOUT` (default 2m) — only the named packages are checked,
  one line says so (`could not resolve the dependencies of foo (…); checking
  the named packages only`), and the install proceeds. A tool run still
  checks what an earlier run left on disk (npm's npx cache, uv's cached or
  installed tool environments), since that is what the tool may run when
  today's resolution fails, and the line then says `checking the named
  packages and N dependencies from an earlier run`. The forwarder never
  blocks an install because it could not predict it. The clean verdict
  reports the coverage: `no malware found in 65 packages (1
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

On a Teams or Enterprise plan, add `cargo` to the list.

Open a new shell to pick them up. There's no recursion to worry about:
`ossprey npm` resolves the real `npm` through `PATH` rather than through your
shell, so the alias doesn't apply a second time. Wrap only the managers
listed above, since `ossprey <anything else>` isn't a command.

An intercepted install needs credentials exactly like `ossprey scan` does, so
run `ossprey login` once (or export `OSSPREY_API_KEY`) before relying on the
aliases. With neither, a gating install stops on a credentials error rather
than being quietly forwarded. That includes `cargo add`, `update`,
`generate-lockfile` and `fetch`, which stop on the same error before cargo
runs (the two dry runs need no credential). If the check then fails (the API
unreachable, timing out or refusing the credential), nothing is written to the
project and the command exits `2`. (A passive install never stops for
anything, so there the same failure is a warning and the install proceeds.)

To check they took, run `type npm`. Non-install commands (`npm run build`, `pip
list`, `poetry run pytest`) go straight through untouched, so an
ordinary-looking `npm --version` means the handoff works. A clean install
prints one line of its own, the verdict, on stderr, and then the manager's
output exactly as it would appear without Ossprey:

```console
$ npm install left-pad
ossprey: no malware found in 1 package (1 requested + 0 dependencies), forwarding to npm

added 1 package in 525ms
```

The count covers only what the platform scanned: `no malware found in 63 of
65 packages` when some were not found or not supported. If a finding fell
below your account's failing severity, the line says so instead of claiming
no malware: `no malware found at or above the failing severity in 65 packages
(1 finding below it)`, and `OSSPREY_VERBOSE=1` prints the finding. When the
platform scanned none of the packages, there is no verdict line.

The verdict is ossprey's last line, not the terminal's: the forwarder replaces
itself with the manager once the check passes, so it cannot print after the
manager finishes. `cargo add`, `update` and `generate-lockfile` are the
exception: cargo resolves before the check, so the verdict follows cargo's
output. An install that was not checked (no dependencies found,
`skip-ci`, a passive scan) prints no verdict, since there is none to give.

Otherwise a forwarder speaks only for a malware block (below) or a platform
error — the API refusing a credential, a passive scan that could not be
posted — each reported on stderr. While the check runs, a terminal gets a live
`ossprey: scan in progress... 4s` indicator that erases itself once the
verdict is in; a CI log or a pipe gets nothing.

If a check comes back dirty you get the full malware report on stderr — the
alert box, an `Error: WARNING:` line per finding, and a blocked line naming
the command (see [Output](output.md)) — and an exit code of `1`. The real
manager never starts, except for `cargo add`, `update`, `generate-lockfile`
and `fetch`, which resolve into a scratch copy first and leave the project as
it was.

Set `OSSPREY_VERBOSE=1` for everything else: why an install
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
