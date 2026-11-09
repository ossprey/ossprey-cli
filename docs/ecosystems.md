# Supported ecosystems

What Ossprey parses, and what it does when a version cannot be pinned.

Python, JavaScript and Rust, via syft's static catalogers.

| Ecosystem | Files parsed |
|-----------|--------------|
| Python | `requirements.txt` (and any `*requirements*.txt`, e.g. `requirements-dev.txt`), `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `setup.py`, `pyproject.toml`, wheel / egg metadata |
| JavaScript | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Rust | `Cargo.lock`, and `Cargo.toml` direct dependencies (one its workspace's `Cargo.lock` pins is sent at that locked version) |

Rust (crates.io) scanning is available on Teams and Enterprise plans.

The CLI never installs your dependencies. It does run a resolver — `npm install
--package-lock-only` (in a temporary directory), `uv pip compile`/`uv export`,
or `pip install --dry-run` on a host with no uv — when a project ships a
manifest with no lockfile, purely to work out which versions an install would
pull; nothing is installed and your project is not modified. When that resolver
is missing from PATH or disabled, expect direct deps only — supply a lockfile
for full transitive coverage. Rust has no resolver tier, so a crate with no
`Cargo.lock` always catalogues direct dependencies only.

### A scan never runs package code

Resolving a Python dependency that ships only a source distribution (no wheel
for your platform) normally means running its build backend to read its
metadata — code from the dependency tree being scanned for malware. The scan
never does that:

- npm runs with `--ignore-scripts`.
- uv runs with `--no-build`.
- pip runs with `--only-binary=:all:`, in isolated mode (`python -I`, so a
  `pip.py` in your repository is never what runs), and is handed a copy of each
  requirements file holding only registry requirements. A `--no-binary`
  option, a local path, an editable (`-e`) or a direct URL (`name @ url`) is
  left out, since pip would build it whatever the flags say, and so is any line
  that names an environment variable (`${VAR}`), which pip would fill in from
  the scanning machine. A requirements file that names its own index or
  find-links location (`--index-url`, `--extra-index-url`, `--find-links`) is
  not resolved by pip at all and is reported unresolved: a wheel there can
  declare a dependency by URL on a source distribution, which pip builds even
  under `--only-binary`. uv refuses such a dependency, so with uv installed the
  file resolves. An include (`-r`, `-c`) outside the scanned directory is not
  read by either resolver, and its manifest is reported unresolved.
- uv is never handed a requirements file (or one it includes) or a
  `pyproject.toml` dependency list (`[project]` dependencies and extras,
  `[dependency-groups]`, or `[tool.uv]`'s dev, override and constraint lists)
  that names `${VAR}`, which uv fills in the same way, nor a requirements file
  including a URL (`-r https://…`), which uv would fetch and fill in; that
  manifest is reported unresolved instead. Keep a private index's
  credentials in pip's or uv's own configuration, `PIP_INDEX_URL` /
  `UV_INDEX_URL`, keyring or `.netrc`, which a repository cannot write.
- A legacy `setup.py` project is not resolved at all: that would run
  `setup.py`. Its literal `install_requires` are still read.
- A `pyproject.toml` whose dependencies are `dynamic`, or a poetry project with
  no `poetry.lock`, would have to be built to learn them, so it is not resolved
  either.
- The resolvers do not see `OSSPREY_API_KEY`, `API_KEY`, `OSSPREY_MONITOR_ID` or
  any other `OSSPREY_*` variable.

A Rust crate with dependencies (git and path ones included) and no
`Cargo.lock` (beside it or at its workspace root) is unresolved too, as is a `package.json` whose
`package-lock.json` or `npm-shrinkwrap.json` cannot be parsed when no npm is
available to resolve it instead. A manifest whose `uv.lock`, `poetry.lock`
or `pdm.lock` parses is covered by that lock even when nothing could resolve it.

A manifest that cannot be resolved this way keeps its direct dependencies and
is reported **unresolved**: a warning names it, the
[`--report`](output.md#machine-readable-verdict---report) file lists it in
`unresolved_manifests`, and [`--require-complete`](ci.md#requiring-complete-coverage)
fails the scan over it. Commit a lockfile (`uv.lock`,
`poetry.lock`) to cover its whole tree. A legacy `setup.py` stays unresolved
until its dependencies move to a `[project]` table, and a requirements file,
even fully pinned, needs uv or pip to resolve.

A `Cargo.toml` range takes its version only from its own workspace's
`Cargo.lock`, the one beside its workspace root (chosen as described below) or
beside the manifest itself when it has none, and only from a release there that
the range allows. A lockfile anywhere else, a locked release outside the range,
or an exact `=` pin of the same crate in another manifest or another dependency
table does not set it, and no lockfile does when the search for the workspace
root ends at a `Cargo.toml` it cannot use (below), so that range is sent at the
latest published release like any other unpinned dependency (below).

Directories that hold installed or built packages rather than your project's
own manifests are not read at all: `node_modules`, `bower_components`,
`.pnpm-store`, `.yarn`, `.venv`, `venv`, `site-packages`, `dist-packages`,
`__pypackages__`, `.tox`, `.nox`, `target`, the framework caches `.cache`,
`.next` and `.nuxt`, and `.git`, at any depth. The
lockfile beside them already names what they contain, and walking them could
add minutes to a scan. A project whose only record of its dependencies is an
installed tree, with no lockfile or manifest, catalogues nothing from it.

Crates that `cargo vendor` copied into the project are not read either,
whatever the vendor directory is called. A crate's `Cargo.toml` and
`Cargo.lock` are skipped only when all of these hold.

- Its directory holds the `.cargo-checksum.json` that `cargo vendor` writes.
- A project above it, with its own `Cargo.toml` and `Cargo.lock`, locks that
  crate at that version with the same checksum, and that lock also holds a
  release meeting every dependency the crate's `Cargo.toml` turns on (its
  non-optional ones and those its default features enable).
- That project's cargo config (`.cargo/config.toml` or `.cargo/config`)
  replaces crates.io with the directory holding the crate, as the config
  `cargo vendor` prints does, and that source is not replaced again. Since
  cargo reads its config from wherever it runs, every other committed cargo
  config in the scan must still send crates.io to a vendor directory.
- Nothing builds the crate by path (a path dependency, `[patch]`, workspace
  member or `paths` override, in any `Cargo.toml` or cargo config in the scan,
  above it, or in `CARGO_HOME`), and its `Cargo.toml` has no `[workspace]`.

Your `Cargo.lock` then already names everything the crate brings in. Only
those two files are skipped; a `.cargo-checksum.json` never hides anything
else, such as an npm or Python lockfile beside it, and a file reached through
a symlink is always read. Crates vendored from git, vendor trees whose cargo
config is generated at build time rather than committed, and a vendored crate
you scan directly are still read. Nothing is skipped when any `Cargo.toml` or
cargo config cannot be read, or names a path the scan cannot place: a
workspace member glob with `[` or `**`, a glob outside the scan, a
`path-bases` `base`, a config `include`, a cargo alias that runs
`cargo vendor` (which ignores source replacement) or passes `--config`, two
configs or a config
named in another case in one directory, or a file reached through a symlink
that leaves the scan.

Lockfile entries for your own code are not components: the root project,
npm workspace links, and yarn `workspace:`, `portal:`, `link:` and `file:`
dependencies are left out, since none of them is published to a registry.
A `Cargo.lock` crate that Cargo fetches from git or from a registry other than
crates.io is sent marked with its source, as a `vcs_url` or `repository_url`
purl qualifier with credentials removed (a registry by its origin only, and a
source too long to send by its origin or scheme), so the platform can tell it
apart from the crates.io crate of that name. A crate from a registry host
spelled with non-ASCII characters is sent both marked and as the crates.io
crate, since Cargo reads some such hosts as crates.io. A dependency that `[patch]`
or `[replace]` redirects to git is sent both ways: the git crate, marked, and the
crates.io crate `Cargo.toml` declares. When your workspace root's `Cargo.lock`
records the git crate from the same URL with the same `branch`, `tag` or `rev`,
at a version the patch's `version` or the replaced release accepts, it comes
from the lock at its locked commit. Otherwise, as when there is no lock, the
lock predates the patch or names another branch, tag, rev or version, or the
lock is not a regular file, it comes from the root's `Cargo.toml`, with the
commit when `rev` names a full one. A
workspace member scanned on its own counts as its own workspace root, so its
git patches are sent too, although Cargo ignores them when it builds the whole
workspace. A patch or replacement by `path` is your own code and is not sent.
An exact `=`
pin in `Cargo.toml` that disagrees with `Cargo.lock` is sent at both versions,
since Cargo rebuilds to the pin unless run with `--locked`.

A cargo config (`.cargo/config.toml` in your project or a directory above it,
or the one in `CARGO_HOME`) can replace crates.io with another source, such as
a mirror, a git repository or a vendor directory. `Cargo.lock` still names
crates.io releases, and those are what the scan checks, not the code that
source serves. When the scan finds such a replacement it says so once, unless
the replacement is a `cargo vendor` directory it verified as described above.

A dependency a Cargo workspace member inherits with `{ workspace = true }`
takes its version from the member's workspace root. That is the root the
member's `package.workspace` names (or `workspace` in a legacy `[project]`
table). Otherwise it is the first `Cargo.toml` on the way up from the member
that has a `[workspace]` table whose `exclude` list leaves the member in, or the
root that a package manifest on the way up names in its own
`package.workspace`. A `package.workspace` path, and an absolute `members` or
`exclude` entry, is compared by real path, so a symlink or another spelling of
the same directory still matches. A `Cargo.toml` on the way up that cannot be
read or parsed, that is a symlink leading out of the directory you scan, or
that has no `[package]`, `[project]` or `[workspace]` table ends the search,
even when a higher `[workspace]` lists the member, and the inherited dependency
is skipped with a warning. It is skipped the same way when no root is found
inside the directory you scan.
A dependency whose `registry-index` points at crates.io is read as a
crates.io dependency. A `=` requirement is sent as a pinned version only when
it is a valid semver release, with no leading zeros and no empty parts, and
any build metadata after `+` is kept as written. Any other requirement is
treated as a range.

When a dependency's version can't be determined — an unpinned range in a
manifest (`click = "^8"`, or a bare `requests` in a requirements file) with no
lockfile or resolver to pin it against — the scan defaults that component to
the **latest published version** from its registry (PyPI, npm or crates.io): the version a
fresh install would pull today. Registry
lookups fail open, so a component whose version can't be resolved (offline,
private, or removed package) is left unversioned rather than dropped or failing
the scan.

To skip these lookups for a fully offline catalog, pass `--no-version-lookup`
(or set `OSSPREY_RESOLVE_LATEST=0`, which also covers the package-manager
forwarders, whose args are passed through untouched). Unpinned components are
then left versionless.

---

[← Back to the docs index](README.md)
