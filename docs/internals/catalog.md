# Scan data flow and cataloguing (`internal/catalog`)

How a scan flows and why the catalogue is assembled as it is. Cargo has its own page: [cargo.md](cargo.md). [Back to the internals index](README.md).

## Core data flow (scan)

`internal/scan` → `internal/catalog` → builds `internal/ossbom.SBOM` →
`.ToMiniBOM()` → `internal/submit` → `internal/client` (POST + poll) →
`sbom.ApplyAPIResponse()` → `scan.MalwareReports()` decides the exit code.

`check` reuses the same `submit`/`client`/`ossbom` path but builds a
one-component-per-spec SBOM instead of cataloging the filesystem. `forward`
reuses `check.Run` after parsing install args.

## Cataloging (`internal/catalog`)

`Catalog()` in `syft.go` deliberately **bypasses `syft.CreateSBOM`** (which
pulls in ~30 MB of unused catalogers). It instantiates a curated set against one
directory `FileResolver` and runs them all unconditionally:

- **Syft built-ins** handle lockfiles + installed-package metadata (Python, JS lock).
- **Custom catalogers** fill resolution gaps where a project ships a manifest but no lockfile:
  - **The Python resolver is chosen once, in `Catalog`** (`lookupUV`): `uv` where the host has one — its three catalogers get the resolved binary path — and `PipCataloger` otherwise. They resolve the same manifests, so building both would pay twice for identical output. Keep that choice at the call site: a cataloger that decides for itself whether to run hides the scan's shape from the one place that assembles it. `lookupUV` **runs** `uv --version` rather than trusting the PATH lookup, because picking uv rules pip out for the whole scan — a uv that is present but cannot execute would fail every manifest with no fallback left. `findPython` probes the same way, for the same reason.
  - **These resolvers execute code, and the docs must not claim otherwise.** Resolving an sdist-only dependency makes pip *and* uv run that package's PEP 517 build backend to read its metadata — from the dependency tree we are scanning for malware. `npm install --package-lock-only --ignore-scripts` is the one that genuinely runs nothing. Neither `--only-binary=:all:` (pip) nor `--no-build` (uv) is set, because a sdist-only dependency would then fail the whole manifest instead of resolving.
  - `UVCataloger` — full transitive resolution via `uv` (hatch, uv, bare pyproject).
  - `SetupPyCataloger` — transitives from legacy `setup.py` setuptools projects.
  - `PipCataloger` — the same resolution via `pip install --dry-run --report`, for hosts with no `uv`. Two rules are load-bearing. It shells out as `python -m pip`, never `pip`: `pip` may be an ossprey shim, which would route straight back into `ossprey pip install` → project scan → pip cataloger, unbounded. And it resolves a `pyproject.toml` from its *parsed* `[project]` requirement strings written to a temp file, never by pointing pip at the directory — `pip install --dry-run .` builds the project's metadata, executing a PEP 517 backend from the tree we are scanning for malware. `[tool.poetry.dependencies]` is skipped because poetry's caret/tilde shorthand is not PEP 508 and would fail the whole manifest (uv's `pip compile` reads `[project]` only, same as here); poetry projects are covered by their `poetry.lock` via syft. pip predating 22.2 has no `--dry-run`/`--report`, so the version is checked once and the cataloger skips with a warning rather than failing every manifest identically.
  - `PyProjectCataloger` — direct-deps fallback for `pyproject.toml` when no resolver is available.
  - `NpmResolveCataloger` — runs `npm install --package-lock-only` to resolve ranges when no lockfile is committed (npm analogue of uv).
  - `PackageJSONCataloger` — direct-deps fallback for `package.json`.
  - `NpmLockCataloger` — reads `npm-shrinkwrap.json` (syft never globs it, yet `hasNpmLockfile` stands the npm resolve down for it) and the nested `dependencies` of v1 package-locks, which syft reads only at the top level.
  - `RequirementsTxtCataloger` — versionless direct deps for requirements lines that pin no release (syft drops a bare `requests`). Exact pins are left to syft/`requirementPins`. Every requirements reader uses syft's own `**/*requirements*.txt` (`requirementsGlob`); a resolver globbing only `requirements.txt` left `requirements-dev.txt` direct-only.
  - `CargoTomlCataloger` reads `Cargo.toml` direct dependencies, since syft reads only `Cargo.lock`. A `{ workspace = true }` dependency takes its pin from the root cargo itself finds (`workspacePool`, OSS-2099): the root `package.workspace` names (a legacy `[project]` table's `workspace` too, which cargo 1.99 still follows before the 2024 edition; `decodeCargoManifest`), else the first ancestor on the way up that has `[workspace]` with an `exclude` leaving the member in (a `members` entry overrides `exclude`, as in cargo's `is_excluded`) or that names a root in its own `package.workspace`. Any other root ships a pin cargo never uses. A `package.workspace` path and an absolute `members` or `exclude` entry are compared by real path (`respell`), because the resolver spells a manifest under the scan root as given on POSIX but under the resolved root on Windows, a Windows runner's temp dir is an 8.3 short name, and a pointed root must be spelled as its `Cargo.lock` is for the fold. The walk climbs past a `Cargo.toml` that `os.Stat` cannot reach, a symlink loop included, since cargo's `find_root_iter` filters ancestors with `Path::exists`, which is false for both (verified with cargo 1.99: past a self-loop it takes the outer root that lists the member, and fails identically to a missing file when that root does not). It stops at one it cannot read or parse or one with no `[package]`, `[project]` or `[workspace]` (cargo rejects each as a potential workspace manifest), and at one linked out of the scan root, which cargo reads but whose pool would come from outside the scan: no higher root counts, so the dependency is dropped with a warning. Cargo run from the member errors at that file (verified with cargo 1.99), while cargo run from a higher root that lists the member never reads it and builds the member with that root's pool. The drop under-reports only that root-invoked build, which we accept rather than reimplement how cargo loads a workspace's members; climbing on without that check borrowed an unrelated outer workspace's pin. A `registry-index` counts as crates.io when `isCratesIo` definitely accepts it spelled as the `Cargo.lock` source cargo records (the value under `registry+`, or as written when it starts `sparse+`); skipping it hid a crates.io crate with no warning. A non-ASCII host that cargo's IDNA may map to github.com or elsewhere is dropped like any other registry's entry, since sending it bare would show a crates.io release for a crate cargo may fetch elsewhere. A `=` pin must be strict semver (`registry.IsCargoRelease`, no leading zero, no empty identifier and no core number past u64) or it is a range, but build metadata stays as written, because crates.io serves a release under the exact string it was published with and stripping `+meta` would name a release that does not exist.

Custom catalogers shell out to a tool the caller resolved (`lookupUV`) or that
they look up themselves (`npm`); a missing tool means the cataloger is not built,
or **silently skips** (returns nil) rather than erroring. The one break in that
silence is `PipCataloger`: when the host has no uv and no usable pip *and* the
tree declares Python dependencies, it prints one line saying the scan covers
direct dependencies only. That silence is what let a customer's CI ship manifest-only
SBOMs for weeks — every unpinned dependency versionless, rejected at intake —
without anything in the output saying so. Custom catalogers named via
`isOspreyCataloger` parse deps only; syft's manifest catalogers also emit the
root project itself, which is dropped via `isRootManifestPackage`.

Every one of those lookups goes through `lookTool`/`toolEnv` (`toolpath.go`),
**never `exec.LookPath`** — including `lookupUV`, even though it resolves once
for the whole scan rather than per cataloger.

**Why not `exec.LookPath`:** `ossprey shim install` puts the shim directory at
the *front* of PATH, so on a machine with shims installed `exec.LookPath("npm")`
returns a script whose whole job is to run `ossprey npm ...`. A cataloger that
executes it re-enters ossprey — the forwarder sees no packages named, scans the
temp manifest the cataloger just wrote, and shells out to the shim again, one
process per level. A plain `ossprey scan .` fork-bombed itself (3000+ processes
in one measured run) until `OSSPREY_RESOLVE_TIMEOUT` fired, then emitted a whole
nested scan's output — its own warnings, verdict and `blocked` line — inside one
cataloger warning, and fell back to the versionless direct-deps cataloger, so
transitive dependencies went unscanned (OSS-1993). `lookTool` is
`shim.LookPathReal`, which skips marker-carrying candidates; `toolEnv` also sets
`OSSPREY_SHIM_BYPASS=1`, the same belt-and-braces pairing as the shim script's
own PATH-stripping guard, for shims reached by a route PATH scanning cannot see.
`TestCatalogNeverInvokesAnOssprevShim` pins it. `PipCataloger` is exempt from the
name lookup but not from the hazard: it shells out as `python -m pip` precisely
because `pip` itself may be a shim.

A cataloger's error is **not** a reason to drop its packages: syft's generic
cataloger returns everything it parsed alongside an `unknown` error naming the
lines it could not, exactly as `syft.CreateSBOM` does. Discarding on `err != nil`
emptied the SBOM of every Python package over one `flask>2.0` line — a scan that
silently checked nothing (OSS-1869).

Versions syft reads out of a requirements file are corrected against the file
itself by `requirementPins` (`requirements_pins.go`). Syft captures the
constraint with `[0-9a-zA-Z.*]`, which truncates every PEP 440 separator outside
that class — `==1.0.0-beta.1` becomes `1.0.0`, `==1.2.3+local1` becomes `1.2.3` —
and strips only `==`, so `===1.0` reaches the SBOM as `=1.0`: real-looking purls
naming a release the project never installs (OSS-1869). It **corrects, it does
not catalog** — only requirements that pin exactly one release are touched, so a
range or wildcard is left to syft's guess, and shapes syft drops outright (a bare
`>2.0`, an epoch `==1!2.0.0`) stay missing for the resolver-backed catalogers to
cover.

Output is deduped by `(type, name, version)` plus a Cargo source mark. Every package keeps its first location, since one location per lockfile let a monorepo's SBOM outgrow the API's 5 MB limit (300 Rust projects with a lock each reached 5.6 MB). A crate also keeps every `Cargo.toml` that declares it, which grows only with the manifests' own dependency lists, while the locks holding each crates.io release go to the per-manifest fold below on the side (`indexCargoLocks`). `mergeVersionless` then collapses
a package emitted both versionless (direct-deps fallback) and pinned (uv-resolved)
into the pinned one. Vendored paths (`node_modules/`) are skipped (`isVendoredPath`). Lockfile entries for the project's own code are dropped: yarn by resolution protocol (`workspace:`/`portal:`/`link:`/`file:`), npm when `resolved` is a scheme-less relative path (a workspace link). Otherwise the project's own name went to the API and was looked up on public npm.

**Package sinks are excluded from the syft index itself** (`packageSinks`,
`newDirectorySource`). Filtering `node_modules` packages after cataloguing was
not enough: syft's directory resolver opens every file it indexes, and a
customer's passive pnpm install spent ~180s under "submitting scan" walking
`node_modules` (reproduced: 273s vs 0s on a 76k-file tree, same 1707
components). Two traps: syft **rewrites the exclusion slice in place**, so
`packageSinkExcludes` returns a fresh one per call; and syft walks the
**symlink-resolved** root but anchors exclusions to the path as given, so the
root is `EvalSymlinks`ed first or no exclusion matches under macOS `/var`.
`TestDirectorySourceSkipsPackageSinks` asserts on the index, not on catalog
output, because catalog output was already clean before the fix.

**syft's TOML lockfile parsers sit behind a resolver wrapper** (`withBoundedLocks`,
OSS-2098). syft v1.44.0 parses `poetry.lock`, `uv.lock` and `pdm.lock` with
BurntSushi/toml, which allocates quadratically in nesting (643 MB for one 8 KB
key, 3.7 GB for 4,000 nested inline tables in a `uv.lock`, which it parses
twice), and `Cargo.lock` with pelletier/go-toml v1, which stays linear but
recurses per array and dies of a fatal stack overflow at 400,000 nested arrays
(800 KB). A fatal error cannot be recovered, so a lockfile over `maxLockBytes`
(2 MiB) or deeper than `maxLockDepth` (16) is hidden from every cataloger, with
one warning per file. A refused `uv.lock` is gone for the uv cataloger too, which then compiles the project from its manifest (`uvArgsForPyProject` asks the resolver, not the disk), so `uv export` never reads pins the warning says were not read. Lockfiles get caps of their own, tighter than a
manifest's: 4,680 real ones swept were at most 650 KB and 4 levels deep, while
one crafted just inside 32 MiB and 64 levels still cost syft tens of seconds and
gigabytes. Cost grows with size more than depth, so the size cap is what bounds a
crafted lockfile: just inside 2 MiB and 16 levels, nested inline tables allocate
1.4 GiB in one BurntSushi decode (5.6 GiB at 8 MiB), and a `uv.lock`, which syft
decodes twice, takes about 2.4 s and under 900 MB at peak (12 s and 3.7 GB at
8 MiB); a real 650 KB `poetry.lock` allocates 10 MB.
`TestBoundedLocksKeepOnlyWhatSyftParsesWithinBounds` holds the worst shapes
under 2 GiB a decode. The `cargo vendor` filter reads `Cargo.lock` within the same
caps (`readLock`), since it runs before this wrapper. Past the `--timeout`
deadline the wrapper reads no more lockfiles and hides every one it has not
checked, without a warning each: the scan is ending, `scan.Run` says so once,
and a lockfile left visible would reach syft's parsers unguarded. syft parses
no `pyproject.toml`, so that one needs no wrapper.

### Why the npm resolve skips workspace members (OSS-1353)

`NpmResolveCataloger` stands down for a manifest whose own dir ships a lockfile,
**and** for one that is a declared workspace member of an ancestor that ships
one (`isWorkspaceMember`, `npm_workspace.go`). The root lockfile already
enumerates every declared member's full transitive tree, so resolving them again
costs a network round trip and adds nothing. On gatsby that is 117 of 362
manifests, each ~17.7s, which is what pushed monorepo scans past the platform's
850s budget.

**The gate is membership, not ancestry, and that distinction is the whole point.**
An earlier revision skipped whenever *any* ancestor had a lockfile. That is wrong:
gatsby's root declares only `workspaces: ["packages/*"]`, so its 237
`examples/`, `integration-tests/`, `benchmarks/` and `e2e-tests/` manifests are
not members and their deps are absent from the root lock. Skipping them silently
dropped real transitives (verified: a non-member depending on `is-odd` lost
`is-number`). If you ever widen this gate, widen it to a path exclusion you can
name, not to "an ancestor had a lock".

Membership reads `workspaces` from `package.json` (bare array and yarn's object
form) and `packages:` from `pnpm-workspace.yaml`, which wins where present since
pnpm ignores the `package.json` field. `!` exclusions prune their subtree
wherever they are listed. A `pnpm-workspace.yaml` with no `packages` key claims
nothing (verified against pnpm 10, which then reports the root project alone).
Do not "fix" that to a catch-all, it would skip every resolve in the tree.

### Timeouts

Two independent budgets, both off-by-default-safe:

- `OSSPREY_RESOLVE_TIMEOUT` (default 2m) caps **one** uv/npm invocation, so a
  single hung manifest cannot eat the whole scan. A real 166-dep manifest
  resolves in ~18s, so the default is roughly 7x headroom.
- `--timeout` / `OSSPREY_SCAN_TIMEOUT` (default off) caps the **whole**
  catalogue. On expiry the SBOM cataloged so far is emitted and the exit code is
  unchanged, because partial results beat being SIGKILLed by an external budget
  with nothing to show. Off by default because an interactive scan has no such
  budget; the platform sets the env var. Per-manifest warnings are suppressed
  once the deadline passes, since every remaining manifest fails identically and
  `scan.Run` already says so once.
