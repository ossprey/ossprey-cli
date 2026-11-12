# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ossprey` is a Go CLI for the [Ossprey](https://ossprey.com) supply-chain malware
platform. It statically catalogs a project's Python/JavaScript dependencies into
an **OSSBOM**, submits it to the Ossprey API, and exits non-zero if any package
is flagged as malware. It never executes the project's package manager during a
scan (no installs, sandbox, or virtualenv) — see the custom catalogers for the
one exception.

## Where docs go

`README.md` is the landing page for someone who has never run this tool: what it
is, install, `init`, scan, and one short section per way of using it, each
linking onward. Keep it that way — every flag table, edge case and rationale
belongs in `docs/`, which is the reference set (`install`, `init`,
`cli-reference`, `forwarder`, `shims`, `passive-monitoring`, `precommit`, `ci`,
`output`, `ecosystems`, `trust`, `architecture`, indexed by `docs/README.md`). When a
behaviour changes, the user-facing statement of it lives in exactly one of those
pages; this file keeps the *why*. `docs/architecture.md` holds the mermaid
diagrams, so a change to the forwarder's decisions or the scan pipeline needs
them updated too.

## Commands

```sh
make build         # release binary -> bin/ossprey (-trimpath, stripped)
make build-debug   # unstripped build with symbols
make test          # go test ./...
make test-race     # go test -race ./...   (CI runs this)
make test-smoke    # end-to-end: build binary, scan test/test_packages fixtures (-tags smoke)
make test-smoke-short  # smoke tests minus network/GitHub-clone tests
make fmt           # go fmt ./...
make vet           # go vet ./...
make tidy          # go mod tidy  (run first time / after dep changes)
```

Run a single test: `go test ./internal/catalog/ -run TestName -v`.
Smoke tests live behind the `smoke` build tag: `go test -tags smoke -run TestName -v ./test/smoke/...`.

CI (`.github/workflows/ci.yml`) gates on `gofmt -l` being empty and `go vet`
(with and without `-tags smoke`) on ubuntu, and on `go test` and `go test -race`
on ubuntu and windows. Keep code gofmt-clean. Requires Go 1.25+.

The `smoke` job also runs the whole tagged suite on both OSes, because the
forwarders and shims can only be verified with the real binaries (pnpm on
Windows is a `.cmd`, as are the shims). It pins Python 3.12 with `setup-python`:
the Python fixtures pin numpy releases whose wheels stop at 3.12, and on the
26.04 image's newer Python pip builds them from source, so every scan of them
waits out `OSSPREY_RESOLVE_TIMEOUT` and the suite misses its 15m budget. Tests that need the shim
directory must ask `ossprey shim dir` rather than assuming `~/.ossprey/shims` —
Windows resolves it under `%LOCALAPPDATA%`.

## Architecture

`cmd/ossprey/main.go` wires three command families with cobra:

0. **`init [path]`** (`cmd/ossprey/init.go`) — the one-command onboarding path
   (OSS-1387), in three steps: ensure a login, mint an API key, scan the project
   **with that key**. Key creation goes through `client.CreateAPIKey` on
   `/dashboard/v1/api-keys`, which **requires a bearer token** — API keys cannot
   mint API keys, so step 2 never uses `OSSPREY_API_KEY`. `ensureLogin`
   reuses/refreshes a stored login, but only when `matchesTenant` says domain,
   client ID **and** audience all agree, else a prod token would be silently
   reused against a QA `--audience`. All three matter: comparing only domain and
   audience let `--client-id <other-app>` reuse a token minted for a different
   Auth0 application. The device-flow prompt is shared with `login` via
   `runDeviceLogin`.

   Step 3 passes the **new key** to `submit.Validate` rather than falling through
   to the stored login, so a clean scan proves the credential works before the
   user wires it into CI. Note this changes the wire path: an API-key client hits
   `/public/v1` with `x-api-key`, a bearer client `/dashboard/v1`. When key
   creation fails, `keyValue` returns `""` and `submit.Validate` falls back to the
   login, so the scan still happens. That fail-**open** posture is deliberate — a
   key limit must not cost the user their scan.

   The scan is the user's **choice** (`wantScan`): `--scan`/`--no-scan` answer up
   front, otherwise an interactive terminal is prompted and a non-interactive run
   declines, printing how to opt in. Use `term.IsTerminal`, **not** `os.Stat` +
   `ModeCharDevice`, to detect interactivity — `/dev/null` is itself a character
   device, so the naive check treats `ossprey init < /dev/null` as interactive and
   silently takes the prompt default. `TestInitNonInteractiveDoesNotScan` pins
   this with a real `/dev/null` stdin.

   `--key-stdout` writes the bare key to stdout for piping into a secret store
   (`ossprey init --key-stdout | gh secret set OSSPREY_API_KEY`), so every
   human-facing line must go to `logOut` (stderr in that mode) — hence the
   `io.Writer` threaded through `ensureLogin`/`freshLogin`/`runDeviceLogin`. It is
   mutually exclusive with `--scan` because a scan verdict on stdout would corrupt
   the pipe, and with `--no-key` because there would be nothing to print.

   **The key cannot be recovered after creation**: the backend stores only an
   HMAC-SHA256 (`keys/api_db.py: hash_api_key`) and the list endpoint redacts it
   (`keys/get_api_keys.py: redact_key`). So "just look it up in the dashboard" is
   not an option to offer users — print-once plus `--key-stdout` is the whole
   surface, and the dashboard link is for revoking, not retrieving.

   **Re-running is safe but not idempotent:** step 2 mints a *new* key each run
   (fresh random name, retried on a 409 collision). That is deliberate — the
   common re-run reason is "I never saved the key" — but the backend caps keys at
   `MAX_KEYS_PER_USER` (10), so repeated runs can exhaust the quota with orphaned
   keys; `--no-key` skips the step. Do not "fix" this by having init GET existing
   keys and skip: the list endpoint redacts key values, so skipping would leave a
   user who lost their key with no way to get one.

   **`init` writes no files, deliberately.** An earlier revision generated
   `.github/workflows/ossprey.yml`; that was dropped because it made a
   GitHub-shaped assumption about a CLI that otherwise doesn't care about your CI,
   and because it wrote into the user's repo. The knowledge that made the template
   correct now lives in `docs/ci.md` ("CI usage") instead, and it is worth
   keeping there: the job needs an `if:` guard so **fork** `pull_request` runs skip
   (GitHub withholds secrets from them, so `OSSPREY_API_KEY` is empty and every
   external PR fails red for a missing key rather than for malware — never close
   that by switching to `pull_request_target`, which hands secrets to untrusted
   code), and actions should be SHA-pinned rather than tag-pinned. If you ever
   reinstate generation, also remember git ref names permit `]`, `#`, `&` and `'`,
   so a branch name dropped raw into `branches: [%s]` yields YAML Actions cannot
   parse — i.e. silently no scanning at all.
1. **`scan [path]`** — catalog a directory, submit, report.
2. **`check -e <pypi|npm|cargo> <name[@version]>...`** checks named packages with no project on disk. A crate takes one exact release or none (`splitCargo`: the version after an optional `=` is held to `registry.IsCargoRelease`, the release grammar the cataloguer applies after its required `=`, and the name to `registry.IsCargoName`; a bare `1.2.3` is that exact release, as `cargo install` reads it): Cargo reads `1.0` as a caret range and nothing here resolves a cargo range, so a range is an error rather than a check of a guessed release; a bare name resolves the latest stable release from crates.io. Both forms go through `registry.CanonicalCrate` and are sent under crates.io's own spelling, because crates.io folds case and `-`/`_` into one crate while the malware lookup matches the name exactly; an outage is an error, but a pinned crate crates.io answers 404 for is sent as typed, since crates.io deletes malicious crates and those are the ones most worth checking. The service folds crate names only for package-wide verdicts, so a deleted crate typed in another spelling still meets one, while a per-version record matches the name exactly. Cargo itself never folds a spelling (verified with cargo 1.99.1: `serde-json = "=1.0.100"` fails with no matching package), so a `Cargo.toml` that builds names each crate as crates.io spells it, and the pre-commit hook sends that spelling unchanged.
3. **Forwarders** (`npm`/`npx`/`pnpm`/`yarn`/`bun`/`bunx`/`pip`/`pip3`/`poetry`/`uv`/`uvx`/`cargo`): registered dynamically from `forward.Managers()`. Each wraps an install, blocks on malware, otherwise execs the real manager. `DisableFlagParsing: true` so every arg reaches the real tool untouched; config comes only from `OSSPREY_API_URL` / `OSSPREY_API_KEY` env vars. `forward.Run` has two modes (`internal/forward/forward.go`): when packages are **named** it checks exactly those (`ParseSpecs` classifies args into `Specs` / `NonPackages` / `ReqFiles`, skipping flag-values, local paths, archives, URLs, VCS refs); when **no** packages are named — a bare `install`/`ci`/`yarn install`/`poetry install`/`poetry sync`/`uv sync`/`uv lock`/`pip install -r`/`uv pip sync` — the manager installs from the project manifest, so it runs a directory scan (`scanProjectFn` → `scan.Run` + `submit.Validate`) and checks every declared dependency rather than falling through unchecked (OSS-1284). Only installs whose sole targets are local/URL refs forward without a check. `uv pip sync`'s positionals are requirements files (`Manager.reqFileArgs`), so it is a manifest install. `uv tool install` is a named install: `--with` values are checked as packages too (`packageValueFlags`), and a `--from` value *replaces* the positional (`sourceFlags`) — checking the bare positional as well would resolve it to latest and check a release that is not being installed. `uv run` is a script runner like `pnpm run`, with the same side-effect gap: it syncs the project env (and installs `--with` packages) unchecked.

   **A named install is checked with its dependencies (OSS-2481).** `npm install express` installs 65 packages; the forwarder used to check one, and the planted package in a real attack is rarely the one asked for. `resolveNamed` (`internal/forward/expand.go`) asks the manager's own kind of resolver what the install would add — `catalog.ResolveNpmInstall` runs `npm install --package-lock-only --ignore-scripts` in a throwaway copy of the project; `catalog.ResolvePythonInstall` runs `uv pip compile --no-build`, or `pip install --dry-run --only-binary=:all:` without uv — and checks the whole tree at the releases the resolver picked. Four rules: it **never runs package code** (no scripts, no sdist builds; a package that needs building fails the dry run and falls back); it **fails open, out loud** — on any error the names are checked alone and `reportUnexpanded` prints one line even when quiet, since a clean verdict on the names must not read as a verdict on the install (a tool run's cached or installed trees, below, are read whether or not the dry run succeeds — a failed resolution is exactly when npm reuses its npx cache — and come back beside the error, so `resolveNamed` still counts them and the line claims them: `checking the named packages and N dependencies from an earlier run`; and since such a tree says nothing about what resolves today, the names are then resolved as well — `npx tool@latest` with `tool@1.0.0` cached may fetch `2.0.0` — each counted once and a release already in the set not repeated, and a cached copy's trusted provenance covering that copy only, never the lookup); the npm copy is **diffed against the project's lockfile** (`Resolved.Locked`), so only what the install adds is checked, not a monorepo's thousand locked packages; and the copy drops local/workspace deps so npm resolves from registries alone. The scratch dry run is **isolated from whatever is above it**: with no project it gets a minimal `package.json` of its own, since npm otherwise takes the nearest ancestor with one as the project and rewrites that project's `package.json` and lockfile (verified: a `TMPDIR` inside a project did exactly that), and every dry run passes `--workspaces=false` so npm cannot walk on to an ancestor workspace root whose globs name scratch (a copied root still locks its own members, verified); the uv probes (`uv cache dir`, `uv tool dir`) name their configuration through `uvToolRunConfig` for the same reason, since a bare scratch directory does not stop uv discovering a project's `uv.toml` above it. The project is the context only when the install will update a lockfile npm can read (`npmProjectDir`); otherwise the names resolve on their own. Trust applies to the tree with the registries the resolver reported. Resolvers get the tokens as typed (`installArgs.Tokens`), and only resolution-affecting flags (`pickFlags`). Tool runs (`npx`, `npm exec`, `bunx`, `uvx`) are expanded too (`installArgs.ToolRun`): with no project context, since the package goes into the tool's own cache, and with none of the program's argv read as a resolver flag — only a uvx flag before the command (`toolRunLeadingFlags`, translated for the pip fallback by `toolRunPipFlags`) reaches the Python resolver, and only the `--registry` and `--userconfig` npm's own parse attributes to npm (`npmArgv.Registry`/`Userconfig`, the path made absolute since the dry run runs elsewhere) reach the npm one. A uv command with a flag pip cannot honour (`uvOnlyResolution`: `--index`, `--extra-index-url`, `--overrides`, `--resolution`, `--exclude-newer`, `--torch-backend`, `--no-binary` — pip's dry run is `--only-binary=:all:`, so it would pick the newest release with a wheel where uv builds the newest of all — …) never reaches the pip fallback: uv takes the first index that has the package, pip the best version across indexes, so pip would check a release uv does not install, and a private-only name would resolve from PyPI, where a squat may wait. `needsUV` routes it to `catalog.ResolvePythonInstallWithUV`, which fails with `ErrNeedsUV` on a host without uv so the names are checked with the warning (`TestExpandInstall_UVOnlyFlagsAreResolvedByUVOnly`). The same holds for configuration outside the line (`catalog.UVConfigShapesResolution`): a `UV_INDEX_URL` or any other `UV_*` variable for an index, strategy, cut-off, build policy, interpreter or override, or such a key (or a `[pip]` table with one) in the file uv reads — `--config-file`/`UV_CONFIG_FILE`, else the project's `uv.toml`/`pyproject.toml [tool.uv]` for a named install (never for a tool run), and the user- and system-level `uv.toml`, which uv merges underneath a project file, so a project file that shapes nothing stops discovery above it and not their check — makes the command uv-only, since pip reads none of it and would resolve from the public index instead; an unreadable file counts as shaping, and `--no-config` stops the files but not the variables. `--default-index` still maps to pip's `--index-url` and `--constraints` to `--constraint`, which mean the same. A uv config named as a pipe (`--config-file <(...)`, `UV_CONFIG_FILE=/dev/fd/3`) is never opened by the dry run or the probes (`uvConfigPipe`): a pipe is read once, uv's children inherit the fd (verified), so any read before the run leaves uvx an empty config and the default index, and the names are checked alone with a line naming the file as a pipe. **Configuration follows the real command, not the cwd.** uvx reads no project configuration (verified: a `uv.toml` with a bad index breaks `uv pip compile` in that directory and not `uvx`), so a tool run resolves with `dir ""`, a scratch directory, and `pythonPathFlags` are made absolute first. The `[pip]` table is the other way round: `uv pip compile` applies it and uvx ignores it (verified: one file with a top-level `index-url` and a `[pip] index-url` sends uvx to the former and the compile to the latter), so for a tool run `uvToolRunConfig` writes the configuration the run reads — the file named by `--config-file` or `UV_CONFIG_FILE`, else the user-level `uv.toml` merged over the system-level one as uv merges them (`mergeTOML`: table by table, the user's value winning, and arrays joined with the user's entries first — verified with `--show-settings`, where the user's `[[index]]` and `extra-index-url` entries precede the system's — since replacing the array dropped an index the run uses) — into scratch without that table and names the copy with `--config-file`, with every relative local path among a file's index and find-links settings made absolute against that file's directory first (`anchorUVConfigPaths`), since uv resolves them there and not against the cwd (verified: `find-links = ["./wheels"]` in the user-level file reads `<config dir>/wheels` from any directory and under `--directory`), so the copy in scratch would otherwise send the dry run to directories under scratch and resolve from the registry what the run takes from local wheels; always, when the files are discovered rather than named, even with no table or no file at all (an empty one then), since a named file stops uv discovering a project's `uv.toml`/`pyproject.toml` above scratch (verified), and scratch sits under a project when `TMPDIR` points inside one; `UV_CONFIG_FILE` names configuration pip does not read, so `uvEnvConfigFlag` hands the resolver and the probes `--config-file <abs>` whenever it is set (absolute or not), which makes the run uv-only rather than letting the pip fallback resolve from indexes the run does not use, and a relative value is made absolute first since it is read where the run runs (`uvToolRunConfig` does the same for a direct caller, even without the table, since the resolver runs in scratch where uv would not find it); uv's path-valued variables (`UV_CONSTRAINT`, `UV_OVERRIDE`, `UV_BUILD_CONSTRAINT`, `UV_FIND_LINKS` — every non-URL entry a path, `constraints.lock` and `wheels` included — and a path-shaped `UV_PYTHON`, which also takes a version or a name) are read against the directory uv runs in too — verified: uvx and `uv pip compile` both honour `UV_CONSTRAINT`, and `--directory sub` reads `sub/c.txt` — so in scratch `UV_CONSTRAINT=requirements.txt` would name the resolver's own input; `uvEnvPathFlags` hands a tool run's resolver each relative entry as the equivalent flag made absolute (one flag per entry, since a flag replaces the whole variable; a flag on the line already does; the entries are split as uv splits them, on whitespace for the requirements-file variables and on commas for `UV_FIND_LINKS`, verified with `--show-settings`: `./w1,./w2` is two find-links entries and `./w1 ./w2` one path with a space in it), and `UV_NO_CACHE` is `--no-cache` from the environment (`uvReadsCache`, `envTrue`: anything but an explicit false), governing the cache and not the installed tool; a relative `UV_CACHE_DIR`, or a relative `cache-dir` in uv's configuration, is read the same way (verified: `uv cache dir` answers `c` from any directory), so `uvCacheDir` reports the path as `moved` and the tool run hands the resolver `--cache-dir <abs>` — uv's own flag, not a uv-only routing — or an offline run would resolve against an empty scratch cache; the cache is found once per run and handed to `withUVCached`, so the probe is one subprocess, and none at all under `--no-cache`/`--refresh` (`uvReadsCache`); `--no-config` reads none, and a named `uv pip install` keeps the table, since it is a pip-interface command that reads it (a named `uv add` does not, and is not corrected: it would need the verb in the resolver's signature). `--reinstall` "implies `--refresh`" (uv's words), so `uvRenames` hands the resolver `--refresh` for it and `--refresh-package` for `--reinstall-package`, both uv-only. A `--with` requirement carrying a marker is installed only where the marker holds, so the cached-environment match does not require it — unless every spelling of that package is conditional; one requested unconditionally too is required (`addTarget` keeps both spellings under one Spec). A cached environment whose metadata cannot be read hides only itself (`UVCachedTree` skips it, and `venvPackages` skips one unreadable dist-info), since the environment uv reuses may be the next one. A tool run's `--with-requirements` files resolve **together** with its packages (`reqFileTokens`: one `-r <abs path>` spec each, a line uv's input reads as it is and pip takes as two arguments), since a release that satisfies each alone may not satisfy both; the files are still scanned on their own as before. uv's `name[extras]@version` shorthand is rewritten for the resolver by `pep508FromAt`, keeping extras and marker (`httpx[cli]@0.28.1` is `httpx[cli]==0.28.1`), since rebuilding it from the Spec dropped the extras and their dependencies. npm's negated cache flags (`--no-offline`, `--no-prefer-offline`) travel with the positive ones, so npm's last-wins reading holds in the dry run. npm reads the `.npmrc` at its local prefix — the nearest ancestor with a `package.json` or `node_modules`, so a run from a project subdirectory gets the project's file, and the **workspace root's** when that ancestor is a member its `package.json` workspaces declare (`stageNpmScratch` stages that directory's file whether or not a project is staged beside it: an earlier revision staged the member's own `.npmrc` with its manifest, so a scoped private registry in the root's file never reached the dry run and the scope resolved against public npm) (`catalog.NpmWorkspaceRoot`, as npm's config loader walks on to the root and ignores the member's `.npmrc` with a warning; verified: `npm prefix` from a member answers the root, `--workspaces=false` stops it, and `mapWorkspaces` reads `package.json` only, so a `pnpm-workspace.yaml` does not count there; the walk reads the filesystem root too, `walkUp`, since npm's does and a loop stopping one short missed a root at `/`) — at `--prefix` when given, and none at all in global mode (verified against npm 11.19.1); `npmConfigDir`/`npmLocalPrefix` decide what `ResolveNpmInstall` stages (`TestNpmConfigDir`); `npmConfigDir` asks `parseNpmArgv` for the mode so npm's last-wins and negation rules hold (`--global --no-global` and `--global=false` are local). `uvGlobalArgs` returns a **copy** of the pre-verb tokens: callers append to it, and an append into `args`'s own backing array overwrote the verb the real uv was about to receive (`uv --no-config tool run --with x ruff` became `uv --no-config --with x --with x ruff`); the uv test asserts `args` is untouched. For a tool run the same comes from npm's own parse: `npmArgv.Config` records every option in `npmRunConfig` that nopt attributes to npm (`--before`, `--tag`, `--omit`, the peer rules, `--global`/`--prefix`/`--location`, and the cache policy — `--offline`/`--prefer-offline` resolve against the cache's metadata, which may be older than the registry's, `--prefer-online` revalidates it, `--cache` names which cache, and `--min-release-age`/`--min-release-age-exclude` pick an older eligible release like `--before`, so all of them reach the dry run; a named install renders the same from npm's own parse (`npmResolveFlags` is `parseNpmArgv(args).resolveFlags()` plus the registry and `--userconfig`), so `--no-no-optional` reaches the dry run as `--optional` and the last of two `--userconfig` values is the one passed, where a filter by flag name dropped the one and kept both of the other; a negated path or url option (`--no-cache`, `--no-prefix`, `--no-globalconfig`, `--no-userconfig`, `--no-registry`) is not recorded at all and clears an earlier value, since nopt's last value wins and it then drops the boolean as invalid for the type, so npm keeps its default (verified: `--cache custom --no-cache` is no cache setting at all), where recording the word rendered `--cache=<cwd>/false` and the dry run built a cache there, and keeping `custom` sent it to a cache the run never reads; a literal `--cache=false` is the path `false`, which npm does use, and is kept, and an array option drops only the invalid entry, so `--omit dev --no-omit` is still `omit=dev`; a relative `npm_config_userconfig`/`_globalconfig` is resolved where npm runs, so `npmEnvConfigFlags` hands the dry run and the probes the file absolutely; the probes (`npm config get omit`, `npm config list -l` for the cache) run in the command's own directory, since a relative `cache=./cache` in an `.npmrc` is resolved against the cwd and not the file's directory (verified: from a subdirectory npm answers `sub/cache`), with `-g`, `--workspaces=false` and `--prefix` as the command had them, `--prefix` naming the configuration directory the command would discover when the line names none (`npmLocationFlags`): named explicitly, npm neither walks for it nor, from a workspace member, fails with ENOWORKSPACES, which every probe from a member did (verified); `workspaces` is recorded for configuration discovery only and never passed, `npmRecordOnly`, since `npm install --workspaces` in a scratch directory fails with "No workspaces found!"), the oracle test holds it to the real npm, and `installArgs.NpmFlags`/`NpmGlobal`/`NpmPrefix` carry it to the dry run — never a flag from the program's argv. uv's global options before the verb (`uvGlobalFlags`: `--config-file`, `--no-config`, `--offline`, `--allow-insecure-host`, `--project`) reach the resolver and count for `needsUV`, as do its cache options wherever they sit (`--cache-dir`, made absolute against the run's directory, `-n`/`--no-cache`, `--refresh`, `--refresh-package`): offline or prefer-cached resolution reads that cache's metadata, which may be older than the registry's, so the dry run must read the same one, and pip has no such cache, so they are uv-only. npm's are read from the whole line (`npmResolveFlags(m, args)`), since `npm --userconfig corp.npmrc install x` puts them before the verb. `--directory` is a directory change and `--project` is not: `uvDir` reads only `--directory`, which is where a named uv install resolves and the base every relative file path is made absolute against (a tool run's `uvx --directory sub -c c.txt` reads `sub/c.txt`) — but not an index location: `--index`, `--default-index`, `--index-url`, `--extra-index-url` and `--find-links`, and the `UV_INDEX`/`UV_DEFAULT_INDEX`/`UV_INDEX_URL`/`UV_EXTRA_INDEX_URL`/`UV_FIND_LINKS` variables, are parsed into absolute paths where the command starts, before `--directory` moves it (verified: `uvx --directory sub --find-links ./wheels` and `--index local=./idx` read beside `sub`), so `pythonIndexFlags` and the `index` entries of `uvEnvPathVars` are anchored there by `absIndexLocation`, a URL left alone and uv's `name=location` keeping its name, for tool runs and named installs alike, since the dry run runs in scratch or `--directory` and would otherwise read `./idx` under a directory the run never looks in and resolve from the registry what the run takes from a local index; `--project` names where a project is discovered, so it is passed on as a flag for a named install and dropped for a tool run (`toolRunNoPass`), which reads no project configuration. A path-shaped `-p/--python` is made absolute, a version or name is not. npm's `--globalconfig` travels like `--userconfig`, made absolute. A short option's value may be attached (`-ihttps://…`, `-cc.txt`, `-p3.12`; clap and argparse both read it), so `splitAttachedShorts` rewrites it into two tokens, from a copy, wherever a Python command is read (`parseInstallArgs`, `parseToolRun`, the resolver flag paths): without it `-cc.txt` read as a boolean and the constraint never reached the dry run. It leaves the value of the option before it as typed and copies everything after `--`: pip's optparse takes the next token as `--config-settings`' value whatever it looks like (verified: `pip install --config-settings -Cfoo=bar requests` installs requests), so splitting that token read `foo=bar` as a package to check; the set it reads is every value-taking option the parser knows (`pythonOptionFlags`: requirements-file, package and source flags too), since `-r -constraints.txt` names a file and `-r` was not in the resolution table. The `=` of `-c=file` goes only where the parser drops it (`clapEquals`): uv reads `file`, pip's optparse the file named `=file` (verified: pip installed the pin from `=c.txt`, uv from `c.txt`), so a dry run stripping it for pip would check another file's pins. npm's lock records every dependency whatever the omit policy, marked `dev`, `optional`, `peer` or `devOptional` (reached both ways); `parseNpmLock` carries the marks into `Resolved`, merging a release found at several paths so a kind survives only if every copy has it (and `Copies` keeps each copy's own kinds, since the AND alone cannot say that a dev-only copy beside an optional-only one is left out entirely under `--omit=dev --omit=optional`; `npmOmitted` judges copy by copy) and the registry only if every copy agrees — copies fetched from different registries record none, so a trusted copy cannot cover a public one (map order must not pick the copy) — and `npmOmit` drops what npm's effective policy leaves out. That policy is npm's own answer: `npmEffectiveOmits` asks `npm config get omit` (`catalog.NpmConfigOmits`) with the dry run's flags and the same `-g`/`--prefix`/`--userconfig` selectors, and npm applies everything itself — the line's `--omit`/`--include` with include winning, nopt's negation and parity (`--no-no-optional` is on), the `optional` boolean (`.npmrc optional=false` answers `optional`), omits set in the environment or any `.npmrc`, and the older spellings `--production`, `--only`, `--dev` and `--also`, which are recorded and rendered so that `--production=false` under `NODE_ENV=production` keeps dev dependencies in the check as npm keeps them in the install (verified against npm 11.19.1: `--production` answers `dev`, and `--production=false` overrides both the variable and an `--omit=dev` on the line). The port's own `omits()` reading was deleted for that reason: the dry run's lockfile cannot say which applied since it records omitted packages too, and npm is the one parser that knows. One subprocess, asked only for a fresh tree with something to prune, and when npm cannot answer nothing is dropped. So a run is not blocked on a package it never installs, and every approximation errs toward checking. A tool-run token is kept as typed (`tool@latest` is not stripped): the tag is what npm fetches whatever `--tag` says, libnpmexec never takes a tag spec from the local tree, and the dry run must see it. **An npx run may execute a tree resolved earlier**: npm keeps each tool run's installation under `<cache>/_npx/<key>` (`key` = the first 16 hex chars of sha512 of the sorted `--package` values, else the command, joined by newline — `catalog.NpxCacheKey`, `TestNpxCachedTreeMatchesARealRun` holds it to a real npx) and reuses it when the package there still satisfies the request, with the dependencies resolved back then. So `withNpxCached` unions the fresh dry run with that cached lock (`catalog.NpxCachedTree`), and an unreadable cache adds nothing. The cache is `--cache`, else `npm_config_cache`, else what npm says with the command's own config-file and location flags (`catalog.NpmConfigGet` with key `cache`, which reads `npm config list -l` rather than `npm config get cache`: the latter refuses a relative path as protected, verified, while the listing prints it resolved against the cwd; a `cache=` in a project, user or global `.npmrc` is where npm reuses from, and the default lookup would miss it), else the platform default when npm cannot be asked. That is one more subprocess per tool run with no `--cache`, next to a dry run costing seconds. It is found once per tool run and handed to `withNpxCached`; and since nopt resolves a relative `npm_config_cache` or `.npmrc` `cache=` against the directory npm runs in, the dry run in scratch is told it absolutely (`npmCacheDir` reports such a path as `moved`; a named install's dry run gets `npmEnvCacheFlag` for the variable), or an offline dry run would face an empty cache. A release both trees report is **one sighting merged conservatively** (`unionSightings`, keyed as the registry compares names — PEP 503 for PyPI, the spelling for npm, where `lodash.get` and `lodash-get` are two packages a PyPI key would fold into one and drop from the check — and `resolveNamed`'s own dedup keys the same way, `canonicalSpec`, so a cached environment's `Django 5.0` and the registry's `django 5.0` are submitted once; `mergeSighting`): a kind survives only when both carry it, the registry only when both agree — a fresh fetch from a trusted registry must not cover a cached copy fetched publicly, and no registry means checked — and the lock covers it only if both say so. Both `npm exec` and the `npx` binary take this path (`m.Bin` is `npx` for the latter, which the first revision missed); bunx has its own cache. The omit policy prunes the **fresh** tree only, before the union: npm reuses a cached installation as it is, so an optional dependency it holds runs under `--omit=optional` too. It prunes npm's and npx's trees only: bun reads none of npm's configuration, so a bunx run installs what an `.npmrc` `omit` would have npm leave out, and pruning it dropped packages that run. The key sorts the specs as libnpmexec does, with node's `localeCompare('en')`, which is not byte order: ICU puts punctuation before digits before letters (`_` before `-`, so `is_js` sorts before `is-odd`) and lowercase before uppercase, and a byte-order key for `--package a_b --package a-b` looked up an entry npm never wrote. `npmCollate` ports that for printable ASCII (primary weights from `npmCollateOrder`, case as a tiebreak) and `TestNpmCollateMatchesNode` holds it to the installed node; `TestNpxCachedTreeMatchesARealRun` finds a real two-package run under it. **uv does the same with tool environments**: `uvx`/`uv tool run` reuse an environment cached under `<cache>/environments-v2/<key>/<key>` (a venv) when it satisfies the request, with the dependencies resolved back then, and `uvx tool@latest` exists because an unpinned request would otherwise never see a newer release. The key is uv's own hash of the request, so `catalog.UVCachedTree` reads every cached environment holding the named packages at the pinned versions (from each dist-info `METADATA` in its site-packages; `lib/pythonX.Y` or `Lib` on Windows; `holdsNames` lists the dist-info directory names first and reads metadata only in an environment that has every wanted name, since a cache holds hundreds of environments and most hold none of them) and `withUVCached` unions them with the fresh resolution, erring toward checking. The cache is `--cache-dir`, else `UV_CACHE_DIR`, else `uv cache dir` (`catalog.UVCacheDir`, one fast subprocess) asked with the run's own `--config-file`/`--no-config` (`uvCacheSelectors`: a `cache-dir` in an explicitly named file is where uvx reuses from, verified) and **from a scratch directory**: uvx reads no project configuration, but `uv cache dir` in a project whose `uv.toml` names a `cache-dir` answers for the project (verified: uvx ignored that file and `uv cache dir` reported it), so asking from the cwd would name a cache the run never touches. Else the platform default, uv's documented one (`uv help cache dir` / `uv help tool dir`): `$XDG_CACHE_HOME/uv` or `~/.cache/uv` on macOS and Linux alike — not `os.UserCacheDir`, which is `~/Library/Caches` on macOS — and `%LOCALAPPDATA%\uv\cache` on Windows; tools under `$XDG_DATA_HOME/uv/tools`, `~/.local/share/uv/tools`, or `%APPDATA%\uv\data\tools`. Every relative path — `--cache-dir c`, a relative `cache-dir` in a config file, which uv resolves against the directory it runs in and not the file's, and so uv's own relative answer — is resolved against `uvDir`'s base, since `uvx --directory sub --cache-dir c` uses `sub/c` (verified). `--no-cache`/`-n`, `--refresh` and `--reinstall` read or rebuild nothing, so they add nothing. A venv records no provenance, so nothing read there is trusted by registry; `TestUVCachedTreeMatchesARealRun` finds a real `uv tool run`'s environment. **An installed tool is run as installed**: for a bare request — the command or `--from` with no version, no `@latest`, no `--with`, no `--isolated` (each verified against uv 0.11 to make uvx resolve instead) — uvx runs the environment `uv tool install` keeps under `uv tool dir` (`<dir>/<name>`, a venv) and resolves nothing, so `parseToolRun` records `installArgs.InstalledTool` and `withUVCached` unions that environment too (`catalog.UVInstalledTree`, the directory from `UV_TOOL_DIR`, else `uv tool dir`, else the platform default), whatever the cache flags say, since those govern the cache and not installed tools. The npx cache is read the same way: its lock records what the earlier run resolved, omitted dependencies included, so `parseNpmLockAt` keeps only entries whose directory exists under the cached install (a run is not blocked on a package it never put on disk), and reads the whole lock only when there is no `node_modules` to check against. A pin is matched as PEP 440 reads `==` (`pep440Equal`: `6.1.0` is `6.1`, `1.0-alpha1` is `1.0a1`, `+build.01` is `+build.1`, a local segment on the candidate is ignored unless the pin names one), and a spelling the specification does not describe is retained rather than skipped; the site-packages glob is relative to the environment (`fs.Glob` over `os.DirFS`), since a bracket in the cache path would otherwise read as a character class and an existing environment would match nothing. An npm lock entry without `resolved` (npm's `omit-lockfile-registry-resolved`) is kept with no registry — `parseNpmLock` drops only the root, `link` entries and local packages outside `node_modules/` — because a package npm installed from a registry it did not name is one to check, not to drop. An npm lock's alias entry (`node_modules/renamed` with `"name": "left-pad"`) is read by its `name`, the registry package; `--prefix`, `--globalconfig` and `--cache` take nopt's path type, so `~/` is expanded (`expandHome`) before they are made absolute. `TestNamedNpmInstall*`/`TestNamedPipInstall*` in `test/smoke` prove it against real tools; unit tests stub `expandFn`.

   Finding the verb is not just `args[0]`: every manager accepts its global options first (`pnpm --filter web add x`, `npm --prefix /tmp install x`, `pip --quiet install x`), and pnpm workspaces always do. `verbIndex` skips leading flags — consuming a value only for flags listed in `globalValueFlags` — and takes the first non-flag token as the verb. It never scans ahead for a verb-shaped token, so `pnpm run add` stays a script run. Getting that table wrong is asymmetric: omitting a value-taking flag just forwards unchecked (fail open, as before), while wrongly listing a *boolean* flag would swallow the verb and hide a real install — so only add flags known to take a value. Note pnpm's `-w` is boolean where npm's `-w` takes a value.

   The post-verb table (`valueFlags`) carries the same asymmetry and it bites harder there: omitting a value-taking flag makes its value read as a package, checking something that isn't being installed (noisy, safe), while wrongly listing a boolean flag swallows the package name and skips its check (silent, unsafe). Keep a table per manager and never alias one to another — `valueFlags["pnpm"] = valueFlags["npm"]` inherited npm's value-taking `-w` into pnpm, where `-w` is boolean `--workspace-root`, so `pnpm add -w <pkg>` installed unchecked (OSS-1577). `TestPnpmBooleanFlagsAreNotValueFlags` now guards both tables.

   **Fetch-and-execute** (`uvx`, `uv tool run`) is checked through its own path, never an install verb list: `Manager.toolRunAt` matches it and `parseToolRun` parses it, because only the first positional is a package and the rest is the program's own argv — `uvx cowsay moo` must check `cowsay`, not `moo` (a real package it could block on). `--from` names the package in the command's place, `--with` adds packages, `pkg@latest` is unpinned. A run with no registry package forwards unchecked rather than falling into the manifest-install scan. The flag asymmetry is two-sided here: an unlisted value flag makes its value read as the command, so the real package goes unchecked — which is why `toolRunValueFlags` is copied from `uv tool run --help` and `TestToolRunValueFlagsMatchUV` diffs it against the installed uv. `uvx` is a forwarder and a default shim of its own, since it is a separate binary.

   **Only an exact pin is a version** (`check.ParseSpec`). Extras and markers are stripped (`evil[x]` checked as `evil`; it used to 404 and install unchecked). npm ranges and dist-tags travel in `Spec.Constraint`, and `registry.Resolve` picks what npm would: latest if it satisfies and is not deprecated, else the highest non-deprecated match, else latest. `npmrange.go` ports node-semver; `TestNpmRangeMatchesNodeSemver` holds it to npm's copy. An npm alias (`x@npm:evil`) is checked as its target. npm's verb is looked up via `npmDeref`, a port of `cmd-list.js` including aliases, typos and abbreviations (`npm isntall x` used to go unchecked); `TestNpmCmdListMatchesNpm` diffs it against the installed npm. Both tables track **npm 11.19.1**, which CI pins with `setup-node` 24 plus `npm install -g npm@11.19.1` on every runner (`ubuntu-latest` moving to the 26.04 image with a newer npm broke them, and the cmd-list test is a strict equality, so no table can satisfy two npm versions); run those tests under the same npm locally, and bump the pin and the tables together. Named packages plus a requirements file (`pip install -r r.txt x`) are submitted with the scan (`scanRequest.Specs`), never checked alone. A requirements-file install scans the files it names (`reqFilesDir`: copied as `requirements.txt`, nested `-r` inlined), not `.`: `.` missed `requirements/prod.txt` (outside the catalogue glob) and let an unrelated `package.json` block a `pip install`. `splitPyPI` rejects anything after the name that is not extras, `@` or a version clause, so `pip install src/pkg` is a path, not PyPI `src`. uv's flag table is shared across subcommands, so a flag is listed only if it takes a value in every one; `TestUVInstallFlagTablesMatchUV` enforces that, and is why `-e/--editable` is absent.

   The npm side (`npx`, `npm exec`/`x`, `bunx`, `bun x`) uses the same `toolRunAt` plus a per-manager `Manager.parseRun` (`internal/forward/jsrun.go`). For npm a flag table was not good enough, because npm's parsing is not table-shaped: `npx-cli.js` rewrites argv (expanding shorthands, inserting `--` before what *it* thinks is the first positional, treating an unknown option as value-taking unless the next token starts with `-`) and then nopt re-parses the result with typed options, abbreviations (`--pack` is `--package`) and combined shorthands (`-gy`). `npx --no-update-notifier cowsay moo` is the case that bites: npx's rewrite reads `cowsay` as the option's value, nopt reads the option as a boolean, and npm runs cowsay — a one-stage reading checks `moo`. So `npxArgv` and `parseNpmArgv` are ports of the two stages, `npm_config.go` is npm's option table copied from `@npmcli/config` definitions, and two tests keep them honest against the installed npm: `TestNpmConfigTableMatchesNpm` diffs the table and `TestNpmParsersMatchNpm` runs the real `npx-cli.js`/`npm-cli.js` with only `lib/cli.js` swapped for a printer of npm's own nopt result. Note `-p` is `--package` to npx but `--parseable` to `npm exec`, and `npm exec` reads options after the command (`npm exec cowsay --package x` fetches `x`). bunx's parser really is simple (only `-p/--package` takes a value, unknown options and `--` are switches, `tsc`/`claude` are fetched as `typescript`/`@anthropic-ai/claude-code` — the token is renamed with the spec, so `tsc@latest` reaches the resolver as `typescript@latest`, and an explicit `--package tool@latest` is kept as typed, so a configured `tag` cannot swap the release), taken from bun's `bunx_command.rs`.

   **A bare command the project already has is not checked** (`installArgs.LocalCommand` + `projectHasBin`): npx and bunx run `node_modules/.bin/<cmd>` instead of fetching, so checking the registry package of that name checks something else and could block a run that installs nothing — `npx tsc` would check the unrelated `tsc` package. The lookup stops at the nearest directory with a `package.json` or `node_modules`, as npm's does; over-reaching would skip checks npm then fetches. A pinned version or `--package` is always checked. A tool run never takes the passive post-install path even when its manager has `Lockfile` (npm), since `npm exec` installs into npm's cache.

   **bun** finds its command by skipping options *without reading values* (in `bun --cwd web add x` its `command::which` takes `web` as the command, not `add`), so it has no `globalValueFlags` entry. Its `valueFlags` leave out `-c/--config` and `--catalog` because their value is optional — listing them would swallow a package name. It has no `Lockfile` because syft cannot read `bun.lock`/`bun.lockb`, so passive bun goes through `passiveAlongside` and a bare `bun install` scan resolves `package.json` via npm; teaching the catalogue `bun.lock` is what would change both.

   **cargo** (`internal/forward/cargo.go`). Verified with cargo 1.99.1 unless
   named; `test/smoke/cargo_smoke_test.go` and `TestCargoFlagTablesMatchCargo`
   hold the code to a real cargo, and `docs/forwarder.md` has what users see.
   Opt-in like git (`shim.optInManagers`, `--cargo`): only Teams and Enterprise
   plans check crates, so a default shim would cost most accounts a round trip
   for an Unsupported answer.

   - **Reading the line.** clap reads a group of shorts as switches up to one
     taking a value, which takes the rest less one `=`, else the next token
     (`-qjF 2` is `-j F`), so `cargoSplitShorts` splits groups. `--bin`,
     `--example` and `--target` take an optional value clap never fills with
     an option (`cargoOptionalValues`), as does `-p` for `add` and `update`,
     which `cargo update --help` hides (`cargoResolveOptional`). An attached
     value is the option's whatever it looks like, so `-p-h` stays one token.
     `cargoPrintsOnly` passes through help and version lines, and `verbIndex`
     skips a `+toolchain` only first.
   - **`install`** builds and runs build scripts at once, so the named crates
     are checked in front, and only those (`errCargoNotResolved`), under the
     name typed, since `cargo install` folds no spelling. A parsed crate never
     meets the archive check (`addCrate`): `tool@1.2.3-beta.zip` is a pin.
     In gating mode each crate is checked at the release cargo takes
     (`registry.CargoInstallReleases`, from the sparse index cargo reads, so a
     host cargo reaches answers it): a range's newest unyanked match, a pin as
     the index spells it with build metadata, and both candidates when only
     an entry newer than cargo's index format `v2` differs. A failed lookup
     refuses the install (exit 2), unlike other forwarders' registry outages;
     passive still resolves the latest release. A
     crate from anywhere but crates.io forwards unchecked (`cargoSourceFlags`,
     `cargoDefaultRegistry`): checking crates.io's crate of that name would
     block an internal tool on a squat, or clear one never installed. Only a
     definite crates.io index counts (`catalog.IsCratesIoIndex`), read as
     cargo reads it: trimmed, `sparse+` in any case, and `\` a separator only
     under a special scheme such as `https`. A `sparse+` URL is parsed twice,
     first as non-special (`sparseFirstParse`: `\` in userinfo is text, so
     `index.crates.io\@host/` is `host`), then without `sparse+` as `https`.
   - **`registry.default` for `install`.** `cargo install` reloads its config
     from `CARGO_HOME` up, never the project's, and the nearest setting wins:
     the last `--config`, `CARGO_REGISTRY_DEFAULT`, then those configs. An
     `include`, or a regular file it cannot read or parse, counts as setting
     it, so gating refuses a line naming no registry (`cargoUnknownDefault`,
     exit 2): forwarding it would install crates.io's crate unseen and
     silently. One that is not a regular file does not: the reload finds a
     one-shot pipe empty and installs from crates.io (`cargo --config
     /dev/stdin`).
     A registry named there or by `--registry` is crates.io when its index,
     read the same way (`registries.<name>.index`,
     `CARGO_REGISTRIES_<NAME>_INDEX`), is (`cargoRegistryIsCratesIo`).
     `[source.crates-io] replace-with`, or a location key on that table
     (`cargoLocationKeys`), read from every config cargo install reads (no
     environment form), keeps the check and prints one warning even when quiet
     (`cargoReplacement`): cargo installs the replacement's copy however the
     line names crates.io. An include, an unreadable config or one that is not
     a regular file (a FIFO may be written twice) warns too, as does any
     `[source]` `replace-with` when `--index` or a registry other than
     `crates-io` reaches crates.io (`cargoNamesCratesIo`), since cargo reads
     such a spelling as its own source, and
     `__CARGO_TEST_CRATES_IO_URL_DO_NOT_USE_THIS`, which cargo 1.99.1 honours.
     A location's value is never printed, since a URL may hold a credential.
   - **Which configs, from where.** At each level cargo reads only the legacy
     `config` when it opens, else `config.toml` (`cargoConfigFile`); the
     catalogue's trust check reads both, since one more config only keeps a
     crate checked. A `--config` value is a file when that path exists where
     cargo runs. `-C` resolves as chdir(2), each link followed before the `..`
     after it (`cargoConfigDir`); a relative `CARGO_HOME` joins cargo's
     physical cwd with `..` cleaned and links kept (`catalog.CargoHome`, shared
     with the catalogue). On Windows both are placed by volume
     (`catalog.JoinIn`): a rooted path on the starting directory's volume, one
     relative to its drive under it. One relative to another drive goes where
     `filepath.Abs` puts it: exact for `-C`, which cargo takes once, from our
     cwd and environment, and for `CARGO_HOME` unless `-C` left the drive it
     names.
   - **Bounded, regular reads.** Locks and configs go through
     `catalog.ReadRegular`: regular by `os.Stat` before the open (opening a
     FIFO releases a blocked writer, opening a device can reset it) and on the
     handle opened `O_NONBLOCK`, read to the bound only, from offset 0 (on
     macOS `/dev/fd/N` shares cargo's offset).
   - **Check first.** In gating mode `update`, `generate-lockfile` and
     `fetch` never change the project before the check (`checkCargoFirst`):
     no unchecked crate may sit where an IDE (rust-analyzer), a watcher
     (cargo-watch, bacon) or CI could build it, so running cargo first and
     undoing a block is out, since that is the window.
   - **The floor.** ossprey's cargo support needs cargo 1.97 or later, the
     first to honour `resolver.lockfile-path`. `cargoBelowFloor` reads `cargo
     -V` before every command ossprey checks or posts: gating refuses below
     it (exit 2), passive forwards the line unchanged and posts nothing.
   - **The redirect.** A user `--config` beats
     `CARGO_RESOLVER_LOCKFILE_PATH`, which beats config files, and the last
     `--config` wins, so ossprey sets both, its `--config` last before any `--`
     (`cargoRedirectArgs`). The project lock is copied to scratch first, or
     cargo resolves from nothing. `CARGO_CACHE_RUSTC_INFO=0` keeps
     `target/.rustc_info.json` out of the project.
   - **Refused before cargo runs.** `update --breaking`, which rewrites
     `Cargo.toml` too, on any `-b` token, even one an option may have taken,
     since a misread costs only a refusal. A `fetch` line `cargo fetch` rejects
     (`cargoFetchUnknown`), since the resolve passes on only what `update`
     takes and the lock would land first. A `resolver.lockfile-path` the run
     may read (`lockfileMoved`: the variable, a `--config`, a config, an
     `include`, or a config ossprey cannot read), since the user's lock would
     be elsewhere and ossprey would check and land the wrong one; decided
     before `cargo metadata` so it never drains a pipe, and only the decoded
     key counts. A `-Zscript` manifest, which cargo locks under
     `$CARGO_HOME/build`. And `add` (not `add --dry-run`), which writes
     `Cargo.toml` before it resolves while only the lock is redirected. Every
     message `checkCargoFirst` returns names the command by its verb alone
     (`cargoVerbOnly` for `add`), since a `--config` value may hold a
     credential.
   - **Workspace and snapshot.** `cargo metadata --no-deps`
     (`readCargoWorkspace`) names the workspace root as cargo spells it, run
     as the command runs (`realCommand`) minus any `--config` naming a file
     (`withoutConfigFiles`), which it would drain. Then the credential, then a
     snapshot of the lock; one that is not a regular file, is over the bound
     or links to nothing refuses.
   - **fetch.** `cargo fetch` downloads before it returns, so `cargo update
     --workspace` resolves instead, locking byte for byte what fetch would and
     downloading no crate (`cargoFetchResolve`, every option but `--target`).
     After landing, the user's fetch runs with `--locked` (`cargoFetchLocked`)
     and the redirect at a scratch copy of the checked bytes
     (`fetchCheckedLock`), since `--locked` alone downloads a lock swapped
     into the project after landing (verified); as a child, so the copy
     outlives cargo and is removed. While a cargo child runs ossprey holds
     SIGINT, SIGTERM and SIGHUP (`holdCargoSignals`), passes one sent to it
     alone on to cargo, removes the scratch, and exits 128 plus the signal
     cargo died by (`exitCodeOf`), since `ExitCode()` is -1 there. One
     already ignored, as SIGHUP under nohup, is left alone for cargo to
     inherit.
     Git dependencies are still checked out under `CARGO_HOME/git` to resolve,
     as plain cargo does; nothing is built. Whether to refuse git sources too,
     whose checkout (`build.rs` included) lands before the check, is open.
   - **Dry runs.** `update --dry-run` writes a whole lock to the redirect when
     there is none, so it runs redirected and nothing is checked or landed.
     `add --dry-run` writes nothing and goes to cargo as typed.
   - **Tripwire, check, land.** After cargo exits the snapshot must still
     match, else what was found is renamed aside unread, any size, to
     `<name>.ossprey-found-<n>` (an editor may have saved it), the snapshot is
     put back even when that rename fails, since an unchecked lock must not
     stay, and the run fails (`cargoTripwire`). The snapshot records the
     lock's link (`cargoLinkOf`) and where its directory led, and only that
     same link is followed when putting back or landing; a new one is moved
     aside or stops the landing, as does a directory relinked since, so
     nothing is written outside the project (the directory is checked just
     before the write, not with it). cargo's own failure returns
     its exit code. A block, a check error or a lock the platform checked
     none of leave the project as it was, errors exiting 2 since 1 means
     malware; trust comes from the configs where cargo runs
     (`CargoConfigDir`). `landCargo` lands nothing if a file changed during
     the check and skips unchanged bytes; `landFile` writes as cargo writes
     `Cargo.toml` and syncs first.
   - **cargo's stderr** goes through `cargoStderr`, which spells the scratch
     lock as the project's and never fails a write: cargo exits 101 without
     locking when its stderr closes. `CARGO_TERM_COLOR=always` is set only
     where cargo's own auto mode would colour (`cargoColours`).
   - **Passive** runs cargo first and posts the lock it leaves, even after a
     failure (`postCargoLock`); a lock that may have moved, or a script's, is
     not posted, with a warning, and a missing workspace leaves cargo's error
     alone.
   - **Not checked.** A `cargo build` with a stale or missing lock resolves on
     the spot, as does an IDE after a hand edit of `Cargo.toml`. `cargo
     install` checks the named crates only. Configs above a linked cwd are
     missed on Windows, where cargo reads them as spelled.

   **Not covered, deliberately (for now):** `pnpm dlx`, `yarn dlx`, and initializers (`npm init <x>`, `npm create`, `bun create`, `yarn create`, which fetch `create-<x>`). Do **not** close `dlx` by adding it to a `verbAt` list (same argv problem: `pnpm dlx cowsay moo` would check `moo`); give it a `toolRunAt`/`parseRun` like npm's. `docs/forwarder.md`'s "What is not checked" section is the user-facing statement of this.

   **Known gap (pnpm 9 and earlier):** `pnpm run` (and `pnpm exec`) install the project's declared dependencies as a side effect when `node_modules` is missing — `npm run` does not. Since `run` is a pass-through, those packages are never checked. Closing it would put a scan in front of every script invocation, so it is an open product decision. Not reproducible on pnpm 10.34.5 (with or without `CI=1`, `verify-deps-before-run` at its default), so pnpm 10 appears to have stopped auto-installing; `TestPnpmRunAutoInstallsUnchecked` skips with a re-check message rather than passing when it can't reproduce.

4. **`shim install|uninstall|status|dir`** (`cmd/ossprey/shim.go` → `internal/shim`) — writes PATH shims so `npm install` routes through `ossprey npm` with no prefix, covering scripts, CI and coding agents that a shell alias never reaches (OSS-1566). Also driven by `install.sh --override-package-managers` / `install.ps1 -OverridePackageManagers`.

5. **`git`** (`internal/gitscan`) — before `git clone`/`git pull` of a **public** GitHub repo, checks the repo itself as `pkg:github/<owner>/<repo>@<sha>` via `check.Run` (ecosystem `github`), not its deps. **Opt-in**: git is in `shim.optInManagers`, not `DefaultManagers()`, so `shim install` only writes it with `--git` or `--managers git`; a flagless re-run re-points an existing git shim, and `shim status` lists git only once shimmed. Why opt-in: it puts a GitHub API round trip in front of every pull. "Public" = unauthenticated `GET /repos/o/r` returns 200 with `private:false`; never send a token, or a private repo would read as checkable. It **fails open** on any GitHub/API error (unlike the package forwarders) because breaking `git pull` in an outage gets the shim ripped out. `pull` resolves remote/ref by running the *real* git (`shim.LookPathReal` + `OSSPREY_SHIM_BYPASS=1`), never PATH `git`, for the same recursion reason as `lookTool`. Value-flag tables carry the forwarder's asymmetry: a boolean wrongly listed swallows the URL and skips the check.

6. **`brew`** (`internal/brewscan`) — checks the GitHub repos a formula and its runtime deps build from, plus each repo's own lockfile deps; behaviour is in `docs/brew.md`. The why: opt-in like git, since it puts a network walk in front of every install. Tags are pinned with `git ls-remote`, not the GitHub API, because a node install walks ~20 repos and the unauthenticated API allows 60 calls/hour. No public check: a homebrew/core source is fetched unauthenticated, so it is public. Repo deps come from the API's `POST /tools/sbom` (`client.RepoSBOM`) because bottles statically link them (crates, Go modules); one client is shared by the workers so a stored login refreshes once. Over-checking is the chosen error: every variation for the OS family, `uses_from_macos` with bounds on macOS. A ref keeps its tag/branch namespace (`source.kind`), since a tag and a branch can share a name.

   **Forwarders are quiet by default.** A forwarder sits in front of every install a developer, script or agent runs, so without `OSSPREY_VERBOSE` a clean install prints exactly one line of ossprey's — the verdict (`ossprey: no malware found in N packages …, forwarding to npm`; git's names the repo), worded by `forward.CleanVerdict`, which counts only what the platform scanned and owns up to a finding below the failing floor — and then the manager's own output. That line was verbose-only once, and was made unconditional because silence could not be told apart from "nothing was checked"; it is printed just before the handoff, since `syscall.Exec` leaves nothing to print after the manager. An unchecked outcome (no components, nothing the platform scanned, `skip-ci`, passive) prints no verdict, because claiming clean there would be false. Beyond that it speaks only for a platform error (main's `error:` line, or a passive `could not post scan` / git `could not look up` / named-install `could not resolve the dependencies` / cargo `crates.io is replaced` warning — fail-open must never also be silent) and for a block, which always gets the full malware report (alert box, `Error: WARNING:` lines, blocked line) — a one-line block was tried and rejected, because that is the outcome a developer must not scroll past. Everything else — why an install went unchecked, scan narration, collected warnings, informational findings, the update notice — is verbose-only. Smoke tests prove a silent check ran through the fake API's submitted purls, not a stderr line. The real manager's output is never touched (it inherits stdio). Three rules: route narration through `note`, never `Fprintf(errOut, ...)`; drain through `flushWarnings`, which **still drains** when quiet, or main's safety-net drain prints the warnings anyway; and draw progress through `progressTo()`, which keeps the self-erasing terminal animation but drops the plain line a pipe or CI log would keep. `gitscan` and `brewscan` follow the same rules. `TestQuietForwarder_*` pins the contract; smoke tests that assert on narration use `runForwardVerbose`.

**The forwarder replaces itself with the manager where nothing follows** (`forward.Handoff`, `syscall.Exec`), so `npm run start` shows as npm in `ps` and to parent-PID checks rather than as `ossprey`. Anything after the exec never runs, including defers: drain warnings and remove temp dirs first (`forwardTo` flushes; the `reqFilesDir` cleanups run before `finish`). A failed `syscall.Exec` falls back to the child-process `Exec`. Passive installs (`passiveAfterInstall`, `passiveAlongside`) must outlive the manager, so they keep the fork and the `ossprey` name; Windows has no exec(2) and does the same. `TestPassThroughReplacesTheProcess` pins it.

### Passive modes and monitor ids

`--passive` submits the scan and returns without polling for a verdict, always exiting 0. It is not new behaviour: `--ci-cache-scan-only` already did exactly this (`submit.Post`, no polling, warn-don't-fail), under a name that reads as "only check the cache" when in fact it runs the full pipeline. The old flag and `OSSPREY_CI_CACHE_SCAN_ONLY` are kept working indefinitely — they are set in pipelines we do not control — but the flag is `Hidden` so there is one name to teach. One behaviour did change: `--passive --report` is now **refused** rather than silently writing nothing, because a consumer reading a stale report from an earlier run cannot tell it apart from this run's.

A **monitor id** (`--monitor`, `OSSPREY_MONITOR_ID`) is a submit-only credential that travels in the URL path: `POST /ingest/<token>/scans`, no auth header at all. It exists so scanning can be rolled out to machines and CI without distributing a secret that could read the customer's data, so the asymmetry is the point and must be preserved:

- `client.mount()` has a third branch for it, and `authenticate()` **returns early** rather than falling through — an empty `x-api-key` header reads as a malformed key, not as no credential.
- `Client.Validate` **refuses** an ingest client (`ErrIngestSubmitOnly`). The ingest mount has no status route; polling it would 404 confusingly.
- `submit.NewSubmitClient` lets a monitor id win outright with no fallback. Quietly sending under a stored login instead would file the scan against the wrong thing and hide a typo in the id.
- The id is validated in `cmd/ossprey/main.go` **before** passive mode's fail-open can swallow it, or a typo becomes a warning on a scan that went nowhere.

**The token format is a security boundary, not a convenience check.** `internal/monitor` is a dependency-free leaf holding the one definition (`^ospi_[0-9a-f]{64}$`, mirroring the service's `ingest/config.py TOKEN_PATTERN`). It is a leaf because `client` needs it for the URL path and `shim` needs it for a generated `/bin/sh` file, and `shim` must not import `client` (see below). Loosening that pattern would let a hostile flag value reach both an interpolated URL and an executable file; `shim.ValidateMode` runs in `Plan`, so `--dry-run` rejects a bad id too, and `TestValidateModeRejectsAHostileMonitorID` pins the shapes.

`shim install --watchdog` / `--monitor <id>` bake `OSSPREY_PASSIVE=1` (plus `OSSPREY_MONITOR_ID`) into the generated script, which previously set no environment at all. The mode round-trips through an `ossprey-mode:` header line next to the existing `ossprey-bin:` one, so `shim status` reports it per manager — per manager, not per directory, because a partial re-install can leave a machine with a mix.

**A passive forwarded install observes the install; it does not predict it.** Passive blocks nothing, so nothing it does belongs in front of the install — and an earlier revision put a whole catalogue there, `npm install --package-lock-only` and uv included, so every passive `npm install` resolved the same tree twice and the user waited for both. `forward.Run` therefore branches on `Manager.Lockfile` before it parses specs at all:

- **npm, pnpm, yarn, poetry, uv** (`Lockfile: true`) go through `passiveAfterInstall` — but only when `writesLocalLockfile` agrees the *invocation* will leave one in `.`. `Manager.Lockfile` is a capability, not a promise: `uv pip install` resolves into an environment, `npm install -g` and `--no-package-lock` write no local lock, and `pnpm --dir ../other add` locks a directory we are not scanning. Routing on the flag alone meant cataloguing `.` after a command that never touched it — reporting an unrelated tree, or nothing, and dropping the package actually installed (CodeRabbit, PR #66). The bias is one-sided: a flag wrongly listed in `noLocalLockfileFlags` costs only a fallback to the slower spec path, a flag missing from it costs the report, so when in doubt list it. `--no-save` is deliberately absent (npm still updates an existing lockfile), and `--prefix .` / `--location=project` / `--package-lock=true` stay on the fast path. `TestWritesLocalLockfile` is the table.
- Where it agrees, the steps are: exec the real manager untouched, then catalogue with `scanRequest.Installed` (which is `catalog.Options.NoExec` — manifests and lockfiles parsed, nothing shelled out to) and `submit.Post`. The lockfile the manager just wrote already names the whole resolved tree, so this costs a parse and a POST, it reads a directory that has stopped moving, and the SBOM describes what was installed rather than what we predicted. Moving this *beside* the install instead (a goroutine) was tried and is worse: it races the manager for the very files it is reading. `TestRun_Passive_NamedPackages_ScanRunsAfterTheInstall` pins the ordering and the two flags.
- **Everything else** — pip (`Lockfile` unset) and any invocation `writesLocalLockfile` rejects — keeps the old spec/manifest logic through `passiveAlongside`, which starts the install first and submits concurrently. `TestPassivePip_DoesNotDelayTheInstall` deadlocks if that order is ever reversed; `TestRun_PassiveGlobalInstall_SubmitsTheNamedPackage` pins that a global install still reports its package.

Two consequences worth keeping: the post-install catalogue falls back to a full declaring scan when it catalogues **nothing** (a failed install, an unsupported layout) rather than reporting a project with no dependencies; and warnings now drain *after* the manager rather than before it, so `passiveAfterInstall`/`passiveAlongside` must drain before returning — `main` leaves via `os.Exit(ee.ExitCode())` on a non-zero install, so a warning not printed by then is lost (`TestPassiveFlushesWarningsBeforeReturning`). Progress is announced only for the residual wait, never in front of the manager's own output.

### Shims (`internal/shim`)

A shim is a generated `/bin/sh` script (`.cmd` on Windows) named after the manager, in `~/.ossprey/shims`, which shell profiles prepend to PATH inside a marked block. Four invariants hold it together:

- **Recursion guard, twice.** The script strips its own directory from PATH before exec'ing, *and* `forward.Exec` resolves via `shim.LookPathReal`, which skips any PATH candidate containing `shim.Marker`. Either alone would do in the normal case; the pair covers symlinked/misspelled PATH entries. Except on the fail-open paths (bypass, missing binary), which exec the manager by name without `LookPathReal`: a `dir/` or symlinked PATH entry made the shim exec itself forever. Those paths also drop PATH entries whose `<entry>/<manager>` carries the marker, and `OSSPREY_SHIM_DEPTH` errors at 8 hand-offs rather than looping. The grep stays off the hot path.
- **Fail open.** Missing ossprey binary or `OSSPREY_SHIM_BYPASS` set → exec the real manager with a warning. A scanner that can break `npm install` gets ripped out.
- **The allowlist lives in `forward`, not the script.** Shims forward everything; `forward.Run`'s `installAt` decides what gets checked, so `npm run`/`poetry run` pass straight through. One allowlist, one language.
- **Only our files.** `Uninstall` deletes only marker-carrying files; profile edits live between `# >>> ossprey shims >>>` markers.
- **Installers fail closed on checksum** (`OSSPREY_SKIP_CHECKSUM=1` is the only way past it) and re-point existing shims on upgrade with `--no-path --managers <installed>`, so an upgrade never shims new managers or edits profiles.

**A profile block only reaches shells that read the profile.** `bash -c` reads none, so an agent's tool shell or a cron job never sees the block unless its parent already had the PATH. That is why `~/.zshenv` (read by every zsh) is a profile, and why `--agent claude` exists: it writes a SessionStart hook into Claude Code's `settings.json` that appends a PATH line to `$CLAUDE_ENV_FILE`, which Claude Code runs before **every** Bash command. The line moves an existing shim entry to the front rather than skipping it, because an inherited PATH can carry the shims behind nvm's or a venv's bin, and the hook appends it only once per env file since it also fires on resume, clear and compact. The hook is found by its `# ossprey-shim-path` marker on a parsed SessionStart command, never a raw substring. A flagless re-run re-points it like the git shim, but `--no-path` leaves it alone (a throwaway `--dir` install must not move the user's global hook). `settings.json` is edited as an ordered object with raw values, so only `hooks.SessionStart` changes and key order and numbers survive, and it is replaced through a temp file and rename because Claude Code writes it too. A file that does not parse is never rewritten, and on a re-point or uninstall that is a warning, not an error. Moving the `.bashrc` block above the distro's `[ -z "$PS1" ] && return` guard was considered and rejected: it does nothing for `bash -c`, and lines below it (bun, nvm) would then prepend their own `bin` ahead of the shims in interactive shells.

`shim` must stay a leaf package (`forward` imports it) — its only first-party dependency is `internal/monitor`, which is itself dependency-free. Do **not** reach for `internal/client` from here to validate a monitor id, which is what `internal/monitor` exists to avoid. `DefaultManagers()` and `forward.Managers()` are kept in agreement by an external test in `internal/shim/forward_agreement_test.go`.

### Trusted sources (`internal/trust`)

A customer's internal packages live on private registries (a CodeArtifact
"internal" PyPI index beside a "public-proxy" one on the **same host**; npm via
`@org:registry=`). They cannot be resolved publicly, so they filled scans with
NOT_FOUND noise and sent internal names off the machine. `trust.Policy` holds
registry URL prefixes and npm scopes; trusted packages are **dropped before the
SBOM is built** (`scan.Run`, after `catalog` marks `Package.Trusted`), so the
submission, `--local` and `-o` agree, and one counted `warn` class
(`scan.TrustedEntry`) says how many were left out. `ossprey trust
list|add|remove` writes `trust.json` beside `credentials.json`;
`OSSPREY_TRUSTED_REGISTRIES` / `OSSPREY_TRUSTED_NPM_SCOPES` add to it.

Every rule is a hole in the scan by design, so the rules are narrow:

- **No name rule for PyPI**, even though a name prefix was the first thing asked for.
  Anyone can publish that name to PyPI, and an internal name resolved from
  the public index (dependency confusion) is exactly what an ignore must never
  hide. npm scopes are the one name rule, because a mapped scope *is* how npm
  picks the registry and it never falls back to the public one.
- **Prefix, never host.** Both CodeArtifact repos share a host; host matching
  would trust the proxy. Paths are `path.Clean`ed after decoding, so
  `/internal/../public-proxy/` (or `%2e%2e`) is judged where it lands.
- **Provenance is what the lockfile recorded** (`registryOf`: npm/yarn
  `resolved`, uv/poetry `Index`, pip `download_info.url`, our npm resolver's
  lock, a `Cargo.lock` `registry+`/`sparse+` `source` via `cargoRegistryOf`).
  Unrecorded means checked. A crate's source is never a git or crates.io one
  (OSS-2581 decides how git crates may count later), nor an index URL that is
  not plain printable ASCII, or that holds a backslash or a percent-escape,
  nor one with an `@` past a `/`, an IP-literal host, or an empty, `.` or
  `..` path segment. The
  first is an allow-list (bytes `!` to `~` bar `\` and `%`, tested before
  anything is trimmed), because each spelling found outside it was another
  place Go and Cargo part: Go's `ToLower` maps `İ` to `i` where Cargo's IDNA
  does not, `TrimSpace` drops a trailing NBSP Cargo keeps as `%C2%A0`,
  `sparse+` is a non-special scheme to Cargo, so `host\@evil` is userinfo to
  it and `internal\outside` one path segment where we read a `/`, and Cargo
  keeps `%2F` inside a segment where `canonicalURL` decodes and cleans
  `public%2F..%2Finternal` to `/internal/` (npm and PyPI still decode).
  Cargo's `..` in `public//../internal` pops only the empty segment, where
  `path.Clean` lands on `/internal/`. A
  symlink anywhere in the scanned tree (outside the directories the scan
  skips) keeps every crate checked (`cargoConfigsInScan`, one pass over syft's
  metadata that the first link ends, about 0.1s at most on 100k files). Links
  are never followed or judged one by one: cargo walks up
  from its physical cwd, so a directory link can lead it into a sink or out of
  the scan, a chain through `/proc/self/cwd` or `/dev/fd` resolves per
  process, and syft cleans a target's `..` before resolving it, so `app ->
  node_modules/../y` past an unindexed `node_modules -> target/a/b` reads as a
  file in the scan while the kernel lands in `target`. Nor does any crate
  count when a config cargo may read (every `.cargo` directory the index
  holds, read on disk, plus those above the root and `CARGO_HOME`, opened by
  name where a directory cannot be listed; manifests above the root play no
  part) sets a `replace-with`, has an `include` (stable since Cargo 1.94), has
  an alias passing `--config` or holding a quote, a backslash or a leading `!`
  (a whitespace split cannot tell what those pass), or cannot be read
  (`clearReplacedCrateRegistries`, one warning; only a regular file is opened,
  since a device or FIFO may never end): cargo then fetches from the
  replacement while the lock still names the trusted index, and a
  repository-controlled lock can carry matching checksums.
  For trust only (`noLinks`), a symlinked config inside `CARGO_HOME`, or a
  symlinked `.cargo` or config above the root, counts as unreadable; the vendor
  filter reads through them as before, since a dotfile manager links
  `~/.cargo/config.toml`. `CARGO_HOME` itself is followed, being the scanning
  user's environment, unless the walk above the root reaches it first as an
  ancestor's `.cargo`. A relative one joins where cargo runs (`CargoConfigDir`
  for a copied lock, else the scan's physical working directory) with `..`
  cleaned and links kept (`CargoHome`), as cargo does, for trust, the
  replacement warning and the vendor filter alike.
  Not checked: a typed `--config`, environment such as `CARGO_HTTP_PROXY` and
  `CARGO_HTTP_CAINFO` (cargo has no environment form for `[source]` keys),
  `[http]` `proxy`/`cainfo`, a config only a build run from inside a sink would
  read, and a `.cargo` inside a scanned directory syft cannot list. The
  crates.io twin of a trusted crate is its own bare component with no recorded
  source, so it stays checked. Trusted needs **every** recorded sighting trusted: dedup and
  `mergeVersionless` (`foldCargoRanges` for a crate) fold sightings' `Registries` together rather than keeping
  the first, since one lockfile fetching it publicly is enough to need a check.
  A crate sighting with no registry, refused or unrecorded, empties the
  merged crate's `Registries`, since its dedup key holds only the origin.
  Don't add pnpm (no URL) or Pipfile.lock (index *name*) without real URLs.
- **Named forwarded installs apply only the scope rule to the names typed**
  (`dropTrusted`, before anything is resolved so nothing private is looked up
  publicly). Inferring the registry from `pip.conf`/`.npmrc` was rejected:
  missing an `extra-index-url` would trust a package pip then fetches
  publicly. The dry run that expands a named install (OSS-2481) changes that
  for what it reports: `resolveNamed` applies both rules to the resolved tree,
  with the registry the resolver recorded for each package (npm's lock
  `resolved`, pip's `download_info.url`; uv records none, so there the
  registry rule cannot match and the package is checked). That is the same
  "provenance is what the resolver recorded" rule as a project scan, not an
  inference from config. A private-only name that the dry run cannot resolve
  fails the whole dry run and falls back to the names, where the old status
  quo still holds — it 404s and is skipped once; a squatted public one gets
  checked. An all-trusted named install must forward directly: an empty spec
  list otherwise reads as a bare install and scans the project.
- **Machine-level only, never from the repo** — a PR could otherwise trust its
  own registry. A bad entry is dropped with a warning (`loadTrust`), which only
  means more is checked; `trust add/remove` refuse to rewrite a file they could
  not fully parse, since writing back what parsed would delete the rest.
- `check` ignores trust: naming a package is asking for it to be checked.

### Core data flow (scan)

`internal/scan` → `internal/catalog` → builds `internal/ossbom.SBOM` →
`.ToMiniBOM()` → `internal/submit` → `internal/client` (POST + poll) →
`sbom.ApplyAPIResponse()` → `scan.MalwareReports()` decides the exit code.

`check` reuses the same `submit`/`client`/`ossbom` path but builds a
one-component-per-spec SBOM instead of cataloging the filesystem. `forward`
reuses `check.Run` after parsing install args.

### Cataloging (`internal/catalog`)

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

A `Cargo.lock` crate from git or a non-crates.io registry is **sent, marked** (`cargoSourceMarks`, OSS-2484) as `vcs_url=git+<url>@<commit>` or `repository_url=<origin>/`, never with userinfo, query, fragment or a registry path, any of which can hold a token; a source Go cannot parse or the API cannot fit falls back to its origin, then its scheme, so a crate Cargo builds is never dropped or sent bare. `isCratesIo` folds at least what Cargo's WHATWG parser and `CanonicalUrl` fold (padding, case, a default port, `./`, escapes, backslashes, `http://`, a trailing `/` or `.git`, each checked for `registry+` with a real `cargo metadata --locked`); `sparse+` spellings fold further than Cargo, which reads them as another source, but one on crates.io's own host. A non-ASCII path stays foreign, tested before `ToLower`, which maps `İ` to `i`; a non-ASCII `registry+` host goes out marked **and** bare, because Cargo's IDNA step maps `ｇithub.com` or a soft hyphen to github.com but `gİthub.com` elsewhere. A marked crate is its own component: never version-resolved, never folded, never absorbing a sighting. The pre-commit hook keys its diff on the mark too, so a crate moved from git to crates.io at the same version reads as new, and it never sends a marked crate, whose bare purl `/malware/check` would match against the crates.io advisory of that name; `-v` counts the ones it leaves out. The hook also writes each unstaged ancestor `Cargo.toml` that declares `[workspace]` into both temp trees (`cargoAncestors`), because a member's `dep = { workspace = true }` takes its pin from that root, and without it every commit touching only a member warned that the root could not be read and dropped the member's inherited crates. The cataloguer reads a member's pool from the nearest ancestor `[workspace]`, while cargo 1.99.1 takes it from the root `package.workspace` names, or from one further up when the nearest root excludes the member, so a pin there under the same alias is looked up in place of cargo's, a range there is skipped like any range, and an alias it does not declare drops with the warning. A pointed root outside the member's parent directories is not written at all; writing it needs a pointer read through symlinks and case as cargo opens it, and a crafted one must not cost the rest of the commit its check. Index paths are named `:0:<path>` (`indexSpec`), since git reads `:0:../x` as stage 0 of a path outside the repo and fails the whole call, and a root whose path holds a newline is resolved by a git of its own before sizing, since `cat-file` reads one name per line. A staged root is diffed on its own pool instead (`workspacePinChanges`): `catalog.CargoWorkspacePins` reads `[workspace.dependencies]` from the index and from HEAD as an inheriting member reads each entry, so path, git and private-registry entries and ranges add nothing, and each exact crates.io pin HEAD lacked goes out attributed to the root. A virtual root emits nothing itself and the members the commit leaves alone are not in the trees, so without it a pin bumped only in the pool reached no lookup. Both reads stop at `CargoManifestLimit`, as the vendor proofs' reads do. An ancestor root is sized with one `git cat-file --batch-check` and read through `blobReader`, and a root git cannot size fails the hook as a staged read does, since dropping its members' inherited pins would go unseen; the pool diff stats a root's tree copies before reading them, so a root over the bound is skipped as an unreadable one is. Writing the members into the trees was tried and dropped: listing them from `workspace.members` missed those Cargo adds on its own (path dependencies under the root, a root whose `[workspace]` is empty), wrote a symlinked member as its link text, and capped the index and HEAD lists apart, so an unchanged crate could read as new. Two accepted over-reports: a pool pin new at the root's path is looked up even when no member inherits it (a changed pin, or every pin of a root that is added, moved or in the first commit), and a crate `[patch.crates-io]` redirects to git also goes out as its `Cargo.toml` declaration, so one unused crates.io crate gets checked; folding it meant guessing which lock owns a manifest, and each guess let a forged or nearby lock hide a declared crates.io dependency.

A versionless crate folds per manifest, and only into a release the `Cargo.lock` at that manifest's workspace root locks (`workspacePool` returns the root, which travels with the manifest's requirements as the range's `cargoRange` metadata to `foldCargoRanges`) and that meets a requirement the manifest declares for it (`registry.CargoSatisfies`, which reads core numbers as the u64 Cargo does and refuses a version Cargo's parser rejects; a requirement it cannot read, such as one past u64, is not met). Folding on the name alone let one member's `=` pin swallow another member's range, a dev-dependency's pin replace the runtime range, and a decoy lock anywhere in the tree set a lockless crate's version, so none of those ranges reached the registry (OSS-2099). Any lock above the manifest is not enough either: a scan-root `Cargo.lock` says nothing about a nested crate with no `[workspace]` over it, and a stale or forged root lock holding only a release outside the range says nothing about what the range builds. The cost is an over-report: any range that no governing `Cargo.lock` locks goes out at its latest release, including one Cargo would unify with an `=` pin elsewhere in the workspace or in the same manifest, and a path dependency outside any workspace whose parent's lock covers it.

**A git `[patch]` or `[replace]` target the root's `Cargo.lock` does not record is read from the manifest** (`cargoGitTargets`, OSS-2099). Cargo honours both tables only in the workspace root, so a member's are skipped (a manifest whose `workspacePool` root is not its own directory; one whose root cannot be found counts as a root, so its targets go out), and a target the lock beside the root records as a package, from the same repository with the same `branch`, `tag` or `rev`, at the manifest's full `rev` when it names one and at a version the target's own requirement accepts (a `[patch]` entry's `version`, or the full version a `[replace]` spec must name, which matches nothing when we cannot read it) (`lockRecords`), adds nothing, since syft reads the same git source from the lock. Cargo matches the selector exactly as written once both sides are read back (`cargoGitRef`: the query form-decoded, the last key winning, `ref` meaning `branch`), so the manifest's selector is spelled as cargo would write it for the lock's version (form-encoded from version 4, as written before) and read back the same way; cargo 1.99 rewrites the lock when the branch, tag or rev changes, from the default branch too, and even to a longer prefix of the locked commit (verified), so each of those targets goes out. It fetches the branch afresh too when that requirement no longer accepts the locked version, and builds the new commit (verified), while a dependency requirement moved past the locked fork leaves the patch unused and builds the crates.io release (verified), which the manifest's own declaration sends. A git URL with a query, two selectors or one that is not a string is never recorded, since cargo 1.99 takes a stale lock as current for a queried URL while it builds the new branch (verified). The lock is read only as a regular file within the caps `withBoundedLocks` applies (`maxLockBytes`, `maxLockDepth`, via `readRegularFile`, on `ReadRegular` like the cargo forwarder's reads) and decoded through `decodeTOML`, so a FIFO or a link to a device named `Cargo.lock` can neither block the scan nor read without end, and a lock the scan hides or this read refuses records nothing. The mere presence of a lock used to hide it, but a lock can predate the patch: cargo 1.99 without `--locked` rewrites such a lock and builds a fork published at the locked version, and records one at another version as unused until `cargo update` (verified), so the target goes out in both cases. An unused patch records nothing, since the lockfile cataloguer sends nothing for it and cargo 1.99 builds the fork at the commit `[[patch.unused]]` holds once a changed requirement reaches its version (verified). The accepted over-report: a member directory scanned on its own has no root above it inside the scan, so it counts as its own root and its git targets are sent, although cargo run from the full checkout ignores them. Each target is carried as a `pkg.RustCargoLockEntry` whose source is spelled as the lock would spell it without the query, `git+<url>` plus `#<rev>` only for a full 40 or 64 hex commit (a short rev is not what a lock records), so `cargoSourceMarks` strips credentials and falls back exactly as it does for a lock. `catalogByGlob` keys its dedup on that source too, or a versionless git target and its versionless crates.io twin collapse into one. A `path` target is the project's own code and is not sent; the crates.io twin stays, as above. Two more behaviours are kept by decision: an exact `Cargo.toml` pin that disagrees with `Cargo.lock` goes out at both versions, since cargo rebuilds to the pin unless run `--locked`, which fails instead, so neither file alone says what builds; and an exact pin keeps its build metadata as written (`=1.0.0+abc`), since the service fetches the `.crate` by that exact string and a crate published with metadata carries it in its file name.

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

**`cargo vendor` crates are hidden by marker, not by name** (`withoutCargoVendor`,
OSS-2561). Every crate it writes holds a `.cargo-checksum.json`, and the vendor
directory's name is configurable, so a `vendor` sink would miss
`third_party/rust` and drop a path dependency kept under `vendor/`. A published
crate ships its own `Cargo.lock` (anyhow 1.0.100's names 59 crates, its dev
tree), which syft's `**/Cargo.lock` glob read as the project's. An exclusion glob
cannot say "a directory holding this file", so the filter wraps the resolver
every cataloger reads instead of the index. A crate at the scan root is exempt,
since that scan asked for it.

**The marker is repository content, so it proves nothing alone.** Review broke
two earlier rules. Hiding every file under a marked directory let a marker
beside a `package-lock.json` hide it, and accepting any lockfile as proof let a
decoy `Cargo.lock` naming a standalone project hide that project's own lock. So
the proof is now what cargo itself would do. The vendoring project is a strict
ancestor whose `Cargo.lock` (beside its `Cargo.toml`) locks the crate's
name@version from a registry with the marker's checksum, has no path entry of
that name@version, and holds a release meeting every normal and build
dependency the crate's manifest turns on, non-optional or enabled by its default
features (so an edited vendored manifest stays visible). The nearest cargo
config for that project replaces `crates-io` with a `directory` source equal to
the crate's parent, and that source is not replaced again. cargo reads config
from where it runs, and an alias or `--manifest-path` reaches any crate from any
directory, so every committed config level in the scan must also resolve
`crates-io` to some directory source.
Under that replacement cargo can take a crates.io dependency only from the
vendor tree, so a hidden manifest cannot pull one from the network. A crate any
manifest or config builds by path is never hidden (`path`, `workspace`,
`members` and `paths` keys, read from every file in the scan, every ancestor of
the scan root and `CARGO_HOME`), nor is one whose manifest has `[workspace]`,
which `cargo publish` strips. References are resolved from both the path a file
was reached by and its real path, through symlinks, with case and Unicode
folded, both backslash readings, and a suffix match for one that leaves the
root; member globs are expanded on disk against a literal base, and a config
counts at the directory cargo reads it from, symlink or not. An alias's `--manifest-path`
counts as a reference. Anything it cannot place (a member glob with `[` or `**`
or outside the root, a `path-bases` `base`, a config `include`, an alias running
`cargo vendor`, which ignores source replacement, or passing `--config`, two
configs or one named in
another case at a level, a file reached through a symlink out of the root, an
unreadable, over-limit or too deeply nested manifest or config) turns the filter
off, a refused `Cargo.lock` only proves nothing, and a hidden file reached
through a symlink stays visible. Out of reach: `--config`, `CARGO_*` environment
overrides and CI steps, which no manifest scan sees, and configs and `path`
dependencies inside package sinks, which the index never holds and which only a
command run from inside a build or install directory would use.
`TestCatalogDoesNotLetACargoMarkerHideOtherFiles`,
`TestCatalogReadsAProjectCrateThatLooksVendored`,
`TestCatalogReadsACrateAProjectAboveTheScanBuilds`,
`TestCatalogHidesNothingWhenAPathCannotBePlaced` and
`TestCatalogRefusesCargoFilesNestedTooDeepForTheFilter` pin one case per guard;
each of the 38 fails with its guard removed.

The pre-commit hook's temp trees hold no marker, so the filter never runs
there; `withoutVendoredLocks` instead drops a staged `Cargo.lock` beside a
marker only when a strict ancestor's staged `Cargo.lock`, beside its own
`Cargo.toml` in a directory with no marker as in `projectLocks`, pins that
crate's name@version at the marker's checksum (`CargoLock.Vendors`, the
filter's own lock check) and the staged `.cargo/config` or `.cargo/config.toml`
at or above that ancestor replaces crates.io with a `directory` source that is
the crate's parent (`CargoVendorSource`: nearest config wins per key, a path is
relative to the directory holding `.cargo`, and no config, an unclear one or a
mismatch skips nothing). `CargoVendorSource` places no directory with `..`
after a named directory, because cargo resolves `..` after following symlinks
and a lexical join can name another directory. A crate whose `Cargo.toml`
declares `[workspace]` is never a vendored copy, as in the filter, since
`cargo publish` strips the table and that crate's own lock is what pins its
range dependencies. Every proof file comes from one
`git ls-files -s` listing and is read by its blob only when its entry is a
regular file: a symlink's blob is its target text, which cargo never reads as
the file. One `git cat-file --batch-check` then sizes every listed blob, and a
blob over the bound its parser enforces (`CargoProofLimit` for a lock or
marker, `CargoManifestLimit` for a manifest or config) proves nothing and is
never read, since the parsers refused it only after the hook had buffered all
of it. Every blob, the staged manifests included, is read through one
`git cat-file --batch` (`blobReader`), since a git per file took 1.1s and
1,509 processes for a commit adding 500 vendored crates on Linux, where
processes start fastest; a blob the batch finds over its limit ends that
process, and a name holding a newline gets a git of its own (`readBlob`,
which also stops git at the bound). That leaves a vendored crate's own lock out of the lookup,
never skips a `Cargo.toml`, and still checks in full a `vendor/` change staged
without its `Cargo.lock`. `ParseCargoLock`, `ParseCargoConfig` and
`CargoPackageID` run `proofTOMLError` before decoding. It refuses a file nested
more than `maxProofNesting` deep outside its strings and comments, with each dot
of a key counted as a level, since the TOML decoder recurses once per level (a
few million overflow the stack) and its memory grows with the square of one
key's parts. It also refuses a line over `maxProofLine` bytes, and six quotes
in a row, where the decoder can close a multi-line string later than the
nesting scan does. Real files reach 7 levels (hyper's
`[[package.metadata.capi.install.include.asset]]`), so the bound is 16.

**Source replacement is warned about, not marked** (`cargoSourceReplaced`,
OSS-2099). A `[source.crates-io] replace-with` in a cargo config leaves
crates.io in `Cargo.lock` while cargo builds whatever the replacement serves (a
mirror, a git repository, a directory), so the scan checks crates.io releases
that may not be the code built. Nothing in the scan records what the replacement
served, so there is nothing to mark, and dropping the crates would only check
less; one warning a scan says so, which is the decision for now. Only `scan.Run`
asks for it (`Options.ReportCargoReplacement`): the pre-commit hook catalogues
temp trees that hold no repository config, so all it could report is the
developer's own `CARGO_HOME` mirror, on every commit, against a hook whose clean
output is nothing. The entry has no `Many`, which `warn.Drain` renders as `One`
however often it is added, so a caller cataloguing twice still prints one
accurate line. It finds
configs in the scan through syft's index of names (`cargoConfigGlobs`:
`**/config`, `**/config.toml`, and `**/.cargo/*` for a config named in another
case, which cargo opens on a case-insensitive filesystem; `isCargoConfig` folds
the directory's case too, so only a config whose `.cargo` directory and file name
are both in another case, such as `.Cargo/Config.toml`, is missed in the scan,
while above it both are read in any case), not with the vendor filter's `**/.*/*`,
which walks every file and added about 40% to a large scan's catalogue time
when it ran for every crate. It files them with the vendor filter's own
`cargoConfigLevels`, and reads `cargoFilesAbove` without manifests and
through symlinks, as the vendor filter does (every ancestor and `CARGO_HOME`); when the filter proved a tree it reuses the levels the proof read (`cargoVendored.levels`), which cover the same configs, all readable. Otherwise configs in the scan are read one at a time, so one
that cannot be parsed does not hide another's replacement. Above the scan only
configs are read, so an ancestor `Cargo.toml` that cannot be parsed hides
nothing, while a config there that cannot be parsed hides the others, as cargo
stops on it too; the vendor filter still reads the manifests and proves
nothing when one fails. It judges the replacement in effect where cargo
would run, at each directory in the scan holding a `Cargo.toml` or a config, so
at the scan root only when it holds one of them
(`cratesIoReplacement`: the nearest level that sets `replace-with`, as
`vendorDir` walks, then `CARGO_HOME`'s, which cargo reads last, else a
location set on `[source.crates-io]` itself, which cargo 1.99.1 also takes
crates.io's crates from), and stays
quiet only where that is a vendor directory the filter proved
(`cargoVendored.vendors`), whose crates the lock pins to crates.io checksums,
though the files cargo checks against `.cargo-checksum.json` are not compared
with the release. Judging each config at its own directory missed a nested
config that redirects the vendored source without restating `replace-with`,
and warned about a `CARGO_HOME` mirror that the project's own vendor config
overrides everywhere in the project; judging a scan root holding neither file
warned about that mirror in a monorepo whose Rust project, in a subdirectory,
builds from a proven vendor tree. A lock copied out of its workspace
(`CargoConfigDir`) is judged where cargo runs, from the configs there and
above and `CARGO_HOME`'s. It runs only when a
crate goes out unmarked, so a scan with no Rust never mentions cargo.

#### Why the npm resolve skips workspace members (OSS-1353)

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

#### Timeouts

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

### Malware alert (`internal/alert`, `internal/ansi`)

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

### Warnings (`internal/warn`)

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

### OSSBOM model (`internal/ossbom`)

`SBOM` is the rich internal model. `MiniBOM` (`minibom.go`) is the compressed
wire format sent to the API — each component becomes `{purl, source, env, location}`
with `purl = pkg:<type>/<name>@<version>`, plus a `vcs_url`/`repository_url`
qualifier for a git or private-registry crate (OSS-2484). The Go model mirrors the Python
`ossbom` library referenced in comments; keep them in sync when the API contract
changes.

### API client (`internal/client`)

`Validate` POSTs the MiniBOM to `/public/v1/scans`, then polls
`/public/v1/scans/status` (capped at `OSSPREY_VERDICT_TIMEOUT`, default
`maxPollAttempts` x `pollInterval` = 15m), and
refuses outright for an ingest client (see "Passive modes and monitor ids"). A
quota-exhausted response surfaces as a typed `*ErrSkipped` that propagates
unwrapped so callers can detect it via `errors.As` and **exit 0** rather than
failing the build (see `reportSkipped` in main.go). Credential resolution order
(`submit.NewClient`): monitor id → `--api-key` flag → stored login →
`OSSPREY_API_KEY` → `API_KEY`. The login beats env keys so a stale exported key
cannot shadow `ossprey login`.

**Transient failures are retried, definite ones are not.** A scan error and a
malware verdict share exit code `1`, so a dropped connection in CI reads as a
detection. `postScan` retries `maxSubmitAttempts` times over `RetryBackoff`, and
the status poll tolerates `maxTransientPolls` consecutive failures within its
existing attempt budget rather than adding sleeps of its own. `retryable` is
deliberately narrow — only 502/503/504. A 4xx is a real answer about the
request, and a 500 means the backend already took the SBOM, so retrying it risks
a duplicate scan against the user's quota for no better odds. Never widen that
set to "any 5xx" for symmetry. The submit endpoint has no idempotency key, so a
retry the backend had already accepted spends a second unit of quota; that is
accepted deliberately, because quota exhaustion fails **open** (`ErrSkipped`,
exit 0) and the failure it prevents fails **closed** and reads as malware. Retries wait via `sleepOrDone` so a cancelled
scan is never held open by a backoff, and `RetryBackoff` is overridable for the
same reason `PollBackoff` is: no test should sleep.

**A poll ceiling is not a scan failure.** It returns `*ErrVerdictTimeout`
naming the scan id and last status, because the scan keeps running and lands
in the dashboard; real scans do exceed 15m at peak (~02:15 UTC). The service's
`ScanExceededClientTimeout` metric counts them, so keep its threshold in step
with the default here. Network timeouts go through `explainTimeout` so a bare
`context deadline exceeded` never reaches the user.

`401`/`403` become `authError`, which names the credential the client actually
used (`--api-key`/env, a stored login, or a monitor id — see
`submit.NewClient`). The raw body is a JSON blob naming no fix, so printing it
told a user with an expired key nothing about how to recover.

`auth.Save` writes through a 0600 temp file and a rename: `os.WriteFile` applies its mode only on create, so an existing 0644 `credentials.json` stayed readable. `ossprey update` compares as semver, never as strings: plain `update`/`--check` only move forward; a downgrade needs `--version` or `--force`.

## Conventions worth knowing

- **Exit codes:** `0` = clean / informational-only / `--local` dump / quota-skipped; `1` = malware found, and nothing else; `2` = scan errored (any error returned to cobra) or panic (recovered in main). Errors used to share `1` with malware, so a network blip in CI read as a detection; keep `1` reserved for a verdict. "Clean" and "skipped" still share `0` — that is what `--report` is for (below). Forwarders still pass the real manager's own exit code through, which may itself be `1`.
- **Severity** (`internal/severity`) grades a finding `Info < Low < Medium < High < Critical`. A finding below the floor is printed as a `Note:` line and the scan still exits 0 (OSS-1432). The floor is **the account's**, served on the scan response as `failing_severity_floor` and decoded in `ossbom.ApplyAPIResponse` (OSS-1994); `FailingFloor` (`Info`) is only the fallback when a response carries none, and it is the bottom of the scale, so nothing passes until an account raises its floor. `--fail-on <level>` on `scan`/`check` overrides it for one run **in either direction** — most specific wins, not strictest, so do not take the minimum of the two. Whichever floor wins drives the exit code and the `--report` split together, so the file cannot disagree with the exit status. The forwarders parse no flags of their own (`DisableFlagParsing`), so they take the account's floor with no override. Parsing is deliberately **fail-closed** — an empty or unrecognised *grade* is `Unknown` and `Unknown` fails at every floor, including a raised one; an unreadable *floor* falls back to `FailingFloor` (`severity.ParseFloor`) rather than failing everything. Those two directions are opposite on purpose. Never invert the grade default for convenience; it is the one thing standing between "we could not grade it" and "we passed it".
- **`--report <file>`** (`internal/scan/report.go`, on `scan` and `check`) writes the machine-readable verdict — `clean` / `malware` / `informational` / `skipped` plus per-finding name, version, ecosystem, severity and description — for CI to act on. `findings` holds only what **fails**, so a consumer counting it to say "N malicious packages" stays correct without knowing what a severity is; anything below the failing floor goes in `informational`, which is omitted when empty; `ossprey/gh-action` renders its PR comment from it. Three rules hold it together. It never touches **stdout**, which `--local` owns for the OSSBOM (the two flags are rejected together, because `--local` returns before any verdict exists). It is written **before** the `os.Exit(1)`, since a malware run is the one CI most needs it on. And `skipped` is its own verdict, not a flavour of clean: a quota-exhausted scan checked nothing, and a consumer that renders it as "no malware found" is lying. `informational` exists for the same reason: that scan *did* find something and said so, so folding it into `clean` would hide a finding we deliberately surfaced. A consumer that only knows the older three should treat it as non-failing. The JSON keys are a contract with the action — `test/smoke/report_smoke_test.go` redeclares the struct so a rename breaks a test instead of the action.
- **Where the CLI stops.** `--report` states the verdict; that is the whole of what the CLI owes CI. Rendering it (Markdown tables, pull-request comments, job summaries, `::error::` annotations) belongs in the consumer — `ossprey/gh-action` does its own, in bash. Do not move that back here, even when a `--report-format markdown` or a `render` subcommand would delete a hundred lines of someone's shell: every such feature is dead weight to the users installing this CLI for `scan`, `check` and the forwarders, and it makes the CLI's release cadence a dependency of one CI vendor's UI. The test for a new flag is whether a GitLab or Jenkins user would reach for it too.
- **Warnings are collected, not printed inline** (`internal/warn`): repeated
  diagnostics arrive as one counted line per cause, before the verdict, on
  stderr. `OSSPREY_VERBOSE=1` (or `scan -v`) lists the individuals and any
  resolver's full output. Never `Fprintf(os.Stderr, ...)` a per-package or
  per-manifest diagnostic directly — that is what OSS-2001 was.
- **The wait is announced** (`internal/progress`): submitting an SBOM and polling for a verdict prints nothing until the verdict arrives, so a healthy multi-second wait reads as a hang. `progress.Scan(w, n)` owns the one sentence every caller uses — `scan`, `check` and the forwarders — so the same wait cannot start describing itself differently depending on where it was started from. Passive waits get `progress.Submit(w, n)` instead, and the split is the point rather than a wording preference: passive posts the SBOM and returns, so a message that said it was *checking* packages would promise a verdict nobody waits for, in front of an install that proceeds regardless. Both `scan --passive` and a passive forwarded install go through it; `TestPassiveInstallDoesNotClaimToCheck` pins that the two never collapse into one message. Three rules hold it up. It draws to **stderr** (`progressOut` in both main.go and `forward`, kept apart from `forward`'s `errOut` so a test capturing verdict lines is not handed the animation), never stdout, which `--local` owns for the OSSBOM and CI greps for the verdict: an indicator that corrupted a machine-readable stream to fix a human-readable one is a bad trade. And it animates **only on a terminal** — `progress.Start` falls back to one plain line into a pipe, a file or a CI log, where a carriage-returned line is noise rather than motion. Nothing is announced for a path that does no waiting: a dry run, or `--local`.
- **API text is untrusted for display** (`internal/apitext`): finding justifications and descriptions are free text from the wire, printed straight to a developer's terminal. `apitext.OneLine` collapses control and formatting characters so a newline cannot forge an extra report line, a carriage return cannot overwrite one, and an ESC cannot start an ANSI sequence. Run any API-supplied string through it before interpolating it into terminal output.
- **Fail-open vs fail-closed:** the `check`/forward path fails *closed* for unpinned packages it can pin (resolves latest via `internal/registry`), but fails *open* (skips with a warning) when the registry is unreachable or a token has no parseable package name — a registry outage must never block development. A gating `cargo install` is the exception: it refuses when crates.io's index cannot say which release cargo takes.
- **Dry-run flags** (`--dry-run-safe`, `--dry-run-malicious`) and `--local` skip the API entirely and need no key — useful for testing catalog output without a live backend.
- **Test seams:** `forward` exposes `execFn`/`checkFn` and `registry` exposes `DefaultHTTP` + base-URL vars so tests run without a real package manager or network. `client.PollBackoff` is overridable for sub-second test polling.
- Test fixtures for every supported ecosystem/manifest combo live under `test/test_packages/` and are driven by the smoke tests.
