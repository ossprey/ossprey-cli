# Trusted sources (`internal/trust`)

Behaviour for users is in [../trust.md](../trust.md). [Back to the internals index](README.md).

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
  ancestor's `.cargo`.
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
