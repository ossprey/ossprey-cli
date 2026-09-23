# Supported ecosystems

What Ossprey parses, and what it does when a version cannot be pinned.

Python, JavaScript and Rust, via syft's static catalogers.

| Ecosystem | Files parsed |
|-----------|--------------|
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `setup.py`, `pyproject.toml`, wheel / egg metadata |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Rust | `Cargo.lock` only, there is no support for parsing cargo.toml. |

The CLI never installs your dependencies. It does run a resolver — `npm install
--package-lock-only` (in a temporary directory) or `uv pip compile` — when a
project ships a manifest with no lockfile, purely to work out which versions an
install would pull; nothing is installed and your project is not modified. When
that resolver is missing from PATH or disabled, expect direct deps only —
supply a lockfile for full transitive coverage. Rust is the exception: with no
`Cargo.lock` it catalogues nothing at all, so a crate that gitignores its
lockfile needs one committed to be scanned.

When a dependency's version can't be determined — an unpinned range in a
manifest (`click = "^8"`) with no lockfile or resolver to pin it against — the
scan defaults that component to the **latest published version** from its
registry (PyPI / npm): the version a fresh install would pull today. Registry
lookups fail open, so a component whose version can't be resolved (offline,
private, or removed package) is left unversioned rather than dropped or failing
the scan.

To skip these lookups for a fully offline catalog, pass `--no-version-lookup`
(or set `OSSPREY_RESOLVE_LATEST=0`, which also covers the package-manager
forwarders, whose args are passed through untouched). Unpinned components are
then left versionless.

---

[← Back to the docs index](README.md)
