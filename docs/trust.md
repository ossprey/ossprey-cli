# Trusted sources — skip your own packages

If you publish internal packages to a private registry, Ossprey cannot look them
up publicly. Scans then fill with "not on the public registry" noise, and the
names of your internal packages are sent with every scan. Tell Ossprey which
sources are yours, and packages from them are **neither checked nor sent**.

```sh
ossprey trust add --npm-scope @my-org
ossprey trust add --registry https://my-org-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/
ossprey trust list
```

There are two kinds of rule:

| Rule | Trusts | Decided from |
| ---- | ------ | ------------ |
| `--registry <url>` | Packages fetched from that registry or index (npm, PyPI or Rust) | Where your **lockfile** says each package came from |
| `--npm-scope @org` | Every `@org/*` npm package | The package name |

## Trusted registries

A registry rule matches on the **full URL prefix**, not the host. That matters
when one host serves several repositories. For example, a CodeArtifact domain
might have an `internal` repository of packages you publish and a
`public-proxy` repository that mirrors PyPI:

```
https://my-org-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/      ← trust this
https://my-org-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/public-proxy/  ← still checked
```

Register the repository's root URL, without the trailing `/simple`. The rule
then covers both the index URL and the file URLs underneath it. Scheme and host
are compared case-insensitively. The path is compared after `..` segments are
resolved, so `/internal/../public-proxy/` does not count as `internal`.

The source of each package is read from the lockfile:

| Lockfile | Field |
| -------- | ----- |
| `package-lock.json` | `resolved` |
| `yarn.lock` | `resolved` |
| `uv.lock` | `source = { registry = … }` |
| `poetry.lock` | `[package.source] url` |
| `Cargo.lock` | `source`, a `registry+` or `sparse+` index URL |
| no lockfile, resolved by pip | pip's `download_info.url` |

A `Cargo.lock` records each crate's index URL, so for Rust register that URL
without its `registry+` or `sparse+` prefix, or any prefix of it. A crate from
crates.io is always checked, even under a rule such as `https://github.com/` or
`https://index.crates.io/` that covers crates.io's index. So is a crate Cargo
fetches from git, whatever rule covers its repository, and a crate whose index
Cargo may read as another one: an index URL that is not plain printable ASCII,
or that holds a backslash or a percent-escape, or that has an IP-literal host
such as `[::1]`, or an empty, `.` or `..` path segment, such as
`public//../internal`. If one
lockfile locks a crate from such an index URL on your registry's host and
another locks the same version from your registry, it is checked.
A crate locked from your registry and the crates.io crate of the same name and
version are different crates to Cargo, so trusting one never hides the other.

Cargo configuration can make Cargo fetch a crate from somewhere other than the
index its lock names. Whenever the scan cannot tell where Cargo will fetch
crates from, every crate is checked and the scan says why in one warning. That
happens when:

- the project holds a symlink. A symlink anywhere in the scanned tree
  (outside the directories the scan skips) keeps every crate checked, even one
  to another file in the project such as a shared `LICENSE`. Cargo reads the
  configs in and above the directory it really runs in, and a link could lead
  it to a config the scan never sees;
- a Cargo config that Cargo may read for the project sets `replace-with` for
  any source, has an `include`, defines an alias that passes `--config` or
  holds a quote, a backslash or a leading `!`, or cannot be read or is not a
  regular file.

The scan reads the configs in the project, in every directory above it and in
`CARGO_HOME`. A relative `CARGO_HOME` counts from where Cargo runs: the scan's
own working directory, or for a lock the forwarder checks, where it runs Cargo,
with `..` taken off the path as written, as Cargo does. For registry trust, a symlinked config inside `CARGO_HOME`, or a
symlinked `.cargo` directory or config above the project, counts as a config
that cannot be read. `CARGO_HOME` itself may be a symlink and is followed,
unless it is also the `.cargo` directory of a directory above the project, as
`~/.cargo` is for a project under your home directory.

These are not checked:

- How Cargo is run, which a repository scan cannot see: its `--config` option
  typed on the command line, and environment variables such as
  `CARGO_HTTP_PROXY` and `CARGO_HTTP_CAINFO`.
- `[http]` `proxy` and `cainfo` settings in a config.
- A config that Cargo reads only when it runs inside a directory the scan
  skips, such as `node_modules` or `target`.
- A `.cargo` directory inside the project that the user running the scan
  cannot list. Git does not record directory permissions, so a checkout alone
  cannot cause this.

**A package whose source was not recorded is checked.** That covers
`pnpm-lock.yaml` (it records no tarball URL), `Pipfile.lock` (it records an
index *name*), bare manifests, and projects resolved through `uv pip compile`.
If a name@version is seen from a trusted registry in one lockfile and from any
other source in another, it is checked, because at least one of those installs
fetches it from somewhere you do not trust.

A name on its own never makes a Python package trusted. Anyone can publish
`my-org-anything` to PyPI. The case this feature must never hide is dependency
confusion, where an internal name gets resolved from the public index.

## Trusted npm scopes

`--npm-scope @org` trusts every `@org/*` package by name, whatever registry it
came from. Use it when either of these is true:

- your `.npmrc` maps the scope to your private registry (`@org:registry=https://…`).
  npm then fetches every `@org/*` package from there, and never falls back to
  the public registry;
- your organisation owns the `@org` scope on npmjs.com.

If neither is true, use a registry rule instead.

## Package-manager forwarders and shims

Trust applies on every path, including [`ossprey npm install`](forwarder.md)
and the [PATH shims](shims.md), in both blocking and
[passive](passive-monitoring.md) mode:

- **Bare installs** (`npm install`, `npm ci`, `uv sync`, `poetry install`) and
  passive installs scan the project's lockfile, so both rules apply.
- **Named installs** (`npm install @org/web`, `pip install my-lib`) apply the
  **npm scope** rule to the packages typed, and both rules to the tree the
  [forwarder's dry run](forwarder.md) resolves, using the registry that dry
  run recorded for each package (npm's lockfile and pip's report record one;
  uv does not, so a uv-resolved package is always checked). Nothing is guessed
  from `pip.conf` or `.npmrc`: guessing could trust a package that pip then
  fetches from an extra public index. A private name that the dry run cannot
  resolve falls back to the names typed, where it is skipped with a single
  warning. A name that *does* exist publicly is checked, which is the result
  you want.

## What you see

A trusted package is left out of the SBOM entirely, so `--local` and `-o` show
exactly what was sent. The scan still says what it left out, on stderr:

```
ossprey: 142 packages are from trusted sources; not checked or sent (OSSPREY_VERBOSE=1 lists them)
```

The [pre-commit hook](precommit.md) leaves trusted packages out of its lookup,
and reports the count only with `-v`. `ossprey check` ignores trust: when you
name a package, it is checked.

## Where trust is stored

`ossprey trust` writes `trust.json` beside your login, in the user config
directory (`OSSPREY_CONFIG_DIR` overrides it). For CI, or any machine where
writing a file is awkward, set the equivalent environment variables. They take
a comma- or space-separated list and add to the file:

| Variable | Adds |
| -------- | ---- |
| `OSSPREY_TRUSTED_REGISTRIES` | Registry URL prefixes |
| `OSSPREY_TRUSTED_NPM_SCOPES` | npm scopes |

Trust is **never read from the repository being scanned**. If it were, a pull
request could add its own registry to the list and exempt its own dependencies.

If an entry fails validation (a typo, a URL containing credentials), it is
ignored with a warning, and its packages are checked. `trust add` and
`trust remove` refuse to rewrite a file they cannot fully read, so a
hand-edited file never silently loses entries.

## Only trust what you publish

Trust a repository only if it contains nothing but packages you publish. A
CodeArtifact, Artifactory or Nexus repository with an **upstream connection to
a public registry** serves public packages under its own URL. Trusting it
trusts every package it proxies, malware included.

## Commands

| Command | Does |
| ------- | ---- |
| `ossprey trust list` | Show trusted registries and scopes, and which came from the environment |
| `ossprey trust add --registry <url> --npm-scope <@org>` | Add entries (both flags repeatable) |
| `ossprey trust remove --registry <url> --npm-scope <@org>` | Remove entries from `trust.json` |

---

[← Back to the docs index](README.md)
