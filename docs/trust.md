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
| `--registry <url>` | Packages fetched from that registry or index, npm or PyPI | Where your **lockfile** says each package came from |
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
| no lockfile, resolved by pip | pip's `download_info.url` |

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
  **npm scope** rule only. A package that is not installed yet has no lockfile
  entry, and guessing its source from `pip.conf` or `.npmrc` could trust a
  package that pip then fetches from an extra public index. A private name
  that is missing from the public registry is already skipped with a single
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
