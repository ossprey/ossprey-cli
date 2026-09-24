# CI usage

Running Ossprey in a pipeline: keys, a complete GitHub Actions workflow, and
the two env vars for a staged rollout.

Get a key with [`ossprey init`](init.md) (or from the
dashboard), store it as a secret, and add a scan step. The CLI exits non-zero on
a malware verdict, which fails the build.

## GitHub Actions

Use [`ossprey/gh-action`](https://github.com/ossprey/gh-action). It installs
this CLI, scans, writes a job summary and posts the malicious packages as a
pull-request comment:

```yaml
# Pin to the tag's commit SHA in a real workflow — see the note below.
- uses: ossprey/gh-action@v3
  with:
    api-key: ${{ secrets.OSSPREY_API_KEY }}
```

This step is handed your API key, so pin it to a commit SHA rather than the
`v3` tag: a tag can be repointed at new code after you have reviewed it, which
is the supply-chain risk the job exists to catch.

Or drive the CLI yourself. The minimal step:

```yaml
- name: Ossprey scan
  env:
    OSSPREY_API_KEY: ${{ secrets.OSSPREY_API_KEY }}
  run: ossprey scan .
```

A complete workflow, with the two things that are easy to get wrong called out:

```yaml
name: Ossprey malware scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  ossprey:
    runs-on: ubuntu-latest
    # GitHub withholds repository secrets from pull_request runs that originate
    # in a fork, so OSSPREY_API_KEY would be empty and the scan would fail for a
    # missing key rather than for malware — a red build no contributor can fix.
    # Skip those runs instead. Do NOT "fix" this by switching the trigger to
    # pull_request_target, which grants your secrets to untrusted code.
    if: >-
      github.event_name != 'pull_request' ||
      github.event.pull_request.head.repo.full_name == github.repository
    steps:
      # Pin actions to a commit SHA, not a mutable tag: a tag can be repointed
      # at new code, which is the same supply-chain risk this job exists to catch.
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Install ossprey
        run: |
          mkdir -p "$HOME/.local/bin"
          curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
            | OSSPREY_INSTALL_DIR="$HOME/.local/bin" sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Ossprey scan
        env:
          OSSPREY_API_KEY: ${{ secrets.OSSPREY_API_KEY }}
        run: ossprey scan .
```

For other CI systems the shape is the same: install the CLI, set
`OSSPREY_API_KEY` from your secret store, run `ossprey scan .`.

Inside GitHub Actions or Azure Pipelines the scan also picks up the repository,
organisation and branch from the runner's environment and sends them with the
OSSBOM, so a scan made with a login or an API key groups by repository in the
dashboard instead of minting a fresh asset per run. Nothing to configure; off
CI those variables are unset and nothing is sent.

A submission made with a [monitor id](passive-monitoring.md#monitor--passive-with-no-credential-at-all)
takes a different route (the ingest endpoint) and may be attributed to the
monitor rather than to the repository, so confirm what you see in the dashboard
before relying on repository grouping for a monitor-based rollout.

Two env vars help while rolling Ossprey out across a CI estate, and both work
for `ossprey scan` and the package-manager forwarders/shims alike:

- `OSSPREY_SKIP_CI=1` — kill switch: no scan runs at all.
- `OSSPREY_PASSIVE=1` — observe-only: scans are gathered and submitted so
  results appear in the dashboard, but the build never fails and installs are
  never blocked. See [passive monitoring](passive-monitoring.md).

`ossprey scan` also accepts them as `--skip-ci` / `--passive` flags.
`OSSPREY_CI_CACHE_SCAN_ONLY=1` and `--ci-cache-scan-only` are the original
spelling of `--passive` and keep working unchanged.

---

[← Back to the docs index](README.md)
