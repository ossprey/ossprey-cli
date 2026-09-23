# Pre-commit hook — block known malware at commit time

Block a commit that adds a known-malicious package, before it reaches CI.

`ossprey precommit` checks the dependencies a commit **adds or version-bumps**
— staged changes to `package.json`, lockfiles, `requirements.txt`,
`pyproject.toml` and friends — against Ossprey's database of already-confirmed
malware. It runs no new scans: parsing the staged diff is local and typically
takes well under 100 ms, plus one small HTTP request (per 100 packages) for
the lookup. A clean
commit prints nothing at all; a commit that touches no dependency manifest
never calls the API.

It needs an API key via `OSSPREY_API_KEY` (or a stored `ossprey login`
session). Without one it warns and lets the commit through.

**Via the [pre-commit framework](https://pre-commit.com)**, in your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ossprey/ossprey-cli
    rev: v0.11.1  # pin the latest release — or run `pre-commit autoupdate`
                  # to resolve it (the hook first shipped in v0.11.0)
    hooks:
      - id: ossprey
```

`id: ossprey` builds the CLI from source, which needs a Go toolchain. If
`ossprey` is already installed on your `PATH`, use `id: ossprey-system`
instead — no Go required.

**Or as a plain git hook**, no framework needed:

```sh
cd your-repo
ossprey precommit install
```

| Command | What it does |
|---------|--------------|
| `ossprey precommit` | Run the check itself (this is what the hook invokes) |
| `ossprey precommit install` | Write `.git/hooks/pre-commit` in the current repo (respects `core.hooksPath`) |
| `ossprey precommit status` | Show whether the hook is installed in this repo |
| `ossprey precommit uninstall` | Remove the hook — only if ossprey wrote it |

Re-running `install` refreshes an existing ossprey hook in place. A
pre-commit hook that ossprey did **not** write is never overwritten or
removed: chain `ossprey precommit` into it yourself, or let the pre-commit
framework manage both.

**How it behaves**

- **It fails open.** No API key, network outage, API error, git trouble — every
  failure mode short of a confirmed malware hit prints a one-line warning and
  lets the commit through (exit `0`). Exit `1` means exactly one thing: a
  staged package is known-malicious. A hook that can break `git commit` gets
  ripped out, so this one can't. The lookup gets a 10s budget (enough to cover
  the API's cold start) and fails open past it — override with
  `OSSPREY_PRECOMMIT_TIMEOUT` (a Go duration like `15s`).
- **Bypass when you must.** `git commit --no-verify` skips the hook for a
  single commit, at your own risk.
- **It only touches its own files.** `uninstall` deletes the hook only when it
  carries the ossprey marker.

## What is not checked

- **Unpinned ranges.** Only pinned versions are looked up. A manifest change
  like `"left-pad": "^1.3.0"` with no lockfile staged alongside it is skipped —
  resolving "latest" at commit time could block you over a version you'll never
  install. Pin the version or commit a lockfile — a lockfile also gives the
  hook the full transitive tree, where a bare manifest yields direct
  dependencies only.
- **Packages already committed.** The hook diffs the staged manifests against
  `HEAD`, so it only sees what this commit introduces. Auditing what's already
  in the tree is `ossprey scan`'s job.

---

[← Back to the docs index](README.md)
