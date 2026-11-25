# Scan settings

`ossprey config` stores scan settings on your machine, so they apply to every
`ossprey scan` and every [forwarded install](forwarder.md) without being
typed or exported each time.

```sh
ossprey config set scan.depth 1            # read one directory level
ossprey config add scan.ignore wf          # never read the top-level wf/ directory
ossprey config add scan.ignore '**/fixtures' 'docs/**/*.md'
ossprey config list                        # what is set, and where it comes from
ossprey config remove scan.ignore wf
ossprey config unset scan.depth            # back to the default
```

## Settings

| Key | Kind | Meaning |
| --- | ---- | ------- |
| `scan.depth` | number | How many directory levels a project scan reads. `1` is the scanned directory's own files, `2` adds its immediate subdirectories, `0` is the whole tree. |
| `scan.ignore` | list | Paths left out of every project scan. |

### `scan.depth`

Unset, `ossprey scan` reads the whole tree, and a forwarded install picks its
own depth: the directory it runs in, or the whole tree when the install
reaches below it (see [what is checked](forwarder.md#what-is-checked)). Once
set, the value replaces that choice everywhere, including in a workspace root,
where a depth of `1` leaves out members' dependencies that are not in the root
lockfile. `0` is a setting of its own, the whole tree, and is not the same as
unset.

A requirements-file install (`pip install -r requirements.txt`) ignores it and
always reads every file it names.

### `scan.ignore`

Each pattern is a glob relative to the directory being scanned, with `/` as
the separator:

| Pattern | Leaves out |
| ------- | ---------- |
| `wf` | the top-level `wf` directory, and everything in it |
| `wf/generated` | `wf/generated` only |
| `**/fixtures` | every `fixtures` directory, at any depth |
| `*.md` | Markdown files in the scanned directory itself, not below it |
| `**/*.md` | Markdown files at any depth |

A pattern is anchored at the scanned directory, so it means the same thing on
every machine; start it with `**/` to match at any depth. A directory that
matches is skipped whole and never walked, which is what makes a pattern
faster than a scan that reads the files and discards them.

A pattern is refused when it is absolute, climbs out with `..`, uses a
backslash, or is made only of wildcards (`*`, `**`, `**/*`): that last would
skip the whole project, and every scan would come back clean having checked
nothing.

A scan that skips paths says so in one warning line naming the patterns
(shown on a forwarded install only with `OSSPREY_VERBOSE=1`, like its other
warnings). Patterns apply to `ossprey scan`, `ossprey init`'s scan and
forwarded installs. They do not apply to a requirements-file install, where
a pattern such as `**/requirements*.txt` would hide every file it names, or
to the [pre-commit hook](precommit.md), which reads only staged files.

Ignored paths also count as part of the tree the scan cannot see for
[trusted sources](trust.md): a Cargo config under an ignored directory could
replace a trusted registry, so crates are not trusted by registry in a scan
that ignores anything.

## Where settings come from

From strongest to weakest:

1. A flag on `ossprey scan`: `--depth`, and `--ignore <pattern>`
   (repeatable), whose patterns are added to the configured ones.
2. The environment: `OSSPREY_SCAN_DEPTH` replaces the stored depth, and
   `OSSPREY_SCAN_IGNORE` adds patterns, separated by commas or newlines (so a
   pattern may contain a space).
3. `config.json`, written by `ossprey config`, beside your login in
   `$OSSPREY_CONFIG_DIR` or your user config directory (`~/.config/ossprey`
   on Linux, `~/Library/Application Support/ossprey` on macOS,
   `%AppData%\ossprey` on Windows).

The forwarders parse no flags of their own, so for them it is the environment
and then the file.

## Never from the repository

Settings are read from your machine and your environment only, never from a
file in the repository being scanned. An ignore pattern is a hole in the
scan: a repository file could add `ignore: [evil]` in the same pull request
that adds a malicious manifest under `evil/`, and a CI scan of that pull
request would skip it. [Trusted sources](trust.md) are machine-level for the
same reason. In CI, set `OSSPREY_SCAN_IGNORE` or `OSSPREY_SCAN_DEPTH` in the
workflow.

## When a setting cannot be read

A value that does not validate, in the file or the environment, is reported in
one warning and not applied; the rest still apply. That only ever means more
is read: a dropped pattern is scanned, and a dropped depth falls back to the
default. A setting never stops a scan or an install.

`ossprey config set`, `add`, `remove` and `unset` refuse to change a
`config.json` they cannot fully read (invalid JSON, or a key they do not
know, such as one written by a newer ossprey), since writing back only what
they understood would delete the rest. Fix or remove the file first.
