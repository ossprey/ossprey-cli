# PATH shims — drop the `ossprey` prefix

Intercept installs everywhere — scripts, Makefiles, CI and coding agents —
not just in your own interactive shell.

Aliases stop at the interactive shell, as above. Shims cover the rest: a shim is
a real executable, so Makefiles, CI steps and the commands your coding agent
spawns go through it too.

A shim is a small script named after the package manager
in a directory at the **front of your PATH**, so `execvp` finds it wherever the
command is run from — scripts and agents included.

```sh
# During install
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | sh -s -- --override-package-managers

# Or any time afterwards
ossprey shim install
```

Then just use your package manager as normal:

```console
$ npm install left-pad
ossprey: no malware found, forwarding to npm
added 1 package in 412ms
```

| Command | What it does |
|---------|--------------|
| `ossprey shim install` | Write the shims and put their directory first on PATH |
| `ossprey shim install --dry-run` | Show what would be written and changed; write nothing |
| `ossprey shim status` | Which managers are intercepted right now, and what they run |
| `ossprey shim uninstall` | Remove the shims and the PATH entry |
| `ossprey shim dir` | Print the shim directory (for `ENV PATH=…` in a Dockerfile) |
| `ossprey shim install --watchdog` | Passive: submit scans with this machine's login, never block an install |
| `ossprey shim install --monitor <id>` | Passive: submit through a monitor's id, with no credential on the machine |

Useful flags: `--managers npm,pip` to shim a subset, `--all` to shim managers
you have not installed yet, `--no-path` to write the shims but manage PATH
yourself, `--dir` / `$OSSPREY_SHIM_DIR` to relocate them.

**How it behaves**

- **Only installs are checked.** `npm run build`, `poetry run pytest`, `pip
  list` and friends are exec'd straight through. The allowlist is the same one
  the forwarder uses, so there is only one place it can drift.
- **It fails open.** If the ossprey binary goes missing the shim prints a
  warning and runs the real manager anyway. `OSSPREY_SHIM_BYPASS=1 npm install
  …` skips the check for one command, and `ossprey shim uninstall` removes them
  for good.
- **It cannot recurse.** Each shim strips its own directory from PATH before
  exec'ing, and ossprey independently refuses to exec any file carrying the shim
  marker.
- **It only touches its own files.** Shell profiles are edited inside a marked
  block that uninstall removes cleanly, and uninstall deletes only files ossprey
  generated.

Which profiles get the PATH entry: `~/.profile` always; `~/.bashrc`,
`~/.zshrc` and `~/.config/fish/config.fish` if the file exists or that shell is
installed; `~/.bash_profile` and `~/.zprofile` only if they already exist. On
Windows the shims are `.cmd` files and the directory is prepended to your user
PATH.

In a container image, skip the profile edit and set PATH directly:

```dockerfile
RUN ossprey shim install --no-path --all
ENV PATH="/root/.ossprey/shims:${PATH}"
```

> **Note on latency:** a package Ossprey has never seen before takes a scan to
> come back, so the first install of a brand-new version is slower than an
> unprotected one. Subsequent installs hit a cached verdict.

---

[← Back to the docs index](README.md)
