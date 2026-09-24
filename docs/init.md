# `init` — one-command setup

`ossprey init` in full: what each step does, every flag, and how to get the
API key it creates somewhere useful.

```
ossprey init [path] [flags]
```

`ossprey init` gets you from a fresh install to a working, CI-ready setup in one
command. `path` defaults to the current directory. It runs three steps:

1. **Log in.** Reuses a stored login if there is one (refreshing it silently),
   otherwise runs the same browser device flow as `ossprey login`.
2. **Create an API key** and print it once. Keys default to a one-year expiry.
3. **Optionally scan the project using that key**, reporting the verdict exactly
   as `ossprey scan` would.

Step 3 **asks first**. Answer up front with `--scan` or `--no-scan`; when there's
no interactive terminal (CI, or output piped somewhere) it's skipped unless you
pass `--scan`, so `init` never does unrequested work in a script.

The scan deliberately authenticates with the key from step 2 rather than with your
login, so **a clean scan is proof the key works** before you paste it into CI.
`init` writes no files and makes no assumptions about which CI you use — see
[CI usage](ci.md) for the snippet to add.

```sh
$ ossprey init
[1/3] Checking login...
Already logged in as you@example.com.
[2/3] Creating an API key...
Created API key "ci-3f9a1c02" (expires 2027-08-14T09:15:00Z).
This is the only time it is shown — it cannot be retrieved later:

    ospy_...

Set it as OSSPREY_API_KEY wherever your scans run. For GitHub Actions:
    gh secret set OSSPREY_API_KEY   # paste the key when prompted

Treat it like a password. It stays in your terminal scrollback, so clear it
when you're done, and don't pipe this command's output to a file or CI log.
Lost it? Create another with `ossprey init`, and delete the unused one at
https://dashboard.ossprey.com — where you can also revoke this one.

Run an example scan of this project now to check the key works? [Y/n] y
[3/3] Scanning with your new API key...
No malware found. See your scans at https://dashboard.ossprey.com

Next steps:
    Add `ossprey scan .` to your CI, with OSSPREY_API_KEY set to this key.
    ossprey shim install         # check every npm/pip install on this machine
    ossprey precommit install    # block commits that add known-malicious packages
```

## Common invocations

**Getting started**

```sh
ossprey init                     # log in, create a key, ask about scanning
ossprey init ./some/project      # same, against another directory
```

**Controlling the scan**

```sh
ossprey init --scan              # scan, don't ask
ossprey init --no-scan           # skip the scan, just get a key
```

In CI — or any time output is piped — the scan is skipped automatically, because
there is nobody to ask. Pass `--scan` if you want it anyway.

**Controlling the key**

```sh
ossprey init --no-key                    # don't create one; scan with your login
ossprey init --key-name my-ci-key        # name it yourself
ossprey init --key-expiry 720h           # 30 days instead of the default year
```

**Piping the key straight into a secret store**

```sh
# GitHub — gh reads the secret value from stdin
ossprey init --key-stdout | gh secret set OSSPREY_API_KEY

# Into a shell variable (progress output goes to stderr, so discard it)
KEY=$(ossprey init --key-stdout 2>/dev/null)
```

`--key-stdout` ends the key with a newline. `gh` strips it, but not every tool
does — if yours doesn't, use command substitution, which strips it for you:

```sh
some-tool set-secret OSSPREY_API_KEY "$(ossprey init --key-stdout 2>/dev/null)"
```

**Just authenticate**

```sh
ossprey init --no-key --no-scan   # login only — same as `ossprey login`
```

**Targeting a non-production tenant**

```sh
ossprey init \
  --url https://api.qa.ossprey.com \
  --auth0-domain auth.qa.ossprey.com \
  --audience https://api.qa.ossprey.com \
  --client-id <qa-app-client-id>

# or via env vars
OSSPREY_AUTH0_DOMAIN=auth.qa.ossprey.com ossprey init

# keep the login out of your real config dir
OSSPREY_CONFIG_DIR=/tmp/ossprey-creds ossprey init
```

**`init` always needs a login.** There is no offline mode: creating a key and
scanning both require credentials, so even `--no-key --no-scan` opens the browser
if you aren't already logged in.

## Getting the key somewhere useful

**The key is shown once and cannot be recovered** — the API stores only an
HMAC hash of it, so neither the dashboard nor the CLI can show it again. If you
lose it, create another and delete the old one.

For scripted setup, `--key-stdout` prints only the key on stdout (all progress
output goes to stderr), so you can pipe it straight into a secret store without
it ever touching your scrollback or disk:

```sh
ossprey init --key-stdout | gh secret set OSSPREY_API_KEY
```

**Re-running creates another key.** Keys are shown only once, so the usual reason
to re-run is that you didn't save the last one — that's the intended path. But
your account is capped at 10 keys, so if you re-run often, pass `--no-key` or
delete the unused keys in the dashboard. If key creation fails for any reason,
`init` warns and still runs the scan (falling back to your login).

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--key-name <name>` | generated (`ci-<random>`) | Name for the created API key (max 20 chars, no whitespace). |
| `--key-expiry <dur>` | `8760h` (1 year) | Lifetime of the created key. The API caps this at 2 years. |
| `--no-key` | off | Don't create a key. The scan then uses your login. |
| `--scan` | ask | Run the example scan without asking. |
| `--no-scan` | ask | Skip the example scan without asking. |
| `--key-stdout` | off | Print only the key on stdout, for piping. Implies no scan. |
| `--url <url>` | `https://api.ossprey.com` | Ossprey API URL. |
| `--auth0-domain <host>` | `auth.ossprey.com` | Auth0 domain (or `OSSPREY_AUTH0_DOMAIN`). |
| `--client-id <id>` | production app | Auth0 client ID (or `OSSPREY_AUTH0_CLIENT_ID`). |
| `--audience <url>` | `https://api.ossprey.com` | Auth0 API audience (or `OSSPREY_AUTH0_AUDIENCE`). |

These three combinations are rejected rather than silently resolved:

| Combination | Why |
|-------------|-----|
| `--scan --no-scan` | Contradictory. |
| `--scan --key-stdout` | A scan verdict on stdout would corrupt the pipe. |
| `--no-key --key-stdout` | No key means nothing to print. |

A stored login is only reused when its domain, client ID and audience all match
the ones this run targets. Point any of those three at a different tenant and
`init` logs in again rather than sending the wrong token to the wrong API.

Creating an API key requires a browser login — API keys cannot mint other API
keys — so step 2 always authenticates via Auth0, never via `OSSPREY_API_KEY`.

`init` does not install the [pre-commit
hook](precommit.md) or [PATH
shims](shims.md), because both change how your
machine behaves outside this project. It prints the commands at the end.

---

[← Back to the docs index](README.md)
