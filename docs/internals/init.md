# `ossprey init`

Why `init` works the way it does. Behaviour for users is in [../init.md](../init.md). [Back to the internals index](README.md).

**`init [path]`** (`cmd/ossprey/init.go`) — the one-command onboarding path
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
