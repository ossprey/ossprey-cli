# Passive monitoring — see everything, block nothing

Watch what a fleet installs without ever blocking anybody.

Everything above *gates*: a bad package stops the install. That is right for
CI and for your own machine, and wrong for rolling out across a fleet, where
you want visibility first and nobody's work interrupted.

Passive mode submits the scan and gets out of the way. It never waits for a
verdict, never blocks an install, and always exits 0 — even if the submission
itself fails. Results show up in the dashboard.

It also never delays the install. For a manager that writes a lockfile (npm,
pnpm, yarn, poetry, uv) the install runs first, untouched, and Ossprey then
reads the lockfile it wrote — so the SBOM describes what was actually
installed, transitives included, and nothing re-resolves a tree the manager has
just resolved for real. pip writes no lockfile, so there it submits the named
packages alongside the install instead.

There are two ways to run it, and the difference is where the credential lives.

## Watchdog — passive, using this machine's own login

```sh
ossprey shim install --watchdog
```

Every `npm install`, `pip install` and friend on this machine now submits a
scan and proceeds. It uses the same credentials as any other scan, so the
machine needs `ossprey login` or `OSSPREY_API_KEY`.

Good for your own laptop, or any machine that is already authenticated.

## Monitor — passive, with no credential at all

```sh
ossprey shim install --monitor ospi_...
```

A **monitor id** is a submit-only credential. It can create a scan and do
nothing else: it cannot read your results, list your scans, or touch anything
in your account. That is what makes it safe to put somewhere an API key should
never go — a shared CI config, a Dockerfile, a coding agent's settings, a
dotfiles repo.

Create one in the dashboard under **Ingest tokens**, then hand it out. Machines
using it need no login, no API key, and nothing to rotate.

```sh
# In CI, or a Dockerfile, or an agent's config
ossprey shim install --monitor ospi_... --no-path --all
ENV PATH="/root/.ossprey/shims:${PATH}"

# Or a one-off scan, no shims involved
ossprey scan . --monitor ospi_...
```

You can also set it during install:

```sh
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | sh -s -- --monitor ospi_...
```

`ossprey shim status` says which mode each shim is in, so you can tell a
blocking install from a passive one at a glance.

## What passive mode costs you

- **Nothing is blocked.** A passive shim reports malware to the dashboard; it
  does not stop the install. If you want the gate, use the default mode.
- **The report comes after the fact.** The install completes at full speed and
  the scan follows it, so a malicious package has already been installed (and
  its install scripts already run) by the time the dashboard hears about it.
  That is the trade passive mode makes; the default mode is the one that gates.
- **A small tail after the install.** Parsing the lockfile and posting it takes
  a moment after the manager exits — no resolver, no verdict wait. On pip,
  where the submission runs beside the install, there is usually nothing left
  to wait for at all.
- **A monitor id is a capability.** Anyone holding it can submit scans to your
  account, which spends quota. It cannot read anything, but revoke it in the
  dashboard if it leaks — deletion takes effect immediately.

---

[← Back to the docs index](README.md)
