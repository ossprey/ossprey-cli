# Passive monitoring — see everything, block nothing

Watch what a fleet installs without ever blocking anybody.

Everything above *gates*: a bad package stops the install. That is right for
CI and for your own machine, and wrong for rolling out across a fleet, where
you want visibility first and nobody's work interrupted.

Passive mode submits the scan and gets out of the way. It never waits for a
verdict and never blocks an install: a failed submission is a warning, not an
error, and does not change the exit status. `ossprey scan --passive` therefore
always exits 0; a passive *forwarded install* passes the real package manager's
exit code straight through, so `npm install` failing still fails. Results show
up in the dashboard.

It also never delays the install. When the command will leave a lockfile in the
current directory — `npm install`, `pnpm add`, `yarn add`, `poetry add`, `uv
sync` and friends — the install runs first, untouched, and Ossprey then reads
the lockfile it wrote. The SBOM therefore describes what was actually
installed, transitives included, and nothing re-resolves a tree the manager has
just resolved for real.

Where no lockfile lands here, there is nothing to read afterwards, so Ossprey
submits the packages it can name **alongside** the install instead — the
install still starts immediately. That covers:

- `pip` and `pip3`, which write no lockfile at all, and `uv pip install`, which
  resolves into an environment rather than into `uv.lock`;
- `npx`, which fetches into npm's cache and writes no project lockfile;
- global installs (`npm install -g`, `--location=global`);
- installs with the lockfile turned off (`npm install --no-package-lock`,
  `pnpm add --no-lockfile`);
- installs redirected elsewhere (`npm --prefix ./app install`, `pnpm --dir
  ../other add`, `poetry -C ../svc add`). A redirect that points here
  (`--prefix .`) keeps the post-install path.

In that mode only the named packages are covered, not their transitives — the
same scope a gating `ossprey npm install foo` has.

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
  a moment after the manager exits — no resolver, no verdict wait. Where the
  submission runs alongside the install instead, there is usually nothing left
  to wait for at all.
- **A monitor id is a capability.** Anyone holding it can submit scans to your
  account, which spends quota. It cannot read anything, but revoke it in the
  dashboard if it leaks — deletion takes effect immediately.

---

[← Back to the docs index](README.md)
