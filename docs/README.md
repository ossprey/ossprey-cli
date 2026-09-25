# Ossprey CLI documentation

The [main README](../README.md) is the five-minute version. These pages are the
detail behind it.

## Getting set up

- [Install](install.md) — every install method, on every platform, plus `ossprey update`
- [`ossprey init`](init.md) — one-command setup: log in, create an API key, scan with it
- [CLI reference](cli-reference.md) — every command and flag, and how credentials are resolved

## Checking installs

- [Package-manager forwarder](forwarder.md) — `ossprey npm install …`: what is checked, what is not, and shell aliases
- [PATH shims](shims.md) — intercept installs in scripts, Makefiles, CI and coding agents too
- [Passive monitoring](passive-monitoring.md) — watchdog and monitor modes: see everything, block nothing
- [Git wrapper](git.md) — opt-in: check a public GitHub repo before `git clone` / `git pull`
- [Pre-commit hook](precommit.md) — block commits that add known-malicious packages

## Running it for real

- [CI usage](ci.md) — API keys, a complete GitHub Actions workflow, and rollout switches
- [Output](output.md) — the alert box, warnings, and the `--report` JSON verdict
- [Supported ecosystems](ecosystems.md) — what is parsed, and what happens to unpinned versions

## Under the hood

- [How it works — diagrams](architecture.md) — the scan pipeline, the forwarder's decisions, and passive timing
