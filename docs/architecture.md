# How it works — diagrams

What happens between your command and a verdict.

## The scan pipeline

Whenever Ossprey checks something — `ossprey scan`, `ossprey check`, or a
forwarded install — it ends up here: a list of packages, compressed to a wire
format, submitted to the Ossprey API. Only a *gating* run polls for the
verdict; passive runs stop at the submission, and commands the forwarder does
not recognise (or that `OSSPREY_SKIP_CI` disables) never enter this pipeline at
all.

Nothing here installs anything. The one exception is the resolver step marked
below, which runs only when a manifest ships without a lockfile.

```mermaid
flowchart LR
    subgraph sources["Where the packages come from"]
        A["scan &lt;path&gt;<br/>catalog the project"]
        B["check -e npm &lt;pkg&gt;<br/>packages named on the CLI"]
        C["npm install &lt;pkg&gt;<br/>forwarder"]
    end

    A --> D["internal/catalog<br/>lockfiles + manifests"]
    D -. "no lockfile" .-> E["uv / npm resolvers<br/>resolve ranges to versions"]
    E --> R
    D --> R["Cargo source + config check<br/>(internal/catalog, crates only)"]
    R --> T{"trusted source?<br/>(internal/trust)"}
    T -- "yes" --> X["dropped: not checked, not sent"]
    T -- "no" --> F["OSSBOM"]
    B --> F
    C --> F
    F --> G["MiniBOM<br/>purl + source + env + location"]
    G --> H["POST /scans"]
    H --> I["poll for a verdict<br/>(gating mode only)"]
    I --> J{"malware?"}
    J -- "yes" --> K["banner + exit 1"]
    J -- "no" --> L["exit 0"]
    J -- "quota exhausted" --> M["skipped, exit 0"]
```

## A forwarded install

The forwarder decides what to check from the command line alone. Everything it
does not recognise is forwarded untouched — the failure mode is always "the
install still works".

```mermaid
flowchart TD
    S["ossprey npm install ..."] --> CA{"cargo add, update,<br/>generate-lockfile or fetch,<br/>not only printing help?"}
    CA -- "yes" --> CV{"OSSPREY_SKIP_CI?"}
    CV -- "set" --> U
    CV -- "unset" --> CP{"passive mode?"}
    CP -- "yes" --> CB["exec cargo first"]
    CB --> AE
    CP -- "no: gating" --> CVG{"cargo 1.97 or later?"}
    CVG -- "no" --> CX["refuse, exit 2:<br/>cargo never runs"]
    CVG -- "yes: add --dry-run" --> U
    CVG -- "yes: add" --> CX
    CVG -- "yes" --> CG{"a line cargo takes (no update<br/>--breaking), a workspace cargo<br/>metadata can read, no lock<br/>lockfile-path may move, no script,<br/>a credential (bar update --dry-run)?"}
    CG -- "no" --> CX
    CG -- "yes" --> CR["cargo resolves into a scratch<br/>Cargo.lock; the project<br/>is not touched"]
    CR -- "a project file changed<br/>while cargo ran" --> CT["move what was found aside,<br/>put it back, exit 2"]
    CR -- "cargo fails" --> CF["cargo's exit code,<br/>nothing written"]
    CR -- "update --dry-run" --> CF
    CR -- "cargo succeeds" --> CC{"malware in the<br/>resolved lock?"}
    CC -- "yes" --> CD["block, exit 1:<br/>the project is unchanged"]
    CC -- "no verdict" --> CN["exit 2:<br/>the project is unchanged"]
    CC -- "no" --> CL{"project files as<br/>cargo started from?"}
    CL -- "no: changed during<br/>the check" --> CN
    CL -- "yes" --> CE["write Cargo.lock; fetch then<br/>runs --locked on a copy<br/>of the checked lock"]
    CA -- "no" --> T{"an install verb, or a<br/>tool run (npx, bunx, uvx)?"}
    T -- "no, e.g. npm run" --> U["exec the real manager"]
    T -- "yes" --> V{"OSSPREY_SKIP_CI?"}
    V -- "set" --> U
    V -- "unset" --> L{"a tool run of the<br/>project's own binary?"}
    L -- "yes: npx eslint" --> U
    L -- "no" --> W{"passive mode?"}

    W -- "no: gating" --> X{"packages named?"}
    X -- "yes" --> E["dry-run the resolver:<br/>what would this install add?"]
    E -- "resolved" --> R{"a requirements<br/>file too?"}
    E -- "failed: warn, fall back<br/>to the names alone" --> R
    R -- "no" --> Y["check those packages"]
    R -- "yes: pip install -r f pkg" --> RZ["scan the project manifest<br/>plus the named packages"]
    X -- "no: bare install" --> Z["scan the project manifest"]
    Y --> AA{"malware?"}
    RZ --> AA
    Z --> AA
    AA -- "yes" --> AB["block: exit 1,<br/>manager never runs"]
    AA -- "no" --> U

    W -- "yes" --> AC{"will it leave a lockfile<br/>in this directory?"}
    AC -- "yes: npm install,<br/>poetry add, uv sync, ..." --> AD["exec the real manager first"]
    AD --> AE["catalog the lockfile it wrote"]
    AE --> AF["post the scan, never block"]
    AC -- "no: pip, uv pip, bun,<br/>uv tool install, npx,<br/>-g, --prefix ../x" --> AG["exec the real manager<br/>and submit the named<br/>packages alongside it"]
    AG --> AF
```

A named gating install does not check only what was typed. `npm install
express` installs 65 packages, so before the check the manager's own kind of
resolver is asked what the install would add, without installing anything —
`npm install --package-lock-only --ignore-scripts` in a throwaway copy of the
project for the npm-side managers, `uv pip compile --no-build` or `pip install
--dry-run --only-binary=:all:` for the Python ones — and the whole tree is
checked at once (`internal/catalog/install_resolve.go`, driven from
`internal/forward/expand.go`). When that dry run cannot be had, the named
packages are checked alone and one warning line says so; the install is never
blocked for want of a prediction.

`cargo update`, `generate-lockfile` and `fetch` are checked by running cargo
against a scratch copy of the lock: `resolver.lockfile-path` sends the lock
there, and only a clean result is written to the project
(`internal/forward/cargo.go`). `cargo fetch` is resolved with `cargo update
--workspace`, which downloads no crate (cargo still checks out git
dependencies to resolve them), and once the lock is written it runs with
`--locked` against a scratch copy of the checked lock. `cargo add` edits
`Cargo.toml` as well as the lock, so it is refused in gating mode until it can
be checked the same way. In passive mode cargo runs first and the lock is
posted. A gating `cargo install` checks each crate at the release crates.io's
index says cargo takes, and is refused with exit 2 when the index cannot say.

The passive branch is the one worth reading twice. It never gates, so it never
sits in front of the install: where a lockfile will land, the install runs
first and Ossprey reads what it wrote, which is both faster and more accurate
than predicting the tree beforehand. Where one will not — pip, `uv pip
install`, `uv tool install`, bun (whose `bun.lock` is not read yet), a tool
run, a global or redirected install — there would be nothing to read, so
the named packages are submitted beside the install instead (`writesLocalLockfile`
in `internal/forward/forward.go` is the one place that decides, for every
command but the cargo ones above).

```mermaid
sequenceDiagram
    participant U as You
    participant O as ossprey
    participant N as npm
    participant API as Ossprey API

    rect rgb(245, 235, 235)
        note over U,API: Gating mode — the install waits for a verdict
        U->>O: npm install foo
        O->>API: submit + poll
        API-->>O: clean
        O->>N: install foo
        N-->>U: done
    end

    rect rgb(235, 243, 235)
        note over U,API: Passive mode — the install never waits
        U->>O: npm install foo
        O->>N: install foo
        N-->>U: done
        O->>O: read package-lock.json
        O->>API: submit, no polling
        API-->>O: accepted
    end
```

---

[← Back to the docs index](README.md)
