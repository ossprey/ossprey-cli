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
    E --> F
    D --> F["OSSBOM"]
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
    S["ossprey npm install ..."] --> T{"an install verb?"}
    T -- "no, e.g. npm run" --> U["exec the real manager"]
    T -- "yes" --> V{"OSSPREY_SKIP_CI?"}
    V -- "set" --> U
    V -- "unset" --> W{"passive mode?"}

    W -- "no: gating" --> X{"packages named?"}
    X -- "yes" --> Y["check those packages"]
    X -- "no: bare install" --> Z["scan the project manifest"]
    Y --> AA{"malware?"}
    Z --> AA
    AA -- "yes" --> AB["block: exit 1,<br/>manager never runs"]
    AA -- "no" --> U

    W -- "yes" --> AC{"will it leave a lockfile<br/>in this directory?"}
    AC -- "yes: npm install,<br/>poetry add, uv sync, ..." --> AD["exec the real manager first"]
    AD --> AE["catalog the lockfile it wrote"]
    AE --> AF["post the scan, never block"]
    AC -- "no: pip, uv pip,<br/>-g, --prefix ../x" --> AG["exec the real manager<br/>and submit the named<br/>packages alongside it"]
    AG --> AF
```

The passive branch is the one worth reading twice. It never gates, so it never
sits in front of the install: where a lockfile will land, the install runs
first and Ossprey reads what it wrote, which is both faster and more accurate
than predicting the tree beforehand. Where one will not — pip, `uv pip
install`, a global or redirected install — there would be nothing to read, so
the named packages are submitted beside the install instead (`writesLocalLockfile`
in `internal/forward/forward.go` is the one place that decides).

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
