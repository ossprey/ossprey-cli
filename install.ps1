# Ossprey CLI installer for Windows (PowerShell 5.1+, no WSL required).
#
# Usage (from any PowerShell prompt):
#   irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex
#
# Or from cmd.exe:
#   powershell -ExecutionPolicy Bypass -Command "irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex"
#
# Flags (when run as a downloaded .ps1 file):
#   -OverridePackageManagers   Install PATH shims so npm, pnpm, yarn, pip, pip3,
#                              poetry and uv route through ossprey without being
#                              prefixed. Same as `ossprey shim install`.
#   -Watchdog                  With the shims, submit scans passively using this
#                              machine's login and never block an install.
#   -MonitorId <id>            With the shims, submit passively through a
#                              monitor's id, needing no credential at all.
#
# Env vars:
#   OSSPREY_VERSION      Tag to install (e.g. v0.1.0). Default: latest.
#   OSSPREY_INSTALL_DIR  Install location. Default: %LOCALAPPDATA%\Programs\ossprey
#   OSSPREY_WATCHDOG=1                    Same as -Watchdog.
#   OSSPREY_MONITOR_ID=<id>               Same as -MonitorId <id>.
#   OSSPREY_OVERRIDE_PACKAGE_MANAGERS=1   Same as -OverridePackageManagers, and
#                              the way to ask for shims through `irm ... | iex`.

param([switch]$OverridePackageManagers, [switch]$Watchdog, [string]$MonitorId)

$ErrorActionPreference = 'Stop'

$Repo = 'ossprey/ossprey-cli'
$Bin  = 'ossprey.exe'

$Version = if ($env:OSSPREY_VERSION) { $env:OSSPREY_VERSION } else { 'latest' }
$InstallDir = if ($env:OSSPREY_INSTALL_DIR) {
    $env:OSSPREY_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\ossprey'
}

function Log([string]$msg) { Write-Host "==> $msg" }

# --- detect arch ---
# RuntimeInformation reports the real OS arch even under x64 emulation on
# ARM64; PROCESSOR_ARCHITECTURE is the fallback for old .NET Framework.
$archRaw = try {
    [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
} catch {
    $env:PROCESSOR_ARCHITECTURE
}
$Arch = switch -Regex ($archRaw) {
    '^(X64|AMD64)$'  { 'amd64' }
    '^(Arm64|ARM64)$' { 'arm64' }
    default { throw "unsupported arch: $archRaw" }
}

$Asset = "ossprey-windows-$Arch.exe"
$Base = if ($Version -eq 'latest') {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

# Windows PowerShell 5.1 defaults to TLS 1.0; GitHub requires 1.2+.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ossprey-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
    $exePath = Join-Path $Tmp $Bin
    Log "downloading $Base/$Asset"
    Invoke-WebRequest -Uri "$Base/$Asset" -OutFile $exePath -UseBasicParsing

    # --- verify sha256 if available ---
    $sumPath = Join-Path $Tmp "$Asset.sha256"
    $expected = $null
    try {
        Invoke-WebRequest -Uri "$Base/$Asset.sha256" -OutFile $sumPath -UseBasicParsing
        $expected = ((Get-Content $sumPath -Raw).Trim() -split '\s+')[0].ToLower()
    } catch {
        Log 'no sha256 file found, skipping verification'
    }
    if ($expected) {
        Log 'verifying sha256'
        $actual = (Get-FileHash $exePath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) {
            throw "sha256 mismatch: expected $expected, got $actual"
        }
    }

    # --- install ---
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir $Bin
    Move-Item -Force $exePath $dest

    # --- add to user PATH if missing ---
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $inPath = ($userPath -split ';' | Where-Object { $_ -eq $InstallDir }).Count -gt 0
    if (-not $inPath) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Log "added $InstallDir to your user PATH (open a new terminal to pick it up)"
    }
    # Make it available in this session too.
    if (($env:Path -split ';' | Where-Object { $_ -eq $InstallDir }).Count -eq 0) {
        $env:Path = "$env:Path;$InstallDir"
    }

    $installedVersion = try { & $dest --version 2>$null } catch { $Bin }
    Log "installed $installedVersion to $dest"

    # --- optional: PATH shims over the package managers ---
    if (-not $MonitorId) { $MonitorId = $env:OSSPREY_MONITOR_ID }
    if (-not $Watchdog -and $env:OSSPREY_WATCHDOG) { $Watchdog = $true }
    if ($MonitorId -and $Watchdog) {
        throw "-Watchdog and -MonitorId are mutually exclusive"
    }

    # Built as an array so an unset mode passes no argument at all. The monitor
    # id is validated by `shim install` before it is written anywhere.
    $modeArgs = @()
    if ($MonitorId) { $modeArgs = @("--monitor", $MonitorId) }
    elseif ($Watchdog) { $modeArgs = @("--watchdog") }

    if ($OverridePackageManagers -or $MonitorId -or $Watchdog -or $env:OSSPREY_OVERRIDE_PACKAGE_MANAGERS) {
        Log 'installing package-manager shims'
        try {
            & $dest shim install @modeArgs
        } catch {
            Log "shim install failed: $_"
            Log "ossprey itself is installed — run 'ossprey shim install' to retry"
        }
    }
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
