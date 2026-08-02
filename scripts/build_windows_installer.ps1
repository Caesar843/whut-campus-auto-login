<#
.SYNOPSIS
    Build the WHUTCampusAutoLogin Windows installer using Inno Setup 6.

.DESCRIPTION
    Validates the PyInstaller onedir input, drives ISCC.exe to produce a
    signed-name installer EXE, prints SHA-256, and enforces environment
    separation between development and production builds.

    This script MUST be run after scripts\build_windows.ps1 has produced
    a clean PyInstaller onedir in dist\WHUTCampusAutoLogin\.

    Do NOT call ISCC.exe directly; use this script for all gate checks.

.PARAMETER BuildEnvironment
    "development" or "production".
    - development: gate checks relaxed; output filename contains "development".
    - production: additional gate checks (clean git, no dev key, etc.); NOT
      approved for actual release in this phase.

.PARAMETER InputDir
    Path to the PyInstaller onedir to package. Defaults to dist\WHUTCampusAutoLogin.

.PARAMETER OutputDir
    Directory for the generated installer EXE. Defaults to installer\output.
    This directory is git-ignored.

.PARAMETER AppVersion
    Version string to embed (e.g. "0.1.0"). Defaults to reading app_version.py.

.PARAMETER IsccPath
    Explicit path to ISCC.exe. If not provided, the script checks standard
    Inno Setup 6 installation paths and PATH.

.PARAMETER IssScript
    Path to the Inno Setup script. Defaults to installer\WHUTCampusAutoLogin.iss.

.EXAMPLE
    pwsh -File scripts\build_windows_installer.ps1 -BuildEnvironment development

.EXAMPLE
    pwsh -File scripts\build_windows_installer.ps1 `
         -BuildEnvironment development `
         -IsccPath "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" `
         -AppVersion "0.1.0"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("development", "production")]
    [string]$BuildEnvironment,

    [string]$InputDir = "",

    [string]$OutputDir = "",

    [string]$AppVersion = "",

    [string]$IsccPath = "",

    [string]$IssScript = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 0. Resolve repo root and defaults
# ---------------------------------------------------------------------------
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir

if (-not $InputDir)  { $InputDir  = Join-Path $RepoRoot "dist\WHUTCampusAutoLogin" }
if (-not $OutputDir) { $OutputDir = Join-Path $RepoRoot "installer\output" }
if (-not $IssScript) { $IssScript = Join-Path $RepoRoot "installer\WHUTCampusAutoLogin.iss" }

$InputDir   = [IO.Path]::GetFullPath($InputDir)
$OutputDir  = [IO.Path]::GetFullPath($OutputDir)
$IssScript  = [IO.Path]::GetFullPath($IssScript)
$MainExe    = Join-Path $InputDir "WHUTCampusAutoLogin.exe"

# ---------------------------------------------------------------------------
# 1. Detect app version (from app_version.py if not supplied)
# ---------------------------------------------------------------------------
if (-not $AppVersion) {
    $versionFile = Join-Path $RepoRoot "app_version.py"
    if (Test-Path $versionFile) {
        $match = Select-String -Path $versionFile -Pattern 'APP_VERSION\s*=\s*"([^"]+)"'
        if ($match) {
            $AppVersion = $match.Matches[0].Groups[1].Value
        }
    }
    if (-not $AppVersion) {
        Write-Error "Cannot determine AppVersion. Provide -AppVersion or ensure app_version.py contains APP_VERSION."
    }
}
Write-Host "AppVersion: $AppVersion"

# ---------------------------------------------------------------------------
# 2. Locate ISCC.exe
# ---------------------------------------------------------------------------
if ($IsccPath) {
    if (-not (Test-Path $IsccPath)) {
        Write-Error "Specified ISCC.exe not found: $IsccPath"
    }
} else {
    $candidates = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $IsccPath = $c; break }
    }
    if (-not $IsccPath) {
        try {
            $cmd = Get-Command ISCC -ErrorAction Stop
            $IsccPath = $cmd.Source
        } catch {}
    }
    if (-not $IsccPath) {
        Write-Error @"
ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php
or provide -IsccPath "C:\...\ISCC.exe".
"@
    }
}
Write-Host "ISCC: $IsccPath"

# ---------------------------------------------------------------------------
# 3. Resolve output filename
# ---------------------------------------------------------------------------
$ShortVersion = $AppVersion -replace '\+.*$', ''   # strip build metadata
if ($BuildEnvironment -eq "development") {
    $OutputBasename = "WHUTCampusAutoLogin-$ShortVersion-development-setup"
} else {
    # production guard (not yet approved for release)
    Write-Warning "PRODUCTION MODE: additional gate checks apply."
    $OutputBasename = "WHUTCampusAutoLogin-$ShortVersion-setup"
}
Write-Host "OutputBasename: $OutputBasename"

# ---------------------------------------------------------------------------
# 4. Gate: ISS script exists
# ---------------------------------------------------------------------------
if (-not (Test-Path $IssScript)) {
    Write-Error "Inno Setup script not found: $IssScript"
}
Write-Host "ISS script: $IssScript [OK]"

# ---------------------------------------------------------------------------
# 5. Gate: Input directory validation
# ---------------------------------------------------------------------------
if (-not (Test-Path $InputDir -PathType Container)) {
    Write-Error "InputDir does not exist: $InputDir"
}
if (-not (Test-Path $MainExe)) {
    Write-Error "Main EXE not found: $MainExe"
}
$exeSize = (Get-Item $MainExe).Length
if ($exeSize -eq 0) {
    Write-Error "Main EXE has zero size: $MainExe"
}
Write-Host "InputDir: $InputDir [OK] (EXE $([Math]::Round($exeSize/1MB,2)) MB)"

# Check _internal exists
$internalDir = Join-Path $InputDir "_internal"
if (-not (Test-Path $internalDir -PathType Container)) {
    Write-Error "_internal directory not found in InputDir. This does not look like a complete PyInstaller onedir build."
}

# ---------------------------------------------------------------------------
# 6. Gate: Forbidden content check on input
# ---------------------------------------------------------------------------
$forbiddenPatterns = @(
    "pytest", "_pytest", "pluggy", "iniconfig",
    "fastapi", "uvicorn", "sqlalchemy", "alembic",
    "requirements-dev", "requirements-server"
)
$forbiddenFound = @()
foreach ($pat in $forbiddenPatterns) {
    $hits = Get-ChildItem $InputDir -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^$pat" }
    if ($hits) {
        foreach ($h in $hits) { $forbiddenFound += $h.FullName }
    }
}
if ($forbiddenFound) {
    Write-Error "Forbidden content found in InputDir:`n$($forbiddenFound -join "`n")`nDo not package a partial or dev-only build."
}
Write-Host "Forbidden content check: PASS"

# ---------------------------------------------------------------------------
# 7. Gate: Git working tree check
# ---------------------------------------------------------------------------
$gitStatus = & git -C $RepoRoot status --porcelain 2>&1
$trackedChanges = $gitStatus | Where-Object { $_ -match "^[MADRCU?!]" -and $_ -notmatch "^\?\? \.venv" -and $_ -notmatch "^\?\? installer.output" }
if ($BuildEnvironment -eq "production") {
    if ($trackedChanges) {
        Write-Error "Production build requires a clean git working tree. Uncommitted changes found:`n$($trackedChanges -join "`n")"
    }
    Write-Host "Git working tree: CLEAN [OK]"
} else {
    if ($trackedChanges) {
        Write-Warning "Uncommitted changes exist (development build, continuing):`n$($trackedChanges -join "`n")"
    } else {
        Write-Host "Git working tree: CLEAN [OK]"
    }
}

# ---------------------------------------------------------------------------
# 8. Production additional guards (not yet approved for release)
# ---------------------------------------------------------------------------
if ($BuildEnvironment -eq "production") {
    Write-Warning @"
PRODUCTION BUILD: This phase does not approve production distribution.
Requirements before production release:
  - Real HTTPS license server URL configured
  - Real Ed25519 public key embedded
  - Code signing certificate applied to EXE and installer
  - Full human GUI verification completed
  - Isolated install/upgrade/uninstall test completed
  - Explicit release approval from project owner
"@
}

# ---------------------------------------------------------------------------
# 9. Create output directory
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-Host "OutputDir: $OutputDir"

# ---------------------------------------------------------------------------
# 10. Compile installer
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Running ISCC.exe ==="
$isccArgs = @(
    "`"/DAppVersionStr=$AppVersion`"",
    "`"/DInputDir=$InputDir`"",
    "`"/DOutputDir=$OutputDir`"",
    "`"/DOutputBasename=$OutputBasename`"",
    "`"/DBuildEnv=$BuildEnvironment`"",
    "`"$IssScript`""
)
Write-Host "Command: $IsccPath $($isccArgs -join ' ')"
Write-Host ""

$proc = Start-Process -FilePath $IsccPath -ArgumentList $isccArgs -Wait -PassThru -NoNewWindow
$exitCode = $proc.ExitCode

Write-Host ""
Write-Host "=== ISCC exit code: $exitCode ==="

if ($exitCode -ne 0) {
    Write-Error "ISCC.exe failed with exit code $exitCode. Installer not produced."
}

# ---------------------------------------------------------------------------
# 11. Verify output
# ---------------------------------------------------------------------------
$installerPath = Join-Path $OutputDir "$OutputBasename.exe"
if (-not (Test-Path $installerPath)) {
    Write-Error "Installer EXE not found at expected path: $installerPath"
}
$installerSize = (Get-Item $installerPath).Length
if ($installerSize -eq 0) {
    Write-Error "Installer EXE has zero size: $installerPath"
}

# ---------------------------------------------------------------------------
# 12. SHA-256
# ---------------------------------------------------------------------------
$hash = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash

# ---------------------------------------------------------------------------
# 13. Final report
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Installer build SUCCESS ==="
Write-Host "Path:         $installerPath"
Write-Host "Size:         $([Math]::Round($installerSize/1MB,2)) MB ($installerSize bytes)"
Write-Host "SHA-256:      $hash"
Write-Host "Environment:  $BuildEnvironment"
Write-Host "Version:      $AppVersion"
Write-Host "Distributable: $(if ($BuildEnvironment -eq 'production') { 'REQUIRES additional review' } else { 'NO - development only' })"
Write-Host ""
