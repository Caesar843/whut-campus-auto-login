[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$BuildDebug,
    [string]$LicensePublicKey = "",
    [string]$BuildEnvironment = ""
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$specPath = Join-Path $repoRoot 'WHUTCampusAutoLogin.spec'
$entryPath = Join-Path $repoRoot 'desktop_app\tray_app.py'

if (-not (Test-Path -LiteralPath $specPath)) {
    throw "Missing PyInstaller spec: $specPath"
}
if (-not (Test-Path -LiteralPath $entryPath)) {
    throw "Missing desktop entry: $entryPath"
}

$python = Get-Command python -ErrorAction Stop

Push-Location $repoRoot
try {
    & $python.Source --version | Write-Output
    if ($LASTEXITCODE -ne 0) {
        throw "Python failed with exit code $LASTEXITCODE"
    }

    & $python.Source -m PyInstaller --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed. Run: python -m pip install -r requirements-build.txt"
    }

    $buildEnvironmentValue = $BuildEnvironment.Trim().ToLowerInvariant()
    if (-not $buildEnvironmentValue) {
        throw "BuildEnvironment is required. Pass -BuildEnvironment development, preproduction, or production."
    }
    if (@('development', 'preproduction', 'production') -notcontains $buildEnvironmentValue) {
        throw "BuildEnvironment must be one of: development, preproduction, production."
    }

    $publicKey = $LicensePublicKey.Trim()
    if (-not $publicKey) {
        throw "LicensePublicKey is required for Windows build. Pass -LicensePublicKey."
    }

    $buildDir = Join-Path $repoRoot 'build'
    if (Test-Path -LiteralPath $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }

    $generatedConfigModule = Join-Path $buildDir 'generated\_license_client_embedded_build_config.py'
    & $python.Source -m license_client.public_key `
        --public-key $publicKey `
        --build-environment $buildEnvironmentValue `
        --output $generatedConfigModule
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to prepare embedded license build config."
    }

    $distAppDir = Join-Path $repoRoot 'dist\WHUTCampusAutoLogin'
    if ($Clean -and (Test-Path -LiteralPath $distAppDir)) {
        Remove-Item -LiteralPath $distAppDir -Recurse -Force
    }

    $pyinstallerArgs = @('--noconfirm')
    if ($BuildDebug) {
        $pyinstallerArgs += '--log-level=DEBUG'
    }
    $pyinstallerArgs += $specPath

    & $python.Source -m PyInstaller @pyinstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }

    $exePath = Join-Path $distAppDir 'WHUTCampusAutoLogin.exe'
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Expected EXE was not created: $exePath"
    }

    $sizeBytes = (Get-ChildItem -LiteralPath $distAppDir -Recurse -File |
        Measure-Object -Property Length -Sum).Sum

    Write-Output "EXE: $exePath"
    Write-Output ("BuildEnvironment: {0}" -f $buildEnvironmentValue)
    Write-Output ("SizeBytes: {0}" -f $sizeBytes)
}
finally {
    Pop-Location
}
