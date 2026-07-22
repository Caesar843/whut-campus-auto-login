[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$BuildDebug,
    [string]$LicensePublicKey = "",
    [string]$LicenseServerUrl = "",
    [string]$BuildEnvironment = ""
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$specPath = Join-Path $repoRoot 'WHUTCampusAutoLogin.spec'
$entryPath = Join-Path $repoRoot 'desktop_app\tray_app.py'
$buildDir = Join-Path $repoRoot 'build'
$generatedDir = Join-Path $buildDir 'generated'
$generatedConfigModule = Join-Path $generatedDir '_license_client_embedded_build_config.py'
$generatedConfigPyc = Join-Path $generatedDir '_license_client_embedded_build_config.pyc'
$generatedConfigCache = Join-Path $generatedDir '__pycache__'
$buildSessionEnvironmentName = 'WHUT_BUILD_SESSION_ID'
$previousBuildSessionId = [Environment]::GetEnvironmentVariable($buildSessionEnvironmentName, 'Process')
$primaryExitCode = 0
$primaryFailureMessage = $null
$cleanupFailureMessage = $null

function Remove-GeneratedBuildConfig {
    if (Test-Path -LiteralPath $generatedConfigModule) {
        Remove-Item -LiteralPath $generatedConfigModule -Force
    }
    if (Test-Path -LiteralPath $generatedConfigPyc) {
        Remove-Item -LiteralPath $generatedConfigPyc -Force
    }
    if (Test-Path -LiteralPath $generatedConfigCache) {
        Get-ChildItem -LiteralPath $generatedConfigCache -File -Filter '_license_client_embedded_build_config.*.pyc' |
            Remove-Item -Force
        if (-not (Get-ChildItem -LiteralPath $generatedConfigCache -Force | Select-Object -First 1)) {
            Remove-Item -LiteralPath $generatedConfigCache -Force
        }
    }
}

Remove-GeneratedBuildConfig

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

    $licenseServerUrlValue = [string]$LicenseServerUrl
    if (@('preproduction', 'production') -contains $buildEnvironmentValue -and -not $licenseServerUrlValue) {
        throw "LicenseServerUrl is required for preproduction and production builds."
    }

    $publicKey = $LicensePublicKey.Trim()
    if (-not $publicKey) {
        throw "LicensePublicKey is required for Windows build. Pass -LicensePublicKey."
    }

    if (Test-Path -LiteralPath $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }

    $buildSessionId = [guid]::NewGuid().ToString('N')
    $buildConfigArgs = @(
        '-m', 'license_client.public_key',
        '--public-key', $publicKey,
        '--build-environment', $buildEnvironmentValue,
        '--build-session-id', $buildSessionId,
        '--output', $generatedConfigModule
    )
    if ($licenseServerUrlValue) {
        $buildConfigArgs += @('--license-server-url', $licenseServerUrlValue)
    }
    & $python.Source @buildConfigArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to prepare embedded license build config."
    }
    [Environment]::SetEnvironmentVariable($buildSessionEnvironmentName, $buildSessionId, 'Process')

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
    $primaryExitCode = $LASTEXITCODE
    if ($primaryExitCode -ne 0) {
        $primaryFailureMessage = "PyInstaller failed with exit code $primaryExitCode"
    }
    else {
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
}
catch {
    $primaryFailureMessage = $_.Exception.Message
    if ($primaryExitCode -eq 0) {
        $primaryExitCode = 1
    }
}
finally {
    try {
        Remove-GeneratedBuildConfig
    }
    catch {
        $cleanupFailureMessage = $_.Exception.Message
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            $buildSessionEnvironmentName,
            $previousBuildSessionId,
            'Process'
        )
        Pop-Location
    }
}

if ($primaryFailureMessage) {
    Write-Error -Message $primaryFailureMessage -ErrorAction Continue
}
if ($cleanupFailureMessage) {
    Write-Error -Message (
        "Generated license build config cleanup failed. " +
        "The next build will retry cleanup before validation. Error: $cleanupFailureMessage"
    ) -ErrorAction Continue
}
if ($primaryExitCode -ne 0) {
    exit $primaryExitCode
}
if ($cleanupFailureMessage) {
    exit 1
}
