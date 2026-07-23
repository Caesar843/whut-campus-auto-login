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
$baselinePath = Join-Path $repoRoot 'packaging\windows\build_baseline.json'
$environmentVerifierPath = Join-Path $repoRoot 'scripts\verify_windows_build_environment.py'
$versionGeneratorPath = Join-Path $repoRoot 'scripts\generate_windows_version_info.py'
$appIconPath = Join-Path $repoRoot 'assets\windows\whut_campus_auto_login.ico'
$buildDir = Join-Path $repoRoot 'build'
$generatedDir = Join-Path $buildDir 'generated'
$generatedConfigModule = Join-Path $generatedDir '_license_client_embedded_build_config.py'
$generatedVersionInfo = Join-Path $generatedDir 'windows_version_info.txt'
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
if (-not (Test-Path -LiteralPath $baselinePath)) {
    throw "Missing Windows build baseline."
}
if (-not (Test-Path -LiteralPath $environmentVerifierPath)) {
    throw "Missing Windows build environment verifier."
}
if (-not (Test-Path -LiteralPath $versionGeneratorPath)) {
    throw "Missing Windows version metadata generator."
}
if (-not (Test-Path -LiteralPath $appIconPath)) {
    throw "Missing official Windows application icon."
}

try {
    $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
}
catch {
    throw "Windows build baseline is invalid."
}
$expectedPythonVersion = [string]$baseline.python_version
$expectedPyInstallerVersion = [string]$baseline.pyinstaller_version
$packagingMode = [string]$baseline.packaging_mode
if (-not $expectedPythonVersion -or -not $expectedPyInstallerVersion -or $packagingMode -ne 'onedir') {
    throw "Windows build baseline is invalid."
}

$python = Get-Command python -ErrorAction Stop

Push-Location $repoRoot
try {
    $pythonVersionOutput = (& $python.Source --version 2>&1 | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0) {
        throw "Python failed with exit code $LASTEXITCODE"
    }
    $pythonVersion = ([string]$pythonVersionOutput -replace '^Python\s+', '').Trim()
    if ($pythonVersion -ne $expectedPythonVersion) {
        throw "Python $pythonVersion does not match required version $expectedPythonVersion."
    }

    $pyInstallerVersion = [string](& $python.Source -m PyInstaller --version | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed. Run: python -m pip install -r requirements-build.txt"
    }
    $pyInstallerVersion = $pyInstallerVersion.Trim()
    if ($pyInstallerVersion -ne $expectedPyInstallerVersion) {
        throw "PyInstaller $pyInstallerVersion does not match required version $expectedPyInstallerVersion."
    }

    & $python.Source $environmentVerifierPath | Write-Output
    if ($LASTEXITCODE -ne 0) {
        throw "Windows build environment validation failed."
    }

    $appVersion = [string](& $python.Source -c 'from app_version import APP_VERSION; print(APP_VERSION)' | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or -not $appVersion.Trim()) {
        throw "Failed to read application version."
    }
    $appVersion = $appVersion.Trim()
    Write-Output ("AppVersion: {0}" -f $appVersion)
    Write-Output ("PythonVersion: {0}" -f $pythonVersion)
    Write-Output ("PyInstallerVersion: {0}" -f $pyInstallerVersion)
    Write-Output ("PackagingMode: {0}" -f $packagingMode)

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

    & $python.Source $versionGeneratorPath '--output' $generatedVersionInfo
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $generatedVersionInfo)) {
        throw "Failed to generate Windows version metadata."
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
