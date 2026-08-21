<#
.SYNOPSIS
    Shared Windows Authenticode signing and verification helpers.

.DESCRIPTION
    Production signing uses a certificate selected by its exact SHA-1
    thumbprint from the Windows MY certificate store.  This file deliberately
    contains no build, Git, deployment, upload, or secret-handling logic.
#>

$script:WindowsCodeSigningEkuOid = '1.3.6.1.5.5.7.3.3'

function Throw-WindowsSigningError {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )

    throw ('{0}: {1}' -f $Code, $Message)
}

function Get-WindowsSigningEnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    return [Environment]::GetEnvironmentVariable($Name, 'Process')
}

function Normalize-WindowsSigningThumbprint {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Thumbprint
    )

    $normalized = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{40}$') {
        Throw-WindowsSigningError `
            'CODE_SIGNING_CERT_THUMBPRINT_INVALID' `
            'Certificate selector must be exactly 40 hexadecimal characters.'
    }
    return $normalized
}

function ConvertTo-WindowsSigningTimestampUri {
    param([Parameter(Mandatory = $true)][string]$TimestampUrl)

    $trimmed = $TimestampUrl.Trim()
    $uri = $null
    if (-not [Uri]::TryCreate($trimmed, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https') {
        Throw-WindowsSigningError `
            'TIMESTAMP_CONFIGURATION_MISSING' `
            'Production signing requires an approved HTTPS RFC3161 timestamp URL.'
    }
    return $uri.AbsoluteUri
}

function Get-WindowsSigningConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('development', 'preproduction', 'public-beta', 'production')]
        [string]$BuildEnvironment
    )

    $environment = $BuildEnvironment.Trim().ToLowerInvariant()
    $enabled = ([string](Get-WindowsSigningEnvironmentValue -Name 'WINDOWS_SIGNING_ENABLED')).Trim().ToLowerInvariant()
    $thumbprintText = Get-WindowsSigningEnvironmentValue -Name 'WINDOWS_SIGNING_CERT_SHA1'
    $storeText = ([string](Get-WindowsSigningEnvironmentValue -Name 'WINDOWS_SIGNING_STORE')).Trim()
    $signToolPath = ([string](Get-WindowsSigningEnvironmentValue -Name 'WINDOWS_SIGNTOOL_PATH')).Trim()
    $timestampText = Get-WindowsSigningEnvironmentValue -Name 'WINDOWS_SIGNING_TIMESTAMP_URL'

    if ($environment -eq 'public-beta') {
        if ($enabled -eq 'true') {
            Throw-WindowsSigningError `
                'PUBLIC_BETA_SIGNING_CONFIGURATION_INVALID' `
                'Public Beta must keep WINDOWS_SIGNING_ENABLED false; it is an explicitly unsigned channel.'
        }
        return [pscustomobject]@{
            SigningRequired = $false
            BuildEnvironment = $environment
            CertificateThumbprint = $null
            Store = 'CurrentUser'
            SignToolPath = $signToolPath
            TimestampUrl = $null
        }
    }

    if ($environment -ne 'production' -and $enabled -ne 'true') {
        return [pscustomobject]@{
            SigningRequired = $false
            BuildEnvironment = $environment
            CertificateThumbprint = $null
            Store = 'CurrentUser'
            SignToolPath = $signToolPath
            TimestampUrl = $null
        }
    }

    if ($environment -eq 'production' -and $enabled -ne 'true') {
        Throw-WindowsSigningError `
            'SIGNING_CONFIGURATION_MISSING' `
            'WINDOWS_SIGNING_ENABLED must be true for production.'
    }

    if ([string]::IsNullOrWhiteSpace($thumbprintText)) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_CERT_THUMBPRINT_MISSING' `
            'WINDOWS_SIGNING_CERT_SHA1 is required for production signing.'
    }
    $thumbprint = Normalize-WindowsSigningThumbprint -Thumbprint $thumbprintText

    if ($storeText -notin @('CurrentUser', 'LocalMachine')) {
        Throw-WindowsSigningError `
            'SIGNING_CONFIGURATION_MISSING' `
            'WINDOWS_SIGNING_STORE must be CurrentUser or LocalMachine.'
    }

    if ([string]::IsNullOrWhiteSpace($timestampText)) {
        Throw-WindowsSigningError `
            'TIMESTAMP_CONFIGURATION_MISSING' `
            'WINDOWS_SIGNING_TIMESTAMP_URL is required for production signing.'
    }
    $timestampUrl = ConvertTo-WindowsSigningTimestampUri -TimestampUrl $timestampText

    return [pscustomobject]@{
        SigningRequired = $true
        BuildEnvironment = $environment
        CertificateThumbprint = $thumbprint
        Store = $storeText
        SignToolPath = $signToolPath
        TimestampUrl = $timestampUrl
    }
}

function Find-WindowsSignTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Configuration
    )

    if ($Configuration.SignToolPath) {
        if (-not [IO.Path]::IsPathRooted($Configuration.SignToolPath)) {
            Throw-WindowsSigningError 'SIGNTOOL_PATH_INVALID' 'WINDOWS_SIGNTOOL_PATH must be an absolute path.'
        }
        if (-not (Test-Path -LiteralPath $Configuration.SignToolPath -PathType Leaf)) {
            Throw-WindowsSigningError 'SIGNTOOL_NOT_FOUND' ('Configured SignTool was not found: {0}' -f $Configuration.SignToolPath)
        }
        $resolved = (Resolve-Path -LiteralPath $Configuration.SignToolPath).Path
        if ((Get-Item -LiteralPath $resolved).Name -ine 'signtool.exe') {
            Throw-WindowsSigningError 'SIGNTOOL_PATH_INVALID' 'WINDOWS_SIGNTOOL_PATH must point to signtool.exe.'
        }
        return [pscustomobject]@{
            Path = $resolved
            Version = (Get-Item -LiteralPath $resolved).VersionInfo.ProductVersion
        }
    }

    $candidates = @()
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($programFilesX86) {
        $windowsKitBin = Join-Path $programFilesX86 'Windows Kits\10\bin'
        if (Test-Path -LiteralPath $windowsKitBin -PathType Container) {
            $candidates += Get-ChildItem -LiteralPath $windowsKitBin -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^10\.' } |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' }
        }
        $candidates += Join-Path $programFilesX86 'Windows Kits\10\App Certification Kit\signtool.exe'
    }

    $pathCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($pathCommand) {
        $candidates += $pathCommand.Source
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $resolved = (Resolve-Path -LiteralPath $candidate).Path
            return [pscustomobject]@{
                Path = $resolved
                Version = (Get-Item -LiteralPath $resolved).VersionInfo.ProductVersion
            }
        }
    }

    Throw-WindowsSigningError 'SIGNTOOL_NOT_FOUND' 'No compatible x64 signtool.exe was found.'
}

function Get-WindowsSigningCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Configuration
    )

    $storePath = if ($Configuration.Store -eq 'LocalMachine') {
        'Cert:\LocalMachine\My'
    }
    else {
        'Cert:\CurrentUser\My'
    }

    $matches = @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
        Where-Object {
            (($_.Thumbprint -replace '\s', '').ToUpperInvariant()) -eq $Configuration.CertificateThumbprint
        })
    if ($matches.Count -ne 1) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_CERT_NOT_FOUND' `
            ('No unique certificate matched the configured thumbprint in {0}.' -f $storePath)
    }

    Assert-WindowsSigningCertificate -Certificate $matches[0]
    return $matches[0]
}

function Assert-WindowsSigningCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Certificate
    )

    if (-not $Certificate.HasPrivateKey) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_PRIVATE_KEY_UNAVAILABLE' `
            'The selected certificate does not expose a usable private key.'
    }

    $now = [DateTime]::UtcNow
    if ($Certificate.NotBefore.ToUniversalTime() -gt $now -or
        $Certificate.NotAfter.ToUniversalTime() -lt $now) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_CERT_EXPIRED' `
            'The selected certificate is outside its validity period.'
    }

    $ekuOids = @($Certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    if ($ekuOids -notcontains $script:WindowsCodeSigningEkuOid) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_EKU_INVALID' `
            'The selected certificate does not contain the Code Signing EKU.'
    }

    if ($Certificate.Subject -eq $Certificate.Issuer) {
        Throw-WindowsSigningError `
            'CODE_SIGNING_CERT_SELF_SIGNED' `
            'Self-signed certificates are not accepted for production signing.'
    }

    if ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        try {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
            if (-not $chain.Build($Certificate)) {
                Throw-WindowsSigningError `
                    'CODE_SIGNING_CHAIN_INVALID' `
                    'The selected certificate chain could not be built.'
            }
        }
        finally {
            $chain.Dispose()
        }
    }
}

function Assert-WindowsSigningPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('development', 'preproduction', 'public-beta', 'production')]
        [string]$BuildEnvironment
    )

    $configuration = Get-WindowsSigningConfiguration -BuildEnvironment $BuildEnvironment
    if (-not $configuration.SigningRequired) {
        return $configuration
    }

    $tool = Find-WindowsSignTool -Configuration $configuration
    $certificate = Get-WindowsSigningCertificate -Configuration $configuration
    Write-Host ('SignTool: {0} ({1})' -f $tool.Path, $tool.Version)
    Write-Host ('Signing certificate thumbprint: {0}' -f $configuration.CertificateThumbprint)
    Write-Host ('Signing certificate expires: {0:u}' -f $certificate.NotAfter.ToUniversalTime())
    return $configuration
}

function Invoke-WindowsSigningArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Configuration,
        [Parameter(Mandatory = $true)][string]$ArtifactPath
    )

    if (-not $Configuration.SigningRequired) {
        return
    }
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -or
        (Get-Item -LiteralPath $ArtifactPath).Length -le 0) {
        Throw-WindowsSigningError 'SIGNING_ARTIFACT_INVALID' ('Artifact does not exist or is empty: {0}' -f $ArtifactPath)
    }

    $tool = Find-WindowsSignTool -Configuration $Configuration
    $null = Get-WindowsSigningCertificate -Configuration $Configuration
    $arguments = @(
        'sign',
        '/fd', 'SHA256',
        '/sha1', $Configuration.CertificateThumbprint,
        '/s', 'My',
        '/tr', $Configuration.TimestampUrl,
        '/td', 'SHA256',
        '/u', $script:WindowsCodeSigningEkuOid,
        '/q',
        $ArtifactPath
    )
    if ($Configuration.Store -eq 'LocalMachine') {
        $arguments = @($arguments[0..6] + @('/sm') + $arguments[7..($arguments.Count - 1)])
    }

    & $tool.Path @arguments 2>&1 | Write-Output
    if ($LASTEXITCODE -ne 0) {
        Throw-WindowsSigningError 'SIGNING_COMMAND_FAILED' ('signtool sign failed with exit code {0}.' -f $LASTEXITCODE)
    }
}

function Assert-WindowsSigningArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Configuration,
        [Parameter(Mandatory = $true)][string]$ArtifactPath
    )

    if (-not $Configuration.SigningRequired) {
        return
    }
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
        Throw-WindowsSigningError 'SIGNING_ARTIFACT_INVALID' ('Artifact was not found: {0}' -f $ArtifactPath)
    }

    $tool = Find-WindowsSignTool -Configuration $Configuration
    $verifyArguments = @(
        'verify',
        '/pa',
        '/sha1', $Configuration.CertificateThumbprint,
        '/u', $script:WindowsCodeSigningEkuOid,
        '/tw',
        '/q',
        $ArtifactPath
    )
    & $tool.Path @verifyArguments 2>&1 | Write-Output
    if ($LASTEXITCODE -ne 0) {
        Throw-WindowsSigningError 'SIGNATURE_VERIFICATION_FAILED' ('signtool verify failed with exit code {0}.' -f $LASTEXITCODE)
    }

    $signature = Get-AuthenticodeSignature -FilePath $ArtifactPath
    if ([string]$signature.Status -ne 'Valid') {
        Throw-WindowsSigningError 'SIGNATURE_VERIFICATION_FAILED' ('Authenticode status is {0}.' -f $signature.Status)
    }
    if (-not $signature.SignerCertificate) {
        Throw-WindowsSigningError 'SIGNATURE_VERIFICATION_FAILED' 'Authenticode signer certificate is missing.'
    }
    $signerThumbprint = Normalize-WindowsSigningThumbprint -Thumbprint $signature.SignerCertificate.Thumbprint
    if ($signerThumbprint -ne $Configuration.CertificateThumbprint) {
        Throw-WindowsSigningError 'SIGNATURE_CERTIFICATE_MISMATCH' 'Signer thumbprint does not match the configured certificate.'
    }
    if (-not $signature.TimeStamperCertificate) {
        Throw-WindowsSigningError 'TIMESTAMP_VERIFICATION_FAILED' 'Authenticode signature has no timestamp certificate.'
    }
}
