# Windows release build SOP

## Fixed baseline

P6-A1b fixes the supported release environment to Windows 10/11 x64, Python 3.11.9, PyInstaller 6.21.0, `onedir`, and APP_VERSION 0.1.0. The committed `requirements-windows-build.lock.txt` contains exact package versions, including direct and transitive build/test dependencies.

The lock was produced in a new Python 3.11.9 virtual environment by upgrading pip, installing `requirements-build.txt`, running `python -m pip check`, and capturing `python -m pip freeze --all`. It is a version lock, not an artifact-hash lock, and does not guarantee byte-identical output across machines.

## Start from a clean checkout

```powershell
git status --short
git rev-parse HEAD
py -3.11 -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements-windows-build.lock.txt
python -m pip check
python .\scripts\verify_windows_build_environment.py
$env:PYTHONDONTWRITEBYTECODE='1'
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -p no:cacheprovider --ignore=tests\client\test_payment_flow.py tests\campus_login tests\client tests\license_client tests\test_windows_build_config_lifecycle.py tests\test_windows_build_environment.py tests\test_windows_release_baseline.py
```

`python --version` must print 3.11.9, and the verifier must exit zero. Do not continue after any mismatch; do not fill gaps from a global Python installation.

The Windows build lock intentionally excludes server-only dependencies. The scoped command excludes `tests\client\test_payment_flow.py` because that integration test imports a license-server test helper. 完整仓库测试需要另行安装 requirements-server.txt in a separate development environment and then run `python -m pytest -p no:cacheprovider`; do not add the server stack to the Windows release bundle merely to run those tests.

## Release build interface

Only `scripts/build_windows.ps1` may launch the spec. `WHUTCampusAutoLogin.spec` 不能直接运行 because the build script creates the current session, validates the exact environment, generates the embedded license configuration, and writes Windows version metadata first.

This example is documentation-only and intentionally cannot produce an approved release:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 `
  -Clean `
  -BuildEnvironment production `
  -LicenseServerUrl "https://example.invalid" `
  -LicensePublicKey "<production-public-key>"
```

P6-A1c must supply an approved HTTPS license URL and approved Ed25519 verification public key. Never place a signing private key, campus-network credential, payment key, token, or other secret in the command or repository.

Before a production build, run
[`PRODUCTION_LICENSE_KEY_PREFLIGHT.md`](PRODUCTION_LICENSE_KEY_PREFLIGHT.md) on
the production server and freeze the successful `public_key_sha256` value. The
public key supplied to `scripts/build_windows.ps1` must reproduce that
fingerprint. A preflight `PASS` does not replace the later public HTTPS and
running-service token checks.

## Expected output and resources

- Packaging remains `onedir`: `dist\WHUTCampusAutoLogin\WHUTCampusAutoLogin.exe` plus its dependency directory.
- The EXE version resource is generated under `build\generated` from `app_version.APP_VERSION`.
- The EXE and runtime use `assets\windows\whut_campus_auto_login.ico`.
- The branding source PNG is retained in the repository but is not included in the release bundle.
- The one-time embedded license configuration is removed after success or failure; Windows version metadata is not a secret and may remain under ignored `build\generated`.

## P6-A1c-2 artifact-attestation flow

P6-A1c-2 adds a reviewable offline attestation tool; this repository change
does not execute or accept a production build.  The tool is intentionally a
separate command so `scripts\build_windows.ps1` remains the only build entry
point and never receives attestation logic or release-publishing authority.

Stage 1 is code review, tests, a Draft PR, and merge of the tool itself.
Stage 2 is a later human-controlled activity from clean merged `main`: obtain
approved process-only release inputs, build with the fixed baseline, run
`scripts\release_artifact_attestation.py`, review the redacted manifest/SBOM/
license archive/checksums, and only then decide separately about signing and
release publication.  Do not commit the approved URL or full public key; the
attestor records only URL-validation booleans and the approved public-key
SHA-256 fingerprint.

## Current release boundary

P6-A1b does not run or accept a real production build. Installation packaging, Authenticode signing, Defender/SmartScreen work, automatic updates, artifact hashes, and production URL/public-key acceptance remain outside this phase.
