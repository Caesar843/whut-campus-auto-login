# Windows build checklist

## Release baseline

- Windows 10/11 x64.
- Python 3.11.9.
- PyInstaller 6.21.0.
- Packaging mode: `onedir`.
- APP_VERSION 0.1.0.
- Dependencies installed from `requirements-windows-build.lock.txt` in a dedicated virtual environment.

## Automated checks

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:QT_QPA_PLATFORM='offscreen'
python .\scripts\verify_windows_build_environment.py
python -m pip check
python -m pytest -p no:cacheprovider tests\campus_login tests\client tests\license_client tests\test_windows_build_config_lifecycle.py tests\test_windows_build_environment.py tests\test_windows_release_baseline.py
```

The environment verifier must pass before any release build. Run `scripts/build_windows.ps1`; `WHUTCampusAutoLogin.spec` 不能直接运行 because it rejects a missing or stale build session.

The Windows build lock excludes server-only dependencies. Run the complete repository suite separately in a development environment that also installs `requirements-server.txt`.

## Controlled release command

The following command documents the interface only. It is intentionally not usable for a real release because the URL is reserved and the public key is a placeholder:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 `
  -Clean `
  -BuildEnvironment production `
  -LicenseServerUrl "https://example.invalid" `
  -LicensePublicKey "<production-public-key>"
```

P6-A1c must replace both placeholder values with approved production inputs. Do not place a private key or admin token in this command.

## Manual checks after an approved P6-A1c build

1. Confirm the output remains `dist\WHUTCampusAutoLogin\WHUTCampusAutoLogin.exe` inside an onedir folder.
2. Confirm the EXE properties show version 0.1.0 and the approved Chinese product metadata.
3. Confirm the EXE, taskbar, main window, and tray use the same official icon.
4. Start the EXE from outside the repository and test normal and `--startup-tray` startup.
5. Confirm credentials remain in Windows Credential Manager and runtime data remains under `%APPDATA%\WHUTCampusAutoLogin`.

## Not covered by P6-A1b

- A real production EXE or production-input acceptance.
- Windows installer, Authenticode signing, SmartScreen handling, or automatic updates.
- Artifact hashes or guaranteed byte-identical output.
- P6-A1c, P6-A2, or P6-A3.
