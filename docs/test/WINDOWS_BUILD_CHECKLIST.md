# Windows build checklist

## Environment

- Windows 10/11.
- Python 3.11 or newer available as `python`.
- Client dependencies installed.
- PyInstaller installed only for build work:

```powershell
python -m pip install -r requirements-build.txt
```

## Build

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

The script can also be launched from the `scripts` directory. It locates the repository root, removes the previous `build/` temporary directory, and builds from `WHUTCampusAutoLogin.spec`.

Output:

```text
dist\WHUTCampusAutoLogin\WHUTCampusAutoLogin.exe
```

## Manual checks

1. Start `dist\WHUTCampusAutoLogin\WHUTCampusAutoLogin.exe` from outside the repository root and confirm the main window opens.
2. Start `dist\WHUTCampusAutoLogin\WHUTCampusAutoLogin.exe --startup-tray` and confirm the process stays alive without a console window.
3. Enable startup from the app and confirm the Startup shortcut points to the packaged EXE with `--startup-tray`.
4. Confirm user config remains in `%APPDATA%\WHUTCampusAutoLogin` and the password remains in Windows Credential Manager.
5. Confirm runtime logs remain under the existing user data log directory.

## Still not covered

- Windows installer.
- Code signing.
- Automatic updates.
- Formal release process.
- Antivirus allowlist or false-positive handling.
- Full clean-machine compatibility result.
- Formal app icon.
