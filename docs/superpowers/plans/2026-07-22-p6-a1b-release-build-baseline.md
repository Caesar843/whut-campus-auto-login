# P6-A1b Windows Release Build Baseline Implementation Plan

**Goal:** Establish a reproducible Windows 3.11.9/PyInstaller 6.21.0 onedir build baseline with one application version source, official icon assets, Windows version metadata, strict environment validation, and a clean-checkout release SOP.

**Architecture:** Keep runtime and build concerns small and separate. `app_version.py` owns the version, two standard-library scripts generate Windows metadata and validate the build environment, the PyInstaller spec consumes generated metadata plus the committed ICO, and one runtime resource helper serves the same icon to the application, main window, and tray.

**Tech Stack:** Python 3.11.9, PySide6, PyInstaller 6.21.0, PowerShell, pytest.

## Global constraints

- Preserve PyInstaller `onedir` with `exclude_binaries=True` and `COLLECT`.
- Preserve the P6-A1a build-session gate, generated license-config cleanup, and primary PyInstaller exit-code precedence.
- Do not add Pillow, a persistent icon-conversion dependency, a production URL, a real public key, signing, an installer, or automatic updates.
- Do not generate or accept a real production EXE.
- Do not change campus login, credential storage, licensing, payment, server, database, autostart, or retry behavior.
- Do not stage, commit, push, create a PR, merge, or switch back to `main`.

## File structure

- Create `app_version.py` for `APP_VERSION` and Windows tuple parsing.
- Create `assets/branding/whut_campus_auto_login_icon_source.png` and `assets/windows/whut_campus_auto_login.ico` from the user-provided root inputs.
- Create `packaging/windows/build_baseline.json` and `requirements-windows-build.lock.txt` for the exact toolchain.
- Create `scripts/generate_windows_version_info.py` and `scripts/verify_windows_build_environment.py` for generated metadata and fail-closed validation.
- Create `desktop_app/resources/__init__.py` and minimally update `desktop_app/tray/runtime.py` for runtime icon lookup and reuse.
- Modify `license_client/constants.py`, `requirements-build.txt`, `scripts/build_windows.ps1`, and `WHUTCampusAutoLogin.spec` for the new sources and build gates.
- Add focused tests and update the Windows build checklist plus `docs/release/WINDOWS_RELEASE_BUILD.md`.

## TDD task sequence

1. Add failing tests for final PNG/ICO structure, version parsing, single-source compatibility, generated version fields, Unicode, atomic deterministic output, and PyInstaller parsing.
2. Move the PNG unchanged; rebuild only the invalid ICO by padding the 488x511 source transparently to 511x511 and embedding 16/24/32/48/64/128/256 PNG frames without adding a dependency.
3. Implement `app_version.py`, import its constant from `license_client.constants`, and implement the version-info generator writing `build/generated/windows_version_info.txt`.
4. Add failing tests for baseline coherence, strict lock parsing, normalized names, Python/venv checks, missing/mismatched/extra packages, and bootstrap allowances; then implement the JSON baseline, exact PyInstaller requirement, clean-venv lock, and validator.
5. Extend build lifecycle/spec tests first, then wire the fail-closed toolchain checks, metadata generation, non-sensitive logs, ICO data, `icon=`, and `version=` while preserving onedir/session/cleanup behavior.
6. Add failing source/frozen/CWD/missing-icon and shared app/window/tray tests, then implement the resource helper and one-icon runtime path.
7. Update the clean-checkout SOP and checklist, using only `example.invalid` and placeholder public-key text for P6-A1c inputs.
8. Run targeted RED/GREEN checks throughout, then the P6-A1a regression, client icon tests, full suite, PowerShell/Python/spec parsers, JSON/lock/image structural checks, and `git diff --check`.
9. Attempt a local uncommitted CodeRabbit review after verifying no secrets are present; fix critical and warning findings and re-run verification. If the CLI is missing or unauthenticated, record that no PR exists because PR creation is forbidden.

## Exact interfaces and data flow

- `app_version.APP_VERSION: str = "0.1.0"`.
- `app_version.windows_version_tuple(version: str) -> tuple[int, int, int, int]` accepts exactly three ASCII numeric segments in the inclusive range 0..65535 and appends a zero fourth segment.
- `generate_windows_version_info.py --output <path>` imports the authoritative version and atomically writes UTF-8 PyInstaller `VSVersionInfo` text with locale `0804`, code page `1200`, the approved fields, and no `CompanyName`.
- `verify_windows_build_environment.py` locates the repository from its own path, reads the baseline-selected lock, compares exact installed distributions via `importlib.metadata`, reports only safe package/version differences, and exits zero only on a complete match.
- `desktop_app.resources.resource_path(relative_path: str) -> Path` resolves beneath `sys._MEIPASS` when frozen and beneath the repository root in source mode, never beneath the current working directory, and raises `FileNotFoundError` for a missing file.
- The build script validates the baseline and environment before parameter validation or build-directory deletion, then generates the license config and version info after the fresh build directory exists.
- The spec embeds only the ICO at `assets/windows`; runtime loads it once, sets the QApplication default, passes it to the tray, and explicitly applies it to the main window.

## Acceptance commands

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -p no:cacheprovider
git diff --check
```

Run the PowerShell parser, Python/spec AST parsing, JSON parsing, lock validation, and PNG/ICO directory tests separately. Do not invoke a real production build; spec wiring is accepted through controlled tests and generated non-secret metadata only.
