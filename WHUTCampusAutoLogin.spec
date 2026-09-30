# -*- mode: python ; coding: utf-8 -*-

import os
import runpy
from pathlib import Path


ROOT = Path(SPECPATH)
GENERATED_MODULE_DIR = ROOT / "build" / "generated"
EMBEDDED_CONFIG_MODULE = GENERATED_MODULE_DIR / "_license_client_embedded_build_config.py"
WINDOWS_VERSION_INFO_PATH = GENERATED_MODULE_DIR / "windows_version_info.txt"
APP_ICON_PATH = ROOT / "assets" / "windows" / "whut_campus_auto_login.ico"
BUILD_SESSION_ENVIRONMENT_NAME = "WHUT_BUILD_SESSION_ID"

if not EMBEDDED_CONFIG_MODULE.exists():
    raise RuntimeError(
        "Missing embedded license build config. Run scripts/build_windows.ps1 "
        "with -BuildEnvironment, -LicensePublicKey, and the release URL when required."
    )

build_session_id = os.environ.get(BUILD_SESSION_ENVIRONMENT_NAME, "")
if not build_session_id:
    raise RuntimeError("Missing current build session. Run scripts/build_windows.ps1.")
try:
    embedded_config = runpy.run_path(str(EMBEDDED_CONFIG_MODULE))
except Exception as exc:
    raise RuntimeError("Embedded license build config is invalid.") from exc
if embedded_config.get("BUILD_SESSION_ID") != build_session_id:
    raise RuntimeError("Embedded license build config does not match the current build session.")
if not APP_ICON_PATH.exists():
    raise RuntimeError("Missing official Windows application icon.")
if not WINDOWS_VERSION_INFO_PATH.exists():
    raise RuntimeError("Missing generated Windows version metadata. Run scripts/build_windows.ps1.")

a = Analysis(
    [str(ROOT / "desktop_app" / "tray_app.py")],
    pathex=[str(ROOT), str(GENERATED_MODULE_DIR)],
    binaries=[],
    datas=[(str(APP_ICON_PATH), "assets/windows")],
    hiddenimports=["_license_client_embedded_build_config"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "deploy",
        "license_server",
        "references",
        "scripts",
        "tests",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WHUTCampusAutoLogin",
    icon=str(APP_ICON_PATH),
    version=str(WINDOWS_VERSION_INFO_PATH),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="WHUTCampusAutoLogin",
)
