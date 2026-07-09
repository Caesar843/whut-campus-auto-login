# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


ROOT = Path(SPECPATH)
GENERATED_MODULE_DIR = ROOT / "build" / "generated"
EMBEDDED_CONFIG_MODULE = GENERATED_MODULE_DIR / "_license_client_embedded_build_config.py"

if not EMBEDDED_CONFIG_MODULE.exists():
    raise RuntimeError(
        "Missing embedded license build config. Run scripts/build_windows.ps1 "
        "with -BuildEnvironment and -LicensePublicKey."
    )

a = Analysis(
    [str(ROOT / "desktop_app" / "tray_app.py")],
    pathex=[str(ROOT), str(GENERATED_MODULE_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=["_license_client_embedded_build_config"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "deploy",
        "license_server",
        "payment",
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
