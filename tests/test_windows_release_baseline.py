import struct
import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PNG = ROOT / "assets" / "branding" / "whut_campus_auto_login_icon_source.png"
WINDOWS_ICO = ROOT / "assets" / "windows" / "whut_campus_auto_login.ico"
REQUIRED_ICON_SIZES = {16, 24, 32, 48, 64, 128, 256}


def test_release_icon_assets_have_required_png_and_ico_structure():
    png = SOURCE_PNG.read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    width, height = struct.unpack(">II", png[16:24])
    assert width >= 256
    assert height >= 256
    assert png[25] in {4, 6}

    ico = WINDOWS_ICO.read_bytes()
    reserved, image_type, image_count = struct.unpack_from("<HHH", ico)
    assert (reserved, image_type, image_count) == (0, 1, 7)
    dimensions = set()
    for index in range(image_count):
        offset = 6 + (16 * index)
        width_byte, height_byte = struct.unpack_from("<BB", ico, offset)
        image_width = width_byte or 256
        image_height = height_byte or 256
        image_size, image_offset = struct.unpack_from("<II", ico, offset + 8)
        assert image_width == image_height
        assert image_size > 0
        assert image_offset + image_size <= len(ico)
        dimensions.add(image_width)
    assert dimensions == REQUIRED_ICON_SIZES


def test_app_version_is_single_source_and_maps_to_windows_tuple():
    app_version = importlib.import_module("app_version")
    constants = importlib.import_module("license_client.constants")

    assert app_version.APP_VERSION == "0.1.0"
    assert constants.APP_VERSION is app_version.APP_VERSION
    assert app_version.windows_version_tuple("0.1.0") == (0, 1, 0, 0)
    assert app_version.windows_version_tuple("0.0.0") == (0, 0, 0, 0)


@pytest.mark.parametrize(
    "version",
    [
        "1.2",
        "1.2.3.4",
        "1..3",
        "1.2.beta",
        "1.2.3-alpha",
        " 1.2.3",
        "1.2.3 ",
        "-1.2.3",
        "65536.2.3",
    ],
)
def test_windows_version_tuple_rejects_invalid_versions(version):
    app_version = importlib.import_module("app_version")

    with pytest.raises(ValueError, match="version"):
        app_version.windows_version_tuple(version)


def test_windows_version_info_is_unicode_parseable_and_deterministic(tmp_path):
    generator = importlib.import_module("scripts.generate_windows_version_info")
    output_path = tmp_path / "generated" / "windows_version_info.txt"

    assert generator.main(["--output", str(output_path)]) == 0
    first = output_path.read_text(encoding="utf-8")
    assert generator.main(["--output", str(output_path)]) == 0
    second = output_path.read_text(encoding="utf-8")

    assert first == second
    assert "filevers=(0, 1, 0, 0)" in first
    assert "prodvers=(0, 1, 0, 0)" in first
    for field, value in {
        "ProductName": "武汉理工校园网助手",
        "FileDescription": "武汉理工校园网自动登录工具",
        "InternalName": "WHUTCampusAutoLogin",
        "OriginalFilename": "WHUTCampusAutoLogin.exe",
        "ProductVersion": "0.1.0",
        "FileVersion": "0.1.0",
        "LegalCopyright": "Copyright © 2026 Caesar843",
    }.items():
        assert f"StringStruct({field!r}, {value!r})" in first
    assert "CompanyName" not in first
    assert "StringTable('080404B0'" in first
    assert "VarStruct('Translation', [2052, 1200])" in first

    from PyInstaller.utils.win32.versioninfo import (
        VSVersionInfo,
        load_version_info_from_text_file,
    )

    assert isinstance(load_version_info_from_text_file(output_path), VSVersionInfo)
    assert not list(output_path.parent.glob("*.tmp"))


def test_windows_build_baseline_and_direct_requirement_are_exact():
    baseline = json.loads(
        (ROOT / "packaging" / "windows" / "build_baseline.json").read_text(
            encoding="utf-8"
        )
    )
    assert baseline == {
        "python_version": "3.11.9",
        "pyinstaller_version": "6.21.0",
        "packaging_mode": "onedir",
        "lock_file": "requirements-windows-build.lock.txt",
    }
    requirements = (ROOT / "requirements-build.txt").read_text(encoding="utf-8").splitlines()
    assert requirements == ["-r requirements-client.txt", "pyinstaller==6.21.0"]


def test_committed_windows_lock_is_exact_complete_and_normalized_sorted():
    from scripts.verify_windows_build_environment import (
        normalize_package_name,
        parse_lock_file,
    )

    lock_text = (ROOT / "requirements-windows-build.lock.txt").read_text(
        encoding="utf-8"
    )
    locked = parse_lock_file(lock_text)
    names = [normalize_package_name(line.split("==", 1)[0]) for line in lock_text.splitlines()]

    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert locked["pyinstaller"] == "6.21.0"
    assert locked["pyside6"] == "6.11.1"
    assert "pytest" not in locked
    assert locked["cryptography"] == "48.0.1"
    assert locked["requests"] == "2.34.2"
    assert {"pyside6-addons", "pyside6-essentials", "shiboken6"} <= set(locked)


def test_windows_release_sop_documents_reproducible_baseline_without_real_inputs():
    checklist = (ROOT / "docs" / "test" / "WINDOWS_BUILD_CHECKLIST.md").read_text(
        encoding="utf-8"
    )
    release_sop = (ROOT / "docs" / "release" / "WINDOWS_RELEASE_BUILD.md").read_text(
        encoding="utf-8"
    )
    combined = checklist + release_sop

    for expected in (
        "Python 3.11.9",
        "PyInstaller 6.21.0",
        "onedir",
        "APP_VERSION 0.1.0",
        "requirements-windows-build.lock.txt",
        "verify_windows_build_environment.py",
        "https://example.invalid",
        "<production-public-key>",
        "P6-A1c",
    ):
        assert expected in combined
    assert "license.whutlogin.cn" not in combined
    assert "bit-for-bit reproducible" not in combined
    assert "WHUTCampusAutoLogin.spec" in combined
    assert "不能直接运行" in combined


def test_windows_release_sop_keeps_server_dependencies_out_of_build_venv():
    release_sop = (ROOT / "docs" / "release" / "WINDOWS_RELEASE_BUILD.md").read_text(
        encoding="utf-8"
    )

    assert "tests\\campus_login tests\\client tests\\license_client" in release_sop
    assert "--ignore=tests\\client\\test_payment_flow.py" in release_sop
    assert "完整仓库测试需要另行安装 requirements-server.txt" in release_sop
