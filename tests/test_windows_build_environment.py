import importlib

import pytest


def _module():
    return importlib.import_module("scripts.verify_windows_build_environment")


def _baseline():
    return {
        "python_version": "3.11.9",
        "pyinstaller_version": "6.21.0",
        "packaging_mode": "onedir",
        "lock_file": "requirements-windows-build.lock.txt",
    }


def test_lock_parser_accepts_exact_versions_and_normalizes_names():
    module = _module()

    assert module.parse_lock_file("PySide6_Essentials==6.10.2\nrequests==2.32.5\n") == {
        "pyside6-essentials": "6.10.2",
        "requests": "2.32.5",
    }
    assert module.normalize_package_name("PySide6.Essentials") == "pyside6-essentials"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "# comment",
        "requests>=2.31",
        "requests~=2.31",
        "requests @ https://example.invalid/package.whl",
        "https://example.invalid/package.whl",
        "file:///C:/packages/example.whl",
        r"C:\packages\example.whl",
        "requests==2.32.5 --hash=sha256:abc",
    ],
)
def test_lock_parser_rejects_non_exact_or_non_index_lines(line):
    module = _module()

    with pytest.raises(ValueError, match="lock"):
        module.parse_lock_file(f"{line}\n")


def test_lock_parser_rejects_duplicate_normalized_names():
    module = _module()

    with pytest.raises(ValueError, match="duplicate"):
        module.parse_lock_file("PySide6_Essentials==6.10.2\npyside6-essentials==6.10.2\n")


def test_environment_comparison_accepts_exact_lock_and_bootstrap_extras():
    module = _module()
    locked = {"pyinstaller": "6.21.0", "requests": "2.32.5"}
    installed = {
        **locked,
        "pip": "26.1.1",
        "setuptools": "65.5.0",
        "wheel": "0.46.3",
    }

    assert module.environment_errors(
        _baseline(),
        locked,
        installed,
        python_version="3.11.9",
        in_virtualenv=True,
    ) == []


def test_environment_comparison_reports_python_venv_and_package_drift_safely():
    module = _module()

    errors = module.environment_errors(
        _baseline(),
        {"pyinstaller": "6.21.0", "requests": "2.32.5", "missing_pkg": "1.0"},
        {"pyinstaller": "6.20.0", "requests": "2.31.0", "extra_pkg": "9.0"},
        python_version="3.11.8",
        in_virtualenv=False,
    )
    output = "\n".join(errors)

    for expected in (
        "Python 3.11.8",
        "virtual environment",
        "pyinstaller",
        "requests",
        "missing-pkg",
        "extra-pkg",
    ):
        assert expected in output
    for forbidden in ("http://", "https://", "PRIVATE KEY", "token=", "password="):
        assert forbidden not in output


def test_environment_comparison_rejects_baseline_and_lock_disagreement():
    module = _module()

    errors = module.environment_errors(
        _baseline(),
        {"pyinstaller": "6.20.0"},
        {"pyinstaller": "6.20.0"},
        python_version="3.11.9",
        in_virtualenv=True,
    )

    assert any("baseline" in error and "pyinstaller" in error for error in errors)
