import os
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_tray_app_entry_can_import_when_loaded_by_script_path(tmp_path):
    script_path = PROJECT_ROOT / "desktop_app" / "tray_app.py"
    command = (
        "import runpy, sys; "
        f"script = r'{script_path}'; "
        f"root = r'{PROJECT_ROOT}'; "
        "script_dir = __import__('pathlib').Path(script).parent.as_posix(); "
        "sys.path = [script_dir, *[p for p in sys.path if p not in ('', root)]]; "
        "runpy.run_path(script, run_name='tray_app_path_import'); "
        "print('import-ok')"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [sys.executable, "-c", command],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "import-ok" in completed.stdout
