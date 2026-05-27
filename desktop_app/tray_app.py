import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_app.tray.runtime import run_tray_app


def main() -> int:
    return run_tray_app(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
