import sys

from desktop_app.tray.runtime import run_tray_app


def main() -> int:
    return run_tray_app(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
