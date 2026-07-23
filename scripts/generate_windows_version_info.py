import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app_version import APP_VERSION, windows_version_tuple


VERSION_FIELDS = (
    ("ProductName", "武汉理工校园网助手"),
    ("FileDescription", "武汉理工校园网自动登录工具"),
    ("InternalName", "WHUTCampusAutoLogin"),
    ("OriginalFilename", "WHUTCampusAutoLogin.exe"),
    ("ProductVersion", APP_VERSION),
    ("FileVersion", APP_VERSION),
    ("LegalCopyright", "Copyright © 2026 Caesar843"),
)


def render_windows_version_info(version: str = APP_VERSION) -> str:
    version_tuple = windows_version_tuple(version)
    fields = tuple(
        (name, version if name in {"ProductVersion", "FileVersion"} else value)
        for name, value in VERSION_FIELDS
    )
    string_structs = "\n".join(
        f"          StringStruct({name!r}, {value!r})," for name, value in fields
    )
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={version_tuple!r},
    prodvers={version_tuple!r},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable('080404B0', [
{string_structs}
      ]),
    ]),
    VarFileInfo([
      VarStruct('Translation', [2052, 1200]),
    ]),
  ],
)
"""


def write_windows_version_info(output_path: Path, version: str = APP_VERSION) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(render_windows_version_info(version))
        os.replace(temporary_path, output_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Windows version metadata.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    write_windows_version_info(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
