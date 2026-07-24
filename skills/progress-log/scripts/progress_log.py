#!/usr/bin/env -S python3 -I -S -B
import sys

_EXIT_POLICY = 76


def _refuse(message: str) -> "NoReturn":
    sys.stderr.write(f"progress-log: {message}\n")
    raise SystemExit(_EXIT_POLICY)


if sys.version_info < (3, 11):
    _refuse("Python 3.11+ is required")
if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.safe_path
):
    _refuse("run with python3 -I -S -B")

import os  # noqa: E402
import stat  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import NoReturn  # noqa: E402

if os.name != "posix" or (
    sys.platform != "darwin" and not sys.platform.startswith("linux")
):
    _refuse("progress-log requires macOS or Linux")


def _validate_runtime() -> Path:
    expected = {
        "__init__.py",
        "commands.py",
        "format.py",
        "git_support.py",
        "model.py",
        "storage.py",
    }
    script = Path(__file__).absolute()
    package = script.parent / "progress_log_lib"
    try:
        script_info = script.lstat()
        package_info = package.lstat()
        if (
            not stat.S_ISREG(script_info.st_mode)
            or script_info.st_nlink != 1
            or not stat.S_ISDIR(package_info.st_mode)
            or stat.S_ISLNK(package_info.st_mode)
        ):
            _refuse("installed runtime boundary is unsafe")
        found: set[str] = set()
        with os.scandir(package) as entries:
            for entry in entries:
                if entry.name not in expected or entry.name in found:
                    _refuse("installed runtime boundary is unsafe")
                found.add(entry.name)
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    _refuse("installed runtime boundary is unsafe")
        if found != expected:
            _refuse("installed runtime boundary is unsafe")
    except OSError:
        _refuse("installed runtime boundary is unavailable")
    return script.parent


sys.path.insert(0, str(_validate_runtime()))

try:
    from progress_log_lib.commands import main  # noqa: E402
except Exception:
    _refuse("installed runtime could not be loaded")


if __name__ == "__main__":
    raise SystemExit(main())
