import errno
import fcntl
import hashlib
import os
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .model import EXIT_CONFLICT, EXIT_PATH, EXIT_USAGE, EXIT_WRITE, Failure

MAX_DOCUMENT_BYTES = 1_048_576
MAX_RELATIVE_PATH_BYTES = 1_024
MAX_RELATIVE_PATH_DEPTH = 32


@dataclass(frozen=True)
class Snapshot:
    digest: str
    mode: int
    identity: tuple[int, ...]


def _path_failure(message: str) -> Failure:
    return Failure(message, EXIT_PATH)


def _inode(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _absolute(path: Path) -> Path:
    selected = path.expanduser()
    return selected if selected.is_absolute() else Path.cwd() / selected


def validate_repo_root(path: Path) -> Path:
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise _path_failure("progress-log requires macOS or Linux")
    if not isinstance(path, Path):
        raise _path_failure("repository root must be a filesystem path")
    selected = path.expanduser().absolute()
    try:
        selected_info = selected.lstat()
        root = selected.resolve(strict=True)
        resolved_info = root.lstat()
    except OSError:
        raise _path_failure("repository root is unavailable") from None
    if (
        stat.S_ISLNK(selected_info.st_mode)
        or not stat.S_ISDIR(selected_info.st_mode)
        or stat.S_ISLNK(resolved_info.st_mode)
        or not stat.S_ISDIR(resolved_info.st_mode)
        or _inode(selected_info) != _inode(resolved_info)
    ):
        raise _path_failure("repository root is not one stable real directory")
    return root


def _relative_text(relative: str | Path) -> str:
    if not isinstance(relative, (str, Path)):
        raise _path_failure("document path must be repository-relative text")
    value = relative.as_posix() if isinstance(relative, Path) else relative
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _path_failure("document path is unsafe") from None
    path = PurePosixPath(value)
    if (
        not value
        or len(encoded) > MAX_RELATIVE_PATH_BYTES
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or len(path.parts) > MAX_RELATIVE_PATH_DEPTH
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _path_failure("document path is unsafe")
    return value


def safe_document_path(
    root: Path, relative: str | Path, allow_missing: bool = True
) -> Path:
    canonical = validate_repo_root(root)
    value = _relative_text(relative)
    parts = PurePosixPath(value).parts
    target = canonical.joinpath(*parts)
    cursor = canonical
    for index, part in enumerate(parts):
        cursor /= part
        final = index == len(parts) - 1
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                return target
            raise _path_failure("document path is missing") from None
        except OSError:
            raise _path_failure("cannot inspect document path") from None
        if (
            stat.S_ISLNK(info.st_mode)
            or (not final and not stat.S_ISDIR(info.st_mode))
            or (final and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
        ):
            raise _path_failure("document path is linked or has the wrong file type")
    return cursor


def safe_scope_directory(root: Path, scope: str) -> Path:
    canonical = validate_repo_root(root)
    if scope == ".":
        return canonical
    value = _relative_text(scope)
    parts = PurePosixPath(value).parts
    cursor = canonical
    for part in parts:
        cursor /= part
        try:
            before = cursor.lstat()
        except OSError:
            raise _path_failure(f"active scope is unavailable: {scope}") from None
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise _path_failure(f"active scope is not a real directory: {scope}")
    try:
        resolved = cursor.resolve(strict=True)
        after = resolved.lstat()
    except OSError:
        raise _path_failure(f"active scope is unavailable: {scope}") from None
    if (
        resolved != cursor
        or stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or _inode(before) != _inode(after)
    ):
        raise _path_failure(f"active scope changed while selected: {scope}")
    return cursor


def scope_directory_identity(root: Path, scope: str) -> tuple[int, int]:
    path = safe_scope_directory(root, scope)
    try:
        before = path.lstat()
        safe_scope_directory(root, scope)
        after = path.lstat()
    except OSError:
        raise _path_failure(f"active scope is unavailable: {scope}") from None
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or _inode(before) != _inode(after)
    ):
        raise _path_failure(f"active scope changed while selected: {scope}")
    return _inode(after)


def _regular_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        *_inode(info),
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def regular_file_identity(path: Path) -> tuple[int, ...]:
    path = _checked_path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise _path_failure("document is missing") from None
    except OSError:
        raise _path_failure("cannot inspect document") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & ~0o777
    ):
        raise _path_failure("document is not one safe regular file")
    return _regular_identity(info)


def resolve_user_path(root_value: Path, root: Path, path: Path) -> Path:
    selected = path
    try:
        selected = _absolute(path)
        alias = _absolute(root_value)
        if ".." in selected.parts:
            return selected
        if selected.is_relative_to(alias):
            return root.joinpath(*selected.relative_to(alias).parts)
        if selected.is_relative_to(root):
            return selected
        return selected.parent.resolve(strict=True) / selected.name
    except (OSError, RuntimeError):
        return selected


def _checked_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise _path_failure("document path contains unsafe traversal")
    try:
        selected = _absolute(path)
    except (OSError, RuntimeError):
        raise _path_failure("document path cannot be made absolute") from None
    if ".." in selected.parts:
        raise _path_failure("document path contains unsafe traversal")
    cursor = Path(selected.anchor)
    try:
        for part in selected.parent.parts[1:]:
            cursor /= part
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise _path_failure(
                    "document path contains a linked or non-directory parent"
                )
    except FileNotFoundError:
        raise _path_failure("document parent is unavailable") from None
    except OSError:
        raise _path_failure("cannot inspect document parent") from None
    return selected


def read_snapshot(
    path: Path, missing_ok: bool = False
) -> tuple[bytes | None, Snapshot | None]:
    if not isinstance(path, Path):
        raise _path_failure("document must be a filesystem path")
    path = _checked_path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise _path_failure("document is missing") from None
    except OSError:
        raise _path_failure("cannot inspect document") from None
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & ~0o777
    ):
        raise _path_failure("document is not one safe regular file")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise _path_failure(f"document exceeds {MAX_DOCUMENT_BYTES} UTF-8 bytes")

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise _path_failure("cannot open document safely") from None
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(descriptor)
        if _regular_identity(before) != _regular_identity(opened):
            raise Failure("document changed while it was opened", EXIT_CONFLICT)
        data = source.read(MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise _path_failure(f"document exceeds {MAX_DOCUMENT_BYTES} UTF-8 bytes")
        if (
            _regular_identity(opened) != _regular_identity(after)
            or len(data) != after.st_size
        ):
            raise Failure("document changed while it was read", EXIT_CONFLICT)
        return data, Snapshot(
            hashlib.sha256(data).hexdigest(),
            stat.S_IMODE(after.st_mode),
            _regular_identity(after),
        )


def _open_directory(path: Path) -> int:
    path = _checked_path(path / "unused").parent
    before = path.lstat()
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError:
        raise _path_failure("cannot open repository directory safely") from None
    after = os.fstat(descriptor)
    if not stat.S_ISDIR(after.st_mode) or _inode(before) != _inode(after):
        os.close(descriptor)
        raise _path_failure("repository directory changed while it was opened")
    return descriptor


@contextmanager
def locked_repo(root: Path, exclusive: bool, timeout: float = 10.0) -> Iterator[Path]:
    canonical = validate_repo_root(root)
    if (
        not isinstance(exclusive, bool)
        or not isinstance(timeout, (int, float))
        or timeout < 0
    ):
        raise Failure("lock mode or timeout is invalid", EXIT_USAGE)
    descriptor = _open_directory(canonical)
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + float(timeout)
    try:
        while True:
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise Failure(
                        "cannot acquire repository lock", EXIT_WRITE
                    ) from None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure(
                        "timed out acquiring repository lock", EXIT_CONFLICT
                    ) from None
                time.sleep(min(0.025, remaining))
        yield canonical
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def atomic_replace(
    path: Path,
    data: bytes,
    expected: Snapshot | None,
    mode: int | None = None,
    pre_replace: Callable[[], None] | None = None,
) -> Snapshot:
    if not isinstance(path, Path) or not isinstance(data, bytes):
        raise Failure("atomic replacement requires a path and bytes", EXIT_USAGE)
    path = _checked_path(path)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise Failure(f"replacement exceeds {MAX_DOCUMENT_BYTES} bytes", EXIT_WRITE)
    selected_mode = mode if mode is not None else expected.mode if expected else 0o644
    if not isinstance(selected_mode, int) or not 0 <= selected_mode <= 0o777:
        raise Failure("replacement mode must contain only permission bits", EXIT_USAGE)
    parent_info = path.parent.lstat()
    directory = _open_directory(path.parent)
    opened_parent = os.fstat(directory)
    if _inode(parent_info) != _inode(opened_parent):
        os.close(directory)
        raise _path_failure("document parent changed before replacement")

    temporary: Path | None = None
    try:
        try:
            descriptor, raw_name = tempfile.mkstemp(
                prefix=f".{path.name}.tmp-", dir=path.parent
            )
            temporary = Path(raw_name)
            with os.fdopen(descriptor, "wb") as staging:
                if staging.write(data) != len(data):
                    raise OSError("short write while staging replacement")
                staging.flush()
                os.fchmod(descriptor, selected_mode)
                os.fsync(descriptor)
        except OSError:
            raise Failure("cannot stage replacement", EXIT_WRITE) from None

        _, current = read_snapshot(path, missing_ok=True)
        if current != expected:
            raise Failure("document changed before replacement", EXIT_CONFLICT)
        if pre_replace is not None:
            pre_replace()
        try:
            os.replace(temporary, path)
            temporary = None
        except OSError:
            raise _classify_post_replace_failure(
                path, data, selected_mode, expected, "installation"
            ) from None

        try:
            installed_data, installed = read_snapshot(path)
            if (
                installed is None
                or installed_data != data
                or installed.mode != selected_mode
            ):
                raise Failure(
                    "installed replacement did not match intended content", EXIT_WRITE
                )
        except Failure:
            raise _classify_post_replace_failure(
                path, data, selected_mode, expected, "verification"
            ) from None

        try:
            os.fsync(directory)
        except OSError:
            raise _classify_post_replace_failure(
                path, data, selected_mode, expected, "directory sync"
            ) from None
        return installed
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()
            with suppress(OSError):
                os.fsync(directory)
        os.close(directory)


def _classify_post_replace_failure(
    path: Path,
    data: bytes,
    mode: int,
    expected: Snapshot | None,
    phase: str,
) -> Failure:
    try:
        installed_data, installed = read_snapshot(path, missing_ok=True)
    except Failure:
        return Failure(
            f"replacement state is ambiguous after {phase} failure",
            EXIT_WRITE,
            changed=None,
        )
    if installed == expected:
        changed: bool | None = False
        state = "destination is unchanged"
    elif installed is not None and installed_data == data and installed.mode == mode:
        changed = True
        state = "replacement installed"
    else:
        changed = None
        state = "replacement state is ambiguous"
    return Failure(f"{state} after {phase} failure", EXIT_WRITE, changed=changed)
