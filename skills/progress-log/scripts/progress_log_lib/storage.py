"""Progress-log POSIX storage."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .model import EXIT_CONFLICT, EXIT_PATH, EXIT_USAGE, EXIT_WRITE, Failure

MAX_DOCUMENT_BYTES = 1_048_576
MAX_RELATIVE_PATH_BYTES = 1_024
MAX_RELATIVE_PATH_DEPTH = 32
_READ_CHUNK = 65_536


@dataclass(frozen=True)
class Snapshot:
    digest: str
    mode: int
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    links: int


def _path_failure(message: str) -> Failure:
    return Failure(message, EXIT_PATH)


def validate_repo_root(path: Path) -> Path:
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise _path_failure("progress-log requires macOS or Linux")
    if not isinstance(path, Path):
        raise _path_failure("repository root must be a filesystem path")
    selected = path.expanduser().absolute()
    try:
        selected_info = selected.lstat()
    except OSError:
        raise _path_failure("repository root is unavailable") from None
    if stat.S_ISLNK(selected_info.st_mode) or not stat.S_ISDIR(selected_info.st_mode):
        raise _path_failure("repository root must be one real directory")
    try:
        root = selected.resolve(strict=True)
        resolved_info = root.lstat()
    except OSError:
        raise _path_failure("repository root cannot be resolved") from None
    if stat.S_ISLNK(resolved_info.st_mode) or not stat.S_ISDIR(resolved_info.st_mode):
        raise _path_failure("repository root must resolve to one real directory")
    if (selected_info.st_dev, selected_info.st_ino) != (
        resolved_info.st_dev,
        resolved_info.st_ino,
    ):
        raise _path_failure("repository root changed while it was selected")
    return root


def _relative_text(relative: str | Path) -> str:
    if isinstance(relative, Path):
        value = relative.as_posix()
    elif isinstance(relative, str):
        value = relative
    else:
        raise _path_failure("document path must be repository-relative text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _path_failure("document path is not valid UTF-8") from None
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
        raise _path_failure("document path is not a safe repository-relative path")
    return value


def safe_document_path(
    root: Path, relative: str | Path, allow_missing: bool = True
) -> Path:
    canonical = validate_repo_root(root)
    value = _relative_text(relative)
    parts = PurePosixPath(value).parts
    cursor = canonical
    for index, part in enumerate(parts):
        cursor /= part
        final = index == len(parts) - 1
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                return canonical.joinpath(*parts)
            raise _path_failure("document path is missing") from None
        except OSError:
            raise _path_failure("cannot inspect document path") from None
        if stat.S_ISLNK(info.st_mode):
            raise _path_failure("document path contains a symbolic link")
        if not final:
            if not stat.S_ISDIR(info.st_mode):
                raise _path_failure("document path ancestor is not a directory")
            continue
        if not stat.S_ISREG(info.st_mode):
            raise _path_failure("document path is not a regular file")
        if info.st_nlink != 1:
            raise _path_failure("document path is multiply linked")
    return cursor


def _regular_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _snapshot(data: bytes, info: os.stat_result) -> Snapshot:
    return Snapshot(
        hashlib.sha256(data).hexdigest(),
        stat.S_IMODE(info.st_mode),
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def resolve_user_path(root_value: Path, root: Path, path: Path) -> Path:
    """Map root aliases; checked I/O rejects any unusable result."""
    selected = path
    try:
        selected = path.expanduser()
        if not selected.is_absolute():
            selected = Path.cwd() / selected
        alias = root_value.expanduser()
        if not alias.is_absolute():
            alias = Path.cwd() / alias
        if ".." in selected.parts:
            return selected
        if selected.is_relative_to(alias):
            return root.joinpath(*selected.relative_to(alias).parts)
        if selected.is_relative_to(root):
            return selected
        return selected.parent.resolve(strict=True) / selected.name
    except (OSError, RuntimeError):
        # Downstream _checked_path rejects unresolved or unsafe results.
        return selected


def _checked_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise _path_failure("document path contains unsafe traversal")
    try:
        selected = path.expanduser()
        if not selected.is_absolute():
            selected = Path.cwd() / selected
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
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _path_failure(
            "document must be one regular file, not a link or special file"
        )
    if before.st_nlink != 1:
        raise _path_failure("document must not have multiple hard links")
    if stat.S_IMODE(before.st_mode) & ~0o777:
        raise _path_failure("document has unsupported special mode bits")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise _path_failure(f"document exceeds {MAX_DOCUMENT_BYTES} UTF-8 bytes")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _path_failure("cannot open document safely") from None
    try:
        opened = os.fstat(descriptor)
        if _regular_identity(before) != _regular_identity(opened):
            raise Failure("document changed while it was opened", EXIT_CONFLICT)
        chunks = bytearray()
        while len(chunks) <= MAX_DOCUMENT_BYTES:
            amount = min(_READ_CHUNK, MAX_DOCUMENT_BYTES + 1 - len(chunks))
            chunk = os.read(descriptor, amount)
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if len(chunks) > MAX_DOCUMENT_BYTES:
            raise _path_failure(f"document exceeds {MAX_DOCUMENT_BYTES} UTF-8 bytes")
        if (
            _regular_identity(opened) != _regular_identity(after)
            or len(chunks) != after.st_size
        ):
            raise Failure("document changed while it was read", EXIT_CONFLICT)
        data = bytes(chunks)
        return data, _snapshot(data, after)
    finally:
        os.close(descriptor)


def _open_directory(path: Path) -> int:
    path = _checked_path(path / "unused").parent
    before = path.lstat()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _path_failure("cannot open repository directory safely") from None
    after = os.fstat(descriptor)
    if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (
        after.st_dev,
        after.st_ino,
    ):
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
    # Lock the directory so crashes leave no lockfile residue.
    descriptor = _open_directory(canonical)
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + float(timeout)
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                acquired = True
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
        if acquired:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def atomic_replace(
    path: Path,
    data: bytes,
    expected: Snapshot | None,
    mode: int | None = None,
) -> Snapshot:
    if not isinstance(path, Path) or not isinstance(data, bytes):
        raise Failure("atomic replacement requires a path and bytes", EXIT_USAGE)
    path = _checked_path(path)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise Failure(f"replacement exceeds {MAX_DOCUMENT_BYTES} bytes", EXIT_WRITE)
    selected_mode = expected.mode if expected is not None and mode is None else mode
    if selected_mode is None:
        selected_mode = 0o644
    if not isinstance(selected_mode, int) or selected_mode < 0 or selected_mode > 0o777:
        raise Failure("replacement mode must contain only permission bits", EXIT_USAGE)

    parent_info = path.parent.lstat()
    directory = _open_directory(path.parent)
    opened_parent = os.fstat(directory)
    if (parent_info.st_dev, parent_info.st_ino) != (
        opened_parent.st_dev,
        opened_parent.st_ino,
    ):
        os.close(directory)
        raise _path_failure("document parent changed before replacement")

    descriptor = -1
    temporary: Path | None = None
    try:
        try:
            descriptor, raw_name = tempfile.mkstemp(
                prefix=f".{path.name}.tmp-", dir=path.parent
            )
            temporary = Path(raw_name)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OSError("short write while staging replacement")
                offset += written
            os.fchmod(descriptor, selected_mode)
            os.fsync(descriptor)
        except OSError:
            raise Failure("cannot stage replacement", EXIT_WRITE) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1

        _, current = read_snapshot(path, missing_ok=True)
        if current != expected:
            raise Failure("document changed before replacement", EXIT_CONFLICT)
        try:
            os.replace(temporary, path)
            temporary = None
        except OSError:
            raise _classify_post_replace_failure(
                path,
                data,
                selected_mode,
                expected,
                "replacement could not be installed; destination is unchanged",
                "replacement installed, but durability is unconfirmed",
                "replacement state is ambiguous after installation failure",
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
                path,
                data,
                selected_mode,
                expected,
                "replacement verification failed; destination is unchanged",
                "replacement installed, but post-install verification failed",
                "replacement state is ambiguous after post-install verification failure",
            ) from None

        try:
            os.fsync(directory)
        except OSError:
            raise _classify_post_replace_failure(
                path,
                data,
                selected_mode,
                expected,
                "directory sync failed; destination is unchanged",
                "replacement installed, but directory sync failed",
                "replacement state is ambiguous after directory sync failure",
            ) from None
        return installed
    finally:
        if descriptor >= 0:
            os.close(descriptor)
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
    unchanged_message: str,
    installed_message: str,
    ambiguous_message: str,
) -> Failure:
    try:
        installed_data, installed = read_snapshot(path, missing_ok=True)
    except Failure:
        return Failure(ambiguous_message, EXIT_WRITE, changed=None)
    if installed == expected:
        return Failure(unchanged_message, EXIT_WRITE, changed=False)
    if installed is not None and installed_data == data and installed.mode == mode:
        return Failure(installed_message, EXIT_WRITE, changed=True)
    return Failure(ambiguous_message, EXIT_WRITE, changed=None)
