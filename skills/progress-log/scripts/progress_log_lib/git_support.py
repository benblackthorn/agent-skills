"""Raw-Git compaction proof."""

from __future__ import annotations

import os
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .model import EXIT_CONFLICT, EXIT_POLICY, EXIT_USAGE, Failure
from .storage import MAX_DOCUMENT_BYTES, safe_document_path, validate_repo_root

MAX_CONTROL_OUTPUT = 65_536
MAX_DIAGNOSTIC_OUTPUT = 65_536
GIT_TIMEOUT_SECONDS = 20.0
_OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_GIT_VERSION_RE = re.compile(
    r"git version ([0-9]{1,4})\.([0-9]{1,4})(?:\.([0-9]{1,4}))?"
)


@dataclass(frozen=True)
class HeadLog:
    oid: str
    blob_oid: str
    data: bytes
    mode: int


@dataclass(frozen=True)
class ResolvedGit:
    executable: Path
    path: str


def _inside(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _resolve_git(root: Path) -> ResolvedGit:
    raw_path = os.environ.get("PATH")
    if raw_path is None:
        raise Failure("PATH is required to select Git safely", EXIT_POLICY)
    entries = raw_path.split(os.pathsep)

    directories: list[Path] = []
    executable: Path | None = None
    for value in entries:
        if not value or not Path(value).is_absolute():
            continue
        selected = Path(value)
        try:
            canonical = selected.resolve(strict=True)
            directory_info = canonical.lstat()
        except (OSError, RuntimeError):
            continue
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or _inside(selected, root)
            or _inside(canonical, root)
        ):
            continue
        candidate = canonical / "git"
        try:
            candidate.lstat()
        except FileNotFoundError:
            if canonical not in directories:
                directories.append(canonical)
            continue
        except OSError:
            continue
        try:
            target = candidate.resolve(strict=True)
            target_info = target.lstat()
        except (OSError, RuntimeError):
            continue
        if (
            _inside(target, root)
            or not stat.S_ISREG(target_info.st_mode)
            or target_info.st_nlink != 1
            or not os.access(target, os.X_OK)
        ):
            continue
        if canonical not in directories:
            directories.append(canonical)
        if executable is None:
            executable = target

    if executable is None:
        raise Failure(
            "no safe Git 2.45+ executable was found in PATH; unsafe candidates were filtered",
            EXIT_POLICY,
        )
    return ResolvedGit(executable, os.pathsep.join(str(path) for path in directories))


def _git_environment(resolved: ResolvedGit) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "HOME": os.devnull,
        "XDG_CONFIG_HOME": os.devnull,
        "LC_ALL": "C",
        "LANG": "C",
    }
    environment["PATH"] = resolved.path
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_git(
    root: Path,
    *arguments: str,
    stdout_limit: int = MAX_CONTROL_OUTPUT,
    resolved: ResolvedGit | None = None,
    repository: bool = True,
) -> bytes:
    selected = resolved or _resolve_git(root)
    command = [str(selected.executable)]
    if repository:
        command.extend(
            (
                "--no-replace-objects",
                "--no-lazy-fetch",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-C",
                str(root),
            )
        )
    command.extend(arguments)
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(selected),
        )
    except OSError:
        raise Failure("Git 2.45+ is unavailable", EXIT_POLICY) from None
    if process.stdout is None or process.stderr is None:
        raise Failure("Git pipe setup failed", EXIT_POLICY)
    stdout_descriptor = process.stdout.fileno()
    streams = {
        stdout_descriptor: (process.stdout, bytearray(), stdout_limit),
        process.stderr.fileno(): (
            process.stderr,
            bytearray(),
            MAX_DIAGNOSTIC_OUTPUT,
        ),
    }
    selector = selectors.DefaultSelector()
    for descriptor, (stream, _, _) in streams.items():
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ, descriptor)
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate(process)
                raise Failure("Git compaction proof timed out", EXIT_POLICY)
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _ in events:
                descriptor = key.data
                stream, output, limit = streams[descriptor]
                amount = max(1, min(65_536, limit + 1 - len(output)))
                try:
                    chunk = os.read(descriptor, amount)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    _terminate(process)
                    raise Failure(
                        "Git compaction proof exceeded its output bound", EXIT_POLICY
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate(process)
            raise Failure("Git compaction proof timed out", EXIT_POLICY)
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        _terminate(process)
        raise Failure("Git compaction proof timed out", EXIT_POLICY) from None
    finally:
        selector.close()
        for stream, _, _ in streams.values():
            if not stream.closed:
                stream.close()
    if returncode != 0:
        raise Failure(
            "Git 2.45+ cannot verify the requested repository data", EXIT_POLICY
        )
    return bytes(streams[stdout_descriptor][1])


def _one_line(output: bytes, label: str, *, filesystem: bool = False) -> str:
    value = output.removesuffix(b"\n")
    if not value or b"\n" in value or b"\r" in value or b"\0" in value:
        raise Failure(f"Git returned an invalid {label}", EXIT_POLICY)
    if filesystem:
        return os.fsdecode(value)
    try:
        return value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise Failure(f"Git returned an invalid {label}", EXIT_POLICY) from None


def _validate_git_version(output: bytes) -> None:
    value = _one_line(output, "version")
    match = _GIT_VERSION_RE.match(value)
    if match is None:
        raise Failure("Git 2.45+ returned an invalid version", EXIT_POLICY)
    suffix = value[match.end() :]
    if suffix and (
        len(suffix) > 80
        or suffix[0] not in " .+-\u0028"
        or any(ord(character) < 32 or ord(character) > 126 for character in suffix)
    ):
        raise Failure("Git 2.45+ returned an invalid version", EXIT_POLICY)
    version = tuple(int(part or "0") for part in match.groups())
    if version < (2, 45, 0):
        raise Failure("Git 2.45+ is required", EXIT_POLICY)


def _head_oid(root: Path) -> str:
    value = _one_line(
        _run_git(root, "rev-parse", "--verify", "HEAD^{commit}"), "HEAD identity"
    )
    if _OID_RE.fullmatch(value) is None:
        raise Failure("Git returned an invalid HEAD identity", EXIT_POLICY)
    return value


def assert_git_root(root: Path) -> None:
    canonical = validate_repo_root(root)
    resolved = _resolve_git(canonical)
    _validate_git_version(
        _run_git(
            canonical,
            "--version",
            resolved=resolved,
            repository=False,
        )
    )
    output = _run_git(
        canonical,
        "rev-parse",
        "--show-toplevel",
        resolved=resolved,
    )
    try:
        top = Path(_one_line(output, "repository root", filesystem=True)).resolve(
            strict=True
        )
    except (OSError, ValueError):
        raise Failure("Git returned an invalid repository root", EXIT_POLICY) from None
    if top != canonical:
        raise Failure("selected root is not the Git repository root", EXIT_POLICY)


def assert_head(root: Path, oid: str) -> None:
    canonical = validate_repo_root(root)
    if not isinstance(oid, str) or _OID_RE.fullmatch(oid) is None:
        raise Failure("captured HEAD identity is invalid", EXIT_USAGE)
    assert_git_root(canonical)
    if _head_oid(canonical) != oid:
        raise Failure("Git HEAD changed during compaction", EXIT_CONFLICT)


def _tree_entry(root: Path, head_oid: str, relative: str) -> tuple[str, str]:
    output = _run_git(
        root,
        "ls-tree",
        "--full-tree",
        "-z",
        head_oid,
        "--",
        f":(literal){relative}",
    )
    if not output or output.count(b"\0") != 1 or not output.endswith(b"\0"):
        raise Failure(
            "progress log is missing or ambiguous in raw Git HEAD", EXIT_POLICY
        )
    try:
        metadata, path = output[:-1].split(b"\t", 1)
        mode, object_type, blob_oid = metadata.split(b" ", 2)
    except ValueError:
        raise Failure("Git returned an invalid tree entry", EXIT_POLICY) from None
    if path != relative.encode("utf-8"):
        raise Failure("Git returned an unexpected tree path", EXIT_POLICY)
    try:
        mode_text = mode.decode("ascii")
        type_text = object_type.decode("ascii")
        oid_text = blob_oid.decode("ascii")
    except UnicodeDecodeError:
        raise Failure("Git returned an invalid tree entry", EXIT_POLICY) from None
    if type_text != "blob" or mode_text not in {"100644", "100755"}:
        raise Failure("Git HEAD path is not a regular file", EXIT_POLICY)
    if _OID_RE.fullmatch(oid_text) is None:
        raise Failure("Git returned an invalid blob identity", EXIT_POLICY)
    return oid_text, mode_text


def load_head_log(root: Path, relative: str = "progress-log.md") -> HeadLog:
    canonical = validate_repo_root(root)
    safe_document_path(canonical, relative, allow_missing=True)
    assert_git_root(canonical)
    head_oid = _head_oid(canonical)
    blob_oid, mode_text = _tree_entry(canonical, head_oid, relative)

    raw_size = _one_line(_run_git(canonical, "cat-file", "-s", blob_oid), "blob size")
    if not raw_size.isdecimal():
        raise Failure("Git returned an invalid blob size", EXIT_POLICY)
    size = int(raw_size)
    if size > MAX_DOCUMENT_BYTES:
        raise Failure("Git HEAD progress log exceeds the read bound", EXIT_POLICY)
    data = _run_git(
        canonical,
        "cat-file",
        "blob",
        blob_oid,
        stdout_limit=MAX_DOCUMENT_BYTES,
    )
    if len(data) != size:
        raise Failure("Git returned incomplete raw HEAD bytes", EXIT_POLICY)
    assert_head(canonical, head_oid)
    mode = 0o644 if mode_text == "100644" else 0o755
    return HeadLog(head_oid, blob_oid, data, mode)
