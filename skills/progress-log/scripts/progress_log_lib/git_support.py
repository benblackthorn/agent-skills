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
    r"(?:[ .+(\-][ -~]{0,79})?"
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


def _policy(message: str) -> Failure:
    return Failure(message, EXIT_POLICY)


def _inside(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _resolve_git(root: Path) -> ResolvedGit:
    raw_path = os.environ.get("PATH")
    if raw_path is None:
        raise _policy("PATH is required to select Git safely")
    directories: list[Path] = []
    executable: Path | None = None
    for value in raw_path.split(os.pathsep):
        if not value or not Path(value).is_absolute():
            continue
        selected = Path(value)
        try:
            canonical = selected.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            not canonical.is_dir()
            or _inside(selected, root)
            or _inside(canonical, root)
        ):
            continue
        candidate = canonical / "git"
        target = None
        try:
            candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            continue
        else:
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
        if executable is None and target is not None:
            executable = target

    if executable is None:
        raise _policy(
            "no safe Git 2.45+ executable was found in PATH; unsafe candidates were filtered"
        )
    return ResolvedGit(executable, os.pathsep.join(str(path) for path in directories))


def _git_environment(resolved: ResolvedGit) -> dict[str, str]:
    return {
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
        "PATH": resolved.path,
    }


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
    allow_one: bool = False,
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
        raise _policy("Git 2.45+ is unavailable") from None
    if process.stdout is None or process.stderr is None:
        raise _policy("Git pipe setup failed")
    stdout = bytearray()
    streams = (
        (process.stdout, stdout, stdout_limit),
        (process.stderr, bytearray(), MAX_DIAGNOSTIC_OUTPUT),
    )
    selector = selectors.DefaultSelector()
    try:
        for stream, output, limit in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (stream, output, limit))
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, GIT_TIMEOUT_SECONDS)
            for key, _ in selector.select(min(remaining, 0.25)):
                stream, output, limit = key.data
                amount = max(1, min(65_536, limit + 1 - len(output)))
                try:
                    chunk = os.read(stream.fileno(), amount)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    _terminate(process)
                    raise _policy("Git compaction proof exceeded its output bound")
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _terminate(process)
        raise _policy("Git compaction proof timed out") from None
    finally:
        selector.close()
        for stream, _, _ in streams:
            if not stream.closed:
                stream.close()
    if returncode == 1 and allow_one:
        return bytes(stdout)
    if returncode != 0:
        raise _policy("Git 2.45+ cannot verify the requested repository data")
    return bytes(stdout)


def _one_line(output: bytes, label: str, *, filesystem: bool = False) -> str:
    value = output.removesuffix(b"\n")
    if not value or b"\n" in value or b"\r" in value or b"\0" in value:
        raise _policy(f"Git returned an invalid {label}")
    if filesystem:
        return os.fsdecode(value)
    try:
        return value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise _policy(f"Git returned an invalid {label}") from None


def _validate_git_version(output: bytes) -> None:
    value = _one_line(output, "version")
    match = _GIT_VERSION_RE.fullmatch(value)
    if match is None:
        raise _policy("Git 2.45+ returned an invalid version")
    version = tuple(int(part or "0") for part in match.groups())
    if version < (2, 45, 0):
        raise _policy("Git 2.45+ is required")


def _head_oid(root: Path) -> str:
    value = _one_line(
        _run_git(root, "rev-parse", "--verify", "HEAD^{commit}"), "HEAD identity"
    )
    if _OID_RE.fullmatch(value) is None:
        raise _policy("Git returned an invalid HEAD identity")
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
        raise _policy("Git returned an invalid repository root") from None
    if top != canonical:
        raise _policy("selected root is not the Git repository root")


def assert_head(root: Path, oid: str) -> None:
    canonical = validate_repo_root(root)
    if not isinstance(oid, str) or _OID_RE.fullmatch(oid) is None:
        raise Failure("captured HEAD identity is invalid", EXIT_USAGE)
    assert_git_root(canonical)
    if _head_oid(canonical) != oid:
        raise Failure("Git HEAD changed during compaction", EXIT_CONFLICT)


def assert_clean_worktree(root: Path) -> None:
    canonical = validate_repo_root(root)
    assert_git_root(canonical)
    output = _run_git(
        canonical,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=normal",
    )
    if output:
        raise _policy("migration requires a clean integration worktree")


def _ref_oid(root: Path, reference: str, label: str) -> str:
    try:
        output = _run_git(root, "show-ref", "--verify", "--hash", reference)
    except Failure:
        raise _policy(f"{label} is not locally available") from None
    value = _one_line(output, f"{label} identity")
    if _OID_RE.fullmatch(value) is None:
        raise _policy(f"Git returned an invalid {label} identity")
    return value


def _local_branch(root: Path) -> str:
    try:
        branch = _one_line(
            _run_git(root, "symbolic-ref", "--quiet", "HEAD"),
            "local branch",
            filesystem=True,
        )
    except Failure:
        raise _policy("migration requires a real local branch") from None
    if not branch.startswith("refs/heads/"):
        raise _policy("migration requires a real local branch")
    return branch


def _local_configured(root: Path, key: str) -> bool:
    output = _run_git(
        root,
        "config",
        "--local",
        "--includes",
        "--get",
        key,
        allow_one=True,
    )
    return bool(output and _one_line(output, "branch configuration", filesystem=True))


def assert_no_divergence_branch(root: Path, expected_oid: str) -> None:
    canonical = validate_repo_root(root)
    if _OID_RE.fullmatch(expected_oid) is None:
        raise Failure("captured HEAD identity is invalid", EXIT_USAGE)
    assert_git_root(canonical)
    branch = _local_branch(canonical)
    short_branch = branch.removeprefix("refs/heads/")
    remote_configured = _local_configured(canonical, f"branch.{short_branch}.remote")
    if remote_configured != _local_configured(
        canonical, f"branch.{short_branch}.merge"
    ):
        raise _policy("migration branch has incomplete upstream configuration")
    upstream: str | None = None
    if remote_configured:
        try:
            upstream = _one_line(
                _run_git(
                    canonical,
                    "rev-parse",
                    "--verify",
                    "--symbolic-full-name",
                    "@{upstream}",
                ),
                "upstream",
                filesystem=True,
            )
        except Failure:
            raise _policy("configured upstream is not locally available") from None
        if not upstream.startswith(("refs/heads/", "refs/remotes/")):
            raise _policy("Git returned an invalid configured upstream")
        if _ref_oid(canonical, upstream, "configured upstream") != expected_oid:
            raise _policy(
                "migration requires local HEAD to equal its locally available upstream"
            )
    if (
        _local_branch(canonical) != branch
        or _ref_oid(canonical, branch, "local branch") != expected_oid
        or (
            upstream is not None
            and _ref_oid(canonical, upstream, "configured upstream") != expected_oid
        )
    ):
        raise _policy("Git branch topology changed during migration proof")


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
        raise _policy("progress log is missing or ambiguous in raw Git HEAD")
    try:
        metadata, path = output[:-1].split(b"\t", 1)
        mode, object_type, blob_oid = metadata.split(b" ", 2)
    except ValueError:
        raise _policy("Git returned an invalid tree entry") from None
    if path != relative.encode("utf-8"):
        raise _policy("Git returned an unexpected tree path")
    if object_type != b"blob" or mode not in {b"100644", b"100755"}:
        raise _policy("Git HEAD path is not a regular file")
    try:
        oid_text = blob_oid.decode("ascii")
    except UnicodeDecodeError:
        raise _policy("Git returned an invalid tree entry") from None
    if _OID_RE.fullmatch(oid_text) is None:
        raise _policy("Git returned an invalid blob identity")
    return oid_text, mode.decode()


def _blob_data(root: Path, blob_oid: str, *, base: bool) -> bytes:
    label = "base " if base else ""
    raw = _one_line(_run_git(root, "cat-file", "-s", blob_oid), f"{label}blob size")
    if not raw.isdecimal():
        raise _policy(f"Git returned an invalid {label}blob size")
    size = int(raw)
    source = "base" if base else "Git HEAD"
    if size > MAX_DOCUMENT_BYTES:
        raise _policy(f"{source} progress log exceeds the read bound")
    data = _run_git(root, "cat-file", "blob", blob_oid, stdout_limit=MAX_DOCUMENT_BYTES)
    if len(data) != size:
        source = "base log" if base else "raw HEAD"
        raise _policy(f"Git returned incomplete {source} bytes")
    return data


def load_head_log(root: Path, relative: str = "progress-log.md") -> HeadLog:
    canonical = validate_repo_root(root)
    safe_document_path(canonical, relative, allow_missing=True)
    assert_git_root(canonical)
    head_oid = _head_oid(canonical)
    blob_oid, mode_text = _tree_entry(canonical, head_oid, relative)
    data = _blob_data(canonical, blob_oid, base=False)
    assert_head(canonical, head_oid)
    return HeadLog(head_oid, blob_oid, data, int(mode_text[-3:], 8))


def load_commit_log(root: Path, oid: str, relative: str = "progress-log.md") -> HeadLog:
    canonical = validate_repo_root(root)
    safe_document_path(canonical, relative, allow_missing=True)
    if not isinstance(oid, str) or _OID_RE.fullmatch(oid) is None:
        raise Failure(
            "base commit must be one full lowercase 40- or 64-hex object ID",
            EXIT_USAGE,
        )
    assert_git_root(canonical)
    object_type = _one_line(
        _run_git(canonical, "cat-file", "-t", oid), "base object type"
    )
    if object_type != "commit":
        raise _policy("base object ID does not identify a commit")
    blob_oid, mode_text = _tree_entry(canonical, oid, relative)
    data = _blob_data(canonical, blob_oid, base=True)
    return HeadLog(oid, blob_oid, data, int(mode_text[-3:], 8))
