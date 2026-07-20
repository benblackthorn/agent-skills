"""Progress-log commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from collections.abc import Iterable
from typing import NoReturn, Sequence

from .format import (
    metrics,
    parse_document,
    render_document,
    render_entry,
    validate_body,
    validate_doc_path,
    validate_key,
    validate_log_path,
    validate_title,
    validate_value,
)
from .git_support import assert_git_root, assert_head, load_head_log
from .model import (
    EXIT_COMPACT,
    EXIT_CONFLICT,
    EXIT_INTERNAL,
    EXIT_INTERRUPTED,
    EXIT_MALFORMED,
    EXIT_PATH,
    EXIT_POLICY,
    EXIT_USAGE,
    Entry,
    Failure,
    OptOut,
    ProgressLog,
)
from .storage import (
    Snapshot,
    atomic_replace,
    locked_repo,
    read_snapshot,
    resolve_user_path,
    safe_document_path,
    validate_repo_root,
)

LOG_NAME = "progress-log.md"
TARGET_BYTES = 16_384
TARGET_LINES = 200
SOFT_BYTES = 24_576
SOFT_LINES = 300
HARD_BYTES = 32_768
HARD_LINES = 500
MIN_REMAINING_ENTRIES = 1

BLOCKING_PATTERNS = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
        ),
    ),
    ("pgp-private-key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    (
        "github-token",
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    ("aws-access-key", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("gitlab-token", re.compile(r"(?:glpat|gldt|glrt)-[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("provider-token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    (
        "credential-url",
        re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@]*(?::|%3[aA])[^\s/@]*@"),
    ),
)

WARNING_PATTERNS = (
    (
        "jwt-shape",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    ("password-assignment", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+")),
)


def _scan(text: str) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    blocking: list[tuple[str, int]] = []
    warnings: list[tuple[str, int]] = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in BLOCKING_PATTERNS:
            if pattern.search(line):
                blocking.append((name, number))
        for name, pattern in WARNING_PATTERNS:
            if pattern.search(line):
                warnings.append((name, number))
    return blocking, warnings


def _enforce_secret_policy(text: str, *, emit_warnings: bool = True) -> None:
    blocking, warnings = _scan(text)
    if blocking:
        detector, line = blocking[0]
        raise Failure(
            f"blocking secret detector {detector} at line {line}",
            EXIT_POLICY,
        )
    if emit_warnings:
        for detector, line in warnings[:8]:
            print(
                f"progress-log: warning: {detector} shape at line {line}",
                file=sys.stderr,
            )
        if len(warnings) > 8:
            print(
                f"progress-log: warning: {len(warnings) - 8} more shape(s) omitted",
                file=sys.stderr,
            )


def _size_flags(text: str, document: ProgressLog) -> tuple[bool, bool, bool]:
    lines, byte_count, _, _ = metrics(text, document)
    target = byte_count > TARGET_BYTES or lines > TARGET_LINES
    soft = byte_count > SOFT_BYTES or lines > SOFT_LINES
    hard = byte_count > HARD_BYTES or lines > HARD_LINES
    return target, soft, hard


def _size_message(text: str, document: ProgressLog) -> str:
    lines, byte_count, tokens, entries = metrics(text, document)
    return f"{byte_count} bytes, {lines} lines, ~{tokens} tokens, {entries} entries"


def _decode(data: bytes, label: str, code: int = EXIT_MALFORMED) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Failure(f"{label} is not UTF-8", code) from None


def _load_log(root: Path, relative: str) -> tuple[Path, str, Snapshot]:
    path = safe_document_path(root, relative, allow_missing=False)
    data, snapshot = read_snapshot(path)
    if data is None or snapshot is None:
        raise Failure("internal log snapshot invariant failed", EXIT_INTERNAL)
    return path, _decode(data, "progress log"), snapshot


def _repository_root(value: Path) -> Path:
    root = validate_repo_root(value)
    assert_git_root(root)
    return root


def _active(text: str, *, mutation: bool) -> ProgressLog | None:
    parsed = parse_document(text)
    if isinstance(parsed, OptOut):
        if mutation:
            raise Failure(
                "repository has opted out of progress-log mutation", EXIT_POLICY
            )
        return None
    return parsed


def _mutable(text: str) -> ProgressLog:
    document = _active(text, mutation=True)
    if document is None:
        raise Failure("internal opt-out invariant failed", EXIT_INTERNAL)
    return document


def _validate_doc_targets(root: Path, document: ProgressLog) -> None:
    missing = 0
    for relative in document.docs:
        target = safe_document_path(root, relative, allow_missing=True)
        try:
            target.lstat()
        except FileNotFoundError:
            missing += 1
    if missing:
        print(
            f"progress-log: warning: {missing} knowledge file(s) are missing",
            file=sys.stderr,
        )


def ensure(root_value: Path, *, log_value: str = LOG_NAME) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    with locked_repo(root, exclusive=True):
        path = safe_document_path(root, relative, allow_missing=True)
        data, snapshot = read_snapshot(path, missing_ok=True)
        if data is None:
            text = render_document(ProgressLog(secrets.token_hex(16)))
            atomic_replace(path, text.encode("utf-8"), snapshot)
            print(f"created {LOG_NAME}")
        else:
            text = _decode(data, LOG_NAME)
            _enforce_secret_policy(text)
            parsed = parse_document(text)
            if isinstance(parsed, OptOut):
                print("progress-log is opted out")
                return 0
            _validate_doc_targets(root, parsed)
            print(f"confirmed {LOG_NAME}")
    return 0


def context(root_value: Path, *, log_value: str = LOG_NAME) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    with locked_repo(root, exclusive=False):
        _, text, _ = _load_log(root, relative)
        _enforce_secret_policy(text)
        document = _active(text, mutation=False)
        if document is not None:
            _validate_doc_targets(root, document)
            _, soft, hard = _size_flags(text, document)
            if hard:
                print(
                    "progress-log: warning: hard size exceeded; compact is still available",
                    file=sys.stderr,
                )
            elif soft:
                print("progress-log: warning: compaction recommended", file=sys.stderr)
    sys.stdout.write(text)
    return 0


def validate(root_value: Path, *, log_value: str = LOG_NAME) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    with locked_repo(root, exclusive=False):
        _, text, _ = _load_log(root, relative)
        _enforce_secret_policy(text)
        document = _active(text, mutation=False)
        if document is None:
            print("PASS opted out")
            return 0
        _validate_doc_targets(root, document)
        _, soft, hard = _size_flags(text, document)
        print(f"PASS canonical: {_size_message(text, document)}")
        if soft or hard:
            print("COMPACT recommended")
            return EXIT_COMPACT
    return 0


def _body_from_text(value: str) -> tuple[str, ...]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if normalized.endswith("\n"):
        normalized = normalized[:-1]
    return validate_body(tuple(normalized.split("\n")))


def _body_from_file(path: Path) -> tuple[str, ...]:
    data, _ = read_snapshot(path)
    if data is None:
        raise Failure("internal body snapshot invariant failed", EXIT_INTERNAL)
    return _body_from_text(_decode(data, "body file", EXIT_PATH))


def _assignments(values: Sequence[str]) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in values:
        if "=" not in raw:
            raise Failure("keyed mutation must use KEY=TEXT", EXIT_USAGE)
        key, value = raw.split("=", 1)
        key = validate_key(key)
        value = validate_value(value, "mutation value")
        if key in seen:
            raise Failure("duplicate keyed mutation", EXIT_USAGE)
        seen.add(key)
        result.append((key, value))
    return tuple(sorted(result))


def _keys(values: Sequence[str]) -> tuple[str, ...]:
    result = tuple(validate_key(value) for value in values)
    if len(result) != len(set(result)):
        raise Failure("duplicate keyed mutation", EXIT_USAGE)
    return tuple(sorted(result))


def _docs(values: Sequence[str]) -> tuple[str, ...]:
    result = tuple(validate_doc_path(value) for value in values)
    if len(result) != len({value.casefold() for value in result}):
        raise Failure("duplicate knowledge file mutation", EXIT_USAGE)
    return tuple(sorted(result, key=lambda value: (value.casefold(), value)))


def _normalized_operation(
    title: str,
    body: tuple[str, ...],
    set_state: tuple[tuple[str, str], ...],
    remove_state: tuple[str, ...],
    open_threads: tuple[tuple[str, str], ...],
    set_threads: tuple[tuple[str, str], ...],
    close_threads: tuple[str, ...],
    add_docs: tuple[str, ...],
    remove_docs: tuple[str, ...],
) -> bytes:
    value = dict(
        version=1,
        title=title,
        body=body,
        set_state=set_state,
        remove_state=remove_state,
        open_threads=open_threads,
        set_threads=set_threads,
        close_threads=close_threads,
        add_docs=add_docs,
        remove_docs=remove_docs,
    )
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Failure(
            "idempotency key must be 1-256 trimmed UTF-8 bytes without controls",
            EXIT_USAGE,
        )
    return value


def _new_timestamp(document: ProgressLog) -> datetime:
    value = datetime.now(UTC)
    if document.entries and value <= document.entries[-1].timestamp:
        try:
            # Preserve ordering when the wall clock stalls or moves backward.
            value = document.entries[-1].timestamp + timedelta(microseconds=1)
        except OverflowError:
            raise Failure("entry timestamp space is exhausted", EXIT_CONFLICT) from None
    return value


def _require_disjoint(left: Iterable[str], right: Iterable[str], label: str) -> None:
    if set(left) & set(right):
        raise Failure(f"conflicting {label} mutations", EXIT_USAGE)


def record(
    root_value: Path,
    *,
    log_value: str = LOG_NAME,
    title_value: str,
    body_value: str | None,
    body_file: Path | None,
    key: str | None,
    set_state_values: Sequence[str],
    remove_state_values: Sequence[str],
    open_thread_values: Sequence[str],
    set_thread_values: Sequence[str],
    close_thread_values: Sequence[str],
    add_doc_values: Sequence[str],
    remove_doc_values: Sequence[str],
) -> int:
    raw_request = "\n".join(
        (
            title_value,
            body_value or "",
            key or "",
            *set_state_values,
            *remove_state_values,
            *open_thread_values,
            *set_thread_values,
            *close_thread_values,
            *add_doc_values,
            *remove_doc_values,
        )
    )
    _enforce_secret_policy(raw_request, emit_warnings=False)
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    title = validate_title(title_value)
    key = _idempotency_key(key)
    body = (
        _body_from_file(resolve_user_path(root_value, root, body_file))
        if body_file is not None
        else _body_from_text(body_value or "")
    )
    _enforce_secret_policy("\n".join(body), emit_warnings=False)
    set_state = _assignments(set_state_values)
    remove_state = _keys(remove_state_values)
    open_threads = _assignments(open_thread_values)
    set_threads = _assignments(set_thread_values)
    close_threads = _keys(close_thread_values)
    add_docs = _docs(add_doc_values)
    remove_docs = _docs(remove_doc_values)
    _require_disjoint((item[0] for item in set_state), remove_state, "state")
    _require_disjoint((item[0] for item in open_threads), close_threads, "thread")
    _require_disjoint(
        (item[0] for item in open_threads),
        (item[0] for item in set_threads),
        "thread",
    )
    _require_disjoint((item[0] for item in set_threads), close_threads, "thread")
    _require_disjoint(add_docs, remove_docs, "knowledge file")
    operation = _normalized_operation(
        title,
        body,
        set_state,
        remove_state,
        open_threads,
        set_threads,
        close_threads,
        add_docs,
        remove_docs,
    )
    digest = hashlib.sha256(operation).hexdigest()
    with locked_repo(root, exclusive=True):
        path, text, snapshot = _load_log(root, relative)
        _enforce_secret_policy(text)
        document = _mutable(text)
        _validate_doc_targets(root, document)
        entry_id = (
            hashlib.sha256(b"progress-log-v1\0" + key.encode("utf-8")).hexdigest()[:16]
            if key is not None
            else secrets.token_hex(8)
        )
        existing = next(
            (entry for entry in document.entries if entry.entry_id == entry_id), None
        )
        if key is not None and existing is not None:
            if existing.operation_digest == digest:
                print(f"record already present: {entry_id}")
                return 0
            raise Failure(f"idempotency conflict for entry {entry_id}", EXIT_CONFLICT)
        if key is None:
            while existing is not None:
                entry_id = secrets.token_hex(8)
                existing = next(
                    (entry for entry in document.entries if entry.entry_id == entry_id),
                    None,
                )

        state = dict(document.state)
        threads = dict(document.threads)
        docs = set(document.docs)
        for state_key in remove_state:
            if state_key not in state:
                raise Failure(
                    f"cannot remove absent state key {state_key}", EXIT_CONFLICT
                )
            del state[state_key]
        state.update(set_state)
        for thread_key in close_threads:
            if thread_key not in threads:
                raise Failure(
                    f"cannot close absent thread key {thread_key}", EXIT_CONFLICT
                )
            del threads[thread_key]
        for thread_key, value in set_threads:
            if thread_key not in threads:
                raise Failure(
                    f"cannot update absent thread key {thread_key}", EXIT_CONFLICT
                )
            threads[thread_key] = value
        for thread_key, _ in open_threads:
            if thread_key in threads:
                raise Failure(f"thread key {thread_key} is already open", EXIT_CONFLICT)
        threads.update(open_threads)
        for relative in remove_docs:
            if relative not in docs:
                raise Failure("cannot remove an absent knowledge file", EXIT_CONFLICT)
            docs.remove(relative)
        for relative in add_docs:
            if any(
                item != relative and item.casefold() == relative.casefold()
                for item in docs
            ):
                raise Failure("knowledge file differs only by case", EXIT_CONFLICT)
            safe_document_path(root, relative, allow_missing=False)
            docs.add(relative)

        entry = Entry(
            entry_id=entry_id,
            timestamp=_new_timestamp(document),
            title=title,
            body=body,
            operation_digest=digest if key is not None else None,
            opens=tuple(key for key, _ in open_threads),
            closes=close_threads,
        )
        candidate = ProgressLog(
            log_id=document.log_id,
            docs=tuple(sorted(docs, key=lambda value: (value.casefold(), value))),
            state=tuple(sorted(state.items())),
            threads=tuple(sorted(threads.items())),
            entries=tuple(
                sorted((*document.entries, entry), key=lambda item: item.sort_key)
            ),
        )
        candidate_text = render_document(candidate)
        _enforce_secret_policy(candidate_text)
        _, soft, hard = _size_flags(candidate_text, candidate)
        if hard:
            raise Failure(
                "record would exceed the hard log budget; compact first", EXIT_POLICY
            )
        atomic_replace(path, candidate_text.encode("utf-8"), snapshot)
        print(f"recorded {entry_id}: {_size_message(candidate_text, candidate)}")
        if soft:
            print("progress-log: warning: compaction recommended", file=sys.stderr)
    return 0


def repair(root_value: Path, *, log_value: str = LOG_NAME) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    with locked_repo(root, exclusive=True):
        path, text, snapshot = _load_log(root, relative)
        _enforce_secret_policy(text, emit_warnings=False)
        parsed = parse_document(text, canonical=False)
        if isinstance(parsed, OptOut):
            raise Failure(
                "repository has opted out of progress-log mutation", EXIT_POLICY
            )
        candidate = render_document(parsed)
        _enforce_secret_policy(candidate)
        _validate_doc_targets(root, parsed)
        if candidate == text:
            print("progress-log is already canonical")
            return 0
        atomic_replace(path, candidate.encode("utf-8"), snapshot)
        print("repaired progress-log representation without changing semantic content")
    return 0


def compact(
    root_value: Path, *, log_value: str = LOG_NAME, list_only: bool = False
) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    preview: str | None = None
    with locked_repo(root, exclusive=True):
        path, text, snapshot = _load_log(root, relative)
        _enforce_secret_policy(text)
        document = _mutable(text)
        _validate_doc_targets(root, document)
        target, soft, hard = _size_flags(text, document)
        if not target:
            print(f"no compaction needed: {_size_message(text, document)}")
            return 0
        head = load_head_log(root, relative)
        head_text = _decode(head.data, "raw HEAD progress log", EXIT_POLICY)
        _enforce_secret_policy(head_text)
        head_document = _mutable(head_text)
        if head_document.log_id != document.log_id:
            raise Failure("raw HEAD progress log has unrelated identity", EXIT_CONFLICT)
        head_entries = {
            entry.entry_id: render_entry(entry) for entry in head_document.entries
        }
        removable = {
            entry.entry_id
            for entry in document.entries
            if head_entries.get(entry.entry_id) == render_entry(entry)
        }
        remaining = list(document.entries)
        removed = 0
        while removable and remaining:
            candidate = ProgressLog(
                document.log_id,
                document.docs,
                document.state,
                document.threads,
                tuple(remaining),
            )
            candidate_text = render_document(candidate)
            candidate_target, _, _ = _size_flags(candidate_text, candidate)
            if not candidate_target:
                break
            if (
                len(remaining) <= MIN_REMAINING_ENTRIES
                or remaining[0].entry_id not in removable
            ):
                break
            removable.remove(remaining[0].entry_id)
            remaining.pop(0)
            removed += 1
        if removed == 0:
            condition = "hard" if hard else "soft" if soft else "target"
            raise Failure(
                f"no oldest entries have raw HEAD proof for {condition} recovery",
                EXIT_POLICY,
            )
        candidate = ProgressLog(
            document.log_id,
            document.docs,
            document.state,
            document.threads,
            tuple(remaining),
        )
        candidate_text = render_document(candidate)
        _enforce_secret_policy(candidate_text)
        assert_head(root, head.oid)
        _, current = read_snapshot(path)
        if current != snapshot:
            raise Failure("progress log changed during compaction", EXIT_CONFLICT)
        proof = (
            f"raw HEAD proof: commit {head.oid}, blob {head.blob_oid}; "
            "recover from the repository root with: "
            "git --no-replace-objects --no-lazy-fetch "
            f"cat-file blob {head.blob_oid}"
        )
        if list_only:
            preview = f"would remove {removed} entries\n{proof}\n\n" + "\n".join(
                render_entry(entry) for entry in document.entries[:removed]
            )
        else:
            atomic_replace(path, candidate_text.encode("utf-8"), snapshot)
            print(
                f"compacted {removed} entries: {_size_message(candidate_text, candidate)}"
            )
            print(proof)
            if _size_flags(candidate_text, candidate)[0]:
                print(
                    "progress-log: warning: safe compaction remains over target",
                    file=sys.stderr,
                )
    if preview is not None:
        sys.stdout.write(preview)
    return 0


_MISSING = object()


def _merge_map(
    base_items: Sequence[tuple[str, str]],
    ours_items: Sequence[tuple[str, str]],
    theirs_items: Sequence[tuple[str, str]],
    label: str,
) -> tuple[tuple[str, str], ...]:
    base = dict(base_items)
    ours = dict(ours_items)
    theirs = dict(theirs_items)
    result: dict[str, str] = {}
    for key in sorted(set(base) | set(ours) | set(theirs)):
        before = base.get(key, _MISSING)
        left = ours.get(key, _MISSING)
        right = theirs.get(key, _MISSING)
        if left == right:
            selected = left
        elif left == before:
            selected = right
        elif right == before:
            selected = left
        else:
            raise Failure(
                f"merge conflict: {label} {key} changed-differently", EXIT_CONFLICT
            )
        if isinstance(selected, str):
            result[key] = selected
    return tuple(sorted(result.items()))


def _merge_docs(
    base: Sequence[str], ours: Sequence[str], theirs: Sequence[str]
) -> tuple[str, ...]:
    before, left, right = set(base), set(ours), set(theirs)
    merged = (left & right) | (left - before) | (right - before)
    if len({item.casefold() for item in merged}) != len(merged):
        raise Failure(
            "merge conflict: knowledge-file normalized identity", EXIT_CONFLICT
        )
    return tuple(sorted(merged, key=lambda item: (item.casefold(), item)))


def _merge_entries(
    base_entries: Sequence[Entry],
    ours_entries: Sequence[Entry],
    theirs_entries: Sequence[Entry],
) -> tuple[Entry, ...]:
    base = {entry.entry_id: entry for entry in base_entries}
    ours = {entry.entry_id: entry for entry in ours_entries}
    theirs = {entry.entry_id: entry for entry in theirs_entries}
    result: dict[str, Entry] = {}
    for entry_id, before in base.items():
        left = ours.get(entry_id)
        right = theirs.get(entry_id)
        if left is None or right is None:
            raise Failure(
                f"merge conflict: entry {entry_id} base-deleted", EXIT_CONFLICT
            )
        if left != before or right != before:
            raise Failure(
                f"merge conflict: entry {entry_id} base-mutated", EXIT_CONFLICT
            )
        result[entry_id] = before
    for entry_id in sorted((set(ours) | set(theirs)) - set(base)):
        left = ours.get(entry_id)
        right = theirs.get(entry_id)
        if left is not None and right is not None:
            same_operation = (
                left.operation_digest is not None
                and replace(left, timestamp=right.timestamp) == right
            )
            if left != right and not same_operation:
                raise Failure(
                    f"merge conflict: entry {entry_id} added-differently",
                    EXIT_CONFLICT,
                )
            result[entry_id] = min((left, right), key=lambda entry: entry.sort_key)
        elif left is not None:
            result[entry_id] = left
        elif right is not None:
            result[entry_id] = right
    return tuple(sorted(result.values(), key=lambda entry: entry.sort_key))


def _read_merge_input(path: Path, label: str) -> tuple[str, Snapshot]:
    data, snapshot = read_snapshot(path)
    if data is None or snapshot is None:
        raise Failure("internal merge snapshot invariant failed", EXIT_INTERNAL)
    text = _decode(data, label)
    _enforce_secret_policy(text)
    return text, snapshot


def _recheck_merge_input(path: Path, expected: Snapshot, label: str) -> None:
    try:
        _, current = read_snapshot(path)
    except Failure:
        raise Failure(
            f"merge {label} changed before installation", EXIT_CONFLICT
        ) from None
    if current != expected:
        raise Failure(f"merge {label} changed before installation", EXIT_CONFLICT)


def _authorize_merge_destination(
    data: bytes | None, log_id: str, *, force: bool
) -> None:
    if not data:
        return
    text = _decode(data, "progress log")
    parsed = parse_document(text)
    if isinstance(parsed, OptOut):
        raise Failure("repository has opted out of progress-log mutation", EXIT_POLICY)
    if parsed.log_id != log_id:
        raise Failure("merge destination has unrelated log identity", EXIT_CONFLICT)
    _enforce_secret_policy(text)
    if not force:
        raise Failure("progress log is non-empty; use --force", EXIT_CONFLICT)


def merge(
    root_value: Path,
    base_path: Path,
    ours_path: Path,
    theirs_path: Path,
    *,
    log_value: str = LOG_NAME,
    force: bool,
) -> int:
    relative = validate_log_path(log_value)
    root = _repository_root(root_value)
    base_path, ours_path, theirs_path = (
        resolve_user_path(root_value, root, path)
        for path in (base_path, ours_path, theirs_path)
    )
    output_path = safe_document_path(root, relative, allow_missing=True)
    with locked_repo(root, exclusive=True):
        base_text, base_snapshot = _read_merge_input(base_path, "merge base")
        ours_text, ours_snapshot = _read_merge_input(ours_path, "merge ours")
        theirs_text, theirs_snapshot = _read_merge_input(theirs_path, "merge theirs")
        base = _mutable(base_text)
        ours = _mutable(ours_text)
        theirs = _mutable(theirs_text)
        if len({base.log_id, ours.log_id, theirs.log_id}) != 1:
            raise Failure("merge conflict: unrelated log identity", EXIT_CONFLICT)
        result = ProgressLog(
            log_id=base.log_id,
            docs=_merge_docs(base.docs, ours.docs, theirs.docs),
            state=_merge_map(base.state, ours.state, theirs.state, "state"),
            threads=_merge_map(base.threads, ours.threads, theirs.threads, "thread"),
            entries=_merge_entries(base.entries, ours.entries, theirs.entries),
        )
        for relative in result.docs:
            safe_document_path(root, relative, allow_missing=True)
        candidate = render_document(result)
        _enforce_secret_policy(candidate)
        _, soft, hard = _size_flags(candidate, result)
        if hard:
            raise Failure("merged log would exceed the hard budget", EXIT_POLICY)
        _recheck_merge_input(base_path, base_snapshot, "base")
        _recheck_merge_input(ours_path, ours_snapshot, "ours")
        _recheck_merge_input(theirs_path, theirs_snapshot, "theirs")
        output_data, output_snapshot = read_snapshot(output_path, missing_ok=True)
        _authorize_merge_destination(output_data, result.log_id, force=force)
        atomic_replace(output_path, candidate.encode("utf-8"), output_snapshot)
        print(f"merged progress log: {_size_message(candidate, result)}")
        if soft:
            print("progress-log: warning: compaction recommended", file=sys.stderr)
    return 0


class Parser(argparse.ArgumentParser):
    def error(self, _: str) -> NoReturn:
        raise Failure("invalid command-line arguments; use --help", EXIT_USAGE)


def _add_log_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log",
        default=LOG_NAME,
        metavar="PATH",
        help="safe repository-relative progress-log.md path (default: root)",
    )


def build_parser() -> Parser:
    parser = Parser(
        prog="progress-log", description="Maintain one bounded repository progress log."
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=Parser
    )
    simple_help = {
        "ensure": "create or confirm the selected log",
        "context": "print validated repository context",
        "validate": "check canonical form and budgets",
        "repair": "canonicalize a parseable hand edit",
    }
    for name, help_text in simple_help.items():
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("repo", type=Path, help="repository root")
        _add_log_argument(command)
    compact_parser = subparsers.add_parser(
        "compact", help="remove only raw-HEAD-proved entries"
    )
    compact_parser.add_argument("repo", type=Path, help="repository root")
    _add_log_argument(compact_parser)
    compact_parser.add_argument(
        "--list", action="store_true", help="preview proved removals without writing"
    )
    record_parser = subparsers.add_parser(
        "record", help="record one completed unit transactionally"
    )
    record_parser.add_argument("repo", type=Path, help="repository root")
    _add_log_argument(record_parser)
    record_parser.add_argument("--title", required=True, help="completed-unit title")
    body_group = record_parser.add_mutually_exclusive_group(required=True)
    body_group.add_argument("--body", help="entry body text")
    body_group.add_argument(
        "--body-file", type=Path, help="multiline entry body from a file"
    )
    record_parser.add_argument(
        "--key",
        help="attempt key: identical retry no-ops; changed retry conflicts; compaction ends replay",
    )
    mutation_help = {
        "set-state": "set current state KEY=TEXT",
        "remove-state": "remove current state KEY",
        "open-thread": "open thread KEY=TEXT",
        "set-thread": "update open thread KEY=TEXT",
        "close-thread": "close thread KEY",
        "add-doc": "add knowledge file PATH",
        "remove-doc": "remove knowledge file PATH",
    }
    for name, help_text in mutation_help.items():
        record_parser.add_argument(
            f"--{name}", action="append", default=[], help=help_text
        )
    merge_parser = subparsers.add_parser(
        "merge", help="merge append-only copies into the selected log"
    )
    merge_parser.add_argument("repo", type=Path, help="repository root")
    _add_log_argument(merge_parser)
    for name in ("base", "ours", "theirs"):
        merge_parser.add_argument(name, type=Path, help=f"{name} log input")
    merge_parser.add_argument(
        "--force",
        action="store_true",
        help="replace a non-empty same-identity selected log",
    )
    return parser


def dispatch(arguments: argparse.Namespace) -> int:
    simple = {
        "ensure": ensure,
        "context": context,
        "validate": validate,
        "repair": repair,
    }.get(arguments.command)
    if simple is not None:
        return simple(arguments.repo, log_value=arguments.log)
    if arguments.command == "compact":
        return compact(
            arguments.repo, log_value=arguments.log, list_only=arguments.list
        )
    if arguments.command == "record":
        return record(
            arguments.repo,
            log_value=arguments.log,
            title_value=arguments.title,
            body_value=arguments.body,
            body_file=arguments.body_file,
            key=arguments.key,
            set_state_values=arguments.set_state,
            remove_state_values=arguments.remove_state,
            open_thread_values=arguments.open_thread,
            set_thread_values=arguments.set_thread,
            close_thread_values=arguments.close_thread,
            add_doc_values=arguments.add_doc,
            remove_doc_values=arguments.remove_doc,
        )
    if arguments.command == "merge":
        return merge(
            arguments.repo,
            arguments.base,
            arguments.ours,
            arguments.theirs,
            log_value=arguments.log,
            force=arguments.force,
        )
    raise Failure("unknown command", EXIT_INTERNAL)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = build_parser().parse_args(argv)
        return dispatch(arguments)
    except Failure as exc:
        print(f"progress-log: {exc}", file=sys.stderr)
        return exc.code
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("progress-log: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception:
        print("progress-log: internal error", file=sys.stderr)
        return EXIT_INTERNAL
