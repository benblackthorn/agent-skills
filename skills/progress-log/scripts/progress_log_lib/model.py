from dataclasses import dataclass
from datetime import datetime


EXIT_SUCCESS = 0
EXIT_COMPACT = 2
EXIT_USAGE = 64
EXIT_MALFORMED = 65
EXIT_PATH = 66
EXIT_INTERNAL = 70
EXIT_WRITE = 73
EXIT_CONFLICT = 75
EXIT_POLICY = 76
EXIT_INTERRUPTED = 130


class Failure(Exception):
    def __init__(
        self, message: str, code: int, *, changed: bool | None = False
    ) -> None:
        super().__init__(message)
        self.code = code
        self.changed = changed


@dataclass(frozen=True)
class Entry:
    entry_id: str
    timestamp: datetime
    title: str
    body: tuple[str, ...]
    operation_digest: str | None = None
    opens: tuple[str, ...] = ()
    closes: tuple[str, ...] = ()
    scope: str = "."

    @property
    def sort_key(self) -> tuple[datetime, str]:
        return (self.timestamp, self.entry_id)


@dataclass(frozen=True)
class ProgressLog:
    log_id: str
    docs: tuple[str, ...] = ()
    state: tuple[tuple[str, str], ...] = ()
    threads: tuple[tuple[str, str], ...] = ()
    entries: tuple[Entry, ...] = ()


@dataclass(frozen=True)
class ContextSource:
    scope: str
    path: str


@dataclass(frozen=True)
class Orientation:
    scope: str
    key: str
    value: str


@dataclass(frozen=True)
class Workstream:
    scope: str
    key: str
    objective: str
    checkpoint: str
    next: str
    blocker: str


@dataclass(frozen=True)
class ProgressLogV2:
    log_id: str
    sources: tuple[ContextSource, ...] = ()
    state: tuple[Orientation, ...] = ()
    workstreams: tuple[Workstream, ...] = ()
    entries: tuple[Entry, ...] = ()


@dataclass(frozen=True)
class OptOut:
    pass


CanonicalLog = ProgressLog | ProgressLogV2
