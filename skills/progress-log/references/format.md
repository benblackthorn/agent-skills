# progress-log v2 contract

## Canonical bytes and versions

The CLI owns canonical bytes.

Rows are ``- `SCOPE`: [PATH](<PATH>)`` and ``- `SCOPE` / `KEY`: VALUE``.
Capsules have scoped markers/heading and four rows. Entries carry
`id/op/scope/opens/closes`, timestamp/title, body, and end marker. Canonical
bytes use LF, final newline, fixed order, and `- None.` for empties. Views/deltas
are noncanonical; opt-out is exactly
`<!-- progress-log: opted-out -->`. Select root `progress-log.md` or a safe
repository-relative `--log` of that basename. `ensure` creates/confirms v2 or
preserves opt-out.

## Scope and records

Scope is `.` or an ASCII repository-relative POSIX directory of at most 512
bytes/16 components matching
`(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}|\.[A-Za-z0-9_][A-Za-z0-9._-]{0,62})`.
Reject empty/dot/dot-dot, absolute, backslash/trailing, non-ASCII/control/NUL/
BOM/bidi, casefold collisions, and linked, special, or escaping inputs. Recheck
active directory identity before replacement. Missing active scope is
`orphan-scope`; history may outlive it.

Applicable scope is global plus lexical ancestors; repeated scopes union.
Cross-cutting material uses the lowest common ancestor without tags or inferred
moves. Keys match `[a-z0-9._-]{1,64}`. Identities are source `(scope,path)`,
current `(scope,key)`, entry 16-hex ID, and log 32-hex ID.

A source is one root-relative regular file, metadata-snapshotted/rechecked
without reading, hashing, or capping content. Later operations ignore its
contents after pointer validation. Missing is `orphan-source`: affected context
refuses; raw/removal remain. State is orientation only.

A workstream has one scope and one-line Objective/Checkpoint/Next/Blocker
(`None` means absent):
512 bytes each, 1,024 combined, eight rendered lines, no timestamp. Retry is
exact; replacement/merge is whole-capsule; competition conflicts.

Entries use a 16-hex ID, microsecond UTC, 120-character/512-byte title,
4,096-byte/40-line body, scope, optional 64-hex digest, and opens/closes.
Normal v2 has `opens=-`; migrated v1 may not. They sort by `(timestamp,ID)` and
merge immutably. Keyed IDs hash log ID/scope/key; operation digests hash
canonical schema-2 JSON with sorted mutations and ordered body. Unknown classes
refuse. Unkeyed allocation makes at most 16 random draws for a valid unoccupied
ID; exhaustion conflicts.

## Projected context

Context caps at 16,384 bytes/200 lines. Mandatory current material and a selected
capsule cap at 10,240/150, reserving 6,144/50 and one maximum entry; `--raw`
excludes selectors.

Explicit views sort ancestor closures, select current material, show eight
capsule summaries plus at most one full capsule, refuse mandatory overflow, then
fit the newest whole-entry suffix.

Root view includes global material/entries and capped non-global rollups.
Rollups reserve omissions and cap at 2,048 bytes/25 lines; root bounds orphan
identities and affected explicit views refuse.
Projection is deterministic and never loads, discovers, infers, ranks, searches,
imports, or mutates.

## Health, mutation, and recovery

| Boundary | Bytes | Lines |
| --- | ---: | ---: |
| Target | 65,536 | 800 |
| Soft | 98,304 | 1,200 |
| Ordinary hard | 131,072 | 2,000 |
| Emergency merge | 262,144 | 4,000 |
| Parser/storage | 1,048,576 | — |

`validate` exit `2` reports `storage-soft`, `storage-hard`,
`active-projection-overflow`, `orphan-scope`, or `orphan-source`. Soft warns;
the others lock additions/merge. Recovery clears both hard dimensions and every
active closure/scope/source. Validation checks root/all active closures;
requested unions/capsules are checked on demand.

`maintain` plan/apply deletes one current identity and binds identity, redacted
delta, source bytes/mode, and candidate digest/metrics. It must remove an
orphan, improve projection excess without creating/worsening another, or reduce
every exceeded hard-storage dimension without increase. It is available only
for hard/projection/orphan health; locked recomputation rejects
drift/replay/absence.

`delta` resolves one full lowercase 40/64-hex OID using raw Git while disabling
replacement refs, lazy fetch, and network access. Path/version/log ID must
match. Bounded Markdown lists scoped changes; same-ID edits conflict without
values.

`compact` plan/apply binds path/log ID, working bytes/mode, raw-HEAD commit/blob,
oldest byte-identical prefix/block digests, metrics, and candidate. It keeps one
entry/all current material and reduces hard excess without increase. Locked
recomputation rejects drift/replay; Git remains the archive.

Merge is pure over immutable entries and three-way current material. Competition,
update/remove, edited/deleted base entries, collisions, unrelated IDs, and mixed
versions conflict. Emergency mode accepts canonical inputs within ordinary hard
ceilings and only a conflict-free union within its envelope: inspect; commit
without push; bound-clean in a second commit; gate; then separately authorize
that exact push. Never rewrite/drop proof or pre-compact.

For rename, move code; validate; remove old identities individually; add
replacements/recreate handoff; validate and commit. History/paths never
auto-move; concurrent old updates conflict.

## Migration, safety, and exclusions

After product/safety proof and separate authority, `migrate
--plan|--apply PLAN_ID` accepts canonical zero-thread v1 in a clean worktree.
Symbolic `HEAD`, local branch, and any configured local upstream equal the
captured commit without fetch; working/raw-HEAD bytes and mode match. Default
mapping preserves every v1 value/entry/log ID/mode at root and infers no capsule.
Optional external absolute mode-0600 `--scope-map` strict JSON uses schema
`progress-log.migration-scope-map.v1`, matches `log_id`/`source_digest`, and
exactly maps every source path, state key, and entry ID. Plan/apply binds the
map plus every mapped directory and ancestor identity, source
commit/blob/digest/mode, and target digest/mode/metrics. Apply re-proves all
inputs and rejects drift/replay. Exact rollback ends at the first v2 mutation;
afterward revert later log changes or fix forward.

Require isolated `python3 -I -S -B`, validated runtime, Git 2.45+, and local
macOS/Linux. Mutations lock, fsync, recheck, replace atomically, verify, and sync.
Post-replace failure classifies old/intended/ambiguous without guessing.
Noncooperators, power loss, and non-local filesystems are excluded.

High-confidence credentials block without echo; diagnostics are bounded. Bidi,
embedded BOM, NUL, invalid UTF-8, ambiguity, and extra text refuse.
`repair` only removes a leading BOM or normalizes newlines without semantic
change. Commands leave no backup, bytecode, temporary, or generated residue.
Exits: `0` success/no-op;
`2` valid maintenance
(`validate` only); `64` usage; `65` malformed; `66` path; `70` internal; `73`
write; `75` lock/stale/conflict; `76` policy; `130` interrupted.

SKILL.md exclusions apply; the overlay is evaluation-only. Migration,
evaluation, promotion, and remote/public actions need separate authority.
