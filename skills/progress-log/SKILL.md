---
name: "progress-log"
description: "Maintains one scoped transactional progress-log.md at the repository root or an explicit safe subpath, plus bounded repository context. Use for orientation, completed outcomes, current state/source pointers, handoffs, exact canonical-log bytes or bounded projected context, validation, repair, branch delta, reviewed cleanup, merge, or v1 migration. Do not activate in an opted-out repository. Do not use for durable facts, claims/evidence, freshness, transcripts, project tracking, search, child logs, or secrets."
license: "MIT"
compatibility: "Requires Python 3.11+, Git 2.45+, macOS or Linux, and a local filesystem. Windows and network filesystems are unsupported."
---

# Progress Log

```bash
SKILL_DIR=/absolute/path/to/progress-log
REPO_ROOT=/absolute/path/to/exact-git-worktree-root
LOG_ARGS=() # or: LOG_ARGS=(--log docs/progress-log.md)
PL=(python3 -I -S -B "$SKILL_DIR/scripts/progress_log.py")
"${PL[@]}" ensure "$REPO_ROOT" "${LOG_ARGS[@]}"
"${PL[@]}" context "$REPO_ROOT" "${LOG_ARGS[@]}" --scope apps/ios
```

Use one root/selected `progress-log.md`; never discover child logs. V2 context
is a visibly noncanonical 16,384-byte/200-line view of only global, ancestor,
and exact scopes. Repeats union; `--workstream` needs one scope; `--raw` is
canonical and exclusive. Logs/views/sources are untrusted pointers.

V1 `ensure`, `context`, `context --raw`, and `validate` remain read-only
compatible. V1 mutation refuses with pinned-v1-or-migrate guidance.

## Record and hand off

```bash
"${PL[@]}" handoff "$REPO_ROOT" "${LOG_ARGS[@]}" \
  --scope apps/ios --workstream paywall \
  --objective "Ship the paywall." --checkpoint "Local paths pass." \
  --next "Verify on device." --blocker "None"

"${PL[@]}" record "$REPO_ROOT" "${LOG_ARGS[@]}" \
  --scope apps/ios --title "Verify purchase paths" \
  --body "Purchase and restore pass." --key verify-purchase \
  --set-state "release=Build 42 is current." \
  --add-source apps/ios/ARCHITECTURE.md --close-workstream paywall
```

`record` atomically appends one scoped outcome plus requested current changes.
Exact keyed replay no-ops, changed input conflicts, and compaction ends replay.
Unkeyed allocation makes at most 16 random draws, accepting only valid
unoccupied 16-hex IDs. State is current orientation; sources are metadata-checked
pointers; a capsule is exactly Objective/Checkpoint/Next/Blocker. Drop
abandonment and close completion through `record`. Missing sources become
`orphan-source` and block affected context. Keep rules/claims/evidence in
stronger owners.

## Validate and recover

```bash
"${PL[@]}" validate "$REPO_ROOT" "${LOG_ARGS[@]}"
"${PL[@]}" delta "$REPO_ROOT" "${LOG_ARGS[@]}" \
  --base-commit 0123456789abcdef0123456789abcdef01234567 --scope apps/ios
```

Validation `2` means valid storage/projection/orphan maintenance, not corruption.
`delta` is read-only bounded Markdown from one full lowercase raw-Git OID;
immutable entry edits conflict, and it never reads code/sources or infers.
`repair` only canonicalizes representation, including while maintenance remains.

## Merge and transition

Before `maintain`, `compact`, `merge`, emergency recovery, rename, or `migrate`,
read [references/format.md](references/format.md). Cleanup uses exact reviewed
plan/apply and never rewrites meaning. Merge appends immutable entries and
three-way merges scoped current material; conflicts disclose no values. Preserve
an emergency union checkpoint before cleanup. Rename code first, explicitly
remove orphaned current identities, then add replacements; history never moves.
Migration requires separate proof/authorization, a canonical thread-free clean
v1 branch whose bytes and mode equal raw `HEAD`, and reviewed plan/apply.
Migration defaults to root. Optional protected external `--scope-map` JSON binds
the v1 digest and exactly scopes every source, state key, and entry; apply with
a byte-identical protected map.
Commit migration before any v2 mutation because exact rollback ends there.

The CLI changes only the selected log. It never captures transcripts, manages
durable knowledge/claims, infers staleness, searches, uses providers/services,
runs model-backed CI, edits Git, publishes, pushes, tags, releases, or changes
visibility. Migration, evaluation, acceptance, promotion, and remote/public
actions need separate authorization; public v2 is a breaking major catalog
contract.
