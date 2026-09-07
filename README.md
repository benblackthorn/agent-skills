# Agent Skills

**A growing collection of focused, reliable skills for coding agents.**

Each skill gives an agent a repeatable workflow for a job where generic model
behavior is not enough. Skills are self-contained, install independently, and
state when they should—and should not—activate.

This repository follows the open [Agent Skills](https://agentskills.io/)
format and supports hosts including Codex, Claude Code, GitHub Copilot, Cursor,
and other compatible agents.

**Building your own skill library?** These skills install and run independently.
They are reviewed and prepared for release with [remek](https://remek.dev/)
([source](https://github.com/benblackthorn/remek)), the open-source governance
and release layer for Agent Skills.

## Skills

### [progress-log](skills/progress-log/)

Bounded repository working context for work that spans agents or sessions.
Records scoped completed outcomes, current orientation, source pointers, and
workstream handoffs with safe repair, Git-proved compaction, and conservative
branch merging.

Every skill’s `SKILL.md` is its source of truth for routing, workflow,
compatibility, and exclusions. The catalog will expand without turning the
repository into one monolithic workflow; install only the skills that fit your
work.

## Browse, preview, and install

`gh skill` requires GitHub CLI 2.90 or newer and remains in public preview.

Browse the available skills interactively:

```bash
gh skill install benblackthorn/agent-skills
```

Preview one skill without installing it:

```bash
gh skill preview benblackthorn/agent-skills <skill-name>
```

Install one skill for Codex in user scope:

```bash
gh skill install benblackthorn/agent-skills <skill-name> \
  --agent codex --scope user
```

For Claude Code, replace `codex` with `claude-code`. Use `--all` only when you
have reviewed and want every skill in the collection.

GitHub releases are complete catalog snapshots, not independent versions of
individual skills. An unversioned install resolves the latest catalog release
first, falling back to the default branch when the repository has no release.
Pin an exact catalog tag or reviewed commit for a reproducible installation:

```bash
gh skill install benblackthorn/agent-skills <skill-name> \
  --pin <tag-or-commit> --agent codex --scope user
```

The open `skills` CLI is also supported:

```bash
npx skills add benblackthorn/agent-skills --skill <skill-name> -g
```

## Repository structure

```text
skills/
  <skill-name>/
    SKILL.md       # routing and operating instructions
    scripts/       # executable helpers, when needed
    references/    # deeper contracts or guidance, when needed
    LICENSE        # the skill's license
release-manifest.json
```

Not every skill needs scripts or references. A good skill owns one clear job
and carries only the material required to perform it reliably.

## Release integrity

Current remek v2 releases use the `remek-v2` branch. The earlier `main` history
and catalog tags remain available for pinned installations.

The released catalog payload is projected with [remek](https://remek.dev/) from
a separate governed source. remek binds exact skill bytes to provenance,
reported evaluation observations, a complete distribution review, and the intended
target before projecting them here.
This repository is the consumer-facing projection and intentionally excludes
private governance records, evaluation traces, and approvals.

[`release-manifest.json`](release-manifest.json) binds the projected payload,
source identity, and mirror lineage. Its digests identify exact bytes; they are
not signatures or independent proof of evaluator honesty. Changing governed
skill bytes requires current evidence and a complete distribution review before
another release.

Pull requests that propose skill changes are welcome, but accepted behavior is
reproduced and verified in the authoritative source before it is projected
here. Repository documentation and community-policy corrections can be made
directly in this repository. A new catalog release is published only when the
mirrored skill set or installed skill bytes change; documentation, workflow,
and other repository-only maintenance can advance the release branch without a
new tag.

## Project policies

- [Contributing](.github/CONTRIBUTING.md)
- [Security](.github/SECURITY.md)

Repository documentation is licensed under the [MIT License](LICENSE). Each
skill carries its own license; check the skill directory before reuse.
