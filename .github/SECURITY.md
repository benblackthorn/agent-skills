# Security policy

The latest commit on `remek-v2` is the supported release surface. Older pinned
commits remain reproducible but do not receive fixes.

## Report a vulnerability

Use
[GitHub private vulnerability reporting](https://github.com/benblackthorn/agent-skills/security/advisories/new).
Do not report a vulnerability in a public issue, discussion, or pull request.

Include:

- the affected skill and exact commit;
- agent host, operating system, and relevant runtime or tool versions;
- the command or prompt that reaches the boundary;
- expected behavior, observed impact, and a sanitized minimal reproduction;
- whether files, credentials, network resources, or external systems were
  accessed or changed.

Never include live credentials, private repository contents, client data, or
raw evaluation transcripts. If a possible destructive-boundary defect changed
data, retain a recoverable copy only when it is safe to do so.

Ordinary behavior errors, unclear documentation, and non-sensitive routing
problems can use public issues.

## Trust and installation

Agent Skills are executable instructions and may include scripts or invoke
external tools. Preview the exact skill and inspect its requirements before
installation. Grant only the permissions needed for the task and pin a reviewed
commit when reproducibility matters.

Each skill documents its own trust boundaries and exclusions in `SKILL.md` and
its bundled references. No repository-wide policy silently expands those
permissions. Release-manifest digests identify exact projected bytes; they are
not signatures, approval authority, or proof that an evaluator was honest.
