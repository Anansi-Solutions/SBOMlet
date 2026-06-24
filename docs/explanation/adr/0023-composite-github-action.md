# ADR-0023: A composite GitHub Action for one-line CI adoption

- **Status:** Accepted
- **Date:** 2026-06-24

## Context and problem

[ADR-0019](0019-adoption-git-clone-taskfile.md) settled adoption as "vendor the
tool + a Taskfile include + mise," and
[ADR-0020](0020-distribution-git-bun.md) kept distribution as git + a mise-pinned
bun rather than a binary. That is a clean local and cross-CI story, but on GitHub
Actions — where many consumers live — it still means wiring mise, Task, and the
include by hand. That is exactly the "still not one line" cost ADR-0020 accepted.

## Decision drivers

- **One-line adoption on the most common CI**, without a new runtime or a published
  artifact to maintain.
- **No divergence.** The action must run the SAME pipeline as the Taskfile path, not
  a second code path that can drift.
- **The injection-safe, data-only posture** of the Taskfile must carry over.

## Considered options

1. **Document the manual mise + Task wiring only** (status quo) — the friction
   ADR-0020 accepted.
2. **A composite action wrapping the pipeline.**
3. **A Docker-container action** — would pin a base image and a second toolchain,
   the redundant-runtime trap ADR-0020 rejected for the binary.

## Decision

We chose option 2: a composite `action.yml` at the repo root. It is three steps —
`jdx/mise-action` for the toolchain, `bun install` in the action's own directory,
and `bun src/cli.ts <mode>` pointed at the consumer's checkout. A consumer adds
`uses: Anansi-Solutions/SBOMlet@<ref>` with a `policy` and optional `mode` input.

Two properties matter. It is the EXISTING pipeline, not a fork: the action calls the
same `src/cli.ts` the Taskfile does, so there is no second behaviour to keep in
sync — only a thin shell around it. And inputs flow through the environment, never
template interpolation, so a crafted input can never reach shell parsing — the same
property the Taskfile holds. A dogfood workflow runs the action against this
repository on every push, so the action is gated by CI rather than only exercised by
consumers.

## Consequences

- **Good:** one `uses:` step on GitHub Actions; no new runtime and no release
  artifact — the action is just source the consumer's runner already checks out.
- **Good:** no code-path divergence; the Taskfile and the action share
  `src/cli.ts`.
- **Cost:** the action is GitHub-specific. Every other CI keeps the Taskfile step
  (one line itself).
- **Neutral:** pinning is the consumer's call — `@main` for latest, a tag or SHA for
  reproducibility; the action.yml sits at the repo root, so any ref resolves.

## See also

- [ADR-0019](0019-adoption-git-clone-taskfile.md) (adoption by git clone +
  Taskfile) and [ADR-0020](0020-distribution-git-bun.md) (git + bun distribution) —
  this adds a one-line front door over the same pipeline.
- Code: `action.yml`, `.github/workflows/action-test.yml` (the dogfood gate).
