# ADR-0020: Yarn workspace scan units from lockfile resolutions

- **Status:** Accepted
- **Date:** 2026-07-06

## Context and problem

A Yarn 4 workspaces monorepo keeps one root `yarn.lock`, so discovery finds a
single target at the repo root and the dual-run plugin (ADR-0010) scans only
the root package's own dependencies. Workspace members' production
dependencies never enter the document — not misclassified, absent — and the
whole tree classifies development-only, letting the dev-downgrade lane wave
through shipped dependencies that should fail the gate.

Scope classification and per-target attribution are already correct once the
right inputs reach them (ADR-0009). The scan needed one unit per workspace
member instead of one for the whole tree; the question was where the member
list comes from.

## Decision drivers

- **No silent under-inventory** — an absent row is the failure class the
  honest residual (ADR-0007) guards against.
- **Structural signal over parsing** (ADR-0015): workspace membership already
  has one authoritative, already-resolved source.
- **Minimal churn** — collector, merge, and render already handle multiple
  targets correctly.

## Considered options

1. **Parse the manifest's `workspaces` globs** — re-implements glob matching
   (`*`, `**`, object form, negations) Yarn already resolved at install time.
2. **Enumerate at discovery time** — hands the pure filesystem walk
   lockfile-parsing duties it deliberately doesn't have.
3. **Expand in the collect loop from the lockfile's own resolutions —
   chosen** — every member appears as a literal resolved path
   (`resolution: "<name>@workspace:<path>"`), globs already expanded, in a
   file the loop already reads once per target.

## Decision

The collect loop expands a Yarn-4-routed target into one scan unit per
workspace member, read from the root lockfile's `resolution:` lines. Each
unit carries its own directory, its own identity
(`<target>/<workspace-path>`), and the root lockfile's directory as its
`lockfileDir`; the dual-run plugin runs per unit, so each workspace gets its
own prod/dev split. The manifest option was rejected because the lockfile has
already done that work with zero glob code; the discovery option because
reading file contents there would blur the discovery/collection boundary
ADR-0010 draws and duplicate the collect loop's read.

Expansion fires only when the lock declares both the root member (`.`) and at
least one non-root member; a single-workspace lock takes the exact
pre-existing single-scan path. Every enumerated directory is resolved and
containment-checked against the target root, and a `@workspace:` path that
would escape is rejected outright — ADR-0015's resolve-then-compare posture
for untrusted structural signals.

## Consequences

- **Good:** a workspaces monorepo gets a complete inventory with
  per-workspace attribution; no collector, merge, or render code changed.
- **Bad / cost:** N members cost 2(N+1) plugin invocations instead of 2, each
  with its own cold start — linear and small at real workspace counts.
- **Neutral:** single-workspace and non-yarn targets take the exact
  pre-existing code path; no golden or dogfood output changes.

## See also

- [ADR-0010](0010-js-generator-routing.md) — extends its collect step;
  routing itself is unchanged
- [ADR-0009](0009-dev-prod-os-scopes.md) — the per-occurrence dev/prod model
  this now feeds correctly
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — the structural-signal
  posture followed here
- Code: `src/pipeline/targets.ts` (`expandYarnWorkspaceUnits`,
  `scanWorkspaceUnits`), `src/targets/firstParty.ts`
  (`yarnWorkspaceMembers`)
