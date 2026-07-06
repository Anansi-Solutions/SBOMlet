# ADR-0020: Yarn workspace scan units from lockfile resolutions

- **Status:** Accepted
- **Date:** 2026-07-06

## Context and problem

A Yarn 4 workspaces monorepo keeps one root `yarn.lock` for every member, so
discovery ever finds a single target at the repo root. The Yarn-4 collector
(ADR-0010) then runs its dual-run plugin once, anchored at that root
directory. The plugin builds its SBOM from the current working directory's
own package only, so a workspace's production dependencies never enter the
scan at all — not misclassified, absent. Once the production run finds
nothing, every occurrence in the merged model falls to the same purl set the
dev run produced, and the whole workspace tree classifies development-only.
For a monorepo whose root carries only dev tooling and pushes real
dependencies into its workspaces, that empties the production column
entirely and lets the dev-downgrade lane wave through a shipped copyleft
dependency that should have failed the gate.

The root cause is the scan's shape, not the classification logic: dev/prod
scope and per-target attribution are already correct once the right inputs
reach them (ADR-0009). The tool needed to feed the dual run one directory per
workspace member instead of one directory for the whole tree.

## Decision drivers

- **No silent under-inventory.** A workspace whose production dependencies
  never enter the document is the same failure class ADR-0007's honest
  residual guards against — an absent row is worse than a wrong one, because
  nothing flags it.
- **Structural signal over parsing** (ADR-0015). Workspace membership already
  has one authoritative, already-resolved source: don't hand-roll a second.
- **No new dependency, minimal churn.** The collector, merge, and render
  layers are already correct for multiple targets; the fix should feed them
  the units they expect, not change what they do with them.

## Considered options

1. **Parse the manifest's `workspaces` globs.** Re-implements glob matching
   (`*`, `**`, object form, negations) that Yarn has already resolved once at
   install time — a second implementation of the same semantics, with its own
   edge cases to keep in sync with Yarn's.
2. **Teach discovery to enumerate workspace targets.** Discovery is a pure
   filesystem walk that reads no file contents; giving it lockfile-parsing
   responsibility duplicates the read the collect loop already does and
   changes what "discovery" means.
3. **Expand in the collect loop, from the lockfile's own resolutions --
   chosen.** The lockfile records every workspace member as a literal
   resolved path (`resolution: "<name>@workspace:<path>"`), including glob
   forms already expanded. The collect loop already reads the lockfile text
   once per target; enumerating members there adds no new read and no new
   parsing responsibility upstream.

## Decision

The collect loop expands a Yarn-4-routed target into one scan unit per
workspace member, read from the root lockfile's own `resolution:` lines. Each
unit is a scan unit carrying its own directory, its own identity
(`<target>/<workspace-path>`), and the root lockfile's directory as its
`lockfileDir` for cache-key and manifest purposes. The dual-run plugin runs
once per unit with its working directory set to that unit's own directory, so
each workspace gets its own full and `--production` runs and therefore its
own correct prod/dev split, exactly the split ADR-0009's occurrence model
already expects from a multi-target input.

Expansion only fires when the lock declares both the root member (`.`) and at
least one non-root member; a single-workspace lock (`@workspace:.` only)
takes the exact pre-existing single-scan path, so a repository with one
workspace is untouched. This is also what keeps every non-workspace repo
byte-identical: the root member reuses the original target unchanged, never
becoming a synthetic unit, so its cache key and dispatch stay exactly what a
non-expanded target already produces.

Parsing the manifest's `workspaces` field was rejected because the lockfile
has already done that work: a `resolution:` line is the literal resolved
path, glob or object form and all, with zero glob-matching code required.
Enumerating at discovery time was rejected because discovery's contract is a
pure filesystem walk — teaching it to read and interpret lockfile text would
duplicate the collect loop's own lockfile read and blur the boundary ADR-0010
already draws between discovery and collection.

A crafted or corrupt lockfile could in principle declare a `@workspace:`
path that resolves outside the target directory. Every enumerated unit's
directory is resolved and checked for containment before it is ever returned
from enumeration, and a unit whose resolved directory would escape the
target root is rejected outright rather than scanned — the same
resolve-then-compare posture ADR-0015 already uses for other untrusted
structural signals.

## Consequences

- **Good:** a Yarn-4 workspaces monorepo now gets a complete inventory --
  every workspace's own dependency tree enters the scan — and per-workspace
  attribution, because each unit carries its own identity through merge and
  render. No collector, merge, or render code changed; the fix is entirely in
  what the collect loop hands to the existing dual-run collector.
- **Bad / cost:** a workspaces monorepo with N members now runs 2(N+1) plugin
  invocations instead of 2, each paying its own cold-start cost. Real
  workspace counts are small enough (single digits) that this is a linear,
  bounded cost, not a scaling concern.
- **Neutral:** a single-workspace lock (`@workspace:.` only) and every
  non-yarn or non-workspace target take the exact pre-existing code path --
  the expansion is a structural no-op for them, so no existing golden or
  dogfood output changes.

## See also

- [ADR-0010](0010-js-generator-routing.md) (Yarn-4 generator routing; this
  decision extends its collect step, routing itself is unchanged)
- [ADR-0015](0015-abstain-over-fragile-parsing.md) (the structural-signal
  posture this decision follows — read the lockfile's own resolved paths
  rather than re-implement glob matching)
- [ADR-0009](0009-dev-prod-os-scopes.md) (the per-occurrence dev/prod model
  this decision now feeds correctly for workspace members)
- Code: `src/pipeline/targets.ts` (`expandYarnWorkspaceUnits`,
  `scanWorkspaceUnits`), `src/targets/firstParty.ts`
  (`yarnWorkspaceMembers`), `src/collectors/yarnPlugin.ts`
