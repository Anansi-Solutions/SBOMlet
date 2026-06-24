# ADR-0005: A per-occurrence canonical model

- **Status:** Accepted
- **Date:** 2026-06-11

## Context and problem

The tool merges the output of several collectors into one inventory, keyed by
purl. The same package version often shows up in many places: `react` in both
`frontend` and `apps/scratch`, a build tool in `docs` and `backend`. Two facts
about that package are not global — they change with the place it is used.

The first is the "used in" column: the report has to name every workspace that
pulls a package in, so a reader can see where an obligation lands. The second is
dev/prod scope. A package can legally be a dev dependency in one workspace and a
production dependency in another, and only what ships carries a distribution
obligation. Later we also wanted to record dependency provenance — direct or
transitive, and which parent introduced it — which is likewise per-place: a
package can be declared directly in one workspace and reached transitively in
another.

So the model had to answer "where is this used, and how, in each place?" without
listing the same package once per place and losing the single-row view the
report needs.

## Decision drivers

- The report needs one row per package with every consumer named — not a row per
  package-and-place.
- Dev/prod scope is a property of (package, place), not of the package.
- Per-workspace policy: copyleft suppression matches a single workspace, so the
  place a package is used has to be a value the policy can join on.
- Room to add provenance later without reshaping the model — additive, not a
  migration.
- One stable shape that every downstream stage (merge, policy, render, gate)
  reads the same way.

## Considered options

1. **One entry per (purl, target)** — a flat row per package-and-place. Simple
   to build, but the same package appears many times and the "used in" view has
   to be reconstructed by grouping after the fact.
2. **One entry per purl with package-level dev/prod** — the model's first shape.
   One row per package, but `isDevDependency` lives on the package, so it can
   only hold one answer for a package used as dev in one workspace and prod in
   another.
3. **Delegate the merge to a generic tool** (`cyclonedx-cli merge`) — let an
   external merger fold the per-target SBOMs together. It discards which input a
   component came from, which is exactly the attribution the report is built on.
4. **One entry per purl, with an occurrence per place it is used** — the package
   carries its identity and licence claims once; an `Occurrence` records the
   target, the dev/prod flag for that target, and (where known) the provenance.

## Decision

We chose option 4: one `PackageEntry` per purl, holding a list of `Occurrence`
values — one per place the package is used. The package owns what is genuinely
global (name, version, purl, licence claims, the merged finding); each
occurrence owns what varies by place (the target, its dev/prod flag, its
provenance).

This is the only shape that gives a single row per package *and* keeps dev/prod
correct per workspace. Option 1 keeps scope correct but multiplies the rows and
pushes the grouping work onto every consumer. Option 2 keeps one row but forces
one dev/prod answer per package, which is wrong the moment a package is dev in
one workspace and prod in another — the case that pushed us off it. Option 3
was ruled out at the research stage: a generic merge throws away the source
attribution the whole report depends on, so the merge is ours, keyed on purl.

The model first shipped with package-level scope (option 2) and was migrated to
per-occurrence scope a day later, once the multi-target merge made the
single-answer limit concrete. Provenance was added the same way much later — a
field on the occurrence, no reshaping — which is the additivity this design was
chosen to allow.

## Consequences

- **Good:** One row per package with every consumer named, and dev/prod that is
  correct per workspace. Per-workspace policy has a clean join key: copyleft
  suppression and dev/prod gating both match on `occurrence.target`. Provenance
  dropped in as a per-occurrence field with no migration.
- **Bad / cost:** Consumers that want a package-wide answer have to fold across
  occurrences — a production dependency is "production anywhere it ships", so
  the gate reduces over the occurrence list rather than reading one flag. The
  merge keeps its own occurrence-union code (a Map keyed by target, OR-combining
  the dev flag when the same target appears twice) instead of leaning on a
  library.
- **Neutral:** Occurrences are sorted by target and the whole model serializes
  with sorted keys, so the dump output stays byte-stable. Provenance is present
  only where a usable dependency graph exists (npm and Python); every other
  source leaves it absent and the report shows an honest "—".

## See also

- Plan summaries: `.planning/phases/02-multi-target-collectors-js-python/02-01-SUMMARY.md`,
  `.planning/phases/01-pipeline-spine/01-01-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-13-provenance-SUMMARY.md`
- Research: `.planning/research/ARCHITECTURE.md` (Pattern 2: purl-keyed merge with occurrence attribution)
- Code: `src/model/dependencies.ts`, `src/merge/merge.ts`
- Related: [ADR-0003](0003-cyclonedx-purl-merge.md) (purl as the merge key),
  [ADR-0010](0010-dev-prod-os-scopes.md) (dev/prod and OS scopes),
  [ADR-0016](0016-provenance-root-reachable.md) (dependency provenance)
