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
dev/prod scope: a package can legally be a dev dependency in one workspace and a
production dependency in another, and only what ships carries a distribution
obligation. Provenance — direct or transitive, and which parent introduced it —
is per-place too.

So the model had to answer "where is this used, and how, in each place?" without
listing the same package once per place and losing the single-row view the report
needs.

## Decision drivers

- One row per package with every consumer named — not a row per package-and-place.
- Dev/prod scope is a property of (package, place), not of the package.
- Per-workspace policy: copyleft suppression matches a single workspace, so the
  place a package is used has to be a value the policy can join on.
- Room to add provenance later without reshaping the model.

## Considered options

1. **One entry per (purl, target)** — a flat row per package-and-place. Simple,
   but the same package appears many times and "used in" has to be reconstructed
   by grouping after the fact.
2. **One entry per purl with package-level dev/prod** — one row per package, but
   `isDevDependency` lives on the package, so it holds only one answer for a
   package used as dev in one workspace and prod in another.
3. **One entry per purl, with an occurrence per place it is used** — the package
   carries its identity and licence claims once; an `Occurrence` records the
   target, its dev/prod flag, and (where known) its provenance.

## Decision

We chose option 3: one `PackageEntry` per purl, holding a list of `Occurrence`
values. The package owns what is genuinely global (name, version, purl, licence
claims, the merged finding); each occurrence owns what varies by place (the
target, its dev/prod flag, its provenance).

This is the only shape that gives a single row per package *and* keeps dev/prod
correct per workspace. Option 1 keeps scope correct but multiplies the rows and
pushes the grouping onto every consumer. Option 2 keeps one row but forces one
dev/prod answer per package, wrong the moment a package is dev in one workspace
and prod in another — the case that pushed the model from package-level scope
(shipped first) to per-occurrence a day later. Provenance was added the same
way much later, as a field on the occurrence with no reshaping — the additivity
this design was chosen to allow.

## Consequences

- **Good:** one row per package with every consumer named, and dev/prod correct
  per workspace. Per-workspace policy has a clean join key: copyleft suppression
  and dev/prod gating both match on `occurrence.target`. Provenance dropped in as
  a per-occurrence field with no migration.
- **Bad / cost:** consumers that want a package-wide answer have to fold across
  occurrences — a production dependency is "production anywhere it ships", so the
  gate reduces over the occurrence list rather than reading one flag. The merge
  keeps its own occurrence-union code (a Map keyed by target, OR-combining the dev
  flag when the same target appears twice).
- **Neutral:** occurrences are sorted by target and the whole model serializes
  with sorted keys, so the dump stays byte-stable. Provenance is present only
  where a usable dependency graph exists (npm and Python); every other source
  leaves it absent and the report shows an honest "—".

## See also

- Related: [ADR-0003](0003-cyclonedx-purl-merge.md) (purl as the merge key),
  [ADR-0009](0009-dev-prod-os-scopes.md) (dev/prod and OS scopes gate on this
  model), [ADR-0014](0014-dependency-provenance.md) (provenance, the additive
  field)
- Code: `src/model/dependencies.ts`, `src/merge/merge.ts`
