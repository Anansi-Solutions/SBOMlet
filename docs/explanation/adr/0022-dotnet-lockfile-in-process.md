# ADR-0022: Parse packages.lock.json in-process for .NET

- **Status:** Accepted
- **Date:** 2026-07-13

## Context and problem

ADR-0002 commits the tool to orchestrating standard SBOM generators rather
than parsing ecosystems itself. Adding .NET support forced the question of
whether any generator earns that role here.

The only committed file carrying a .NET project's complete dependency set is
`packages.lock.json`, written when a project opts in with
`RestorePackagesWithLockFile=true`. The alternatives cannot feed the offline
gate (ADR-0008): project files alone list direct dependencies only — 3 of 84
packages in the evaluation fixture — and `project.assets.json`, the full
resolution, is a gitignored build artifact absent on a fresh clone. So the
input is settled; the decision is what reads it.

## Decision drivers

- The full third-party set, deterministically, offline, with no side effects
  inside the scanned repository.
- Canonical `pkg:nuget` purls that merge across targets and key enrichment.
- No new dependency or subprocess for data the lockfile already carries.

## Considered options

Each candidate was run against a restored two-project fixture (84 known
packages):

1. **cdxgen `-t dotnet`** — reads the lockfile, but hard-fails on
   single-project layouts (a duplicated project reference trips its own
   schema validation: exit 1, no output) and emits zero license and zero
   scope data when it succeeds.
2. **syft** — re-emits the same lockfile entries with no per-target scoping
   and no dedup across lockfiles; first-party entries included; zero licenses.
3. **cyclonedx-dotnet** — the only candidate with license data, but it runs a
   package restore inside the scanned repository, or silently emits zero on a
   fresh clone with restore disabled.
4. **dotnet list package** — requires a restore first; no purls.
5. **Microsoft sbom-tool** — SPDX only, every license NOASSERTION, a volatile
   per-run document namespace.
6. **Parse the lockfile in-process** — read the committed JSON directly.

## Decision

The tool parses `packages.lock.json` in-process, the same conscious exception
already made for `bun.lock` (ADR-0010). Every candidate that avoids side
effects reads this one file and adds nothing to it, while the lockfile itself
carries strictly more machine-readable signal than any of their outputs:
entry types including the first-party project marker, pinned versions, and
per-entry dependency maps.

The runner-up was cdxgen with `--no-validate`, which clears its crash — at
the cost of shipping known schema-invalid documents and forking the shared
generator arguments for zero added data.

This is not an ADR-0015 violation: the input is structured JSON with a
documented schema, read with a strict JSON parse and a tolerant narrow, not
a hand-rolled text grammar.

## Consequences

- **Good:** scanning needs no .NET toolchain and no subprocess; the collector
  is deterministic and offline by construction; first-party project
  references are excluded by the lock's own entry-type marker.
- **Bad / cost:** adopters must opt into lockfiles, and most projects have
  not: in one real-world multi-project repository, 97 of 164 projects carried
  no committed lockfile. The lock has no dev/prod marker, so every package
  gates as production. Embedded-license-file and pre-2019 url-only packages
  resolve to honest unknowns.
- **Neutral:** paket uses its own lockfile format and is a separate,
  unsupported lane. `getting-started.md` documents the prerequisite, and
  `dotnet restore --locked-mode` in the adopter's CI makes a stale lockfile
  their build error. The lock format itself is owned by the SDK and has moved
  before (version 1 → 2): a scheduled canary
  (`.github/workflows/dotnet-canary.yml`) restores a probe project with the
  newest GA SDK monthly and runs the collector over the resulting lockfile,
  so a format move fails this repository's CI before it reaches an adopter.
  A future enrichment arm could route github license URLs
  through the existing license lookup, recovering much of the url-only class.

## See also

- Source: `src/collectors/nugetLock.ts`, `src/enrich/nuget.ts`
- Related:
  - [ADR-0002](0002-orchestrate-standard-generators.md) — the rule this excepts
  - [ADR-0008](0008-offline-check-committed-cache.md) — inputs must be committed
  - [ADR-0010](0010-js-generator-routing.md) — the bun.lock precedent
  - [ADR-0015](0015-abstain-over-fragile-parsing.md) — no fragile text grammars
