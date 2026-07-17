# ADR-0023: Read a committed CycloneDX sidecar for Maven, produced by the consumer's own CI

- **Status:** Accepted
- **Date:** 2026-07-17

## Context and problem

Maven has no lockfile. `pom.xml` declares direct dependencies only, and the
resolved closure — parent BOMs, `dependencyManagement`, and Maven's own
version mediation — exists only after Maven itself has run. The design test
from earlier ADRs still applies: a fresh clone reproduces `check` offline,
with no build step.

Five candidates were run against a real Maven project — hundreds of
resolved dependencies, including a handful of commercial system-scoped jars
declared with `<scope>system</scope>` — to see which one clears that bar.

## Decision drivers

- The full resolved closure — parent-BOM-managed versions included — not
  just what `pom.xml` states directly.
- Licence data, the hard part of Maven: a package's own `<licenses>` block is
  frequently absent from its POM and only resolves once its parent chain is
  walked.
- No Maven toolchain, no subprocess, and no network reachable from `generate`
  or `check` themselves — the offline-check contract every other ecosystem
  already holds.
- Canonical `pkg:maven` purls, stable across a double run.

## Considered options

1. **`cyclonedx-maven-plugin`'s `makeBom` goal**, run inside the build. Reads
   Maven's own resolved model, so every parent-BOM-managed version and every
   inherited licence comes free. Declares `requiresOnline` and can only run
   as part of the consumer's own build — never at scan time.
2. **`cdxgen -t java`.** With `mvn` on `PATH` it shells out to it inside the
   scanned repository — the exact side effect this project forbids at
   generate/check time. Without `mvn` on `PATH` it exits `0` having silently
   emitted a small fraction of the real closure, many of those components
   with no version at all.
3. **`syft`.** Reads `pom.xml` directs only (many with no version — a
   parent-managed version syft cannot see from text) and separately
   inventories every jar file sitting in a local `lib/` directory, including
   stale versions never referenced by the current `pom.xml`, with an
   identity it invents from the jar's manifest rather than reading.
4. **A maintained Maven lockfile plugin** (`maven-lockfile`). Byte-stable and
   real, but its nested dependency tree flattens the reactor past the
   wrapper's own mediated entries — pre-mediation extras a consumer of the
   file would have to reconcile — carries no licence data at all, and
   commits the machine's own OS/Maven/Java versions into the file by
   default.
5. **`mvn dependency:tree -DoutputType=json`, committed.** Matches the
   mediated closure exactly and is the only candidate to carry Maven's own
   per-dependency scope, but carries no licence data either, and nothing
   else in the Maven ecosystem reads or writes this shape.

## Decision

The consumer's own CI runs the pinned `cyclonedx-maven-plugin` and commits
its output, `maven.sbom.json`, at each module's own root; this project reads
that committed document in process, the same split ADR-0018 draws around the
Docker daemon: the generator that can only run inside its own domain runs
there, and this project reads what it produced. `generate` and `check` never
invoke Maven.

The plugin is the only candidate whose output IS the full resolved closure —
the full resolved closure it wrote for the evaluation fixture is exactly the
wrapper's own known-good set, zero missing, zero extra, classifiers
included — and it carries the licence data every other candidate lacks:
nearly all of those components resolve a usable licence claim straight from
the committed document, because the plugin reads Maven's own already-resolved
model, parent inheritance included, inside the build where that resolution is
free. Recovering that data any other way means fetching and parsing each
package's own POM plus its parent chain over the network at enrichment
time — the fragile-grammar trade ADR-0015 already declines elsewhere, for a
signal this design gets from the committed file instead. A consumer runs the
plugin once at the reactor root; its goal runs per module automatically and
writes one file per module, so collapsing the whole reactor into a single
`maven.sbom.json` is deliberately not the recipe — that goal exists
(`makeAggregateBom`), but it loses the per-module attribution a multi-module
inventory needs.

The remaining rare components with no licence claim on the evaluation
fixture are a system-scoped commercial jar and a privately-hosted fork —
packages with genuinely no public record. They enter the model as ordinary
components and resolve to an honest unknown once enrichment finds nothing
for them, exactly like any other package with no public licence record; a
project records the decision with a `LicenseRef-` `[[clarify]]` expression,
which the tool already accepts end to end with no code change.

Unknowns that do have a public record are resolved through
[deps.dev](https://deps.dev)'s per-version API, one fetch per package, ahead
of a Maven-Central POM fetch with its own parent chain: deps.dev is an
aggregator of Central's own metadata, not a second authority, and its answer
still flows through this project's own SPDX normalizer rather than being
trusted as pre-resolved; a `"non-standard"` answer, deps.dev's own way of
saying it could not classify a package, is dropped rather than promoted into
a fabricated id.

The committed document carries no per-component Maven scope, so this design
carries none either: every component gates as **production**, and Maven's
`test` scope is not merely hidden in a dev column — it is absent from the
committed document entirely, because the plugin's default `makeBom` excludes
it. A consumer cannot recover test dependencies by adding
`includeTestScope=true`: on the evaluation fixture every test dependency that
flag adds arrives indistinguishable from production, so all of them would
gate as production too. A future sidecar carrying both a default document and
a test-inclusive one is the honest way to add real dev/prod classification
for Maven; it is recorded here as a follow-up, not built.

## Consequences

- **Good:** scanning needs no Maven toolchain and no subprocess; the
  collector is deterministic and offline by construction; the committed
  document already carries the bulk of the licence data most ecosystems need
  a network round trip for.
- **Bad / cost:** a project adopts by adding a CI step, one per module — the
  same one-time cost .NET's `packages.lock.json` opt-in carries (ADR-0022).
  Every package gates as production, because the input carries no scope; a
  commercial or system-scoped jar with no public record resolves as an
  honest unknown, not a bundled licence.
- **Neutral:** setting `project.build.outputTimestamp` once, the standard
  reproducible-builds property, is what keeps a re-run byte-identical; a
  consumer who skips it sees the committed file churn on its own build
  timestamp alone, caught the same way any stale committed file is —
  `check` regenerating in memory and finding a byte mismatch.

## See also

- Source: `src/collectors/mavenSbom.ts`, `src/enrich/maven.ts`,
  `src/pipeline/targets.ts` (the reactor first-party pre-pass)
- Related:
  - [ADR-0002](0002-orchestrate-standard-generators.md) — orchestrate a
    standard generator rather than build detection; the plugin still does
    the generating, just not at scan time
  - [ADR-0007](0007-honest-residual.md) — the honest-residual rule this
    lane's unknowns and scope omission both follow
  - [ADR-0008](0008-offline-check-committed-cache.md) — the committed-cache
    split `check`'s hermetic contract already relies on
  - [ADR-0015](0015-abstain-over-fragile-parsing.md) — the fragile-parsing
    trade this design avoids by reading a committed document instead of a
    package's own POM chain
  - [ADR-0018](0018-docker-generated-image-scan.md) — the committed-artifact
    split this design generalizes from Docker to a per-module lockfile kind
  - [ADR-0022](0022-dotnet-lockfile-in-process.md) — the .NET precedent for
    an ecosystem whose committed input is an opt-in prerequisite
