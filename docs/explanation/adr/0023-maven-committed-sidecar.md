# ADR-0023: Read a committed CycloneDX sidecar for Maven, produced by the consumer's own CI

- **Status:** Accepted
- **Date:** 2026-07-17

## Context and problem

Maven has no lockfile. `pom.xml` declares direct dependencies only; the
resolved closure — parent BOMs, `dependencyManagement`, and version
mediation — exists only after Maven itself has run. The design test still
holds: a fresh clone reproduces `check` offline, with no build step.

Five candidates were run against a real Maven project — hundreds of
resolved dependencies, including a handful of commercial system-scoped
jars — to see which clears that bar.

## Decision drivers

- The full resolved closure, parent-BOM-managed versions included — not just
  what `pom.xml` states directly.
- Licence data, the hard part of Maven: a package's own `<licenses>` block is
  often absent from its POM and resolves only once its parent chain is walked.
- No Maven toolchain, no subprocess, no network reachable from `generate` or
  `check` — the offline-check contract every other ecosystem already holds.
- Canonical `pkg:maven` purls, stable across a double run.

## Considered options

1. **`cyclonedx-maven-plugin`'s `makeBom` goal.** Reads Maven's own resolved
   model, so every managed version and inherited licence comes free — but
   declares `requiresOnline` and runs only inside the consumer's build.
2. **`cdxgen -t java`.** With `mvn` on `PATH` it shells out to it inside the
   scanned repo (forbidden at scan time); without it, exits `0` having
   emitted a small, mostly version-less fraction of the closure.
3. **`syft`.** `pom.xml` directs only (many version-less), plus every jar
   in `lib/` — stale versions included — under an identity invented from the
   jar manifest.
4. **`maven-lockfile`.** Byte-stable, but flattens the reactor past the
   mediated closure, carries no licence data, and commits the machine's
   OS/Maven/Java versions by default.
5. **Committed `mvn dependency:tree -DoutputType=json`.** Matches the closure
   exactly and is the only one carrying Maven scope, but carries no licence
   data and no ecosystem tool reads the shape.

## Decision

The consumer's CI runs the pinned `cyclonedx-maven-plugin` and commits its
output, `maven.sbom.json`, at each module root; this project reads that
document in process — the same split ADR-0018 draws around the Docker daemon.
`generate` and `check` never invoke Maven.

The plugin's output IS the full resolved closure, classifiers included: it
reads Maven's already-resolved model inside the build, so nearly all of it
resolves a usable licence claim straight from the document. Recovering that
otherwise means fetching each POM and its parent chain over the network, the
fragile-grammar trade ADR-0015 declines. The goal runs per module and writes
one file per module, so `makeAggregateBom`, which loses per-module
attribution, is deliberately not the recipe.

A rare component — a system-scoped commercial jar, a privately-hosted fork —
carries no licence claim and has no public record. It enters as an ordinary
component and resolves to an honest unknown, which a project records with a
`LicenseRef-` `[[clarify]]` expression the tool already accepts end to end.

Unknowns with a public record resolve through [deps.dev](https://deps.dev),
one fetch each — an aggregator of Central's metadata, not a second authority,
so its answer flows through this project's SPDX normalizer, and its
`"non-standard"` sentinel is dropped, never promoted to a fabricated id.

The document carries no per-component scope, so this design carries none:
every component gates as **production**, and `test` scope is absent entirely
(the default `makeBom` excludes it). `includeTestScope=true` is not a recovery
path — the test dependencies it adds arrive indistinguishable from production.
A future sidecar carrying both a default and a test-inclusive document is the
honest way to add dev/prod classification; it is a recorded follow-up.

## Consequences

- **Good:** scanning needs no Maven toolchain and no subprocess; the collector
  is deterministic and offline by construction, with most of the licence data
  already in the committed document.
- **Bad / cost:** a project adopts by adding a CI step per module — the
  one-time cost .NET's `packages.lock.json` opt-in carries (ADR-0022). Every
  component gates as production; a commercial jar with no public record
  resolves as an honest unknown, not a bundled licence.
- **Neutral:** `project.build.outputTimestamp`, set once, keeps a re-run
  byte-identical; skipping it churns the file on its build timestamp, caught
  like any stale committed file.

## See also

- Source: `src/collectors/mavenSbom.ts`, `src/enrich/maven.ts`,
  `src/pipeline/targets.ts`
- [ADR-0002](0002-orchestrate-standard-generators.md) — orchestrate a standard
  generator; the plugin still generates, just not at scan time
- [ADR-0007](0007-honest-residual.md) — the honest-residual rule the unknowns
  and scope omission follow
- [ADR-0008](0008-offline-check-committed-cache.md) — the committed-cache split
  `check` relies on
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — the fragile-parsing trade
  this avoids by reading a committed document
- [ADR-0018](0018-docker-generated-image-scan.md) — the committed-artifact
  split this generalizes from Docker
- [ADR-0022](0022-dotnet-lockfile-in-process.md) — the .NET opt-in-prerequisite
  precedent
