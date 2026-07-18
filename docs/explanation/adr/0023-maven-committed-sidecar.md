# ADR-0023: Read a committed CycloneDX sidecar for Maven, produced by the consumer's own CI

- **Status:** Accepted
- **Date:** 2026-07-17

## Context and problem

Maven has no lockfile. `pom.xml` declares direct dependencies only; the
resolved closure — parent BOMs, `dependencyManagement`, and version
mediation — exists only after Maven itself has run.

Five candidates were run against a real Maven project — hundreds of resolved
dependencies, including a handful of commercial system-scoped jars — to see
which clears that bar.

## Decision drivers

- The full resolved closure, parent-BOM-managed versions included — not just
  what `pom.xml` states directly.
- Licence data, the hard part of Maven: a package's own `<licenses>` block is
  often absent from its POM and resolves only once its parent chain is walked.
- No Maven toolchain, no subprocess, no network reachable from `generate` or
  `check` — the offline-check contract every other ecosystem already holds.
- Canonical `pkg:maven` purls, stable across a double run.

## Considered options

1. **`cyclonedx-maven-plugin`'s `makeBom` goal.** Free access to Maven's own
   resolved model, but needs network access and only runs in the consumer's
   build.
2. **`cdxgen -t java`.** Shells out to `mvn` when present (forbidden at scan
   time); without it, silently emits a small, mostly version-less fraction.
3. **`syft`.** Reads `pom.xml` directs only, many version-less, plus every
   jar in `lib/` under an identity invented from its manifest.
4. **`maven-lockfile`.** Byte-stable, but flattens the reactor past the
   mediated closure, carries no licence data, and commits the machine's own
   OS/Maven/Java versions.
5. **Committed `mvn dependency:tree -DoutputType=json`.** Matches the closure
   and carries Maven scope, but no licence data and no ecosystem tool reads
   the shape.

## Decision

The consumer's CI runs the pinned `cyclonedx-maven-plugin` and commits its
output, `maven.sbom.json`, at each module root; this project reads that
document in process — the same split ADR-0018 draws around the Docker
daemon. `generate` and `check` never invoke Maven.

The plugin's output IS the full resolved closure, classifiers included: it
reads Maven's already-resolved model inside the build, so nearly all of it
resolves a usable licence claim straight from the document. Recovering that
otherwise means fetching every POM and its parent chain over the network,
the fragile-grammar trade ADR-0015 declines. The goal runs per module, so
`makeAggregateBom` — which loses per-module attribution — is not the recipe.

A rare component — a system-scoped commercial jar, a privately-hosted fork —
carries no licence claim and resolves to an honest unknown, recorded with a
`LicenseRef-` `[[clarify]]` expression. A public-record unknown resolves
instead through [deps.dev](https://deps.dev), an aggregator of Central's
metadata whose `"non-standard"` sentinel is dropped, never fabricated.

To classify dev vs. production, the consumer may also commit a second,
test-inclusive document, `maven.test.sbom.json`, built by the same plugin
with `-DincludeTestScope=true` at the same module root and CI run. A
component present only in the test document classifies dev; everything in
the default document classifies production. The two documents' root purls
must be identical — a mismatch throws, naming both — because Maven's scope
never survives the CycloneDX shape (`scope` there is the required/optional
axis, not compile/test), so their separation is the only signal available.
Folding `includeTestScope=true` into one default document is still not a
recovery path: it makes test dependencies indistinguishable from production.
Committing only the default document behaves exactly as before — adopting
the test document is opt-in and backward-compatible.

## Consequences

- **Good:** no Maven toolchain or subprocess needed; deterministic and
  offline by construction, most licence data already committed. The
  test-inclusive document adds real dev/prod classification, Maven's first.
- **Bad / cost:** adopted via a CI step per module, the one-time cost .NET's
  `packages.lock.json` opt-in carries (ADR-0022); dev/prod costs a second
  step and file. An unrecorded component resolves unknown, not bundled.
- **Neutral:** `project.build.outputTimestamp`, set once, keeps a re-run
  byte-identical for both documents; skipping it churns a file on its build
  timestamp like any other stale committed file.

## See also

- Source: `src/collectors/mavenSbom.ts`, `src/enrich/maven.ts`,
  `src/pipeline/targets.ts`
- [ADR-0002](0002-orchestrate-standard-generators.md) — orchestrate, not
  generate at scan time
- [ADR-0007](0007-honest-residual.md) — the honest-residual rule the
  unknowns follow
- [ADR-0008](0008-offline-check-committed-cache.md) — the committed-cache
  split `check` relies on
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — the fragile-parsing
  trade this avoids
- [ADR-0018](0018-docker-generated-image-scan.md) — the committed-artifact
  split this generalizes from
- [ADR-0022](0022-dotnet-lockfile-in-process.md) — the .NET opt-in
  precedent
