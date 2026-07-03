# ADR-0018: Scan the generated images in CI, evolving the base-image consumer model

- **Status:** Accepted
- **Date:** 2026-07-03

## Context and problem

ADR-0012 reads `deb`/`apk` packages from the images a Dockerfile builds `FROM` —
the base a project starts on, not the image it ships. Two things a base-image
scan cannot see: the packages a Dockerfile's own `RUN apt install`/`apk add`
steps add, and the application itself — the app's `npm`/`pypi` dependencies
copied into the final layers. A base scan of a Python app image lists the
Debian packages under it and nothing about the packages `pip` installed on top.
The inventory's claim to completeness depends on scanning the image a project
actually produces and distributes, not only what it started from.

## Decision drivers

- **Complete inventories over partial ones.** An app-layer package that ships
  in the image is exactly as real an obligation as an OS package underneath it.
- **`check` stays offline and daemon-free.** ADR-0012's daemon boundary carries
  forward unchanged.
- **Determinism.** The committed artifact `check` compares against is
  byte-stable across machines and re-runs.
- **Minimal new machinery.** Reuse the existing collector, the existing merge,
  and the existing policy lane rather than build a second inventory path.

## Considered options

1. **Keep base-image-only.** Simplest, but leaves every app-layer package and
   every Dockerfile-installed OS package invisible.
2. **Build and scan the generated images in CI, chosen.** CI builds each
   discovered Dockerfile locally and scans the built result, so the inventory
   covers what the project actually ships.
3. **Rely solely on externally attested SBOMs**, ingested via `--from-sbom`.
   Correct where a build pipeline already produces and signs an SBOM, but it
   assumes that pipeline exists; a project with no attestation step gets no
   generated-image coverage at all.

## Decision

CI builds each discovered Dockerfile with a deterministic, never-pushed local
tag and scans the built result through the tool's built-image mode
(`--built-image`). The collector's filter widens for a built-image scan: instead
of keeping only `pkg:deb`/`pkg:apk`, it keeps every component the image
carries, so application packages (`npm`, `pypi`, …) sit alongside the OS layer
in one scan. The committed artifact stays the same file,
`.sbomlet.cache/docker-os.sbom.json` — the name is now historical, the same
kind of conscious non-rename as the `[os_dependencies]` policy key and the
`docker:os-packages` target identity, both of which predate app-layer coverage
and are left alone rather than chased through every doc and test fixture.

Three boundaries are worth stating plainly, because each is a place a
maintainer's intuition about "the SBOM changed" needs correcting.

**Built-image identity.** A locally built, never-pushed tag has no registry
digest — `docker inspect` returns nothing to pin, unlike a pulled base image,
so the sidecar records an empty digest for it. A rebuild that changes the
image's contents (a dependency bump, a new `RUN` layer) legitimately changes
the scanned components, and that is a real content change the commit-back step
exists to record — not a determinism violation. Scanning the same built image
twice without rebuilding still produces byte-identical output; only a genuine
content change moves the artifact. Pulled base images are unaffected: their
digest-pin contract from ADR-0012 is unchanged.

**Commit-back mechanics.** CI regenerates the inventory after every build-and-scan
and commits the result back so the repository never drifts from what was last
built. On a push, the workflow commits the regenerated artifacts through the
`createCommitOnBranch` GraphQL mutation, producing a GitHub-signed Verified
commit from the run's own token; because a `GITHUB_TOKEN`-authored commit does
not retrigger workflows, this cannot loop. On a pull request, the same
divergence instead fails the check red and uploads the regenerated artifacts,
so a contributor pulls them down and commits deliberately rather than the bot
committing to a fork or an unreviewed branch. Whichever lane a given change
takes is a property of the triggering event, not a configuration choice.

**Dedup and the dev-flip.** The built image's packages enter the same
purl-keyed merge every other collector feeds. A purl already seen at the
application level keeps its application scope and occurrence list; the image
scan only adds the image as one more place the package was used, recorded in
its Used-in column. The consequence is deliberate: an application dependency
that is dev-only everywhere else but ships inside the built image classifies
as production, because a distributed image carries the same distribution
obligation as any other shipped artifact, regardless of how the dependency was
declared upstream.

## Consequences

- **Good:** the inventory now covers what a project actually ships — the
  application layer as well as the OS layer — without a maintainer round-trip;
  a fresh scan-and-commit runs on every push that touches image sources. No new
  merge or policy machinery: the existing purl-keyed merge and the existing
  `[os_dependencies]` lane both already generalize to a fuller component set.
- **Bad / cost:** an image rebuild churns the committed artifact whenever the
  image's actual contents change, which is correct but means the sidecar
  updates more often than a base-image-only scan ever did. A repository whose
  built image contains the application's own package lists that package under
  the image's scope too — there is no root-purl suppression on the docker
  input, so this is a documented limitation rather than a resolved one.
- **Neutral:** the `--from-sbom` ingest lane is unaffected and stays
  OS-shaped; widening it to accept full-content externally-attested SBOMs is a
  possible future extension, not something this decision requires. Every
  base-image mode from ADR-0012 — `--image`, `--repo-root`, `--dockerfile` —
  remains, unchanged, for a project that only wants base coverage.

## See also

- [ADR-0012](0012-docker-os-via-syft.md) (the base-image model this evolves)
- [ADR-0008](0008-offline-check-committed-cache.md) (the offline-check /
  committed-artifact split this decision reuses)
- [ADR-0017](0017-cache-directory-layout.md) (where the committed sidecar
  lives)
- Code: `src/collectors/dockerOs.ts`, `src/pipeline/dockerSbom.ts`,
  `.github/workflows/docker-scan.yml`
