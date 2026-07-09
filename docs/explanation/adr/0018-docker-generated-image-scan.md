# ADR-0018: One Docker scan model — build the image and scan its full contents

- **Status:** Accepted
- **Date:** 2026-07-09

## Context and problem

Scanning a project's container images had grown six overlapping ways to run: scan
a named image, discover base images from a repository's Dockerfiles, scan a
Dockerfile's base directly, scan a pre-built local image, ingest an externally
attested SBOM, and list Dockerfiles. Several of them scanned only the base a
Dockerfile starts `FROM` — its OS packages, not the application the project builds
on top. It was more ways to do one thing than a maintainer could keep straight,
and the extra paths carried real machinery: a parser that guessed a base image
from `FROM` lines, and a filter that kept only OS packages.

This record settles one question: what does a scan cover, and how does a run reach
it? The removed modes and the kept names both follow from that answer.

## Decision drivers

- **One obvious way in**, not a choice between near-duplicate modes for the same
  result.
- **Scan what a project ships** — a real image's full contents, not a partial view
  of the base it started from.
- **`check` stays offline and daemon-free**, reusing ADR-0012's committed-artifact
  split unchanged.
- **Determinism.** The committed artifact `check` compares against is byte-stable
  across machines and re-runs.

## Considered options

1. **Keep the accreted surface** — familiar, but six ways to do one thing and two
   partial-scan postures.
2. **One model, reached three ways, chosen** — analyze a real image's full
   contents, reached by building named Dockerfiles, discovering and building a
   directory's Dockerfiles, or scanning pre-existing image refs.
3. **One model, images only** — simplest, but drops the build lanes a project
   needs to scan what its own Dockerfiles produce.

## Decision

Every run analyzes the full contents of a real image, reached one of three ways:
build the Dockerfiles you name, discover and build a directory's Dockerfiles, or
scan image references you already have — pulled when absent, scanned as-is when
present. The tool owns the build, tagging each image by a deterministic function
of the Dockerfile path so the same source always scans under the same identity.
The base-image-only scan, the `FROM`-line parser behind it, and the external-SBOM
ingest lane are removed: a Dockerfile is a build input now, not an object of
analysis, so a failing build stops the run loudly instead of being guessed at.

The digest posture from ADR-0012 carries forward — a registry image is pinned to
its digest, a locally built one records an empty digest, and a rebuild that
changes the contents changes the committed artifact. The committed file keeps its
name, `docker-os.sbom.json`, as do the `docker:os-packages` target identity and
the `[os_dependencies]` policy key: renaming them would break every consumer's
`check` for no functional gain, so they stay as a conscious non-rename.

## Consequences

- **Good:** one model a person can hold in their head; the inventory covers what a
  project actually ships, not just its base; a large, fragile Dockerfile parser is
  gone from the surface entirely.
- **Bad / cost:** dropping the base-image and ingest modes is a breaking change for
  anyone who used them — consumers pick up the reduced surface when the CI Action
  updates. An image that bundles the application's own package lists that package
  under the image's scope too, a documented limitation rather than a resolved one.
- **Neutral:** the committed-artifact contract, the purl-keyed merge, the
  `[os_dependencies]` lane, offline `check`, and byte-determinism are all
  unchanged.

## See also

- [ADR-0012](0012-docker-os-via-syft.md) — the base-image model this supersedes
- [ADR-0008](0008-offline-check-committed-cache.md) — the offline-check /
  committed-artifact split this reuses
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — the abstention the removed
  `FROM` parser illustrated, kept as history
- Code: `src/pipeline/dockerSbom.ts`, `src/collectors/dockerBuild.ts`,
  `src/collectors/dockerOs.ts`, `.github/workflows/docker-scan.yml`
