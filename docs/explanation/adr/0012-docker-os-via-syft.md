# ADR-0012: Docker OS packages via syft, consumed as a committed digest-pinned SBOM

- **Status:** Accepted
- **Date:** 2026-06-15

## Context and problem

A container image ships an operating system made of packages — glibc, bash, openssl,
the whole Debian or Alpine base — each with its own licence. A complete inventory
accounts for them, so the tool reads the `deb` and `apk` packages out of the images
a project distributes and resolves their licences.

Two questions came first. Which tool extracts the packages and their licences? The
tool already leans on cdxgen for JS and Python, so the obvious move was to point
cdxgen at the images too. And where does that extraction run? Every other collector
runs on both `generate` and `check` — `check` re-runs the collect loop in memory and
byte-compares. A collector that scans a Docker image would drag a running Docker
daemon onto every CI `check`, which breaks the offline, daemon-free gate.

## Decision drivers

- **The OS licences have to be real.** An inventory that lists every Debian package
  as `unknown` is not an inventory of licences. Whatever extracts the packages
  resolves their licences across `deb` and `apk`.
- **`check` stays offline and daemon-free.** The gate runs in CI with no Docker
  daemon and no network.
- **Minimal dependencies, orchestrate don't reinvent.** Parsing dpkg `copyright`
  files and apk licence fields ourselves is the fragile hand-rolled parsing the tool
  avoids.
- **Determinism.** The committed artifact `check` compares against is byte-stable
  across machines and re-runs.

## Considered options

For the extractor:

1. **cdxgen `-t docker`** — reuse the tool we already run for JS and Python.
2. **syft** — Anchore's container SBOM tool, used only for the OS collector.
3. **Hand-roll dpkg/apk parsing** — read the package databases ourselves.

For where it runs:

4. **A registered collector** — scan images on every run, like every other
   collector.
5. **A generate-only step that writes a committed SBOM** — the maintainer scans and
   commits; `check` only reads the file.

## Decision

We use syft for the extraction and consume a separately committed, digest-pinned
`.sbomlet.cache/docker-os.sbom.json` rather than scanning on the gate path.

syft won the licence-fill measurement. On `postgres:18` cdxgen `-t docker` resolved
210 Debian packages and zero licences; syft resolved the same base at 96.7% (145 of
150) with mostly precise SPDX ids, and Alpine apk at 100%. The "prefer cdxgen" lean
is per-collector and settled by spike: cdxgen keeps the JS and Python collectors it
serves well, and syft owns the OS collector it is built for. Hand-rolling the parsers
was rejected on the minimal-dependency driver — dpkg copyright is free-text, apk
licences are their own field, and syft already maps both to SPDX. syft adds no
runtime dependency: it is a pinned, checksummed CLI orchestrated through mise/aqua,
like docker and tofu.

The second half keeps the daemon off the check path. The OS scan is a generate-only
step: the maintainer runs `generate-docker-sbom`, which builds or pulls the images,
scans them with syft, and writes `.sbomlet.cache/docker-os.sbom.json`. CI's `check`
reads that committed file as one more merge input and never scans. This is the same
split the enrichment cache uses (ADR-0008): `generate` writes committed bytes,
`check` only reads them. A missing file means no OS entries and no scan. The
collector is deliberately not registered, because a registered collector would run
inside the `check` collect loop and force a daemon onto every gate run.

What pins the artifact to a real image is the digest. After scanning, the step
records the platform RepoDigest of the image it scanned (`docker inspect`, not
`buildx imagetools inspect`, which returns the manifest-list digest). `check` never
re-resolves it, so drift surfaces the next time the maintainer regenerates and the
committed bytes differ.

## Consequences

- **Good:** the OS section carries real licences (96.7% deb, 100% apk on the dogfood
  images) instead of a wall of `unknown`. The gate stays offline and daemon-free —
  `check` exits 0 in CI with no Docker and no network. No runtime dependency added.
  The committed SBOM is byte-deterministic: it re-emits a minimal CycloneDX document
  through the tool-wide sorted-JSON contract, dropping syft's `serialNumber` and
  `metadata.timestamp`, with the image identified by content digest.
- **Bad / cost:** the inventory is only as fresh as the last commit of
  `docker-os.sbom.json`. A base-image bump not followed by a regenerate leaves the OS
  packages stale until the maintainer reruns the scan; the digest pin makes the
  staleness visible at regenerate time but does not refresh it. The OS scope is
  informational by policy (the deny terminal, ADR-0013, stays above it): expected
  base-image copyleft is satisfied by shipping the image, so the gate lists OS
  packages rather than failing on every base.
- **Neutral:** a digest-pinned committed SBOM is the shape a build CI would attest.
  The consume path (`consumeDockerOsSbom`) ingests pre-made syft SBOMs produced
  elsewhere without running Docker locally — the build attests, the tool consumes.
  Produce it from a single-arch image so the recorded digest pins the layers actually
  inventoried.

## See also

- Plan summaries:
  `.planning/phases/07-docker-os-packages/07-01-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-03-SUMMARY.md`
- Related: [ADR-0009](0009-dev-prod-os-scopes.md) (the OS scope this feeds),
  [ADR-0013](0013-source-available-deny.md) (the deny terminal above OS scope),
  [ADR-0017](0017-cache-directory-layout.md) (where the committed SBOM lives)
- Code: `collectors/dockerOs.ts`, `pipeline/dockerSbom.ts`
