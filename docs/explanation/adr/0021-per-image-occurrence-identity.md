# ADR-0021: Per-image occurrence identities — `docker:os-packages/<source>`

- **Status:** Accepted
- **Date:** 2026-07-13

## Context and problem

Accepting a package is a judgment about a context: busybox reviewed in one
image's OS layer says nothing about the same package in a second image. Every
docker package shared one occurrence identity, `docker:os-packages`: two
Dockerfiles' packages were indistinguishable to policy, and an acceptance
reviewed for one covered the other.

The identity renders in consumers' committed THIRD_PARTY files and is what
`where` scopes are written against, so the choice is costly to reverse. This
record settles one question: what identifies a docker occurrence, and how
existing inventories migrate.

## Decision drivers

- A policy author writes and reviews the identity by hand; it must name the
  place they judged.
- Adding an image or re-pinning a digest must not churn other images' rows or
  scoped policy entries.
- An existing committed inventory keeps working, and a scoped acceptance must
  never silently apply where it wasn't reviewed.

## Considered options

1. **Hierarchical `docker:os-packages/<source>` — chosen.**
2. **The build tag as the identity** — hash-suffixed and non-invertible; a
   policy author cannot write or review it.
3. **A flat `docker:<image>` namespace** — renames the prefix ADR-0018
   deliberately kept, for no gain.
4. **Split only multi-image repositories** — identity would depend on how many
   images a repo scans; a second Dockerfile churns the first's rows anyway.
5. **Digests in the identity** — a re-pin would churn every scoped policy.
6. **The Dockerfile's directory as the identity** — two Dockerfiles in one
   directory are legal and would collide; the prefix match already gives
   directory granularity.

## Decision

An occurrence identity is `docker:os-packages/<source>`: the Dockerfile's
repo-relative path for an image the tool builds, the reference verbatim for
an image scanned as-is. The path is what a policy author writes in a `where`
scope and reads back on review; the build tag lost because it is derived from
the path through a non-invertible sanitizer.

The committed `docker-os.sbom.json` gains the attribution additively —
per-package image membership, per-image source — and the new fields' presence
is the only version marker; an explicit version field would lock one more
byte to say what field presence already says.

A file written before attribution reads under the old shared identity, which
no rule scoped below the prefix can match: a scoped acceptance can never
silently apply, the package flags on its own, and a one-line hint names the
regeneration fix.

## Consequences

- **Good:** "accepted here, not there" is expressible for images; a bare
  `docker:os-packages` scope keeps a pre-existing acceptance covering every
  image, as an explicit choice.
- **Bad / cost:** consumers regenerate once — the Used-in cell of every docker
  row changes, the same posture as every prior committed-artifact change. The
  cross-image licence posture becomes visible: a package in two images shows
  one row whose licences come from whichever image sorts first — today's
  posture made honest, deliberately not changed.
- **Neutral:** workspace suppression is not extended to image identities; its
  justification needs a workspace's own distribution licence, which an image
  does not have.

## See also

- [ADR-0018](0018-docker-generated-image-scan.md) — the scan model and the
  `docker:os-packages` non-rename this extends
- [ADR-0005](0005-per-occurrence-model.md) — the per-occurrence model whose
  where-dimension this makes expressible for images
- Code: `src/collectors/dockerOs.ts`, `src/pipeline/pipeline.ts`,
  `src/policy/evaluate.ts`
