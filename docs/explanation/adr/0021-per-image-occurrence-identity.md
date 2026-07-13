# ADR-0021: Per-image occurrence identities — `docker:<source>`

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
record settles two questions: what identifies a docker occurrence, and whether
inventories written before the change keep working.

## Decision drivers

- A policy author writes and reviews the identity by hand; it must name the
  place they judged.
- Adding an image or re-pinning a digest must not churn other images' rows or
  scoped policy entries.
- A scoped acceptance must never silently apply where it wasn't reviewed.
- A crafted directory name must not be able to impersonate an image
  occurrence.

## Considered options

1. **Flat `docker:<source>` — chosen.**
2. **Hierarchical `docker:os-packages/<source>`** — keeps ADR-0018's prefix,
   but the middle segment names nothing: every occurrence under it is already
   per-image, and the file covers full image contents, not only OS packages.
3. **The build tag as the identity** — hash-suffixed and non-invertible; a
   policy author cannot write or review it.
4. **Digests in the identity** — a re-pin would churn every scoped policy.
5. **Reading a pre-attribution file under a shared legacy identity** — keeps
   two read paths alive forever to avoid one regeneration.

## Decision

An occurrence identity is `docker:<source>`: the Dockerfile's repo-relative
path for an image the tool builds (`docker:examples/docker-scan/Dockerfile`),
the reference verbatim for an image scanned as-is (`docker:postgres:18`). The
path is what a policy author writes in a `where` scope and reads back on
review; the `os-packages` segment is dropped because it named nothing.

Backward compatibility is deliberately not kept. The committed file is renamed
`docker-os.sbom.json` → `docker.sbom.json` (CLI flag `--docker-sbom`), so
every consumer regenerates once and a freshly named file always carries
per-image attribution — one read path. A file missing attribution fails the
run; a legacy file found without the current one fails loudly naming the
remedy, so an un-regenerated repo never silently loses its docker inventory.

The whole `docker:` prefix is reserved: a non-docker input whose identity
starts with it is refused, because on a POSIX filesystem a directory can be
literally named `docker:whatever` and would otherwise inherit `where`-scoped
acceptances reviewed for an image.

## Consequences

- **Good:** "accepted here, not there" is expressible for images; one reader
  code path; the filename says what the file holds.
- **Bad / cost:** consumers regenerate once — every docker row's Used-in cell
  and every docker-scoped `where` entry changes — and until they do, generate
  and check fail with the remedy rather than proceed without docker rows.
- **Neutral:** the cross-image licence posture is unchanged: a package in two
  images shows one row whose licences come from whichever image sorts first.
  Workspace suppression is not extended to image identities.

## See also

- [ADR-0018](0018-docker-generated-image-scan.md) — the scan model; its
  `docker:os-packages` identity is what this record renames
- [ADR-0005](0005-per-occurrence-model.md) — the per-occurrence model whose
  where-dimension this makes expressible for images
- Code: `src/collectors/dockerOs.ts`, `src/pipeline/pipeline.ts`,
  `src/policy/evaluate.ts`, `src/merge/merge.ts`
