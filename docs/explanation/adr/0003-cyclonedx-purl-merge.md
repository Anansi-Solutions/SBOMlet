# ADR-0003: CycloneDX as the interchange format, purl as the merge key

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The tool runs a generator per scan target — a Yarn workspace, a `poetry.lock`, a
Terraform directory, a Docker image — then folds all of it into one inventory. Two
questions had to be settled first: what format the generators speak, and what
identity the merge joins on.

The format is largely settled by the ecosystem: the generators we orchestrate emit
CycloneDX or SPDX. The merge key is the harder question. The same package shows up
in several workspaces, and the report needs a "used in" column, so the merge has to
recognise the same package across documents. A wrong identity either collapses two
packages into one row or splits one into two.

## Decision drivers

- **Correct cross-ecosystem identity.** The key must distinguish an npm package
  from a PyPI package of the same name, and must not merge `@types/react` with
  `react`. Name-plus-version does neither.
- **"Used in" is a core output.** The merge must keep, per package, the targets it
  came from; that list is also the join key the policy uses for per-workspace
  copyleft suppression.
- **Standard formats, small footprint.** We want SPDX identifiers and a recognised
  SBOM format, and to rely on the generators rather than parse lockfiles.
- **The merge owns the model.** Everything downstream reads our canonical types, so
  the interchange format must be something we can narrow and otherwise ignore.

## Considered options

1. **CycloneDX in, purl as the merge key, our own merge code** — every generator
   emits CycloneDX JSON; we join components on their package URL.
2. **SPDX as the interchange format** — consume SPDX instead of, or alongside,
   CycloneDX.
3. **Name + version as the merge key** — the obvious join, perhaps via a generic
   tool like `cyclonedx-cli merge`.

## Decision

Every collector emits CycloneDX, and the merge joins components on their purl
into one canonical model, keyed by the purl string verbatim. We write the merge
ourselves.

Purl gives correct identity: it encodes the ecosystem (`pkg:npm/…` vs
`pkg:pypi/…`), namespace, name, and version. Name+version collides same-named
npm and PyPI packages and cannot separate a scoped package from its bare twin.

CycloneDX is the format because cdxgen and syft emit it natively, carrying
purls, the licence-claim shapes we need, and the `cdx:*` properties for
dev/prod and workspace markers. SPDX is equally standard but would add a second
parse path for no coverage gain.

We do the merge ourselves rather than shelling out to a generic tool: a generic
merge discards which input document a component came from — the "used in"
attribution we need — and `cyclonedx-cli merge` has open dedup defects. Owning
it lets us key on purl and accumulate a per-target occurrence list.

## Consequences

- **Good:** one identity correct across ecosystems; the "used in" column and
  per-occurrence policy join come from the occurrence list; the rest of the tool
  never sees CycloneDX.
- **Good:** the merge is a pure function over parsed documents — no I/O, no
  logging — so every rule is table-testable and golden-lockable.
- **Bad / cost:** we maintain merge code and a hand-narrowed view of CycloneDX. The
  official JS library serialises but cannot deserialise CycloneDX, so the consumed
  subset sits behind our own validation boundary.
- **Neutral:** the key is the purl string verbatim, URL-encoding intact (`%40`
  stays `%40`), never the document-local bom-ref. A source that emits no purl
  contributes nothing — the honest residual, not a silent drop.

## See also

- Related: [ADR-0002](0002-orchestrate-standard-generators.md) (the generators
  whose CycloneDX we merge), [ADR-0005](0005-per-occurrence-model.md) (the model
  the merge builds)
- Code: `src/merge/merge.ts`, `src/model/dependencies.ts`, `src/validate/sbom.ts`
