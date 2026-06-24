# ADR-0003: CycloneDX as the interchange format, purl as the merge key

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The tool runs a generator per scan target — a yarn workspace, a `poetry.lock`,
a Terraform directory, a Docker image — and then has to fold all of those
outputs into one inventory. Two questions had to be settled before any of the
pipeline could be built: what format the generators speak, and what identity the
merge joins on.

The format question is mostly settled by the ecosystem: the standard generators
we orchestrate (cdxgen, syft) emit CycloneDX or SPDX, and we shouldn't invent a
third shape. The merge-key question is the one with teeth. The same package
shows up in several workspaces, and the output needs a "used in" column, so the
merge has to recognise "this is the same package" across documents. Get the
identity wrong and two different packages collapse into one row, or one package
splits into two.

## Decision drivers

- **A correct cross-ecosystem identity.** The key must distinguish a npm package
  from a PyPI package of the same name, and must not merge `@types/react` with
  `react`. Name plus version is known to be wrong here.
- **"Used in" attribution is a core output, not an extra.** The merge has to
  keep, per package, the list of targets it came from — and that list is also
  the join key the policy uses for per-workspace copyleft suppression. Losing it
  is not an option.
- **Minimal dependency footprint, standard formats.** We want SPDX license
  identifiers and a recognised SBOM format, and we want to lean on the
  generators rather than parse lockfiles ourselves.
- **The merge owns the model.** Everything downstream — normalisation, policy,
  rendering — reads our canonical types, never the raw SBOM. The interchange
  format must be something we can narrow into those types and otherwise ignore.

## Considered options

1. **CycloneDX in, purl as the merge key, our own merge code** — every generator
   emits CycloneDX JSON; we join components on their package URL.
2. **SPDX documents as the interchange format** — consume SPDX instead of, or
   alongside, CycloneDX.
3. **Name + version as the merge key** — the obvious join, possibly via a
   generic merge tool like `cyclonedx-cli merge`.

## Decision

Every collector emits CycloneDX, and the merge joins components on their purl
into one canonical model, keyed by the purl string verbatim. We write the merge
ourselves rather than delegating it.

Purl wins on identity. A package URL already encodes the ecosystem
(`pkg:npm/...` vs `pkg:pypi/...`), the namespace, the name, and the version, so
it distinguishes packages that name+version conflates and never merges two
genuinely different ones. Name+version is known-wrong across ecosystems —
same-named npm and PyPI packages collide, and `@types/react` is not `react`. It
also fails to separate a scoped package from its bare twin. Choosing it would
trade correctness for a key that looks simpler and isn't.

CycloneDX wins on format because the strongest generators for our ecosystems
(cdxgen for JS and Python, syft for Docker) speak it natively and carry purls,
license claims in the three shapes we need, and the `cdx:*` properties we read
for dev/prod and workspace markers. SPDX is an equally standard format, but it
would mean a second parse path and a second mental model for no gain — both our
generators already emit CycloneDX, so consuming SPDX would add surface without
adding coverage. We narrow only the subset of CycloneDX we use and tolerate
every other field, so the format choice stays cheap.

We do the merge ourselves, in roughly a couple of hundred lines, instead of
shelling out to a generic merge tool. A generic merge discards which input
document a component came from — and that is exactly the "used in" attribution
we cannot lose. `cyclonedx-cli merge` additionally has open dedup defects
(components with differing bom-refs are not deduped). Owning the merge lets us
key on purl, accumulate a per-target occurrence list, and keep full control of
the model the rest of the pipeline depends on.

## Consequences

- **Good:** one identity that is correct across ecosystems; the "used in" column
  and per-occurrence policy join fall out of the occurrence list for free; the
  rest of the tool reads our model and never has to know CycloneDX exists.
- **Good:** the merge is a pure function over parsed documents — no I/O, no
  logging — so every merge rule is table-testable and golden-lockable.
- **Bad / cost:** we maintain merge code and a hand-narrowed view of the
  CycloneDX shape. The official JS library serialises but cannot deserialise
  CycloneDX, so the consumed subset lives behind our own validation boundary.
- **Neutral:** the key is the purl string verbatim, URL-encoding intact (`%40`
  stays `%40`), never the bom-ref — bom-refs are document-local and not an
  identity. A source that emits no purl for a component contributes nothing to
  the inventory; that is the honest residual, not a silent drop.
- **Neutral:** because the merge is ours, the few places where two documents
  disagree about one purl (dev/prod flags, scope, claims) are reconciled by
  explicit, order-independent rules rather than by whichever document arrived
  first.

## See also

- Research: `.planning/research/ARCHITECTURE.md` (Pattern 2, Anti-Pattern 1)
- Plan summaries: `.planning/phases/01-pipeline-spine/01-01-SUMMARY.md`,
  `.planning/phases/01-pipeline-spine/01-02-SUMMARY.md`
- Related: [ADR-0002](0002-orchestrate-standard-generators.md),
  [ADR-0005](0005-per-occurrence-model.md)
- Code: `src/merge/merge.ts`, `src/model/dependencies.ts`, `src/validate/sbom.ts`
