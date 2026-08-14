# ADR-0025: Target-license compatibility lane

- **Status:** Accepted
- **Date:** 2026-08-14

## Context and problem

`.sbomlet.policy.toml`'s compatibility logic was entirely hand-authored:
every accepted licence needed its own `[[compatible]]` entry, re-deriving
well-studied, directional GPL/LGPL/AGPL/MPL compatibility per project. A
vetted, actively-maintained compatibility matrix (OSADL) already exists;
the question was how to embed it as data, not reinvent it by hand.

## Decision drivers

- Vetted data over hand-rolled pairwise logic (ADR-0015) — a wrong
  compatibility verdict is a silent-bypass bug class, not a cosmetic one.
- Additive only: no declared target must render and gate byte-identically
  to today.
- Honest residual (ADR-0007): an uncovered pair stays visible, never `ok`.

## Decision

Embed OSADL's pairwise matrix (tier 1), its per-licence copyleft-class
table (tier 2, the proprietary-target axis), the ScanCode LicenseDB
category index (tier 3), and SBOMlet's own literal copyleft/AGPL id sets
(tier 4, exhaustive) as a fallback chain — the first tier covering a leaf
decides; an uncovered pair is the honest residual, a `warn`/`fail` knob
mirroring `[unknown]`, never a new verdict status. Rejected instead: a
hand-rolled table (doesn't scale), vendoring ORT's rules DSL or flict
(disproportionate surface; flict is GPLv3, SBOMlet is MIT), and modelling
linking mode as a fourth axis (no vetted dataset exists at this scale).

The declared usage profile (`license`/`network`/`distribution`, all
mandatory) gates SCOPE, never the verdict: the flags decide which
obligation class is in play; the matrix always decides the outcome for an
in-scope obligation — an AGPL, network-deployed target absorbs an AGPL
dependency fine (the matrix diagonal), an MIT one still fails it. OSS
cells are read raw, no softening for `Check dependency`/`Questionable`; a
project accepts one itself via `[[compatible]]`. Election becomes
target-aware only inside this lane — the untargeted `elect()` is
unchanged — so a repository with no declared target never routes through
it. `distribution = "internal"` holds a positively-known copyleft/AGPL
obligation out of scope as `ok` with the distinct rule
`target:internal-use`, never a bare `target:ok`, so the exposure stays
enumerable if the profile flips back; an `Unknown` cell or a non-copyleft
incompatibility is never held this way.

Container (`os`-scope) packages stay outside the lane entirely, even under
an AGPL-licensed target — `[[compatible]]` is still the accept path there,
since a base image is the OS's own compliance surface, not the project's.
The one exception: a complete project profile's `network` flag now owns
the "is this container network-deployed" fact the AGPL-container
escalation used to guess at, demoting it under `network = false`. A
per-container profile override is deferred, not rejected — a scoped
`[[compatible]]` already covers the rare divergent case.

Provenance for both datasets lives in-repo beside the vendored files; the
report carries a document-level attribution line (source names +
timestamps, once, licenses document only) plus a scope-of-assertion
statement that it was audited against, and asserts validity only against,
the declared target.

## Consequences

- **Good:** a project declares its licence and deployment shape once
  instead of an accept-list; the answer comes from a maintained external
  matrix, not this tool's own judgment; fully additive and reversible.
- **Bad / cost:** raw-cell strictness produces conservative false-fails
  cured only by a reviewed `[[compatible]]`; ~7% of cells are themselves
  `Unknown`; a proprietary target's weak-copyleft warns are intentionally
  a per-dependency review session; a data refresh is human-reviewed since
  a flipped cell can flip a verdict.
- **Neutral:** the tool trusts the declared profile completely and can't
  verify it against reality; the header line makes that trust boundary
  visible to the document's reader, not just its author.

## See also

- Related: [ADR-0007](0007-honest-residual.md) (the residual principle this
  lane extends), [ADR-0009](0009-dev-prod-os-scopes.md) (the os-scope
  boundary this lane never crosses), [ADR-0013](0013-source-available-deny.md)
  (the deny-precedence this lane sits below),
  [ADR-0015](0015-abstain-over-fragile-parsing.md) (the vetted-data-over-
  hand-authored-rules precedent)
- Code: `src/policy/compat/`, `src/policy/target.ts`,
  `src/policy/evaluate.ts`, `src/render/markdown.ts`
