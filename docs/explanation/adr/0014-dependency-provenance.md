# ADR-0014: Dependency provenance — root-reachable introducers, honest residual otherwise

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

When the report flags a dependency, the reviewer asks "why is this here?" —
direct, or pulled in by something else, and what? The attribution table names
every workspace a package is used in; provenance adds a "Why" column that says
*direct* or names the introducer.

The data exists for two ecosystems: the yarn-plugin BOM carries a
root-anchored `dependencies` graph, and `poetry.lock` records each package's
dependency table with `pyproject` declaring the top-level ones. Terraform, the
Docker OS lists, bun, and an npm BOM with no graph give no edges to walk.

The risk is a *wrong* cell, not a blank one. A "direct" on a package that is
transitive, or a named introducer that does not introduce it in the flagged
workspace, is worse than saying nothing — the reviewer reasons from a false
premise. A graph offers several ways to fabricate: a chain stitched across two
versions that share a name, an introducer borrowed from a workspace not on
the row, a parent unreachable from any root. Each surfaced in review as a
plausible value no real relationship supported.

## Decision drivers

- **No fabrication, no mislabel.** A rendered value must describe a
  relationship that exists in the flagged workspace.
- **Honest about what we don't know.** Where no usable graph exists, the cell
  says so.
- **Minimal dependencies.** No PEP-440 solver or HCL parser to answer a
  provenance question.
- **Determinism.** The same inputs produce a byte-identical column.

## Considered options

1. **Skip provenance** — leave the table as it was; the reviewer traces the
   graph by hand.
2. **Answer for every ecosystem** — invent a best-effort introducer for
   Terraform, Docker OS, and graph-less inputs so no cell is blank.
3. **Two graph-backed lanes, honest residual elsewhere** — derive provenance
   only where a real graph exists (npm via the BOM, Python via the lockfile),
   render `—` elsewhere, and hold every derived value to a reachability
   invariant.

## Decision

We render provenance from the two lanes with a real graph, and `—` everywhere
else. Within a lane, one invariant governs: a named introducer must be
reachable from a declared root. A direct package carries no introducer and no
chain; a transitive package carries the parents that introduced it —
intersected with the purls reachable from the roots — and one representative
shortest chain. A package the graph contains but cannot connect to a root has
no derivable introducer, so its cell is `—`. The invariant lives in one shared
derivation both lanes call: the reachable set is computed once per graph by a
breadth-first walk from the roots, every node's parent set is intersected with
it, and the representative chain is gated on the same reachability, so the
introducer set and the chain never disagree.

Skipping provenance leaves the reviewer's question unanswered when the answer
is in the BOM and the lockfile. Answering everywhere means fabricating an
introducer for ecosystems whose artifacts carry no edges, needing a version
solver and an HCL parser to attempt. Two lanes plus an honest residual answers
where the data supports it and says `—` where it does not.

The residual's shape was settled through several adversarial-review rounds
that each found a value looking right but resting on nothing:

- **The cell is scoped to the row's flagged targets.** The "Why" and "Used in"
  cells fold over the same occurrence subset — folding over every occurrence
  let a row borrow "direct" or a chain from an unflagged workspace it never
  names.
- **Introducers are intersected with the root-reachable set** — the central
  invariant above. The npm lane re-derives introducers on the real
  per-resolution graph, not the version-collapsed one, because a chain
  stitched across two resolutions of the same purl exists on no concrete
  instance.
- **Version ambiguity in Python is a residual, not a guess.** When a lockfile
  name maps to several versions, the name alone cannot say which, and
  resolving it would need a PEP-440 solver we declined — so it yields no edge
  and falls to `—`.
- **Optionality was descoped.** An early version marked Python dependencies
  optional from PEP 508 markers and extras; parsing those markers mislabeled
  in three of four review rounds, so it was removed end to end. The npm lane
  never had it — the BOM carries no optional or peer information.

## Consequences

- **Good:** the reviewer gets a real answer where a graph supports one and an
  honest `—` where it does not. A fabricated or mislabeled introducer is
  unrepresentable by construction, and the shared derivation keeps both lanes
  from drifting.
- **Bad / cost:** coverage is uneven. Terraform, Docker OS, bun, and any
  graph-less npm BOM show `—`; a Python dependency reached only through a
  multi-version name shows `—` even where a solver could in principle resolve
  it. Optionality is not reported.
- **Neutral:** provenance is an additive per-occurrence field (ADR-0005), so
  occurrences without it serialize unchanged. The reference monorepo's real
  graphs are entirely root-reachable and single-version, so the fabrication
  paths are exercised by adversarial review, not dogfooding.

## See also

- Related: [ADR-0005](0005-per-occurrence-model.md) (the per-occurrence field
  provenance attaches to), [ADR-0007](0007-honest-residual.md) (the `—`
  residual it shares)
- Code: `collectors/provenanceGraph.ts` (`deriveIntroductions`,
  `reachableFromRoots`), `collectors/npmProvenance.ts`,
  `collectors/poetryProvenance.ts`, `render/markdown.ts` (`whyCellOf`)
