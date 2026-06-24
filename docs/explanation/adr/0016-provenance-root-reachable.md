# ADR-0016: Dependency provenance: root-reachable introducers, honest residual otherwise

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

When the report flags a dependency, the reviewer's first question is "why is
this here?" — did we ask for it directly, or did something else pull it in, and
what? The attribution table already names every workspace a package is used in;
provenance adds the missing half: a "Why" column on the Problematic and Copyleft
tables that says *direct* or names the dependency that introduced it.

The data to answer this only exists for two ecosystems. The yarn-plugin
CycloneDX BOM carries a complete root-anchored `dependencies` graph. The
`poetry.lock` file records each package's own dependency table, and `pyproject`
declares the top-level ones. Everything else — Terraform, the Docker OS package
lists, bun, an npm BOM with no graph — gives us no edges to walk.

The danger in this feature is not a blank cell. It is a *wrong* cell. A
confidently rendered "direct" on a package that is actually transitive, or a
named introducer that does not in fact introduce the package in the flagged
workspace, is worse than saying nothing — the reviewer trusts it and reasons
from a false premise. Provenance derives from a graph, and a graph offers many
ways to fabricate: a chain stitched across two versions of a package that share
a name, an introducer borrowed from a workspace that is not on this row, a
parent that is itself unreachable from any root. Each of these surfaced in
review as a plausible-looking value that no real relationship supported.

## Decision drivers

- **No fabrication, no mislabel.** A rendered provenance value must describe a
  relationship that actually exists in the flagged workspace. This is the one
  property the feature cannot trade away.
- **Honest about what we don't know.** Where no usable graph exists, or where
  the graph cannot answer unambiguously, the cell must say so rather than guess.
- **Minimal dependencies.** The tool audits dependency trees; it does not add a
  PEP-440 version solver or an HCL parser to answer a provenance question.
- **Determinism.** The same inputs must produce a byte-identical column, so the
  `check` gate can tell a real change from noise.

## Considered options

1. **Skip provenance** — keep the attribution table as it was; let the reviewer
   trace the graph by hand.
2. **Answer for every ecosystem** — invent a best-effort introducer for
   Terraform, Docker OS, and graph-less inputs so no cell is ever blank.
3. **Two graph-backed lanes, honest residual elsewhere** — derive provenance
   only where a real dependency graph exists (npm via the BOM, Python via the
   lockfile), render `—` everywhere else, and hold every derived value to a
   reachability invariant.

## Decision

We render provenance from the two lanes that have a real graph, and a `—`
everywhere else. Within a lane, the governing rule is one invariant: a named
introducer must be reachable from a declared root. A direct package carries no
introducer and no chain. A transitive package carries the set of parents that
introduced it — intersected with the set of purls reachable from the roots — and
one representative shortest chain. A package the graph contains but cannot
connect back to a root has no derivable introducer, so its cell is `—`.

The invariant lives in one shared derivation that both lanes call, which is why
it holds for both. The reachable set is computed once per graph by a breadth-
first walk from the roots, and every node's parent set is intersected with it.
A parent that no root can reach is structurally unable to appear as an
introducer. The representative chain is gated on the same reachability, so the
introducer set and the chain never disagree.

Comparing on the drivers that decided it:

- **Skipping provenance** leaves the reviewer's main question unanswered when
  the answer is sitting in the BOM and the lockfile. Rejected — the data is
  there.
- **Answering everywhere** means manufacturing an introducer for ecosystems
  whose artifacts carry no edges. That is fabrication by another name, and it
  would need a version solver and an HCL parser to even attempt. Rejected on
  both the no-fabrication and the minimal-dependency drivers.
- **Two lanes plus an honest residual** answers exactly where the data supports
  an answer, and says `—` — the same residual already used for unknowns
  elsewhere in the report — where it does not. It buys the reviewer the real
  answer without ever risking a false one.

The shape of the residual was settled the hard way. Provenance went through
several adversarial-review rounds, and almost every finding was a value that
looked right but rested on nothing. The fixes converged on the same few rules,
which are worth recording because they are the load-bearing part of this
decision:

- **The cell is scoped to the row's flagged targets.** The "Why" cell and the
  "Used in" cell are folded over the *same* occurrence subset — only the
  workspaces this row actually shows. Folding over every occurrence let a row
  borrow "direct", or a concrete chain, from an unflagged workspace that the row
  never names. Scoping closes that: when the flagged occurrences carry no
  provenance, the cell is `—`, never borrowed.
- **Introducers are intersected with the root-reachable set.** This is the
  central invariant above, enforced in the shared derivation for both lanes. The
  npm lane additionally re-derives its introducers on the real per-resolution
  graph rather than the version-collapsed one, because a chain stitched across
  two resolutions of the same purl exists on no concrete instance.
- **Version ambiguity in Python is a residual, not a guess.** Version is part of
  the purl. When a lockfile name maps to exactly one version, an edge resolves
  precisely; when it maps to several, the name alone cannot say which version
  the edge meant, and resolving it would need a PEP-440 version solver we
  declined to add. So a multi-version name yields no edge and marks no version
  direct — it falls to `—`.
- **Optionality was descoped.** An early version tried to mark Python
  dependencies optional from PEP 508 markers and extras. Parsing those markers
  produced a mislabeling defect in three of four review rounds — an `extra ==`
  variant treated as blanket-optional, the literal value `"extra"` mistaken for
  the marker variable. The robust direct/transitive/introducer derivation never
  re-broke, so optionality was removed end to end rather than patched again. The
  npm lane never had it; the BOM carries no optional or peer information.

## Consequences

- **Good:** the reviewer gets a real answer where a graph supports one and an
  honest `—` where it does not. A fabricated or mislabeled introducer is
  unrepresentable by construction — the bad state cannot be produced, rather than
  being caught case by case. The same shared derivation backs both lanes, so
  they cannot drift apart.
- **Bad / cost:** coverage is uneven. Terraform, Docker OS, bun, and any
  graph-less npm BOM show `—` in the Why column; a Python dependency reached
  only through a multi-version name shows `—` even though a version solver could
  in principle resolve it. We accept the blank over a guess. Optionality is not
  reported at all.
- **Neutral:** provenance is an additive per-occurrence field (see
  [ADR-0005](0005-per-occurrence-model.md)), so occurrences without it serialize
  unchanged. The two lanes' fabrication paths are not exercised by the
  reference monorepo — its real graphs are entirely root-reachable and
  single-version — which is precisely why adversarial review, not dogfooding,
  found the defects these invariants close.

## See also

- Plan summaries:
  `.planning/phases/07-docker-os-packages/07-13-provenance-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-17-why-cell-scoping-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-18-poetry-multiversion-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-19-descope-poetry-optional-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-21-introducedby-reachability-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-22-introducedby-real-reachable-SUMMARY.md`
- Code: `collectors/provenanceGraph.ts` (`deriveIntroductions`,
  `reachableFromRoots`), `collectors/npmProvenance.ts`,
  `collectors/poetryProvenance.ts`, `render/markdown.ts` (`whyCellOf`)
- Related: [ADR-0005](0005-per-occurrence-model.md) (the per-occurrence model
  provenance attaches to)
