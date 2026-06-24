# ADR-0008: Honest residual: surface ambiguity, never guess

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

The tool exists to produce an inventory a compliance reviewer can trust. The
quiet failure that destroys that trust is a value the tool invented: a precise
SPDX id where the source only said "BSD", a base image picked out of an
ambiguous `FROM`, a dependency shown as direct when the graph never proved it.
Each of these looks like a complete answer and reads like one, so nobody knows
to check it.

The pressure to guess is real, because the libraries we lean on guess by
default. PyPI's trove classifier for the Jupyter/IPython stack reports the bare
label "BSD". Hand it to `spdx-correct` and it returns `BSD-2-Clause` — a
confident, specific, and almost certainly wrong answer for a 23-package stack
that is actually BSD-3-Clause. The same library turns "Apache" into
`Apache-2.0`, "GPL" into `GPL-3.0-or-later`, and — worst of all — the bare
strong-copyleft label "EUPL" into the permissive `UPL-1.0`, a guess that would
slip a copyleft obligation straight past the gate. A Dockerfile whose `FROM`
depends on an unresolvable `ARG` could be made to yield *some* image if we
squinted. A CycloneDX graph with no locatable root could be made to yield *some*
provenance edges if we assumed an order.

In every case the easy path produces a plausible value and the honest path
produces a marked gap. We had to decide which one the tool emits.

## Decision drivers

- **A wrong answer is worse than a flagged gap.** The tool is a compliance
  gate. A reviewer who sees "—" or "(imprecise)" knows to look; a reviewer who
  sees a fabricated `BSD-2-Clause` does not. Silent wrongness is the one failure
  mode the tool cannot have.
- **The output is auditable only if every value traces to evidence.** A precise
  id should mean the source actually said something precise. If guesses and
  facts both render as plain ids, the document stops meaning anything.
- **Ambiguity is information, not noise.** "We could not determine this" is a
  real finding a reviewer can act on — pin it, clarify it, or accept it — so it
  belongs in the output, not swallowed.

## Considered options

1. **Guess, using the library default** — let `spdx-correct` (or an analogous
   heuristic) fill every gap with its best precise answer.
2. **Drop to plain unknown** — when a value is not exactly determinable, emit
   nothing distinguishable from a genuine "no data" row.
3. **Surface the residual faithfully** — represent what *is* known at the
   precision it is known, mark it as imprecise or unresolved, and route it to
   review instead of inventing the missing part.

## Decision

We surface the residual. When a value cannot be determined precisely, the tool
records exactly what it could determine and flags the rest for a human, rather
than inventing the part it does not have.

This is one principle with three faces across the codebase, each shaped by what
"the residual" is in that collector.

For licenses, a bare family label becomes a first-class *imprecise* finding. The
normalizer intercepts the ambiguous labels — `BSD`, `Apache`, `GPL`, `AGPL`,
`LGPL`, `EUPL` — *before* `spdx-correct` can fabricate a clause count, and
carries the family forward as `impreciseFamily` with the SPDX expression left
null, because a bare family is not a valid SPDX expression. The policy engine
gives this its own lane: a permissive family warns and passes, a could-be-
copyleft family (`GPL`/`AGPL`/`LGPL`) is flagged for review, and neither is ever
silently failed or silently passed on a guessed id. The document renders it as
`BSD (imprecise)`, keeps it out of the unknown count, and lists it in a
dedicated "review / disambiguate" section. A maintainer who knows the real
answer pins it with a `[[clarify]]` override; until then the honest label
stands.

For Docker, the residual is an unresolvable base image. The Dockerfile collector
answers one question — which external base does this image build on — and
abstains the moment the answer is ambiguous: an unresolvable `ARG`, a cyclic
stage alias, a `FROM` mangled by a line continuation it cannot safely tokenize.
It returns `{kind: "unresolved", reason}` and the caller warns and skips, rather
than ship a base it is not sure of. The reviewer pins the base with `--image`.

For provenance, the residual is a "why is this here?" the graph cannot prove.
When a CycloneDX document has no locatable root, or no dependency edge anchors
that root, the provenance lane emits no edges and the column renders "—". It
never fabricates a `direct`/`transitive` label from component order.

Comparing on the driver that decided it:

- **Guessing** fails the first driver outright. The `BSD → BSD-2-Clause` and
  `EUPL → UPL-1.0` cases are not hypothetical; they are values `spdx-correct`
  produced against the real corpus, one of them flipping copyleft to permissive.
  A guess that the gate then trusts is exactly the silent-wrong failure the tool
  exists to prevent.
- **Plain unknown** is honest but throws away what we knew. Collapsing
  imprecise-BSD into the same bucket as a genuinely license-less package hides
  the obligation a reviewer most needs to see, and a could-be-copyleft family
  would lose its review flag. Rejected for discarding real signal.
- **The faithful residual** keeps what is known at its true precision, makes the
  gap visible and actionable, and gives the gate a defined verdict for it.
  Chosen.

## Consequences

- **Good:** every precise id in the output now means the source was precise; the
  reviewer can trust a plain id and knows a marked one needs a look. The
  imprecise lane caught the `EUPL → UPL-1.0` copyleft-to-permissive guess that
  would otherwise have passed the gate. Each residual is a defined state with its
  own verdict, render, and escape hatch, so nothing falls through unhandled.
- **Bad / cost:** the output carries gaps a guessing tool would have papered
  over, and someone has to resolve them. For the dogfood corpus that means a
  handful of `[[clarify]]` overrides and the occasional `--image` pin. We accept
  that work as the price of an auditable inventory. The honest accounting also
  lowered the headline precise-resolution rate — the live measure is 99.25%, not
  the ~99.9% we would have reported by counting guesses as resolutions — which is
  the more truthful number.
- **Neutral:** the imprecise families are a small, enumerated, test-asserted set,
  not a runtime heuristic; adding a label is a deliberate edit, and a label that
  carries a version (`Apache License, Version 2.0`) is deliberately absent
  because its corrected result is precise and correct, not a guess. The same
  decision recurs in the Terraform gate (ADR-0013), which abstains on a missing
  init signal rather than guessing whether modules exist.

## See also

- Plan summaries:
  `.planning/phases/05-enrichment-committed-cache/05-04-SUMMARY.md`,
  `.planning/phases/05-enrichment-committed-cache/05-05-SUMMARY.md`,
  `.planning/phases/05-enrichment-committed-cache/05-07-gap-closure-SUMMARY.md`
- Code: `normalize/normalize.ts` (`AMBIGUOUS_FAMILY`), `policy/copyleftFamily.ts`,
  `collectors/dockerfile.ts` (`deriveBaseImage`), `collectors/npmProvenance.ts`
- Related: [ADR-0013](0013-terraform-filesystem-signal-gate.md)
