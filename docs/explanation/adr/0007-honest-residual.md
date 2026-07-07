# ADR-0007: Honest residual — surface ambiguity, never guess

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

The tool produces an inventory a compliance reviewer relies on. The failure mode it
must avoid is a silent guess: a precise licence, version, or base image inferred
from incomplete data. A wrong value is worse than a gap, because nobody knows to
check it — even though the underlying tools guess by default.

That default is concrete. PyPI's trove classifier for the Jupyter/IPython stack
reports the bare label "BSD"; `spdx-correct` turns it into `BSD-2-Clause`, wrong for
a 23-package stack that is actually BSD-3-Clause. The same library maps "Apache" to
`Apache-2.0`, "GPL" to `GPL-3.0-or-later`, and the strong-copyleft "EUPL" to the
permissive `UPL-1.0` — a guess that would pass a copyleft dependency through the
gate.

## Decision drivers

- **A wrong answer is worse than a flagged gap.** A reviewer who sees "—" or
  "(imprecise)" knows to look; a fabricated `BSD-2-Clause` reads as settled.
- **Auditable output.** A precise id should mean the source was precise.
- **Ambiguity is information.** "We could not determine this" is a finding a
  reviewer can act on, so it belongs in the output.

## Considered options

1. **Guess, using the library default** — let `spdx-correct` (or a similar
   heuristic) fill every gap with its best precise answer.
2. **Drop to plain unknown** — emit nothing distinguishable from a genuine "no
   data" row.
3. **Surface the residual** — record what is known at the precision it is known,
   mark the rest imprecise or unresolved, and route it to review.

## Decision

We surface the residual: record what can be determined, flag the rest for a
human. The principle has three faces. For **licences**, a bare family label
(`BSD`, `Apache`, `GPL`, `AGPL`, `LGPL`, `EUPL`) is a first-class *imprecise*
finding: the normalizer intercepts it before `spdx-correct` can add a clause
count, carries the family forward as `impreciseFamily` with the SPDX expression
null, and the policy engine warns-and-passes a permissive family while flagging a
could-be-copyleft one for review. A maintainer pins the real answer with a
`[[clarify]]` override. For **Docker**, the residual is an unresolvable base
image — the collector returns `{kind: "unresolved", reason}` and the caller warns
and skips (mechanics in [ADR-0015](0015-abstain-over-fragile-parsing.md)). For
**provenance**, the residual is a "why is this here?" the graph cannot prove; the
lane emits no edges and the column renders "—" rather than a guessed
`direct`/`transitive` label (see [ADR-0014](0014-dependency-provenance.md)).

Guessing fails the first driver: the `BSD → BSD-2-Clause` and `EUPL → UPL-1.0`
values are what `spdx-correct` produced against the real corpus, one flipping
copyleft to permissive. Plain unknown is honest but discards what we knew,
collapsing imprecise-BSD into the same bucket as a licence-less package and losing
the copyleft review flag. Surfacing the residual keeps what is known at its true
precision and gives the gate a defined verdict for it.

## Consequences

- **Good:** a precise id in the output means the source was precise. The imprecise
  lane caught the `EUPL → UPL-1.0` guess. Each residual is a defined state with its
  own verdict, render, and escape hatch.
- **Bad / cost:** the output carries gaps a guessing tool would have hidden, and
  someone resolves them — for the dogfood corpus, a handful of `[[clarify]]`
  overrides and the occasional `--image` pin. The measured precise-resolution rate
  is 99.25%, below the ~99.9% that counting guesses as resolutions would report.
- **Neutral:** the imprecise families are a small, enumerated, test-asserted set,
  not a runtime heuristic. A label carrying a version (`Apache License, Version
  2.0`) is absent, because its corrected result is precise and correct.

## See also

- Related: [ADR-0015](0015-abstain-over-fragile-parsing.md) (the same principle
  applied to parsers), [ADR-0014](0014-dependency-provenance.md) (the provenance
  residual)
- Code: `normalize/normalize.ts` (`AMBIGUOUS_FAMILY`), `policy/copyleftFamily.ts`,
  `collectors/dockerfile.ts` (`deriveBaseImage`), `collectors/npmProvenance.ts`
