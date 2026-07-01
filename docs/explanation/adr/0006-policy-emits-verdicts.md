# ADR-0006: Policy emits structured verdicts; renderer and gate are pure consumers

- **Status:** Accepted
- **Date:** 2026-06-11

## Context and problem

Two parts of the tool need to know whether a dependency is acceptable. The renderer
builds the copyleft-and-notices section of `THIRD_PARTY_LICENSES.md`, so it has to
know which packages are problematic. The `check` gate sets the CI exit code, so it
has to know which packages fail. Same question, asked twice, and the answer is not
a substring match: it weighs the parsed SPDX expression, OR-election, per-workspace
copyleft suppression, denylist riders, exceptions, and the warn-versus-fail
treatment of unknowns.

If the renderer decides as it formats and the gate re-implements the same logic,
the two copies drift and the document and the exit code start to disagree — a
package the gate fails on need not appear in the rendered notices, or the reverse.

## Decision drivers

- **One source of truth for a verdict.** The document the reviewer reads and the
  exit code CI acts on must reflect the same decision.
- **Testability.** Policy is the most rule-dense part of the tool — suppression
  precedence, OR-election, denylist-over-override. Those decisions should be
  testable on a table of inputs, without rendering a document or comparing files.
- **The gate renders nothing to disk.** `check` regenerates in memory and compares;
  it never writes the notices file. Logic inside the renderer's formatting is logic
  the gate cannot reach.

## Considered options

1. **Renderer decides while formatting** — the copyleft section evaluates the rules
   as it builds rows; the gate re-implements the same evaluation.
2. **Shared helper both call at format/exit time** — extract the decision into a
   function, but still invoke it separately inside the renderer and the gate.
3. **A policy engine emits a verdict per package, ahead of both** — `evaluate`
   produces a `Verdict[]`, and the renderer and the gate each only read it.

## Decision

The policy engine evaluates once and emits a structured verdict for every
package-and-occurrence pair; the renderer and the gate both consume that list, and
neither re-derives anything. `evaluate(model, policy)` is a pure fold — no
filesystem, no subprocess, no logging, no knowledge of CycloneDX — and the same
model and policy produce the same sorted `Verdict[]`. Each verdict carries a status
(`ok`, `warn`, `fail`, or `suppressed`), a machine-readable rule id, and a human
reason naming the deciding input.

One `buildOutputs` call evaluates the policy once and hands the same list to both
sides. The renderer reads it to decide copyleft-section membership through its
`PolicyView` projection; it does not evaluate policy itself. The gate reads it to
count `fail` verdicts, which drives the exit code. Because both read one list from
one evaluation, they cannot disagree about a package.

Option 1 leaves the decision unreachable except by rendering, and gives the gate a
second copy to drift — the anti-pattern the architecture research names. Option 2
removes the duplicated code but not the duplicated invocation: two call sites can
pass different inputs or diverge as signatures grow, so agreement is by discipline,
not construction. A verdict list emitted ahead of both makes the decision a value
that exists before either consumer runs, and the purity makes the engine
table-testable.

## Consequences

- **Good:** the rendered document and the CI exit code come from one evaluation, so
  they cannot disagree. The engine is a pure function, tested on a table of
  model-plus-policy inputs. Every verdict names the rule and input that decided it,
  so a reviewer can trace a flagged package to a policy line.
- **Bad / cost:** the verdict is a defined contract — a status set, a rule-id
  format, a reason string — that the engine, renderer, and gate all bind to. A new
  policy behaviour extends that contract in one place and teaches both consumers the
  new shape.
- **Neutral:** the consumers stay thin. The renderer maps verdicts to
  copyleft-section membership; the gate filters for `fail` and counts. Keep that
  thinness when either side grows.

## See also

- Research: `.planning/research/ARCHITECTURE.md` (Anti-Pattern 6: policy logic in
  the renderer)
- Related: [ADR-0004](0004-deterministic-output.md) (the deterministic output the
  gate byte-compares), [ADR-0013](0013-source-available-deny.md) (the precedence
  chain the engine walks)
- Code: `policy/evaluate.ts`, `render/markdown.ts` (`PolicyView`), `gate/check.ts`
