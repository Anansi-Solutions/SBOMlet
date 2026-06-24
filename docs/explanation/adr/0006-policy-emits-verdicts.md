# ADR-0006: Policy emits structured verdicts; renderer and gate are pure consumers

- **Status:** Accepted
- **Date:** 2026-06-11

## Context and problem

Two parts of the tool need to know whether a dependency is acceptable. The
renderer builds the copyleft-and-notices section of `THIRD_PARTY_LICENSES.md`,
so it has to know which packages are problematic. The `check` gate sets the CI
exit code, so it has to know which packages fail. These are the same question
asked twice, and the answer is anything but a substring match: it weighs the
parsed SPDX expression, OR-election, per-workspace copyleft suppression,
denylist riders, exceptions, and the warn-versus-fail treatment of unknowns.

The tempting shortcut is to let the renderer decide as it formats — walk the
packages, apply the rules inline, and emit the problematic ones into the
copyleft table. The gate would then need the same logic a second time. The risk
is not hypothetical: the moment the two copies of "what counts as problematic"
sit in different files, they drift, and the document and the exit code start to
disagree. A package the gate fails on might never appear in the rendered notices,
or the reverse.

## Decision drivers

- **One source of truth for a verdict.** The document the reviewer reads and the
  exit code CI acts on must reflect the same decision. Two evaluators are two
  chances to disagree.
- **Testability of the decision.** Policy is the most rule-dense part of the
  tool — suppression precedence, OR-election, denylist-over-override. We need to
  test those decisions directly, on a table of inputs, without rendering a
  document or shelling out to compare files.
- **The gate renders nothing to disk.** `check` regenerates in memory and
  compares; it never writes the notices file. Logic that lives inside the
  renderer's formatting is logic the gate cannot reach without rendering.

## Considered options

1. **Renderer decides while formatting** — the copyleft section evaluates the
   rules as it builds rows; the gate re-implements the same evaluation to set the
   exit code.
2. **Shared helper both call at format/exit time** — extract the decision into a
   function, but still invoke it separately inside the renderer and inside the
   gate.
3. **A policy engine emits a verdict per package, ahead of both** — `evaluate`
   produces a `Verdict[]`, and the renderer and the gate each only read it.

## Decision

The policy engine evaluates once and emits a structured verdict for every
package-and-occurrence pair; the renderer and the gate both consume that list and
neither re-derives anything. `evaluate(model, policy)` is a pure fold — no
filesystem, no subprocess, no logging, no knowledge that CycloneDX exists — and
the same model and policy always produce the identical, sorted `Verdict[]`. Each
verdict carries a status (`ok`, `warn`, `fail`, or `suppressed`), a
machine-readable rule id naming the rule that decided it, and a human reason
naming the deciding input.

Downstream, one `buildOutputs` call evaluates the policy once and hands the same
verdict list to both sides. The renderer reads it to decide copyleft-section
membership and takes the verdicts pre-computed in its `PolicyView` projection —
its own documentation states it does not evaluate policy. The gate reads it to
count `fail` verdicts, and that count drives the exit code. Because both sides
read one list produced by one evaluation, they cannot disagree about a package.

Comparing on the driver that decided it:

- **Renderer decides while formatting** leaves the decision unreachable except by
  rendering, and forces the gate to keep a second copy that can drift from the
  first. Rejected on the one-source-of-truth and gate-renders-nothing drivers —
  this is the anti-pattern the architecture research calls out by name: policy
  logic in the renderer makes verdicts untestable without rendering, and the gate
  needs the same decisions.
- **A shared helper called at format/exit time** removes the duplicated *code*
  but not the duplicated *invocation*: two call sites can still pass different
  inputs, evaluate at different moments, or diverge as the signatures grow.
  Better, but the agreement is by discipline, not by construction.
- **A verdict list emitted ahead of both** makes the decision a value that exists
  before either consumer runs. The agreement is structural — there is one list —
  and the purity makes the engine trivially table-testable, which is where the
  suppression and precedence rules actually get exercised.

## Consequences

- **Good:** the rendered document and the CI exit code derive from one
  evaluation, so they cannot disagree about whether a package is problematic. The
  engine is a pure function, so its rules are tested on a table of model-plus-policy
  inputs with no rendering and no subprocess. Every verdict names the rule and the
  input that decided it, so a reviewer can trace a flagged package back to a policy
  line.
- **Bad / cost:** the verdict is a defined contract — a status set, a rule-id
  format, a reason string — that the engine, the renderer, and the gate all bind
  to. A new policy behaviour means extending that contract in one place and
  teaching both consumers to read the new shape, rather than editing whatever code
  happened to be nearby.
- **Neutral:** the consumers stay genuinely thin. The renderer maps verdicts to
  copyleft-section membership; the gate filters for `fail` and counts. Neither
  re-parses an expression or re-applies a rule, and that thinness is the property
  to preserve when either side grows.

## See also

- Plan summaries:
  `.planning/phases/03-normalization-policy-engine/03-03-SUMMARY.md`,
  `.planning/phases/04-ci-gate-full-attribution/04-02-SUMMARY.md`,
  `.planning/phases/04-ci-gate-full-attribution/04-05-SUMMARY.md`
- Research: `.planning/research/ARCHITECTURE.md` (Anti-Pattern 6: policy logic in
  the renderer)
- Code: `policy/evaluate.ts`, `render/markdown.ts` (`PolicyView`), `gate/check.ts`
