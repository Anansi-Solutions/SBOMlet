# ADR-0022: Opting out of a source-available deny via [[allow_source_available]]

- **Status:** Accepted
- **Date:** 2026-06-24

## Context and problem

[ADR-0021](0021-source-available-deny-defaults.md) made BUSL-1.1, SSPL-1.0, and
Elastic-2.0 fail the gate by default, and flagged the gap it left: a deny is
terminal, so once a source-available licence is denied no `[[compatible]]` rule
can argue it back. That is the right default, but it has no escape hatch for a
legitimate, reviewed exception — an internal-only build tool that is never
redistributed, or a component the consumer holds a separate commercial licence
for. Without a way out, the only options were to remove the dependency or to stop
using the tool's deny defaults entirely. Both are worse than a documented
exception.

## Decision drivers

- **A reviewed exception must not fail CI** — that is the whole point of an
  opt-out.
- **It must stay visible, never silent.** Accepting a source-available licence is
  a real risk decision; it has to remain auditable in the output, not vanish into
  a clean `ok`.
- **It must not weaken an explicit `[[deny]]`.** A licence the consumer denies
  themselves is absolute; the opt-out is only for the shipped DEFAULT.
- **Minimal surface, auditable.** Reuse the policy-validation and deny machinery;
  require a written reason.

## Considered options

1. **No opt-out** (the ADR-0021 status quo) — too rigid for a tool meant to be
   adopted widely.
2. **Let `[[compatible]]` override a deny** — breaks the load-bearing
   deny-is-terminal invariant ([ADR-0015](0015-source-available-deny-list.md)) and
   the tests that lock it.
3. **A dedicated `[[allow_source_available]]` exemption that surfaces as a warn.**

## Decision

We chose option 3. A policy `[[allow_source_available]]` table names one built-in
source-available licence (`license`) plus a mandatory `reason`. At evaluation, a
package whose terminal-0 deny is a SHIPPED default (cited `default:source-available`,
not the consumer's own `[[deny]]`) and whose licence is listed here is NOT
force-failed — it surfaces as a **warn** citing `allow_source_available[i]` and the
reason. Warn is non-gating, so CI passes, but the accepted source-available licence
stays visible in the summary and roll-up rather than passing silently.

Two properties keep it safe. An explicit `[[deny]]` still wins: `denyRuleFor`
attributes a consumer's own deny first (policy-first order), so the matched rule is
never the builtin id when the consumer also denied the licence themselves — the
exemption can only soften the DEFAULT. And only a shipped default can be named:
validation rejects any other licence (a typo, or a non-builtin id), because
exempting something that was never a default deny is a mistake, not a no-op.

## Consequences

- **Good:** a legitimate exception is expressible, with a mandatory reason as its
  audit trail, and it passes CI.
- **Good:** the exempted licence is surfaced as a warn — never silently `ok` — so a
  reviewer reading the output still sees it.
- **Good:** the deny-is-terminal invariant is untouched; an explicit `[[deny]]`
  is unaffected, and `[[compatible]]` still cannot override a deny.
- **Neutral:** the opt-out is scoped to the shipped defaults by design. If a
  consumer wants to allow a licence they denied themselves, they edit their own
  `[[deny]]`, not this table.

## See also

- [ADR-0021](0021-source-available-deny-defaults.md) — the defaults this opts out
  of; this record closes the "no opt-out" gap it flagged.
- Code: `src/policy/schema.ts` (`validateAllowSourceAvailable`),
  `src/policy/evaluate.ts` (`sourceAvailableExemption`), `policy.example.toml`.
