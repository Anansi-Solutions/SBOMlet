# ADR-0015: Source-available licences — a terminal deny lane, shipped defaults, and an opt-out

- **Status:** Accepted
- **Date:** 2026-06-14; shipped defaults + opt-out 2026-06-24 (consolidated from the former ADR-0021 and ADR-0022)

## Context and problem

The policy engine already had ways to say "this licence is fine here": a
`[[compatible]]` rule, a workspace suppression for copyleft a project bundles under
its own copyleft licence, a dev-scope downgrade. All move a dependency *toward*
passing. What the engine had no way to say was the opposite: "this licence may never
ship, and nothing else in the policy can argue otherwise."

That gap matters because of what the inventory is for. The output is a
`THIRD_PARTY_LICENSES.md` that travels with software handed to clients and with
infrastructure code. For that artifact the licence that actually puts you at legal
risk is not classic copyleft — suppression and a project's own licence already
handle the GPL/MPL a project distributes correctly. The real exposure is a
*source-available* licence: BUSL, SSPL, Elastic, the Redis RSAL, a Commons-Clause
rider. These are not open source; they carry use restrictions — no production use
until a change date, no resale, no managed-service competition — that make the
component unredistributable in a client-shipped artifact at all. A copyleft licence
tells you how you may redistribute; a source-available one often tells you that you
may not. So we needed a lever above every accept lever, naming these licences
explicitly, that cannot be overridden back to "ok" by accident — and, once it
existed, the right defaults and a safe escape hatch for it.

## Decision drivers

- **A licence the project cannot legally redistribute must fail**, with no accept
  rule, suppression, dev downgrade, or override able to license it back.
- **Correct by default.** The protection that matters most must not depend on a
  consumer copying boilerplate.
- **Auditable.** A failure names which entry fired and why; an accepted exception
  stays visible, never silent.
- **No over-denial.** `MIT OR BUSL-1.1` can elect MIT and is fine.
- **Catch the non-SPDX cases** (Commons-Clause, the Redis licence) without a regex
  that denies the wrong package.
- **Minimal surface, no silent failure.** Reuse the SPDX-satisfies path and the
  policy-validation boundary; one bad id must not disable the whole lane unnoticed.

## Considered options

1. **Route source-available licences through the copyleft/suppression chain** — but
   that chain exists to *suppress*, and would invite a pass for a licence that can
   never pass.
2. **A deny-list with normal precedence**, checked mid-chain — a later
   `[[compatible]]` or suppression could outrank it if precedence numbers drift.
3. **A deny-list as the top-precedence terminal**, checked first, that force-fails
   and stops.
4. For the entries: **keep them policy-authored** (boilerplate a consumer copies)
   vs. **ship the well-known source-available licences as engine defaults** vs. ship
   a broader set (PolyForm, Confluent) as defaults too.
5. For the escape hatch: **no opt-out**, **let `[[compatible]]` override a deny**
   (breaks the terminal invariant), or **a dedicated `[[allow_source_available]]`
   exemption that surfaces as a warn**.

## Decision

**`[[deny]]` is the highest-precedence, terminal lane.** A matching entry force-fails
the dependency and the walk stops, above the stale-override lane and every accept
lever. Precedence has to be *terminal*, not merely present: a source-available
licence cannot be argued back to acceptable by any later rule, so the engine must
not give a later rule the chance. `applyDevScope` is never reached for a denied
verdict, so even a dev-only occurrence of a denied licence fails. Two match modes
carry the cases: `match = "license"` names an SPDX id (decomposed into a satisfies
allow-list, the same path `[[compatible]]` uses), and `match = "name"` compares the
package name exactly, for the riders with no usable SPDX id (Commons-Clause rides as
`MIT AND Commons-Clause`, not SPDX-parseable; the Redis licence has no registered
id). Denial is OR-election-consistent: an OR is denied only when *both* branches are
denied, an AND when *either* is — and the election runs over the *union* of every
licence deny entry at once, so three separate entries for BUSL, SSPL, and Elastic
still deny `BUSL-1.1 OR SSPL-1.0`.

**BUSL-1.1, SSPL-1.0, and Elastic-2.0 ship as engine-default deny rules**
(`builtinDenylist.ts`), not as boilerplate a consumer must copy. A tool whose
out-of-the-box behaviour PASSES the highest-risk licence has its defaults inverted.
The effective deny set is the consumer's policy denies FIRST, then these defaults;
the OR-election union spans both, so they compose. Attribution is policy-first: a
licence a consumer also lists keeps its `denied[i]` citation; a default-only catch
is cited `default:source-available`. Only registered SPDX ids ship, and a test
asserts it against `spdx-license-ids` — a load-bearing guard, not hygiene: the
patterns join the combined satisfies allowlist, and a single non-SPDX id makes
`spdx-satisfies` throw, which the defensive catch turns into "deny nothing" for the
ENTIRE union. We found this the hard way — PolyForm ids, not SPDX-registered,
silently disabled every licence deny until the test caught them; that is why the
broader set (PolyForm, Confluent) cannot ship as license-mode defaults today. The
non-SPDX riders stay name-mode opt-ins in the consumer policy, since a name-mode
default would have to GUESS encumbered package names, which the matcher must never
do.

**A reviewed exception opts out via `[[allow_source_available]]`** — as a warn, not
a pass. A deny is terminal, so without an escape hatch the only options for a
legitimate exception (an internal-only build tool never redistributed, or a
component held under a separate commercial licence) were to drop the dependency or
abandon the deny defaults. So a policy `[[allow_source_available]]` table names one
built-in source-available licence plus a mandatory `reason`; a package whose
terminal-0 deny is a SHIPPED default (cited `default:source-available`) and whose
licence is listed is NOT force-failed — it surfaces as a **warn** citing
`allow_source_available[i]`, non-gating but visible in the summary and roll-up. Two
properties keep it safe: an explicit `[[deny]]` still wins (policy-first attribution
means the matched rule is never the builtin id when the consumer also denied the
licence themselves, so the exemption can only soften the DEFAULT), and validation
rejects any licence that is not a shipped default (exempting a non-default is a
mistake, not a no-op). `[[compatible]]` still cannot override a deny — the terminal
invariant is untouched.

## Consequences

- **Good:** a source-available licence fails the gate the moment the tool is
  adopted, no policy required, and auditably — the verdict cites
  `default:source-available` (or `denied[i]`), names the matched pattern, and states
  the rationale. The risk that actually applies to client-shipped and IaC
  inventories is the one the gate is strictest about.
- **Good:** a legitimate exception is expressible with a mandatory reason as its
  audit trail and passes CI, while the exempted licence is surfaced as a warn —
  never silently `ok`.
- **Good:** no new dependency and no new parser. Deny reuses the SPDX-satisfies path,
  the policy-validation boundary, and the expression AST; the defaults are reviewable
  data run through the existing election; the opt-out reuses the same validation.
- **Bad / cost:** the name-mode riders (`redis`, Commons-Clause) cannot ship as
  defaults — name-mode is exact by design and cannot guess encumbered package names
  — so a consumer must set them to the actual names in its inventory, or the rider
  goes uncaught. `policy.example.toml` keeps them as the worked `[[deny]]` example.
- **Neutral:** the precedence position is load-bearing, locked by tests proving deny
  beats compatible, suppression, the dev downgrade, and a stale override. The
  observed-claim mechanism that closed two review-found bypasses (an override
  rewriting a denied observed licence; an OR across separate deny entries) is the
  subject of [ADR-0007](0007-deny-terminal-observed-claims.md); this record is about
  *what* we deny, that it ships by default, and how a reviewed exception opts out.

## See also

- [ADR-0007](0007-deny-terminal-observed-claims.md) — the terminal precedence and
  observed-claim mechanism.
- Code: `src/policy/denylist.ts` (`effectiveDenyRules`),
  `src/policy/builtinDenylist.ts`, `src/policy/evaluate.ts`
  (`sourceAvailableExemption`), `src/policy/schema.ts`
  (`validateAllowSourceAvailable`), `test/builtinDenylist.test.ts`,
  `policy.example.toml`.
