# ADR-0015: A source-available deny-list as the top-precedence terminal

- **Status:** Accepted
- **Date:** 2026-06-14

## Context and problem

The policy engine already had a way to say "this licence is fine here": a
`[[compatible]]` rule, a workspace suppression for copyleft a project bundles
under its own copyleft licence, and a dev-scope downgrade. All of those move a
dependency *toward* passing. What the engine had no way to say was the opposite:
"this licence may never ship, and nothing else in the policy can argue
otherwise."

That gap matters because of what this tool produces an inventory for. The output
is a `THIRD_PARTY_LICENSES.md` that travels with software handed to clients, and
with infrastructure code. For that kind of artifact the licence that actually
puts you at legal risk is not classic copyleft — the suppression machinery and a
project's own licence already handle GPL or MPL the project distributes
correctly. The real exposure is a *source-available* licence: BUSL, SSPL,
Elastic, the Redis source-available licence, or a Commons-Clause rider. These
are not open source. They carry use restrictions — no production use until a
change date, no resale, no managed-service competition — that make the component
unredistributable in a client-shipped artifact at all. A copyleft licence tells
you how you may redistribute; a source-available licence often tells you that you
may not.

So we needed a lever that sits above every accept lever, names these licences
explicitly, and cannot be overridden back to "ok" by accident.

## Decision drivers

- **A licence the project cannot legally redistribute must fail, with no escape
  hatch.** No compatible rule, suppression, dev downgrade, or override may
  license it back in.
- **The decision must be auditable.** A failure has to name *which* deny entry
  fired and *why*, so a reviewer can act on it.
- **It has to catch the non-SPDX cases.** Commons-Clause and the Redis licence
  have no clean SPDX identifier; an identifier-only mechanism would miss them.
- **No over-denial.** A dependency offered as `MIT OR BUSL-1.1` can elect MIT and
  is fine. The lever must not fail a dependency that has an acceptable branch.
- **Minimal surface.** Reuse the existing SPDX matching and policy-validation
  machinery rather than add a parser or a dependency.

## Considered options

1. **Treat source-available licences like copyleft** — let them flow through the
   normal `default:copyleft` / suppression chain.
2. **A deny-list with normal precedence** — a `[[deny]]` block checked somewhere
   in the middle of the chain, alongside compatible and suppression.
3. **A deny-list as the top-precedence terminal** — a `[[deny]]` block checked
   first, before every other lane, that force-fails and stops.

## Decision

We chose option 3: `[[deny]]` is the highest-precedence lane in the engine. A
matching entry force-fails the dependency and the walk stops there, above the
stale-override lane and above every accept lever.

The reason precedence has to be *terminal*, not merely *present*, is the whole
point. A source-available licence cannot be argued back to acceptable by any
later rule, so the engine must not give a later rule the chance. Option 2 would
have let a `[[compatible]]` entry or a workspace suppression silently outrank a
deny if the rule order or the precedence numbers drifted — exactly the kind of
gate-bypass that is invisible until it ships. Putting deny at position 0 makes
the property structural: `applyDevScope` is never reached for a denied verdict,
so even a dev-only occurrence of a denied licence fails.

Option 1 was wrong about the risk. The copyleft chain is built to *suppress* —
to recognise that a project may legitimately bundle GPL under its own copyleft
licence. Routing source-available licences through it would invite the same
suppression and produce a pass for a licence that can never pass. These licences
need the opposite default.

Two match modes carry the cases. A `match = "license"` entry names an SPDX id
(BUSL-1.1, SSPL-1.0, Elastic-2.0) and is decomposed at validation time into a
satisfies allow-list, the same path `[[compatible]]` uses. A `match = "name"`
entry compares the package name exactly, for the riders with no usable SPDX id —
Commons-Clause rides alongside another licence as `MIT AND Commons-Clause`, which
is not even SPDX-parseable, and the Redis licence has no registered id at all. An
exact name compare catches both without a regex that could deny the wrong
package.

Denial is OR-election-consistent with compatible, and over-denial is the failure
we guarded against hardest. Asking `satisfies("MIT OR BUSL-1.1", ["BUSL-1.1"])`
returns true and would wrongly fail a dependency that can elect MIT. The correct
rule is the dual of the copyleft recursion: an OR is denied only when *both*
branches are denied, an AND when *either* is. And the election runs over the
*union* of every license deny entry at once — three separate entries for BUSL,
SSPL, and Elastic must still deny `BUSL-1.1 OR SSPL-1.0`, which an entry-by-entry
check would miss by judging each branch electable against the other.

## Consequences

- **Good:** a source-available licence fails the gate unconditionally and
  auditably — the verdict cites `denied[i]`, names the matched pattern, and
  states the source-available rationale. The risk that actually applies to
  client-shipped and IaC inventories is the one the gate is strictest about.
- **Good:** no new dependency and no new parser. Deny reuses the SPDX-satisfies
  path, the policy-validation boundary, and the expression AST already in the
  engine.
- **Bad / cost:** the shipped name-mode entries (`redis`,
  `commons-clause-licensed-package`) are placeholders. A consuming repository has
  to set them to the actual encumbered package names in its inventory, or the
  rider goes uncaught — name-mode is exact by design and cannot guess.
- **Neutral:** the precedence position is load-bearing and is locked by tests
  proving deny beats compatible, suppression, the dev downgrade, and a stale
  override. Two adversarial-review findings — deny being bypassable through an
  override that rewrites a denied observed licence, and an OR across separate
  deny entries — were both closed by also consulting every *observed* expression,
  not only the post-override one. That mechanism is the subject of
  [ADR-0007](0007-deny-terminal-observed-claims.md); this record is about
  *what* we deny and *why*.

## See also

- Plan summaries: `.planning/phases/06-terraform-dogfood/06-02-SUMMARY.md`,
  `.planning/phases/06-terraform-dogfood/06-06-review-fixes-SUMMARY.md`
- Related: [ADR-0007](0007-deny-terminal-observed-claims.md) (the terminal
  precedence and observed-claim mechanism)
- Code: `src/policy/denylist.ts`, `src/policy/evaluate.ts`,
  `policy.example.toml`
