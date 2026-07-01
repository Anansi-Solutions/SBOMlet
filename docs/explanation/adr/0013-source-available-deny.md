# ADR-0013: Source-available licences are a terminal deny lane

- **Status:** Accepted
- **Date:** 2026-06-14; observed-claim mechanics, shipped defaults, and opt-out added
  2026-06-19–24 (consolidates the earlier deny-mechanics, shipped-defaults, and opt-out records)

## Context and problem

The output is a `THIRD_PARTY_LICENSES.md` that travels with software handed to
clients and with infrastructure code. For that artifact, the licence that puts you
at legal risk is not classic copyleft — a project's own licence and workspace
suppression already handle the GPL/MPL it distributes. The risk is a
*source-available* licence: BUSL, SSPL, Elastic, the Redis RSAL, a Commons-Clause
rider. These are not open source; they carry use restrictions (no production use
until a change date, no resale, no managed-service competition) that make the
component unredistributable in a client-shipped artifact.

The policy engine could move a dependency *toward* passing — a `[[compatible]]`
rule, workspace suppression, a dev-scope downgrade — but had no way to say the
opposite: this licence may never ship, and nothing else in the policy can argue
otherwise. Adding that lever raised three questions: where it sits in precedence,
what input it is checked against, and what ships by default.

## Decision drivers

- **A denied licence fails unconditionally.** No accept rule, suppression, dev
  downgrade, or override may license it back.
- **Correct by default.** The protection must not depend on a consumer copying
  boilerplate.
- **No over-denial.** `MIT OR BUSL-1.1` can elect MIT and is fine.
- **Catch the non-SPDX riders** (Commons-Clause, Redis) without a regex that denies
  the wrong package.
- **Auditable.** A failure names the entry that fired; an accepted exception stays
  visible.
- **Minimal surface.** Reuse the SPDX-satisfies path and the policy-validation
  boundary; one bad id must not silently disable the lane.

## Considered options

- **Precedence:** a mid-chain lane checked alongside compatible and suppression, vs.
  the terminal at precedence 0 that force-fails and stops.
- **Input deny reads:** only the combined finding expression the normalizer
  rendered, vs. every observed claim carried onto the finding.
- **Defaults:** policy-authored boilerplate, vs. ship the well-known ids as engine
  defaults, vs. ship a broader set (PolyForm, Confluent) too.
- **Escape hatch:** none, vs. let `[[compatible]]` override a deny (breaks the
  terminal invariant), vs. a dedicated `[[allow_source_available]]` exemption that
  surfaces as a warn.

## Decision

**`[[deny]]` is the highest-precedence, terminal lane.** A matching entry
force-fails the dependency and the walk stops, above the stale-override lane and
every accept lever. Terminal, not merely present: a source-available licence cannot
be argued back to acceptable, so the engine does not give a later rule the chance.
The scope downgraders (ADR-0009) run after deny returns, so a dev-only or OS
occurrence of a denied licence still fails. Two match modes carry the cases:
`match = "license"` names an SPDX id, decomposed into a satisfies allow-list (the
`[[compatible]]` path); `match = "name"` compares the package name exactly, for the
riders with no usable SPDX id (Commons-Clause rides as `MIT AND Commons-Clause`; the
Redis licence has no registered id).

**Deny is evaluated over every observed claim, not the single combined expression.**
The normalizer builds one combined expression per package, and that combination is
lossy on purpose: when claims disagree it elects an imprecise family or collapses to
unknown. A denied member can disappear into that collapse — `[BUSL-1.1, GPL]` elects
"GPL" and renders nothing precise; an override that rewrites `BUSL-1.1 → MIT` hands
deny the clean expression. So deny consults three inputs in order: the combined
expression (which also carries the name-mode check), the pre-override observed
expression, and every per-claim precise expression the package was seen with. If any
one is denied, deny fires. Teaching the combiner to keep denied members visible was
the rejected alternative — it bends a general normalization step around one policy
lane and trades one lossy behaviour for a subtler one. Carrying the observed claims
gives deny its own complete view and leaves the combiner unchanged. Two details keep
it honest: the per-claim checks pass a null package name, so a per-claim expression
cannot re-trigger a name rule; and election runs over the *union* of every deny
entry's allow-list at once, so `BUSL-1.1 OR SSPL-1.0` is denied even though BUSL and
SSPL are separate entries.

**BUSL-1.1, SSPL-1.0, and Elastic-2.0 ship as engine defaults**
(`builtinDenylist.ts`), not boilerplate a consumer copies. A tool whose
out-of-the-box behaviour passes the highest-risk licence has its defaults inverted.
The effective deny set is the consumer's denies first, then the defaults; the union
election spans both. Attribution is policy-first: a licence a consumer also lists
keeps its `denied[i]` citation; a default-only catch is cited
`default:source-available`. Only registered SPDX ids ship, asserted by a test against
`spdx-license-ids`. That test is load-bearing: the patterns join one combined
satisfies allow-list, and a single non-SPDX id makes `spdx-satisfies` throw, which
the defensive catch turns into "deny nothing" for the whole union. PolyForm ids (not
SPDX-registered) silently disabled every licence deny until the test caught them —
which is why the broader set cannot ship as license-mode defaults, and the non-SPDX
riders stay name-mode opt-ins rather than defaults that would have to guess
encumbered package names.

**A reviewed exception opts out via `[[allow_source_available]]`, as a warn.**
Without an escape hatch, a legitimate exception (an internal-only build tool, or a
component held under a separate commercial licence) forces dropping the dependency or
abandoning the deny defaults. The table names one built-in source-available licence
plus a mandatory `reason`; a package whose terminal-0 deny is a *shipped default* and
whose licence is listed is not force-failed — it surfaces as a warn citing
`allow_source_available[i]`, non-gating but visible. Two properties keep it safe: an
explicit `[[deny]]` still wins (policy-first attribution means the exemption can only
soften the default, never a licence the consumer denied themselves), and validation
rejects exempting any licence that is not a shipped default. `[[compatible]]` still
cannot override a deny.

## Consequences

- **Good:** a source-available licence fails the moment the tool is adopted, no
  policy required, and auditably — the verdict cites `default:source-available` or
  `denied[i]` and names the matched pattern. A denied licence fails however it
  reached the finding (combined, elected into a family, collapsed to unknown, or
  rewritten by an override) and in every scope.
- **Good:** the combiner stays a general normalization step with no knowledge of
  deny; deny owns its completeness through the observed-claim set. No new dependency
  or parser — deny reuses the satisfies path, the validation boundary, and the
  expression AST.
- **Good:** a legitimate exception is expressible with a mandatory reason and passes
  CI, while the exempted licence is surfaced as a warn, never silently `ok`.
- **Bad / cost:** the name-mode riders (`redis`, Commons-Clause) cannot ship as
  defaults — name-mode is exact and would have to guess package names — so a consumer
  sets them to the actual names in its inventory or the rider goes uncaught.
  `policy.example.toml` keeps them as the worked `[[deny]]` example. The finding also
  carries an extra `observedExpressions` field, redundant when nothing was lossy.
- **Neutral:** the precedence position and observed-claim behaviour are locked by
  tests — deny beating compatible, suppression, the dev and OS downgrades, and a
  stale override, with `[BUSL-1.1, GPL]` / `[Elastic-2.0, GPL]` / `[BUSL-1.1,
  custom]` failing in both app and OS scope while non-denied sets are untouched.

## See also

- Plan summaries:
  `.planning/phases/06-terraform-dogfood/06-02-SUMMARY.md`,
  `.planning/phases/06-terraform-dogfood/06-06-review-fixes-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-07-review-fixes-SUMMARY.md`
- Related: [ADR-0006](0006-policy-emits-verdicts.md) (the verdict the deny lane
  emits), [ADR-0009](0009-dev-prod-os-scopes.md) (the scope downgraders deny sits
  above), [ADR-0007](0007-honest-residual.md) (the imprecise/unknown collapse deny
  sees through)
- Code: `src/policy/denylist.ts` (`effectiveDenyRules`, `firstDeny`),
  `src/policy/builtinDenylist.ts`, `src/policy/evaluate.ts`
  (`sourceAvailableExemption`), `src/policy/schema.ts`
  (`validateAllowSourceAvailable`), `test/builtinDenylist.test.ts`,
  `policy.example.toml`
