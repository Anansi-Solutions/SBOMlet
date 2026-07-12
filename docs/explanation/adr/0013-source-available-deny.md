# ADR-0013: Source-available licences are a terminal deny lane

- **Status:** Accepted
- **Date:** 2026-06-14; observed-claim mechanics, shipped defaults, and opt-out
  added 2026-06-19–24 (consolidates the earlier deny-mechanics, shipped-defaults,
  and opt-out records)

> **In short —** a source-available licence (BUSL, SSPL, Elastic) can never ship
> in a client-handed artifact, so `[[deny]]` is a terminal, top-precedence lane
> that no accept rule, suppression, scope downgrade, or override can reverse.

## Context and problem

The output is a `THIRD_PARTY_LICENSES.md` that travels with software handed to
clients and with infrastructure code. For that artifact, the licence that puts
you at legal risk is not classic copyleft — a project's own licence and
workspace suppression already handle the GPL/MPL it distributes. The risk is a
*source-available* licence: BUSL, SSPL, Elastic, the Redis RSAL, a
Commons-Clause rider. These are not open source; they carry use restrictions
(no production use until a change date, no resale, no managed-service
competition) that make the component unredistributable in a client-shipped
artifact.

The policy engine could move a dependency *toward* passing — an accept rule,
suppression, a dev-scope downgrade — but had no way to say the opposite: this
licence may never ship, and nothing else in the policy can argue otherwise.

## Decision drivers

- **A denied licence fails unconditionally.** No accept rule, suppression, dev
  downgrade, or override may license it back.
- **Correct by default.** Protection must not depend on a consumer copying
  boilerplate.
- **No over-denial.** `MIT OR BUSL-1.1` can elect MIT and is fine.
- **Catch the non-SPDX riders** (Commons-Clause, Redis) without a regex that
  denies the wrong package.
- **Auditable.** A failure names the entry that fired; an accepted exception
  stays visible.
- **Minimal surface.** Reuse the SPDX-satisfies path and the policy-validation
  boundary; one bad id must not silently disable the lane.

## Considered options

- **Precedence:** a mid-chain lane checked alongside compatible and
  suppression, vs. a terminal at precedence 0 that force-fails and stops.
- **Input deny reads:** only the combined finding expression, vs. every
  observed claim carried onto the finding.
- **Defaults:** policy-authored boilerplate, vs. ship well-known ids as engine
  defaults, vs. ship a broader set (PolyForm, Confluent) too.
- **Escape hatch:** none, vs. let `[[compatible]]` override a deny (breaks the
  terminal invariant), vs. a dedicated exemption that surfaces as a warn.

## Decision

**`[[deny]]` is the highest-precedence, terminal lane**, above every accept
lever; a match force-fails the dependency and stops the walk. The scope
downgraders (ADR-0009) run after, so a dev-only or OS occurrence of a denied
licence still fails. Two match modes: `match = "license"` names an SPDX id
decomposed into a satisfies allow-list; `match = "name"` compares the package
name exactly, for riders with no usable SPDX id (Commons-Clause rides as
`MIT AND Commons-Clause`; Redis has none).

**Deny reads every observed claim, not the single combined expression.** The
normalizer's combined expression is lossy on purpose — disagreeing claims
elect an imprecise family or collapse to unknown, and a denied member can
disappear into that (`[BUSL-1.1, GPL]` elects "GPL"). So deny checks three
inputs in order — the combined expression, the pre-override observed
expression, every per-claim precise expression — and fires if any is denied.
Teaching the combiner to keep denied members visible was rejected as bending
a general step around one policy lane. Per-claim checks pass a null package
name so they cannot re-trigger a name rule; election runs over the union of
every deny entry's allow-list, so `BUSL-1.1 OR SSPL-1.0` is denied though BUSL
and SSPL are separate entries.

**BUSL-1.1, SSPL-1.0, and Elastic-2.0 ship as engine defaults**
(`builtinDenylist.ts`) — a tool that passes the highest-risk licence
out-of-the-box has its defaults inverted. The effective set is the consumer's
denies first, then the defaults; attribution is policy-first (a consumer's own
listing keeps its `denied[i]` citation, a default-only catch reads
`default:source-available`). Only registered SPDX ids ship, asserted by a test
against `spdx-license-ids` — load-bearing, since one non-SPDX id makes
`spdx-satisfies` throw and the defensive catch turns that into "deny nothing"
for the whole union. PolyForm ids (unregistered) silently disabled every
licence deny until the test caught them, which is why the non-SPDX riders stay
name-mode opt-ins rather than defaults.

**A reviewed exception opts out via `[[allow_source_available]]`, as a warn.**
The table names one built-in licence plus a mandatory `reason`; a package
whose terminal-0 deny is a shipped default and whose licence is listed
surfaces as a non-gating warn (`allow_source_available[i]`) instead of
force-failing. An explicit `[[deny]]` still wins; validation rejects exempting
a licence that is not a shipped default.

## Consequences

- **Good:** a source-available licence fails the moment the tool is adopted,
  no policy required, and auditably — however it reached the finding and in
  every scope.
- **Good:** the combiner stays a general normalization step with no knowledge
  of deny; no new dependency or parser.
- **Good:** a legitimate exception is expressible with a mandatory reason and
  passes CI, surfaced as a warn, never silently `ok`.
- **Bad / cost:** the name-mode riders (`redis`, Commons-Clause) cannot ship
  as defaults, so a consumer sets them to the actual names in its inventory or
  the rider goes uncaught. The finding also carries an extra
  `observedExpressions` field, redundant when nothing was lossy.
- **Neutral:** the precedence position and observed-claim behaviour are locked
  by tests — deny beating compatible, suppression, the dev and OS downgrades,
  and a stale override, with non-denied sets untouched.

## See also

- Related: [ADR-0006](0006-policy-emits-verdicts.md) (the verdict the deny
  lane emits), [ADR-0009](0009-dev-prod-os-scopes.md) (the scope downgraders
  deny sits above), [ADR-0007](0007-honest-residual.md) (the
  imprecise/unknown collapse deny sees through)
- Code: `src/policy/denylist.ts` (`effectiveDenyRules`, `firstDeny`),
  `src/policy/builtinDenylist.ts`, `src/policy/evaluate.ts`
  (`sourceAvailableExemption`), `src/policy/schema.ts`
  (`validateAllowSourceAvailable`), `test/builtinDenylist.test.ts`,
  `policy.example.toml`
