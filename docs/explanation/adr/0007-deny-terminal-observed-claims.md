# ADR-0007: Deny is terminal at precedence 0, evaluated over every observed claim

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

A separate decision, [ADR-0015](0015-source-available-deny-list.md), settled
*what* the engine denies and *why*: a source-available licence (BUSL, SSPL,
Elastic, Commons-Clause) can never ship in a client-handed artifact, so the
policy needs a lever that says "this may never pass" and means it. This record
is about the two mechanics that make that lever actually hold: *where* in the
precedence chain deny sits, and *what input* it is checked against.

Both turned out to be load-bearing in ways that were not obvious up front, and
both were where adversarial review found real bypasses.

The precedence question is the simpler one. The engine walks a chain of lanes
per dependency — compatible rules, workspace suppression, the dev-scope
downgrade, override citations — and every one of those lanes exists to move a
dependency *toward* passing. If deny is just another lane somewhere in that
chain, a later lane can outrank it, or a drift in rule order can let it. A licence
that legally cannot ship would then pass because a `[[compatible]]` entry or a
suppression happened to match first.

The input question is subtler, and it is the one review kept reopening. The
finding the engine evaluates is not the raw licence data — it is a *combined*
expression the normalizer builds from every claim observed for a package. That
combination is lossy on purpose: when claims disagree or some are imprecise, it
elects an imprecise family token or collapses to unknown rather than inventing a
precise answer. A denied member can disappear into that collapse. `[BUSL-1.1,
GPL]` elects the imprecise "GPL" family and renders nothing precise; `[BUSL-1.1,
some-custom-token]` collapses to unknown. In both cases the combined expression
no longer mentions BUSL-1.1, so a deny check that reads only the combined
expression sees nothing to deny. An override makes the same hole a different way:
a `[[clarify]]` that rewrites a denied observed licence to a clean one (BUSL-1.1
→ MIT) hands deny the rewritten expression, and the denied original is gone.

## Decision drivers

- **A denied licence must fail unconditionally** — no later lane, no lossy
  combination, and no override may license it back in. This is the one property
  the deny lever exists to guarantee.
- **The bypass must close by construction, not by patching renders.** Changing
  what the normalizer combines to "keep BUSL visible" would trade one lossy
  behaviour for another and invite the next edge case.
- **Determinism and the pure-fold contract.** The engine is a pure function of
  model and policy; whatever deny reads has to already be on the finding, not
  re-derived with side effects mid-evaluation.

## Considered options

For precedence:

1. **Deny as a mid-chain lane** — checked alongside compatible and suppression.
2. **Deny as the terminal at precedence 0** — checked first, force-fails, stops
   the walk.

For the input deny is checked against:

3. **Only the combined finding expression** — whatever the normalizer rendered.
4. **Make the combiner keep denied members visible** — change election so a
   denied member never collapses.
5. **Check every observed claim, decoupled from the render** — carry each
   observed precise expression onto the finding and deny if any one is denied,
   whatever the combination shows.

## Decision

Deny is the terminal lane at precedence 0, and it is evaluated against the set of
*every observed claim*, not the single combined expression.

Precedence 0 means deny is the first thing `verdictFor` checks, above the
stale-override lane and above every accept lever. A match force-fails and the
walk stops. The point of making it terminal rather than merely present is that a
source-available licence cannot be argued back to acceptable by any later rule,
so the engine must not give a later rule the chance. Because the denied verdict
returns before the scope downgraders run, even a dev-only or OS-scope occurrence
of a denied licence fails — there is no occurrence shape that reaches a downgrade
from a denied package. Rejected option 1 (mid-chain) because it leaves the gate
one rule-order edit away from a silent bypass; the property has to be structural.

For the input, deny consults three things in order: the combined expression
(which also carries the name-mode check against the package name), the
pre-override observed expression that an override may have rewritten, and then
every per-claim precise expression the package was ever seen with. If any one of
them is denied, deny fires. The denied member that the combiner elected away or
collapsed into unknown is still sitting in that per-claim set, and the denied
original that an override rewrote is still sitting in the pre-override
expression. What the combiner *renders* and what deny *sees* are deliberately
decoupled.

The reason this is option 5 and not option 4 is the second driver. We could have
taught the combiner to never drop a denied member, but that bends a
general-purpose normalization step around one policy lane and replaces a known
lossy behaviour with a subtler one — the next reviewer would find the next shape
that slips through. Carrying the observed claims onto the finding leaves the
combiner's imprecise/unknown render exactly as it was and gives deny its own,
complete view. The bypass class closes because deny no longer depends on the
lossy step at all.

Two details keep the observed-claim checks honest. They pass a null package name,
so they consult only the licence allow-list — name-mode already had its single
chance against the real package name in the combined check, and a per-claim
expression must never re-trigger a name rule. And the licence election runs over
the *union* of every deny entry's allow-list at once, so `BUSL-1.1 OR SSPL-1.0`
is denied even though BUSL and SSPL are separate entries; an entry-by-entry check
would judge each branch electable against the other and deny neither.

## Consequences

- **Good:** a denied licence fails no matter how it reached the finding —
  combined precise, elected into an imprecise family, collapsed to unknown, or
  rewritten by an override — and in every scope. The two adversarial-review
  bypasses (override-relicensing and the imprecise/unknown collapse) are closed
  at the deny terminal rather than by special-casing the normalizer.
- **Good:** the combiner stays a general normalization step with no knowledge of
  the deny policy. Deny owns its own completeness through the observed-claim set
  on the finding.
- **Bad / cost:** the finding now carries `observedExpressions`, an extra
  per-package field that the annotator populates and the golden dumps include.
  It is redundant with the combined expression for the common case where nothing
  was lossy, and it widens the model surface for the sake of this one lane.
- **Neutral:** the precedence position and the observed-claim behaviour are both
  locked by tests — deny beating compatible, suppression, the dev and OS
  downgrades, and a stale override, and `[BUSL-1.1, GPL]` / `[Elastic-2.0, GPL]`
  / `[BUSL-1.1, custom]` failing in both app and OS scope while non-denied sets
  are untouched.

## See also

- Related: [ADR-0015](0015-source-available-deny-list.md) (what the deny-list
  contains and why source-available licences are denied at all)
- Plan summaries:
  `.planning/phases/06-terraform-dogfood/06-02-SUMMARY.md` (deny terminal-0,
  POL-09),
  `.planning/phases/06-terraform-dogfood/06-06-review-fixes-SUMMARY.md` (deny
  terminal over overrides + union election),
  `.planning/phases/07-docker-os-packages/07-07-review-fixes-SUMMARY.md` (deny
  sees every observed claim)
- Code: `src/policy/denylist.ts`, `src/policy/evaluate.ts` (`firstDeny`)
