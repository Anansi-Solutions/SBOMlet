# ADR-0018: Adversarial review before completion as a release gate

- **Status:** Accepted
- **Date:** 2026-06-19

## Context and problem

This tool's whole reason to exist is to never let a problematic dependency pass
unseen. The danger is a specific shape of bug: not a crash, but a quiet wrong
answer — a denied licence that comes back ok, a dependency dropped from the
inventory, a "why is this here?" cell that states something that is not true.
None of these announce themselves. The run exits 0, the documents look complete,
and the gate stays green.

Our two strongest correctness checks both have a blind spot here. The TDD suite
only tests the cases we thought to write. The dogfood gate — regenerate against
a real monorepo and prove the output byte-identical to the committed
baseline — only exercises the code paths that the real repo happens to reach.
And the real repo is tame. Its base images carry no source-available licences,
its dependency graphs have no fabricated paths, its overrides never relicense a
denied member. So a bug that fires only on `BUSL-1.1 OR SSPL-1.0`, or on a
dependency reached through two different parents, sails through a byte-identical
dogfood untouched. Passing tests and an identical golden tell you the paths you
exercised are unchanged; they say nothing about the paths you never reached.

We needed a check aimed at exactly that gap — the load-bearing safety property
that the happy path leaves unprobed.

## Decision drivers

- **The failures that matter here are silent.** A denied licence that passes, a
  dropped dependency, a fabricated provenance chain — each exits 0 and looks
  right. The check has to go looking for them on purpose.
- **Goldens and tests cannot cover paths the inputs never reach.** The dogfood
  is necessary but not sufficient; it proves stability, not absence of the
  silent-bypass class.
- **Effort has to land where the risk is.** A full adversarial pass on every
  trivial edit is wasteful; on a change that touches the gate, it is the
  cheapest insurance we have.

## Considered options

1. **Rely on TDD plus the byte-identical dogfood.** Trust that green tests and
   an unchanged golden mean the change is safe.
2. **A single reviewer reading the diff.** One pass, general code review, find
   what stands out.
3. **A multi-lens adversarial review that probes the safety properties, with
   every finding verified by default-refute.** Before a substantive change is
   called done, attack the change from several angles — deny precedence,
   determinism, completeness, no-fabrication — and treat each suspected bug as
   false until a failing test proves it real.

## Decision

We adopted option 3. Before a substantive change completes, it goes through an
adversarial review that probes the properties the tool cannot give up, and each
finding is confirmed by writing the failing test first — default-refute, so a
hunch that cannot be made to fail is dropped, and a real bug arrives with the
regression that pins it.

The reason is what the review keeps catching that the other gates passed over.
Every find below survived a green suite and a byte-identical dogfood, because the
real repo never walked the broken path:

- **Deny re-licensed in by an override.** An override rewrote a denied observed
  licence before the deny lane ran, so the terminal never saw it — a clean
  gate-bypass. The fix made deny consult every observed claim, not the rewritten
  one.
- **Deny bypassed by an OR across separate entries.** Three separate deny
  entries for BUSL, SSPL, and Elastic each judged the *other* branch electable,
  so `BUSL-1.1 OR SSPL-1.0` passed. The fix elects over the union of every deny
  entry at once.
- **A denied member silently dropped by license combination.** When an imprecise
  family token co-existed with a precise denied member, combination elected the
  family and dropped the member, leaving the deny terminal a null expression to
  match against. Threading every per-claim precise licence onto the finding
  closed it.
- **A module dropped from the inventory.** A self-hosted or private-registry
  Terraform module fell outside a fixed host allow-list and was collected as
  nothing at all.
- **Fabricated provenance.** A "why is this here?" path computed on a
  collapsed dup-purl graph could enter a node through one variant's subtree and
  leave through another's, printing a dependency chain that exists on no real
  instance; and an orphan with no introducer rendered a confident "transitive"
  instead of an honest dash.

Comparing on the driver that decided it:

- **TDD plus the dogfood** is the baseline both other gates rest on, and it was
  green for every bug above. It proves the paths you reach are stable. It cannot
  reach the silent-bypass path the tame real repo never walks. Necessary, not
  sufficient.
- **A single general review** finds what stands out in a diff. The bugs above do
  not stand out — each is a correct-looking line that is wrong only on an input
  the diff does not contain. A review with no fixed properties to attack and no
  default-refute discipline tends to miss them and to wave through plausible
  false alarms.
- **The multi-lens adversarial pass** names the properties up front — deny is
  terminal, output is deterministic, no dependency is dropped, nothing is
  fabricated — and goes hunting for a counterexample to each, then makes every
  real finding fail a test before it is fixed. That is the pass that caught the
  list above.

The default-refute rule is what keeps the gate honest in both directions. A
finding is not a bug until a red test demonstrates it, which throws out the
plausible-but-wrong alarms; and once demonstrated, the test ships with the fix,
so the bypass cannot quietly return.

## Consequences

- **Good:** the silent-bypass class — denied licences passing, dropped
  dependencies, fabricated provenance — is caught before completion rather than
  after a wrong inventory ships. Each confirmed finding leaves behind a
  regression test, so the gate gets harder to bypass over time. The reviews
  concentrate on the safety properties, which is where a compliance tool's real
  risk lives.
- **Bad / cost:** it is real effort and it is not free to automate — a
  substantive change to the gate or a collector earns a deliberate pass, which
  slows the change down. We accept that cost on changes that touch correctness,
  and skip it on edits that cannot affect a verdict (a comment diet, a doc fix).
- **Neutral:** the review's discipline is what hardened the design itself. The
  Terraform module-drop pushed the collector off HCL parsing onto a filesystem
  signal (ADR-0013); the deny bypasses fixed the precedence terminal to read
  every observed claim (ADR-0007, ADR-0015); the provenance fabrications
  produced the honest-residual rule (ADR-0016). Several of those decisions exist
  because an adversarial pass refused to accept the first answer.

## See also

- Plan summaries:
  `.planning/phases/06-terraform-dogfood/06-06-review-fixes-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-07-review-fixes-SUMMARY.md`,
  `.planning/phases/07-docker-os-packages/07-16-provenance-fixes-SUMMARY.md`,
  `.planning/phases/05-enrichment-committed-cache/05-07-gap-closure-SUMMARY.md`
- Related: [ADR-0007](0007-deny-terminal-observed-claims.md),
  [ADR-0013](0013-terraform-filesystem-signal-gate.md),
  [ADR-0015](0015-source-available-deny-list.md),
  [ADR-0016](0016-provenance-root-reachable.md)
