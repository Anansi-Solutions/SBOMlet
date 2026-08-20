# ADR-0026: Chain-scoped acceptances and re-checkable overrides

- **Status:** Accepted
- **Date:** 2026-08-20

## Context and problem

A policy override is an assertion about a dependency, written once and read
years later. The schema recorded them in a shape nobody could re-check. An
acceptance covered a package wherever its optional scope reached, whatever
pulled it in, so a judgment made about a build tool's use of a package silently
also accepted the same package arriving in shipped code. A clarification carried
one free-text reason and one string covering both detection sources at once, so
the only thing the tool could verify was that a single string had not moved.
Neither shape let the gate tell a judgment that still held from one that had
quietly stopped being true.

## Decision drivers

- Fail closed: a claim the scan cannot check must never be applied as though it
  had been checked.
- Honest residual (ADR-0007): where nothing was recorded about a package,
  decide nothing rather than assume the favourable reading.

## Decision

A package-level acceptance now names whose use of the package was judged. Where
the target has a dependency graph the claim is checked against it, and a package
that arrives past every name the entry lists makes the claim untrue — the entry
then decides nothing at that target rather than part of it. The bluntness is the
point: an entry wrong about one package was wrong as written, and splitting it
into narrower entries states the same information truthfully. Where a target has
no graph, a container image's OS layer being the usual one, nothing can be
chain-scoped: only the reserved name for the project itself is accepted there,
and both the documentation and the verdicts say so rather than implying a check
that never ran.

Free-text reasons on an acceptance and on a clarification give way to a value
from a closed set, with prose moved to a separate comment field. A closed value
is what makes a reason checkable: the tool knows what each one asserts, so it
can fail an entry the current evidence disproves, and can tell that apart from
an entry whose subject has merely gone away — the second is a maintenance
signal, not a failure. Letting the tool infer the reason from the licences
involved was rejected: that puts the tool's guess in the audit trail in place of
the author's judgment.

The single precondition string becomes one record per detection source, each
holding what that source reported or the fact that it reported nothing. Two
sources disagreeing is the case most worth recording and one string could not
hold it; recording "nothing" is what lets a source that later starts speaking
reopen the judgment.

There is no compatibility shim. A removed key is rejected by name with its
replacement, so the tool's own error is the migration guide. A deprecation
window was rejected because the rewrite is mechanical and a period in which both
shapes parse means two sets of semantics to keep honest at once. Wildcard
versions were rejected too: a list of exact versions is what a reviewer can
audit, and the tooling below removes the churn that would otherwise argue for
them.

Clarifications may live in a file of their own, named by an explicit key rather
than found by convention — a policy that silently picks up a file it never named
is one nobody can read. That file is machine-owned: an offline maintainer
subcommand rewrites it whole, so the version churn that dominates these entries
is tooling's work rather than hand-editing.

## Consequences

- **Good:** an acceptance records which use was judged and the gate notices when
  that stops being how the package arrives; a stated reason can be disproved
  rather than merely believed; version churn has somewhere to go.
- **Bad / cost:** every existing policy is rewritten once, by hand; validity now
  depends on the scan, so adding a first target without a dependency graph can
  reject a policy nobody edited; a voided entry fails packages that were never
  the problem.
- **Neutral:** an acceptance on a graph-less target is unscoped, and nothing in
  the report suggests otherwise; the closed sets change only with a release, so
  a reason nobody anticipated goes in the comment beside the nearest value.

## See also

- Related: [ADR-0007](0007-honest-residual.md) (the residual principle an
  unrecorded introduction follows), [ADR-0014](0014-dependency-provenance.md)
  (the provenance the chains are walked over),
  [ADR-0025](0025-target-license-compatibility-lane.md) (the lane these entries
  still decide ahead of)
- Code: `src/policy/schema.ts`, `src/policy/chain.ts`,
  `src/policy/crossValidate.ts`, `src/policy/justificationValidity.ts`,
  `src/policy/clarifications.ts`, `src/maintain/refreshClarifications.ts`
