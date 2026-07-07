# ADR-0019: ScanCode intensive collector

- **Status:** Accepted
- **Date:** 2026-07-06

## Context and problem

Registry enrichment resolves most licenses by reading a package's own manifest —
the field npm or PyPI already publish. Some packages carry no such field. Their
only license evidence lives in the source: a `LICENSE` file, a header comment, a
notice in a bundled file. Reading that by hand does not scale, and leaving the
package unknown forces every downstream consumer into a manual policy override for
a question a detector could answer.

ScanCode is the standard tool for exactly this — the same detector corpus
[ADR-0002](0002-orchestrate-standard-generators.md) named as the reason we
orchestrate rather than reimplement detection. Bringing it in raised a handful of
smaller calls: how it gets installed, where its answers live, how they interact
with what the registry already decided, whether to remember a "no answer", what to
do with a detection that contradicts a declared license, and what a future ScanCode
upgrade should mean for the committed cache.

## Decision drivers

- **A tool is a tool.** Whatever runs the scan is a dependency of this tool like any
  other; how it is installed should follow the same rule as `task` or `syft`, not a
  special case carved out for size or frequency.
- **One cache, one envelope.** [ADR-0008](0008-offline-check-committed-cache.md)'s
  committed enrichment cache is already the single offline source of truth; a second
  file duplicates that contract for no reason.
- **Fail safe, not fail loud-but-wrong.** A wrong upgrade from imprecise to precise
  is worse than staying imprecise — it hides a license family mismatch instead of
  surfacing it.
- **Honesty over inflation.** [ADR-0007](0007-honest-residual.md)'s residual
  discipline applies here: an unresolved case stays unresolved rather than getting a
  guessed answer.

## Considered options

For where ScanCode is installed:

1. **Pin it in `mise.toml`** like every other tool, installed by `mise install`.
2. **Install it only inside the occasional workflow that runs it**, via an
   exact-pinned `pipx install` in one step, to keep the install cost off runs that
   never scan.

For where its answers live:

3. **Reuse the enrichment cache envelope**, tagging entries by source.
4. **A second, ScanCode-only cache file**, parallel to the enrichment cache.

## Decision

We pin ScanCode in `mise.toml` (option 1) and store its answers in the existing
enrichment cache envelope (option 3).

ScanCode is a dependency of the `--intensive` lane — that lane cannot run without
it, the same way the rest of the tool cannot run without `task` or `syft`. Every
other tool here is declared in `mise.toml` and installed by `mise install`, so
carving ScanCode out because it is large and occasional-use would have been an
exception to that rule rather than a case of it. Installing it only inside the
workflow keeps the cost off the common path, but it splits tool acquisition across
two mechanisms and leaves the `--intensive` lane impossible to run locally with the
same `mise install` the rest of the tool relies on. Pinning it in `mise.toml` costs
every `mise install` ScanCode's provision time — about 90 seconds cold, cached
after — whether or not that run ever scans, and that cost is accepted as part of the
toolchain. The runtime boundary is unchanged: `--intensive` is generate-only and off
by default, so `generate` and `check` never *run* ScanCode unless asked. Only the
install footprint grew, not the default behaviour.

Its answers land in the same enrichment cache envelope ADR-0008 established, tagged
`source: "scancode"` on the entry, with no version bump to the cache format. The
`fetchedAt` field set the precedent: `readCache` casts entries without validating
their field set, so an added optional field is invisible to any consumer that
doesn't ask for it, and a cache written before this phase reads back unchanged. A
second cache file would split the single offline source of truth `check` depends on
into two files that must agree; one envelope with a provenance tag needed no new
machinery.

A ScanCode claim can only ever *fill* a gap, never override a precise one. A package
leaves the scan set once every claim it carries normalizes precisely, or once a
previous scan's answer replays from the committed cache — so a package kept residual
by an imprecise or garbled claim is scanned once, and warm runs re-scan nothing,
letting the scheduled workflow no-op on unchanged inputs. Where a package is
imprecise — a family is known but the exact identifier is not — a ScanCode claim
replaces the entry only when it agrees with the known family. A ScanCode MIT
detection against a declared-imprecise GPL family does not "helpfully" resolve to
MIT; that would hide a real copyleft signal. The disagreement stays imprecise, the
same fail-safe shape [ADR-0015](0015-abstain-over-fragile-parsing.md) uses
elsewhere: when the check to allow an upgrade can't be made confidently, don't make
it.

We do not cache a ScanCode "no license found". A negative registry entry saves a
real network round-trip on every future run; a negative ScanCode entry would only
save a local filesystem scan a small source tree completes quickly, and a fresh
answer is worth more than the round-trip it saves. A package whose license claim
comes back garbled or contradicted stays where the rest of the tool sends
contradictions: `[[clarify]]`, unknown until a person resolves it, never silently
upgraded on a detector's guess.

A ScanCode version bump is a conscious cache invalidation, not an automatic one. The
entry's `via` field records `scancode-toolkit@<version>/<lane>`, so the tool version
behind an answer travels with it. Bumping the pin does not retroactively invalidate
existing entries — the next scan of a package records its own `via` — and a reviewer
can see which tool version stands behind which entry, the audit trail
[ADR-0014](0014-dependency-provenance.md) established for provenance.

## Consequences

- **Good:** the tool gains a real answer for packages the registry lane could never
  resolve. The committed cache stays the single offline source of truth `check`
  reads, with one provenance tag doing all the new work. A wrong upgrade from
  imprecise to precise is structurally prevented, not merely discouraged.
- **Bad / cost:** ScanCode is slow — tens of seconds per unresolved package's source
  tree — and every `mise install` now provisions it, so the toolchain install got
  heavier for the common case that never scans. Both costs are the price of treating
  it as an ordinary pinned tool behind an opt-in lane.
- **Neutral:** the dogfood repository currently has no unresolved packages, so the
  scheduled workflow will mostly no-op. That is expected — the lane exists for the
  dependency that ships a license the registries can't answer, whenever that happens.
  mise's pipx backend drops the `[full]` extra from the pin before installing,
  harmless at 32.5.0 because ScanCode already requires both extras-gated
  dependencies unconditionally; the `[full]` stays in the key so a later release that
  makes the extra load-bearing stays correct.

## See also

- [ADR-0002](0002-orchestrate-standard-generators.md) — orchestrate standard
  detectors; this collector applies that principle to source-level license detection
- [ADR-0008](0008-offline-check-committed-cache.md) — the committed enrichment cache
  envelope this collector writes into
- [ADR-0007](0007-honest-residual.md) — the residual discipline behind fail-safe
  refinement and leaving garbled claims unknown
- Code: `src/enrich/scancode.ts`, `.github/workflows/intensive-scan.yml`, `mise.toml`
