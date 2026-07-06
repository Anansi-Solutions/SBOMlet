# ADR-0019: ScanCode intensive collector

- **Status:** Accepted
- **Date:** 2026-07-06

## Context and problem

Registry enrichment resolves most licenses by reading a package's own
manifest data — the field npm or PyPI already publish. Some packages carry
no such field. Their only license evidence lives in their source: a
`LICENSE` file, a header comment, a notice buried in a bundled file. Reading
that evidence by hand does not scale, and leaving the package unknown forces
every downstream consumer into a manual policy override for a question a
detector could answer.

ScanCode is the standard tool for exactly this — the same detector corpus
ADR-0002 already named as the reason we orchestrate rather than reimplement
detection. Bringing it in raises six smaller questions that each needed a
call: how to install it without taxing every consumer, where its answers
live, how they interact with what the registry already decided, whether to
remember a "no answer" the way we remember a positive one, what to do with a
detection that outright contradicts a declared license, and what a future
ScanCode upgrade should mean for the committed cache.

## Decision drivers

- **Minimal footprint for the common case.** Most runs need no scanning; the
  cost of the capability should fall only on the runs that use it.
- **One cache, one envelope.** ADR-0008's committed enrichment cache is
  already the tool's single offline source of truth; a second file
  duplicates that contract for no reason.
- **Fail safe, not fail loud-but-wrong.** A wrong upgrade from imprecise to
  precise is worse than staying imprecise — it hides a license family
  mismatch instead of surfacing it.
- **Honesty over inflation.** [ADR-0007](0007-honest-residual.md)'s residual
  discipline applies here too: an unresolved case stays unresolved rather
  than getting a guessed answer.

## Considered options

1. **Add ScanCode to the tool's pinned runtime (`mise.toml`).** Every
   consumer and every CI lane installs a full Python toolchain, whether or
   not they ever hit the scan path.
2. **Install ScanCode only inside the occasional CI workflow that uses it,
   pinned to an exact version — chosen.**
3. **A second, ScanCode-only cache file**, parallel to the enrichment cache.
4. **Reuse the existing enrichment cache envelope, tagging entries by
   source — chosen** over option 3.

## Decision

We install ScanCode with an exact-pinned `pipx install` inside the workflow
that runs it, not as a `mise.toml` tool. `mise.toml` tools are paid for by
every consumer on every run; ScanCode is a slow, occasional, opt-in
capability (`--intensive`, generate-only), and the flag it sits behind
already keeps it out of the default path in code. Pinning it in the workflow
keeps that boundary in the install step too: the default `generate` and
`check` never provision Python at all.

Its answers land in the same enrichment cache envelope ADR-0008 established,
tagged `source: "scancode"` on the entry, with no version bump to the cache
format. The `fetchedAt` field set the precedent for this: `readCache` already
casts entries without validating their field set, so an additional optional
field is invisible to every consumer that doesn't ask for it, and a fresh
cache written before this phase reads back unchanged. A second cache file
would have split the single offline source of truth `check` depends on into
two files that have to agree; one envelope with a provenance tag needed no
new machinery at all.

A ScanCode claim can only ever *fill* a gap, never override a precise one. A
package leaves the scan set once every claim it carries normalizes precisely,
or once a previous scan's answer is already replayed from the committed
cache — a package kept residual by an imprecise or garbled claim is scanned
once, and warm runs after that re-scan nothing and rewrite nothing, so the
scheduled workflow no-ops on unchanged inputs. Where a package is imprecise
— a family is known but the
exact identifier is not — a ScanCode claim only replaces the entry when it
agrees with the already-known family; a ScanCode MIT detection against a
declared-imprecise GPL family does not "helpfully" resolve to MIT, because
that would hide a real copyleft signal instead of surfacing it. A
disagreement stays imprecise, which is the same fail-safe shape
[`spdx-satisfies`'s](0015-abstain-over-fragile-parsing.md) try/catch already
uses elsewhere in the tool: when the check to allow an upgrade can't be made
confidently, don't make it.

We do not cache a ScanCode "no license found" the way the registry lane
caches a negative registry answer. A negative registry entry saves a real
network round-trip on every future run; a negative ScanCode entry would save
a local filesystem scan that a small package's source tree completes quickly
enough that the honesty of a fresh answer is worth more than the round-trip
it would save. A package whose garbled or contradicted license claim comes
back stays exactly where the rest of the tool already sends contradictions:
`[[clarify]]`, unknown until a person resolves it, never silently upgraded on
the strength of a detector's guess.

Finally, a ScanCode version bump is a conscious act of cache invalidation,
not an automatic one. The cache entry's `via` field records
`scancode-toolkit@32.5.0/<lane>`, so the tool version that produced an answer
travels with the answer. Bumping the pinned version in the workflow does not
retroactively invalidate existing entries — the next scan of a given package
records its own `via`, and a reviewer auditing the cache can see exactly
which tool version stands behind which entry, the same audit trail ADR-0014
established for provenance generally.

## Consequences

- **Good:** the tool gains a real answer for the packages the registry lane
  could never resolve, without adding a Python dependency to the common
  path. The committed cache stays the single offline source of truth `check`
  reads, with one small provenance tag doing all the new work. A wrong
  upgrade from imprecise to precise is structurally prevented, not just
  discouraged.
- **Bad / cost:** ScanCode is slow — tens of seconds per unresolved
  package's source tree — which is why it lives behind an opt-in flag and a
  scheduled workflow rather than the default path. A repository with several
  unresolved packages in one run pays that cost several times over in a
  single scheduled invocation.
- **Neutral:** the dogfood repository currently has no unresolved packages,
  so the scheduled workflow will mostly no-op. That is expected, not a sign
  the lane is unused — it exists for the dependency that introduces a
  license the registries can't answer, whenever that happens.

## See also

- [ADR-0002](0002-orchestrate-standard-generators.md) (orchestrate standard
  detectors; this collector is the same principle applied to source-level
  license detection)
- [ADR-0008](0008-offline-check-committed-cache.md) (the committed
  enrichment cache envelope this collector writes into)
- [ADR-0007](0007-honest-residual.md) (the residual discipline behind
  fail-safe refinement and leaving garbled claims unknown)
- Code: `src/enrich/scancode.ts`, `.github/workflows/intensive-scan.yml`
