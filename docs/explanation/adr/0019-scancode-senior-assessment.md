# ADR-0019: ScanCode as the senior licence assessment

- **Status:** Accepted
- **Date:** 2026-07-09

## Context and problem

Most licences are settled by a quick check — the field npm or PyPI already
publish. That field is often thin, sometimes missing, and sometimes wrong: it
names one licence while the text in the package's own source says another.
ScanCode reads that source directly and is far more accurate.

The first cut of this record answered one question the wrong way: when the quick
check and an in-depth scan disagree, which is believed? It treated the scan as a
junior gap-filler — run only where the quick check came up empty, never allowed
to contradict a published answer — so a real disagreement was silently dropped.
This record settles how the two rank, what a disagreement does, and where a
scan's answers are kept.

## Decision drivers

- The in-depth reading is the more trustworthy one; where it exists it should
  be believed over the quick check.
- A disagreement is the case a person needs to see, not one to resolve
  automatically in either direction.
- A scan is slow, so a past result must not be recomputed.
- Offline `check` and byte-for-byte determinism must survive unchanged.

## Considered options

1. **Scan as a junior gap-filler** — run it only on unresolved packages, never
   let it override, drop disagreements. (The first cut of this record; rejected.)
2. **Scan as the senior assessment** — assess every package, let a scan outrank
   the quick check, surface disagreements to resolve.
3. **Keep scan answers in the quick-check cache**, tagged by origin.
4. **Keep them in a separate committed record.**

## Decision

We assess the full package set and let a scan outrank the declared and registry
answer wherever one exists; an explicit `[[clarify]]` still sits above all, the
lane a person uses to have the last word. Where a scan and the quick check
disagree, neither is taken automatically — the package fails the gate as a
distinct conflict, resolved by a `[[clarify]]` recording the decision. That
visible failure replaces the old silent drop ([ADR-0007](0007-honest-residual.md)).

The scan's answers live in their own committed record, keyed by package and
version, separate from the quick-check cache. It also records versions scanned
and found empty, so an unchanged version is never rescanned; a missing record is
a no-op replay, byte-identical to a repository that never scanned. One shared
cache was rejected: the two answers carry different meanings and audit stories.

The scan stays an opt-in `--intensive` step on `generate`; `check` never runs
it. The scanner is pinned in `mise.toml` like every other tool, and each answer
keeps a `via` note of the tool version behind it.

## Consequences

- **Good:** the more accurate reading wins by default, and a real disagreement
  becomes a visible gate failure with a documented fix; a past scan is never
  repeated, so scheduled runs stay cheap after the first.
- **Bad / cost:** ScanCode is slow — tens of seconds per source tree — so the
  first full run is a long backfill, and every `mise install` provisions the
  scanner even when a run never scans. A scheduled run that finds a new
  disagreement turns the main gate red until someone writes the clarify — the
  design working, not a regression.
- **Neutral:** the scan record has no online audit — nothing upstream can
  re-derive a source scan the way a registry re-answers a query. Its integrity
  rests on reviewed commits, per-entry `via` provenance, and the deny lane still
  failing any denied licence whatever the record holds. A stale answer is
  refreshed deliberately — delete entries and re-scan.

## See also

- [ADR-0002](0002-orchestrate-standard-generators.md) — orchestrate standard
  detectors; this applies that to source-level licence detection
- [ADR-0007](0007-honest-residual.md) — the honest-residual discipline behind
  surfacing a disagreement instead of guessing
- Code: `src/enrich/scancode.ts`, `src/enrich/assess.ts`,
  `.github/workflows/intensive-scan.yml`, `mise.toml`
