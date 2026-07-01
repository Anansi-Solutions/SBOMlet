# ADR-0008: Offline `check` via a committed enrichment cache

- **Status:** Accepted
- **Date:** 2026-06-13

## Context and problem

Generators leave gaps. A lockfile entry often carries no usable licence, so the
inventory shows it as unknown — about 500 packages on the first live run, mostly
Python and notebook dependencies. Registries have the answer: PyPI and npm publish
the licence in their JSON, and reading it cuts the unknown list to a handful of
genuinely licence-less packages.

That answer comes over the network, and `check` — the CI gate — cannot depend on
the network. It runs on every pull request, often in a sandbox with no egress, and
its verdict must not depend on whether pypi.org is reachable today. So the licences
have to be fetched somewhere, but not in `check`.

## Decision drivers

- **The gate is hermetic.** `check` does not touch the network; its verdict depends
  only on what is committed.
- **Determinism.** The same commit always produces the same result. A live fetch
  makes the result a function of registry availability.
- **The enriched licences survive into the gate.** What `generate` learns has to be
  available to a later offline `check`.
- **Auditability.** A reviewer should see in a diff what the registry said and when
  it changed.

## Considered options

1. **Fetch in both `generate` and `check`.** Each run asks the registry; no stored
   state.
2. **Fetch in `generate`, store in a gitignored cache.** Speeds up repeated local
   runs, but CI has nothing to read.
3. **Fetch in `generate`, write to a committed cache; `check` reads it and never
   fetches.**

## Decision

We fetch only in `generate` and persist the results to a cache file committed to
the repository. `check` reads that cache and never opens a socket. The cache is the
contract between the online step and the offline gate: the only licence `check`
knows about an enriched package is the one a human committed.

A single mode flag threads through the pipeline. `generate` runs enrichment in
generate mode — on a cache miss it fetches the registry, resolves the licence,
appends it as a `registry`-sourced claim, and records the result. `check` runs the
same stage in check mode, where a miss never fetches: an unknown package with no
cache entry is treated as stale, the gate names the package and prints the
`task generate` remedy, and exits 2. There is one write site for the cache, gated on
generate mode, so `check` cannot fetch or write.

The cache is keyed by the verbatim purl, which pins name and version. A given
`name@version` has one licence upstream, so a hit stays valid until the lockfile
changes the purl — no expiry, no staleness heuristic. It is committed, not
gitignored, because an offline `check` needs it on a fresh checkout, and it uses the
tool-wide deterministic format so the byte-comparison gate can tell a real licence
change from noise.

Fetching in `check` breaks the hermetic requirement. A gitignored cache keeps
`check` offline only on a machine that already ran `generate`, and hides the
enriched licences from review. The committed cache lets `check` regenerate the whole
inventory offline and byte-compare it against the committed documents; a tampered
cache that would change the output is caught as stale by the same comparison.

One detail keeps the cache honest: a clean registry answer that genuinely carries no
licence is recorded as a negative entry, so an unresolvable package is not
re-fetched every run. A fetch *failure* is never cached — `generate` throws and
writes nothing, so a transient outage cannot freeze into a false "no licence here".

## Consequences

- **Good:** `check` is fully offline and deterministic. The enriched licences are a
  committed, reviewable artifact: a registry licence change shows in a diff, and
  `[[clarify]]` overrides sit above the cache so a disputed licence is fixable
  without a network round-trip. The first live run took the unknown set from ~500
  packages to four.
- **Bad / cost:** the cache is a file someone keeps current. When a lockfile adds or
  bumps a dependency that needs enrichment, `check` goes stale (exit 2) until
  someone runs `generate` and commits the cache. That is deliberate, but it is a
  step in the dependency-update loop.
- **Neutral:** the cache stores the raw registry string, not a resolved SPDX id. The
  raw string flows through the same normalization path as a generator claim, so
  there is one place that turns text into an expression and the cache is not a
  second resolution authority.

## See also

- Plan summaries:
  `.planning/phases/05-enrichment-committed-cache/05-03-SUMMARY.md`,
  `.planning/phases/05-enrichment-committed-cache/05-04-SUMMARY.md`
- Related: [ADR-0004](0004-deterministic-output.md) (the deterministic format the
  cache uses), [ADR-0017](0017-cache-directory-layout.md) (where the committed cache
  lives)
- Code: `src/enrich/enrich.ts`, `src/enrich/cache.ts`, `src/gate/check.ts`
