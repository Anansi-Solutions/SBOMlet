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
its verdict must not depend on whether the registry is reachable today. So the
licences have to be fetched somewhere, but not in `check`.

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
the repository; `check` reads that cache and never opens a socket. The cache is
the contract between the online step and the offline gate — the only licence
`check` knows about an enriched package is the one a human committed. A single
mode flag threads through the pipeline: on a cache miss, `generate` fetches the
registry and appends a `registry`-sourced claim, while `check` treats the same
miss as stale, names the package, prints the `task generate` remedy, and exits 2.
`generate` writes the cache on every run, even when nothing new resolves, so a
first-time adopter with an all-resolved tree still has a file to commit.

The cache is keyed by the verbatim purl: a given `name@version` has one licence
upstream, so a hit stays valid with no expiry. It is committed, not gitignored,
because an offline `check` needs it on a fresh checkout — fetching in `check`
would break the hermetic requirement, and a gitignored cache would keep `check`
offline only on a machine that already ran `generate`, hiding the enriched
licences from review. A clean registry answer that carries no licence is recorded
as a negative entry so it isn't re-fetched every run; a fetch *failure* is never
cached, so a transient outage cannot freeze into a false "no licence here".

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
- **Neutral:** the cache stores the raw registry string, not a resolved SPDX id, so
  it flows through the same normalization path as a generator claim rather than
  acting as a second resolution authority.

## See also

- Related: [ADR-0004](0004-deterministic-output.md) (the deterministic format the
  cache uses), [ADR-0017](0017-cache-directory-layout.md) (where the committed cache
  lives)
- Code: `src/enrich/enrich.ts`, `src/enrich/cache.ts`, `src/gate/check.ts`
