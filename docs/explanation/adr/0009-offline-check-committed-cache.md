# ADR-0009: Offline check via a committed enrichment cache

- **Status:** Accepted
- **Date:** 2026-06-13

## Context and problem

Generators leave gaps. A lockfile entry often carries no usable licence, so the
inventory shows it as unknown — about 500 packages on the first live
run, mostly Python and notebook dependencies. The fix is to ask each package's
own registry: PyPI and npm publish the licence in their JSON, and reading it
burns the unknown list down to a handful of genuinely licence-less packages.

That answer comes over the network, and the network is exactly what the gate
cannot depend on. `check` is the CI gate. It runs on every pull request, often
in a sandbox with no egress, and it has to be deterministic: the same inputs
must produce the same verdict whether or not pypi.org is reachable today. A gate
that fetches is a gate that can pass on Monday and fail on Tuesday because a
registry was slow, or fail in an air-gapped runner that was never the problem.
So the licences have to be fetched somewhere, but not in `check`.

## Decision drivers

- **The gate must be hermetic.** `check` cannot touch the network. Its verdict
  depends only on what is committed to the repository.
- **Determinism.** The same commit must always produce the same gate result.
  A live fetch makes the result a function of registry availability and timing,
  which is not something a CI gate may depend on.
- **The enriched licences must survive into the gate.** Whatever `generate`
  learns from a registry has to be available to a later offline `check` without
  re-fetching it.
- **Auditability.** A reviewer should be able to see in a diff what the registry
  said and when it changed, the same way they see any other source change.

## Considered options

1. **Fetch in both `generate` and `check`.** Each run asks the registry directly;
   no stored state.
2. **Fetch in `generate`, store in a runtime (gitignored) cache.** The cache
   speeds up repeated local runs but is not committed, so CI has nothing to read.
3. **Fetch in `generate`, write to a committed cache; `check` reads it and never
   fetches.** The enriched licences are a reviewed artifact in the repository.

## Decision

We fetch only in `generate` and persist the results to a cache file that is
committed to the repository. `check` reads that cache and never opens a socket.
The cache is the contract between the online step and the offline gate: the only
licence `check` knows about an enriched package is the one a human committed.

The split lives in a single mode flag threaded through the pipeline. `generate`
runs the enrichment stage in generate mode — on a cache miss it fetches the
registry, resolves the raw licence, appends it as a `registry`-sourced claim,
and records the result. `check` runs the same stage in check mode, where a miss
never fetches: an unknown package with no cache entry is treated as stale, the
gate names the package and prints the `task generate` remedy, and exits
2. There is one write site for the cache, and it is gated on generate mode, so
`check` cannot fetch and cannot write even by accident.

The cache is keyed by the verbatim purl, which already pins name and version.
A given `name@version` has one licence upstream forever, so a cache hit stays
valid until the lockfile changes the purl — no expiry, no hashing, no staleness
heuristic. The file is committed, not gitignored, because an offline `check`
needs it present on a fresh checkout. It uses the tool-wide deterministic format
— sorted keys, two-space indent, LF, no timestamp — so it diffs cleanly and the
byte-comparison gate can tell a real licence change from noise.

Comparing on the driver that decided it:

- **Fetching in `check`** fails the hermetic requirement outright. The gate would
  break in an air-gapped runner and could flip its verdict on a registry hiccup.
  Rejected.
- **A gitignored runtime cache** keeps `check` offline only on a machine that
  already ran `generate`. A clean CI checkout has nothing to read, so the gate
  would still have to fetch or fail. It also hides the enriched licences from
  review — they would never appear in a diff. Rejected on both the hermetic and
  the auditability drivers.
- **The committed cache** lets `check` regenerate the whole inventory offline and
  byte-compare it against the committed documents. The enriched licences are a
  reviewed file like any other, and a tampered cache that would change the output
  is caught as stale by the same comparison.

One detail matters for trust: a clean registry answer that genuinely carries no
licence is recorded as a negative entry, so a package known to be unresolvable
is not re-fetched on every run. A fetch *failure*, by contrast, is never cached
— `generate` throws loudly and writes nothing, so a transient outage can never
be frozen into a false "no licence here". The cache records what a registry
said, never what a timeout implied.

## Consequences

- **Good:** `check` is fully offline and deterministic — it closes the
  zero-network clause that the CI gate (ADR for the check gate) had deferred. The
  enriched licences are a committed, reviewable artifact: a registry licence
  changing shows up in a diff, and policy `[[clarify]]` overrides sit above the
  cache so a disputed licence is fixable without a network round-trip. The first
  live run took the unknown set from roughly 500 packages to four.
- **Bad / cost:** the cache is a file someone has to keep current. When a
  lockfile adds or bumps a dependency that needs enrichment, `check` goes stale
  (exit 2) until someone runs `generate` to refresh and commit the cache. This
  is deliberate — a stale gate that names the package and the remedy is the
  honest outcome — but it is an extra step in the dependency-update loop.
- **Neutral:** the cache stores the raw registry string, not a resolved SPDX id.
  The raw string flows through the same normalization path as a generator claim,
  so there is one place that turns text into an SPDX expression, and the cache
  never becomes a second resolution authority.

## Amendment, 2026-07-02

The write condition described above changed. `generate` used to write the cache
only after fetching at least one new license, so a repository with nothing left
to enrich never got the file at all — a first-time adopter with an all-resolved
dependency tree ran `generate`, found no committed cache on disk, and had nothing
to commit for `check` to read offline. `generate` now writes the cache on every
run, recording an empty envelope when there was nothing to fetch. An empty cache
is a valid answer: it means enrichment ran and needed nothing, not that
enrichment never happened. The rest of this record still holds — there is one
write site, gated on generate mode, and `check` still never fetches or writes.

## See also

- Plan summaries: `.planning/phases/05-enrichment-committed-cache/05-03-SUMMARY.md`,
  `.planning/phases/05-enrichment-committed-cache/05-04-SUMMARY.md`
- Phase context: `.planning/phases/05-enrichment-committed-cache/05-CONTEXT.md`
- Code: `src/enrich/enrich.ts`, `src/enrich/cache.ts`, `src/gate/check.ts`
