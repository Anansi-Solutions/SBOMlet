# ADR-0024: Honest licenseUrl resolution for NuGet

- **Status:** Accepted
- **Date:** 2026-07-18

## Context and problem

NuGet's registration API carries three license shapes: `licenseExpression`
(SPDX, already resolved), `licenseFile` (embedded in the nupkg, out of
reach), and a bare `licenseUrl` — the pre-2019 class every package published
before `licenseExpression` existed still carries. On a real .NET fixture, 112
of 387 packages resolve only to that bare URL.

Following it is normally a lie. `licenseUrl` is author-controlled and can
drift after the package version shipped: a branch can be force-pushed, a
redirect repointed, a page rewritten. A GitHub `master` URL currently
serving MIT text does not prove the cited *version* shipped under MIT — it
proves what `master` says today. Stamping that as the version's license
would assert something never actually verified.

## Decision drivers

- Never assert a license the resolver cannot tie to an immutable target.
- Keep the offline `check` contract (ADR-0008): fetch once, at `generate`,
  into the committed cache — nothing at `check` reads a network.
- No fragile prose scraping (ADR-0015): classifying free text into a
  licensing bucket is the parsing trade this project already declines.
- A grant already extended for a shipped version is irrevocable; evidence is
  cited honestly, not defended as a legal position.

## Considered options

1. **Fetch and SPDX-match every `licenseUrl`.** Clears all 112, inheriting
   the drift above on every one.
2. **Route through deps.dev**, the Maven arm. Measured against the 112: it
   mirrors nuget.org's own `licenseExpression` field and clears 0 — out.
3. **Resolve only GitHub URLs naming an immutable ref; abstain on
   everything else.** Chosen for the packages that support it.

## Decision

`licenseUrl` resolution follows `github.com` / `raw.githubusercontent.com`
only, and only when the URL names a 40-hex commit SHA or a ref proven to be
an existing tag via the GitHub Git Refs API — never a branch, including one
named like a version. A lightweight tag resolves directly; an annotated tag
is peeled once to its commit. The license is read from the GitHub License
API at that exact commit, never the symbolic ref, and both the ref and the
resolved commit are recorded in the cache entry's `via` field.

Two fixture packages show both ends: `Microsoft.AspNetCore.Authorization@2.1.1`
names `raw.githubusercontent.com/aspnet/Home/2.0.0/LICENSE.txt` — `2.0.0`
proves out as a real tag, so it resolves to Apache-2.0.
`System.Buffers@4.5.1` names `.../dotnet/corefx/blob/master/LICENSE.TXT` —
`master` is a branch, so it stays an honest unknown even though that path
currently reads MIT.

A third shape does not fit this arm: roughly 57 pre-2019 `System.*`/
`runtime.*` packages carry `licenseUrl` pointing at
`go.microsoft.com/fwlink/?LinkId=329770`, never auto-followed. As of this
writing it resolves to
[`dotnet/core`'s license-information.md at commit `8c8e5836c343f854b65437dfedb13598d3aa3707`](https://github.com/dotnet/core/blob/8c8e5836c343f854b65437dfedb13598d3aa3707/license-information.md),
which states library packages use MIT but carves out "Product distributions"
(runtime packs, the Windows `.NET Library License`) as non-MIT. Sorting the
57 against that carve-out is a human call, not a pattern match —
`System.IO@4.3.0` is one of them and stays unresolved by this arm; a
follow-up mechanism pins that human decision to this commit, so a later doc
edit re-surfaces it for review.

## Consequences

- **Good:** the ref-pinned class — roughly 25 fixture packages — auto-clears
  with a verifiable audit trail. Every other url-only shape stays an honest
  unknown by design, which is the correct answer, not a gap.
- **Bad / cost:** a cache entry committed before this ADR holds
  `resolvable: false` and is never re-fetched — offline `check` trusts what
  is committed. An existing consumer sees no change until they delete the
  affected entries (or the cache file) and re-run `generate`.
- **Neutral:** a git tag is only *conventionally* immutable. The mitigation
  is recording the resolved commit SHA, not the tag name, plus an online
  `verify-cache` pass that re-resolves the ref and flags a divergence for
  human review — never inside offline `check`. The License API also answers
  for the repository root only, so a URL naming a subdirectory file is not
  resolved by this arm.

## See also

- [ADR-0007](0007-honest-residual.md) — the honest-residual rule this
  follows for every unresolved shape
- [ADR-0008](0008-offline-check-committed-cache.md) — the committed-cache
  split `check` relies on
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — why the fwlink class is
  a human decision, not a prose parser
- [ADR-0022](0022-dotnet-lockfile-in-process.md) — flagged this class as a
  future enrichment arm
- Code: `src/enrich/nugetGithub.ts`, `src/enrich/nuget.ts`,
  `src/enrich/enrich.ts`, `src/enrich/verify.ts`
