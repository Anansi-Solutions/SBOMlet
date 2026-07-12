# ADR-0002: Orchestrate standard SBOM generators; don't build a licence-detection engine

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

For every dependency in a repository the tool has to learn what package it is and
what licence it carries — across Yarn, npm, pnpm, Bun, Poetry, uv, Terraform, and
Docker images. There are two ways to get that. One is to read it ourselves: parse
each ecosystem's lockfiles, open each installed package, and detect its licence
from `LICENSE` file text. The other is to run the tools that already do this —
syft, cdxgen, the Yarn CycloneDX plugin — and merge what they report.

Doing it ourselves is expensive and error-prone. Lockfile formats change (Yarn 4
protocol entries, poetry groups, npm aliases), and detecting a licence from raw
file text is a corpus problem that ScanCode and askalono have tuned over years. A
detector that is only good enough produces an inventory that looks complete but is
wrong in places.

## Decision drivers

- **Correctness through maintained tooling.** Credible detection already exists in
  active projects; re-deriving it trades their accuracy for our bugs.
- **Small footprint, low maintenance.** A lockfile parser per ecosystem plus a
  licence-text scanner needs a fix every time an ecosystem changes.
- **Where our value is.** No surveyed tool does generate-and-gate-and-attribute
  over a simple policy file across ecosystems. That gap is the merge, the policy,
  and the rendered document — not detection.

## Considered options

1. **An in-house detection engine** — parse lockfiles and scan `LICENSE` text
   ourselves, askalono/ScanCode-style.
2. **Orchestrate standard generators** — drive cdxgen, the Yarn plugin, and syft
   per target; own only the merge, normalization, policy, and rendering.

## Decision

We orchestrate. Each target goes to the generator that handles it best, and
every generator returns CycloneDX, the only contract the rest of the tool sees.
The generators resolve licences from inside each ecosystem's own resolution —
the Yarn plugin fills licences for 99.6–99.8% of packages on a real Yarn 4
target, where cdxgen alone fills none. None is installed into the scanned
project: each runs from a pinned version through a throwaway invocation
(`bun x`, `yarn dlx`) with install disabled.

An in-house engine would have to match that detection accuracy from scratch and
carry a lockfile parser per ecosystem on top. The residual error from
declared-metadata detection is cheaper to absorb: a `clarify`-style policy
override corrects a wrong package by hand.

This fixes the scope. The tool aggregates *declared* licences and gates on a
policy; it does not scan dependency source text and does not reason about
licence *compatibility*. Each of those is a separate product that trades a
bounded "unknown" for a surface of subtle wrong answers.

The one place we parse rather than orchestrate is Terraform, where no upstream
tool resolves provider and module licences at their resolved versions — the
exception in [ADR-0015](0015-abstain-over-fragile-parsing.md).

## Consequences

- **Good:** detection accuracy comes from maintained tools and improves as they
  do. Coverage grows by adding a thin adapter, not a parser. Our code concentrates
  on the merge, policy, and document.
- **Bad / cost:** we depend on external executables and their failure modes — a
  generator can mis-report or omit a licence. The `clarify` override corrects a
  single package, and "no licence found" is surfaced as unknown rather than passed.
- **Neutral:** generators are pinned by version through mise and run as
  subprocesses, so an upgrade is a deliberate change. The narrow interface makes
  switching a generator a one-file change.

## See also

- Related: [ADR-0001](0001-typescript-on-bun.md) (the stack that drives these
  generators), [ADR-0015](0015-abstain-over-fragile-parsing.md) (the Terraform
  exception, where we parse a filesystem signal instead)
- Code: `collectors/` (`cdxgen.ts`, `yarnPlugin.ts`, `dockerOs.ts`, `dispatch.ts`)
