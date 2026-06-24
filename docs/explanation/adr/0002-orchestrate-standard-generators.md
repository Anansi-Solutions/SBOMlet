# ADR-0002: Orchestrate standard SBOM generators; do not build a licence-detection engine

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The tool has to learn, for every dependency in a repository, what package it is
and what licence it carries — across Yarn, npm, pnpm, Bun, Poetry, uv, Terraform,
and Docker images. There are two ways to get that information. One is to read it:
parse each ecosystem's lockfiles and manifests ourselves, then open each
installed package and detect its licence from the text of its `LICENSE` files.
The other is to ask the tools that already do this — syft, cdxgen, the Yarn
CycloneDX plugin — and merge what they report.

The first path is where most of a licence tool's risk lives. Lockfile formats
change under you (Yarn 4 protocol entries, poetry groups, npm aliases), and
detecting a licence from raw file text is a corpus problem that projects like
ScanCode and askalono have spent years tuning. Building either one well is a
full-time job; building either one badly produces an inventory that looks
complete and is quietly wrong — the exact failure this tool exists to prevent.

## Decision drivers

- **Correctness through standard tooling.** Industry-credible detection is a
  solved problem owned by maintained projects. Re-deriving it ourselves trades
  their accumulated correctness for our bugs.
- **Minimal footprint and maintenance.** The tool audits dependency trees, so it
  keeps its own surface small. A lockfile parser per ecosystem plus a
  licence-text scanner is a large standing liability that needs a fix every time
  an ecosystem shifts.
- **Where our value actually is.** Nothing in the survey of existing tools does
  generate-and-gate-and-attribute over a simple policy file across ecosystems.
  That gap is in the merge, the policy, and the rendered document — not in
  detection, which several tools already do well.

## Considered options

1. **Build an in-house detection engine** — parse each ecosystem's lockfiles and
   scan installed packages' `LICENSE` text ourselves, askalono/ScanCode-style.
2. **Orchestrate standard generators** — drive cdxgen, the Yarn CycloneDX plugin,
   and syft per target, take their CycloneDX output, and own only the merge,
   normalization, policy, and rendering downstream of it.

## Decision

We orchestrate. Each target is handed to the generator that knows it best, and
every generator returns CycloneDX, which is the only contract the rest of the
tool sees. The generators read lockfiles and resolve licences from inside each
ecosystem's own resolution, which is more accurate than anything a general-purpose
scanner reaches: the Yarn plugin fills licences for 99.6–99.8% of packages on a
real Yarn 4 target where cdxgen alone fills none, because it reads what Yarn
itself resolved. cdxgen covers JS and Python lockfiles; syft covers OS packages in
container images. None of these tools is ever installed into the scanned
project — they run from a pinned version through a throwaway invocation
(`bun x`, `yarn dlx`) with the install step explicitly disabled, so scanning has
no side effect on the repository.

Comparing on the driver that decided it:

- **An in-house engine** would have to match the detection accuracy of tools that
  have years of corpus tuning behind them, and carry a lockfile parser for every
  ecosystem on top. The residual error from declared-metadata detection is
  cheaper to absorb than the cost of getting detection right from scratch.
  Rejected on correctness and maintenance together.
- **Orchestration** inherits that accuracy for free, keeps the runtime tree to a
  handful of packages, and points our effort at the merge-policy-render gap that
  is genuinely unserved. Where a generator's metadata is wrong or missing, a
  `clarify`-style policy override corrects that one package by hand — a small,
  reviewable patch rather than a detection engine.

This draws a hard line around scope. The tool aggregates *declared* licences and
gates on a policy; it does not scan dependency source text, and it does not
reason about licence *compatibility* — that judgment stays with the human reading
the document. Whole-corpus source scanning and a compatibility matrix are listed
as anti-features for the same reason: each is a separate product, and each
trades a bounded, honest "unknown" for a large surface of subtle wrong answers.

The one place we do parse rather than orchestrate is Terraform, and it is a
deliberate exception: no upstream tool resolves Terraform provider and module
licences at their exact resolved versions, so there is nothing to drive there.
That collector reads two trusted artifacts the repo already commits or
materializes and is the subject of its own record — it proves the rule by being
the only case where orchestration was not available.

## Consequences

- **Good:** Detection accuracy comes from maintained, credible tools and improves
  as they improve. The runtime footprint stays small, and per-ecosystem coverage
  grows by adding a thin adapter, not a parser. Our code concentrates on the
  merge, policy, and document — the part no existing tool delivers as a drop-in.
- **Bad / cost:** We depend on external executables and accept their failure
  modes — a generator can mis-report or omit a licence. This is bounded by the
  `clarify`-style override path, which corrects a single package without touching
  the engine, and by the tool treating "no licence found" as a surfaced unknown
  rather than a silent pass.
- **Neutral:** Generators are pinned by exact version through mise and run as
  subprocesses, never added as dependencies of our own code, so a generator
  upgrade is a deliberate, reviewable change. The narrow generator interface
  means switching or adding a generator for a target type is a one-file change
  that the rest of the pipeline never sees.

## See also

- Research: `.planning/research/ARCHITECTURE.md` (orchestration pipeline,
  Anti-Pattern 4), `.planning/research/FEATURES.md` (anti-features: own
  detection engine, compatibility reasoning, deep source scanning)
- Related: [ADR-0001](0001-typescript-on-bun.md) (the stack chosen to drive these
  generators), [ADR-0013](0013-terraform-filesystem-signal-gate.md) (the
  Terraform exception)
- Code: `collectors/` (`cdxgen.ts`, `yarnPlugin.ts`, `dockerOs.ts`, `dispatch.ts`)
