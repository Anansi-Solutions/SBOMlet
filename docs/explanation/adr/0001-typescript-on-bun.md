# ADR-0001: TypeScript on Bun as the implementation stack

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The tool orchestrates external SBOM generators, merges their output, applies a
policy, and renders an attribution document. Before writing any of that, we had
to pick a language and runtime. The two serious candidates were TypeScript on
Bun and Python on uv. The choice shapes everything downstream: which generators
we can drive cleanly, how the tool is distributed (it ships by git clone and a
Taskfile include, with no build step), and whether we can keep the dependency
footprint small enough that a tool which audits dependencies isn't an
embarrassment itself.

## Decision drivers

- **Fit with the SBOM tooling ecosystem.** The generators and SPDX data the tool
  leans on should be reachable without friction.
- **Minimal dependency footprint.** A license auditor cannot ship thousands of
  its own transitive dependencies.
- **Distribution without a build step.** The tool runs from a clone via mise and
  Taskfile in any CI, so the runtime has to execute source directly.
- **No vendor lock-in.** The runtime is a convenience, not a cage; the code
  should keep running if a consuming project refuses it.

## Considered options

1. **TypeScript on Bun** — runtime-agnostic TypeScript, run on Bun, no Bun-only
   APIs in the core.
2. **Python on uv** — `cyclonedx-python-lib` plus nexB's `license-expression`,
   environments managed by uv.

## Decision

We chose TypeScript on Bun because the SBOM ecosystem's center of gravity is
JavaScript and the first consumer is a Yarn 4 monorepo. The most capable
multi-ecosystem generator, cdxgen, is itself a TypeScript project; the official
Yarn SBOM plugin is JavaScript and reads license metadata from inside Yarn's own
resolution; and the SPDX expression and data packages that npm itself depends on
live on npm. Driving, pinning, and (where useful) importing these is
straightforward from TypeScript and awkward from Python.

The footprint constraint holds in TypeScript. The CycloneDX library we build on
has no hard runtime dependencies, and the SPDX and TOML packages are small and
mostly pure data. The runtime tree is a handful of direct packages with no CLI
framework, no logger, and no HTTP client — argument parsing uses `node:util`,
requests use the global `fetch`, and the renderer is template literals.

Python on uv was a real contender, not a straw man. `cyclonedx-python-lib` is a
strong library, and `license-expression` is arguably the best SPDX-expression
library in any language. But the tool's work is process orchestration, JSON
merging, and rendering — Python gains nothing there, loses the Yarn-native
integration, and uv's strength in environment management is irrelevant to a tool
that deliberately never installs the scanned project's dependencies. Python
would have been the choice for a Python-first team, or if we needed
ScanCode-grade license-text *detection* rather than declared-license
aggregation, which is out of scope.

## Consequences

- **Good:** The Yarn plugin, cdxgen, and the SPDX toolchain are all native to the
  runtime, so per-ecosystem integration stays simple. Bun runs `.ts` directly,
  which suits the git-clone distribution, and its test runner adds no dev
  dependency. Cold start is fast, which matters for a CI gate.
- **Bad / cost:** Bun is younger than Node and less battle-tested. We accept that
  by writing the core against standard APIs — `fetch`, `node:` builtins,
  `node:util` `parseArgs`, and `smol-toml` in place of Bun's native TOML import —
  so the tool also runs under Node 20+ unchanged. Bun is the recommended runner,
  not a hard dependency.
- **Neutral:** External generators are pinned by exact version and run through
  mise, never added as dependencies of our code. If the tool is later published,
  Bun can compile a single-file executable without restructuring, which keeps the
  clone path and opens a registry path at the same time.

## See also

- Research: `.planning/research/STACK.md`, `.planning/research/SUMMARY.md`
- Plan summary: `.planning/phases/01-pipeline-spine/01-01-SUMMARY.md`
- Code: `tools/licenses/mise.toml`, `tools/licenses/package.json`,
  `tools/licenses/src/cli.ts`
