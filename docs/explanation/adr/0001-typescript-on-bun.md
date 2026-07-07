# ADR-0001: TypeScript on Bun as the implementation stack

- **Status:** Accepted
- **Date:** 2026-06-10

## Context and problem

The tool orchestrates external SBOM generators, merges their output, applies a
policy, and renders an attribution document. Before writing any of that we had to
pick a language and runtime. The choice affects which generators we can drive, how
the tool ships (git clone and a Taskfile include, no build step), and how small
its own dependency footprint stays.

The two serious candidates were TypeScript on Bun and Python on uv.

## Decision drivers

- **Fit with the SBOM ecosystem.** The generators and SPDX data we depend on
  should be reachable without friction.
- **A small dependency footprint.** A licence auditor should not ship thousands of
  its own transitive dependencies.
- **No build step.** The tool runs from a clone in any CI, so the runtime has to
  execute source directly.
- **No lock-in.** The code should keep running if a consumer refuses Bun.

## Considered options

1. **TypeScript on Bun** — runtime-agnostic TypeScript, run on Bun, no Bun-only
   APIs in the core.
2. **Python on uv** — `cyclonedx-python-lib` plus `license-expression`,
   environments managed by uv.

## Decision

We chose TypeScript on Bun. The SBOM ecosystem is mostly JavaScript, and the
first consumer is a Yarn 4 monorepo: cdxgen is a TypeScript project, the
official Yarn SBOM plugin is JavaScript, and the SPDX packages we need are on
npm. Driving and importing these is direct from TypeScript and awkward from
Python.

The footprint holds — no CLI framework, logger, or HTTP client; `node:util` for
arguments, the global `fetch`, template literals for rendering. Python on uv was
viable (`cyclonedx-python-lib` is strong, `license-expression` is the best
SPDX-expression library in any language), but the tool's work is process
orchestration, JSON merging, and rendering, where Python gains nothing and loses
the Yarn-native integration.

## Consequences

- **Good:** the Yarn plugin, cdxgen, and the SPDX toolchain are native to the
  runtime, so per-ecosystem integration stays simple. Bun runs `.ts` directly
  with a fast cold start, which matters for a CI gate.
- **Bad / cost:** Bun is younger and less battle-tested than Node. The core is
  written against standard APIs (`fetch`, `node:` builtins, `smol-toml` rather
  than Bun's native TOML import) so it also runs under Node 20+. Bun is
  recommended, not required.
- **Neutral:** external generators are pinned by version through mise and run as
  subprocesses, never added as our dependencies.

## See also

- Related: [ADR-0002](0002-orchestrate-standard-generators.md) (the generators this
  stack drives), [ADR-0016](0016-adoption-and-distribution.md) (git-clone
  distribution)
- Code: `mise.toml`, `package.json`, `src/cli.ts`
