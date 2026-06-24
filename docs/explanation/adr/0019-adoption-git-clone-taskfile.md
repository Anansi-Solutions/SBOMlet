# ADR-0019: Adoption by git clone + Taskfile include; single-binary deferred

- **Status:** Accepted
- **Date:** 2026-06-13

## Context and problem

The tool has to be adoptable by any repository, not just the one it was built
in. That is a stated project constraint: a project picks it up without taking on
a coupling to it, and a contributor can read and change the tool in place. So we
had to settle how the tool is delivered and how a consumer wires it in.

Two questions sit underneath that. The first is the distribution channel — do we
publish to a registry (npm, or a mise plugin) and have consumers install a
versioned package, or do they take a copy of the source? The second is the form
the tool runs in — does it stay a `.ts` source tree run by a pinned Bun, or do
we ship a compiled single-file executable so a consumer needs no runtime at all?
Both questions were open from the first phase and the second one stayed open
because Bun can compile a binary, which is a real option we did not want to
adopt on reflex.

## Decision drivers

- **Independence from the consuming project.** Adoption must not make the
  consumer depend on a release we control or a registry account. A repository
  should be able to clone the tool and own its copy outright.
- **No build step.** The runtime runs `.ts` directly. A distribution that needed
  a compile-and-publish cycle would add machinery the clone path does not have.
- **Minimal dependency footprint.** A tool that audits dependency trees keeps its
  own small. Any packaging layer that drags in a CLI framework and its tree is a
  poor trade for a tool whose argument parsing is already a few lines of
  `node:util`.
- **CI-vendor neutrality.** The same two commands have to run in any CI and
  locally, through mise and Taskfile, with nothing tied to one CI provider.

## Considered options

1. **Copied directory + Taskfile include + policy file** — the consumer copies
   `tools/licenses/`, adds a Taskfile `includes:` entry, and writes one
   `policy.toml`.
2. **Publish to npm (or a mise plugin registry)** — consumers install a
   versioned package and invoke a published binary.
3. **Ship a compiled single binary** — `bun build --compile` produces a
   self-contained executable; consumers run it with no Bun on the path.
4. **Adopt bunli** — a CLI framework that wraps the same compile step and adds
   command scaffolding.

## Decision

A consumer adopts the tool by copying the `tools/licenses/` directory into their
repository, adding one Taskfile include, and copying `policy.example.toml` to
`policy.toml`. There is no `npm publish`, no registry, and no install step beyond
mise and Task, which the consumer already needs. The include points Task at the
tool's own Taskfile and pins its working directory so the pinned Bun resolves
from the tool's `mise.toml`; from there `task licenses:generate` and
`task licenses:check` are the whole interface.

This holds the independence driver directly. A copied directory belongs to the
consumer — they can read it, pin it, patch it, and never wait on a release of
ours. Publishing to a registry would invert that: it couples every consumer to a
version we cut and a channel we maintain, for a tool the project explicitly
wants to keep decoupled. The footprint of the copy is the source tree itself,
which a contributor can already see, so there is nothing to weigh against the
no-build-step and minimal-footprint drivers.

The single binary is deferred, not rejected. The phase that proved it confirmed
that a raw `bun build --compile` already produces a working executable of this
tool — the full exit taxonomy, the external generator spawning, all of it — once
the one `createRequire` call was replaced with a static import. So the v2
distribution path is open and proven; it is just not needed while every target
consumer already runs mise. Shipping the binary now would add a build-and-attach
release step to a clone-based tool that has none, for an audience that does not
yet exist.

`bunli` was rejected outright rather than deferred. It wraps the same compile we
already get for free and brings costs the bare compile does not: a second runtime
validation library (zod) alongside the arktype boundary the tool had just
standardized on, roughly eight more packages against the footprint constraint,
and a pre-1.0 single-publisher maturity profile with no Windows usage signal —
and Windows is a supported platform here. It buys command scaffolding the tool
does not need, since the CLI is one `parseArgs` call and a subcommand switch.

## Consequences

- **Good:** A consumer owns its copy with no upstream coupling and no registry
  account. The clone path needs no build and no compile, the runtime footprint
  stays the visible source tree plus a handful of pinned packages, and the same
  `generate`/`check` tasks run in any CI through mise and Task. The single-binary
  route is proven feasible, so deferring it costs no future option.
- **Bad / cost:** A copied directory does not update itself. A consumer who wants
  a later version re-copies the directory; there is no `npm update` to pull a
  fix. This is the price of the independence we chose, and it is acceptable while
  the dogfood repository is the only consumer.
- **Neutral:** The decision is reversible in the additive direction. Publishing a
  package or attaching a compiled binary to a release later does not disturb the
  clone path — the same source compiles, so a registry path and the clone path
  can coexist. The static-import fix that unblocked the compile already landed,
  so a future v2 picks up from a working build.

## See also

- Plan summaries:
  `.planning/phases/04.7-code-quality-refactoring-inserted/04.7-04-SUMMARY.md`
  (the bunli verdict and proven `bun build --compile` feasibility),
  `.planning/phases/04.7-code-quality-refactoring-inserted/04.7-02-SUMMARY.md`
  (the `createRequire` → static-import fix that unblocked the compile)
- Research: `.planning/research/FEATURES.md` (npm/mise-registry distribution
  deferred to v2+), `.planning/research/STACK.md`
- Related: [ADR-0001](0001-typescript-on-bun.md)
- Code: `tools/licenses/Taskfile.yml`, `tools/licenses/README.md`,
  `tools/licenses/policy.example.toml`
