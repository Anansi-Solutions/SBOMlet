# ADR-0019: Adoption by git clone + Taskfile include; a compiled binary declined

- **Status:** Accepted
- **Date:** 2026-06-13; compiled-binary decision 2026-06-24 (consolidated from the former ADR-0020)

## Context and problem

The tool has to be adoptable by any repository, not just the one it was built in.
That is a stated project constraint: a project picks it up without taking on a
coupling to it, and a contributor can read and change the tool in place. So we had
to settle how the tool is delivered and how a consumer wires it in.

Two questions sit underneath that. The first is the distribution channel — do we
publish to a registry (npm, or a mise plugin) and have consumers install a
versioned package, or do they take a copy of the source? The second is the form
the tool runs in — does it stay a `.ts` source tree run by a pinned Bun, or do we
ship a compiled single-file executable so a consumer needs no runtime at all? Both
were open from the first phase, and the binary question stayed open because Bun can
compile one — a real option we did not want to adopt on reflex, and one we later
built and measured before deciding.

## Decision drivers

- **Independence from the consuming project.** Adoption must not make the consumer
  depend on a release we control or a registry account. A repository should be able
  to clone the tool and own its copy outright.
- **No build step, minimal footprint.** The runtime runs `.ts` directly; a tool
  that audits dependency trees keeps its own small. A packaging layer that needs a
  compile-and-publish cycle, or that drags in a CLI framework and its tree, is a
  poor trade.
- **No redundant machinery.** A distribution mechanism that duplicates something
  mise already provides is weight without benefit.
- **The generators are not ours.** cdxgen (JS/npm) and syft (Go) do the SBOM
  generation; the ~15 kLOC we own is orchestration. Any distribution has to account
  for what those generators need at runtime.
- **CI-vendor neutrality.** The same two commands have to run in any CI and locally,
  through mise and Taskfile, with nothing tied to one CI provider.

## Considered options

1. **Copied directory + Taskfile include + policy file** — the consumer vendors the
   source, adds a Taskfile `includes:` entry, and writes one `.sbomlet.toml`.
2. **Publish to npm (or a mise plugin registry)** — consumers install a versioned
   package and invoke a published binary.
3. **Ship a compiled per-platform binary** (`bun build --compile`) + a release
   pipeline, with cdxgen also pinned as a mise binary so the tool is runtime-free.
4. **Adopt a CLI framework** (bunli) that wraps the same compile step.
5. **Rewrite the orchestrator in a compile-to-native language (Go/Rust)** for a
   genuinely small self-contained binary.

## Decision

**Adoption is git clone + a Taskfile include.** A consumer vendors the tool's
directory, adds one Taskfile include, and copies `policy.example.toml` to
`.sbomlet.toml`. There is no `npm publish`, no registry, and no install step beyond
mise and Task, which the consumer already needs. The include points Task at the
tool's own Taskfile and pins its working directory so the pinned Bun resolves from
the tool's `mise.toml`; from there `task generate` and `task check` are the whole
interface. A copied directory belongs to the consumer — they read it, pin it, patch
it, and never wait on a release of ours. Publishing to a registry would invert that,
coupling every consumer to a version we cut and a channel we maintain, for a tool
the project explicitly wants to keep decoupled.

**The compiled binary is declined, not deferred.** We built it — a `bun build
--compile` binary per platform with a tag-triggered release workflow, and a switch
of cdxgen from `bun x` to a mise-pinned standalone binary so the compiled tool would
not need bun at all — and two findings settled it against shipping:

- **The binary is ~100 MB because `bun build --compile` embeds the entire Bun
  runtime;** our code is a few hundred KB. That embedded runtime is redundant:
  cdxgen is a JS tool, so a JS runtime is already in the toolchain, and a binary
  that bundles a second copy buys nothing mise does not already provide.
- **mise's github backend cannot pin cdxgen's standalone binary.** cdxgen's release
  ships ~24 assets across platforms, and mise resolves the sibling `aibom` tool,
  ignoring `matching`/`bin` — verified in `mise install` and the lockfile. The
  runtime "validation" that appeared to pass was aibom, which shares cdxgen's
  codebase and so answers `-t js` plausibly. cdxgen is fundamentally an npm tool,
  most reliably run via `bun x` with the version pinned in the argv.

So distribution stays git + a Taskfile include + a single mise-pinned **bun** that
both runs the tool from source and runs `bun x @cyclonedx/cdxgen`; syft stays an
aqua-pinned binary on the maintainer-only Docker path. `bunli` was rejected
outright: it wraps the same compile and adds a second validation library, ~8 more
packages, and a pre-1.0 single-publisher profile with no Windows signal. A native
(Go/Rust) rewrite is the only path to a genuinely small binary, but it does not by
itself remove the JS runtime — cdxgen would still be shelled out to — so it is gated
behind a coverage measurement (below), not adopted now.

## Consequences

- **Good:** a consumer owns its copy with no upstream coupling and no registry
  account. The clone path needs no build and no compile; the runtime footprint stays
  the visible source tree plus a single mise-pinned bun (the build tool, the
  from-source runtime, and the `bun x` cdxgen launcher in one). The same
  `generate`/`check` tasks run in any CI through mise and Task. No 100 MB artifact,
  no release pipeline, no per-platform build matrix, no cdxgen-asset breakage. cdxgen
  stays the actual tool, pinned in the argv.
- **Bad / cost:** a copied directory does not update itself — a consumer who wants a
  later version re-copies it; there is no `npm update`. And adoption is "vendor the
  source + a Taskfile include + mise," not a one-line binary install. Both are the
  price of the independence we chose, acceptable while the dogfood repository is the
  main consumer (and [ADR-0023](0023-composite-github-action.md) collapses the CI
  wiring to one step on GitHub Actions).
- **Neutral — the path if a binary becomes a priority:** the decision to revisit is
  gated on one measurement, not a language preference — whether syft or trivy (both
  Go, both embeddable as a library) give acceptable app-dependency licence coverage
  versus cdxgen ([ADR-0002](0002-orchestrate-standard-generators.md) chose cdxgen for
  better fill). If they do, a Go rewrite embedding syft yields a true single binary
  with no JS runtime and trivial cross-compilation, at the cost of the port and
  re-validating coverage and determinism. If they do not, orchestrating cdxgen (and
  thus a JS runtime) stands. Python was ruled out either way: its single-binary story
  bundles the interpreter with no clean cross-compile.

## See also

- [ADR-0001](0001-typescript-on-bun.md) (TypeScript on Bun),
  [ADR-0002](0002-orchestrate-standard-generators.md) (orchestrate standard
  generators — why a generator's runtime is unavoidable),
  [ADR-0023](0023-composite-github-action.md) (the one-line GitHub Action over this
  same pipeline).
- Code: `Taskfile.yml`, `mise.toml` (bun + syft), `collectors/cdxgen.ts` (`bun x`
  invocation), `README.md`, `policy.example.toml`.
