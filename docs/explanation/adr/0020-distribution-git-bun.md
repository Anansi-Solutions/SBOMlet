# ADR-0020: Distribution as git clone + Taskfile + mise-pinned bun; a compiled binary declined

- **Status:** Accepted
- **Date:** 2026-06-24

## Context and problem

[ADR-0019](0019-adoption-git-clone-taskfile.md) chose git clone + a Taskfile
include as the v1 adoption path and deferred the single-binary question. With
the tool in use, two adoption frictions made it worth revisiting: a consumer has
to vendor the tool's source and wire mise + Task themselves, and CI integration
is a few hand-written steps rather than one. The hoped-for fix was the usual
one — ship a self-contained per-platform binary and a GitHub Action, so adopting
the tool is "add one line" rather than "clone and wire."

So we built it: a `bun build --compile` binary per platform with a tag-triggered
release workflow, and a switch of cdxgen from `bun x` to a mise-pinned standalone
binary so the compiled tool would not need bun at all. Both ran into the same
wall — the tool is an ORCHESTRATOR, and the thing it orchestrates anchors a
runtime no matter what we do.

## Decision drivers

- **Adoption should be easy**, ideally a single CI step, without making the
  consumer manage a toolchain by hand.
- **No redundant machinery.** A distribution mechanism that duplicates something
  mise already provides is weight without benefit.
- **The generators are not ours.** cdxgen (JS/npm) and syft (Go) do the SBOM
  generation; the ~15 kLOC we own is orchestration. Any distribution has to
  account for what those generators need at runtime.
- **Correctness and minimal dependencies** — the standing constraints. A
  distribution change must not silently swap a generator or pull in weight.

## Considered options

1. **Per-platform compiled binary** (`bun build --compile`) + a release
   pipeline, with cdxgen also pinned as a mise binary so the tool is runtime-free.
2. **Stay git + Taskfile + mise-pinned bun**, cdxgen via `bun x`, syft via aqua.
3. **Rewrite the orchestrator in a compile-to-native language (Go/Rust)** for a
   genuinely small self-contained binary.

## Decision

We stay on option 2 — git clone + a Taskfile include, with a single mise-pinned
**bun** that both runs the tool from source and runs `bun x @cyclonedx/cdxgen`;
syft stays an aqua-pinned binary on the maintainer-only Docker path. The
compiled binary is declined, not deferred.

Two findings settled it. First, **the compiled binary is ~100 MB because
`bun build --compile` embeds the entire Bun runtime** — our code is a few hundred
KB. That embedded runtime is redundant: cdxgen is a JS tool, so a JS runtime is
already in the toolchain, and a binary that bundles a second copy of one buys
nothing mise does not already provide. Second, **mise's github backend cannot
pin cdxgen's standalone binary.** cdxgen's release ships ~24 assets (cdxgen,
cdxgen-slim, aibom, cdx-verify, … across platforms), and mise resolves the
sibling `aibom` tool, ignoring `matching`, `matching_regex`, and `bin` — verified
in both `mise install` and the generated lockfile. The runtime "validation" that
appeared to pass was aibom, which shares cdxgen's codebase and so answers
`-t js` plausibly. cdxgen is fundamentally an npm tool and is most reliably run
via `bun x` with the version pinned in the argv.

Comparing on the drivers:

- **The compiled binary** fails the no-redundant-machinery driver: it ships a
  second runtime beside the one cdxgen forces, and it dragged in a 5-platform
  build, a release workflow, and the unsolved cdxgen-pinning problem. Rejected.
- **git + bun** is what the project already had. It adds nothing to carry: one
  mise-pinned bun is the build tool, the from-source runtime, and the launcher
  for `bun x` cdxgen. It keeps cdxgen the real tool, version-pinned in the argv,
  and is already dogfooded green. Chosen.
- **A native rewrite** is the only path to a genuinely small self-contained
  binary, but it is a multi-week port and — more importantly — it does not by
  itself remove the JS runtime, because cdxgen would still be shelled out to.
  Removing the runtime means replacing cdxgen with an embeddable native generator
  (syft or trivy as a Go library), which is a license-COVERAGE decision
  ([ADR-0002](0002-orchestrate-standard-generators.md) chose cdxgen for better
  app-dependency licence fill). Deferred behind a measurement, below.

## Consequences

- **Good:** zero rewrite and zero new runtime. Distribution is the project's
  existing, dogfooded model — clone the tool, include its Taskfile, let mise pin
  bun. No 100 MB artifact, no release pipeline, no per-platform build matrix, and
  none of the cdxgen-asset-selection breakage. cdxgen stays the actual tool,
  pinned in the argv.
- **Bad / cost:** adoption is still "vendor the source + a Taskfile include +
  mise," not a one-line binary install. A consumer needs mise and bun on the
  runner (both mise-pinned, so it is one `mise install`). The "for now" is
  literal: if a self-contained binary becomes a priority, this is revisited.
- **Neutral — the path if that priority arrives:** the decision to revisit is
  gated on one measurement, not on a language preference. The question is whether
  syft or trivy — both Go, both embeddable as a library in a single static
  binary — give acceptable app-dependency LICENCE coverage versus cdxgen. If they
  do, a Go rewrite embedding syft yields a true single binary with no JS runtime
  and trivial cross-compilation, at the cost of the port and re-validating the
  coverage and determinism guarantees. If they do not, orchestrating cdxgen (and
  thus a JS runtime) stands, and a language port would only shrink the
  orchestrator — a modest win not worth the weeks. Python was ruled out either
  way: its single-binary story bundles the interpreter and has no clean
  cross-compile, worsening the problem this set out to solve.

## See also

- Supersedes the deferral in
  [ADR-0019](0019-adoption-git-clone-taskfile.md) (single binary "viable but
  deferred") with a decision: declined for now, on the evidence above.
- [ADR-0002](0002-orchestrate-standard-generators.md) — the orchestrate-don't-
  reinvent stance that makes a generator's runtime unavoidable.
- Code: `collectors/cdxgen.ts` (`bun x` invocation), `mise.toml` (bun + syft),
  `Taskfile.yml` (the consumer entry points).
