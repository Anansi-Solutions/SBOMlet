# ADR-0016: Adoption and distribution — git clone + Taskfile, no compiled binary, a composite Action

- **Status:** Accepted
- **Date:** 2026-06-13; binary declined and GitHub Action added 2026-06-24
  (consolidates the earlier compiled-binary and GitHub-Action records)

## Context and problem

The tool has to be adoptable by any repository, not just the one it was built
in: a project picks it up without a coupling to it, and a contributor can
read and change it in place. Three questions sit under that: the distribution
channel (publish to a registry, or copy the source?), the form it runs in (a
`.ts` tree run by a pinned Bun, or a compiled single-file binary?), and how a
consumer wires it into CI without hand-assembling the toolchain.

The binary question stayed open because Bun can compile one — a real option
we built and measured before deciding.

## Decision drivers

- **Independence from the consuming project.** Adoption must not tie the
  consumer to a release we cut or a registry account.
- **No build step, minimal footprint.** The runtime runs `.ts` directly; a
  packaging layer needing a compile-and-publish cycle, or a CLI framework, is
  a poor trade.
- **No redundant machinery.** Duplicating what mise already provides is
  weight without benefit.
- **The generators are not ours.** cdxgen (JS) and syft (Go) do the SBOM
  generation; the ~15 kLOC we own is orchestration.
- **CI-vendor neutrality.** The same commands run in any CI and locally,
  through mise and Taskfile.

## Considered options

1. **Copied directory + Taskfile include + policy file** — the consumer
   vendors the source, adds a Taskfile `includes:` entry, writes one
   `.sbomlet.policy.toml`.
2. **Publish to npm (or a mise plugin registry)** — consumers install a
   versioned package.
3. **Ship a compiled per-platform binary** (`bun build --compile`) + a
   release pipeline, cdxgen pinned as a mise binary so the tool is
   runtime-free.
4. **Adopt a CLI framework** (bunli) wrapping the same compile step.
5. **Rewrite the orchestrator in Go/Rust** for a genuinely small
   self-contained binary.

For the GitHub CI front door, over option 1: document manual mise + Task
wiring, a composite action, or a Docker-container action.

## Decision

**Adoption is git clone + a Taskfile include.** A consumer vendors the tool's
directory, adds one Taskfile include, and copies `policy.example.toml` to
`.sbomlet.policy.toml`. No `npm publish`, no registry, no install step beyond
mise and Task, which the consumer already needs. The include points Task at
the tool's Taskfile and pins its working directory so the pinned Bun resolves
from the tool's `mise.toml`; from there `task generate` and `task check` are
the whole interface. A copied directory belongs to the consumer — they read,
pin, and patch it, and never wait on a release of ours. Publishing to a
registry would invert that, coupling every consumer to a version we cut.

**The compiled binary is declined, not deferred.** We built it — a
`bun build --compile` binary per platform with a tag-triggered release
workflow, and cdxgen switched from `bun x` to a mise-pinned standalone
binary — and two findings settled it:

- The binary is ~100 MB because `bun build --compile` embeds the entire Bun
  runtime; our code is a few hundred KB. The embedded runtime is redundant:
  cdxgen is a JS tool, so a JS runtime is already in the toolchain.
- mise's github backend cannot pin cdxgen's standalone binary: cdxgen's
  release ships ~24 assets across platforms, and mise resolves the sibling
  `aibom` tool instead, ignoring `matching`/`bin`.

So distribution stays git + a Taskfile include + a single mise-pinned **bun**
that both runs the tool from source and runs `bun x @cyclonedx/cdxgen` with
the version pinned in the argv; syft stays an aqua-pinned binary on the
maintainer-only Docker path. `bunli` was rejected — it wraps the same compile
and adds a validation library and a pre-1.0 single-publisher profile. A
Go/Rust rewrite is the only path to a genuinely small binary, but it does not
remove the JS runtime (cdxgen is still shelled out to), so it is gated on a
coverage measurement, not adopted now.

**A composite GitHub Action gives one-line CI adoption.** A composite
`action.yml` at the repo root is three steps — `jdx/mise-action` for the
toolchain, `bun install`, and `task <mode>` against the consumer's checkout; a
consumer adds `uses: Anansi-Solutions/SBOMlet@<ref>` with a `policy` and
optional `mode` input. It drives the same Taskfile a local run does, so there
is no second code path to keep in sync, and inputs flow through the
environment, never template interpolation, so a crafted input cannot reach
shell parsing. A Docker-container action was rejected as the same
redundant-runtime trap as the binary. A dogfood workflow runs the action
against this repository on every push.

## Consequences

- **Good:** a consumer owns its copy with no upstream coupling and no
  registry account. The clone path needs no build; the runtime footprint is
  the visible source tree plus a single mise-pinned bun. Adoption is one
  `uses:` step on GitHub Actions and a one-line Taskfile step everywhere else.
  No 100 MB artifact, no release pipeline, no cdxgen-asset breakage.
- **Bad / cost:** a copied directory does not update itself — a consumer who
  wants a later version re-copies it. The action is GitHub-specific.
- **Neutral — the path to a binary:** revisiting is gated on one measurement,
  whether syft or trivy (both Go, both embeddable) give acceptable
  app-dependency licence coverage versus cdxgen (ADR-0002 chose cdxgen for
  better fill). If they do, a Go rewrite embedding syft yields a true single
  binary with no JS runtime, at the cost of the port and re-validating
  coverage and determinism. Python was ruled out either way: its
  single-binary story bundles the interpreter with no clean cross-compile.

## See also

- Related: [ADR-0001](0001-typescript-on-bun.md) (the from-source runtime),
  [ADR-0002](0002-orchestrate-standard-generators.md) (why a JS runtime for
  cdxgen is unavoidable)
- Code: `action.yml`, `Taskfile.yml`, `mise.toml` (bun + syft),
  `collectors/cdxgen.ts` (`bun x`), `.github/workflows/action-test.yml` (the
  dogfood gate), `README.md`, `policy.example.toml`
