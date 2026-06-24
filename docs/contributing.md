# Contributing

This page is for contributors, people changing the tool itself rather than
adopting it. It covers what you need installed, how the source is laid out, how
to run the tests and the quality gates, how to add a new
[collector](./glossary.md#collector), and how to start an architecture decision
record.

If you only want to run the tool against a repository, read the top-level
[`README.md`](../README.md) and the [getting-started tutorial](./getting-started.md)
instead. For the reasoning behind the design, see the explanation docs under
[`docs/explanation/`](./explanation/) and the [ADRs](./explanation/adr/).

Every command below runs from ``.

## Prerequisites

The tool needs few host tools, because a tool that audits dependencies should
not add a build chain of its own. There is no Node build step, no transpile, no
`dist/`. The CLI runs from TypeScript source via `bun src/cli.ts`. TypeScript,
ESLint, and Prettier are dev dependencies you install below, not host tools.

| Tool | Version | Pinned in | Needed for |
| ---- | ------- | --------- | ---------- |
| [mise](https://mise.jdx.dev) | any recent | — | resolving the pinned `bun` |
| [bun](https://bun.sh) | `1.3.14` | `mise.toml` | the runtime and the test runner |
| [Task](https://taskfile.dev) | v3 | the consumer repo | running `task generate`, `task check` |
| [syft](https://github.com/anchore/syft) | `1.45.1` | `mise.toml` | `generate-docker-sbom` only |

`mise.toml` in this directory pins exactly two versions: `bun = "1.3.14"` and
`aqua:anchore/syft = "1.45.1"`. syft is needed only on the
`generate-docker-sbom` path, which is maintainer-only; `generate`, `check`, the
tests, and the quality gates never touch it. The syft pin must stay equal to the
version the Docker OS collector reads, and the comment in `mise.toml` records
that invariant.

Source: `collectors/dockerOs.ts` (`SYFT_TOOL.version`), `mise.toml`.

## Install

```sh
mise x -- bun install
```

This reads the committed `bun.lock` and `package.json` under the pinned bun. The
runtime dependencies stay few on purpose: `arktype` (input-boundary validation),
`smol-toml` (policy parsing), and the SPDX toolkit (`spdx-correct`,
`spdx-expression-parse`, `spdx-satisfies`, `spdx-license-list`). The standard
SBOM [generators](./glossary.md#generator) (cdxgen, the Yarn CycloneDX plugin,
syft, tofu) are orchestrated rather than vendored, so they are not npm
dependencies; the collectors fetch them on demand.

## The `src/` layout

The data flows in one direction (discover, collect, merge, enrich, normalize,
evaluate policy, render), and the directories mirror those stages. The canonical
data model is the hub. Every module imports its types from there, never from
each other. For the stage-by-stage walk see
[`docs/explanation/data-flow.md`](./explanation/data-flow.md).

Source: `model/dependencies.ts`.

| Directory | What lives there |
| --------- | ---------------- |
| `src/cli.ts` | The entry point — the only module that owns process exit codes and parses argv. |
| `src/model/` | The canonical data model, the `compareCodeUnits` comparator, and the sorted-key/LF JSON serializers. |
| `src/targets/` | [Target](./glossary.md#target) discovery: walking `--repo-root` for the lockfile kinds, resolving a single target, deriving workspace-member names. |
| `src/collectors/` | The [collector](./glossary.md#collector) registry and one collector per source, plus generator selection and the npm/poetry provenance derivers. |
| `src/merge/` | The [purl](./glossary.md#purl)-keyed [merge](./glossary.md#merge) of every collected document into one model. |
| `src/enrich/` | The [enrichment](./glossary.md#enrichment-and-the-enrichment-cache) stage: filling unknown licences from PyPI/npm and persisting them to the committed cache. |
| `src/normalize/` | [License-claim](./glossary.md#license-claim) → SPDX [normalization](./glossary.md#normalization) and SPDX expression parsing. |
| `src/extract/` | Copyright-line extraction for the notices document. |
| `src/policy/` | The policy engine: TOML parse and validation, [verdict](./glossary.md#verdict) evaluation, the deny list, copyleft families, shipped overrides. |
| `src/render/` | The three pure renderers — `THIRD_PARTY_LICENSES.md`, `THIRD_PARTY_NOTICES.md`, and the [CycloneDX](./glossary.md#cyclonedx) export. |
| `src/pipeline/` | The write-free orchestration core that runs the stages in order. |
| `src/gate/` | The [check](./glossary.md#the-gate-check) gate: re-run the pipeline, byte-compare against committed files, map to exit codes. |
| `src/validate/` | arktype input boundaries for untrusted inputs (consumed SBOMs, the policy file, lockfiles, registry responses). |

## Running the tests

Tests run on Bun's built-in runner. Everything lives under `test/`, one
`*.test.ts` file per unit of behaviour, with no co-located specs.

```sh
mise x -- bun test                              # the whole suite
mise x -- bun test test/merge.test.ts           # one file
mise x -- bun test --test-name-pattern merge    # by test-name substring
```

Two support directories sit alongside the test files. `test/golden/` holds
committed contract bytes the renderers must reproduce exactly; a change that
alters them is a deliberate decision, reviewed as a diff. `test/fixtures/` holds
the input SBOM and lockfile fixtures the unit tests feed through the pipeline.
Both are bytes, not code, so ESLint and Prettier are configured to never touch
them.

Most tests are pure and offline, so the default run is fast and hermetic. The
live end-to-end tests in `test/e2e.test.ts` are gated behind an environment
variable, because they spawn the real pinned generators (a cold Yarn-plugin run
on a large target can take over a minute, and the first fetch needs the network):

```sh
RUN_E2E=1 mise x -- bun test test/e2e.test.ts
```

Without `RUN_E2E=1` those tests are skipped.

## Quality gates

Three checks gate every change: lint, format, and typecheck. Run them together:

```sh
task quality
```

That runs the three under the pinned bun:

```sh
mise x -- bun run lint          # eslint .
mise x -- bun run format:check  # prettier --check
mise x -- bun run typecheck     # tsc --noEmit
```

To fix formatting instead of only checking it, run `mise x -- bun run format`.

The gates enforce TypeScript strict mode with no emit; the recommended ESLint and
typescript-eslint rule sets plus project rules (an explicit return type and no
`any` are errors, and `max-depth` and `complexity` caps favour small,
guard-claused functions); and Prettier with double quotes and trailing commas.
`eslint-config-prettier` runs last, so formatting is owned by Prettier alone.
Goldens and fixtures are excluded from both.

Run `bun test` and `task quality` before you commit.

## Adding a new collector

A [collector](./glossary.md#collector) turns one discovered
[target](./glossary.md#target) into a merge-ready
[CycloneDX](./glossary.md#cyclonedx) document. The registry is the single
extension point. Adding a target kind is one registration, not a new dispatch
branch.

### The interface

Every collector implements two methods. `tool` returns the identity printed in
the collect loop's `collecting <id> via <name>@<version>` stderr line. `collect`
turns one target into the merge-ready input and throws on a scan failure. The CLI
maps that throw to its tool-error exit code, so a collector that cannot scan
should throw rather than emit an empty or partial document.

```ts
export interface Collector {
  tool(lockfileText: string): ToolIdentity;
  collect(
    target: DiscoveredTarget,
    ctx: CollectContext,
  ): Promise<CollectedSbom>;
}
```

The `lockfileText` argument to `tool` lets a collector pick its identity from the
file's contents. Only the Yarn collector uses it: it returns the plugin's
identity for a Yarn 4+ lockfile and cdxgen's otherwise. Every other kind ignores
the argument.

The `ctx` a collector receives carries the lockfile text (read once by the
collect loop), a per-scan timeout, a `verbose` flag, and a `log` sink.
Collectors never write to stderr themselves; the loop owns that one line, so the
stderr shape is emitted from one place. A collector that needs to surface a line
sends it through `ctx.log`.

`collect` returns a `CollectedSbom`: the SBOM plus the target identity, and
optional `prodPurlSet`, `firstPartyNames`, `introductions`, and `scope` fields
that downstream stages pair with the components by [purl](./glossary.md#purl).

### Two shapes to copy from

Start with the default shape and use the second only when you have to.

The default shape orchestrates a standard generator. A factory runs cdxgen for
an ecosystem and reads the SBOM it emits; npm, pnpm, uv, and the inventory half
of poetry are all built this way.

The second shape is a custom in-process parser. Use it only when no upstream tool
reads the format correctly. The two precedents are the Bun-lockfile and Terraform
collectors, each with a header that documents why no generator suffices: cdxgen
and syft emit zero components from `bun.lock`, and no tool resolves Terraform
module versions. A custom parser stays pure, does no `cwd` change, and bounds its
input size before any read.

The Bun-lockfile collector is the cleanest worked example of the custom shape. It
exports the two things a custom collector module owns, a `*_TOOL` `ToolIdentity`
and a `collectWith*` function, and its `collect` does the four things a
parser-shaped collector should do: gate the file size before any read, parse
tolerantly (a malformed individual entry is skipped, but a whole-file parse
failure throws), exclude first-party workspace members, and emit a minimal
deterministic CycloneDX 1.6 document with no `serialNumber` and no timestamp. The
collector entry in the registry then calls the `collectWith*` function and wraps
the result.

Source: `collectors/bunLock.ts`, `collectors/registry.ts`, `collectors/terraform.ts`.

### Steps

1. Add the new lockfile filename and its `LockfileKind` to the target-discovery
   module (the `LOCKFILES` map and the `LockfileKind` union), and add a
   `manifestFilesFor` case to the dispatch module, plus an `ecosystemFor` case if
   it routes through cdxgen.
2. Implement the collector, either via the cdxgen factory or as a custom module
   that mirrors the Bun-lockfile collector.
3. Register it in the `collectors` map at the bottom of the registry module. That
   map is exhaustive over `LockfileKind` and locked by a registry test, so a
   missing registration fails the suite.
4. Add a unit test (`test/<kind>.test.ts`) and a fixture under `test/fixtures/`.
   If the collector changes rendered output, regenerate and review the affected
   `test/golden/` bytes.

The collect loop does the rest. It reads the lockfile once, enforces the coverage
policy, resolves the collector for the target's kind, prints the loop-owned
stderr line, awaits `collect`, and folds the result into the merge.

Source: `collectors/registry.ts`, `collectors/dispatch.ts`, `targets/discover.ts`,
`pipeline/targets.ts`, `test/registry.test.ts`.

## Adding an ADR

An [architecture decision record](./explanation/adr/) captures one decision: the
problem that forced it, the options weighed, what was chosen, and what it costs.
Records are immutable once accepted. To change a decision, write a new one and
mark the old `Superseded by ADR-NNNN` rather than editing it.

Scaffold one from the MADR template:

```sh
task adr:new TITLE="Keep the cache offline"
```

This copies `docs/explanation/adr/0000-template.md` to the next number with the
title and date filled in. Write the body, set the status to `Accepted` when it
lands, and add a row to the index in
[`docs/explanation/adr/README.md`](./explanation/adr/README.md).
