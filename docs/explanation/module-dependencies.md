# Module dependencies

This page is for a contributor, someone changing the tool itself. It describes
how the folders under `src/` depend on one another, the layering that keeps the
graph tractable, and the proposed rules that check it. The companion
[architecture](architecture.md) page covers what each stage does; this one is
only about who imports whom.

## The layers

Read the folders bottom-up. Each layer may import the ones below it, never the
ones above.

- **Foundation — `model`, `validate`, `extract`.** The canonical
  [data model](data-model.md), the validation primitives, and the small text
  extractors. They import nothing else under `src/`, so everything can depend on
  them freely.
- **`normalize` and `policy`.** `normalize` maps raw generator output to
  [SPDX](../glossary.md#spdx); `policy` evaluates the normalized model against
  the [policy lanes](../glossary.md#policy-lanes). Both build on the foundation.
- **Collection — `collectors`, `targets`.** These gather raw package inventory
  from lockfiles, manifests, and images. Collection sits *below* policy and
  render: it cannot depend on how a finding is later judged or printed.
- **`merge` and `enrich`.** Merge folds every collector's output into one
  purl-keyed model; enrich annotates it (license resolution, assessments).
- **`render`.** Turns the already-evaluated model into the output documents. It
  consumes `model`, `policy`, and `normalize` and never reaches back into a
  collector.
- **`pipeline`.** The orchestrator. It wires every layer together and so may
  depend on all of them.
- **`cli`.** The entry point; it drives `pipeline`, the gate, and the
  maintenance commands.

A few cross-cutting helpers — artifact paths and a log-sanitizer — live under
`pipeline/` and are imported from several layers. That is why some folder-level
arrows point back into `pipeline` even though the orchestrator itself sits on
top; at the module level those are calls into leaf utilities, not into the
orchestration code.

## The graph

A directory-level snapshot, own code only, collapsed to one node per top-level
folder. It is generated, not hand-drawn, and goes stale as the code moves —
regenerate it with `task arch:graph`.

```mermaid
flowchart LR

subgraph 0["src"]
1["cli.ts"]
2["collectors"]
3["enrich"]
4["extract"]
5["gate"]
6["maintain"]
7["merge"]
8["model"]
9["normalize"]
A["pipeline"]
B["policy"]
C["render"]
D["targets"]
E["validate"]
end
1-->5
1-->6
1-->A
2-->8
2-->D
2-->E
2-->7
2-->A
3-->8
3-->A
3-->7
3-->9
3-->E
3-->2
5-->A
6-->8
6-->9
6-->B
7-->4
7-->8
7-->9
7-->E
9-->8
9-->B
A-->2
A-->3
A-->7
A-->8
A-->9
A-->B
A-->C
A-->D
A-->E
A-->6
B-->8
B-->9
B-->E
C-->8
C-->B
C-->9
D-->8
D-->A
D-->E
```

## The rules

The rules live in `.dependency-cruiser.cjs` at the repository root. Run them by
hand with `task arch:check`. Most are enforced at error, including
`no-circular` now that the graph is acyclic; a couple of advisory checks stay
at warn. Wiring the task into `check` is the remaining step to make them part
of the blocking gate.

- **no-circular** (error) — no dependency cycles between modules.
- **no-orphans** (warn) — no modules imported by nothing (the CLI entry point
  and declaration files are exempt).
- **not-to-test** (error) — production code under `src/` must never import from
  `test/`.
- **not-to-unresolvable** (error) — no dangling or misspelled import paths.
- **no-deprecated-core** (error) — no dependence on deprecated Node core
  modules.
- **foundation-is-dependency-free** (error) — `model` and `validate` must not
  import any other own-code layer.
- **collectors-below-policy-and-render** (error) — `collectors` must not import
  `policy` or `render`.
- **render-consumes-not-collects** (error) — `render` must not import
  `collectors`, `enrich`, `merge`, or `targets`.

## Cycles

The module graph is fully acyclic, so `no-circular` is enforced at error.

Getting there meant untangling one genuine runtime cycle and several type-only
ones. The runtime cycle used to couple `policy` and `normalize` into a single
unit: `statedLicense` and `EVERYWHERE_SCOPE` were the value imports that closed
the loop through the schema and the package matcher. Both now live in leaf
modules — `EVERYWHERE_SCOPE` in `policy/schema/scope`, `statedLicense` in
`policy/statedLicense` — that either side imports without importing the other.

The rest were type-only: dependency-cruiser counts an `import type` as an edge
even though TypeScript erases it at compile time, so none was a runtime cycle,
but each is resolved now too. They sat in three spots — the `deny`/`schema`
type graph, `compat/classify` ⇄ `compat/profile`, and `pipeline` ⇄
`pipeline/targets` — each broken by lifting the shared types into a leaf module
both sides import one-way: `policy/schema/deny`, `policy/compat/classification`,
and `pipeline/options`.

## Running the checks

```sh
task arch:check   # validate src/ against the rules above
task arch:graph   # print the directory graph as Mermaid text
```

Both invoke dependency-cruiser through `bunx` at a pinned version. It is kept
out of `package.json` on purpose: adding it as a dependency would pull its
transitive tree into the tool's own license inventory. It borrows the
`typescript` already installed for typechecking, found through `NODE_PATH`.
