# Architecture decision records

An ADR captures one architectural decision: the problem that forced it, the
options we weighed, what we chose, and what that choice costs us. Together they
answer "why is the tool built this way?" — they are the canonical place for that
question. The `Key Decisions` table in `.planning/PROJECT.md` indexes into them,
and the phase summaries under `.planning/phases/` hold the detailed execution
history.

We use the [MADR](https://adr.github.io/madr/) format. Records are immutable once
accepted: to change a decision, write a new ADR and mark the old one
`Superseded by ADR-NNNN` rather than editing it.

## Adding a record

```sh
task adr:new TITLE="Keep the cache offline"
```

This copies [`0000-template.md`](0000-template.md) to the next number with the
title filled in. Write it, set the status to `Accepted` when it lands, and add a
row below.

## Status lifecycle

`Proposed` → `Accepted` → `Superseded by ADR-NNNN`. A `Deprecated` record
describes something we no longer do but haven't replaced.

## Index

The records below back-fill the decisions already made, distilled from the phase
summaries and research notes.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-typescript-on-bun.md) | TypeScript on Bun as the implementation stack | Accepted |
| [0002](0002-orchestrate-standard-generators.md) | Orchestrate standard SBOM generators; do not build a licence-detection engine | Accepted |
| [0003](0003-cyclonedx-purl-merge.md) | CycloneDX as the interchange format, purl as the merge key | Accepted |
| [0004](0004-deterministic-output.md) | Deterministic, timestamp-free output as the foundation of the gate | Accepted |
| [0005](0005-per-occurrence-model.md) | A per-occurrence canonical model (target + dev/prod scope) | Accepted |
| [0006](0006-policy-emits-verdicts.md) | Policy emits structured verdicts; renderer and gate are pure consumers | Accepted |
| [0007](0007-deny-terminal-observed-claims.md) | Deny is terminal at precedence 0, evaluated over every observed claim | Accepted |
| [0008](0008-honest-residual.md) | Honest residual: ambiguous licences are surfaced, never guessed | Accepted |
| [0009](0009-offline-check-committed-cache.md) | Offline `check` via a committed enrichment cache | Accepted |
| [0010](0010-dev-prod-os-scopes.md) | dev / prod and OS dependency scopes; a production occurrence always gates | Accepted |
| [0011](0011-js-generator-routing.md) | JS generator routing: yarn-plugin for Yarn 4, cdxgen otherwise, custom `bun.lock` parser | Accepted |
| [0012](0012-python-cdxgen-poetry.md) | Python via cdxgen, with prod/dev recovered from `poetry.lock` | Accepted |
| [0013](0013-terraform-filesystem-signal-gate.md) | The Terraform gate keys on the `.terraform/` filesystem signal, not HCL parsing | Accepted |
| [0014](0014-docker-syft-consumer.md) | Docker OS packages via syft, consumed as a committed digest-pinned SBOM | Accepted |
| [0015](0015-source-available-deny-list.md) | Source-available licences: a terminal deny lane, shipped defaults, and an opt-out | Accepted |
| [0016](0016-provenance-root-reachable.md) | Dependency provenance: root-reachable introducers, honest residual otherwise | Accepted |
| [0017](0017-dockerfile-base-abstain.md) | Dockerfile base derivation abstains on ambiguity | Accepted |
| [0019](0019-adoption-git-clone-taskfile.md) | Adoption by git clone + Taskfile include; a compiled binary declined | Accepted |
| [0023](0023-composite-github-action.md) | A composite GitHub Action for one-line CI adoption | Accepted |
| [0024](0024-cache-directory-layout.md) | Committed artifacts in one configurable cache directory; policy renamed .sbomlet.policy.toml | Accepted |
