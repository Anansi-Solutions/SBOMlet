# Architecture decision records

An ADR captures one architectural decision: the problem that forced it, the options
weighed, what we chose, and what it costs. Together they answer "why is the tool
built this way?"

We use the [MADR](https://adr.github.io/madr/) format. Records are immutable once
accepted: to change a decision, write a new ADR and mark the old one `Superseded by
ADR-NNNN` rather than editing it. A few records here consolidate earlier ones from a
pre-release renumbering; each notes what it consolidates.

## Adding a record

```sh
task adr:new TITLE="Keep the cache offline"
```

This copies [`0000-template.md`](0000-template.md) to the next number with the title
filled in. Write it, set the status to `Accepted` when it lands, and add a row below.

## Status lifecycle

`Proposed` → `Accepted` → `Superseded by ADR-NNNN`. A `Deprecated` record describes
something we no longer do but haven't replaced.

## Index

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-typescript-on-bun.md) | TypeScript on Bun as the implementation stack | Accepted |
| [0002](0002-orchestrate-standard-generators.md) | Orchestrate standard SBOM generators; no in-house detection engine | Accepted |
| [0003](0003-cyclonedx-purl-merge.md) | CycloneDX interchange, purl as the merge key | Accepted |
| [0004](0004-deterministic-output.md) | Deterministic, timestamp-free output underpins the gate | Accepted |
| [0005](0005-per-occurrence-model.md) | A per-occurrence canonical model | Accepted |
| [0006](0006-policy-emits-verdicts.md) | Policy emits verdicts; renderer and gate consume them | Accepted |
| [0007](0007-honest-residual.md) | Honest residual: surface ambiguity, never guess | Accepted |
| [0008](0008-offline-check-committed-cache.md) | Offline `check` via a committed enrichment cache | Accepted |
| [0009](0009-dev-prod-os-scopes.md) | dev/prod and OS scopes; a production occurrence always gates | Accepted |
| [0010](0010-js-generator-routing.md) | JS generator routing: yarn-plugin, cdxgen, custom bun.lock parser | Accepted |
| [0011](0011-python-cdxgen-poetry.md) | Python via cdxgen, prod/dev recovered from poetry.lock | Accepted |
| [0012](0012-docker-os-via-syft.md) | Docker OS packages via syft, a committed digest-pinned SBOM | Superseded by ADR-0018 |
| [0013](0013-source-available-deny.md) | Source-available licences are a terminal deny lane | Accepted |
| [0014](0014-dependency-provenance.md) | Dependency provenance: root-reachable introducers, honest residual | Accepted |
| [0015](0015-abstain-over-fragile-parsing.md) | Abstain rather than parse a fragile grammar (Terraform, Dockerfile) | Accepted |
| [0016](0016-adoption-and-distribution.md) | Adoption and distribution: git clone + Taskfile, no binary, a composite Action | Accepted |
| [0017](0017-cache-directory-layout.md) | Committed artifacts in one configurable cache directory | Accepted |
| [0018](0018-docker-generated-image-scan.md) | One Docker scan model — build the image and scan its full contents | Accepted |
| [0019](0019-scancode-senior-assessment.md) | ScanCode as the senior licence assessment: outranks the registry, conflicts fail the gate, its own memo | Accepted |
| [0020](0020-yarn-workspace-scan-units.md) | Yarn workspace scan units from lockfile resolutions | Accepted |
| [0021](0021-per-image-occurrence-identity.md) | Per-image occurrence identities — `docker:os-packages/<source>` | Accepted |
| [0022](0022-dotnet-lockfile-in-process.md) | Parse packages.lock.json in-process for .NET | Accepted |
