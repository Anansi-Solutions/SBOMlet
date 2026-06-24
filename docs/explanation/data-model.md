# Data model

This page is for a contributor. It describes the in-memory model the tool builds:
the types every stage reads and writes, what each field means, and why the model
is shaped the way it is. If you are changing how dependencies are collected,
merged, normalized, or evaluated, this is the vocabulary you work in.

Every module imports its types from `model/dependencies.ts` and not from each
other, so the shape of the data is defined in one place and the stages stay
decoupled. If anything here disagrees with that file, the file is right.

For how these types flow through the stages, see
[architecture](architecture.md) and [data-flow](data-flow.md). For the
rules the design enforces — determinism, [honest residuals](../glossary.md#honest-residual),
deny-is-terminal — see [design-principles](design-principles.md).

## The shape at a glance

The model is built in two stages.

First, per-target collection. Each [target](../glossary.md#target) — a yarn,
npm, pnpm, or bun workspace, a poetry project, the Terraform tree — is scanned
into one [CycloneDX](../glossary.md#cyclonedx) document and wrapped as a
`CollectedSbom`. The committed Docker-OS [SBOM](../glossary.md#sbom) is read
straight from disk and wrapped the same way, as a `scope:os` merge input;
`generate` and `check` never scan a Docker image themselves. The wrapper is the
document plus the side-band metadata the [merge](../glossary.md#merge) needs:
which target it is, its [scope](../glossary.md#scope-app-and-os), the dev/prod
signal, and the per-[purl](../glossary.md#purl)
[provenance](../glossary.md#dependency-provenance).

Second, the purl-keyed merge. `mergeSboms` folds every `CollectedSbom` into one
`CanonicalDependencies`: a sorted list of `PackageEntry`, each carrying its
per-target `Occurrence`s, its raw [license claims](../glossary.md#license-claim),
and, after a policy run, its normalized
[license finding](../glossary.md#license-finding). Evaluating a policy produces
one [`Verdict`](#verdict) per package per occurrence.

```
CollectedSbom[]  ──mergeSboms──▶  CanonicalDependencies { packages: PackageEntry[] }
   (per target)                          │
                                         ├─ normalize + annotateFindings ─▶ PackageEntry.finding
                                         └─ evaluate(policy) ─────────────▶ Verdict[]
                                                                            (EvaluatedDependencies)
```

One choice runs through all of it. The merge key is the purl, kept byte-verbatim
from the SBOM. Anything that can differ between two workspaces that both use the
same package — whether it is dev or prod, what pulled it in, which target it
appears in — is stored per occurrence, not on the package. That lets the same
package be a dev dependency in one workspace and a production dependency in
another without the model having to call one of those facts wrong.

## `CollectedSbom`

One collected CycloneDX document plus the side-band metadata the merge needs. The
collectors produce these; the merge consumes them.

| Field              | Type                                          | Meaning                                                                                                                                                                                          |
| ------------------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sbom`             | `unknown`                                     | The parsed CycloneDX JSON, treated as an untrusted shape. It is narrowed through the arktype boundary before use; a failed narrow skips the document rather than throwing.                       |
| `targetIdentity`   | `string`                                      | Forward-slash repo-relative target identity, such as `"libraries/iframe-rpc"`. Becomes the `Occurrence.target`.                                                                                  |
| `prodPurlSet?`     | `ReadonlySet<string>`                         | The purl set of the `--production` run. When present (Yarn-4 plugin targets), the dual-run diff decides dev: an occurrence is dev when its purl is absent from this set. When absent, the cdxgen property markers decide instead. |
| `firstPartyNames?` | `ReadonlySet<string>`                         | First-party workspace and portal member names from the target's own lockfile. Used to drop first-party members from the inventory, but only paired with a second signal (see below).            |
| `scope?`           | `ScopeTaxonomy`                               | The scope of every component this input contributes. Absent defaults to `"app"`; the Docker-OS input sets `"os"`.                                                                               |
| `introductions?`   | `ReadonlyMap<string, DependencyIntroduction>` | Per-purl dependency provenance for this target, keyed by purl. Present for the npm/yarn and python lanes; absent for sources that carry no dependency graph.                                     |

The wrapper exists because the dev/prod signal, the scope, and the provenance are
per-target facts that the CycloneDX document either does not carry or carries
unreliably. Keeping them next to the document lets the merge attach them when it
creates each occurrence.

### Dropping a first-party member needs two signals

A first-party workspace member must never reach the inventory, and the drop must
be impossible to trigger by accident or by a crafted package. A component is
dropped only when both signals agree: its display name is in the target's own
`firstPartyNames`, and the component carries a second first-party marker, either
the yarn or plugin local-version sentinel `version === "0.0.0-use.local"` or the
cdxgen npm workspace property `cdx:npm:isWorkspace === "true"`. A name collision
on its own, or a crafted marker on its own, cannot drop a third-party package.

## `CanonicalDependencies`

```ts
interface CanonicalDependencies {
  packages: PackageEntry[]; // invariant: sorted by comparePackages
}
```

The in-memory model the whole pipeline shares. Its one invariant is that
`packages` is sorted by [`comparePackages`](#determinism-the-comparators), the
stable total order `(name, version, purl)`. Sorting is part of the determinism
contract. The same inputs have to serialize to byte-identical output so the
[`check` gate](../glossary.md#the-gate-check) can compare byte-for-byte.

A policy run extends the model to `EvaluatedDependencies`, which adds a
`verdicts: Verdict[]` array. The sorted-key JSON serializer handles the extended
shape with no special case.

## `PackageEntry`

One third-party package, deduplicated across every target that uses it.

| Field           | Type                 | Meaning                                                                                                                                                                                              |
| --------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `purl`          | `string`             | The dedup key. Kept verbatim from the SBOM, URL-encoding such as `%40` intact. Never the bom-ref. This is the merge identity.                                                                       |
| `name`          | `string`             | Display name including group, such as `@ampproject/remapping`. Composed at merge time from the CycloneDX `group` and `name`; an empty-string group is treated as absent, so an ungrouped npm package does not become `/abab`. |
| `version`       | `string`             | The package version, verbatim from the component.                                                                                                                                                  |
| `occurrences`   | `Occurrence[]`       | Every consuming target, with per-occurrence scope, sorted by target.                                                                                                                                |
| `licenseClaims` | `LicenseClaim[]`     | Every raw license assertion seen for this package, deduped structurally.                                                                                                                            |
| `scope`         | `ScopeTaxonomy`      | `"app"` or `"os"`. Package-level, not occurrence-level: it routes the package through the app gate or the `[os_dependencies]` lane.                                                                  |
| `rawScope?`     | `string`             | The generator's own scope string, recorded verbatim for audit but never trusted for dev/prod decisions.                                                                                             |
| `finding?`      | `LicenseFinding`     | The normalized license conclusion. Set only by a policy run; absent without `--policy`, so dump-model goldens stay byte-identical.                                                                  |
| `attribution?`  | `PackageAttribution` | Evidence-derived attribution (copyright lines, NOTICE texts, optionally verbatim license texts). Set only when the component carried usable CycloneDX evidence.                                      |

`finding` and `attribution` are optional-and-absent rather than
present-and-empty. That keeps goldens that predate a feature byte-identical,
which the determinism contract depends on.

### `PackageAttribution`

Extracted artifacts only. Raw license texts never enter the model. The exception
is `verbatimTexts`, kept only for packages that carry no SPDX-id or expression
claim, where the license file is the only license statement there is. All stored
text is normalized to LF line endings and stripped of control characters at
intake, so no renderer downstream sees a raw control byte and a CRLF-origin
verbatim text does not gain a trailing space on every line.

| Field             | Type       | Meaning                                                                                                                                                       |
| ----------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `copyrightLines`  | `string[]` | Concrete copyright lines extracted from evidence, deduped, capped at 20, never fabricated.                                                                    |
| `noticeTexts`     | `string[]` | Decoded `NOTICE` file contents, an Apache §4(d) input. Never claims-gated — they reach the rendered notices even for a package that has a parseable claim.    |
| `author?`         | `string`   | `component.author` when it is a string — secondary attribution, never a copyright claim.                                                                      |
| `hasVerbatimText` | `boolean`  | True when at least one non-NOTICE license file was decoded.                                                                                                   |
| `verbatimTexts?`  | `string[]` | Decoded license-file texts. Present only for packages with zero SPDX-id or expression claims.                                                                 |

## `Occurrence`

One consuming target of a package.

```ts
interface Occurrence {
  target: string; // "apps/scratch" — forward-slash, never backslash
  isDevDependency: boolean; // scope of THIS package in THIS target
  introduction?: DependencyIntroduction;
}
```

Scope lives here, on the occurrence, and not on the package. The same package can
legally be a dev dependency in one workspace and a production dependency in
another, and both flags have to be recorded independently. A package-level dev
flag would force one of those two truths to be wrong.

`target` is the `targetIdentity` of the `CollectedSbom` that contributed this
occurrence, always forward-slash.

`isDevDependency` is set when the occurrence is created, from one of two sources.
For plugin targets the dual-run `prodPurlSet` diff decides: an occurrence is dev
when its purl is absent from the production run. Otherwise the cdxgen property
markers decide. The JS marker is `cdx:npm:package:development === "true"` and not
`cdx:npm:package:optional === "true"`. The optional guard matters because cdxgen
marks optional-production dependencies with `development=true` as well, and
without the guard their production license obligations would be understated. The
python marker is `cdx:pyproject:group === "dev"`.

`introduction` is the dependency provenance for this target. It is attached at
occurrence creation and carried through the merge unchanged, since it is
per-target and needs no cross-purl reconciliation. It is absent when the source
carries no usable dependency graph.

## `LicenseClaim`

One raw, un-normalized license assertion, as a [generator](../glossary.md#generator)
or the [enrichment](../glossary.md#enrichment-and-the-enrichment-cache) stage emitted it.

```ts
interface LicenseClaim {
  raw: string; // verbatim asserted value
  kind: LicenseClaimKind; // "spdx-id" | "name" | "expression"
  source: LicenseClaimSource; // "generator" | "corrected" | "curated" | "override" | "registry"
}
```

`raw` is the asserted string exactly as it appeared. No normalization happens at
claim time; that is the [normalizer](../glossary.md#normalization)'s job,
downstream.

`kind` is which of the three CycloneDX license shapes the value came from: an
SPDX expression, an SPDX id, or a free-text name. The three shapes are tried in
that order and the first that narrows wins.

`source` records provenance, for auditability. Collectors emit `"generator"`.
The enrichment stage appends `"registry"` when a PyPI or npm response supplies a
license for an otherwise-unknown package, so a registry-sourced finding can be
traced back. `"corrected"`, `"curated"`, and `"override"` are reserved values on
the type.

A package keeps every distinct claim. Claims are deduped structurally by their
`(kind, source, raw)` triple, NUL-joined so distinct fields can never collide.
Two identical `"MIT"` claims never render as `MIT, MIT`, and because the key
includes `source`, a curated claim is never silently swallowed by a generator
claim that happens to carry the same raw value.

## `LicenseFinding`

The normalized license conclusion for one package: the result of running the
package's claims through the normalizer and the staleness-guarded override chain.
It is the structured input the policy engine consumes. It is set only by a policy
run; without `--policy` the field is absent.

| Field                  | Type                 | Meaning                                                                                                                                                                              |
| ---------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `expression`           | `string \| null`     | Full normalized SPDX expression. `null` means unknown or imprecise — an [imprecise family](../glossary.md#imprecise-family) is not a valid SPDX expression and is never emitted as one. |
| `elected`              | `string \| null`     | The elected branch as a rendered canonical string, such as the permissive branch of an `OR`. `null` when unknown or imprecise.                                                       |
| `source`               | `LicenseClaimSource` | `"generator"` for an exact parse or unknown, or `"corrected"`, `"registry"`, or `"override"` for a clarify or builtin.                                                              |
| `confidence`           | `FindingConfidence`  | `"exact" \| "corrected" \| "none" \| "imprecise"` — see below.                                                                                                                      |
| `impreciseFamily?`     | `string`             | The faithful ambiguous family label (`"BSD"`, `"Apache"`, `"GPL"`). Present only when `confidence` is `"imprecise"`.                                                                |
| `overrideRule?`        | `string`             | The citation for a tool-level builtin override that decided this finding, such as `"override:builtin[3]"`. A project `[[clarify]]` keeps its own `clarify[i]` citation, so this is absent for those. |
| `staleOverride?`       | `StaleOverride`      | Set when an override's `expects` precondition no longer matches the observed signal. The override is not applied, and the engine fails the gate loudly.                              |
| `observedExpression?`  | `string`             | The pre-override observed expression, set when an override rewrote `expression`. The deny terminal reads it so a denied observed license can never be licensed back in.              |
| `observedExpressions?` | `readonly string[]`  | The set of every observed per-claim precise expression, deduped and sorted. The deny terminal also reads this so a denied member is seen even when combination elected an imprecise family or collapsed to unknown. |
| `unrecognizedTokens?`  | `readonly string[]`  | Non-normalizable tokens surfaced for a non-gating `os`-scope partial finding only. Advisory: never enters `expression`, never gates.                                                |

### Why `imprecise` is not `none`

`FindingConfidence` has four values, and the line between the last two carries
the honest-residual principle.

`exact` means the raw value parsed as a valid SPDX expression verbatim.
`corrected` means `spdx-correct` fixed a sloppy-but-precise value, turning
`"Apache License, Version 2.0"` into `Apache-2.0`. `none` means genuinely
unknown: no license could be determined, `expression` is `null`, and
`impreciseFamily` is absent. `imprecise` means an ambiguous family label was
observed, such as `"BSD"`, `"Apache Software License"`, or a bare `"GPL"`, that
carries no clause or version. The tool does not guess it into a precise SPDX id.
`expression` stays `null`, because a bare family is not a valid SPDX expression,
and the faithful family string is carried on `impreciseFamily`.

`imprecise` is its own value, separate from `none`, because an imprecise finding
is a license, an under-specified one that a `[[clarify]]`
[override](../glossary.md#policy-lanes) can disambiguate, whereas `none` is the
absence of any license signal at all. The policy engine routes them differently.
An imprecise family is checked against the `COULD_BE_COPYLEFT_FAMILIES` token set
and surfaced as a warn, so a [copyleft](../glossary.md#copyleft)-looking family is
not silently passed; a `none` finding goes to the unknown-handling lane. Guessing
is forbidden for a concrete reason: `spdx-correct("GPL")` would return
`GPL-3.0-or-later`, a wrong copyleft id. See
[design-principles](design-principles.md).

### Why two `observed*` fields feed deny

`observedExpression` (singular) and `observedExpressions` (plural) both exist so
the deny terminal can see every license a package ever claimed, even after
combination or an override has hidden it.

`observedExpression` carries the single pre-override expression. It is set only
when an override rewrote `expression`, for example a builtin clarify mapping
`BUSL-1.1` to `MIT`. Without it, an override could license a denied observed
license back in.

`observedExpressions` carries the full set of per-claim precise expressions. It
exists because combination can elect an imprecise family, or collapse a claim set
to unknown, when an imprecise or unknown token co-exists with a precise denied
member such as `BUSL-1.1` or `Elastic-2.0` (both
[source-available](../glossary.md#source-available), not copyleft). The combined
`expression` then never shows the denied member, but the deny terminal also walks
this set, so deny fires no matter how combination rendered the finding, in every
scope.

Both fields are only about what deny can see, not about what combination renders,
so deny stays terminal.

### `StaleOverride`

```ts
interface StaleOverride {
  level: "clarify" | "builtin"; // which override carried the precondition
  expected: string; // the value the override expected to still see
  observed: ReadonlyArray<string>; // the now-observed signal members
}
```

An override, a project `[[clarify]]` or a shipped builtin, may carry an `expects`
precondition. When the package's pre-override observed signal no longer matches
`expects`, the asserted expression is not applied, and the engine emits a `fail`
naming the package, the expected value, and the now-observed value. A stale
override must never silently mask a relicense.

## `DependencyIntroduction`

This answers "why is this dependency here?" It is stored on the `Occurrence`, not
the package, because introduction is per-target: the same purl can be a direct
dependency in one workspace and transitive in another.

```ts
interface DependencyIntroduction {
  direct: boolean;
  introducedBy: readonly string[]; // sorted-unique parent purls; empty for direct
  path?: readonly string[]; // one representative root→component purl chain
}
```

`direct` is true exactly when the purl is a declared-direct dependency of this
target's BOM root.

`introducedBy` is the sorted-unique set of direct-parent purls that pull this
package in for this target. It is a union: a package reached through several
parents names every parent that really introduces it. It is empty for a direct
dependency.

`path` is a deterministic representative root-to-component purl chain, one
shortest path. It is omitted for a direct dependency, where the chain would be
the package itself. The tie-break is the smallest child purl at each BFS level,
not a whole-path lexicographic minimum.

### Two lanes populate it; everything else leaves it absent

Only two collect-time lanes can derive provenance, because they are the only
sources that carry a usable graph. The npm lane, via `yarn-plugin-cyclonedx`,
gets a complete root-anchored `dependencies` graph from the BOM. The python lane,
via `poetry.lock` and `pyproject`, gets it from the lockfile
`[package.dependencies]` tables and the declared roots.

Every other source — Terraform, Docker-OS deb and apk, bun, any npm BOM without a
graph — leaves `introduction` absent, and the renderer shows an honest `—`
instead of a fabricated value.

### The root-reachable invariant

This is the safety property of provenance:

> A node's `introducedBy` may name only parents that are themselves reachable
> from a declared root.

Both lanes route through `deriveIntroductions`, which computes the root-reachable
set once and intersects every node's parent set with it. A transitive whose
parents are all root-disconnected ends up with an empty `introducedBy`, a true
orphan, rendered as the honest `—`. A transitive with a mix of reachable and
disconnected parents keeps only the reachable parents. `path` is gated on the
same reachability check, so `introducedBy` and `path` stay consistent.

A root-disconnected, fabricated parent is therefore unrepresentable for both
lanes. One caveat is part of the contract: a multi-parent transitive has several
real introducer chains, so `introducedBy` is the complete set while `path` is one
deterministic representative.

### Optionality is out of scope

There is no `optional` field, on purpose. The npm BOM never carried optional or
peer information. The python lane once derived optionality from poetry markers,
but that marker parsing was a recurring mislabeling bug class and was removed.
Markers and extras are not parsed; every dependency edge is a plain edge.

## `Verdict`

One policy decision per package per occurrence, produced by `evaluate`.

```ts
interface Verdict {
  purl: string;
  occurrenceTarget: string;
  status: "ok" | "warn" | "fail" | "suppressed";
  rule: string; // machine-readable deciding rule id
  reason: string; // human-readable explanation naming the deciding input
}
```

`purl` and `occurrenceTarget` name the package and occurrence the verdict is
about. There is exactly one verdict per occurrence, and `evaluate` sorts them by
`(purl, occurrenceTarget)`.

`status` is `ok` (passes), `warn` (surfaced but non-gating), `fail` (gates the
build), or `suppressed` (a family-justified workspace copyleft suppression).

`rule` is the machine-readable deciding rule id, such as `compatible[1]`,
`clarify[0]`, `denied[2]`, `workspace.copyleft_suppressed[0]`, `default:copyleft`,
`default:unknown`, `default:imprecise`, `default:imprecise-copyleft`,
`default:ok`, `override:builtin[3]`, or `override:stale[clarify|builtin]`. The
renderer and the gate are pure consumers of these structured ids; neither
re-derives policy.

`reason` is a sentence naming the deciding input, such as the matched license,
the workspace path, or the elected expression, so the rendered document carries
its own audit trail.

The statuses map onto the gate's behaviour. A `fail` is a policy violation and
exits 1; see [data-flow](data-flow.md) and the
[README exit-code table](../../README.md). The `[dev_dependencies]` and
`[os_dependencies]` knobs can downgrade a would-be-`fail` to `warn` or `ok` for
dev-only or Docker-OS occurrences, but a production occurrence always fails, and a
`denied[i]` rule is terminal and reaches none of the downgraders.

## Worked example: a `PackageEntry`

A small, realistic entry — `@ampproject/remapping`, an MIT package that appears
as a production dependency of one workspace and a dev-only dependency of another,
after a policy run has attached the finding:

```jsonc
{
  "purl": "pkg:npm/%40ampproject/remapping@2.3.0",
  "name": "@ampproject/remapping",
  "version": "2.3.0",
  "scope": "app",
  "occurrences": [
    {
      "target": "apps/scratch",
      "isDevDependency": false,
      "introduction": {
        "direct": false,
        "introducedBy": ["pkg:npm/%40babel/core@7.26.0"],
        "path": [
          "pkg:npm/%40babel/core@7.26.0",
          "pkg:npm/%40ampproject/remapping@2.3.0",
        ],
      },
    },
    {
      "target": "docs",
      "isDevDependency": true,
      "introduction": { "direct": true, "introducedBy": [] },
    },
  ],
  "licenseClaims": [{ "raw": "MIT", "kind": "spdx-id", "source": "generator" }],
  "finding": {
    "expression": "MIT",
    "elected": "MIT",
    "source": "generator",
    "confidence": "exact",
  },
}
```

There is one package and two occurrences: the purl is the identity, and
`apps/scratch` and `docs` each contribute an `Occurrence`. In `apps/scratch` the
package is a transitive production dependency introduced by `@babel/core`; in
`docs` it is a direct dev dependency, which is why its `introducedBy` is empty and
it has no `path`.

The dev/prod split is per occurrence. `apps/scratch` says production, `docs` says
dev. Both are true, and neither overwrites the other.

The finding is precise. A single `MIT` claim parses verbatim, so `confidence` is
`"exact"`, `source` is `"generator"`, and `expression`, `elected`, and the claim
all read `MIT`. The optional audit fields `observedExpression` and
`observedExpressions` are elided here, because they are populated only when an
override rewrote the expression or when the deny terminal has to see a per-claim
member that a lossy combine hid. A clean single-claim MIT finding sets neither.

The Ecosystem column the renderer shows (`npm`) is derived from the purl type
segment at render time. It is not a stored field.

Evaluating a permissive policy against this entry emits two `ok` verdicts, one
per occurrence, each with `rule: "default:ok"`.

## Purl-keyed merge semantics

`mergeSboms` folds the `CollectedSbom[]` into one model. The internal map is
keyed by purl, byte-verbatim. When two inputs contribute the same purl,
`mergeInto` reconciles them, and the reconciliation is deterministic and
order-independent. It has four parts.

### Occurrence union, with prod-wins dev folding

Occurrences from both sides are unioned by `target`. Distinct targets keep their
flags independently. When the same target appears twice for one purl — a bun
transitive reached through both a prod and a dev parent at the same version, or a
cdxgen document emitting the purl twice with divergent markers — the dev flags
fold prod-wins:

```
present.isDevDependency = present.isDevDependency && occurrence.isDevDependency
```

An occurrence is dev-only only when every contributing component for that target
is dev; a single production contribution forces the whole occurrence to
production. That is the safety-bearing direction, because a shipped occurrence
carries the distribution obligation and must never be masked to dev. A same-target
`introduction` fold is reconciled the same way, so the result does not depend on
input order: `direct` is ORed (and a direct result clears `introducedBy` and
`path`, since a direct dependency has no introducer chain), `introducedBy` is
sorted-unioned, and `path` is taken from the lexicographically-smallest chain.
This same-target case is currently unreachable, because target identities are
unique, but it is kept correct by construction. The final occurrence list is
re-sorted by target.

### Claim concatenation, deduped structurally

Incoming claims are appended to the existing list and deduped by the structural
`(kind, source, raw)` key. First-seen order is preserved. Because the dedup key
includes `source`, a generator claim never swallows a curated or override claim
that shares the same raw value, so provenance survives the merge.

### Scope reconciliation, app wins over os

If the existing entry is `os` and the incoming is `app`, the entry is promoted to
`app`. A purl shared between an app input and an os input must never be silently
demoted out of the gating lane because of merge order, so the gating scope wins.

### First-seen attribution wins

If the existing entry has no attribution and the incoming does, the incoming
attribution is adopted; a stored attribution is never mutated by a later target.
The same purl from two targets carries identical tarball contents, so re-folding
would only duplicate lines.

### What the merge never does

It never throws on malformed input. A document that fails the arktype narrow is
skipped, a component missing the required `purl`/`name`/`version` triple is
skipped, and the scanned root purl is excluded. The result is always a model
sorted by `comparePackages`. The merge is a pure function with no I/O and no
logging; the CLI owns stderr.

## Determinism: the comparators

Three exported helpers carry the determinism contract the `check` gate depends
on.

`compareCodeUnits(a, b)` is the only string comparator in the tool. It orders by
UTF-16 code unit using the `<` and `>` operators, which is platform-invariant.
Locale-aware comparison is ICU-dependent and produces different orderings across
Windows and Linux and across runtimes, silently breaking byte-identity, so it is
forbidden tool-wide.

`comparePackages(a, b)` is the stable total order `(name, version, purl)` that the
`packages` array is sorted by.

`sortedKeyReplacer`, `toSortedJson`, and `toSortedDependenciesJson` are the single
sorted-key JSON serializer: object keys sorted, arrays untouched, indent 2,
trailing newline. `JSON.stringify` never emits `\r`, so the output is LF-only by
construction. The committed enrichment cache reuses this same serializer.

These comparators are why double-generation is byte-identical and why `check` can
regenerate the inventory in memory and compare it byte-for-byte against the
committed outputs. See [design-principles](design-principles.md) for the full
determinism rationale.

Source: `model/dependencies.ts`, `merge/merge.ts`, `normalize/normalize.ts`, `policy/evaluate.ts`, `collectors/provenanceGraph.ts`, `render/markdown.ts`.
