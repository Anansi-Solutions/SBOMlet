# Dependency classification

This page is for the classification engine — `src/merge/merge.ts`,
`src/pipeline/containerScope.ts`, `src/policy/evaluate.ts` — and anyone
changing it. It is the normative [scope](../glossary.md#scope-app-and-os) and
[verdict](../glossary.md#verdict) decision tree: for any
[package entry](../glossary.md#package-entry), what kind of package it is and
what policy decides about it. The engine and its tests follow this page; a
behavior change to any of them updates this page in the same commit. Each
path in the Path index below is verified one-to-one by
`test/reportPlacement.test.ts`, alongside its markdown-placement counterpart
in [report-placement.md](./report-placement.md).

Classification never decides which document, or which section of one, a
package appears in — that is placement, an output-format concern layered on
top. This page covers only scope and verdict; the markdown report's
placement rules built on this classification live in
[report-placement.md](./report-placement.md), and a future output format
would define its own placement page against this same classification tree.

Classification is two questions, asked in order: what kind of package is this
([scope](../glossary.md#scope-app-and-os)), and what does policy say about it
(a [verdict](../glossary.md#verdict)). This page answers each in turn, then
closes with the invariants that must hold regardless.

## Stage 1 — classification

Every package gets a scope, `app` or `os`. Every docker occurrence
independently gets a development marker. Two questions decide scope; a third,
unrelated one decides the marker.

- **Does the package have a workspace (non-`docker:`) occurrence?**
  - Yes → scope `app`. If the same [purl](../glossary.md#purl) is *also* found
    baked into an image, the merge promotes that docker occurrence to `app`
    too, even though the docker collector stamps every docker input `os` at
    intake — app always wins over os on a shared purl.
  - No (every occurrence is a docker occurrence) → the purl's ecosystem
    decides:
    - Ecosystem on the OS allowlist (`deb`, `apk`, `rpm`, `alpm`) → scope
      `os`, a system package.
    - Any other ecosystem, recognized or not → scope `app`, an application
      dependency an application layer installed into the image. An
      unrecognized ecosystem lands here too: the allowlist fails safe.

```mermaid
flowchart TD
    A["Package has a workspace<br/>(non-docker:) occurrence?"] -->|yes| B["scope: app<br/>(a shared docker occurrence is promoted too)"]
    A -->|no, container-only| C{"purl ecosystem on the<br/>OS allowlist (deb/apk/rpm/alpm)?"}
    C -->|yes| D["scope: os<br/>(system package)"]
    C -->|no| E["scope: app<br/>(application dependency in the image)"]
```

- **Is a docker occurrence's container marked `[[docker.development]]`?** This
  sets that occurrence's development marker (`isDevDependency: true`) — but
  only on a package that ends up scope `app`: a re-scoped application-ecosystem
  package, or a package shared with a workspace. A genuine system package
  (stays `os`) is never development-marked, whatever its container's
  classification; `[os_dependencies]` (Stage 2) is its only downgrade lever. A
  workspace occurrence's development marker comes from its own lockfile or
  manifest signal instead, unrelated to any container.

The `docker:` occurrence-identity namespace is merge-reserved: a workspace
target that would mint one fails the run instead of silently colliding with it.

Source: `src/merge/merge.ts` (`mergeInto`, `assertNotReservedIdentity`),
`src/pipeline/pipeline.ts` (`readCommittedDockerSbom`),
`src/pipeline/containerScope.ts` (`applyContainerScopes`),
`src/policy/osEcosystems.ts` (`OS_PACKAGE_ECOSYSTEMS`).

## Stage 2 — verdict routing

The policy engine decides one verdict per (package × occurrence). Precedence,
highest to lowest:

1. **Deny** — a `[[deny]]` match, or a shipped source-available default: fail,
   unless the consumer exempted that exact license via
   `[[allow_source_available]]` (then a warn instead). Terminal: nothing below
   can license a denied finding back in.
2. **A stale override** — an override's precondition no longer matches what's
   observed: fail.
3. **An assessment conflict** — fail, via one of two independent triggers for
   the assessment-conflicts surface, either one independent of everything that
   follows: the in-depth scan disagreeing with the declared/registry quick
   check, or two-or-more docker occurrences of the same purl declaring
   different license claims (a cross-image divergence, detected at merge
   time, claim-SET comparison so listing the same claims in a different order
   is never a divergence).
4. **A `[[compatible]]` package or license rule** — ok. (`[[clarify]]` isn't a
   tier of its own here: it rewrites the finding *before* this precedence walk
   runs, so a clarified package falls through the same lanes as any other
   finding. One that clears every lane below cites `clarify[i]` at the
   default-ok tier instead of a bare `default:ok`.)
5. **The target-compatibility lane** — entered only when a target profile
   governs this occurrence *and* the finding has a parseable, non-imprecise
   expression. The tree below.
6. **The copyleft lane** — entered only when the elected SPDX branch is
   copyleft. The tree below.
7. **The imprecise-family lane** — entered when the finding names only a
   family, with no elected expression.
8. **The unknown lane** — entered when the finding has no expression and isn't
   imprecise: follows `[unknown]` handling (`warn` or `fail`).
9. **Default: ok.**

### The target-compatibility lane

Activates per occurrence only when BOTH hold: a `[target]`/`[[target.workspace]]`
profile resolves for that occurrence (a workspace occurrence takes the
most-specific covering `[[target.workspace]]` entry, else the project
profile; a docker occurrence takes the project profile only — a workspace
override never governs a container), and the finding is parseable (not
imprecise, not a genuine unknown). `os`-scope packages never enter this lane
at all — they keep today's walk, with one reconciliation noted below.

**The scope-gating principle:** the profile's `network`/`distribution` flags
decide which obligation class is *in scope*; the compatibility relation (the
vetted OSADL-matrix-first tier chain) always decides the *verdict* for an
in-scope obligation — a flag never hardcodes an outcome. Five outcomes:

- **compatible** → ok, `target:ok` (a clarified package landing here still
  cites `clarify[i]`, exactly like the default-ok tier above).
- **held-internal** — a positively-known copyleft/AGPL obligation the profile
  takes out of scope (`distribution = "internal"` for copyleft; additionally
  `network = false` for AGPL, since `network = true` keeps the AGPL class in
  scope regardless of distribution) → ok, `target:internal-use`, distinct
  from a bare `target:ok` so the exposure stays enumerable for the day the
  profile flips. A non-copyleft-driven incompatibility, or an obligation
  class the vetted data cannot positively classify, is *never* held — the
  flag gates only a declared obligation class, never broader legal inference.
- **boundary** → warn, `target:boundary` (weak copyleft under a proprietary
  target — usable only behind a compliant linking boundary).
- **incompatible** → fail, `target:incompatible`, dev-downgraded per
  `[dev_dependencies]` exactly like `default:copyleft`.
- **a matrix-uncovered pair** → the `unknown_pair` knob (`warn` by default,
  `fail` also dev-downgraded) — honest residual, never a silent pass.

A ref-carrying elected branch (under the target-aware election, which can
differ from the no-target election) falls through to the unknown lane below
instead, never `target:ok` — an opaque reference's content is unknowable
regardless of a declared target.

**The AGPL-container/network reconciliation:** the container AGPL escalation
below (`default:agpl-container`) encodes "a container is network-deployed" as
a heuristic. Where a *complete* project target profile is declared, the
explicit `network` flag owns that applicability fact instead: `network =
true` leaves the escalation exactly as it is today (now declared, not
guessed); `network = false` demotes it to the routine would-be
`default:copyleft` fail, then `[os_dependencies]` decides from there, the
reason naming the declared basis. A repo with no complete project profile
keeps the heuristic byte-identically. This is the one place a declared target
profile touches an `os`-scope verdict — the target-compatibility lane itself
still never governs `os`-scope packages.

### The copyleft lane

- A target-governed occurrence never reaches this lane at all — the
  target-compatibility lane above decides it first, so a
  `[[workspace.copyleft_suppressed]]` entry a target governs is effectively
  dead there (surfaced by `policy/target.ts`'s `suppressionOverlapNotices`,
  never silently).
- A family-justified workspace copyleft suppression (the occurrence sits under
  the suppressed path, and the elected copyleft is absorbed by that
  workspace's own declared license family) → `suppressed`. Checked *before*
  the AGPL check below, ahead of every scope — in practice this only matters
  for a workspace-identity occurrence, since a suppression path is authored
  against workspace paths, not `docker:` ones.
- Otherwise, scope `os` and the elected expression carries an AGPL leaf → fail
  `default:agpl-container`, checked before the os downgrade so
  `[os_dependencies]` can never soften it — UNLESS a complete project target
  profile declares `network = false` (the reconciliation above), which
  demotes it to the routine would-be `default:copyleft` fail instead. The
  practical accept path for the undemoted escalation is a `[[compatible]]`
  rule (tier 4 above — it never even reaches this lane); that acceptance is
  recorded and surfaced by the output layer — see
  [report-placement.md](./report-placement.md) for the markdown report's
  accepted-AGPL notice, which a network=false-demoted row landing `ok` (via
  `[os_dependencies] = "ignore"`) also gets, so the obligation is never
  silently absent.
- Otherwise, scope `os`, any other copyleft → would-be fail
  `default:copyleft`, then `[os_dependencies]`: `fail` stays fail, `warn`
  downgrades to warn with the rule id preserved, `ignore` downgrades to ok.
- Otherwise, scope `app` → fail `default:copyleft`; a development occurrence
  then downgrades per `[dev_dependencies]` (`warn`, `ignore`, or stays `fail`).

### The imprecise-family lane

- Scope `os` and the family is the bare `AGPL` token → fail
  `default:agpl-container` (the same escalation as the precise case, and the
  same network=false demotion reconciliation).
- Family is a could-be-copyleft token (bare `GPL`, `AGPL`, `LGPL`) → warn
  `default:imprecise-copyleft`.
- Any other family (a known-permissive one like bare `BSD`) → warn
  `default:imprecise`.

### The unknown lane

Follows `[unknown]` handling; a `fail` result applies the same os/development
downgrades as the copyleft default does. Also entered when the elected
expression still carries a `LicenseRef-`/`DocumentRef-` leaf after election (a
bare ref, or an `AND` that keeps one alongside a known license) — an opaque
reference's content is unknowable to the tool, so it is never silently
`default:ok`; an `OR` with an electable known branch already resolves to that
branch before this lane and never reaches it. A ref-carrying elected branch
under a target-aware election falls through here too, from the
target-compatibility lane above.

Source: `src/policy/evaluate.ts` (`verdictFor`, `targetVerdict`,
`copyleftVerdict`, `impreciseVerdict`, `unknownVerdict`, `refUnknownVerdict`,
`acceptedContainerNotices`), `src/policy/target.ts` (`resolveTargetProfile`),
`src/policy/compat/classify.ts` (`classifyExpression`), `src/policy/copyleft.ts`
(`AGPL_IDS`), `src/merge/merge.ts` (`crossImageClaimDivergence`, detecting the
divergence), `src/normalize/normalize.ts` (`withCrossImageConflict`,
surfacing it on the finding).

## Invariants

- Deny is terminal.
- An unrecognized purl ecosystem gates as an application dependency — the OS
  allowlist fails safe.
- An AGPL obligation is never silently softened at the verdict level: the
  container AGPL escalation (`default:agpl-container`) bypasses both
  `[os_dependencies]` and `[dev_dependencies]`; only an explicit
  `[[compatible]]` rule, or a complete project target profile's declared
  `network = false`, can change the verdict — and the declared-`network`
  path stays visible even when it lands `ok` (the accepted-AGPL notice).
- Absent a `[target]`/`[[target.workspace]]` profile, or on an occurrence no
  profile governs, verdict routing is byte-identical to a repo with no
  `[target]` table at all — the target-compatibility lane is purely additive.
- `os`-scope packages never receive a `target:*` rule; the declared `network`
  flag's only effect on an `os`-scope verdict is the AGPL-container
  reconciliation above.

## Path index (verified end to end)

The same 48 paths as
[report-placement.md](./report-placement.md#path-index-verified-end-to-end),
one row each, stating the Stage-1/Stage-2 outcome (scope, verdict status,
rule) instead of the markdown destination — the two tables share one slug
set, verified by the same suite (`test/reportPlacement.test.ts`). A shared
classification with an unremarkable outcome still gets its own row; the
tables are about slug coverage, not about every classification being unique.

| id | given | classification |
| --- | --- | --- |
| `workspace-prod-permissive` | npm workspace prod dependency, permissive license | `app · ok · default:ok` |
| `workspace-dev-only` | npm workspace dependency, every occurrence dev | `app · ok · default:ok` |
| `shared-workspace-and-container` | npm dependency in a workspace AND baked into a prod container | `app · ok · default:ok` |
| `container-only-system` | apk/deb package, container-only | `os · ok · default:ok` |
| `container-only-app-ecosystem` | npm package baked into a prod container, permissive, container-only | `app · ok · default:ok` |
| `unrecognized-ecosystem-gates` | unrecognized purl ecosystem, copyleft, in a prod container | `app · fail · default:copyleft` |
| `system-copyleft-os-warn` | apk GPL-2.0-only, `os_dependencies = "warn"` | `os · warn · default:copyleft` |
| `system-copyleft-os-fail` | same, `os_dependencies = "fail"` | `os · fail · default:copyleft` |
| `system-copyleft-os-ignore` | same, `os_dependencies = "ignore"` | `os · ok · default:copyleft` |
| `system-agpl-escalates` | apk AGPL-3.0-only, `os_dependencies = "warn"` | `os · fail · default:agpl-container` |
| `system-agpl-accepted-notice` | same, accepted via `[[compatible]]` | `os · ok · compatible[0]` |
| `system-agpl-imprecise-escalates` | imprecise bare-`AGPL` system package | `os · fail · default:agpl-container` |
| `system-agpl-imprecise-accepted` | same, accepted | `os · ok · compatible[0]` |
| `mixed-agpl-fail-and-accept` | one AGPL system purl, failing in one container, accepted in another | `os · fail · default:agpl-container` |
| `app-copyleft-prod-container` | golang/npm copyleft baked into a prod container | `app · fail · default:copyleft` |
| `app-copyleft-dev-container` | app-ecosystem copyleft in a `[[docker.development]]` container | `app · warn · default:copyleft` |
| `app-copyleft-workspace-dev` | workspace dev-dependency copyleft | `app · warn · default:copyleft` |
| `problematic-dedup-keeps-inventory` | workspace prod copyleft, fails | `app · fail · default:copyleft` |
| `imprecise-copyleft-family-only-imprecise` | bare `GPL` app package | `app · warn · default:imprecise-copyleft` |
| `imprecise-permissive-family` | bare `BSD` app package | `app · warn · default:imprecise` |
| `unknown-license-counted` | [unknown] handling = "warn", no license | `app · warn · default:unknown` |
| `licenseref-only-unknown` | a package whose only license content is a LicenseRef | `app · warn · default:unknown` |
| `suppressed-workspace-copyleft` | family-justified `[[workspace.copyleft_suppressed]]` | `app · suppressed · workspace.copyleft_suppressed[0]` |
| `denied-license-terminal` | a `[[deny]]` match with a `[[compatible]]` rule that would otherwise accept it | `app · fail · denied[0]` |
| `system-package-in-dev-container-counts-dev` | apk permissive package whose only container is dev-marked | `os · ok · default:ok` |
| `conflict-scancode` | npm workspace package whose in-depth scan answer disagrees with the declared claim, no `[[clarify]]` resolving it | `app · fail · conflict:scancode` |
| `detected-mismatch` | npm workspace package a `[[clarify]]` entry recorded as `BSD` in the registry lane, now reporting GPL-3.0-only there | `app · fail · override:stale[clarify]` |
| `cross-image-claim-divergence` | apk purl baked into two prod containers with different declared licenses | `os · fail · conflict:cross-image-claims` |
| `target-ok-permissive` | MIT dep under a (MIT, network=false, external) target | `app · ok · target:ok` |
| `target-incompatible-prod` | GPL-3.0-only dep under a (MIT, external) target, prod occurrence | `app · fail · target:incompatible` |
| `target-incompatible-dev-downgrade` | same finding, dev occurrence, `dev_dependencies = "warn"` | `app · warn · target:incompatible` |
| `target-apache-gpl2-incompatible` | Apache-2.0 dep under a (GPL-2.0-only, external) target | `app · fail · target:incompatible` |
| `target-or-election-flip` | `Apache-2.0 OR GPL-2.0-only` dep under a (GPL-2.0-only, external) target | `app · ok · target:ok` |
| `target-proprietary-boundary-external` | LGPL-2.1-only dep under a (proprietary, network=true, external) target | `app · warn · target:boundary` |
| `target-unknown-pair-residual` | a matrix-uncovered pair, `unknown_pair` absent then `"fail"` | `app · warn · target:unknown-pair` then `app · fail · target:unknown-pair` |
| `target-internal-holds-gpl` | GPL-3.0-only dep under a (MIT, network=false, internal) target | `app · ok · target:internal-use` |
| `target-internal-network-agpl-fails` | AGPL-3.0-only dep under a (MIT, network=true, internal) target | `app · fail · target:incompatible` |
| `target-network-agpl-absorbed` | AGPL-3.0-only dep under an (AGPL-3.0-only, network=true, external) target, container occurrence | `app · ok · target:ok` |
| `target-network-false-agpl-internal-held` | AGPL-3.0-only dep under a (MIT, network=false, internal) target | `app · ok · target:internal-use` |
| `target-internal-nondistribution-conflict-stays` | Apache-2.0 dep under a (GPL-2.0-only, network=false, internal) target | `app · fail · target:incompatible` |
| `target-workspace-divergence` | one purl, two workspace occurrences under diverging per-workspace targets | `app · fail · target:incompatible` (workspace A) and `app · ok · target:ok` (workspace B) |
| `target-container-app-ecosystem` | npm GPL-3.0-only baked into a prod container, project (GPL-3.0-only, external) target | `app · ok · target:ok` |
| `target-os-agpl-network-true-escalates` | apk AGPL-3.0-only, project target `network = true` | `os · fail · default:agpl-container` |
| `target-os-agpl-network-false-routine` | same package (precise and imprecise), project target `network = false`, `os_dependencies = "warn"` | `os · warn · default:copyleft` |
| `target-os-scope-untouched` | apk GPL-2.0-only under any target profile | `os · warn · default:copyleft` (byte-identical reason to the no-target run) |
| `target-supersedes-suppression` | a governed occurrence matching a family-justified `[[workspace.copyleft_suppressed]]` | `app · ok · target:ok` (never `suppressed`) |
| `target-os-agpl-network-false-ignored-notice` | apk AGPL-3.0-only, project target `network = false`, `os_dependencies = "ignore"` | `os · ok · default:copyleft` |
| `target-held-survives-purl-fail` | one purl, two workspace occurrences: one fails (project MIT/external target), the other holds (a `[[target.workspace]]` MIT/internal override) | `app · fail · target:incompatible` (workspace A) and `app · ok · target:internal-use` (workspace B) |
