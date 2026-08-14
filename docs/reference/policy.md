# `.sbomlet.policy.toml` reference

This page is for the policy author. It lists every table and field in
`.sbomlet.policy.toml`, with types, whether each is required, and what it means. The
narrative, covering when to reach for each lane and why the precedence is
ordered the way it is, lives in the
[explanation pages](../explanation/design-principles.md); this page is the
lookup table.

A `.sbomlet.policy.toml` is optional. Without it, the tool inventories licences and
writes the documents but assigns no [verdicts](../glossary.md#verdict). With it,
every (package × occurrence) gets a verdict of `ok`, `warn`, `fail`, or
`suppressed`, and `check` becomes a gate that can fail your build. You pass the
file to either command:

```sh
task sbomlet:generate POLICY=.sbomlet.policy.toml
task sbomlet:check POLICY=.sbomlet.policy.toml
```

A starter file ships as `policy.example.toml`. Copy it to your repo root and
edit from there.

## Precedence

The policy is a set of [lanes](../glossary.md#policy-lanes). For one package in
one occurrence, the engine consults them in this order and takes the first that
decides:

| Order | Lane | Table | Effect |
|-------|------|-------|--------|
| 1 | Deny | `[[deny]]` | Force-fail. Terminal — nothing below can license it back in. |
| 2 | Clarify | `[[clarify]]` | Replace the package's [licence finding](../glossary.md#license-finding) with a precise expression, then re-decide. |
| 3 | Compatible (package) | `[[compatible]]` with `match = "package"` | Allow this exact package. |
| 4 | Compatible (licence) | `[[compatible]]` with `match = "license"` | Allow this licence. |
| 5 | Target compatibility | `[target]` / `[[target.workspace]]` | When a declared target profile governs this occurrence, decide the verdict from license-vs-target compatibility instead of the lanes below. |
| 6 | Workspace suppression | `[[workspace.copyleft_suppressed]]` | Stop flagging absorbed copyleft inside a workspace that ships under that copyleft. |
| 7 | Category default | `[unknown]`, `[dev_dependencies]`, `[os_dependencies]` | What an unresolved, dev-only, or OS-scope would-be-fail does when no lane above caught it. |

Deny sits above everything because a
[source-available](../glossary.md#source-available) licence legally cannot be
redistributed in a shipped artifact, so no accept lever may override it. The
category defaults are floors rather than lanes that match a specific package.
They set what happens to a verdict that no override touched.

The order matters whenever a package could match more than one lane. A
package denied by `[[deny]]` fails even though a `[[compatible]]` rule would
accept it, because deny is terminal. A copyleft dependency accepted by a
`[[compatible]]` licence pattern never reaches workspace suppression, because
compatible already decided it. A target-governed occurrence never reaches
workspace suppression either: the target lane decides it first, so a
`[[workspace.copyleft_suppressed]]` entry whose path a declared target
governs is **superseded** — surfaced as a notice naming both, never
silently.

## Validation

Validation is strict and rejects the whole file on the first run, reporting
every problem at once. Each problem names the table path and key it came from
(`compatible[2]: missing required key "reason"`), so you fix them in one pass
rather than one error per run.

The rules that hold across the file:

- Every override carries a `reason` (or, for suppression, a `description`), and
  it must be present and non-empty. An empty or whitespace-only value is
  rejected. These strings are the audit trail a reviewer reads, so the tool
  treats a blank one as a missing one.
- Every `pattern`, `expression`, and workspace `license` is parsed against
  [SPDX](../glossary.md#spdx) grammar at load time. A typo like `Apache 2.0` (no
  hyphen) fails immediately, naming the field, rather than surfacing
  mid-evaluation.
- A licence-mode `[[deny]]` or `[[compatible]]` pattern may be a single SPDX id
  or an `OR` of ids (`MPL-2.0`, `MPL-2.0 OR MPL-1.1`). An `AND` pattern is
  rejected, because the underlying satisfies check cannot hold an `AND` as an
  allowlist entry. Use a per-package rule for an `AND`-licensed dependency
  instead.
- Licence patterns flow through the SPDX parser, never a text compare, so there
  is no substring matching. `BSD` does not match `BSD-3-Clause`; name them
  exactly or use an `OR`.
- Suppression `path` values, `[docker]` `ignore` globs, and compatible `where`
  entries must use forward slashes, carry no `..` segment, and have no leading
  or trailing slash. This confines each to its namespace — the repo for paths
  and globs, the occurrence identities for `where` — so a crafted value cannot
  suppress everything or escape it.
- A `[[workspace.copyleft_suppressed]]` `path` must not start with `docker:` —
  that prefix is the reserved occurrence-identity namespace for image targets,
  and a container image is not a workspace.
- Unknown top-level tables and unknown keys inside a known table are both
  errors. A misspelled `[[deney]]` or a stray field is not silently ignored.

A TOML syntax error, rather than a semantic one, propagates from the parser with
its own line, column, and caret-marked source line.

## `[[deny]]`

An array of tables. Each entry force-fails any matching package in any
occurrence, ranking above dev/OS scope, above compatible, above suppression, and
above a stale clarify. This is the lane for a
[source-available](../glossary.md#source-available) licence or a use-restriction
rider that can never ship.

**Shipped defaults.** BUSL-1.1, SSPL-1.0, and Elastic-2.0 are denied by default —
they ship with the tool
([ADR-0013](../explanation/adr/0013-source-available-deny.md)), so every
repository denies them without authoring an entry here. This table ADDS to that
set: a default-denied licence is cited `default:source-available`, a licence you
list is cited `denied[i]`. To ALLOW a default-denied licence for a reviewed
exception, see [`[[allow_source_available]]`](#allow_source_available). Absent
table: only the shipped defaults apply.

Exactly one of two match modes per entry.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"license"` \| `"name"` | yes | Which mode this entry uses. |
| `pattern` | string | yes | In `license` mode, an SPDX id or `OR` of ids, satisfies-matched against the finding. In `name` mode, an exact, case-sensitive package name. |
| `reason` | string (non-empty) | yes | Why this is denied — the audit trail. |

Licence mode is OR-election-consistent: a finding is denied only when it cannot
elect an acceptable branch. With a deny covering `BUSL-1.1`,
`MIT OR BUSL-1.1` is not denied, because the package can elect `MIT`; a finding
whose every branch is denied is. The election runs against the union of all
licence-mode deny patterns, so listing `BUSL-1.1`, `SSPL-1.0`, and
`Elastic-2.0` as three entries still denies `BUSL-1.1 OR SSPL-1.0`.

Name mode covers things SPDX does not register. A
[use-restriction rider](../glossary.md#source-available) like Commons-Clause
rides alongside another licence (`MIT AND Commons-Clause`) and is not a
parseable SPDX value, and a licence like RSAL has no registered id at all. Name
mode matches the package by exact name, so it catches these even on a package
whose finding is unknown.

Deny also sees through an override: if a `[[clarify]]` rewrote a denied
licence into something benign, deny still fires on the original, pre-override
observed value, so a source-available licence can never be laundered clean by
a clarify entry.

## `[[allow_source_available]]`

An array of tables. Each entry exempts ONE built-in source-available licence from
the [shipped deny defaults](#deny) for a reviewed exception — an internal-only tool
that is never redistributed, or a component you hold a separate licence for. The
package then surfaces as a **warn** (visible, non-gating) citing the exemption,
rather than failing, so an accepted source-available licence never silently passes
review.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `license` | string | yes | One of the built-in defaults — `BUSL-1.1`, `SSPL-1.0`, `Elastic-2.0`. Any other id is rejected. |
| `reason` | string (non-empty) | yes | Why this source-available licence is accepted — the audit trail. |

The exemption is scoped to the defaults only. A licence you deny yourself via
`[[deny]]` is absolute and is never softened here — an explicit deny still wins.
See [ADR-0013](../explanation/adr/0013-source-available-deny.md).

## `[[clarify]]`

An array of tables. Each entry corrects or disambiguates one package's
[licence finding](../glossary.md#license-finding) before the verdict is decided.
The override replaces the finding, and the package is then judged on the
corrected value. Absent table: no clarifications.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `package` | inline table `{ name, version? }` | yes | Which package. `name` is required; omit `version` to match all versions. |
| `expression` | string (SPDX) | yes | The corrected SPDX expression, parsed at load time. |
| `expects` | string | no | A staleness precondition — the pre-override value you're disambiguating *from*. |
| `reason` | string (non-empty) | yes | Where the correction comes from. |

There are two kinds, distinguished by whether `expects` is present.

Without `expects`, the entry is a misdetection correction: `expression`
replaces the finding unconditionally. Use it to fix garbage or missing upstream
metadata, such as a package that declares `Public Domain` mapped to
`Unlicense`.

With `expects`, the entry is a staleness-guarded disambiguation: the override
applies only while the package's currently-observed licence still matches
`expects`. If the observed value has moved on, such as a `BSD` → `BSD-3-Clause`
override on a package now reporting `GPL-3.0`, the override is stale, and the
gate fails naming the package, the expected value, and the observed one. A stale
assertion is never applied, so an old override cannot silently mask a relicence.

**Compound claims.** The staleness check falls back to canonical claim-string equality
— instead of the per-licence comparison above — when `expects` is itself a compound
`AND`/`OR` expression (a registry declaring `(MIT AND CC-BY-3.0)`, say, or even a
plain `(MIT OR Apache-2.0)`), or when `expression` contains an `AND` anywhere and so
cannot be reduced to a set of OR-only branches. An `expression` that is OR-only —
even multi-branch — still goes through the ordinary per-licence comparison as long
as `expects` names a single licence.

In the fallback, `expects` must canonically equal one of the package's observed
licence claims: both sides run through the same boolean-algebra canonicalization
(flatten, dedupe, absorb, sort) that governs the ScanCode assessment and
cross-image comparisons in
[output-format.md](./output-format.md#assessment-conflicts), then a
case-insensitive, whitespace-trimmed comparison — never re-derived or corrected
beyond that. A registry re-spelling the same licence set, `MIT AND CC0-1.0` read
back as `CC0-1.0 AND MIT`, canonicalizes to the same structure and never reopens
the override. There is still no redundancy path for a compound override — a
compound claim already names the exact multi-licence reading it was written
against, so a real change to the licence SET, not merely its spelling, is
staleness. This exists because the underlying SPDX-satisfies check that powers
the simple case cannot take an `AND` expression as an allowlist entry (the same
restriction the Validation section describes for `[[deny]]` and `[[compatible]]`
patterns).

The tool also ships its own curated clarifications for commonly-ambiguous
projects, applied without your re-authoring them. When a project-level
`[[clarify]]` names the same package, your entry takes precedence.

## `[[compatible]]`

An array of tables. Each entry accepts a licence or a package that would
otherwise be flagged as [copyleft](../glossary.md#copyleft). Acceptance applies
at every occurrence unless the optional `where` narrows it. Absent table: no
compatible rules.

Exactly one of two match modes per entry.

Licence mode (`match = "license"`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"license"` | yes | Selects licence mode. |
| `pattern` | string | yes | An SPDX id or `OR` of ids, satisfies-matched. `AND` is rejected. |
| `reason` | string (non-empty) | yes | The documented judgment call. |
| `where` | array of strings | no | Occurrence-identity prefixes the rule is limited to; omit to apply everywhere. |

Package mode (`match = "package"`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"package"` | yes | Selects package mode. |
| `name` | string | yes | Exact package name, as the inventory reports it. |
| `version` | string | no | Pin to one version; omit to cover all versions. |
| `reason` | string (non-empty) | yes | The documented judgment call. |
| `where` | array of strings | no | Occurrence-identity prefixes the rule is limited to; omit to apply everywhere. |

Licence mode allows a whole licence, such as a weak copyleft you have reviewed
and accepted like `MPL-2.0`. Package mode allows one specific dependency,
optionally one version of it, for when only a single package's obligations have
been reviewed rather than a whole licence.

`where` limits either form to the occurrences whose target matches one of its
entries: the target is the entry itself, or sits under it as a whole segment.
`docker:a` covers `docker:a/Dockerfile`; `apps/scratch`
never covers `apps/scratch-helper`. Docker targets are
`docker:<source>` — the Dockerfile's repo-relative path for a built
image, the image reference verbatim for an `--image` scan; app targets are
workspace paths. Entries are validated like suppression paths (forward slashes
only, no `..` segment, no leading or trailing slash); an empty array is
rejected. Rules are consulted in file order per occurrence, and the first whose
match and scope both hold decides. A scoped rule that matches no occurrence is
reported as an unused entry on stderr.

## `[[workspace.copyleft_suppressed]]`

An array of tables under the `[workspace]` table. Each entry stops flagging
absorbed copyleft for occurrences inside one workspace that itself ships under
a copyleft licence. Absent: no suppressions.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `path` | string | yes | Repo-relative workspace prefix (forward slashes, no `..`, no leading/trailing slash). |
| `license` | string (single SPDX id) | yes | The SPDX id the workspace is distributed under. Must be a single id, not a compound expression. |
| `description` | string (non-empty) | yes | Why suppression is justified here. |

Suppression is per [occurrence](../glossary.md#occurrence) rather than per
package, so the same dependency in a non-suppressed workspace still flags. The
`path` match is segment-aware, so `apps/scratch` covers occurrences under it but
never a sibling like `apps/scratch-helper`. `path` is also rejected outright if
it starts with `docker:` — a container image is not a workspace, so accept a
container's copyleft package with a scoped [`[[compatible]]`](#compatible) rule
instead.

It is also family-aware. A finding is suppressed only when it satisfies the
workspace `license`, or when every copyleft obligation in it belongs to a family
the workspace's own licence family absorbs. The GNU family spans AGPL, GPL, and
LGPL, and a GNU-family workspace also absorbs MPL, so an `AGPL-3.0-only`
workspace suppresses AGPL, GPL, LGPL, and MPL findings. It does not suppress
SSPL, CC-BY-SA, or any other out-of-family copyleft, which falls through to the
normal fail default. The `license` must be a single id because that family check
has no single identity to compare against for a compound expression.

## `[unknown]`

A table governing packages whose licence could not be determined, whether from
no claim at all or a value that neither parses nor corrects. Absent table:
defaults to `warn`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `handling` | `"warn"` \| `"fail"` | yes (if table present) | `warn` reports unknowns without failing; `fail` treats every unknown as a violation. |

Start with `warn` while you burn down the unknown population, then switch to
`fail` once the inventory is clean. The knob is global; per-ecosystem handling
is not yet available.

## `[dev_dependencies]`

A table governing what a would-be-fail does on a
[development-only](../glossary.md#development-only-and-production) occurrence. The
would-be-fail is a copyleft licence, or an unknown licence under `[unknown]`
`handling = "fail"`, that appears only in build tools or test runners. Absent
table: defaults to `warn`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `handling` | `"warn"` \| `"fail"` \| `"ignore"` | yes (if table present) | `warn` downgrades a dev would-be-fail to a warning; `fail` gates dev exactly like production; `ignore` makes it `ok`. |

A build-time-only copyleft tool carries no distribution obligation, which is why
`warn` is the default. The knob is per occurrence, so a package used as a dev
dependency in one workspace and a production dependency in another still fails on
the production occurrence. A shipped copyleft can never be dev-downgraded, and
deny still wins above this lane.

## `[os_dependencies]`

A table governing what a would-be-fail does on a genuine
[OS-scope](../glossary.md#scope-app-and-os) package: one from the committed
`.sbomlet.cache/docker.sbom.json` whose ecosystem is on the OS package-manager
allowlist (`deb`, `apk`, `rpm`, `alpm`) — base-image content, not something an
application layer installed. Absent table: defaults to `warn`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `handling` | `"warn"` \| `"fail"` \| `"ignore"` | yes (if table present) | `warn` downgrades an OS would-be-fail to a warning; `fail` gates OS packages exactly like production app code; `ignore` makes it `ok`. |

The expected copyleft in a Debian or Alpine base image, such as glibc under LGPL
or bash and coreutils under GPL, is the operating system the container ships on,
not code your project authored. Those obligations are satisfied by shipping the
image, so by default the gate lists the OS packages under their container's own
System-packages table (see `[docker.development]` below) rather than failing
your build on every standard base image. This knob has no effect on an
application-ecosystem package the image scan found — npm, pypi, go, and the
rest — because installing something via an application package manager makes
it an application dependency wherever it lives; it gates on
[`[dev_dependencies]`](#dev_dependencies) and the normal copyleft rule
instead, exactly like a lockfile dependency. Use `fail` if you vendor or
rebuild your base, or you want every base-image copyleft reviewed. As with
`[dev_dependencies]`, deny still wins, so a source-available licence in an
OS-scope package fails regardless of this knob — and so does AGPL: an AGPL
SYSTEM package always fails via the dedicated `default:agpl-container` rule,
never downgraded by this knob, because network-copyleft (section 13) reaches
server-side use and is not routine base-image noise the way an ordinary GPL
or LGPL package is. An AGPL application-ecosystem package in a container
fails too, but through the ordinary `default:copyleft` rule, since it was
never OS-scope to begin with.

The `.sbomlet.cache/docker.sbom.json` this lane reads is produced separately by the
`generate-docker-sbom` subcommand — run by hand over named Dockerfiles or images,
or by CI discovering and building the repository's Dockerfiles — and committed;
`generate` and `check` only read it as a `scope:os` merge input. They never
discover or scan Docker images themselves. See the
[`generate-docker-sbom` reference](cli.md) for how that file is
built.

## `[document]`

An optional table that customizes the rendered `THIRD_PARTY_LICENSES.md`
heading and intro. It affects that document only, never the notices companion.
Absent table: the defaults are used. Both keys are optional; a present-but-empty
`[document]` is valid.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `title` | string (non-empty) | no | Replaces the default `Third-Party Licenses` H1. |
| `preamble` | string (non-empty) | no | A verbatim Markdown block rendered below the auto-generated header. |

Both values are rendered as you write them, `title` as the heading and
`preamble` as raw author Markdown, so the policy file is a trusted source here.
Write the `preamble` as a multi-line string if it spans paragraphs.

## `[docker]`

An optional table holding Dockerfile-discovery exclusion globs, consulted by the
maintainer-only `generate-docker-sbom` subcommand, and `[[docker.development]]`,
consulted by `generate`/`check` when rendering `THIRD_PARTY_LICENSES.md`. A
Dockerfile whose repo-relative path matches an `ignore` glob is excluded
entirely, so it is never built or scanned. Absent table: nothing is excluded and
every container renders production. A present table without `ignore` is the
same as an empty list.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `ignore` | array of strings | no | Repo-relative forward-slash globs; a matching Dockerfile is excluded. |

Each glob is validated like a suppression path, with forward slashes only, no
`..` segment, and no leading or trailing slash, so a crafted glob cannot reach
outside the repo.

### `[[docker.development]]`

An optional array of tables marking whole containers as development-only in the
rendered report. Every analyzed container defaults to production; a container
whose `docker:<source>` identity matches an entry's `source` glob is instead
listed under `## Development-only dependencies` and its own `### Container:`
subsection, rather than under `## Production dependencies`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `source` | string (glob) | yes | Repo-relative glob over the Dockerfile identity, without the `docker:` prefix. |
| `reason` | string (non-empty) | yes | Mandatory documentation: why this container never ships. |

`source` is matched against each analyzed container's bare identity with the
EXACT same matcher and dialect as `[docker].ignore`: `*` matches within one path
segment, `**` crosses segments, matching is case-insensitive and anchored to the
whole identity, and a literal path is a valid glob that matches only itself. A
`source` is validated like a suppression path (forward slashes only, no `..`
segment, no leading or trailing slash) and must not start with `docker:` — the
table already scopes the Dockerfile identity, so the prefix would double up and
could never match. A `source` that matches no analyzed container prints one
stderr warning naming it, the same dead-entry posture as an unused scoped rule;
two entries matching the same container mark it development-only once,
idempotently.

This marking is placement-only for a SYSTEM package (the OS package-manager
allowlist): a routine base-image copyleft package still downgrades or gates
per `[os_dependencies]` regardless of which half it renders under, and an AGPL
system package still fails via `default:agpl-container` either way. For an
application-ecosystem package baked into the image, marking its container
development is NOT placement-only — it moves the verdict too, exactly like
marking a lockfile dependency a `devDependency`: a copyleft fail in a
production image dev-downgrades to a warning once the container is marked.
Use it for images that only run CI or local tooling and are never shipped to
a user — see the [writing-policy guide](../guides/writing-policy.md) for a
worked example.

## `[cache]`

An optional table choosing where the tool writes its generated committed
artifacts: the registry-resolved license cache (`licenses.cache.json`) and the
Docker image package SBOM (`docker.sbom.json`). Absent table: they live in
`.sbomlet.cache/` at the repo root. Set `dir` to relocate the directory and keep
your root clean (a .NET shop's `eng/`, a `.cache/` convention, and so on).

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `dir` | string | no | Repo-relative directory for committed artifacts; defaults to `.sbomlet.cache`. |

`dir` is validated like a suppression path (forward slashes only, no `..`
segment, no leading or trailing slash), so a committed-artifact directory can
never escape the repo. Whatever directory you choose is committed; `check` reads
it offline. The location resolves against the scanned repo, so it is the same
under the GitHub Action as locally.

## `[target]`

An optional table that activates the compatibility lane: instead of
hand-authoring `[[compatible]]`/`[[deny]]` entries for every dependency
licence, you declare your own software's usage profile and the tool decides
compatibility against it using the vetted OSADL compatibility matrix and
copyleft class table, then the ScanCode LicenseDB category index. Absent
table: behaviour is byte-identical to a policy with no `[target]` at all —
the lane is purely additive. See
[dependency-classification.md#the-target-compatibility-lane](./dependency-classification.md#the-target-compatibility-lane)
for the normative routing tree — how a verdict lands in one of the lane's
outcomes — and the
[adopting a target recipe](../guides/writing-policy.md#adopting-a-target)
for a worked before/after.

A declared target is a **usage profile**, not just a licence id. All three
profile keys are mandatory together (no defaults — declaring a target is a
load-bearing choice, so the tool forces you to make it consciously):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `license` | string | yes | One FOSS SPDX id, or the literal `"proprietary"`. A compound expression (`MIT OR Apache-2.0`) or a `LicenseRef-`/`DocumentRef-` reference is rejected — neither can anchor a compatibility-matrix row (dual-licensed targets aren't supported yet). |
| `network` | boolean | yes | Whether your software is deployed on a network. Gates whether the AGPL/section-13 obligation class is *in scope* — it never hardcodes the verdict. `true` keeps that class in scope regardless of `distribution`; the compatibility relation then decides — an AGPL (or otherwise section-13-compatible) target absorbs an AGPL dependency fine, an incompatible target still fails. `false` folds AGPL into the ordinary copyleft class, gated by `distribution` instead. |
| `distribution` | `"external"` \| `"internal"` | yes | Whether you convey the software outside your organization in any form. `external` keeps the distribution-triggered copyleft class fully in scope. `internal` takes that class out of scope: a would-be `target:incompatible`/`target:boundary` whose deciding leaf carries a positively-known copyleft (or, when `network = false`, AGPL) obligation becomes `ok` with the distinct rule `target:internal-use` instead — visible in its own report list, never a silent pass. A non-copyleft-driven incompatibility, or an obligation the vetted data can't positively classify, is never held this way; the flag gates a declared obligation class, never broader legal inference. |
| `unknown_pair` | `"warn"` \| `"fail"` | no | The residual knob for a licence pair none of the vetted data covers, mirroring `[unknown].handling`. Defaults to `"warn"`. Never a silent pass. |

A project-level profile is **all-or-nothing**: declaring any one of
`license`/`network`/`distribution` without the other two is rejected,
naming every missing key. Omitting all three — a `[target]` table carrying
only `unknown_pair` and/or `[[target.workspace]]` entries — is the
workspaces-only shape (below). An entirely empty `[target]` table, with
neither a project profile nor any workspace entry, declares nothing to
govern and is rejected as a dead activation switch.

### `[[target.workspace]]`

An array of tables under `[target]`. Each entry overrides the project
profile for one workspace and every occurrence under it — the same
segment-aware path matching as `[[compatible]]` `where` and
`[[workspace.copyleft_suppressed]]` `path`; the **most specific** covering
entry wins per occurrence. A docker (container) occurrence is never
governed by a workspace entry — only the project profile applies there,
since a container ships the project's software as a whole.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `path` | string | yes | Repo-relative workspace prefix (forward slashes, no `..`, no leading/trailing slash); must not start with `docker:`, and must not duplicate an earlier entry (the first match wins at resolution, so a repeat would be dead). |
| `license` | string | yes | This workspace's own target licence — same rules as the project-level `license`. Always overrides; there is no "inherit the project licence" option. |
| `reason` | string (non-empty) | yes | Why this workspace diverges from the project profile — the audit trail. |
| `network` | boolean | no | Overrides the project profile's `network`; inherited when absent and a complete project profile is declared. |
| `distribution` | `"external"` \| `"internal"` | no | Overrides the project profile's `distribution`; inherited the same way. |

**Inheritance is per field.** Omitting `network`/`distribution` inherits
the project profile's own value for that field only; `license` always
overrides, since a workspace entry with no licence divergence at all would
be pointless. When no *complete* project-level profile is declared (the
workspaces-only shape), there is nothing to inherit from, so every
`[[target.workspace]]` entry must then carry its own `network` and
`distribution` too — omitting either there is rejected, naming the entry.

**The compatibility engine's absorption assumption.** The OSADL matrix —
and this lane's use of it — models one question: does integrating a
dependency into a combined work distributed under the *leading* (target)
licence discharge the dependency's obligations? It does not model linking
mode — static versus dynamic, in-process versus a separate service — its
cells are the same regardless of how a dependency is actually wired in.
This is a deliberate simplification, not an oversight: modelling linking
modes would need a second axis of vetted data that doesn't exist publicly
at this matrix's scale, and a conservative pairwise absorption answer is
the safer default. [`[[compatible]]`](#compatible) stays the reviewed
escape hatch for a specific pairing you've examined more closely — a
weak-copyleft dependency behind a genuinely compliant linking boundary the
matrix's conservative cell can't know about. (The same absorption idea, at
workspace-license-family granularity rather than the matrix, is what
[`[[workspace.copyleft_suppressed]]`](#workspacecopyleft_suppressed) checks
above — the two lanes never both govern the same occurrence, since a
target-governed one is superseded first.)

## Related pages

- [Glossary](../glossary.md) — the canonical vocabulary used above.
- [Design principles](../explanation/design-principles.md) — why the lanes are
  ordered as they are, and why deny is terminal.
- [Data model](../explanation/data-model.md) — what a verdict, occurrence, and
  finding are inside the tool.
