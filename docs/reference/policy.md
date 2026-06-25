# `.sbomlet.toml` reference

This page is for the policy author. It lists every table and field in
`.sbomlet.toml`, with types, whether each is required, and what it means. The
narrative, covering when to reach for each lane and why the precedence is
ordered the way it is, lives in the
[explanation pages](../explanation/design-principles.md); this page is the
lookup table.

A `.sbomlet.toml` is optional. Without it, the tool inventories licences and
writes the documents but assigns no [verdicts](../glossary.md#verdict). With it,
every (package × occurrence) gets a verdict of `ok`, `warn`, `fail`, or
`suppressed`, and `check` becomes a gate that can fail your build. You pass the
file to either command:

```sh
task generate POLICY=.sbomlet.toml
task check POLICY=.sbomlet.toml
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
| 4 | Compatible (licence) | `[[compatible]]` with `match = "license"` | Allow this licence everywhere. |
| 5 | Workspace suppression | `[[workspace.copyleft_suppressed]]` | Stop flagging absorbed copyleft inside a workspace that ships under that copyleft. |
| 6 | Category default | `[unknown]`, `[dev_dependencies]`, `[os_dependencies]` | What an unresolved, dev-only, or OS-scope would-be-fail does when no lane above caught it. |

Deny sits above everything because a
[source-available](../glossary.md#source-available) licence legally cannot be
redistributed in a shipped artifact, so no accept lever may override it. The
category defaults are floors rather than lanes that match a specific package.
They set what happens to a verdict that no override touched.

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
- Suppression `path` values and `[docker]` `ignore` globs must use forward
  slashes, carry no `..` segment, and have no leading or trailing slash. This
  confines them to the repo, so a crafted value cannot suppress everything or
  escape the repo namespace.
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
([ADR-0015](../explanation/adr/0015-source-available-deny-list.md)), so every
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
See [ADR-0015](../explanation/adr/0015-source-available-deny-list.md).

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

The tool also ships its own curated clarifications for commonly-ambiguous
projects, applied without your re-authoring them. When a project-level
`[[clarify]]` names the same package, your entry takes precedence.

## `[[compatible]]`

An array of tables. Each entry accepts a licence or a package that would
otherwise be flagged as [copyleft](../glossary.md#copyleft). Acceptance applies
everywhere, not per workspace. Absent table: no compatible rules.

Exactly one of two match modes per entry.

Licence mode (`match = "license"`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"license"` | yes | Selects licence mode. |
| `pattern` | string | yes | An SPDX id or `OR` of ids, satisfies-matched. `AND` is rejected. |
| `reason` | string (non-empty) | yes | The documented judgment call. |

Package mode (`match = "package"`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"package"` | yes | Selects package mode. |
| `name` | string | yes | Exact package name, as the inventory reports it. |
| `version` | string | no | Pin to one version; omit to cover all versions. |
| `reason` | string (non-empty) | yes | The documented judgment call. |

Licence mode allows a whole licence, such as a weak copyleft you have reviewed
and accepted like `MPL-2.0`. Package mode allows one specific dependency,
optionally one version of it, for when only a single package's obligations have
been reviewed rather than a whole licence.

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
never a sibling like `apps/scratch-helper`.

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

A table governing what a would-be-fail does on an
[OS-scope](../glossary.md#scope-app-and-os) package, meaning a `pkg:deb` or
`pkg:apk` row from a Docker base image, read from the committed
`docker-os-sbom.json`. Absent table: defaults to `warn`.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `handling` | `"warn"` \| `"fail"` \| `"ignore"` | yes (if table present) | `warn` downgrades an OS would-be-fail to a warning; `fail` gates OS packages exactly like production app code; `ignore` makes it `ok`. |

The expected copyleft in a Debian or Alpine base image, such as glibc under LGPL
or bash and coreutils under GPL, is the operating system the container ships on,
not code your project authored. Those obligations are satisfied by shipping the
image, so by default the gate lists the OS packages in their own section rather
than failing your build on every standard base image. Use `fail` if you vendor
or rebuild your base and want every OS copyleft reviewed. As with
`[dev_dependencies]`, deny still wins, so a source-available licence in an OS
package fails regardless of this knob.

The `docker-os-sbom.json` this lane reads is produced separately by the
maintainer-only `generate-docker-sbom` subcommand and committed; `generate` and
`check` only read it as a `scope:os` merge input. They never discover or scan
Docker images themselves. See the
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
maintainer-only `generate-docker-sbom` subcommand. A Dockerfile whose
repo-relative path matches an `ignore` glob is excluded entirely, so its base
image is never derived or scanned. Absent table: nothing is excluded. A present
table without `ignore` is the same as an empty list.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `ignore` | array of strings | no | Repo-relative forward-slash globs; a matching Dockerfile is excluded. |

Each glob is validated like a suppression path, with forward slashes only, no
`..` segment, and no leading or trailing slash, so a crafted glob cannot reach
outside the repo.

## Related pages

- [Glossary](../glossary.md) — the canonical vocabulary used above.
- [Design principles](../explanation/design-principles.md) — why the lanes are
  ordered as they are, and why deny is terminal.
- [Data model](../explanation/data-model.md) — what a verdict, occurrence, and
  finding are inside the tool.
