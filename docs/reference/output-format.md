# Output format

Reference for everything the tool writes. For an operator regenerating the
inventory, for a policy author or compliance reviewer reading it, and for a
contributor changing the renderers.

`check` writes nothing; it regenerates these artifacts in memory and compares
them byte-for-byte against the committed files. `generate` writes them:

| Artifact | When written | Default path |
| --- | --- | --- |
| `THIRD_PARTY_LICENSES.md` | always | `--output`, defaults to `THIRD_PARTY_LICENSES.md` |
| `THIRD_PARTY_NOTICES.md` | always | `--notices`, defaults to `THIRD_PARTY_NOTICES.md` beside the output |
| the [enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache) | only when it fetches a new licence | `--enrichment-cache`, defaults to `enrichment-cache.json` at the base dir |
| a [CycloneDX](../glossary.md#cyclonedx) export | only with `--cyclonedx` | `--cyclonedx <path>` (no default) |
| a model dump | only with `--dump-model` | `--dump-model <path>` (no default) |

An adopter running only `task licenses:generate` gets three files: the two
Markdown documents and, on the first run that has a licence to fetch, the
enrichment cache. A warm run that finds every licence already in the cache does
not touch it. The CycloneDX export and the model dump appear only when their flag
is passed; the dump is a debug artifact and is not committed.

`generate` does **not** write `docker-os-sbom.json`. That sidecar is produced by
the separate, maintainer-only `generate-docker-sbom` subcommand and committed by
hand; `generate` and `check` only read it as a [`scope:os`](../glossary.md#scope-app-and-os)
[merge](../glossary.md#merge) input. See [the committed sidecars](#the-committed-sidecars)
below.

Two properties hold across every artifact. Each is sorted to a stable order, so
the same inventory always produces the same bytes. Each is written with `\n`
line endings only, so a Windows checkout and a Linux CI run agree. Nothing
carries a timestamp. A timestamp would change on every run, and `check` could
never tell a real change from the clock ticking, so each document records how to
regenerate it instead.

```sh
# Regenerate every committed artifact (the command in every auto-generated header)
task licenses:generate

# Regenerate including the CycloneDX export
bun run src/cli.ts generate --policy policy.toml --cyclonedx bom.cdx.json
```

## THIRD_PARTY_LICENSES.md

The human-readable inventory. Its section order is fixed, so a diff shows a
content change rather than a reordering.

The first two lines are the title (`# Third-Party Licenses`, taken from
`[document].title` or the default) and the auto-generated header comment that
names the regenerate command. When the policy sets `[document].preamble`, that
paragraph follows. On a policy run a line then points at the policy file:
`Copyleft notice rules are configured in <policy>.`

Sections appear in this order:

| Section | Heading | Shown when |
| --- | --- | --- |
| Package counts | `**Package counts:**` | always |
| Problematic licenses | `## Problematic licenses` | policy run only |
| Copyleft and special notices | `## Copyleft and special notices` | policy run only |
| Imprecise licenses | `## Imprecise licenses (review / disambiguate)` | any [imprecise](../glossary.md#imprecise-family) package exists |
| Production dependencies | `## Production dependencies` | always |
| Development-only dependencies | `## Development-only dependencies` | always |
| Docker base-image OS packages | `## Docker base-image OS packages` | always |

A run without a policy omits the policy pointer line, the Problematic section,
and the Copyleft section. The three summary sections always render their heading
and table header even when they hold no rows, so the document shape stays the
same whatever the dependency mix.

### Package counts

A bullet list: the total, then one line per ecosystem (`npm`, `pypi`, `deb`,
`apk`, …) sorted by name, then four roll-up counts.

```text
**Package counts:**

- Total packages: 3616
- npm: 3502
- pypi: 114
- Production packages: 3100
- Development-only packages: 516
- Docker OS packages: 0
- Unknown license: 502
```

The three population counts partition the total: every package is one of
production, development-only, or Docker OS. A package is
[development-only](../glossary.md#development-only-and-production) when it has at
least one [occurrence](../glossary.md#occurrence) and every occurrence is a dev
dependency; any production occurrence makes the whole package production. Docker
OS packages are counted on their own because the dev/prod split is an app-scope
idea. Unknown license is a separate tally that overlaps the other three: it
counts packages whose [finding](../glossary.md#license-finding) resolved to no
expression. An [imprecise](../glossary.md#imprecise-family) finding is present,
not unknown, so it is excluded from this count.

### The summary tables

The three summary sections share five columns:

| Column | Contents |
| --- | --- |
| Name | the package name |
| Ecosystem | the [purl](../glossary.md#purl) type — `npm`, `pypi`, `deb`, … |
| Version | the package version |
| License | the [finding](../glossary.md#license-finding), see below |
| Used in | the [targets](../glossary.md#target) where the package is used, comma-joined |

The License column shows the full normalized SPDX expression when a finding
exists, the whole expression rather than one elected branch of an `OR`. The
variations:

- A precise finding renders its expression, for example `Apache-2.0 AND LGPL-3.0-or-later`.
- An [imprecise](../glossary.md#imprecise-family) finding renders its family
  token plus a marker, for example `BSD (imprecise)`.
- An OS-scope partial finding that recognized part of its license but not all of
  it appends the surfaced remainder, for example `MIT (+ tok, tok)`, so both the
  known obligation and the unrecognized tokens stay visible.
- A package with no finding renders `unknown`, or, before annotation, the
  deduplicated raw [license claims](../glossary.md#license-claim) joined with
  commas.

OS packages appear only in the Docker base-image section, never in the app
sections. Lockfile-only scans that were never enriched will show `unknown` in
the License column; that is correct pre-annotation behavior, not a defect.

### Problematic licenses

A self-contained gate report, rendered on a policy run only, before the copyleft
section so the gate-blocking findings sit near the top.

It opens with a blocking table of every `fail` [verdict](../glossary.md#verdict),
grouped so one row is one (purl, rule, reason) triple with its targets
deduplicated and joined. When there are no blocking violations the table is
replaced by a single line, `✅ No blocking policy violations.` The columns:

| Column | Contents |
| --- | --- |
| Severity | always `fail` in this table |
| Rule | the [policy lane](../glossary.md#policy-lanes) rule that decided the verdict |
| Name, Ecosystem, Version, License | as in the summary tables |
| Used in | the group's targets, deduplicated and sorted |
| Why | per-row [provenance](../glossary.md#dependency-provenance), see below |
| Reason | the verdict's reason string |

After the table, when any `warn` verdicts exist, one non-blocking line rolls
them up by coarse category (copyleft, unknown, deny, other) with a count each,
for example `_Non-blocking: 12 copyleft warning(s), 3 unknown warning(s) (dev/os-downgraded or suppressed). See the sections below._`
The line is omitted when there are no warnings.

### Copyleft and special notices

Rendered on a policy run only. It opens with a one-line summary sentence: _The
packages listed below carry copyleft or special license obligations in at least
one non-suppressed workspace._

When the policy suppresses any workspaces, the list of them follows. These are
workspaces themselves distributed under a [copyleft](../glossary.md#copyleft)
licence, where in-family copyleft dependencies impose no extra obligation. Each
renders as `- <path> (<license>) — <description>`, sorted by path. With no
suppressed workspaces the list is omitted.

Then a table of every package carrying a copyleft or special obligation in at
least one workspace that policy did not suppress. Membership is a `fail` or
`warn` [verdict](../glossary.md#verdict) whose rule is exactly `default:copyleft`.
It uses the five summary columns plus a trailing **Why** column:

| Column | Contents |
| --- | --- |
| Name, Ecosystem, Version, License | as in the summary tables |
| Used in | only the flagged, non-suppressed targets |
| Why | per-row dependency provenance |

The Used-in cell here lists only the flagged targets, not every place the
package is used. This is how an elected copyleft branch surfaces in the output:
the leaking workspaces are named.

### The Why column

The Why column carries [dependency provenance](../glossary.md#dependency-provenance)
for one row, folded over the same target set the row's Used-in cell names. Its
value is one of:

- `direct` — the package is a direct dependency in every one of those targets.
- An introducer chain, for example `pkg:npm/a@1 → pkg:npm/b@2 → pkg:npm/c@3`.
  The package is transitive, and this is the path that pulled it in. Long chains
  and wide multi-parent sets are truncated with a stable `(+N more)`.
- `—` — provenance is unknown for these targets. This is the
  [honest residual](../glossary.md#honest-residual): an em dash rather than a
  guess. Provenance is available for npm and Python; Terraform, Docker OS, and
  Bun show `—`.

### Cell escaping

Every value drawn from SBOM data or the policy file is escaped before it lands
in a cell, so a package name or licence string can never break the table or
forge Markdown structure. Pipes, backticks, and brackets are backslash-escaped;
angle brackets become HTML entities; any line break collapses to a space. A
policy-supplied title and preamble are the deliberate exception: they are author
prose, rendered as written.

## THIRD_PARTY_NOTICES.md

The attribution companion. The same header and regenerate command lead it,
followed by a paragraph explaining its grouped layout. Attribution is grouped to
keep the file small, roughly half a megabyte to a megabyte at repository scale,
rather than the several megabytes that repeating each licence text verbatim
would cost.

It has three parts, in order.

**Package attributions** (`## Package attributions`) — one `###` section per
package that has something concrete to attribute: extracted copyright lines, a
`NOTICE` file's contents, an author, or a verbatim licence text for a package
with no standard SPDX licence. Each section names the package as `name@version`,
states its licence, and then renders what it has. A package with nothing
concrete to attribute gets no section, an empty result rather than a fabricated
copyright. When no copyright line was found but an author is known, the author
appears as `Author: …`, which is an attribution and not a copyright claim.
`NOTICE` contents and verbatim texts render inside fenced code blocks whose fence
is computed long enough that the content cannot close it early.

**Packages with unknown licenses** (`## Packages with unknown licenses`) — a
list of every package whose licence could not be determined, each with no text
and a note saying so. Omitted when there are none.

**License texts** (`## License texts`) — the canonical appendix: one `###` entry
per SPDX identifier referenced by any normalized expression in the inventory,
sorted. Each entry carries the canonical SPDX licence text from the pinned
`spdx-license-list` data, followed by the marker
`(canonical SPDX text — package-specific copyright not located)` so that every
fallback to canonical text is auditable rather than silent. A referenced
identifier with no canonical text available, and any SPDX licence exception, are
each flagged with a line directing the reader to the package's own licence
files.

## The CycloneDX export

Written only when you pass `--cyclonedx <path>`. It is a [CycloneDX](../glossary.md#cyclonedx)
1.6 JSON document of the merged, policy-annotated inventory: the same model the
Markdown is rendered from, in the machine-readable interchange format.

The document is minimal by intent. The top level carries `bomFormat`,
`specVersion` (`"1.6"`), `version`, a `metadata.tools` block naming
`licenses-tool`, and the `components` array. It omits `serialNumber` and
`metadata.timestamp`, the two fields that would otherwise change on every run, so
a regenerated export is byte-identical and `check` can still compare it. Both
omissions are schema-valid: CycloneDX 1.6 makes those fields optional.

Each component is a `library` with `type`, `name`, `version`, `purl`, and a
`bom-ref` equal to the purl. Two optional keys follow when they have content:

`licenses` carries the finding. A normalized expression emits a single
expression entry, `[{ "expression": "MIT OR Apache-2.0" }]`. When there is no
expression, the raw [license claims](../glossary.md#license-claim) emit named
entries, `{ "license": { "name": "Public Domain" } }`. A package with neither
omits the key. OS-scope unrecognized tokens are appended as additional named
entries, so the export never drops what the Markdown shows in its `(+ …)` suffix.

`properties` carries provenance and verdicts as `{name, value}` pairs. CycloneDX
allows duplicate property names, which is how one package records several
occurrences cleanly. The per-component property names:

| Property name | Value | Emitted |
| --- | --- | --- |
| `licenses-tool:used-in` | a target | once per [occurrence](../glossary.md#occurrence) |
| `licenses-tool:scope:<target>` | `dev` or `prod` | once per occurrence |
| `licenses-tool:verdict:<target>` | the verdict status (`ok`, `warn`, `fail`, `suppressed`) | once per matching verdict, policy runs only |
| `licenses-tool:rule:<target>` | the [policy lane](../glossary.md#policy-lanes) rule | once per matching verdict, policy runs only |

The determinism guarantees: components are sorted by purl; the JSON is indented
two spaces with exactly one trailing newline; `JSON.stringify` is the only
encoder, so the output is LF-only and no hand-built string fragment can drift.
Top-level keys are emitted in a fixed order rather than alphabetized, so
`bomFormat` is first.

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": { "tools": { "components": [{ "type": "application", "name": "licenses-tool" }] } },
  "components": [
    {
      "type": "library",
      "name": "expr-pkg",
      "version": "3.0.0",
      "purl": "pkg:npm/expr-pkg@3.0.0",
      "bom-ref": "pkg:npm/expr-pkg@3.0.0",
      "licenses": [{ "expression": "MIT OR Apache-2.0" }],
      "properties": [
        { "name": "licenses-tool:used-in", "value": "apps/a" },
        { "name": "licenses-tool:scope:apps/a", "value": "prod" }
      ]
    }
  ]
}
```

## The committed sidecars

Two JSON files are committed to the repository alongside the inventory. Both
follow the same determinism contract (sorted keys, two-space indent, LF, a
trailing newline, no timestamp), so they diff cleanly and `check` can compare
them byte-for-byte.

`enrichment-cache.json` records the licences fetched from registries during
[enrichment](../glossary.md#enrichment-and-the-enrichment-cache). It is keyed by
the verbatim purl and committed on purpose, not gitignored, because it lets
[`check`](../glossary.md#the-gate-check) run with no network. `generate` reads
it, fetches on a miss, and writes the results back, including negative entries,
so a package known to have no registry licence is never re-fetched. `check` only
reads it. Each entry records the raw registry licence string (or null), which
registry answered, and whether the package is resolvable. `generate` writes the
file only when a run fetches at least one new licence; a warm run that satisfies
every lookup from the cache leaves it untouched.

`docker-os-sbom.json` is the operating-system package inventory for the Docker
base images, the [`scope:os`](../glossary.md#scope-app-and-os) merge input. It is a
minimal CycloneDX-shaped document holding `bomFormat`, `specVersion`,
`components`, and a `dockerImages` array pinning each scanned image to its
content digest, and nothing else. It is **not** written by `generate`. It is
produced by the maintainer-only `generate-docker-sbom` subcommand, the only path
in the tool that touches Docker or syft, and committed by hand. `generate` and
`check` never run Docker; they read these committed bytes as one more merge
input. The digest pin is why the file carries no timestamp: the image is
identified by content, which is stable.

```sh
# Maintainer-only: scan the configured images and write the OS sidecar
bun run src/cli.ts generate-docker-sbom --image postgres:18 --image nginx:stable-alpine
```

## Related

- [Getting started](../getting-started.md) — a first run that produces these files.
- [Glossary](../glossary.md) — the terms used throughout this page.
- [Data model](../explanation/data-model.md) — the in-memory model these
  artifacts are rendered from.
- [Data flow](../explanation/data-flow.md) — where rendering sits in the
  pipeline, after merge, enrich, and normalize.
