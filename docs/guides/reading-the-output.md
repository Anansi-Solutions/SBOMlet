# Reading the output

This guide is for the compliance reviewer: the person who opens
`THIRD_PARTY_LICENSES.md` after a run and has to decide what, if anything, to do
about it. It walks the document top to bottom, every block and every table
column, and then takes one flagged dependency through triage end to end.

You don't need to read the tool's code to use this page. If you're tuning the
rules that decide what gets flagged, that's the
[writing-policy guide](./writing-policy.md). If you're setting the tool up for
the first time, start with [`getting-started.md`](../getting-started.md).

A `generate` run writes two documents you read by hand. This guide covers them
in order:

- `THIRD_PARTY_LICENSES.md` is the inventory and the gate report. This is the one
  you read.
- `THIRD_PARTY_NOTICES.md` is the attribution companion: copyright lines and full
  license texts. You consult it for a specific package; you rarely read it
  through.

## The shape of the licenses document

`THIRD_PARTY_LICENSES.md` is generated in a fixed order, so you always know
where to look. From the top:

| Block | What it answers |
| --- | --- |
| Title and header | What this is, and the one command that regenerates it |
| Package counts | How big the inventory is, and how it breaks down |
| `## Problematic licenses` | What is failing the gate right now, and what is only being warned about |
| `## Copyleft and special notices` | Which packages carry a [copyleft](../glossary.md#copyleft) obligation you might owe on |
| `## Imprecise licenses` | Which licenses the tool couldn't pin to a precise id, and wants a human to resolve |
| `## Containers` | Every analyzed container, and whether it renders production or development-only |
| `## Production dependencies` | The full inventory of everything you ship, including each production container's packages |
| `## Development-only dependencies` | The full inventory of build- and test-time-only packages, including each development container's packages |

The header is a comment that names the regenerate command instead of a date.
There is no timestamp anywhere in the file. A date would change on every run, and
[`check`](../glossary.md#the-gate-check) could never tell a real change from the
clock advancing. To know whether the file is current, run `check` rather than
looking for a date.

The `## Problematic licenses` and `## Copyleft and special notices` sections
appear only when the document was generated with a policy. Without one, the tool
inventories the dependencies but does not judge them, so there is nothing to
flag.

## The package counts

Right under the header is a short list:

```text
**Package counts:**

- Total packages: 3946
- apk: 71
- deb: 239
- npm: 3503
- pypi: 114
- terraform: 19
- Production packages: 2248
- Development-only packages: 1388
- Container packages: 310
- Unknown license: 42
```

The first line is the total distinct
[package entries](../glossary.md#package-entry) in the inventory. The lines that
follow it, before "Production packages", are per-ecosystem counts, one per
[purl](../glossary.md#purl) type the scan found.

The next three lines partition that total exactly:

- Production packages ship somewhere. A single shipped use is enough to count a
  package here, because only what you ship carries a distribution obligation.
  This is the conservative side of the
  [development-only / production](../glossary.md#development-only-and-production)
  split.
- Development-only packages are ones whose every use is a dev dependency: build
  tools, test runners, and the like.
- Container packages come from inside a scanned Docker image — its full
  contents, the base-image (OS) layer and any application packages layered on
  top of it. They are counted on their own because a package that also ships
  at the application level keeps its production/development-only
  classification there instead; which container each one came from, and
  whether it is base-image or application content, is what `## Containers`
  and its per-container subsections show.

Production plus development-only plus container packages equals the total. The last line,
**Unknown license**, is a separate tally that cuts across all three: it counts
packages where the tool could determine no license at all. An
[imprecise](../glossary.md#imprecise-family) license, such as `BSD` with no
clause, is *not* unknown. It's a present-but-vague finding, counted with the rest
and surfaced in its own section, so the unknown count and the imprecise section
never overlap.

## Problematic licenses: the gate report

Read this section first when you're triaging. It tells you what is stopping the
build and what is only being warned about.

It has two parts.

### The blocking table

Every dependency with a `fail` [verdict](../glossary.md#verdict) appears here.
These are the ones that make the gate exit non-zero. When there are none, the
whole table is replaced by a single line:

```text
## Problematic licenses

✅ No blocking policy violations.
```

When there are failures, you get a table whose columns wrap the usual package
columns in the gate's reasoning:

| Column | What it tells you |
| --- | --- |
| Severity | Always `fail` here — this table is blocking failures only |
| Rule | The [policy lane](../glossary.md#policy-lanes) that decided the failure, e.g. `denied[0]` or `default:copyleft` |
| Name, Ecosystem, Version | Which package, and which ecosystem it came from |
| License | The [finding](../glossary.md#license-finding) — the SPDX expression the tool concluded |
| Used in | The [targets](../glossary.md#target) where this failure applies, deduplicated and sorted |
| Why | The [provenance](../glossary.md#dependency-provenance): how this package got into those targets |
| Reason | The human-readable explanation the policy attached to the rule |

One row is one (package, rule, reason) group, so a package that fails the same
rule in several workspaces is a single row with every workspace named in
**Used in**. The **Rule** and **Reason** columns together tell you why the
policy decided this; start there, then read **Why** to see how the package got
in.

### The non-blocking roll-up

Below the blocking table, or below the ✅ line, a single italic line summarizes
everything that was flagged but *not* failed:

```text
_Non-blocking: 201 copyleft warning(s), 69 unknown warning(s) (dev/os-downgraded or suppressed). See the sections below._
```

These are `warn` verdicts. They don't fail the gate. They're things the policy
chose to surface rather than block: a copyleft package that's development-only,
an OS-scope copyleft satisfied by shipping the base image, an unrecognized
license the policy treats as a warning. The line counts them by coarse category
(copyleft, unknown, deny, other) so you can see the size of each pile. The detail
lives in the sections below, copyleft warnings in the copyleft section and
unknown ones in the unknown-license parts of the notices.

If this line is absent, there were no warnings at all.

A package that fails here never repeats in the Copyleft section below — you
find it in exactly one of the two, Problematic or Copyleft, never both. It
still keeps its row in its Production/Development-only table, or its
container's own subsection, so the full inventory is always complete; only the
narrative sections dedup. This table is also where an AGPL SYSTEM package
(base-image content — `deb`, `apk`, `rpm`, `alpm`) always shows up: even in a
container whose ordinary GPL/LGPL packages are only warnings,
`default:agpl-container` fails unconditionally, because AGPL's network-copyleft
obligation reaches server-side use. An AGPL package an application layer
installed into the image fails here too, but as an ordinary `default:copyleft`
failure — see [Containers](#containers) below for why the two are judged
differently.

## Copyleft and special notices

This section lists every package carrying a [copyleft](../glossary.md#copyleft)
obligation in at least one workspace that the policy hasn't suppressed. Copyleft
licenses (GPL, LGPL, AGPL, MPL) can require you to release your own changes under
the same terms when you distribute, so a reviewer reads this section closely.

A container's own base-image (system-package) copyleft never appears here,
whatever its verdict — the expected GPL/LGPL in a Debian or Alpine layer lists
only under that container's own System-packages table (below `## Containers`),
not repeated in this narrative section. An application-ecosystem package an
application layer installed into the image is not covered by that exclusion:
a dev-downgraded copyleft warning on one rows here like any other copyleft
warning. Nor does a package already shown in Problematic licenses above; the
two sections never overlap.

It opens with a one-line summary sentence, then the suppressed-workspaces list
when there is one:

```text
The packages listed below carry copyleft or special license obligations in at
least one non-suppressed workspace.

Workspaces that are themselves distributed under a copyleft license are
suppressed by policy:

- apps/scratch (AGPL-3.0-only) — apps/scratch and its scratch-editor submodule
  are themselves distributed under AGPL-3.0-only; the bundled scratch-* AGPL
  dependencies … impose no additional obligation within this workspace.
```

Each line is a workspace your policy declared as already shipping under a
copyleft license. Inside such a workspace, an in-family copyleft dependency adds
no new obligation, so it's intentionally not flagged. The text after the em-dash
is the reason the policy author wrote, which is your audit trail for why the
suppression is justified.

Then comes the table. A package is in it when it has a copyleft `fail` or `warn`
verdict, meaning the policy's copyleft rule fired and was not suppressed. The
columns are the same as the inventory tables plus a **Why** column:

| Column | What it tells you |
| --- | --- |
| Name, Ecosystem, Version | The package |
| License | The copyleft finding |
| Used in | Only the workspaces where the obligation actually applies — not every place the package is used, only the flagged, non-suppressed ones |
| Why | How the package got into those workspaces |

The **Used in** cell is narrower than it looks: it names only the targets where
this package was flagged, which is how the document shows you the workspaces that
carry the obligation. A package used in ten workspaces but suppressed in nine
names one workspace here.

## Imprecise licenses

```text
## Imprecise licenses (review / disambiguate)

These packages report an ambiguous license family that was NOT guessed to a
precise SPDX id. Disambiguate each via a policy `[[clarify]]` override.

| Name | Ecosystem | Version | License | Used in |
| --- | --- | --- | --- | --- |
| appnope | pypi | 0.1.4 | BSD (imprecise) | apps/jupyter |
| arrow | pypi | 1.4.0 | Apache (imprecise) | apps/jupyter |
```

Each row is a package whose source named the license only by family, "BSD" or
"Apache", with no clause or version. The tool does not guess which precise
[SPDX](../glossary.md#spdx) id that is, because `BSD` could be `BSD-2-Clause` or
`BSD-3-Clause`, and guessing would put a wrong obligation in your inventory. It
records the family as given, marks it `(imprecise)`, and asks you to pin it down.
This follows the tool's [honest-residual](../glossary.md#honest-residual)
approach: a visible gap you can act on rather than an invented value.

The action for each row is a [`[[clarify]]`](../glossary.md#policy-lanes)
override in your policy that states the precise license. The
[writing-policy guide](./writing-policy.md) shows how. The section disappears
once nothing is imprecise.

## The inventory tables

Two tables hold the complete app-scope inventory. Every application package
appears in exactly one of them:

- Production dependencies are everything you ship.
- Development-only dependencies are build- and test-time packages only.

Both always render, even when empty, so the document's shape is stable. They
share five columns:

| Column | What it tells you |
| --- | --- |
| Name | The package name |
| Ecosystem | The purl type — `npm`, `pypi`, `terraform`, `deb`, `apk`. This is what tells `react` apart from a same-named package in another ecosystem |
| Version | The exact version in the inventory |
| License | The finding: a precise SPDX expression, a `<family> (imprecise)` marker, or `unknown` |
| Used in | Every [target](../glossary.md#target) the package is used in |

The inventory tables do **not** carry a **Why** column. Provenance is shown only
in the problematic and copyleft tables, where it answers a compliance question.
Adding it to the full inventory would be noise. How an ordinary production
package got pulled in is a question you ask when it's flagged, not for every
row.

## Containers

Right after Imprecise licenses, `## Containers` lists every analyzed container
once:

```text
## Containers

| Container | Classification | Packages |
| --- | --- | --- |
| docker:services/backend/Dockerfile | production | 214 |
| docker:tools/lint/Dockerfile | development | 96 |
```

Classification is `production` unless a policy `[[docker.development]]` entry
marks that container's Dockerfile identity development-only — see the
[writing-policy guide](./writing-policy.md#mark-a-container-development-only).
For a base-image (system) package it decides only where the container's
packages are listed below, never a verdict: a routine system copyleft package
still downgrades or gates per `[os_dependencies]` regardless of the half it
renders under, and an AGPL system package still fails unconditionally either
way. For an application-ecosystem package baked into the image, it also
decides the verdict: exactly like marking a lockfile dependency a
`devDependency`, a copyleft fail becomes a warning once the container is
marked. This is the reason a `pip`- or `npm`-installed package inside an
image can be a blocking copyleft while a `deb` package right next to it,
carrying the same license, is routine — one is code an application layer
chose to install, the other is the base distribution the image runs on, and
the report holds them to the standards their own ecosystem implies.

Each container's own packages then appear as a `### Container: docker:<source>`
subsection right after the app table of the half it classifies into —
`## Production dependencies` for a production container,
`## Development-only dependencies` for a development one. A container's
subsection is its complete package inventory — including a package that also
has an application occurrence elsewhere — split into two four-column tables,
no **Used in** since every row is already scoped to that one image:

- **System packages** — base-image content: `deb`, `apk`, `rpm`, `alpm`.
- **Application packages** — everything else, installed by an application
  layer into the image.

A table with no rows is omitted, so a base-image-only container shows just
System packages. Both tables share the same two columns beyond Name and
Version:

| Column | What it tells you |
| --- | --- |
| Name, Ecosystem, Version | The package |
| License | The finding, same rules as the inventory tables above |

A note on the **License** column for a container row: it often shows a long
`AND`-joined expression, sometimes with a `(+ …)` suffix. The expression is
every license the base distribution recorded for that package. The `(+ …)`
suffix lists license tokens the tool recognized but couldn't map to a precise
SPDX id, surfaced rather than dropped. A package the scan also finds at the
application level still gets a row in its container subsection — it keeps its
application scope in the inventory table above too, so both views stay
complete.

### The Why column, read in detail

Where it appears, in the problematic and copyleft tables, the **Why** column
answers one question: how did this package end up in the workspaces named in
**Used in**? It takes one of three forms:

- `direct` means your project declares this package itself, in every flagged
  workspace.
- An introducer chain like `pkg:pypi/copier@9.11.3 → pkg:pypi/jinja2-ansible-filters@1.3.2`
  means the package is [transitive](../glossary.md#dependency-provenance), and the
  chain is the path from a thing you declared down to it. A very long path or a
  wide set of parents is truncated with a stable `(+N more)`.
- `—` means the tool has no usable provenance for this package in these
  workspaces. This is the expected value for container packages, Terraform
  modules, and bun, not a failure. [Provenance](../glossary.md#dependency-provenance)
  is available for npm (from the Yarn-4 plugin) and Python (from `poetry.lock`);
  elsewhere you'll see the dash.

The **Why** cell is always scoped to the same workspaces as **Used in**. It never
borrows a "direct" or a chain from a different workspace where the package happens
to be used, so what you read is true of the flagged workspaces and only those.

## The notices companion

`THIRD_PARTY_NOTICES.md` is the attribution bundle. You don't read it top to
bottom; you open it when you need the copyright lines or the full license text
for a specific package, for instance when assembling an attribution file for a
release. It has three parts:

- Package attributions are one section per package that has something concrete to
  attribute: copyright lines pulled from its files, the contents of its `NOTICE`
  file, or its verbatim license text when the license isn't a standard SPDX one.
  A package with nothing real to attribute gets no section rather than a
  fabricated one.
- Packages with unknown licenses are the same packages the counts block tallied
  as unknown, listed with no text, so the gap is explicit.
- License texts are one canonical text per SPDX id referenced anywhere in the
  inventory. Texts are grouped here instead of repeated per package, which keeps
  the file to roughly a megabyte rather than several. Each canonical entry is
  marked `(canonical SPDX text — package-specific copyright not located)` so you
  can tell a grouped standard text from a package's own.

## Triage: from a flagged dependency to a decision

Here is the end-to-end path for one flagged dependency. Suppose `check` exits `1`
and the build is red.

**1. Find what failed.** Open `THIRD_PARTY_LICENSES.md` and go to
`## Problematic licenses`. The blocking table lists every `fail`. Pick the row
you're triaging.

**2. Read its Why and its Reason.** The **Rule** and **Reason** columns tell you
which policy lane decided the failure and the explanation attached to it. The
**License** column shows the finding. The **Why** column shows how the package
got in: `direct`, a chain, or `—`.

**3. Confirm the obligation.** If you need the actual license terms, look the
package up by name in `THIRD_PARTY_NOTICES.md`: the package attribution section
and the canonical text in the License texts appendix give you the full license.

**4. Decide.** There are two outcomes, and which one is right depends on what you
found.

The first is to remove or replace the dependency. If the **Why** shows it's
`direct`, you declared it and can drop or swap it. If it's transitive, the chain
names the parent you'd need to change or replace. Regenerate, and the row
disappears.

The second is to add the right policy lane. If the dependency is acceptable and
the failure is the policy being stricter than your situation warrants, encode
that decision in `.sbomlet.policy.toml`. The lane depends on the case:

- the license is fine to allow: a
  [`[[compatible]]`](../glossary.md#policy-lanes) rule;
- the finding is [imprecise](../glossary.md#imprecise-family) and you can state
  the precise license: a [`[[clarify]]`](../glossary.md#policy-lanes) override;
- the package is copyleft inside a workspace that itself ships under that copyleft
  license: a [workspace copyleft suppression](../glossary.md#policy-lanes).

The [writing-policy guide](./writing-policy.md) walks through each lane. Every
override you add takes a written reason, because the policy file is your audit
trail. The reason is what shows up in the **Reason** column and the suppressed
list the next time someone reads the document.

**5. Regenerate and re-check.** After either fix, run the generate task, review
the diff to confirm the row is gone, commit, and run `check`. A `0` exit means
the failure is resolved and the committed documents are current.

Whatever you choose, the document records it: a removed dependency vanishes from
every table, and a policy decision shows up with its reason wherever the package
appears, so the next reviewer can see what was decided and why.

## Where to go next

- [writing-policy.md](./writing-policy.md) — how to write the `[[deny]]`,
  `[[clarify]]`, `[[compatible]]`, and suppression lanes the triage flow points
  at.
- [getting-started.md](../getting-started.md) — the first-run walkthrough, the
  exit codes, and the CI wiring.
- [glossary.md](../glossary.md) — the definitions behind the terms used here.
