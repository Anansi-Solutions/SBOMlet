# Writing your policy

This guide is for the policy author — the person who writes
`.sbomlet.policy.toml`, reads the generated documents, and decides what to do
about a flagged dependency.

You will normally arrive here from a red gate. `check` names the package, the
occurrence, and the rule that decided the verdict;
[reading the output](./reading-the-output.md) routes each flagged row to the
recipe below that resolves it. Write the entry, regenerate, run `check` again.

Each section is a recipe: the situation, a minimal working entry, and the one
thing most likely to trip you up. Skip to the one you need. Every field, every
validation rule, and the full precedence table live in the
[policy reference](../reference/policy.md); this page only tells you when to
reach for which lane and shows you the shape of a working entry.

Every override states why it exists: `[[compatible]]` and `[[clarify]]` choose
from a closed set the tool can check, and `[[deny]]` and suppression carry free
text. Validation rejects a value outside the set, and a missing or empty free
text, because that is the audit trail a reviewer reads later. The rest of what
validation checks is
[policy.md#validation](../reference/policy.md#validation).

Start from the shipped [`policy.example.toml`](../../policy.example.toml),
which carries a working entry for each table with the rules inline as
comments. Copy it to `.sbomlet.policy.toml` at your repo root and pass it with
`--policy`:

```sh
task sbomlet:generate POLICY=.sbomlet.policy.toml
```

Without `--policy` the tool only inventories licences. With it, every package
gets a [verdict](../glossary.md#verdict) — `ok`, `warn`, `fail`, or
`suppressed` — and the [gate (`check`)](../glossary.md#the-gate-check) fails
the build on any `fail`.

## How the lanes decide (read this once)

For one package in one occurrence, the engine consults the lanes in a fixed
order and takes the first that decides: deny, then clarify, then compatible
(package, then licence), then the target-compatibility lane (only when a
declared `[target]` profile governs the occurrence), then workspace
suppression, then the category default. The full table, and why deny is
terminal, is [policy.md#precedence](../reference/policy.md#precedence).

Within one lane, entries are consulted in file order and the first whose match
and scope both hold decides. A narrow entry written after a broad one that also
matches never runs, so put the specific entry first.

## Correct a wrongly-detected or imprecise licence

A package reports a licence that is wrong, missing, or named only by family
("BSD" with no clause), and you know the right answer. Record what each source
reported, and the answer you stand behind:

```toml
[[clarify]]
name = "jsonify"
version = "0.0.1"
detected = { registry = "Public Domain", intensive = false }
justification = "license-not-found"
expression = "Unlicense"
evidence = ["node_modules/jsonify/README.md"]
comment = "The README dedicates the package to the public domain; mapped to Unlicense deliberately."
```

Copy the `detected` values out of the report rather than typing what you expect
them to be. `registry` is the quick answer — the package's own metadata plus
whatever registry enrichment resolved, often not SPDX at all — and `intensive`
is the in-depth source scan's reading. Record `false` for a source that reports
nothing; at least one of the two is required. The entry applies only while every
source you recorded still reports what you wrote down, so a later relicence
fails the gate loudly instead of being masked by an old answer.

`justification` says why your expression is preferred over what detection
reports, chosen from a fixed list so the tool can check the claim. Pick it from
what the two sources actually did: the scan resolving a vague declared label is
`scan-more-precise`, the scan reading files that do not govern the package is
`scan-overdetection`, metadata naming licences the scan cannot see is
`declared-more-complete`. When the two genuinely contradict each other and
neither reading is wrong, `contradictory-claims-recorded` is the sanctioned
fallback. All seven values, and what each one asserts, are in
[policy.md#justification](../reference/policy.md#justification--the-closed-set).

`evidence` is an optional list of files or URLs a reader can check, recorded
verbatim: the tool never fetches or verifies it. `comment` carries what the
justification cannot.

For an [imprecise family](../glossary.md#imprecise-family) — pinning down which
`BSD` you mean — record the family the source reports:

```toml
[[clarify]]
name = "some-package"
detected = { registry = "BSD", intensive = "BSD-3-Clause" }
justification = "scan-more-precise"
expression = "BSD-3-Clause"
```

The gotcha: a justification is checked, not just filed. If the current signal
disproves what the value asserts — you claimed the package offers a choice and
the scan shows the licences were joined, say — the entry fails the gate as
`clarify:invalid[i]`, and the failure names where the entry can go instead. A
justification whose subject has simply gone away is different: the entry has
become unnecessary rather than wrong, and nothing fails.

One entry can cover a whole family of packages with `pattern` instead of `name`,
and several pinned versions with a `version` list. The tool also ships curated
clarifications for commonly-ambiguous projects, such as the Jupyter/IPython BSD
stack — yours wins on any conflict. Every field and the validation rules:
[policy.md#clarify](../reference/policy.md#clarify).

### When the two detectors disagree

A `conflict:scancode` row means the in-depth scan read a different licence than
the quick check, and the tool will not pick a side for you. Only an entry that
records the `intensive` source settles it: that is the entry stating which
reading you stand behind. Recording `registry` alone says nothing about the
scan, so the disagreement stays open and the gate keeps asking.

## Move your clarifications into their own file

Your policy has become mostly `[[clarify]]` entries, and every dependency bump
churns them while the rest of the file sits still. A top-level key moves them
out:

```toml
clarifications = ".sbomlet.clarifications.toml"
```

That file holds `[[clarify]]` tables and nothing else; any other key is
rejected naming it. The path is repo-relative, and a declared file that is
missing or unreadable is a configuration error rather than a policy that
quietly runs as though it had said nothing.

Two things change once entries live there. Citations become `clarifications[j]`,
numbered within that file, so a verdict tells you which file to open as well as
which table. And a `[[clarify]]` in the policy proper that names the same
package decides first, shadowing the imported entry — deliberately, so a local
decision can take precedence without editing the imported file.

The gotcha: keep prose about an entry in its `comment` and `evidence` fields,
not in `#` lines above it. The file is machine-maintained — the refresh below
rewrites it whole — so a comment line would not survive. Full semantics:
[policy.md#a-separate-clarifications-file](../reference/policy.md#a-separate-clarifications-file).

## Refresh your clarifications after an upgrade

After a dependency bump some entries cover versions that are gone, some new
versions want the same judgment, and some entries have nothing left to correct
because upstream fixed its metadata. The `refresh-clarifications` subcommand
audits the entries you already have and tells you which is which, reading only
the committed caches, so it answers the same on every machine.

It reports one line per finding. `EXTEND` means an entry's recorded detections
still hold for a version it does not yet list, so that version can join the
list. `REVIEW` means something reads differently there and you have to look.
`FINISHED` means every package an entry governs has caught up with it.
`SHADOWED` means a policy entry decides ahead of an imported one. With
`--write`, the two edits that take no judgement — dropping a finished entry and
adding an extendable version — are applied to the clarifications file; the
policy proper is only ever suggested against. How to run it, and the full set
of labels: [cli.md#refresh-clarifications](../reference/cli.md#refresh-clarifications).

## Allow a licence pattern or an exact package

A licence is fine for your project even though it is not permissive by default,
or one specific package is reviewed and accepted. Use `[[compatible]]`.

```toml
[[compatible]]
match = "license"
pattern = "MPL-2.0"
rationale = "license-reviewed"
where = ["/"]
comment = "Weak copyleft; compatible under AGPL-3.0 and Apache-2.0."
```

```toml
[[compatible]]
match = "package"
name = "@img/sharp-win32-x64"
version = "0.34.5"
as-dependency-of = ["image-pipeline"]
rationale = "license-reviewed"
where = ["apps/media"]
comment = "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; the LGPL obligations are reviewed and accepted for these prebuilt binaries."
```

`rationale` comes from a fixed list, so the tool can check the claim; `comment`
carries what the list cannot. `where` is required — state which occurrences you
judged, or `["/"]` for every one of them. `version` is required too, so a silent
relicense in a new release cannot inherit the acceptance; the one exception is an
entry scoped entirely to a container os-scope (`where` all `docker:…`), whose
base-image versions you do not control. One entry can cover a family of packages
with `pattern` instead of `name`, or an explicit bundle of disparate ones that
share these fields with a `packages` list. Every field, the rationale list, and
the `AND`-rejection rule:
[policy.md#compatible](../reference/policy.md#compatible).

### Naming the parents honestly

At package level `as-dependency-of` is required too: the packages whose use of
this one you judged, by display name, or the reserved token `self` for your own
software. A build tool's copyleft is fine while a build tool pulls it in; the
same package reaching your shipped code through another chain is a different
question, and one entry should not silently answer both.

On a target that has a dependency graph — a Yarn workspace, a poetry project —
the tool checks the claim against the chains it recorded, and `self` means the
direct edge from your project and nothing else. A target without a graph, such
as a container image's OS layer, has no chains to check: `self` is the only
value allowed there, and it accepts every occurrence the entry's `where`
reaches. That is an unscoped acceptance. Write it knowing that, and let `where`
do the scoping — usually
[the one image you reviewed](#accept-a-package-only-where-you-reviewed-it).

Naming a parent other than `self` at a target with no graph is rejected before
any verdict, as is naming a package no node of that target's graph carries.
Both depend on what the scan found, so a policy that was fine yesterday can be
rejected today — adding a first target without a dependency graph is enough.
Your own workspace members count as graph nodes even though they never appear
in the inventory: a package arriving through one is named after that member,
never `self`.

## Split an acceptance the chains contradict

The gate fails with `compatible:voided[i]` and names a chain. One package the
entry accepts reaches your project through a chain passing none of the parents
you named, so what the entry claims is not what the scan sees, and the tool
refuses to apply any of it: every package the entry governs at that target
fails, including the ones that were never the problem.

Say a bulk entry accepts a family of codecs as used by one toolkit:

```toml
[[compatible]]
match = "package"
pattern = "@acme/codec-*"
version = "2.1.0"
as-dependency-of = ["media-toolkit"]
rationale = "license-reviewed"
where = ["apps/media"]
```

and `@acme/codec-webm` turns out to arrive through `web-player` instead. There
are two honest fixes. If you also reviewed the player's use of it, add
`"web-player"` to the entry's `as-dependency-of` — but only if you did, since
the list is the claim. Otherwise split the entry, and put the narrower one
first so it decides before the family pattern reaches that package:

```toml
[[compatible]]
match = "package"
name = "@acme/codec-webm"
version = "2.1.0"
as-dependency-of = ["web-player"]
rationale = "license-reviewed"
where = ["apps/media"]
comment = "The player bundles this codec; its obligations were reviewed for that use."

[[compatible]]
match = "package"
pattern = "@acme/codec-*"
version = "2.1.0"
as-dependency-of = ["media-toolkit"]
rationale = "license-reviewed"
where = ["apps/media"]
```

Splitting states the same information so that each part is true. Two cases void
nothing, whatever else the chains say: a package your project declares directly
is covered by `self` and by nothing else, and an occurrence the scan recorded no
introduction for is covered by no parent at all — the entry decides nothing
there, and the occurrence falls through to the lanes below. The full semantics:
[policy.md#as-dependency-of](../reference/policy.md#as-dependency-of--whose-use-you-judged).

## Accept a package only where you reviewed it

Your repo builds two images, and you reviewed busybox in one image's OS
layer. A plain `[[compatible]]` entry would also accept it in the other,
unreviewed image. Add `where` to limit the rule to what you judged:

```toml
[[compatible]]
match = "package"
name = "busybox"
as-dependency-of = ["self"]
rationale = "os-package-unmodified"
where = ["docker:a/Dockerfile"]
```

`where` narrows, never widens. It is required precisely because the everywhere
case, `["/"]`, is rarely what a per-image review means to say, and writing it
out makes that a decision rather than an omission. Prefer the narrowest identity
you actually reviewed, usually the full `docker:<source>` of one image, and
check a scoped rule against the Used-in column: an entry matching nothing prints
an unused-rule warning. Target-matching rules and
both target forms (`docker:<source>`, workspace path):
[policy.md#compatible](../reference/policy.md#compatible).

## Adopting a target

Instead of hand-authoring `[[compatible]]`/`[[deny]]` entries for every
dependency licence, declare your own software's licence and how it is
used, and the tool decides compatibility against a vetted licence
compatibility matrix for you.

```toml
[target]
license = "MIT"
network = false
distribution = "external"
```

All three keys are mandatory together — `license` (a single FOSS SPDX id
covered by the OSADL compatibility matrix's own rows, or the literal
`"proprietary"`), `network` (whether you're deployed on a network — gates
the AGPL/section-13 obligation class), and `distribution` (`"external"` or
`"internal"` — gates the ordinary distribution-triggered copyleft class).
A valid SPDX id the matrix has no row for is rejected at parse time; govern
those packages with per-package `[[compatible]]` rules instead. See
[policy.md#target](../reference/policy.md#target) for the full field
reference.

### What changes, and what doesn't

Adopting a target does not retire your existing hand-tuned policy.
`[[deny]]`, `[[clarify]]`, and `[[compatible]]` still decide first — they
sit above the target lane in
[precedence](../reference/policy.md#precedence) — so a package you already
reviewed and accepted keeps its `compatible[i]` verdict unchanged. What
changes is everything BELOW those lanes: a
`[[workspace.copyleft_suppressed]]` entry inside a workspace the target now
governs is **superseded** — the target lane decides that occurrence
instead, and `generate`/`check` print a notice naming both the suppression
entry and the target that supersedes it, so nothing goes silent. Once you
confirm the overlap notice reads as expected, that suppression entry is
prunable: it can never fire again while the target governs the same
occurrence. The tool also warns, unused-entry style, on a
`[[target.workspace]]` entry whose path matches no occurrence in the run —
the same dead-rule posture as an unused `[[compatible]]` rule.

### The first run is a review session

Adopting a proprietary target is noisy at first. Every weak-copyleft dependency
(LGPL, MPL, and similar "restricted" licences) warns — `target:boundary` —
until you record a scoped `[[compatible]]` boundary confirmation for it. A
weak-copyleft licence's obligations depend on how you link the dependency in,
which the vetted matrix data cannot see, so the tool asks a human to confirm
the boundary once per package rather than guessing. There is no class-level
"accept every weak copyleft" switch; each confirmation is its own line in the
audit trail.

```toml
[[compatible]]
match = "package"
name = "some-lgpl-lib"
version = "3.0.0"
as-dependency-of = ["self"]
rationale = "license-reviewed"
where = ["apps/studio"]
comment = "Dynamically linked via its published API; the boundary satisfies LGPL-3.0-only's relinkability requirement."
```

### The declared profile must be true

The tool has no way to verify `network` or `distribution` against your actual
deployment, so it takes both as written. `network = false` with containerized
services is usually wrong, and the cost is specific: an AGPL dependency that
should fail under a network-deployed target folds into the ordinary copyleft
class instead, where `distribution = "internal"` can then hold it out of scope
(see the AGPL-container reconciliation in
[dependency-classification.md](../reference/dependency-classification.md#the-target-compatibility-lane)).
Declare the profile that matches reality, not the one that produces the
fewest warnings.

### A monorepo with divergent workspaces

Your project declares one project-wide target, but one workspace ships
under a different licence, or with a different deployment shape.
`[[target.workspace]]` overrides per field — declare only what diverges,
and the rest inherits from the project profile:

```toml
[target]
license = "MIT"
network = true
distribution = "external"

[[target.workspace]]
path = "apps/studio"
license = "AGPL-3.0-only"
reason = "apps/studio bundles an AGPL-licensed editor component and ships under AGPL-3.0-only itself, not the project's MIT licence."
```

`apps/studio`'s occurrences are now judged against an AGPL target instead
of MIT; `network`/`distribution` are inherited unchanged since this entry
doesn't override them. See
[policy.md#targetworkspace](../reference/policy.md#targetworkspace) for the
inheritance rules and the workspaces-only shape (declaring no project-level
profile at all).

## Allow a copyleft dependency inside a copyleft workspace

You ship one workspace under a copyleft licence, and it bundles dependencies
from the same family. Those add no obligation you don't already carry, so
stop flagging them there, and only there.

```toml
[[workspace.copyleft_suppressed]]
path = "apps/reporting"
license = "AGPL-3.0-only"
description = "apps/reporting is itself distributed under AGPL-3.0-only; its bundled AGPL dependencies are in-family copyleft and impose no additional obligations within this workspace."
```

This only suppresses a workspace, never a container — a container's copyleft
package needs a
[`[[compatible]]`](#allow-a-licence-pattern-or-an-exact-package) rule instead.
Field meaning, the family-aware check, and the path-matching rules are
[policy.md#workspacecopyleft_suppressed](../reference/policy.md#workspacecopyleft_suppressed).

## Deny a source-available licence or a named package

You want a licence — or one specific package — to fail the build
unconditionally, with no way to accidentally allow it back in. This is the
lane for source-available licences (BUSL, SSPL, Elastic) and use-restriction
riders that legally can't ship in a distributed artifact.

Deny by SPDX licence:

```toml
[[deny]]
match = "license"
pattern = "BUSL-1.1"
reason = "Business Source License 1.1 is source-available, not open source: it forbids production use until the change date and can never appear in a distributed THIRD_PARTY set."
```

Deny by exact package name, for a licence SPDX can't express:

```toml
[[deny]]
match = "name"
pattern = "redis"
reason = "Redis Source Available License has no registered SPDX id, so it is matched by package name. Use-restricted — cannot be redistributed."
```

Deny sees through an override: a `[[clarify]]` that rewrites the finding to
something benign still fails, because deny also checks the pre-override
observed value. BUSL-1.1, SSPL-1.0, and Elastic-2.0 are already denied by
default; to exempt one instead of fighting this lane, see
[policy.md#allow_source_available](../reference/policy.md#allow_source_available).
Both match modes and full validation: [policy.md#deny](../reference/policy.md#deny).

## Set how unknown, dev, and OS dependencies are handled

Three tables tune what the default lane does for whole categories, each
defaulting to `warn` so you can adopt the tool without failing on day one and
tighten later: unknown licences, development-only dependencies (build tools
and test runners you never ship), and Docker image packages (the base image
and whatever an application layer installed into it).

```toml
[unknown]
handling = "warn"
```

```toml
[dev_dependencies]
handling = "warn"
```

```toml
[os_dependencies]
handling = "warn"
```

The gotcha: `[os_dependencies]` only covers the OS package-manager allowlist
(`deb`, `apk`, `rpm`, `alpm`) — an npm or pypi package the image scan finds is
an application dependency wherever it lives, so it gates on
`[dev_dependencies]` and the normal copyleft rule instead, never this knob.
All three tables' `warn`/`fail`/`ignore` semantics, the AGPL and deny
carve-outs, and where `[os_dependencies]` gets its input:
[policy.md#unknown](../reference/policy.md#unknown),
[policy.md#dev_dependencies](../reference/policy.md#dev_dependencies),
[policy.md#os_dependencies](../reference/policy.md#os_dependencies).

## Set a document title and preamble

You want `THIRD_PARTY_LICENSES.md` to open with your own heading and an
introductory paragraph — a company name, a compliance statement, a link to an
internal policy.

```toml
[document]
title = "Third-Party Licenses — Acme Corp"
preamble = """
This inventory is generated automatically and reviewed before each release.
Questions about a listed dependency go to compliance@acme.example.
"""
```

`preamble` is rendered verbatim, unescaped, as author Markdown — write it as
you'd write any Markdown in your repo. Both keys, and that neither touches
the notices companion, are
[policy.md#document](../reference/policy.md#document).

## Exclude Dockerfiles you don't want built

Your repo has Dockerfiles you don't want the tool to build, such as a
fixture or a template that isn't a real image.

```toml
[docker]
ignore = ["docker/dev.Dockerfile", "ci/runner.Dockerfile"]
```

This only affects Dockerfile *discovery* (`generate-docker-sbom`) — the
everyday `generate` and `check` commands never discover Dockerfiles, so an
`ignore` glob has no effect on them. Glob rules and validation:
[policy.md#docker](../reference/policy.md#docker).

## Mark a container development-only

One of your Dockerfiles builds an image that only runs in CI — a lint
runner, a test harness — and never ships to a user, but its packages
currently render under `## Production dependencies`.

```toml
[[docker.development]]
source = "ci/**"
reason = "every image under ci/ only runs the test suite in the pipeline and is never published or shipped."
```

Don't mark a container development-only just to quiet a copyleft warning —
for an application-ecosystem package baked into the image, this
dev-downgrades its copyleft verdict too, exactly like marking a lockfile
dependency a `devDependency`. Use it only when the image genuinely never
reaches a user. The glob dialect, the SYSTEM-package placement-only
carve-out, and validation:
[policy.md#dockerdevelopment](../reference/policy.md#dockerdevelopment).

## Related pages

- [Reading the output](./reading-the-output.md) — which recipe above a
  flagged row wants, by the rule that decided its verdict.
- [Getting started](../getting-started.md) — a first run, end to end.
- [Policy reference](../reference/policy.md) — every table, field, and
  validation rule.
- [Glossary](../glossary.md) — every term a verdict can use.
