# Writing your policy

This guide is for the policy author — the person who writes `.sbomlet.policy.toml`, reads
the generated documents, and decides what to do about a flagged dependency.

Each section below is a recipe: the situation, a minimal working TOML entry, and
the one thing most likely to trip you up. Skip to the one you need. Every
field, every validation rule, and the full precedence table live in the
[policy reference](../reference/policy.md); this page only tells you when to
reach for which lane and shows you the shape of a working entry.

Every override needs a written `reason` (or, for suppression, a `description`)
— validation rejects a missing or empty one, because that text is the audit
trail a reviewer reads later. The rest of what validation checks is
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

All three keys are mandatory together — `license` (a single FOSS SPDX id,
or the literal `"proprietary"`), `network` (whether you're deployed on a
network — gates the AGPL/section-13 obligation class), and `distribution`
(`"external"` or `"internal"` — gates the ordinary distribution-triggered
copyleft class). See [policy.md#target](../reference/policy.md#target) for
the full field reference.

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

Adopting a proprietary target is intentionally noisy at first. Every
weak-copyleft dependency (LGPL, MPL, and similar "restricted" licences)
warns — `target:boundary` — until you record a scoped `[[compatible]]`
boundary confirmation for it. This volume is by design, not a defect: a
weak-copyleft licence's obligations depend on HOW you link the dependency
in, something the vetted matrix data can't see, so the tool asks a human to
confirm the boundary once per package rather than guessing silently. There
is no class-level "accept every weak copyleft" switch — each confirmation
is its own line in the audit trail.

```toml
[[compatible]]
match = "package"
name = "some-lgpl-lib"
reason = "Dynamically linked via its published API; the boundary satisfies LGPL-3.0-only's relinkability requirement."
```

### The declared profile must be true

The tool trusts your declared profile completely — it has no way to verify
`network` or `distribution` against your actual deployment. `network =
false` with containerized services is almost always wrong: a container is
reachable over a network far more often than not, and getting this wrong
silently defeats the AGPL scope-gating the flag exists to provide — an
AGPL dependency that should fail under a network-deployed target instead
folds into the ordinary copyleft class, where a permissive
`distribution = "internal"` profile could then hold it out of scope
entirely (see the AGPL-container reconciliation in
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
path = "apps/scratch"
license = "AGPL-3.0-only"
description = "apps/scratch is itself distributed under AGPL-3.0-only; the bundled scratch-* AGPL dependencies are in-family copyleft and impose no additional obligations within this workspace."
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

## Correct a wrongly-detected or imprecise licence

A package reports a licence that's wrong, missing, or named only by family
("BSD" with no clause), and you know the right answer.

The plain form replaces the finding unconditionally:

```toml
[[clarify]]
package = { name = "jsonify", version = "0.0.1" }
expression = "Unlicense"
reason = "Upstream declares the non-SPDX value 'Public Domain'; jsonify's README dedicates it to the public domain, mapped to Unlicense deliberately."
```

For an [imprecise family](../glossary.md#imprecise-family) — pinning down
which `BSD` you mean — add an `expects` precondition instead:

```toml
[[clarify]]
package = { name = "some-package" }
expects = "BSD"
expression = "BSD-3-Clause"
reason = "Confirmed BSD-3-Clause in the upstream LICENSE file."
```

`expects` is a staleness guard: the override applies only while the package's
observed licence still matches it, so a later relicense fails loudly instead
of silently keeping the old answer. The tool also ships curated
clarifications for commonly-ambiguous projects, such as the Jupyter/IPython
BSD stack — yours wins on any conflict. Both forms, the `expects` mechanics,
and validation: [policy.md#clarify](../reference/policy.md#clarify).

## Allow a licence pattern or an exact package

A licence is fine for your project even though it isn't permissive by
default, or one specific package is reviewed and accepted. Use
`[[compatible]]`.

```toml
[[compatible]]
match = "license"
pattern = "MPL-2.0"
reason = "Weak copyleft; compatible under AGPL-3.0 and Apache-2.0."
```

```toml
[[compatible]]
match = "package"
name = "@img/sharp-win32-x64"
version = "0.34.5"
reason = "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; the LGPL obligations are reviewed and accepted for these prebuilt sharp binaries."
```

Both forms accept the match everywhere unless you add `where` to narrow it —
see the next recipe. Pattern syntax, the `AND`-rejection rule, and both
modes' fields: [policy.md#compatible](../reference/policy.md#compatible).

## Accept a package only where you reviewed it

Your repo builds two images, and you reviewed busybox in one image's OS
layer. A plain `[[compatible]]` entry would also accept it in the other,
unreviewed image. Add `where` to limit the rule to what you judged:

```toml
[[compatible]]
match = "package"
name = "busybox"
where = ["docker:a/Dockerfile"]
reason = "Reviewed in a/Dockerfile's image: shipped unmodified in the OS layer."
```

`where` is opt-in and narrows, never widens — omit it and the rule applies
everywhere, which is rarely what a per-image review means to say. Prefer the
narrowest identity you actually reviewed, usually the full `docker:<source>`
of one image, and check a scoped rule against the Used-in column: an entry
matching nothing prints an unused-rule warning. Target-matching rules and
both target forms (`docker:<source>`, workspace path):
[policy.md#compatible](../reference/policy.md#compatible).

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

## What to do when the gate flags something

[`reading-the-output.md`](./reading-the-output.md) is where you start: it
routes each flagged row in `THIRD_PARTY_LICENSES.md` to the recipe above that
resolves it, by the rule that decided the verdict. This page is where you
land once that routing told you which table to write — pick the recipe,
write the TOML, regenerate, and re-run `check`. The
[getting-started guide](../getting-started.md) walks through a first run end
to end, and the [glossary](../glossary.md) defines every term a verdict can
use.
