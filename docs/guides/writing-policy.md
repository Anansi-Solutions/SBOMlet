# Writing your policy

This guide is for the policy author — the person who writes `.sbomlet.policy.toml`, reads
the generated documents, and decides what to do about a flagged dependency.

Each section below is a recipe: a task you have in mind, the TOML to paste, and a
sentence on what it does. Skip to the one you need. If a term is unfamiliar, the
[glossary](../glossary.md) defines it.

Two things hold across every recipe. Every override needs a written `reason` or
`description`; the tool rejects an entry with a missing or empty one, because
that text is the audit trail a reviewer reads to understand why the exception
exists. Validation is strict and runs all at once: an unknown key, an invalid
SPDX pattern, or a malformed path rejects the whole file, and the error names
every problem it found by its table path, so you never fix one mistake only to
discover the next on the following run.

You can start from the shipped [`policy.example.toml`](../../policy.example.toml),
which carries a working entry for each table with the rules inline as comments.
Copy it to `.sbomlet.policy.toml` at your repo root and pass it with `--policy`:

```sh
task sbomlet:generate POLICY=.sbomlet.policy.toml
```

Without `--policy` the tool only inventories licences. With it, every package in
every place it appears gets a [verdict](../glossary.md#verdict) — `ok`, `warn`,
`fail`, or `suppressed` — and the [gate (`check`)](../glossary.md#the-gate-check)
fails the build on any `fail`.

## How the lanes decide (read this once)

When two rules could apply to the same package, the policy follows a fixed order
and the first lane that matches wins. Highest precedence first:

1. `[[deny]]` — force-fail a [source-available](../glossary.md#source-available)
   licence or a named package. This lane is terminal: nothing below can license
   the package back in.
2. `[[clarify]]` — correct a package's [finding](../glossary.md#license-finding)
   to a precise expression before anything else looks at it.
3. `[[compatible]]` `match = "package"` — accept an exact package by name.
4. `[[compatible]]` `match = "license"` — accept a licence pattern.
5. `[[workspace.copyleft_suppressed]]` — stop flagging in-family
   [copyleft](../glossary.md#copyleft) inside a workspace that ships under that
   same copyleft.
6. The category default — copyleft fails, unknown follows `[unknown]`,
   everything else is `ok`.

`[[clarify]]` sits near the top because it doesn't decide a verdict on its own.
It rewrites the finding, and then the lower lanes judge the corrected value. The
`[unknown]`, `[dev_dependencies]`, and `[os_dependencies]` tables aren't lanes;
they tune what the default lane does at the bottom.

The order matters when a package could match more than one rule. A package
denied by `[[deny]]` fails even if a `[[compatible]]` rule would accept it, which
is the purpose of a terminal lane. A copyleft dependency accepted by a
`[[compatible]]` licence pattern never reaches workspace suppression, because
compatible already settled it.

## Allow a copyleft dependency inside a copyleft workspace

You ship one workspace under a copyleft licence, and it bundles dependencies
under the same family. Those impose no additional obligation inside that
workspace, so you want to stop flagging them there, and only there.

```toml
[[workspace.copyleft_suppressed]]
path = "apps/scratch"
license = "AGPL-3.0-only"
description = "apps/scratch is itself distributed under AGPL-3.0-only; the bundled scratch-* AGPL dependencies are in-family copyleft and impose no additional obligations within this workspace."
```

This suppresses copyleft findings for any occurrence whose
[target](../glossary.md#target) is `apps/scratch` or sits under it. The same
package used in a different workspace still flags, because suppression is per
occurrence rather than per package.

Three rules keep this from over-reaching. The `path` is a repo-relative,
forward-slash prefix, with no leading or trailing slash and no `..` segments; the
match is segment-aware, so `apps/scratch` never matches an `apps/scratch-helper`
next to it. The `license` must be a single SPDX id, not an expression, and it
anchors a family-aware check: suppression applies only when the dependency's
licence is absorbed by the workspace licence. The GNU family spans AGPL, GPL, and
LGPL, so an `AGPL-3.0-only` workspace suppresses those (and an MPL dependency it
bundles), but never SSPL, CC-BY-SA, or any out-of-family copyleft; those fall
through and still fail, and the verdict reason records which relationship it
verified. The `description` is mandatory and is the audit trail.

For a per-package judgment call rather than a whole-family rule, use
`[[compatible]]` instead.

## Deny a source-available licence or a named package

You want a licence — or one specific package — to fail the build unconditionally,
with no way to accidentally allow it elsewhere. This is the lane for
source-available licences (BUSL, SSPL, Elastic) and use-restriction riders that
legally can't ship in a distributed artifact.

Deny by SPDX licence:

```toml
[[deny]]
match = "license"
pattern = "BUSL-1.1"
reason = "Business Source License 1.1 is source-available, not open source: it forbids production use until the change date and can never appear in a distributed THIRD_PARTY set."
```

Deny by exact package name:

```toml
[[deny]]
match = "name"
pattern = "redis"
reason = "Redis Source Available License has no registered SPDX id, so it is matched by package name. Use-restricted — cannot be redistributed."
```

A matching package force-fails everywhere, above every accept lever and above a
stale override. The two modes cover different situations.

`match = "license"` takes an SPDX id or an `OR` of ids; an `AND` pattern is
rejected. It matches by SPDX semantics, not substring. An `OR` finding is denied
only when every branch is denied, so `MIT OR BUSL-1.1` stays allowed, because the
dependency can elect MIT.

`match = "name"` takes an exact, case-sensitive package name. Use it for things
SPDX can't express, such as a licence with no registered id (RSAL) or a
use-restriction rider like Commons-Clause that rides on top of another licence
(`MIT AND Commons-Clause`). Name mode doesn't need a parseable licence, so it
still catches a rider on a package whose finding is unknown.

Deny sees through an override. If a `[[clarify]]` rewrote a denied licence into
something benign, deny still fires on the original observed value, so a
source-available licence can't be laundered clean.

## Correct a wrongly-detected or imprecise licence

A package reports a licence that's wrong, missing, or named only by family
("BSD" with no clause). You know the right answer and want to record it.

The plain form replaces the finding blindly:

```toml
[[clarify]]
package = { name = "jsonify", version = "0.0.1" }
expression = "Unlicense"
reason = "Upstream declares the non-SPDX value 'Public Domain'; jsonify's README dedicates it to the public domain, mapped to Unlicense deliberately."
```

This sets the package's finding to `Unlicense` regardless of what the lockfile
said. `version` is optional; omit it to cover every version. `expression` must be
valid SPDX, parsed when the policy loads, so a typo fails immediately rather than
mid-run.

For an [imprecise family](../glossary.md#imprecise-family) — where the data says
"BSD" and you're asserting which BSD — add an `expects` precondition:

```toml
[[clarify]]
package = { name = "some-package" }
expects = "BSD"
expression = "BSD-3-Clause"
reason = "Confirmed BSD-3-Clause in the upstream LICENSE file."
```

`expects` records the value you're disambiguating from. The override applies only
while the package's observed licence still matches it. If the package relicenses
and the observed value no longer matches `expects` — say it now reports GPL-3.0 —
the override is stale, and the gate fails, naming the package, the expected
value, and the now-observed value. A stale override is never applied, so an old
disambiguation can't silently mask a relicense. Use the `expects` form when
you're pinning down an imprecise family, and the plain form for fixing garbage
metadata.

### Several packages, one disambiguation

Some ecosystems point a whole family of packages at the same evidence. Older
`System.*` and `Microsoft.NETCore.*` packages all carry a `licenseUrl` that
redirects to a single retired Microsoft page, so writing forty near-identical
`[[clarify]]` entries would just be one decision copy-pasted forty times. Use
`packages` in place of `package` to name the list once:

```toml
[[clarify]]
packages = [
  { name = "System.IO", version = "4.3.0" },
  { name = "System.Text", version = "4.3.1" },
  { name = "System.Xml", version = "4.3.2" },
]
expression = "MIT"
evidence_url = "https://github.com/dotnet/core/blob/8c8e5836c343f854b65437dfedb13598d3aa3707/license-information.md"
reason = "licenseUrl is the retired .NET Library EULA fwlink; the pinned page states library packages use the MIT license"
```

Every field besides `package`/`packages` stays the same and applies to each
listed package individually: this is forty entries collapsed into one, not one
group verdict. A version you didn't list — including a newer release of
`System.IO` itself — isn't covered and surfaces as unknown, exactly as if it
had no clarify entry at all. Leave a package off the list, or give it its own
entry, when it doesn't genuinely share the reasoning — a package that wraps
third-party native code, say, deserves its own reading rather than riding
along on this one.

The tool also ships its own curated clarifications for commonly-ambiguous
projects, such as the Jupyter/IPython BSD stack. You get those without
re-authoring them, and your own `[[clarify]]` wins on any conflict.

## Allow a licence pattern or an exact package

A licence is fine for your project even though it isn't permissive by default, or
one specific package is reviewed and accepted. Use `[[compatible]]`.

Accept a licence everywhere — a rule without `where` applies at every
occurrence:

```toml
[[compatible]]
match = "license"
pattern = "MPL-2.0"
reason = "Weak copyleft; compatible under AGPL-3.0 and Apache-2.0."
```

Accept one package, optionally pinned to a version:

```toml
[[compatible]]
match = "package"
name = "@img/sharp-win32-x64"
version = "0.34.5"
reason = "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; the LGPL obligations are reviewed and accepted for these prebuilt sharp binaries."
```

A licence pattern accepts any finding its SPDX expression satisfies. It takes a
single id or an `OR` of ids: `(MPL-2.0 OR MPL-1.1)` works, while `MPL-2.0 AND
MIT` is rejected, because an `AND` can't be satisfied by a single allowlist
entry. A package rule matches by exact name; with `version` it pins to that one
version, and without it covers every version.

Both forms remove the package from copyleft flagging everywhere, unless a
`where` field narrows the rule to the occurrences you name — the next recipe.
Use compatible for a documented judgment call, and keep it narrow; `where` is
how you keep it narrow.

## Accept a package only where you reviewed it

Your repo builds two images, `a/Dockerfile` and `b/Dockerfile`. You reviewed
busybox in the first image's OS layer and accepted it there. A plain
`[[compatible]]` entry would also accept it in the second image, which nobody
reviewed. Add `where` to limit the rule to what you judged:

```toml
[[compatible]]
match = "package"
name = "busybox"
where = ["docker:a/Dockerfile"]
reason = "Reviewed in a/Dockerfile's image: shipped unmodified in the OS layer."
```

busybox is now `ok` in the first image only. The same package in
`b/Dockerfile`'s image still warns — or fails, when `[os_dependencies]` is set
to `fail` — and the verdict names that unreviewed occurrence. `where` works on
both compatible forms, licence and package.

Each entry is an occurrence-identity prefix, matched with the same
segment-aware rule as a suppression `path`: the occurrence's
[target](../glossary.md#target) must be the entry itself or sit under it as a
whole segment. Docker targets are `docker:<source>` — the Dockerfile's
repo-relative path for an image the tool builds, or the image reference
exactly as you passed it (`docker:node:24-alpine`) for an `--image` scan. App
targets are the workspace paths you see in the Used-in column.

Prefer the narrowest identity you actually reviewed — usually the full
`docker:<source>` of one image.

A scoped rule that matches nothing is reported as an unused entry — check the
`where` value against the Used-in column of the committed document.

## Set how unknown, dev, and OS dependencies are handled

Three tables tune what the default lane does for whole categories. Each defaults
to `warn` when you leave it out, so you can adopt the tool without failing on day
one and tighten later.

Unknown licences — a package with no determinable licence:

```toml
[unknown]
handling = "warn"
```

`warn` lists unknowns without failing; `fail` treats every unknown as a
violation. Start with `warn` while you burn down the unknown population, then
switch to `fail` once the inventory is clean.

Development-only dependencies — build tools and test runners that you never ship:

```toml
[dev_dependencies]
handling = "warn"
```

This governs a would-be fail on a
[development-only](../glossary.md#development-only-and-production) occurrence: a
copyleft licence, or an unknown one when `[unknown]` is `fail`. `warn` downgrades
it (the default), `fail` gates dev exactly like production, and `ignore` is a
documented opt-out that turns it into `ok`. This is per occurrence, so the same
package used as a dev dependency in one workspace and a production dependency in
another still fails on the production side. A shipped copyleft can't be
dev-downgraded.

Docker image packages — the full contents of the images you ship, the OS layer
and the application packages an image scan finds inside it:

```toml
[os_dependencies]
handling = "warn"
```

The expected copyleft in a Debian or Alpine base image — glibc under LGPL, bash
and coreutils under GPL — is the operating system the container ships on, not
code your project redistributes as a library. Its obligations are satisfied by
shipping the image, so `warn` (the default) lists those packages in a dedicated
section rather than failing your build on every standard base image. The same
downgrade covers an application package the image scan finds that isn't also
declared directly — it entered the inventory only because the image ships it.
`fail` gates [OS-scope](../glossary.md#scope-app-and-os) packages like app code,
for projects that rebuild their base, or that want every image-sourced copyleft
reviewed, and `ignore` opts out explicitly. A `[[deny]]` licence in an OS-scope
package still fails regardless, because deny sits above this knob.

These packages reach the merge only if a `.sbomlet.cache/docker.sbom.json` is present in your
repo, produced separately by the `generate-docker-sbom` subcommand — run by hand
over named Dockerfiles or images, or by CI discovering and building the
repository's Dockerfiles. `generate` and `check` never scan images themselves; they only read that
committed file as an OS-scope input. See the
[getting-started guide](../getting-started.md) for producing it.

## Set a document title and preamble

You want the generated `THIRD_PARTY_LICENSES.md` to open with your own heading
and an introductory paragraph — a company name, a compliance statement, a link to
an internal policy.

```toml
[document]
title = "Third-Party Licenses — Acme Corp"
preamble = """
This inventory is generated automatically and reviewed before each release.
Questions about a listed dependency go to compliance@acme.example.
"""
```

`title` replaces the default `Third-Party Licenses` heading. `preamble` is
rendered verbatim as Markdown below the auto-generated header, so you can use
links and emphasis. Both keys are optional, and both apply only to the licenses
document, not the [notices companion](../glossary.md#sbom). The preamble is
trusted as author markdown and isn't escaped, so write it as you'd write any
Markdown in your repo.

## Exclude Dockerfiles you don't want built

Your repo has Dockerfiles you don't want the tool to build, such as a fixture or a
template that isn't a real image, and a discovery walk would otherwise hand each
one to `docker build`.

```toml
[docker]
ignore = ["docker/dev.Dockerfile", "ci/runner.Dockerfile"]
```

When `generate-docker-sbom` discovers Dockerfiles under `--repo-root`, any whose
repo-relative path matches an `ignore` glob is excluded entirely, so it is never
built and never scanned. The globs follow the same path rules as
suppression paths: forward slashes only, no `..` segments, no leading or trailing
slash. An empty `ignore` (or no `[docker]` table at all) excludes nothing.

This affects every `generate-docker-sbom` discovery walk, whether run by hand or
by CI's `--list-dockerfiles` build-set resolution — both share the same walk and
the same `[docker]` ignore globs. The everyday `generate` and `check` commands
don't discover Dockerfiles, so this table has no effect on them.

## What to do when the gate flags something

The policy is one half of the loop; the other is reading what comes back. When
`check` reports a `fail`, the verdict names the deciding rule and the reason, so
you can tell which recipe above applies, whether a denied licence, an
unsuppressed copyleft, or an unknown you've now identified. The
[getting-started guide](../getting-started.md) walks through a first run end to
end, and the [glossary](../glossary.md) defines every term a verdict can use.
