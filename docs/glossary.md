# Glossary

The words this project uses for its own moving parts, defined once. The docs link
here on first use. If two words could mean the same thing, only the one defined
here is correct — there are no synonyms.

### abstain

To return no answer on purpose, rather than a possibly-wrong one. When the tool
can't determine a value with confidence, it abstains: a Dockerfile base it can't
resolve is reported `unresolved`; an unknowable licence is left blank. See
[honest residual](#honest-residual).

### collector

The component that turns one [target](#target) into a list of dependencies with
their licences. There is one collector per ecosystem. A collector either runs a
standard [generator](#generator) and reads its output, or parses a lockfile
itself.

### CycloneDX

An industry-standard SBOM format (JSON). It's the interchange format inside the
tool — every collector's output is CycloneDX, and the tool can export a merged
CycloneDX document. Version 1.6 throughout.

### copyleft

A licence that requires you to release your own changes (and sometimes the whole
work that includes it) under the same terms. GPL, LGPL, AGPL, MPL. The policy
flags copyleft dependencies because they carry an obligation when you distribute.

### dependency provenance

Why a dependency is present: whether your project depends on it **directly** (you
declared it) or **transitively** (something you declared pulls it in), and which
parent — the **introducer** — does the pulling. Shown in the "Why" column.
Available for npm and Python; other ecosystems show "—".

### development-only and production

A dependency is **development-only** when every place it's used is a dev
dependency (build tools, test runners). It's a **production** dependency if it
ships anywhere. The distinction matters because only what you ship carries a
distribution obligation, so the policy can treat the two differently.

### enrichment and the enrichment cache

Some lockfiles don't record a licence. **Enrichment** fills those gaps by asking
the package registry (npm, PyPI). The answers are written to a committed
**enrichment cache** so that [check](#the-gate-check) never needs the network.
`generate` writes this cache on every run, even one where nothing needed
enriching (an empty cache is still a cache); the bytes change only when it
fetches a licence the cache doesn't already hold. `check` only ever reads it.

### the gate (`check`)

The `check` command: the part that makes the tool a CI gate. It regenerates the
inventory in memory, compares it byte-for-byte against the committed documents,
evaluates the policy, and exits with a code that says what (if anything) is
wrong. It writes nothing and never uses the network.

### generator

A standard, third-party SBOM tool the [collector](#collector) drives — cdxgen,
the Yarn CycloneDX plugin, syft. The tool orchestrates these rather than
detecting licences itself.

### honest residual

The design rule that the tool surfaces what it can't determine instead of
guessing it. Ambiguity becomes a visible gap a person can act on, not an
invented value. See [abstain](#abstain), [imprecise family](#imprecise-family).

### imprecise family

A licence the data names only by family — "BSD", "Apache" — with no clause or
version, so it can't be turned into a precise SPDX id without guessing. The tool
records it as imprecise and flags it for a human to pin down with a
[clarify](#policy-lanes) override.

### license claim

A single raw licence value as some source stated it, before any cleanup — a
verbatim string from a lockfile, a registry, or an override. A package can carry
several claims from several sources.

### license finding

The tool's conclusion about a package's licence after normalising and combining
its [claims](#license-claim): a precise SPDX expression, an
[imprecise family](#imprecise-family), or unknown.

### merge

The step that combines every [collector](#collector)'s output into one inventory,
keyed by [purl](#purl). The same package found in two workspaces becomes one
entry with two [occurrences](#occurrence).

### normalization

Turning raw [licence claims](#license-claim) into standard SPDX. It corrects
sloppy-but-clear values ("Apache License 2.0" to `Apache-2.0`) and parses licence
expressions, but never guesses an [imprecise family](#imprecise-family) into a
precise id.

### occurrence

One place a package is used: a [target](#target), whether it's used there as a
[development-only](#development-only-and-production) dependency, and (where known) its
[provenance](#dependency-provenance). A package has one entry and one occurrence
per place it appears.

### package entry

One dependency in the merged inventory: its name, version, [purl](#purl),
[licence finding](#license-finding), [scope](#scope-app-and-os), and the list of
[occurrences](#occurrence) where it's used.

### policy lanes

The ordered rules in `.sbomlet.policy.toml`, highest precedence first:
**deny** (force-fail a source-available or named licence — terminal),
**clarify** (correct a package's finding to a precise expression),
**compatible** (allow a licence or an exact package), and
**workspace copyleft suppression** (stop flagging in-family copyleft inside a
workspace that itself ships under that copyleft licence).

### purl

A package URL — the standard, ecosystem-agnostic identifier for a package
version, like `pkg:npm/react@19.2.3` or `pkg:deb/debian/bash@5.2`. It's the key
the [merge](#merge) joins on.

### SBOM

Software Bill of Materials: a machine-readable list of everything a piece of
software is built from. The tool produces one and consumes several (see
[CycloneDX](#cyclonedx)).

### scope: app and os

Where a package comes from. **App** scope is your declared dependencies (npm,
Python, Terraform). **OS** scope is the operating-system packages inside a Docker
base image. They're listed separately and the policy can gate them differently —
base-image GPL is expected and isn't a violation.

### source-available

A licence that lets you read and modify the source but restricts production or
commercial use — BUSL, SSPL, Elastic, Commons Clause. Not
[copyleft](#copyleft), and the bigger risk for most distributed software, which
is why the [deny lane](#policy-lanes) targets it.

### SPDX

The standard catalogue of licence identifiers (`MIT`, `Apache-2.0`,
`GPL-3.0-only`) and the grammar for combining them (`MIT OR Apache-2.0`). The tool
speaks SPDX everywhere a licence is named.

### staleness

The condition [check](#the-gate-check) reports (exit code 2) when a committed
document no longer matches what the tool would generate today — usually because a
dependency changed and the inventory wasn't regenerated.

### target

One thing the tool scans: a single lockfile or Terraform directory, found by
walking the repository. `yarn.lock`, `poetry.lock`, a `.terraform.lock.hcl`
directory. Each target is handled by one [collector](#collector).

### verdict

The policy's decision about one package in one [occurrence](#occurrence):
`ok`, `warn`, `fail`, or `suppressed`, with the rule that decided it and a
reason. The rendered documents and the [gate](#the-gate-check) both read
verdicts; neither decides anything itself.
