# Glossary

The words this project uses for its own moving parts, defined once. The docs link
here on first use. If two words could mean the same thing, only the one defined
here is correct — there are no synonyms.

### abstain

To return no answer on purpose, rather than a possibly-wrong one. When the tool
can't determine a value with confidence, it abstains: an unknowable licence is
left blank rather than guessed, and a dependency whose provenance can't be traced
is surfaced without one. See [honest residual](#honest-residual).

### clarifications file

The separate file a policy can keep its [clarify](#policy-lanes) entries in,
named by a top-level `clarifications` key. It holds those tables and nothing
else, and its entries are cited `clarifications[j]`, numbered within that file.
It is machine-maintained — `refresh-clarifications` rewrites it whole — so notes
about an entry belong in the entry's own fields, never in comment lines around
it. See
[policy.md](reference/policy.md#a-separate-clarifications-file).

### collector

The component that turns one [target](#target) into a list of dependencies with
their licences. There is one collector per ecosystem. A collector either runs a
standard [generator](#generator) and reads its output, or parses a lockfile
itself.

### compatibility lane

The verdict lane a declared [target profile](#target-profile) activates:
instead of an occurrence's licence being judged only by hand-authored
`[[compatible]]`/`[[deny]]` rules, it is judged by directional compatibility
against the target, using a vetted licence-compatibility matrix. Sits below
`[[compatible]]` and above workspace copyleft suppression in
[precedence](reference/policy.md#precedence); absent a declared target,
the lane never activates and routing is unchanged. The matrix models
absorption into a combined work under the target licence, not linking mode
— see
[policy.md#targetworkspace](reference/policy.md#targetworkspace) for
that assumption stated in full.

### CycloneDX

An industry-standard SBOM format (JSON). It's the interchange format inside the
tool — every collector's output is CycloneDX, and the tool can export a merged
CycloneDX document. Version 1.6 throughout.

### copyleft

A licence that requires you to release your own changes (and sometimes the whole
work that includes it) under the same terms. GPL, LGPL, AGPL, MPL. The policy
flags copyleft dependencies because they carry an obligation when you distribute.

### dependency graph

The per-[target](#target) record of which package pulls in which. Two lanes
reconstruct one: the Yarn lane, and only where the lockfile is Yarn 4 or later
— an earlier, empty, or unreadable one falls back to the flat generator — and
the Python (poetry) lane. Every other source, npm and bun and Terraform and the
committed Docker image SBOM alike, reports a flat list, so those targets carry
no [introduction path](#introduction-path) to check. The collector registration
decides this, from the lockfile it is about to read, never from whether the
document it gets back happens to carry edges.

### dependency provenance

Why a dependency is present: whether your project depends on it **directly** (you
declared it) or **transitively** (something you declared pulls it in), and which
parent — the **introducer** — does the pulling. Shown in the "Why" column.
Recorded for the targets that have a [dependency graph](#dependency-graph);
other ecosystems show "—".

### detection record

What a [clarify](#policy-lanes) entry's `detected` key holds: what each source
reported when the entry was written, one value per source — the registry answer
and the in-depth scan's. The entry applies only while every source it records
still reports what was written down, so a later relicence reopens the judgment
instead of being masked by an old answer.

### development-only and production

A dependency is **development-only** when every place it's used is a dev
dependency (build tools, test runners). It's a **production** dependency if it
ships anywhere. The distinction matters because only what you ship carries a
distribution obligation, so the policy can treat the two differently.

### election

What an OR expression does: it lets the consumer pick whichever branch they
want to rely on. `elect()` (`src/normalize/expression.ts`) makes that pick
deterministic — preferring a non-copyleft branch, then one without an opaque
`LicenseRef-`/`DocumentRef-` leaf, then a stable tie-break — so the same
finding always resolves to the same branch. Copyleft and deny walk the same
tree asking the mirror question: is there an *electable* branch, one a
consumer could legitimately choose, that avoids the obligation or the deny
rule? A finding is copyleft only if every branch is; a finding is denied only
when it has no electable branch left — an OR is denied only when every
branch is denied (an electable branch defeats it), while an AND is denied
when any conjunct is denied (a conjunct can't be elected away). When a
[target profile](#target-profile) governs the occurrence, election becomes
target-aware: the preference for a non-copyleft branch can pick a DIFFERENT
branch than the untargeted walk would, because "non-copyleft" isn't always
the branch that best serves the declared target — an OR containing a branch
the target absorbs cleanly is preferred over one that merely avoids
copyleft in the abstract.

### enrichment and the enrichment cache

Some lockfiles don't record a licence. **Enrichment** fills those gaps by asking
the package registry (npm, PyPI). The answers are written to a committed
**enrichment cache** so that [check](#the-gate-check) never needs the network.
`generate` writes this cache on every run, even one where nothing needed
enriching (an empty cache is still a cache); the bytes change only when it
fetches a licence the cache doesn't already hold. `check` only ever reads it.

### everywhere token

The reserved `where` element `/`, covering every [occurrence](#occurrence).
`where` is required on a `[[compatible]]` entry, so a repository-wide acceptance
is written out rather than reached by omission. No target identity can be `/`,
since a leading or trailing slash is rejected wherever a path is validated, so
the token is unambiguous.

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

### introduction path

The chain by which a dependency reaches your project at one [target](#target):
the package your project declared, then each package that pulls in the next,
down to the dependency itself. Recorded only where the target has a
[dependency graph](#dependency-graph). A package-level `[[compatible]]` entry
states whose use of a package was judged, and is checked against these paths.

### justification

The closed set a [clarify](#policy-lanes) entry picks from to say why its
recorded expression is preferred over what detection reports. Each value asserts
something the tool can re-check, so an entry the current signal disproves fails
the gate instead of applying; free prose goes in the entry's `comment`. The
values are in [policy.md](reference/policy.md#justification--the-closed-set).
Compare [rationale](#rationale), the equivalent set for an acceptance.

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
**compatible** (allow a package, or a licence), the
[compatibility lane](#compatibility-lane) a declared
[target profile](#target-profile) activates, and
**workspace copyleft suppression** (stop flagging in-family copyleft inside a
workspace that itself ships under that copyleft licence). Under all of them sit
the category defaults for unknown, development-only, and OS-scope packages. The
full table is [policy.md](reference/policy.md#precedence).

### purl

A package URL — the standard, ecosystem-agnostic identifier for a package
version, like `pkg:npm/react@19.2.3` or `pkg:deb/debian/bash@5.2`. It's the key
the [merge](#merge) joins on.

### rationale

The closed set a `[[compatible]]` entry picks from to say why a package or a
licence is accepted. Two of its values state something a scan can contradict and
are rejected outright when it does; the rest state a judgment about how your
software is built, which no scan observes, so they are taken as written. The
values are in [policy.md](reference/policy.md#rationale--the-closed-set).
Compare [justification](#justification), the equivalent set for a clarification.

### SBOM

Software Bill of Materials: a machine-readable list of everything a piece of
software is built from. The tool produces one and consumes several (see
[CycloneDX](#cyclonedx)).

### scope: app and os

Where a package comes from. **App** scope is your declared dependencies (npm,
Python, Terraform) — and any package a Docker image scan finds that isn't on
the OS package-manager allowlist (`deb`, `apk`, `rpm`, `alpm`), since
something installed via an application package manager is an application
dependency wherever it lives. **OS** scope is only the allowlisted base-image
packages a Docker image scan finds. They're listed separately and the policy
can gate them differently — base-image GPL is expected and isn't a
violation, but an application package baked into an image gates like any
other application dependency.

### the `self` token

The reserved `as-dependency-of` value naming your own software rather than a
package that pulls one in. On a target with a
[dependency graph](#dependency-graph) it covers exactly one edge: the package
your project declared directly. On a target without one it is the only value a
policy may name, and it accepts every occurrence the entry's `where` reaches —
an acceptance no [introduction path](#introduction-path) scopes.

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

Two things go stale. A committed **document** is stale when it no longer matches
what the tool would generate today — usually because a dependency changed and
the inventory wasn't regenerated — which [check](#the-gate-check) reports with
exit code 2. An **override** is stale when a source no longer reports what its
[detection record](#detection-record) wrote down; the recorded expression is not
applied, and the gate fails naming the source, the recorded value, and the
current one.

### target

One thing the tool scans: a single lockfile or Terraform directory, found by
walking the repository. `yarn.lock`, `poetry.lock`, a `.terraform.lock.hcl`
directory. Each target is handled by one [collector](#collector).

### target profile

Your own software's declared licence and usage — not the scan
[target](#target) above, an unrelated word for a different thing. A
`[target]` table in `.sbomlet.policy.toml` declares one: a licence (or
`"proprietary"`), whether you're deployed on a network, and whether you
distribute externally or keep the software internal. Declaring one
activates the [compatibility lane](#compatibility-lane); `[[target.workspace]]`
overrides the profile per workspace. See
[policy.md#target](reference/policy.md#target).

### verdict

The policy's decision about one package in one [occurrence](#occurrence):
`ok`, `warn`, `fail`, or `suppressed`, with the rule that decided it and a
reason. The rendered documents and the [gate](#the-gate-check) both read
verdicts; neither decides anything itself.

### voided entry

A package-level `[[compatible]]` entry whose judgment the recorded
[introduction paths](#introduction-path) contradict at one
[target](#target): something it accepts arrives there through a chain passing
none of the parents it names. The entry then accepts nothing at that target, and
every occurrence it governs there fails as `compatible:voided[i]`, naming the
chain. Splitting the entry so each part covers one way in is the recovery.
