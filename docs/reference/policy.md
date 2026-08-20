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
| 3 | Compatible (package) | `[[compatible]]` with `match = "package"` | Allow this package, or a family of them. |
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

The table above is where an applied verdict comes from. The tiers that fail an
entry instead of applying it — a stale precondition, a justification the
evidence disproves, a chain the acceptance never judged — sit inside this order
and are laid out in the normative routing tree,
[dependency-classification.md](./dependency-classification.md#stage-2--verdict-routing).

## Validation

Validation is strict and rejects the whole file on the first run, reporting
every problem at once. Each problem names the table path and key it came from
(`compatible[2]: missing required key "where"`), so you fix them in one pass
rather than one error per run.

The rules that hold across the file:

- Every override states why it exists: a `rationale` or `justification` from a
  closed set on `[[compatible]]` and `[[clarify]]`, a free-text `reason` on
  `[[deny]]` and `[[allow_source_available]]`, a `description` on a suppression.
  A closed-set value outside its set is rejected naming the whole set; a free
  text one must be present and non-empty, since a blank audit trail is a missing
  one.
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
- A `[target]`/`[[target.workspace]]` OSS `license` must be one of the OSADL
  compatibility matrix's own row keys — a valid SPDX id the matrix has no row
  for is rejected too, naming the id, because the target lane could never
  classify a dependency against an uncovered target. `"proprietary"` is
  exempt.
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
corrected value. Absent table: no clarifications. Entries may also live in a
file of their own — see
[A separate clarifications file](#a-separate-clarifications-file).

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | exactly one of `name`/`pattern` | One package, by its exact display name. |
| `pattern` | string (name glob) | exactly one of `name`/`pattern` | A family of packages by name — see [Name patterns](#name-patterns). |
| `version` | string, or array of strings | yes | The exact version, or versions, covered. A single string or a non-empty list — a clarify is never version-less. |
| `detected` | inline table | yes | What each source reported when you wrote the entry — see below. |
| `justification` | string (closed set) | yes | Why your expression is preferred over what detection reports. |
| `expression` | string (SPDX) | yes | The corrected SPDX expression, parsed at load time. |
| `evidence` | array of strings | no | Files or URLs a reader can check. Recorded verbatim; never fetched or verified. |
| `comment` | string (non-empty) | no | What the justification cannot carry. |

### `detected` — the staleness precondition

Every entry records what each source reported when it was written:

| Key | Meaning |
|-----|---------|
| `registry` | The quick answer: the package's own metadata, plus whatever registry enrichment resolved. Often not SPDX at all — `BSD`, `Dual License` — so record it exactly as reported. |
| `intensive` | The in-depth source scan's answer. |

Both keys are optional and at least one is required. A key's value is that
source's reported value, or `false` to record that the source reports
**nothing**.

The entry applies only while every source you recorded still reports what you
wrote down. Comparison is case-insensitive, whitespace-trimmed, and blind to
boolean-algebra re-spelling: a registry that reports `MIT AND CC0-1.0` one day
and `CC0-1.0 AND MIT` the next has not changed anything, and neither reading
reopens the entry. Anything else is staleness, and the gate fails naming the
source, the recorded value, and the current one:

- the source reports a different value — a relicence;
- the source reports nothing where you recorded a value — the evidence has
  disappeared, so the entry is unverifiable rather than vacuously satisfied;
- the source reports something where you recorded `false`.

A stale entry is never applied, so an old entry cannot silently mask a
relicence. Staleness also covers a licence appearing *beside* what you
recorded: if any source reports a licence your `expression` does not account
for, the entry is stale even though everything you wrote down still holds.
Without that, a lingering obsolete `BSD` label would license out a co-present
new `GPL-3.0-only` claim. A bare family label counts here too — an `AGPL`
next to a recorded `MIT` is not something a `MIT` expression answers for —
unless you recorded that family yourself, which is the ordinary `BSD` →
`BSD-3-Clause` disambiguation. A label naming no family the tool recognises
contradicts nothing and is passed over.

One entry stays valid through a divergence it did not intend to hide: when a
source upgrades its own imprecise label to exactly the licence you asserted —
`BSD` becoming `BSD-3-Clause` — the entry is redundant rather than stale, and
the observed finding stands unchanged. That does not extend to a `false`
record: you asserted that a source says nothing, and a source that has started
speaking is new evidence to read, whether or not it happens to agree.

A disagreement between the two sources — reported as an [assessment
conflict](./output-format.md#assessment-conflicts) — is only settled by an
entry that recorded the `intensive` source. That is the entry stating which
side you stand behind; recording `registry` alone says nothing about the scan,
so the disagreement stays open and the gate keeps asking.

### `justification` — the closed set

The tool can only check a claim it understands, so the reason is chosen from a
fixed list. `comment` carries anything the list cannot.

| Value | Meaning | Proven invalid when |
|-------|---------|---------------------|
| `contradictory-claims-recorded` | The sources disagree irreconcilably and the expression is the reading you stand behind. The sanctioned fallback. | never — it becomes unnecessary instead, below |
| `declared-more-complete` | The package's own metadata names licences the scan cannot see. | the declared claim no longer names part of the expression |
| `dual-license-choice` | The package offers a choice of licences that the in-depth scan read as one joined licence; the expression restores the choice it offers, not the branch you took. | the scan's licences are not the recorded choice — nothing was joined — or the declared claim offers none of them |
| `license-not-found` | No source states a licence; the expression comes from evidence outside detection. | either source now states a licence |
| `scan-found-additional-content` | The in-depth scan sees further licences that do govern content the package ships. | the expression no longer accounts for what the scan reads |
| `scan-more-precise` | The in-depth scan resolves an under-specified declared label to the exact licence. | the expression no longer accounts for what the scan reads |
| `scan-overdetection` | The in-depth scan reports licences from files that do not govern the package. | never — it becomes unnecessary instead, below |

Each of these is a claim about what a source reported, so the lane it speaks
for may not be recorded as `false`. `contradictory-claims-recorded` speaks for
both lanes, `declared-more-complete` for `registry`, and the three `scan-`
values for `intensive`; recording `false` there says that source reported
nothing, which is the opposite of the claim. Leaving a lane out is different
and stays allowed — `detected` records what you checked. And
`license-not-found` says no source states a licence, so neither recorded value
may be one — including a label that names one, such as `MIT License`, which
the tool resolves to `MIT`. A value that names no licence, such as
`Public Domain`, is exactly the case it is for. A policy breaking either rule
is rejected when it is read.

Wherever a verdict cites the entry, its reason is the justification value, and
the comment after an em-dash when one is present.

The invalidity check runs only once `detected` still holds: staleness is the
earlier and more urgent question, and an entry that fails it never reaches this
one. An entry the evidence disproves fails the gate as `clarify:invalid[i]`
(`clarifications:invalid[j]` when it came from the separate file),
and the failure names where the entry can legally go instead — the
justification the evidence now supports, `contradictory-claims-recorded` when
the sources genuinely disagree, or a `[[compatible]]` entry with rationale
`license-reviewed` when the licence is simply accepted.

Two values are undone by their own success rather than by contrary evidence.
`scan-overdetection` has nothing left to drop once the scan stops reporting
licences outside the expression, and `contradictory-claims-recorded` has
nothing left to record once the two sources read the same licences. Neither
fails the gate: the entry has become unnecessary, not wrong.

The tool also ships its own curated clarifications for commonly-ambiguous
projects, applied without your re-authoring them, and preconditioned the same
way. When a project-level `[[clarify]]` names the same package, your entry
takes precedence.

### A separate clarifications file

Clarifications tend to outnumber every other kind of entry and to turn over on
their own schedule. A top-level `clarifications` key moves them out of the
policy:

```toml
clarifications = ".sbomlet.clarifications.toml"
```

The path is relative to the repository root and forward-slash, validated like
every other path in this file, so it cannot leave the repository. A declared
file that is missing or unreadable is a configuration error naming both files:
a policy never runs as though it had said nothing.

That file holds `[[clarify]]` tables and nothing else — any other key is
rejected naming it — and its entries go through the same validator, so an entry
means there exactly what it means here.

The two files have separate citation spaces. The policy's own entries are
`clarify[i]`; the imported ones are `clarifications[j]`, numbered within the
imported file. Every id derived from an entry follows: the citation on an
accepted verdict, `clarifications:invalid[j]`, the unused-entry warning, and
the entry a stale-override failure tells you to update. A citation therefore
names both which file to open and which table in it.

The entries are combined policy-first, and the first entry matching a package
decides it. A policy entry naming a package an imported entry also names
therefore shadows it — deliberately, so a local decision can take precedence
without editing the imported file.

Keep prose about an entry in its `comment` and `evidence` keys rather than in
`#` lines above it. The imported file is written to be machine-maintainable,
and comment lines around the tables are not part of what an entry records.

[`refresh-clarifications`](cli.md#refresh-clarifications) is what maintains it.
That subcommand rewrites this file whole — the entries come out in the key order
documented above, one blank line apart — so a `#` comment would not survive the
next `--write`. Rather than lose it, the subcommand refuses to write at all while
the file carries one. The policy proper is never rewritten, whatever it holds.

### Migrating from the previous schema

The keys below were replaced outright. An entry still carrying one is rejected
with a message naming its replacement:

| Removed | Replacement |
|---------|-------------|
| `package = { name, version }` | `name` (or `pattern`) and `version`, written directly on the entry. |
| `expects` | `detected`, which records each source separately. |
| `reason` | `justification`, plus `comment` for what it cannot carry. |

`version` is required on every clarify entry — it was optional before. A clarify
carries no `where`, so it has no container os-scope exemption: always pin the
version(s) the correction applies to.

### Name patterns

`pattern` selects a family of packages by their display name:

| Form | Covers |
|------|--------|
| `@scope/thing-*` | One name segment: `@scope/thing-a`, not `@scope/thing/a`. |
| `@scope/**` | Any depth beneath the scope. |
| `@scope/` | Shorthand for `@scope/**`. |

Both `name` and `pattern` select a package's canonical display name — the value
the report's Package column shows, such as `@img/sharp-win32-x64` — never its
purl. Matching is case-sensitive and covers the whole name. A pattern must
carry a wildcard — a pattern without one names a single package, so write
`name` instead — and at least one literal character, so a pattern of wildcards
alone cannot become a blanket rule. Versions have no wildcard anywhere in the
schema, and are required (with the one container os-scope exemption a
`[[compatible]]` entry has): list them when several share a judgment.

## `[[compatible]]`

An array of tables. Each entry accepts a licence or a package that would
otherwise be flagged as [copyleft](../glossary.md#copyleft), scoped to the
occurrences the required `where` covers. Absent table: no compatible rules.

Exactly one of two match modes per entry. `match` also decides how `pattern` is
read: an SPDX expression at licence level, a package-name glob at package
level.

Licence mode (`match = "license"`):

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"license"` | yes | Selects licence mode. |
| `pattern` | string (SPDX) | yes | An SPDX id or `OR` of ids, satisfies-matched. `AND` is rejected. |
| `rationale` | string (closed set) | yes | Why the licence is accepted — see below. |
| `where` | array of strings | yes | Occurrence-identity prefixes, or `["/"]` for every occurrence. |
| `comment` | string (non-empty) | no | What the rationale cannot carry. |

Package mode (`match = "package"`) — exactly one selector of `name`, `pattern`,
and `packages`:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `match` | `"package"` | yes | Selects package mode. |
| `name` | string | one selector of `name`/`pattern`/`packages` | One package, by its exact display name. |
| `pattern` | string (name glob) | one selector of `name`/`pattern`/`packages` | A family of packages by name — see [Name patterns](#name-patterns). |
| `packages` | array of `{ name, version }` | one selector of `name`/`pattern`/`packages` | A bundle of disparate packages sharing this entry's other fields — see [The `packages` list](#the-packages-list). |
| `version` | string, or array of strings | yes on a `name`/`pattern` entry (except a container os-scope one); not on a `packages` entry | The exact version, or versions, covered — see [Versions are required](#versions-are-required). |
| `as-dependency-of` | array of strings | yes | Whose use of this package you judged — see below. |
| `rationale` | string (closed set) | yes | Why the package is accepted — see below. |
| `where` | array of strings | yes | Occurrence-identity prefixes, or `["/"]` for every occurrence. |
| `comment` | string (non-empty) | no | What the rationale cannot carry. |

Licence mode allows a whole licence, such as a weak copyleft you have reviewed
and accepted like `MPL-2.0`. Package mode allows one dependency, a family of
them, or an explicit bundle of unrelated ones, for when only specific packages'
obligations have been reviewed rather than a whole licence.

### Versions are required

A `name` or `pattern` entry must pin a `version` — a single exact string, or a
non-empty list. Omitting it would carry the acceptance silently into a future
version, so a relicense in a new release could slip through unreviewed.

The one exception is an entry scoped **entirely** to a container os-scope: when
`where` is present and every element is a `docker:`-prefixed identity, `version`
may be omitted. A base image's OS-package versions are not author-controlled and
change on every rebuild, so pinning them would be churn rather than a guarantee.
A mixed `where` — any element that is not `docker:`-prefixed, `["/"]` included —
requires a version like any other entry. Clarify entries carry no `where` and so
have no exemption: a `[[clarify]]` always pins a version.

### The `packages` list

`packages` is a third selector, for `[[compatible]]` only, that bundles disparate
packages sharing the entry's other fields:

```toml
[[compatible]]
match = "package"
packages = [
  { name = "left-pad", version = "1.3.0" },
  { name = "right-pad", version = ["1.0.0", "1.0.1"] },
]
as-dependency-of = ["self"]
rationale = "unused-transitive"
where = ["apps/media"]
comment = "Both padding helpers arrive transitively and are never reached at runtime; reviewed together."
```

Each member is an exact `{ name, version }`: no glob inside a member — the family
selector stays the `pattern` mode — and every member pins its own `version`
(a string or a non-empty list). The entry-level `where`, `as-dependency-of`,
`rationale`, and optional `comment` are **shared** across every listed package;
that shared judgment is the whole point of bundling, so list packages together
only when they genuinely share it. An occurrence matches the entry when it
matches **any** member, and the entry is one rule wherever a verdict cites it —
one `compatible[i]` id, one voiding decision, one unused-entry report. It is
mutually exclusive with `name` and `pattern`: exactly one selector per entry.
`[[clarify]]` has no `packages` form, since a clarify's `detected` and
`expression` are intrinsically per-package.

### `rationale` — the closed set

The tool can only check a claim it understands, so the reason is chosen from a
fixed list. `comment` carries anything the list cannot.

| Value | Meaning |
|-------|---------|
| `build-time-only` | Consumed while building, absent from what ships. |
| `development-tool-only` | A tool for working on the repository, never reached by the product. |
| `license-reviewed` | A human read the licence and accepted its obligations. The sanctioned fallback when no structural reason applies. |
| `os-package-unmodified` | A distribution package shipped inside a container image exactly as it arrived, not linked into the software. |
| `unused-transitive` | Pulled in by a dependency but never reached at runtime. |

Wherever a verdict cites the entry, its reason is the rationale value, and the
comment after an em-dash when one is present.

Two of them state something the scan can contradict, and a contradiction is
rejected before any verdict: `os-package-unmodified` on a package outside a
container image's OS layer, and `unused-transitive` on a package your project
declares directly. The rest state a judgment about how your software is built
that no scan observes — overriding what the tool concluded is exactly what they
are for — so they are taken as written.

### `as-dependency-of` — whose use you judged

Package-mode acceptances are about how a package arrives, not only about the
package. A build tool's copyleft is fine while a build tool pulls it in; the
same package reaching your shipped code through a different chain is a
different question, and the same entry should not silently answer both.

Each element is a package's display name, or the reserved token `self`, meaning
your own software. On a target with a dependency graph, `self` is the direct
edge from your project — that package, declared by you, and nothing else. On a
target without one — a container image's OS layer, for instance — there are no
recorded chains to check, so `self` is the only value allowed there and it
accepts every occurrence the entry's `where` reaches. That acceptance is not
chain-scoped, and no verdict it decides claims it is; `where` is what scopes
it.

#### What the tool checks

A parent must be checkable where the entry is scoped, and the scan settles that
before any verdict is decided. Two things are rejected outright, with the entry,
the target and the fix named:

- a parent other than `self` at a target with no dependency graph — there is no
  chain to check there, so scope `where` to the targets that have one, or say
  `self` and mean it;
- a parent no node of the target's graph carries. Your own workspace members
  count as nodes even though they never appear in the inventory: a package
  arriving through one is `as-dependency-of = ["<the member>"]`, never `self`.

Both depend on what the scan found, so a policy that was fine yesterday can be
rejected today — adding a first target without a dependency graph is enough.
That is the point: the entry says something the new scan cannot check.

#### When the judgment turns out to be untrue

Where the target has a dependency graph, the tool walks every chain by which
the packages the entry accepts reach your project. If one of them arrives
through a chain passing none of the parents you named, what the entry claims is
not what the scan sees, and the tool refuses to apply it: **the whole entry is
void at that target**. Every occurrence it governs there fails, cited as
`compatible:voided[i]`, and the reason names the offending chain and the
package that arrives through it.

The failure is the entry's, not one package's — a bulk entry accepting a family
of packages fails for all of them at that target. Splitting it into narrower
entries, each covering one way in, is how you recover: it is the same
information, stated so each part is true.

Two cases decide nothing rather than voiding anything. A package your project
declares directly is covered by `self` and by nothing else. And an occurrence
whose arrival the scan did not record — no introduction at all, or a transitive
one nothing reachable introduces — is not covered by any parent, `self`
included, and equally never voids an entry: nothing is known about how it
arrives, which is neither an acceptance nor evidence of a bypass.

`as-dependency-of` is not applicable at licence level and is rejected there: a
licence is accepted wherever `where` covers it, not through one package's use
of another.

### `where` — which occurrences you judged

`where` limits either form to the occurrences whose target matches one of its
entries: the target is the entry itself, or sits under it as a whole segment.
`docker:a` covers `docker:a/Dockerfile`; `apps/media` never covers
`apps/media-helper`. Docker targets are `docker:<source>` — the Dockerfile's
repo-relative path for a built image, the image reference verbatim for an
`--image` scan; app targets are workspace paths. Entries are validated like
suppression paths (forward slashes only, no `..` segment, no leading or
trailing slash); an empty array is rejected.

`where` is required so that scoping stays a decision rather than a default. A
deliberately repository-wide acceptance is still expressible, and visibly so:
the reserved element `/` covers every occurrence. No target identity can be
`/`, since a leading or trailing slash is rejected wherever a path is
validated, so the token is unambiguous.

Rules are consulted in file order per occurrence, and the first whose match and
scope both hold decides. A rule that matches no occurrence is reported as an
unused entry on stderr.

### Migrating from the previous schema

The keys below were replaced outright. An entry still carrying one is rejected
with a message naming its replacement:

| Removed | Replacement |
|---------|-------------|
| `reason` | `rationale`, plus `comment` for what it cannot carry. |

`where` was optional and is now required; `as-dependency-of` and `rationale`
are new and required. An entry using `as-dependency-of` at licence level is
rejected as inapplicable. `version` was optional and is now required on a
`name`/`pattern` entry — except one scoped entirely to a container os-scope,
which may still omit it (see [Versions are required](#versions-are-required)).

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
`path` match is segment-aware, so `apps/reporting` covers occurrences under it
but never a sibling like `apps/reporting-helper`. `path` is also rejected if
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
| `license` | string | yes | One FOSS SPDX id covered by the OSADL compatibility matrix's own rows, or the literal `"proprietary"`. A compound expression (`MIT OR Apache-2.0`, dual-licensed targets aren't supported yet), a `LicenseRef-`/`DocumentRef-` reference, or a valid SPDX id the matrix simply has no row for is rejected — none can anchor a compatibility-matrix row. |
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
