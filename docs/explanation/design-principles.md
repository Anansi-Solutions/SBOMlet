# Design principles

This page is for contributors. It records the principles the tool is built
around, the reasoning behind each, and the files that hold each one up. Before
you change behaviour, read the principle the existing code is protecting and keep
it protected.

Each principle is load-bearing. The [gate](../glossary.md#the-gate-check)'s
correctness, the tool's portability, and its legal credibility depend on them,
and each is enforced in code. Most modules state their principle in their own
header comments; this page gathers those scattered statements into one set of
rules and links each to the [architecture decision record](adr/) that argued it
through.

For how the pieces fit together rather than why, see
[`architecture.md`](./architecture.md). For the model the principles operate
over, see [`data-model.md`](./data-model.md). For how a
[claim](../glossary.md#license-claim) travels from a
[collector](../glossary.md#collector) to a rendered
[verdict](../glossary.md#verdict), see [`data-flow.md`](./data-flow.md).

---

## Determinism is a prerequisite of the gate

Generating the documents twice from the same inputs produces byte-identical
output: no timestamps, no serial numbers, no locale-sensitive ordering, no
platform line endings.

This comes first because everything else rests on it. The
[`check`](../glossary.md#the-gate-check) command regenerates every configured
output in memory and compares those bytes against the committed files. If
generation were not deterministic, that comparison would report a phantom
[staleness](../glossary.md#staleness) on every run and the gate would be useless.
Determinism is what makes a byte-comparison gate possible at all.

The intention holds tool-wide in four ways. Every sort routes through one string
comparator that orders by UTF-16 code unit with bare `<`/`>`, never a
locale-sensitive compare; locale ordering is ICU-dependent and differs across
Windows, Linux, and runtimes, which would silently break byte-identity. Every
on-disk JSON artifact serializes through one sorted-key serializer that indents
by two and appends a trailing newline, and since `JSON.stringify` never emits
`\r` the result is LF-only by construction. The Markdown renderer assembles its
lines with `"\n"` literals and never the platform EOL constant, so the same model
produces the same bytes everywhere. And the volatile fields a generator stamps
into its output — the document serial number, the metadata timestamp, generator
annotations — are never declared in the schema at the
[merge](../glossary.md#merge) boundary, so they cannot leak into compared content
even when a fixture carries them.

One place needs a real clock, and it is kept off every compared surface. The
[enrichment](../glossary.md#enrichment-and-the-enrichment-cache) stage takes an injectable
`now` source, production by default and overridden in tests, and the value it
stamps lands only on the cache's `fetchedAt` field, never in any rendered
document. Copy that pattern if you ever need the time of day: inject it, and keep
it out of anything `check` compares.

This has a practical consequence for `check` itself. It writes nothing, and both
sides of its comparison come from one build. The pipeline that produces the
in-memory strings is write-free, and the only file writes in the
cli/pipeline/gate trio live in `generate`. The string `check` compares is exactly
what `generate` would write, so there is no regenerate-then-compare window and
nothing is round-tripped through disk.

If you reach for `Date.now()`, `toLocaleString`, a bare `Array.prototype.sort`,
or the OS EOL constant in a path that feeds an output, you are about to break the
gate. Any new artifact serializes through the sorted serializer; any new rendered
surface uses `"\n"` and the code-unit comparator.

Source: `model/dependencies.ts` (`compareCodeUnits`, `comparePackages`,
`toSortedJson`), `render/markdown.ts`, `merge/merge.ts`, `enrich/enrich.ts`,
`pipeline/pipeline.ts`, `gate/check.ts`, `test/determinism.test.ts`.
See [ADR-0004](adr/) (deterministic, timestamp-free output).

---

## Minimal dependencies; orchestrate standard tools

The tool that audits dependencies must not itself drag in thousands of them, and
it must not re-implement license detection that mature tools already do. Where an
industry-standard scanner exists, it is wired in as a pinned, swappable
[generator](../glossary.md#generator) the tool drives.

There are two reasons. A license auditor with a sprawling dependency tree is its
own compliance liability and undercuts its own message. And SBOM generation and
license detection are solved problems with credible tools; re-deriving them by
hand would be less correct and harder to defend in an audit.

The runtime dependency list is therefore small: six packages, namely an
untrusted-input validator, a TOML parser for the
[policy](../glossary.md#policy-lanes), and four [SPDX](../glossary.md#spdx)
libraries for correcting, parsing, listing, and satisfying license expressions.
There is no CLI framework; the CLI parses its arguments with Node's built-in
`parseArgs`, a choice the module header ties directly to the dependency-footprint
constraint. Detection is orchestrated: per-ecosystem collection delegates to
pinned external generators. Yarn-4 lockfiles route to the Yarn CycloneDX plugin;
other npm and pnpm lockfiles and all Python lockfiles route to cdxgen, which is
where Poetry licences come from. Docker OS packages are scanned by syft, but only
in the maintainer-only `generate-docker-sbom` subcommand, which writes a committed
`.sbomlet.cache/docker-os.sbom.json`; `generate` and `check` never run a docker daemon — they
read that file as an `os`-scope merge input. The version tag inside each argv is
the pin, floating tags are forbidden, and each argv is locked byte-for-byte by a
test, so changing a flag must consciously break that test and invalidate the
goldens.

Two [collectors](../glossary.md#collector) emit [CycloneDX](../glossary.md#cyclonedx)
in-house, each with its reason recorded in the module header. The Terraform
collector exists because no upstream tool resolves Terraform provider and module
licenses; cdxgen's Terraform mode emits components with zero licenses. The
`bun.lock` collector exists for the same reason: cdxgen and syft both emit zero
components for `bun.lock`, and trivy corrupts package identity on version-conflict
entries. Even these add no new runtime dependency and emit the same minimal,
deterministic CycloneDX 1.6 every orchestrated generator produces.

Before adding a dependency, check whether the standard library or one of the six
existing ones already covers it. Before writing a parser, check whether a credible
tool already does the job; if you must write one, record why no tool serves in the
module header, the way the Terraform and `bun.lock` collectors do.

Source: `cli.ts`, `package.json`, `collectors/cdxgen.ts`,
`collectors/dockerOs.ts` (`SYFT_TOOL`), `collectors/terraform.ts`.
See [ADR-0002](adr/) (orchestrate generators), [ADR-0010](adr/) (JS generator
routing), [ADR-0011](adr/) (Python via cdxgen), [ADR-0001](adr/) (TypeScript on
Bun).

---

## Honest residual; correct by construction

When the tool cannot compute something precisely it renders an
[honest residual](../glossary.md#honest-residual) — a literal `—`, an explicit
`unresolved`, or a surfaced raw token — or it fails loudly. It never fabricates a
value and never guesses. Where a signal is available structurally, on the
filesystem or in a lockfile graph, the tool reads that rather than lexing
free-form text.

An inventory that quietly guesses is worse than one that admits ignorance. A
confident-but-wrong license id can pass a gate it should have failed, and a
fabricated provenance chain misleads the auditor reading it. Shaping the code so
the bad state cannot be represented at all removes a whole class of bugs instead
of patching them one fixture at a time. This principle has the most worked
examples, because the project has repeatedly taken the residual over a tempting
guess.

The intention is one rule applied across the tool: avoid wrong answers, and
clearly surface the ambiguities a human needs to resolve. It shows up in five
places, each shaped by what it is refusing to guess.

[Imprecise license families](../glossary.md#imprecise-family) are surfaced, not
invented. `spdx-correct` will turn the bare label `"BSD"` into `BSD-2-Clause`,
`"Apache"` into `Apache-2.0`, `"GPL"` into `GPL-3.0-or-later`, and `"EUPL"`, which
is strong [copyleft](../glossary.md#copyleft), into the permissive `UPL-1.0`. Each
is a clause or version the source never stated.
[Normalization](../glossary.md#normalization) intercepts these family labels
before `correct()` sees them and records the package as an imprecise
[finding](../glossary.md#license-finding): the SPDX expression stays empty, and
the faithful family token rides alongside it. The renderer shows
`"<family> (imprecise)"` and gathers every such package into its own review
section, and the policy routes a bare GPL/AGPL/LGPL/EUPL token to a surfacing
`imprecise-copyleft` warn rather than letting it pass silently. The cure is a
[`[[clarify]]`](../glossary.md#policy-lanes) override, which is itself auditable.

The Terraform gate keys on a filesystem signal, not a hand-lexed HCL parse. The
collector needs one answer — did `tofu init` run? — and earlier revisions
hand-lexed `.tf` files to find `module` blocks. Four consecutive adversarial
reviews each found another valid-HCL shape the lexer mis-tokenized into a silent
module drop. The redesign deletes the lexer and reads the filesystem instead.
`tofu init`/`tofu get` writes `.terraform/modules/modules.json` the moment it
processes any module call, so a present `.terraform/providers/` directory with
`.terraform/modules/` absent is a real providers-only init, and any other shape
fails loud with a "run tofu init first" error. Provider versions come from a tight
regex over the committed lock file — the lock is the pin, no `.tf` constraint
blocks are read — and module versions from `modules.json` verbatim. The
mis-tokenization bug class disappears because no `.tf` source is ever inspected.

Dockerfile base derivation emits `unresolved` rather than a wrong base. The
deriver resolves a Dockerfile's shipped `FROM` ref, stripping `--platform`,
substituting `ARG` defaults to a fixpoint, and following `AS` aliases, but it is a
tight parser, not a full Dockerfile AST, and it is honest on anything ambiguous.
Its result is a discriminated union of image, scratch, or unresolved. A residual
`$` after substitution, an empty or flag-shaped token, a missing `FROM`, a cyclic
alias, or any ref that fails the conservative validator becomes `unresolved`,
which the caller warns about and skips rather than emitting a guess. Discovery is
honest too: it matches Dockerfiles by name pattern with no extension blocklist,
because a blocklist silently drops real variants; a stray non-Dockerfile that
matches the name resolves to `unresolved` and is skipped.

[Provenance](../glossary.md#dependency-provenance) introducers are always
root-reachable. The reason a dependency is present is derived from real dependency
graphs — the npm BOM graph and the `poetry.lock` dependency tables — through one
shared function, and its central invariant is that a node's introducers may name
only parents that are themselves reachable from a declared root. The reachable set
is computed once and every node's parent set is intersected with it. The npm lane
goes one step further and re-derives each transitive's introducers from the real,
root-reachable graph, so a parent whose only edge sits on a root-disconnected
duplicate-purl variant is dropped, keeping the introducer set consistent with the
path it emits. A transitive whose parents are all root-disconnected gets an empty
introducer set and the renderer shows the honest `—`; a mix keeps only the
reachable parents. The representative path is one shortest chain, deterministically
tie-broken; the introducer set is complete, so a single path is honestly flagged
as one-of-many for a multi-parent package. Every other source leaves provenance
absent and the renderer shows `—` rather than a fabricated value.

Optionality was descoped rather than guessed. Provenance once tried to derive
whether a Python dependency was optional from poetry markers: `optional = true`,
PEP 508 marker variables, extras, multi-variant spec arrays. That marker parsing
was a recurring mislabeling bug, flagged in three of four adversarial-review
rounds, and was removed. There is intentionally no `optional` field: every
dependency edge is a plain edge. Descoping a signal that cannot be derived
reliably is itself the honest-residual rule, since no claim is better than a wrong
one.

One rule cuts across these. When a package's claims mix a normalizable license
with a genuinely unparseable token, the finding collapses to unknown for every
gating scope, because partial knowledge must not hide an obligation. The single
exception is the non-gating [`os` scope](../glossary.md#scope-app-and-os), where the
known SPDX members are kept and the unparseable remainder is surfaced verbatim as
a `"(+ tok, tok)"` suffix, shown for review, never silently dropped, and never
allowed into the gating expression.

When you cannot compute a value precisely, the choices are to render `—` or
`unknown`, surface the raw token, or throw loudly. Never invent. When a decision
can be read from a structural signal — a file's existence, a lockfile edge, a purl
shape — read that instead of lexing free-form text; structural signals have no
decoy edge cases.

Source: `normalize/normalize.ts` (`AMBIGUOUS_FAMILY`, `findingFromClaims`),
`policy/copyleftFamily.ts`, `collectors/terraform.ts`
(`absentModulesJsonShouldFail`), `collectors/dockerfile.ts` (`deriveBaseImage`,
`isValidImageRef`), `collectors/provenanceGraph.ts` (`reachableFromRoots`),
`collectors/npmProvenance.ts`, `render/markdown.ts` (`whyCellOf`,
`licenseCellOf`).
See [ADR-0007](adr/) (imprecise families surfaced), [ADR-0015](adr/) (Terraform
and Dockerfile abstain rather than parse),
[ADR-0014](adr/) (root-reachable provenance).

---

## Deny is terminal at precedence 0, over every observed claim

A [source-available](../glossary.md#source-available) or use-restricted license —
BUSL, SSPL, Elastic, RSAL, or a rider like Commons-Clause — that appears anywhere
in a package's observed claims fails the gate, and nothing licenses it back in: no
compatible rule, no workspace suppression, no dev or os scope downgrade, no
clarify or builtin override, not even one that applied successfully.

This is the tool's load-bearing safety property. The point of a compliance gate is
that a license a project legally cannot redistribute never passes silently. Every
other lever in the policy engine accepts dependencies;
[deny](../glossary.md#policy-lanes) is the one lever that rejects, so to be
trustworthy it has to sit above all acceptance and be impossible to route around.

The intention is enforced in one shape, in three reinforcing parts. Deny is the
first branch of the per-package verdict and returns immediately; the
stale-override lane, compatible rules, workspace suppression, and the scope
downgraders all sit strictly below it. Deny is evaluated over every observed
claim, not only the combined expression: the check consults the combined
assessment expression, the pre-override observed expression (so a denied license
an override rewrote can never be reinstated), and the set of every per-claim
precise expression. That third source matters because combining can elect an
imprecise family or collapse to unknown before a precise denied member like
BUSL-1.1, so reading only the combined expression would miss it. And the match is
OR-election-consistent over the union of every license-mode deny entry: a finding
is denied only when it cannot elect out of the deny set, so `"MIT OR BUSL-1.1"` is
correctly not denied, while `"BUSL-1.1 OR SSPL-1.0"`, both members listed
separately, has no electable branch and is denied. Name-mode, for non-SPDX riders,
is an exact case-sensitive package-name compare that needs no parseable
expression.

The scope knobs are the one place a fail can be downgraded, and they are written
so they can never touch a deny. The dev and os downgraders only ever soften a
would-be default fail, never a deny, and they soften a dev or os
[occurrence](../glossary.md#occurrence) only; a
[production](../glossary.md#development-only-and-production) occurrence's fail is
returned unchanged. A shipped copyleft or unknown can never be dev-downgraded, and
a denied license fails regardless of scope.

Treat the deny branch and its three-source evaluation as untouchable safety code.
A new acceptance lever goes below deny in the verdict function, never above. A new
way for a license to be observed must flow into the per-claim expression set so
deny can see it. The review history of this engine exists largely to protect this
property.

Source: `policy/evaluate.ts` (`verdictFor`, `firstDeny`, `applyDevScope`,
`applyOsScope`), `policy/denylist.ts`, `normalize/normalize.ts`
(`observedExpressions`).
See [ADR-0013](adr/) (deny terminal at precedence 0),
[ADR-0009](adr/) (a production occurrence always gates).

---

## Standards: SPDX identifiers and CycloneDX 1.6

Licenses are [SPDX](../glossary.md#spdx) identifiers and expressions; SBOM
documents are [CycloneDX](../glossary.md#cyclonedx) 1.6.

Standards buy interoperability and credibility. An auditor, a downstream consumer,
or another tool can ingest the output without bespoke parsing, and the SPDX
expression algebra — satisfies, election — gives the policy engine a rigorous
semantics instead of ad-hoc string matching.

SPDX therefore runs through normalization and policy end to end: normalization
parses and corrects with the SPDX libraries, and the policy engine matches with
`spdx-satisfies` over pre-decomposed OR-leaf allowlists. There is no substring
matching on license values anywhere; patterns flow through the expression parser
and its OR leaves. Every collector emits CycloneDX 1.6, and the
[merge](../glossary.md#merge) joins packages on their [purl](../glossary.md#purl),
kept verbatim from the SBOM with URL-encoding intact; the ecosystem column is
derived from the purl's type segment. The merged CycloneDX export is a first-class
output.

The exception worth knowing is deliberate strictness rather than a departure. The
syft collector asserts the scanner returned `specVersion` 1.6 and fails loudly
otherwise, and the Terraform and Docker emitters stamp 1.6 on their own minimal
documents. If you bump a scanner that changes the spec version, that assertion
catches it, which is the point.

Resist matching licenses by substring or regex; route through the SPDX libraries.
New SBOM output stays CycloneDX 1.6.

Source: `normalize/normalize.ts`, `policy/evaluate.ts`, `policy/schema.ts`,
`collectors/dockerOs.ts` (`parseSyftOutput`), `render/cyclonedx.ts`,
`render/markdown.ts` (`ecosystemOf`).
See [ADR-0003](adr/) (CycloneDX interchange, purl as merge key).

---

## Adversarial review before completion

A safety-relevant change is not done when the tests pass. It is done after a
multi-lens adversarial review has tried to find the input shape that defeats it.

TDD and golden files prove the cases you thought of. The bugs that let a copyleft
or source-available license slip past the gate are, by definition, the cases you
did not think of: the decoy HCL shape, the imprecise family that elects before a
denied member, the orphan introduction that hides a real direct dependency. A
deliberate adversarial pass, run before a change is declared complete, catches the
gate-bypass bugs that example-based tests miss.

The evidence that this is a real discipline is woven into the source as
review-round annotations, each marking a bug an adversarial pass caught. The
Terraform filesystem gate exists because four consecutive reviews each found
another valid-HCL shape the prior lexer mis-tokenized. Poetry optionality was
removed after being flagged in three of four review rounds. Deny's three-source
evaluation carries inline markers, each recording a specific way a denied license
could otherwise have been hidden. The provenance "why" cell's orphan-exclusion
logic and the Dockerfile deriver's numbered residual guards are each a
review-caught case. The labels are the artifact: a comment that says a branch
closes a specific finding from a specific round is telling you that branch is
load-bearing and was added to fix a real bypass, not for tidiness.

When you touch the policy engine, the normalizer's combine logic, the deny
matcher, a collector's honest-residual gate, or anything that decides a verdict,
run an adversarial pass before you call it done: construct the malformed,
ambiguous, multi-parent, mixed-scope, or relicense-in-flight input that would
defeat your change, and add a failing test for it first. Preserve the review-round
annotations when you refactor; each one marks a property that was hard-won and is
easy to regress silently.

Source: `collectors/terraform.ts`, `model/dependencies.ts`,
`collectors/poetryProvenance.ts`, `policy/evaluate.ts`, `policy/denylist.ts`,
`render/markdown.ts`, `collectors/dockerfile.ts`.

---

## How the principles reinforce each other

The principles lean on one another. Determinism is what makes the byte-comparison
gate possible. The gate is where the deny terminal actually bites. The deny
terminal stays correct across imprecise and unknown findings only because honest
normalization refuses to guess a family into a precise id. Those residuals are
credible only because the tool speaks SPDX and CycloneDX faithfully. And the whole
set is kept honest by adversarial review, the discipline that turned a fragile HCL
lexer into a filesystem signal and a guessable base image into an explicit
`unresolved`. Minimal dependencies and orchestration keep the surface small enough
for that scrutiny to stay tractable. Change one in isolation and you risk
undermining the others, so weigh a change against the whole set.
