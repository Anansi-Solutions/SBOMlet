# Report placement

This page is for the renderer and anyone changing it. It is the normative
placement specification for `THIRD_PARTY_LICENSES.md` — for any
[package entry](../glossary.md#package-entry), exactly where its row lands
and why, given the scope and verdict
[dependency-classification.md](./dependency-classification.md) already
decided. `src/render/markdown.ts` and the placement tests follow it; a
behavior change to it updates this page in the same commit. Each path in the
Path index below is verified one-to-one by `test/reportPlacement.test.ts`,
alongside its classification counterpart in
[dependency-classification.md](./dependency-classification.md); the page,
the suite, and the implementation change together.

These are the placement rules for the markdown report
(`THIRD_PARTY_LICENSES.md`) only. Classification — a package's scope and its
policy verdict — is decided upstream, in
[dependency-classification.md](./dependency-classification.md); a future
output format (a JSON export, say) would define its own placement page
against that same classification tree, not this one.
`THIRD_PARTY_NOTICES.md` already has one:
[notices-placement.md](./notices-placement.md).

Placement is one question, asked after classification already answered scope
and verdict: given a package's scope and verdict, which section does it land
in? This page answers that, then closes with the invariants that must hold
regardless.

## Section placement

`renderMarkdown` places every package into two different kinds of section, in
this fixed order: package counts, Problematic licenses (policy run only),
Copyleft and special notices (policy run only), Target compatibility (policy
run only, and only when the target lane held an occurrence for internal use),
Imprecise licenses, Assessment conflicts, Containers, Production
dependencies, Development-only dependencies. See
[output-format.md](./output-format.md) for what each column means; this
page states only where a package lands.

### Narrative sections (verdict- or finding-driven, deduped)

- **Problematic licenses** — every `fail` and `warn` verdict, one row per
  (severity, purl, rule, reason), fail rows before warn rows. It is the only
  section that rows a `fail` or `warn` verdict, so every warning the
  [non-blocking summary](../glossary.md#non-blocking-summary) counts is
  locatable here, and a warned package with no fail appears here and not in
  Copyleft and special notices or Target compatibility. A package with both a
  fail and a warn gets one row per severity: each row's Used-in cell names
  only the occurrences its own verdicts decided, failing targets on a fail
  row and warned targets on a warn row. A purl carrying a fail anywhere never
  appears in Copyleft's accepted-AGPL notice list. Target compatibility's
  held-for-internal-use list is exempt from that: a `target:internal-use`
  verdict at one occurrence is never suppressed by a fail at a *different*
  occurrence of the same purl — the two describe unrelated facts (one
  occurrence discharges an out-of-scope obligation, another fails outright
  under its own profile), and the hold's own visibility guarantee (see the
  invariants below) requires the row to stay enumerable regardless of what any
  other occurrence decides.
- **Copyleft and special notices** — two independent parts, neither of them
  a verdict row (a copyleft `fail` or `warn` rows in Problematic licenses):
  - The suppressed-workspaces list, shown whenever policy configures any,
    whether or not it currently suppresses anything. A suppression a declared
    target governs never decides anything (the target-compatibility lane
    intercepts the occurrence first — see
    [dependency-classification.md](./dependency-classification.md)), but it
    still renders here unconditionally when configured; `policy/engine/target.ts`'s
    `suppressionOverlapNotices` is a stderr-only diagnostic, not a placement
    change.
  - Accepted-AGPL container notices: a scope-`os` package whose AGPL
    obligation (a precise leaf, or the imprecise `AGPL` token) was accepted
    through a `[[compatible]]` rule at some occurrence, OR demoted to a
    routine `ok` by a complete project target profile's `network = false`
    (`[os_dependencies] = "ignore"`) — both excluded when the purl also
    carries a fail elsewhere. Either acceptance path renders identically here
    (a bullet naming the accepting/demoting rule and its reason); the
    declared-`network` reason names the demotion basis instead of a
    `[[compatible]]` citation.

  When neither part renders, the section is the line
  `✅ No copyleft or special notices.` The accepted-notice mechanism exists only for the two
  cases that would otherwise fail (or go silently `ok`) unconditionally, the
  container-system AGPL escalation and its network=false-demoted sibling; an
  occurrence `[[compatible]]` accepts never reaches the copyleft lane at all
  ([dependency-classification.md](./dependency-classification.md), tier 5
  decides first), so it rows nowhere but its inventory table.
- **Target compatibility** — policy run only, and only rendered at all when at
  least one `target:internal-use` (status `ok`) verdict exists (unlike
  Copyleft, an empty lane renders no heading). It is a "held for internal
  use" bullet list, one bullet per such verdict — the usage profile takes the
  obligation out of scope, but the row stays visible for the day the profile
  flips (never silent, unlike a bare `ok` would be). NOT excluded by a fail
  at another occurrence: see the Problematic licenses note above.

  A `target:ok` verdict never rows here (it is a clean pass, exactly like
  `default:ok`); a `target:boundary`, `target:unknown-pair`, or
  `target:incompatible` verdict, `warn` or `fail`, rows in Problematic
  licenses instead.
- **Imprecise licenses** — every package whose finding is imprecise,
  unconditionally, independent of its verdict. This overlaps Problematic
  licenses by design: a bare-`AGPL` system package that fails
  `default:agpl-container`, or a bare-`GPL` package that warns
  `default:imprecise-copyleft`, rows in both.
- **Assessment conflicts** — every package whose finding carries a conflict
  marker, unconditionally, from either trigger (the ScanCode disagreement, or
  a cross-image license-claim divergence). A package here also rows in
  Problematic, since a conflict is always a fail.
  Each trigger renders its own sub-table (a ScanCode conflict's In-depth/Quick
  check columns and a cross-image divergence's per-image claims name different
  things and never share a row shape); a purl with a cross-image divergence
  also keeps its complete inventory row in every diverging container's
  subsection, same as any other package.

### Inventory sections (placement-driven, complete — nothing is ever dropped)

- **Containers** — a thin index of every analyzed container (one row per
  distinct `docker:<source>` occurrence target), classified `production` or
  `development` by the `[[docker.development]]` globs.
- **Production dependencies** — the app table (every package with a workspace
  occurrence that isn't
  [development-only](../glossary.md#development-only-and-production)) plus one
  `### Container: docker:<source>` subsection per container *not* marked
  development.
- **Development-only dependencies** — the app table (every occurrence
  development) plus one container subsection per container marked
  development.
- **Container subsection** — every package with a docker occurrence in that
  container, with no exclusion — a Problematic-escalated package still rows
  here. Split into a System packages table (the OS allowlist) and an
  Application packages table (everything else), each sorted the same way as
  the inventory tables; an empty half is omitted.
- A package shared with a workspace rows in *both* its app table and each
  container subsection it occurs in — a complete inventory, not an exclusive
  choice.

### Counts

- Total: every package entry.
- One line per ecosystem, sorted by name.
- Production + Development-only = Total, a two-way partition. This pair uses
  its own placement predicate, not the app-table split directly: a package
  counts development-only when it has no occurrence in a production-classified
  container *and* is either a pure-container package or has every occurrence
  marked development. That second clause is what lets a system package —
  never development-marked itself, per
  [dependency-classification.md](./dependency-classification.md) — still
  count development-only when its only container is
  `[[docker.development]]`-marked.
- Container packages (any docker occurrence) and Unknown license are
  cross-cutting subtotals, not a third slice of the partition — a package can
  be counted in either in addition to its Production or Development-only
  bucket.

Source: `src/render/markdown.ts` (`renderMarkdown` and its section-lines
helpers).

## Invariants

- Every package has exactly one Production/Development-only classification.
- Every `fail` and `warn` verdict rows in Problematic licenses, and no other
  narrative section rows one: what the non-blocking summary counts, the
  reader finds there. A package in Problematic keeps its inventory row, its
  Imprecise-licenses row, and its Assessment-conflicts row. A DIFFERENT
  occurrence of the same purl that holds (`target:internal-use`) still rows
  in Target compatibility's held list — see the invariants below.
- An AGPL obligation is always visible: a fail routes to Problematic, an
  accepted system AGPL (via `[[compatible]]` or a declared `network = false`
  demotion) routes to a special notice, and it is never silently absent.
- Routine system copyleft (anything but AGPL) never appears in the Copyleft
  section: it rows under its container, and in Problematic licenses when
  `[os_dependencies]` leaves it a `warn` or `fail`.
- A `target:internal-use` row always renders in Target compatibility's held
  list — never silently absorbed into a bare inventory row.
- Absent a `[target]` table, the Target compatibility section never renders
  at all, and every other section's bytes are identical to the same run with
  no `[target]` table.
- The report is byte-deterministic: fixed section order, stable sorts
  throughout.

## Path index (verified end to end)

The same 51 paths as
[dependency-classification.md](./dependency-classification.md#path-index-verified-end-to-end),
one row each, stating where the package lands in the markdown report instead
of its Stage-1/Stage-2 outcome — the two tables share one slug set, verified
by the same suite (`test/reportPlacement.test.ts`).

| id | given | lands |
| --- | --- | --- |
| `workspace-prod-permissive` | npm workspace prod dependency, permissive license | Production dependencies (app table) |
| `workspace-dev-only` | npm workspace dependency, every occurrence dev | Development-only dependencies (app table) |
| `shared-workspace-and-container` | npm dependency in a workspace AND baked into a prod container | Production dependencies (app table) AND that container's Application packages table |
| `container-only-system` | apk/deb package, container-only | that container's System packages table only |
| `container-only-app-ecosystem` | npm package baked into a prod container, permissive, container-only | that container's Application packages table only |
| `unrecognized-ecosystem-gates` | unrecognized purl ecosystem, copyleft, in a prod container | Problematic licenses (fails `default:copyleft`, the allowlist fails safe) + that container's Application packages table |
| `system-copyleft-os-warn` | apk GPL-2.0-only, `os_dependencies = "warn"` | Problematic licenses (warn row) + that container's System packages table; not Copyleft |
| `system-copyleft-os-fail` | same, `os_dependencies = "fail"` | Problematic licenses |
| `system-copyleft-os-ignore` | same, `os_dependencies = "ignore"` | inventory only (that container's System packages table) |
| `system-agpl-escalates` | apk AGPL-3.0-only, `os_dependencies = "warn"` | Problematic licenses (`default:agpl-container` — the warn knob cannot soften it) |
| `system-agpl-accepted-notice` | same, accepted via `[[compatible]]` | accepted-AGPL notice in Copyleft and special notices; not Problematic |
| `system-agpl-imprecise-escalates` | imprecise bare-`AGPL` system package | Problematic licenses AND Imprecise licenses (overlap by design) |
| `system-agpl-imprecise-accepted` | same, accepted | accepted-AGPL notice in Copyleft and special notices AND Imprecise licenses |
| `mixed-agpl-fail-and-accept` | one AGPL system purl, failing in one container, accepted in another | Problematic licenses only, no notice |
| `app-copyleft-prod-container` | golang/npm copyleft baked into a prod container | Problematic licenses + that container's Application packages table |
| `app-copyleft-dev-container` | app-ecosystem copyleft in a `[[docker.development]]` container | Problematic licenses (dev-downgraded warn row); subsection under Development-only dependencies |
| `app-copyleft-workspace-dev` | workspace dev-dependency copyleft | Problematic licenses (warn row); Development-only dependencies (app table) |
| `problematic-dedup-keeps-inventory` | workspace prod copyleft, fails | Problematic licenses only (never Copyleft); still in Production dependencies (app table) |
| `fail-and-warn-one-package` | one workspace copyleft package, a production occurrence in one workspace and a dev occurrence in another, `dev_dependencies = "warn"` | Problematic licenses: a fail row naming the production workspace, then a warn row naming the dev workspace; Production dependencies (app table) |
| `imprecise-copyleft-family` | bare `GPL` app package | Problematic licenses (warn row) + Imprecise licenses; never Copyleft |
| `imprecise-permissive-family` | bare `BSD` app package | Problematic licenses (warn row) + Imprecise licenses |
| `unknown-license-counted` | [unknown] handling = "warn", no license | counted under Unknown license; Problematic licenses (warn row); inventory row (app table) |
| `licenseref-only-unknown` | a package whose only license content is a LicenseRef | counted under Unknown license; Problematic licenses (warn row); inventory row; never Copyleft or Imprecise |
| `suppressed-workspace-copyleft` | absorption-justified `[[workspace.copyleft_suppressed]]` | suppressed-workspaces list in Copyleft and special notices; no flagged row |
| `denied-license-terminal` | a `[[deny]]` match with a `[[compatible]]` rule that would otherwise accept it | Problematic licenses (deny is terminal) |
| `system-package-in-dev-container-counts-dev` | apk permissive package whose only container is dev-marked | counted Development-only (via the container's classification); System packages table under the Development-only subsection |
| `conflict-scancode` | npm workspace package whose in-depth scan answer disagrees with the declared claim, no `[[clarify]]` resolving it | Problematic licenses + Assessment conflicts (ScanCode assessment vs quick check sub-table) + Production dependencies (app table) |
| `detected-mismatch` | npm workspace package a `[[clarify]]` entry recorded as `BSD` in the registry lane, now reporting GPL-3.0-only there | Problematic licenses + Production dependencies (app table); the unapplied expression never appears |
| `cross-image-claim-divergence` | apk purl baked into two prod containers with different declared licenses | Problematic licenses + Assessment conflicts (Cross-image license claims sub-table) + both containers' System packages tables |
| `target-ok-permissive` | MIT dep under a (MIT, network=false, external) target | Production dependencies (app table) only |
| `target-incompatible-prod` | GPL-3.0-only dep under a (MIT, external) target, prod occurrence | Problematic licenses |
| `target-incompatible-dev-downgrade` | same finding, dev occurrence, `dev_dependencies = "warn"` | Problematic licenses (warn row) + Development-only dependencies (app table) |
| `target-apache-gpl2-incompatible` | Apache-2.0 dep under a (GPL-2.0-only, external) target | Problematic licenses |
| `target-or-election-flip` | `Apache-2.0 OR GPL-2.0-only` dep under a (GPL-2.0-only, external) target | Production dependencies (app table); the License column shows the full unelected expression, byte-identical to the no-target run |
| `target-proprietary-boundary-external` | LGPL-2.1-only dep under a (proprietary, network=true, external) target | Problematic licenses (warn row) + Production dependencies (app table) |
| `target-unknown-pair-residual` | a matrix-uncovered pair, `unknown_pair` absent then `"fail"` | Problematic licenses: a warn row with `unknown_pair` absent, a fail row with `unknown_pair = "fail"` |
| `target-internal-holds-gpl` | GPL-3.0-only dep under a (MIT, network=false, internal) target | Target compatibility (held-for-internal-use list) + Production dependencies (app table) |
| `target-internal-network-agpl-fails` | AGPL-3.0-only dep under a (MIT, network=true, internal) target | Problematic licenses |
| `target-network-agpl-absorbed` | AGPL-3.0-only dep under an (AGPL-3.0-only, network=true, external) target, container occurrence | Production dependencies (app table) + that container's Application packages table |
| `target-network-false-agpl-internal-held` | AGPL-3.0-only dep under a (MIT, network=false, internal) target | Target compatibility (held-for-internal-use list) |
| `target-internal-nondistribution-conflict-stays` | Apache-2.0 dep under a (GPL-2.0-only, network=false, internal) target | Problematic licenses |
| `target-workspace-divergence` | one purl, two workspace occurrences under diverging per-workspace targets | Problematic licenses (any-fail rule), naming workspace A's profile; inventory row in both workspaces |
| `target-container-app-ecosystem` | npm GPL-3.0-only baked into a prod container, project (GPL-3.0-only, external) target | Production dependencies is n/a (container-only); that container's Application packages table |
| `target-os-agpl-network-true-escalates` | apk AGPL-3.0-only, project target `network = true` | Problematic licenses (unchanged escalation) |
| `target-os-agpl-network-false-routine` | same package (precise and imprecise), project target `network = false`, `os_dependencies = "warn"` | Problematic licenses (os-downgraded warn row, not `default:agpl-container`) + that container's System packages table; not Copyleft |
| `target-os-scope-untouched` | apk GPL-2.0-only under any target profile | Problematic licenses (warn row) + that container's System packages table, both byte-identical to the no-target run |
| `target-supersedes-suppression` | a governed occurrence matching an absorption-justified `[[workspace.copyleft_suppressed]]` | Production dependencies (app table) only; no suppressed-workspaces entry decides it |
| `target-os-agpl-network-false-ignored-notice` | apk AGPL-3.0-only, project target `network = false`, `os_dependencies = "ignore"` | accepted-AGPL notice in Copyleft and special notices; not Problematic |
| `target-held-survives-purl-fail` | one purl, two workspace occurrences: one fails (project MIT/external target), the other holds (a `[[target.workspace]]` MIT/internal override) | Problematic licenses (workspace A's fail) + Target compatibility (held-for-internal-use list, workspace B's hold - never dropped by workspace A's fail) + Production dependencies (app table) |
| `voided-compatible` | a `[[compatible]]` package entry judged under one introducer, in a workspace where a package it accepts also arrives through another | Problematic licenses, one row per package the entry governs there, each naming the chain that voided it; every one keeps its Production dependencies (app table) row |
| `invalid-justification` | npm workspace package whose `[[clarify]]` entry records a choice of licences the in-depth scan never joined | Problematic licenses + Production dependencies (app table); the entry's expression still stands, so the recorded licence is what both rows show |
