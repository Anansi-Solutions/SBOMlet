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
Copyleft and special notices (policy run only), Imprecise licenses, Assessment
conflicts, Containers, Production dependencies, Development-only dependencies.
See [output-format.md](./output-format.md) for what each column means; this
page states only where a package lands.

### Narrative sections (verdict- or finding-driven, deduped)

- **Problematic licenses** — every `fail` verdict, grouped by (purl, rule,
  reason). Takes precedence over the whole Copyleft and special notices
  section below: a purl carrying a fail anywhere never rows in that section's
  flagged table, and never appears in its accepted-notice list either.
- **Copyleft and special notices** — three independent parts:
  - The suppressed-workspaces list, shown whenever policy configures any,
    whether or not it currently suppresses anything.
  - Accepted-AGPL container notices: a scope-`os` package whose AGPL
    obligation (a precise leaf, or the imprecise `AGPL` token) was accepted
    through a `[[compatible]]` rule at some occurrence, excluded when the
    purl also carries a fail elsewhere.
  - Flagged rows: scope is not `os`, the purl isn't already in Problematic,
    and it carries at least one fail or warn verdict whose rule is *exactly*
    `default:copyleft` — an imprecise-copyleft warn never qualifies here, only
    in Imprecise licenses below.

  A system package's non-AGPL copyleft never rows here — it's routine, and
  excluded by scope alone, regardless of its verdict. Acceptance via
  `[[compatible]]` keeps a package out of the flagged rows for every
  ecosystem and scope, because an accepted occurrence never reaches the
  copyleft lane at all
  ([dependency-classification.md](./dependency-classification.md), tier 4
  decides first); the accepted-notice mechanism above exists only for the one
  case that would otherwise fail unconditionally, the container-system AGPL
  escalation.
- **Imprecise licenses** — every package whose finding is imprecise,
  unconditionally, independent of its verdict. This overlaps the sections
  above by design: a bare-`AGPL` system package that fails
  `default:agpl-container` still rows here too.
- **Assessment conflicts** — every package whose finding carries a conflict
  marker, unconditionally. Exempt from the Problematic dedup: a package here
  also rows in Problematic, since a conflict is always a fail.

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
- A purl in Problematic never rows in Copyleft, but keeps its inventory row
  and its Assessment-conflicts row when it carries a conflict marker.
- An AGPL obligation is always visible: a fail routes to Problematic, an
  accepted system AGPL routes to a special notice, and it is never silently
  absent.
- Routine system copyleft (anything but AGPL) appears only under its
  container, never in the Copyleft section.
- The report is byte-deterministic: fixed section order, stable sorts
  throughout.

## Path index (verified end to end)

The same 25 paths as
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
| `system-copyleft-os-warn` | apk GPL-2.0-only, `os_dependencies = "warn"` | that container's System packages table; not Problematic, not Copyleft |
| `system-copyleft-os-fail` | same, `os_dependencies = "fail"` | Problematic licenses |
| `system-copyleft-os-ignore` | same, `os_dependencies = "ignore"` | inventory only (that container's System packages table) |
| `system-agpl-escalates` | apk AGPL-3.0-only, `os_dependencies = "warn"` | Problematic licenses (`default:agpl-container` — the warn knob cannot soften it) |
| `system-agpl-accepted-notice` | same, accepted via `[[compatible]]` | accepted-AGPL notice in Copyleft and special notices; not Problematic |
| `system-agpl-imprecise-escalates` | imprecise bare-`AGPL` system package | Problematic licenses AND Imprecise licenses (overlap by design) |
| `system-agpl-imprecise-accepted` | same, accepted | accepted-AGPL notice in Copyleft and special notices AND Imprecise licenses |
| `mixed-agpl-fail-and-accept` | one AGPL system purl, failing in one container, accepted in another | Problematic licenses only, no notice |
| `app-copyleft-prod-container` | golang/npm copyleft baked into a prod container | Problematic licenses + that container's Application packages table |
| `app-copyleft-dev-container` | app-ecosystem copyleft in a `[[docker.development]]` container | Copyleft and special notices (dev-downgraded warn); subsection under Development-only dependencies |
| `app-copyleft-workspace-dev` | workspace dev-dependency copyleft | Copyleft and special notices (warn); Development-only dependencies (app table) |
| `problematic-dedup-keeps-inventory` | workspace prod copyleft, fails | Problematic licenses only (never Copyleft); still in Production dependencies (app table) |
| `imprecise-copyleft-family-only-imprecise` | bare `GPL` app package | Imprecise licenses only, never a Copyleft flagged row |
| `imprecise-permissive-family` | bare `BSD` app package | Imprecise licenses only |
| `unknown-license-counted` | [unknown] handling = "warn", no license | counted under Unknown license; inventory row (app table) |
| `licenseref-only-unknown` | a package whose only license content is a LicenseRef | counted under Unknown license; inventory row only |
| `suppressed-workspace-copyleft` | family-justified `[[workspace.copyleft_suppressed]]` | suppressed-workspaces list in Copyleft and special notices; no flagged row |
| `denied-license-terminal` | a `[[deny]]` match with a `[[compatible]]` rule that would otherwise accept it | Problematic licenses (deny is terminal) |
| `system-package-in-dev-container-counts-dev` | apk permissive package whose only container is dev-marked | counted Development-only (via the container's classification); System packages table under the Development-only subsection |
