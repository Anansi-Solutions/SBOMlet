# ADR-0026: Chain-scoped acceptances and re-checkable overrides

- **Status:** Accepted
- **Date:** 2026-08-20

## Context

A policy override is written once and read years later. The old shapes
recorded a judgment the gate could not re-check: an acceptance covered a
package wherever its scope reached, whatever pulled it in, and a clarification
carried one free-text reason plus one string standing in for both detection
sources. The tool could confirm only that a string had not moved — never that
the judgment still held.

## Decision

Rewrite both entry shapes so every claim is checkable against the current
scan.

A package-form `[[compatible]]` acceptance, old then new:

```toml
[[compatible]]
match = "package"
name = "@img/sharp-win32-x64"
version = "0.34.5"          # optional
reason = "LGPL obligations reviewed and accepted."
```

```toml
[[compatible]]
match = "package"
name = "@img/sharp-win32-x64"
version = "0.34.5"          # required
as-dependency-of = ["image-pipeline"]
where = ["apps/media"]
rationale = "license-reviewed"
comment = "LGPL obligations accepted for these prebuilt binaries."
```

A `[[clarify]]` override, old then new:

```toml
[[clarify]]
package = { name = "jsonify", version = "0.0.1" }
expects = "BSD"             # optional, single precondition
expression = "BSD-3-Clause"
reason = "Confirmed BSD-3-Clause in the upstream LICENSE file."
```

```toml
[[clarify]]
name = "jsonify"
version = "0.0.1"           # required
detected = { registry = "BSD", intensive = "BSD-3-Clause" }
justification = "scan-more-precise"
expression = "BSD-3-Clause"
comment = "Confirmed BSD-3-Clause in the upstream LICENSE file."
```

The rationale for each material change:

- **`as-dependency-of` (required on a package entry).** Names whose use of the
  package was judged. On a target with a dependency graph the claim is checked
  against it — a package arriving past every named parent voids the entry
  rather than riding a judgment that never covered that path. A graph-less
  target (a container OS layer) accepts only the reserved `self`, and the
  report calls that acceptance unscoped rather than implying a check that
  never ran.
- **`where` and `version` required.** An unscoped, unpinned acceptance
  silently followed a package into a relicensed release or an unrelated
  occurrence. Both are now stated, so the blast radius is auditable; only a
  container os-scope `where` may omit `version`, since base-image versions are
  not author-controlled.
- **Closed `rationale` / `justification`, replacing free-text `reason`.** A
  value from a fixed set has a meaning the tool knows, so it can fail an entry
  the evidence disproves and tell that apart from one whose subject merely
  went away. Prose moves to `comment`; inferring the reason from the licences
  was rejected, as it would put the tool's guess in the audit trail in place
  of the author's.
- **Per-source `detected`, replacing one `expects` string.** One record per
  detection source (`registry`, `intensive`), each holding what that source
  reported or `false` for nothing. Two sources disagreeing is the case most
  worth recording and one string could not hold it; a `false` that later
  starts speaking reopens the judgment.
- **The `packages` list.** One entry may bundle disparate packages that share
  a `where`, `as-dependency-of`, `rationale`, and `comment`, each pinning its
  own version — the "reviewed together" case without repeating four fields.
- **A separate clarifications file.** Clarify entries may live in a file named
  by an explicit top-level key, never found by convention. That file is
  machine-owned: an offline maintainer subcommand rewrites it whole, so the
  version churn these entries accumulate is tooling's work, not hand-editing.

There is no compatibility shim. A removed key is rejected by name with its
replacement, so the tool's own error is the migration guide.

## Consequences

- Every existing policy is rewritten once, by hand.
- Validity now depends on the scan: adding a first graph-less target can
  reject a policy nobody edited, and a voided entry fails packages that were
  never the problem. The bluntness is deliberate — an entry wrong about one
  package was wrong as written, and splitting it into narrower entries states
  the same fact truthfully.
- An acceptance records which use was judged, a stated reason can be disproved
  rather than merely believed, and version churn has somewhere to go.

## See also

- Related: [ADR-0007](0007-honest-residual.md) (the residual an unrecorded
  introduction follows), [ADR-0014](0014-dependency-provenance.md) (the
  provenance the chains are walked over),
  [ADR-0025](0025-target-license-compatibility-lane.md) (the lane these
  entries decide ahead of)
- Code: `src/policy/schema/`, `src/policy/engine/chain.ts`,
  `src/policy/engine/crossValidate.ts`, `src/policy/engine/justificationValidity.ts`,
  `src/policy/parse/clarificationsFile.ts`, `src/policy/refresh/refreshClarifications.ts`
