# ADR-0024: Container-aware licenses report

- **Status:** Accepted
- **Date:** 2026-08-06

## Context and problem

A report review against a real multi-container repository surfaced two
problems in `THIRD_PARTY_LICENSES.md`. The Copyleft section was dominated by
base-image system packages — dozens of Debian/Alpine `deb` packages, each
carrying routine GPL/LGPL because that is simply what a base image is,
drowning the obligations worth a reviewer's attention. And a package already
listed as a policy failure in Problematic licenses could duplicate into
Copyleft, reading the same obligation twice. Underneath both: every
container's packages lived in one flat, standalone Docker section,
disconnected from the rest of the inventory, with no way to mark a CI-only
image as never shipping.

## Decision drivers

- Routine base-image copyleft should not dominate a section meant for
  obligations worth reviewing.
- Network-copyleft (AGPL) reaches server-side use even inside a container, so
  it must never be softened as routine base-image noise.
- A package's obligation should surface in exactly one narrative place, never
  both, while the full inventory stays complete everywhere else.
- Container packages belong with the rest of the inventory, grouped by
  container, and marking a container never-shipping should reuse the
  existing glob dialect rather than invent a second one.

## Considered options

1. Filter routine container copyleft out of the Copyleft table only, leaving
   the standalone Docker section and the Problematic/Copyleft duplication
   untouched.
2. **Restructure the report end to end — chosen.**
3. A separate "trust tier" concept for containers, orthogonal to the existing
   `[docker]` policy table and its glob matcher.

## Decision

Problematic licenses takes precedence over Copyleft: a package listed there
is never repeated in Copyleft, though it keeps its row in its
Production/Development-only inventory table and in Assessment conflicts — the
dedup is narrative-only. Container system-package copyleft is routine and
never appears in Copyleft regardless of verdict status; it lists only under
its container's own subsection. The exception is AGPL: an AGPL container
package always escalates to Problematic (`default:agpl-container`), because
its network-copyleft clause reaches server-side use the way ordinary
container GPL/LGPL does not. The standalone Docker section is removed —
container packages fold into Production or Development-only, grouped under a
`### Container: docker:<source>` subsection, with a thin `## Containers`
index naming each container's classification. Containers default to
production; a policy `[[docker.development]]` entry marks one
development-only via a `source` glob matched with the same dialect as
`[docker].ignore`.

## Consequences

- **Good:** the Copyleft section surfaces real obligations instead of
  base-image noise; AGPL can never be silently downgraded; every dependency,
  app or container, has exactly one inventory location; a CI-only image no
  longer inflates the production surface.
- **Bad / cost:** every consumer regenerates once — the removed Docker
  section, the renamed `Container packages` count, and the new Containers
  index all change committed bytes.
- **Neutral:** the marking is render-only. `[os_dependencies]`, deny, and the
  AGPL escalation decide verdicts exactly the same regardless of which half a
  container renders under; `docker:<source>` occurrence identities and
  existing `where`-scoped rules are unaffected.

## See also

- [ADR-0009](0009-dev-prod-os-scopes.md) — the dev/prod and OS scope split
  this extends to containers
- [ADR-0021](0021-per-image-occurrence-identity.md) — the `docker:<source>`
  identity this groups packages by
- Code: `src/render/markdown.ts`, `src/policy/evaluate.ts`,
  `src/policy/schema.ts`, `src/pipeline/pipeline.ts`
