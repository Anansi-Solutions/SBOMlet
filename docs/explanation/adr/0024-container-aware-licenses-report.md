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
container's packages lived in one flat, standalone Docker section, with no
way to mark a CI-only image as never shipping.

## Decision drivers

- Routine base-image copyleft should not dominate a section meant for
  obligations worth reviewing — but only for packages a base image owns,
  never for something an application layer installed into the image.
- Network-copyleft (AGPL) reaches server-side use even inside a container, so
  it must never be softened as routine base-image noise.
- A package's obligation should surface in exactly one narrative place, never
  both, while the full inventory stays complete everywhere else.
- Marking a container never-shipping should reuse the existing glob dialect
  rather than invent a second one.

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
Production/Development-only inventory table and in Assessment conflicts. The
standalone Docker section is removed — container packages fold into
Production or Development-only, grouped under a `### Container: docker:<source>`
subsection, with a thin `## Containers` index naming each container's
classification. Containers default to production; a policy
`[[docker.development]]` entry marks one development-only via a `source`
glob matched with the same dialect as `[docker].ignore`.

The routine-copyleft carve-out keys on the OS-package ecosystem, not on
container scope — an image scan reports every package under one occurrence
identity, base-image plumbing and an application layer's own installs alike,
so scope cannot tell them apart. A named allowlist of Linux distro
package-manager types (`deb`, `apk`, `rpm`, `alpm`) is the discriminator: on
it, a package stays routine (de-noised out of Copyleft, downgraded under
`[os_dependencies]`), except AGPL, which still escalates to Problematic
(`default:agpl-container`). Off the allowlist — npm, pypi, go, cargo, and the
rest — a package is an application dependency wherever it lives: it fails on
real copyleft in a production image, dev-downgrades to warn once its
container is `[[docker.development]]`-marked, and its AGPL takes the normal
copyleft path instead of the container escalation. Each `### Container:`
subsection splits into a System packages table (the allowlist) and an
Application packages table (everything else); an empty half is omitted. A
package that is both an application dependency and part of a container's
inventory shows in both places — the subsection groups by occurrence
identity, not by scope.

## Consequences

- **Good:** the Copyleft section surfaces real obligations instead of
  base-image noise; AGPL can never be silently downgraded; every dependency
  has exactly one inventory location; an application dependency baked into
  an image is held to the same standard as one declared in a lockfile.
- **Bad / cost:** every consumer regenerates once — the removed Docker
  section, the renamed `Container packages` count, the Containers index, and
  the per-container System/Application split all change committed bytes.
- **Neutral, for a system package only:** the container marking is
  render-only — `[os_dependencies]` and the AGPL escalation decide its
  verdict the same regardless of which half it renders under. For an
  application-ecosystem package it is not: `[[docker.development]]` moves
  its verdict too, like an app-level `devDependency`. Occurrence identities
  and `where`-scoped rules are unaffected either way.

## See also

- [ADR-0009](0009-dev-prod-os-scopes.md) — the dev/prod and OS scope split
  this extends to containers
- [ADR-0021](0021-per-image-occurrence-identity.md) — the `docker:<source>`
  identity this groups packages by
- Code: `src/render/markdown.ts`, `src/policy/engine/evaluate.ts`,
  `src/policy/schema/`, `src/pipeline/pipeline.ts`,
  `src/pipeline/containerScope.ts`, `src/policy/engine/osEcosystems.ts`
