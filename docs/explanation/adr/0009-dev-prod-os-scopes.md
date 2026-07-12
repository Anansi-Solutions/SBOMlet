# ADR-0009: dev/prod and OS dependency scopes; a production occurrence always gates

- **Status:** Accepted
- **Date:** 2026-06-15

## Context and problem

A distribution obligation attaches to what you ship. A copyleft library
compiled into the client bundle carries one; the same library used only to run
the test suite does not. The base OS of a container is a third case: glibc,
bash, coreutils and the rest of a Debian or Alpine image are copyleft, but they
are the OS the container sits on, not code the project redistributes, and the
distro handles its own compliance.

The first gate drew none of these lines: a default-FAIL fired on any copyleft
(or, under a strict unknown policy, any unrecognised licence) regardless of
where the package was used, failing on build-time-only copyleft and on every
standard base image.

The direction of the mistake is what matters: relaxing the gate for a dev or OS
package is fine; relaxing it for something that ships is not.

## Decision drivers

- **The one unsafe direction:** a production occurrence of a copyleft or unknown
  licence must never be downgraded.
- **Per-place truth:** a package can be dev in one workspace and prod in another,
  so the gate must read scope per occurrence (ADR-0005), not per package.
- **Tunable:** a library vendor and an internal service ship differently, so the
  relaxation is a policy knob, not a fixed rule.
- **Deny stays absolute:** the source-available deny-list (ADR-0013) is terminal;
  no scope relaxation licenses a denied package back in.

## Considered options

1. **Gate every copyleft/unknown everywhere** — the original behaviour. Safe, but
   false-positives on dev tooling and every base image.
2. **Strip dev and OS packages from the inventory** — loses the inventory; a
   reviewer can no longer see what the base image contains.
3. **One package-level dev/prod flag, gate on it** — wrong the moment a package is
   dev in one workspace and prod in another.
4. **Per-occurrence dev scope and package-level OS scope, each a policy knob,
   applied only at the would-be-FAIL terminal, with production always winning.**

## Decision

We chose option 4. Two downgraders sit where the engine is about to emit a
default FAIL, each softening — never inventing — a verdict, and only for a
package the policy marks as not shipping.

The dev downgrader keys on the occurrence's dev/prod flag; a production
occurrence is returned unchanged, the load-bearing safety property. The OS
downgrader is the same shape one level up, keying on the package's `os` scope.
Both read a policy knob (`dev_dependencies` / `os_dependencies`, each
defaulting to `warn`).

Gating everything is safe but unusable. Stripping dev/OS packages throws away
the inventory. A package-level dev flag cannot answer dev-here/prod-there, and
its wrong guess is toward the unsafe direction. Per-occurrence downgrade with
production unchanged makes the unsafe direction structurally impossible: the
downgraders have no branch that touches a production occurrence.

The OS lane runs first, then the dev lane on its result; the deny terminal sits
above both, so a denied licence still fails regardless of scope.

## Consequences

- **Good:** the gate stops firing on build-time-only copyleft and on standard base
  images, while still failing on anything that ships a copyleft or unknown licence.
  A downgraded verdict keeps its originating rule id and appends an auditable note,
  so it is not confused with a genuine one.
- **Bad / cost:** "production" is now a fold across occurrences — a package is
  production if it ships anywhere. The report grew a Production / Development-only
  split and a Docker base-image OS section to keep the classification visible.
- **Neutral:** both knobs default to `warn`, so a fresh adoption sees its dev and OS
  copyleft listed for review rather than blocking CI on day one. The OS scope is fed
  by the committed Docker SBOM (ADR-0012); without that input the OS lane never
  fires.

## See also

- Related: [ADR-0005](0005-per-occurrence-model.md) (the per-occurrence model this
  gates on), [ADR-0013](0013-source-available-deny.md) (the deny terminal above both
  downgraders), [ADR-0012](0012-docker-os-via-syft.md) (the committed SBOM feeding
  OS scope)
- Code: `src/policy/evaluate.ts` (`applyDevScope`, `applyOsScope`,
  `applyScopeDowngrades`)
