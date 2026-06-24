# ADR-0010: dev/prod and OS dependency scopes; a production occurrence always gates

- **Status:** Accepted
- **Date:** 2026-06-15

## Context and problem

A distribution obligation attaches to what you ship. A copyleft library compiled
into the client bundle carries one; the same library used only to run the test
suite does not, because it never reaches a user. The base operating system a
container runs on is its own case again — glibc, bash, coreutils and the rest of
a Debian or Alpine image are copyleft, but they are the OS the container sits on,
not code the project wrote or redistributes as a library, and the distro handles
its own compliance.

The first version of the gate did not draw these lines. A would-be default-FAIL
fired on any copyleft (or, under a strict unknown policy, any unrecognised
licence) regardless of where the package was used. On a large monorepo
that meant the gate failed on build-time-only copyleft and on every standard
base image — false positives that would train an operator to ignore the gate.

So the gate had to learn the difference between a package that ships and one that
does not. The hard part is the direction of the mistake. Relaxing the gate for a
dev or OS package is fine; relaxing it for something that actually ships is the
exact failure the tool exists to prevent — a shipped copyleft waved through as if
it were a test fixture.

## Decision drivers

- **The one mistake we cannot make:** a production occurrence of a copyleft or
  unknown licence must never be downgraded. Whatever scope logic we add has to be
  safe in that single direction above all else.
- **Per-place truth:** a package can be a dev dependency in one workspace and a
  production dependency in another. The model already records dev/prod per
  occurrence (ADR-0005), so the gate must read scope per place, not per package.
- **Tunable, not hard-coded:** different projects ship differently. A library
  vendor and an internal service want different defaults, so the relaxation has
  to be a policy knob, not a fixed rule.
- **Don't reach the deny terminal:** the source-available deny-list (ADR-0015) is
  absolute. No scope relaxation may license a denied package back in.

## Considered options

1. **Gate every copyleft/unknown everywhere** — the original behaviour. Safe, but
   false-positives on dev tooling and every base image, which erodes trust in the
   gate.
2. **Strip dev and OS packages from the inventory** — don't report what doesn't
   ship. Loses the inventory; a reviewer can no longer see what the base image
   contains.
3. **One package-level dev/prod flag, gate on it** — wrong the moment a package is
   dev in one workspace and prod in another (the case ADR-0005 was migrated to fix).
4. **Per-occurrence dev scope and package-level OS scope, each a policy knob,
   applied only at the would-be-FAIL terminal, with production always winning** —
   downgrade a failure for a dev-only or OS occurrence by policy, but return any
   production failure unchanged.

## Decision

We chose option 4. Two downgraders sit at the point where the engine is about to
emit a default FAIL — a `default:copyleft`, or a `default:unknown` under a
strict unknown policy. Neither invents a verdict; each can only soften a failure
the engine already reached, and only for a package the policy marks as not
shipping.

The dev downgrader keys on the occurrence's dev/prod flag. A production
occurrence is returned unchanged — this is the load-bearing safety property, and
it is asserted both at the engine and end to end through the exit code. A dev
occurrence consults the `dev_dependencies` knob: `warn` (the default) turns the
failure into a non-gating warning, `ignore` into a clean pass, `fail` leaves the
old gate-everything behaviour for strict projects. The OS downgrader is the same
shape one level up: it keys on the package's `os` scope and reads
`os_dependencies`, which also defaults to `warn`. Both knobs mirror the existing
`unknown.handling` idiom, so the policy file reads consistently.

Comparing on the driver that decided it — the production-wins property:

- **Gating everything** is safe but unusable; it fails on every base image and
  every build tool. Rejected on the false-positive cost.
- **Stripping dev/OS packages** would also be safe, but it throws away the
  inventory the tool exists to produce. Rejected.
- **A package-level dev flag** cannot answer dev-here/prod-there, so it would have
  to pick one answer and be wrong half the time — and being wrong toward "dev"
  is the unsafe direction. Rejected on correctness.
- **Per-occurrence downgrade with production unchanged** keeps the inventory,
  reads scope per place, stays tunable, and makes the unsafe direction
  structurally impossible: the downgraders have no branch that touches a
  production occurrence. One copyleft package used dev in workspace A and prod in
  workspace B produces two verdicts — A warns, B fails — and the gate fails.

The two downgraders compose deterministically. The OS lane runs first, then the
dev lane runs on its result, so an OS-scope copyleft stays a warning even under
`dev_dependencies=fail` — once OS has softened the failure, the dev lane's `fail`
branch returns that warning unchanged. The two never genuinely interact: an OS
package is not an app dev occurrence, and an app package never enters the OS lane.
Above both sits the deny terminal, which returns before either downgrader runs, so
a denied licence in a dev or OS package still fails unconditionally.

## Consequences

- **Good:** the gate stops false-positiving on build-time-only copyleft and on
  standard base images while still failing on anything that actually ships a
  copyleft or unknown licence. The relaxation is two policy knobs a project tunes
  to how it distributes. A downgraded verdict keeps its originating rule id and
  appends an auditable note, so a dev- or OS-downgraded warning is never confused
  with a genuine one.
- **Bad / cost:** "production" is now a fold across occurrences rather than a
  single flag — a package is production if it ships anywhere — which every
  consumer of the model has to respect. The report grew a Production /
  Development-only split and a separate Docker base-image OS section to make the
  classification visible, which is more document shape to keep deterministic.
- **Neutral:** both knobs default to `warn` (non-gating but surfaced), so a fresh
  adoption sees its dev and OS copyleft listed for review rather than blocking CI
  on day one; a project that wants the strict gate sets either knob to `fail`. The
  OS scope is fed by the committed Docker SBOM (ADR-0014); without that input the
  OS lane simply never fires.

## See also

- Plan summaries:
  `.planning/phases/05-enrichment-committed-cache/05-08-SUMMARY.md` (POL-08, dev scope),
  `.planning/phases/07-docker-os-packages/07-02-SUMMARY.md` (COLL-04, OS scope)
- Code: `src/policy/evaluate.ts` (`applyDevScope`, `applyOsScope`, `applyScopeDowngrades`)
- Related: [ADR-0005](0005-per-occurrence-model.md) (the per-occurrence model this gates on),
  [ADR-0015](0015-source-available-deny-list.md) (the deny terminal above both downgraders),
  [ADR-0014](0014-docker-syft-consumer.md) (the committed SBOM that feeds the OS scope)
