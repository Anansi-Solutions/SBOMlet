# ADR-0012: Python via cdxgen, with prod/dev recovered from poetry.lock

- **Status:** Accepted
- **Date:** 2026-06-15

## Context and problem

Python is one of the ecosystems the tool has to inventory, and the reference project's
Python code lives behind a `poetry.lock`. A lockfile records the dependency
tree but carries no licence text, so something has to turn it into a component
list with licences attached. The tool's standing rule is to orchestrate a
maintained SBOM generator rather than parse manifests itself, so the first
question was which generator to drive for Python.

That choice settled, a second problem surfaced during the dogfood run.
Every collector feeds a per-occurrence model that records whether each
dependency is production or development-only, because the gate treats a
production occurrence as binding and a dev-only one as advisory. For Python,
every dependency was landing in production. `jinja2-ansible-filters`, a
build-time dev-group transitive licensed `GPL-3.0-or-later`, was being flagged
as a production copyleft violation and had to be silenced with an explicit
exception — a sign the dev/prod signal was simply missing for poetry.

## Decision drivers

- **Declared-licence quality without installing anything.** The tool must never
  run a package manager inside the scanned project, so the generator has to
  produce licences from lockfile and registry data alone.
- **Correct dev/prod scope.** A dev-only copyleft dependency should be surfaced
  for review, not fail the gate as if it shipped. Getting this wrong forces
  per-package exceptions that hide the real obligation.
- **One dev/prod mechanism across ecosystems.** The merge already had a way to
  mark dev dependencies; adding a second, poetry-specific path would be a
  maintenance cost for no gain.
- **Conservative on uncertainty.** When scope is unclear, a dependency must
  default to production. Silently dropping a shipped dependency to dev-only is
  the failure the tool exists to prevent.

## Considered options

For the inventory generator:

1. **cdxgen against the lockfile** — reads `poetry.lock`, fetches declared
   licences from PyPI, installs nothing.
2. **syft against the lockfile** — the container-scanning standard, but its
   static lockfile parsing yields weak Python licence data.
3. **cyclonedx-py against an installed venv** — the most complete Python licence
   data, but only if the environment is already installed.

For dev/prod scope, once cdxgen was chosen:

4. **Trust cdxgen's group markers** — read the `cdx:pyproject:group` property
   the merge already understands.
5. **Synthesize the missing marker** — post-process cdxgen output to attach a
   group property per component.
6. **Recover scope from `poetry.lock` directly** — read each package's `groups`
   array from the lockfile and feed the result through the same prod-set
   mechanism the yarn path already uses.

## Decision

We drive **cdxgen** for the Python inventory and **recover prod/dev from
`poetry.lock`**.

cdxgen is the generator the wider ecosystem converges on for Python: it reads
the lockfile, enriches licences from PyPI, and installs nothing, which is
exactly the no-side-effects posture the tool requires. syft's lockfile parsing
gives poorer Python licence data, and cyclonedx-py needs an installed
environment the tool is not allowed to create.

The scope problem comes from how cdxgen has to be run. Under `--no-install-deps`
— the flag that keeps the scan side-effect-free — cdxgen emits no
`cdx:pyproject:group` property on poetry components, so the merge's
property-based dev marker never fires and every poetry dependency reads as
production. The group information that cdxgen drops is sitting in the lockfile:
`poetry.lock` records a `groups` array on each package. So rather than trust an
absent marker or fabricate one, we read the authoritative source. A small pure
function parses the lockfile and returns the purl set of every package whose
`groups` include `main` — the production set. The merge already derives
"dev = not in the production set" for the yarn dual-run path, so threading this
set in reuses that machinery wholesale.

Comparing on the driver that decided each:

- **Trusting cdxgen's markers** fails on correctness: under the side-effect-free
  flag there are no markers to trust. Rejected.
- **Synthesizing the marker** would work but adds a poetry-specific post-process
  and a second dev/prod path. Reading the lockfile and reusing the existing
  prod-set path is simpler and keeps one mechanism. Rejected on the
  one-mechanism driver.
- **Reading `poetry.lock` directly** gives the authoritative scope, reuses the
  yarn path, and inherits its prod-wins rule for free: a package in both `main`
  and a dev group lands in the production set and stays production.

Two details fall out of matching cdxgen's purls. Names are compared after PEP
503 normalization — lowercase, with each run of `-_.` collapsed to a single
hyphen — because that is the transform cdxgen applies before emitting a
`pkg:pypi/<name>` purl; against the dogfood all 114 lockfile names map one-to-one
onto cdxgen's purls. And an absent or malformed `groups` value defaults to
`["main"]`, i.e. production, honouring the conservative-on-uncertainty driver:
a shipped dependency is never silently downgraded to dev.

## Consequences

- **Good:** poetry dev-group dependencies now classify dev-only, so a build-time
  dev copyleft is surfaced for review instead of failing the gate. The
  `jinja2-ansible-filters` exception was deleted; the dev-scope rule owns it now.
  In the dogfood, twelve poetry dev-group packages moved from production to
  development-only. The recovery is one pure function over untrusted text — it
  returns an empty set on garbage rather than throwing — and adds no dependency,
  since the TOML parser was already present for policy parsing.
- **Bad / cost:** the dev/prod signal for Python now depends on the shape of
  `poetry.lock` rather than on the generator's output, so a future lockfile
  format change would need a matching update here. This is a deliberate trade:
  the lockfile is the authoritative source and the generator's marker is the one
  that proved unreliable.
- **Neutral:** the recovery is poetry-specific. uv was left on the plain cdxgen
  path because the reference project uses poetry; a migration to uv would need the same
  treatment for its lockfile. cdxgen still reports the tool identity for poetry
  targets — the lockfile read changes scope, not provenance.

## See also

- Plan summaries: `.planning/phases/06-terraform-dogfood/06-05-poetry-dev-SUMMARY.md`,
  `.planning/phases/06-terraform-dogfood/06-06-review-fixes-SUMMARY.md`
- Research: `.planning/research/STACK.md` (per-ecosystem generator matrix)
- Code: `collectors/poetryLock.ts` (`poetryProdPurlSet`), `collectors/cdxgen.ts`
  (`--no-install-deps`), `merge/merge.ts` (`packageEntryOf`)
