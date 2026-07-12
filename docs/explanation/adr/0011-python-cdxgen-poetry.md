# ADR-0011: Python via cdxgen, with prod/dev recovered from poetry.lock

- **Status:** Accepted
- **Date:** 2026-06-15

## Context and problem

Python is one of the ecosystems the tool inventories, and the reference
project's Python code sits behind a `poetry.lock`. A lockfile records the tree
but carries no licence text, so something has to turn it into a component list
with licences.

A second problem surfaced during the dogfood run. Every collector feeds a
per-occurrence model that marks each dependency production or dev-only,
because the gate treats a production occurrence as binding and a dev-only one
as advisory. For Python, every dependency landed in production.
`jinja2-ansible-filters`, a build-time dev-group transitive licensed
`GPL-3.0-or-later`, was flagged as a production copyleft violation and needed
an explicit exception — the dev/prod signal was missing for poetry.

## Decision drivers

- **Declared-licence quality without installing anything.** The generator
  produces licences from lockfile and registry data alone.
- **Correct dev/prod scope.** A dev-only copyleft dependency should be
  surfaced for review, not fail the gate as if it shipped.
- **One dev/prod mechanism across ecosystems.** The merge already marks dev
  dependencies; a second poetry-specific path is maintenance for no gain.
- **Conservative on uncertainty.** An unclear scope defaults to production.

## Considered options

1. **cdxgen against the lockfile** — reads `poetry.lock`, fetches licences
   from PyPI, installs nothing.
2. **syft against the lockfile** — weak Python licence data from static
   parsing.
3. **cyclonedx-py against an installed venv** — the most complete data, but
   only with the environment installed.
4. **Trust cdxgen's group markers**, once cdxgen is chosen.
5. **Synthesize the missing marker** by post-processing cdxgen output.
6. **Recover scope from `poetry.lock` directly**, feeding the result through
   the prod-set mechanism the yarn path already uses.

## Decision

We drive **cdxgen** for the Python inventory and **recover prod/dev from
`poetry.lock`**.

cdxgen reads the lockfile, enriches licences from PyPI, and installs nothing —
syft's lockfile parsing gives poorer Python data, and cyclonedx-py needs an
installed environment the tool may not create.

Under `--no-install-deps` — the flag that keeps the scan side-effect-free —
cdxgen emits no `cdx:pyproject:group` property, so the merge's dev marker never
fires and every poetry dependency reads as production. That group information
is in the lockfile: `poetry.lock` records a `groups` array per package. A small
pure function returns the purl set of every package whose `groups` include
`main`, feeding the same production-set mechanism the yarn dual-run path
already uses.

Trusting cdxgen's markers fails outright: there are none under the flag.
Synthesizing one adds a poetry-specific post-process and a second dev/prod
path. Reading the lockfile gives the authoritative scope and inherits the yarn
path's prod-wins rule: a package in both `main` and a dev group stays
production.

Names are matched after PEP 503 normalization (lowercase, `-_.` collapsed to a
hyphen), the transform cdxgen applies before emitting a `pkg:pypi/<name>` purl;
against the dogfood all 114 lockfile names map one-to-one. An absent or
malformed `groups` value defaults to `["main"]`, honouring the
conservative-on-uncertainty driver.

## Consequences

- **Good:** poetry dev-group dependencies now classify dev-only; the
  `jinja2-ansible-filters` exception was deleted, the dev-scope rule owns it.
  Twelve poetry dev-group packages moved from production to development-only
  in the dogfood. The recovery is one pure function over untrusted text — it
  returns an empty set on garbage — and adds no dependency.
- **Bad / cost:** the Python dev/prod signal now depends on the shape of
  `poetry.lock` rather than the generator's output, so a lockfile format
  change needs a matching update.
- **Neutral:** the recovery is poetry-specific; uv stays on the plain cdxgen
  path. cdxgen still reports tool identity for poetry targets — the lockfile
  read changes scope, not provenance.

## See also

- Related: [ADR-0009](0009-dev-prod-os-scopes.md) (the dev/prod scope model
  this feeds)
- Code: `collectors/poetryLock.ts` (`poetryProdPurlSet`), `collectors/cdxgen.ts`
  (`--no-install-deps`), `merge/merge.ts` (`packageEntryOf`)
