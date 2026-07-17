# Wire the gate into CI

This guide is for an operator who has a committed inventory and wants CI to
fail the build when it drifts or when a dependency breaks the policy. It assumes
you've been through [getting-started](../getting-started.md) and already have a
`THIRD_PARTY_LICENSES.md`, a `THIRD_PARTY_NOTICES.md`, and an
`.sbomlet.cache/licenses.cache.json` committed at your repository root.

The CI integration is one step. The rest of this page covers what makes that
step reliable: the exit codes it returns, the workflow of committing what
`generate` writes, the line-ending pins that keep the comparison stable across
operating systems, and why the gate never needs the network. Two later sections
cover commands that run outside the gate: the cache-integrity audit you run
before a release, and the Docker scan.

## Add the check step

[`check`](../glossary.md#the-gate-check) is a single Task invocation that uses no
CI-vendor features. Wherever your pipeline runs its checks, add one step:

```sh
task sbomlet:check POLICY=.sbomlet.policy.toml
```

That is the entire integration. It works the same on GitHub Actions, GitLab CI,
a Jenkins stage, a pre-merge hook, or a developer's terminal, because all the
behavior lives in the tool and the Taskfile rather than in the runner.

Some concrete shapes, so you can paste the right one:

```yaml
# GitHub Actions — a step inside a job that has mise and Task available
- run: task sbomlet:check POLICY=.sbomlet.policy.toml
```

```yaml
# GitLab CI — a job
licenses:
  script:
    - task sbomlet:check POLICY=.sbomlet.policy.toml
```

The runner needs [mise](https://mise.jdx.dev) and [Task](https://taskfile.dev)
on `PATH`, the same as a local run. mise resolves the pinned runtime the tool ships
with, so you don't install it in CI either. Beyond that there is nothing to
configure, and no API key, service container, or network allowance.

If your repository keeps its outputs somewhere other than the root, or uses a
CycloneDX export, pass the same flags you pass to `generate` so the gate
compares the same files. The variables are caller-overridable:

```sh
task sbomlet:check POLICY=.sbomlet.policy.toml CYCLONEDX=sbom.cdx.json
```

## Or: the GitHub Action

On GitHub Actions specifically, the composite action collapses the whole setup —
toolchain, install, run — into one step, so you don't put mise or Task on the
runner yourself:

```yaml
- uses: actions/checkout@v6
- uses: Anansi-Solutions/SBOMlet@main # pin a tag or SHA in production
  with:
    policy: .sbomlet.policy.toml
```

It runs `check` by default (the exit codes below apply); pass `mode: generate` to
write the inventory instead. It is exactly the mise + Task pipeline above, wrapped
— use it on GitHub Actions and the Taskfile step everywhere else.

For a pull-request pattern built on the action — run the gate, and when it fails
because the inventory is out of date, regenerate and open a refresh PR against the
contributor's branch — see the shipped
[`examples/licenses-refresh.yml`](../../examples/licenses-refresh.yml).

## What the exit code means

The step passes or fails on the process exit code, and the code tells you which
class of problem to look at. A policy violation and an out-of-date document are
different problems with different fixes, and the code distinguishes them.

| Exit code | Meaning | What to do |
| --------- | ------- | ---------- |
| `0` | Clean — the committed outputs match the regenerated inventory, and no dependency tripped a `fail` [verdict](../glossary.md#verdict) | Nothing; the gate passes |
| `1` | A dependency tripped a `fail` verdict | Fix the dependency, or add a documented override to `.sbomlet.policy.toml` |
| `2` | A committed output is [stale](../glossary.md#staleness) or missing | Re-run `generate`, review the diff, commit |
| `3` (and above) | Tool or config error — a bad flag, an invalid policy file, a pipeline failure | Fix the invocation or the policy |

Two details affect how you read the result. When a `fail` verdict and staleness
are both true, the gate returns `1`, so a policy violation can never hide behind
a document that also happens to be out of date. And `warn` verdicts, along with
unused-policy-entry warnings, print to stderr but never change the exit code;
only a `fail` verdict reaches exit `1`.

Exit codes `0`, `1`, and `2` come only from the gate's structured result. Any
exception, such as a malformed policy or an unknown flag, propagates to a single
handler that exits `3`, so a tool error can never be mistaken for a clean run or
a verdict.

## Commit the outputs, then gate them

The gate compares the committed files against what the tool would generate from
the current dependency tree. For that comparison to mean anything, the generated
files have to be in the repository. The routine is the same one you set up during
your first run.

When a dependency changes, regenerate and commit:

```sh
task sbomlet:generate POLICY=.sbomlet.policy.toml
git add THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md .sbomlet.cache/licenses.cache.json
git commit -m "chore: refresh third-party license inventory"
```

`generate` writes the inventory, its companion, and the enrichment cache on
every run. Commit all three:

- `THIRD_PARTY_LICENSES.md` — the inventory. Written on every run.
- `THIRD_PARTY_NOTICES.md` — the attribution companion. Written on every run.
- `.sbomlet.cache/licenses.cache.json` — the licenses fetched from registries during
  [enrichment](../glossary.md#enrichment-and-the-enrichment-cache), committed so
  the gate can run offline. Written on every run, even one with nothing to
  enrich; its bytes change only when `generate` fetches a new license, so a warm
  run rewrites identical bytes.
- A [CycloneDX](../glossary.md#cyclonedx) export — only when you pass
  `--cyclonedx` (the `CYCLONEDX` Task variable).

A run with `--dump-model` also writes a sorted-key JSON dump of the model. That
is a debugging aid for golden-file tests, not something you commit.

So an adopter running a plain `task sbomlet:generate` always gets three files:
the inventory, the companion, and the cache.

A plain `generate` never writes `.sbomlet.cache/docker.sbom.json` — it only
reads the committed copy. The file comes from the docker lane of the same task:
`task sbomlet:generate DOCKER=1` first rebuilds and rescans the repository's images to
refresh it, then regenerates the full inventory (described at the end of this
page). Commit it like any other input the gate reads.

The way `check` works is what makes this workflow safe. It runs the same
discover, collect, merge, enrich, normalize, evaluate, render pipeline as
`generate`, but instead of writing each output it renders it in memory and
byte-compares it against the committed file. The string it compares against is
the same one `generate` would have written, so the only thing that can make a
fresh render and the committed file disagree is the committed file being out of
date. The gate writes nothing.

The only way to clear an exit `2` is to regenerate and commit. A reviewer who
sees CI go red on `2` knows a dependency moved and the inventory wasn't
refreshed; on `1`, that a license needs a decision.

## Pin the outputs to LF

The tool writes LF-only bytes, and the gate's byte comparison depends on that.
Windows checkouts can break an otherwise-correct setup here, so set this up once.

Git's default on Windows, `core.autocrlf=true`, rewrites text files to CRLF when
it checks them out. A contributor on Windows would then have a working-tree
`THIRD_PARTY_LICENSES.md` full of CRLF line endings, while the tool regenerates
LF. The gate would read the two as different and report the document stale on
every run, a failure with nothing actually wrong.

Pin the committed outputs to LF in a `.gitattributes` file at your repository
root, so git can't rewrite them on any platform:

```gitattributes
THIRD_PARTY_LICENSES.md text eol=lf
THIRD_PARTY_NOTICES.md text eol=lf
.sbomlet.cache/licenses.cache.json text eol=lf
.sbomlet.cache/docker.sbom.json text eol=lf
```

Keep all four lines even if your repository doesn't ship Docker base images.
The `.sbomlet.cache/docker.sbom.json` line is harmless when the file is absent and saves a
surprise if you add one later.

This matters even when nobody on the team develops on Windows today. The pins
travel with the repository, so the first Windows checkout, whether a new hire, a
CI runner, or another contributor, works the same as every other.

The gate carries a fallback for the unpinned case. When it reads a committed
file, it normalizes CRLF to LF before comparing, so a checkout that slipped
through without the pins doesn't produce a false stale result. The
`.gitattributes` pins are still the fix to apply, because they keep the committed
bytes stable in the first place, which is what the determinism guarantee depends
on.

## The gate never uses the network

The gate never touches the network, and this is enforced rather than configured.

`check` runs the pipeline in a mode that forbids the enrich step from fetching
or writing. Every license it needs comes from the committed
`.sbomlet.cache/licenses.cache.json`. If the inventory contains a package whose license
isn't in the cache and would otherwise require a registry lookup, the gate does
not reach out for it. It reports that package as stale (exit `2`) and names the
remedy, which is to run `generate` to refresh the committed cache. A missing
answer is treated the same as a missing output, because in both cases the
committed state is behind what the tool would produce today.

`generate` is the command that may use the network, and only to fill gaps a cold
cache can't answer: registry enrichment for otherwise-unknown licenses, and the
Docker scan (when run in its live, daemon-using modes). Once the committed caches are warm, `generate`
serves every license claim from them and runs offline too. So after the first
warm `generate`, steady-state runs of both commands need no network, and the
gate needs none ever.

This is why you don't grant the CI step any network egress, and why a locked-down
runner with no outbound access still passes the gate.

## Verify the cache before a release

The gate trusts the committed `.sbomlet.cache/licenses.cache.json` completely: every license
it can't read from a lockfile comes from that file, offline. That is what keeps
`check` fast and network-free, but it also means a wrong value in the cache — an
edit that flips a copyleft license to a permissive one, an entry for a package
that doesn't exist, or a real license quietly recorded as no-license — would pass
the gate unnoticed. `verify-cache` is the audit that closes that gap.

It re-resolves every committed cache entry against its registry — npm, PyPI,
the NuGet registration API, deps.dev for Maven, or the GitHub License API for
Terraform providers — with the same logic `generate` uses, and compares each
answer to the stored license. A divergence is either tampering or a genuine
upstream license change; either way it wants a person's eyes before you ship.

```sh
task sbomlet:verify:cache
```

Unlike `check`, this command needs the network — it is the one place the tool
re-reads the registries on purpose. Run it before a release or a compliance
audit, not on every build. Its exit codes follow the same taxonomy:

| Exit code | Meaning | What to do |
| --------- | ------- | ---------- |
| `0` | Every cache entry still matches its registry | Nothing; the cache is sound |
| `1` | At least one entry diverges from upstream | Read the report, then re-run `generate` to refresh the cache, or investigate the change |
| `3` (and above) | A registry was unreachable, or the cache file is malformed — the audit could not complete | Retry, or fix the cache file |

A `3` is deliberately distinct from a `1`: an unreachable registry means the tool
could not verify an entry, which is never quietly treated as agreement.

### Run it when the cache changes

The cache can only gain a wrong value when the committed file changes, so the
most useful trigger is exactly that — run the audit whenever the cache file is
touched, and never otherwise. On GitHub Actions a path filter does this:

```yaml
name: License cache integrity
on:
  push:
    paths: [".sbomlet.cache/licenses.cache.json"]
  pull_request:
    paths: [".sbomlet.cache/licenses.cache.json"]
permissions:
  contents: read
jobs:
  verify-cache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v2
      - run: task sbomlet:verify:cache
        env:
          # Lifts the GitHub License API rate limit for Terraform entries; the
          # audit works unauthenticated too, only slower.
          GITHUB_TOKEN: ${{ github.token }}
```

The path filter is the point: the job runs on the one event that can introduce a
bad entry — a commit that edits the cache — and stays idle the rest of the time.
Point the filter at wherever your repository keeps the cache if it isn't at the
root.

## Run an intensive scan to assess licenses at the source

Registry enrichment reads the license a package declares. That is a quick check,
and for some packages it is thin, missing, or wrong. `--intensive` adds a deeper
reading: it scans each package's actual source with
[ScanCode](https://github.com/aboutcode-org/scancode-toolkit), the same detector
suite the wider license-scanning ecosystem is built on, and treats that reading
as the senior one.

Unlike the registry lane, an intensive run assesses the **full** package set,
not just the unresolved leftovers. Where ScanCode reads a license, that reading
takes priority over the declared and registry answer. Where the two disagree,
the package fails the gate as a `conflict:scancode` finding for a person to
resolve with a `[[clarify]]` entry — the tool never silently picks a side. See
the [CLI reference](../reference/cli.md#generate) for the flag and a worked
`[[clarify]]` resolution.

```sh
task sbomlet:generate INTENSIVE=1
```

This is occasional/scheduled CI, not every build. ScanCode needs its own install
and takes real time to run, so the right place for it is a scheduled job, not a
step on every push:

- ScanCode is a real DEPENDENCY, so it is pinned in `mise.toml` like every other
  tool and arrives through the same `mise install` step every workflow already
  runs — no separate acquisition command.
- Installing it (`mise install`, cold) took about 90 seconds in a one-time
  measurement. Every `mise install` now pays this cost once per cache, whether
  or not that run scans — it is part of the pinned toolchain.
- Scanning one package's source tree took about 37 seconds wall-clock for a
  92-file dependency in this project's own measurements — cost scales with the
  size of each package, not the size of your repository.

### The first run is a backfill

Because the first intensive run assesses every package with locally-present
sources, it is long — on this repository, on the order of tens of minutes; on a
larger tree, a few hours. That one-time cost is why the scheduled workflow's
`timeout-minutes` is set generously (240 here). Rather than waiting for the cron
to reach it, trigger the first run yourself with `workflow_dispatch`, so the
backfill runs when you expect it.

After the backfill, steady state is cheap. ScanCode's answers are memoized in a
committed cache, `scancode.cache.json`, keyed by package version — including the
versions it scanned and found no license in. A later run only scans versions it
has never assessed, so a monthly run after a routine dependency bump scans a
handful of packages, and an unchanged lockfile scans nothing. A package whose
sources aren't installed that run is reported on stderr and skipped, never
memoized, so a later install can still assess it.

Wire it up the same way as the [cache-integrity audit](#verify-the-cache-before-a-release) —
a separate scheduled workflow, not the gate. This repository's own
`.github/workflows/intensive-scan.yml` runs it monthly and on manual dispatch,
then commits any new memo entries back the same way the Docker scan below does.
The gate reads the committed memo offline: once a scan assesses a package, every
later `generate` and `check` reuses the answer without scanning again.

### A scheduled scan can turn the main gate red

This is by design, and worth expecting. When a scheduled intensive run finds a
new disagreement between ScanCode and the registry, it commits a memo whose
presence makes the next `check` on `main` exit 1 — the `conflict:scancode`
finding demands a decision. That is not CI breaking; it is the tool asking a
person to resolve a real disagreement. The fix is to read the "Assessment
conflicts" section, decide which reading to trust, and record it with a
`[[clarify]]` entry. Until then the gate stays red, which is the point: an
unresolved conflict should not pass.

`--intensive` is generate-only; passing it to `check` is a config error, because
the gate never scans anything.

## Maven: regenerate the committed sidecar in your own CI

Maven is the one lane where the tool reads an artifact it never generates.
Same as the Docker scan below, this is a step alongside `task sbomlet:check`,
not a replacement for it — `generate` and `check` only ever read the
committed `maven.sbom.json` each module carries; neither one invokes Maven.

Run the pinned, ecosystem-standard `cyclonedx-maven-plugin` once at your
reactor root; its `makeBom` goal runs per module automatically:

```sh
./mvnw org.cyclonedx:cyclonedx-maven-plugin:2.9.2:makeBom -DoutputFormat=json -DoutputDirectory=. -DoutputName=maven.sbom -Dproject.build.outputTimestamp=2020-01-01T00:00:00Z
```

Commit every module's `maven.sbom.json`, then guard against a stale one the
same way you'd guard any other committed input — regenerate and fail the
build when the result differs from what's committed:

```yaml
# a step in your own build workflow, ahead of the SBOMlet gate
- run: ./mvnw org.cyclonedx:cyclonedx-maven-plugin:2.9.2:makeBom -DoutputFormat=json -DoutputDirectory=. -DoutputName=maven.sbom -Dproject.build.outputTimestamp=2020-01-01T00:00:00Z
- run: git diff --exit-code -- '**/maven.sbom.json'
```

A reactor regenerates every module's sidecar in the same run, so a module you
bump always leaves a matching sibling behind — the guard step above exists so
that never has to be caught downstream. If a sidecar ever does go stale
anyway, it fails safe rather than silently: the bumped module's new version
no longer matches what its siblings recorded as its identity, so the stale
reference surfaces as an ordinary third-party component in the inventory
instead of being excluded.

`makeAggregateBom`, the plugin's other goal, is deliberately not the recipe
here: it merges the whole reactor into one file and loses the per-module
attribution the inventory needs.

## The Docker scan is a separate step from the gate

Docker packages, the [os-scope](../glossary.md#scope-app-and-os) half of the
inventory, are not discovered or scanned by a plain `generate` or by `check`.
Neither runs Docker or [syft](../glossary.md#generator). Instead, a
`.sbomlet.cache/docker.sbom.json` is produced ahead of time by the
`generate-docker-sbom` subcommand and committed, and from then on `generate`
and `check` read it as a merge input the same way they read a lockfile. This
keeps a Docker daemon off the gate path: a CI `check` never needs Docker, even
for a repository that ships container images.

The Taskfile entry point for all of it is `task sbomlet:generate DOCKER=1`: refresh the
committed docker OS SBOM, then regenerate the inventory that merges it in, in
one run. There are three lanes, all reaching the same result: syft scans a real
image's full contents — OS packages and application packages alike. You pick a
lane by the variable you pass, and use exactly one at a time.

### Discover and build every Dockerfile in the repository

The default lane, with no extra variable, walks the repository (`REPO_ROOT`),
builds each Dockerfile it finds, and scans the image. A Dockerfile you don't
want built — a fixture, or a template that is not a real build — is kept out
with the policy's `[docker]` ignore globs (see below), so it never reaches
`docker build`.

```sh
# Discover, build & scan every Dockerfile under the repo root, then regenerate
task sbomlet:generate DOCKER=1
```

You run this when a Dockerfile or a base image changes, not on every CI run.

`task sbomlet:docker:list` prints the exact set the discovery lane would build, with no
daemon and no writes — useful to preview it or drive a build from a shell:

```sh
task sbomlet:docker:list
```

### Or name the Dockerfiles or images yourself

```sh
# Build named Dockerfiles and scan the images they produce
task sbomlet:generate DOCKER=1 DOCKERFILES="backend/Dockerfile frontend/Dockerfile"

# Or scan images you already have or can pull
task sbomlet:generate DOCKER=1 IMAGES="postgres:18 redis:7"
```

`DOCKERFILES` (the subcommand's `--dockerfile` flag) builds each named
Dockerfile to a local tag and scans the image it produces, so the inventory
covers what the Dockerfile actually ships: its base, the packages its own
`RUN apt install`/`apk add` steps add, and the application layered on top. It
needs a Docker daemon.

`IMAGES` (the `--image` flag) scans image references directly with the pinned
syft and pins each by content digest, so the committed file is stable across
machines. An image absent locally is pulled first; one already present is
scanned as-is.

### In CI: the Docker-scan workflow

This repository's own `.github/workflows/docker-scan.yml` runs the discovery lane
on a path-filtered push or pull request: it discovers the repository's Dockerfiles,
builds each to a local, never-pushed tag, scans those tags, and regenerates the
inventory — the same `task generate DOCKER=1` a maintainer runs locally.

A locally built, never-pushed tag has no registry digest, so the sidecar records
an empty one for it — that is expected, not a gap. A rebuild that changes the
image's contents changes the committed artifact, which is the scan recording a real
change. On a push, the workflow commits the regenerated artifacts back with a
signed bot commit; on a pull request, it fails the check red instead and uploads
the regenerated artifacts, so a contributor commits them deliberately. See
[ADR-0018](../explanation/adr/0018-docker-generated-image-scan.md) for why the
two events take different lanes.

### Whichever lane you use

The result is one committed `.sbomlet.cache/docker.sbom.json`. A scan or build
failure exits `3`, the same tool-error code as a bad flag — a Dockerfile that fails
`docker build` stops the run loudly, naming the file. It is never a gate verdict,
because this command is not the gate. After the file is committed, its packages
flow into the merged inventory, and `generate` and `check` go on reading the
committed bytes offline. Remember to add `.sbomlet.cache/docker.sbom.json` to
your `.gitattributes` LF pins so it byte-compares the same way on every checkout.

## See also

- [getting-started](../getting-started.md) — the guided first run that
  produces the inventory this gate checks.
- [glossary](../glossary.md) — the exact terms used here: the gate, staleness,
  enrichment, scope, verdict.
- [design-principles](../explanation/design-principles.md) — why the gate is
  built on determinism, an offline check, and honest residuals.
- [ADR-0019](../explanation/adr/0019-scancode-senior-assessment.md) — why the
  in-depth scan outranks the registry answer and keeps its own memo.
