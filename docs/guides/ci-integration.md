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
task check POLICY=.sbomlet.policy.toml
```

That is the entire integration. It works the same on GitHub Actions, GitLab CI,
a Jenkins stage, a pre-merge hook, or a developer's terminal, because all the
behavior lives in the tool and the Taskfile rather than in the runner.

Some concrete shapes, so you can paste the right one:

```yaml
# GitHub Actions — a step inside a job that has mise and Task available
- run: task check POLICY=.sbomlet.policy.toml
```

```yaml
# GitLab CI — a job
licenses:
  script:
    - task check POLICY=.sbomlet.policy.toml
```

The runner needs [mise](https://mise.jdx.dev) and [Task](https://taskfile.dev)
on `PATH`, the same as a local run. mise resolves the pinned runtime the tool ships
with, so you don't install it in CI either. Beyond that there is nothing to
configure, and no API key, service container, or network allowance.

If your repository keeps its outputs somewhere other than the root, or uses a
CycloneDX export, pass the same flags you pass to `generate` so the gate
compares the same files. The variables are caller-overridable:

```sh
task check POLICY=.sbomlet.policy.toml CYCLONEDX=sbom.cdx.json
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
task generate POLICY=.sbomlet.policy.toml
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

So an adopter running plain `task generate` always gets three files:
the inventory, the companion, and the cache.

`generate` does not write `.sbomlet.cache/docker-os.sbom.json`. That file is produced by the
separate `generate-docker-sbom` command, described at the end of this page, and
is committed like any other input the gate reads.

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
.sbomlet.cache/docker-os.sbom.json text eol=lf
```

Keep all four lines even if your repository doesn't ship Docker base images.
The `.sbomlet.cache/docker-os.sbom.json` line is harmless when the file is absent and saves a
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

It re-resolves every committed cache entry against its registry — npm, PyPI, or
the GitHub License API for Terraform providers — with the same logic `generate`
uses, and compares each answer to the stored license. A divergence is either
tampering or a genuine upstream license change; either way it wants a person's
eyes before you ship.

```sh
task verify-cache
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
      - run: task verify-cache
        env:
          # Lifts the GitHub License API rate limit for Terraform entries; the
          # audit works unauthenticated too, only slower.
          GITHUB_TOKEN: ${{ github.token }}
```

The path filter is the point: the job runs on the one event that can introduce a
bad entry — a commit that edits the cache — and stays idle the rest of the time.
Point the filter at wherever your repository keeps the cache if it isn't at the
root.

## The Docker scan is a separate step from the gate

Docker packages, the [os-scope](../glossary.md#scope-app-and-os) half of the
inventory, are not discovered or scanned by `generate` or `check`. Neither
command runs Docker or [syft](../glossary.md#generator). Instead, a
`.sbomlet.cache/docker-os.sbom.json` is produced ahead of time by the separate
`generate-docker-sbom` subcommand and committed, and from then on `generate`
and `check` read it as a merge input the same way they read a lockfile. This
keeps a Docker daemon off the gate path: a CI `check` never needs Docker, even
for a repository that ships container images.

There are two ways to run it: by hand against a project's base images, or as a
CI job that builds and scans the images the repository actually produces.

### By hand: scan the images you name or discover

You run this when a base image changes, not on every CI run:

```sh
task generate-docker-sbom
```

The command's manual modes are mutually exclusive. The right one depends on
whether you have a daemon, a repository full of Dockerfiles, or a pre-built SBOM
from your image pipeline.

| Mode | When to use it | Needs a Docker daemon |
| ---- | -------------- | --------------------- |
| `--image <ref>…` | You can pull or build the images and want to scan them directly | Yes |
| `--repo-root <dir>` | You want the tool to discover Dockerfiles and scan each shipped base image | Yes |
| `--from-sbom <path>…` | Your build pipeline already produced syft SBOMs and attested them by digest | No |

`--image` scans each ref directly with the pinned syft, and pins each scanned
image by content digest so the committed file is stable across machines. With no
`--image` and no other mode, the command falls back to the maintainer's
documented default image set, which is why the bare
`task generate-docker-sbom` above works for the project that ships the
tool. Pull or build each image first, since the scanner fails loudly on an image
that isn't present locally.

`--repo-root` is the discovery mode. The tool walks the repository for
Dockerfiles, derives the external base image each shipped (final) stage declares,
and scans those bases. A Dockerfile whose base it can't pin down (an unresolvable
build argument, a heredoc, a Windows escape directive) contributes no image and
is skipped loudly rather than guessed at, so you can pin that base with an
explicit `--image`. Discovery derives the base image's own OS packages, not the
packages a Dockerfile's `RUN apt install` lines add on top; capturing those needs
a built image, which is what the CI lane below and `--from-sbom` are for.

```sh
# Discover Dockerfiles under the repo and scan their bases, plus an explicit one
task generate-docker-sbom DISCOVER_ROOT=. IMAGES="postgres:18"
```

`--from-sbom` is the daemon-free consumer path, and the one to use in a mature
pipeline. Your image build already produces a syft SBOM by registry digest as a
build attestation; this mode ingests those SBOMs without running Docker or the
network. Scan a platform-specific (single-arch) image when you produce the SBOM,
so the recorded digest is the real image digest and not a multi-arch
manifest-list digest.

```sh
# Ingest pre-built, attested SBOMs — no daemon, no network
task generate-docker-sbom FROM_SBOM="build/backend.cdx.json build/frontend.cdx.json"
```

### In CI: build and scan the images the repository produces

The manual modes above all scan a base image — what a Dockerfile builds `FROM`,
not what it ships. To also capture the packages a Dockerfile's own `RUN` steps
install and the application layered on top, build the image and scan the result
with `--built-image`. This is what this repository's own
`.github/workflows/docker-scan.yml` does on a path-filtered push or pull
request: it lists the repository's Dockerfiles with `--list-dockerfiles`,
builds each one to a local, never-pushed tag, scans those tags with
`--built-image`, and regenerates the inventory.

```sh
# List the Dockerfiles a CI job should build (no Docker, no writes)
task list-dockerfiles

# Scan already-built local tags — full contents, no daemon digest to pin
task generate-docker-sbom BUILT_IMAGES="myapp:ci myworker:ci"
```

A locally built, never-pushed tag has no registry digest, so the sidecar records
an empty one for it — that is expected, not a gap. On a push, the workflow commits
the regenerated artifacts back with a signed bot commit; on a pull request, it
fails the check red instead and uploads the regenerated artifacts, so a
contributor commits them deliberately. See
[ADR-0018](../explanation/adr/0018-docker-generated-image-scan.md) for why the
two events take different lanes.

### Whichever way you produce it

The result is one committed `.sbomlet.cache/docker-os.sbom.json`, whether it came
from a manual base-image scan or a CI built-image scan. A scan or build failure
exits `3`, the same tool-error code as a bad flag. It is never a gate verdict,
because this command is not the gate. After the file is committed, its packages
flow into the merged inventory, and `generate` and `check` go on reading the
committed bytes offline. Remember to add `.sbomlet.cache/docker-os.sbom.json` to
your `.gitattributes` LF pins so it byte-compares the same way on every checkout.

## See also

- [getting-started](../getting-started.md) — the guided first run that
  produces the inventory this gate checks.
- [glossary](../glossary.md) — the exact terms used here: the gate, staleness,
  enrichment, scope, verdict.
- [design-principles](../explanation/design-principles.md) — why the gate is
  built on determinism, an offline check, and honest residuals.
