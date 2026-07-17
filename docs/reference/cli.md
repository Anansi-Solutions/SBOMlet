# CLI reference

For the operator. Every subcommand, every flag, and what the tool returns when it
exits. For a guided first run, start with [getting started](../getting-started.md).
Terms in bold link to the [glossary](../glossary.md) the first time they appear.

The tool has four subcommands:

- `generate` — scan the repository and write the committed documents.
- `check` — regenerate in memory and compare against the committed documents; the
  [CI gate](../glossary.md#the-gate-check).
- `verify-cache` — online; re-resolve every committed
  [enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache) entry
  against its registry and report any divergence from the stored licence.
- `generate-docker-sbom` — maintainer-only; produce the committed
  `.sbomlet.cache/docker.sbom.json` that `generate` and `check` read as an
  [OS-scope](../glossary.md#scope-app-and-os) input.

You run the tool through the Taskfile; the [Taskfile entry points](#taskfile-entry-points)
are at the bottom of this page. The flags documented below are what each `task`
forwards to the CLI.

## generate

Scans the repository and writes `THIRD_PARTY_LICENSES.md`,
`THIRD_PARTY_NOTICES.md`, and the [enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache),
plus a [CycloneDX](../glossary.md#cyclonedx) export when you ask for one. It does
not write `.sbomlet.cache/docker.sbom.json` — that is the maintainer-only
[`generate-docker-sbom`](#generate-docker-sbom) subcommand.

`generate` always writes the documents whatever the policy verdicts say. The policy
is evaluated and its verdicts print to stderr, but the gate is `check`, never
`generate`.

| Flag | Meaning | Default |
| --- | --- | --- |
| `--repo-root <path>` | Discovery mode: scan every lockfile [target](../glossary.md#target) under this root. | current directory |
| `--target <path>` | Single-target mode: scan one lockfile or Terraform directory. For debugging one ecosystem. | — |
| `--exclude <glob>` | Drop targets whose identity matches the glob. Repeatable. | none |
| `--policy <path>` | TOML policy file. Validated before any scan; verdicts print to stderr. | none |
| `--output <path>` | Where to write `THIRD_PARTY_LICENSES.md`. | `THIRD_PARTY_LICENSES.md` |
| `--notices <path>` | Where to write the `THIRD_PARTY_NOTICES.md` companion. | beside `--output` |
| `--cyclonedx <path>` | Also write a merged CycloneDX 1.6 export to this path. | not written |
| `--dump-model <path>` | Write the internal merged model as JSON, for inspecting what the tool built. | not written |
| `--base-dir <path>` | Anchor every relative path flag to this directory instead of the working directory. | working directory |
| `--enrichment-cache <path>` | Where to read and write the enrichment cache. | tool default |
| `--scancode-cache <path>` | Where to read and write the ScanCode assessment memo (`scancode.cache.json`). | tool default |
| `--intensive` | Assess every package with ScanCode, an in-depth source scan that outranks the registry answer where present; a disagreement fails the gate as a conflict. Generate-only; for occasional, scheduled CI, not every build. | off |
| `--verbose` | Print per-stage progress to stderr. | off |

`--target` and `--repo-root` are mutually exclusive; pass at most one. With
neither, discovery runs from the current directory.

`--target` on a Yarn workspaces root still expands into one scan unit per
workspace member ([ADR-0020](../explanation/adr/0020-yarn-workspace-scan-units.md)) —
single-target mode narrows which directory the loop starts from, not whether a
Yarn lockfile's own workspace members get expanded.

`--intensive` assesses the full package set with
[ScanCode](https://github.com/aboutcode-org/scancode-toolkit), a deep read of
each package's own source. It runs after registry enrichment, against whatever
[target](../glossary.md#target) directories `generate` already collected — it
never triggers a second discovery walk.

Where ScanCode reads a licence, that reading is the senior one: it takes
priority over the declared and registry answer for that package. A `[[clarify]]`
override still outranks it, since that is where you record a human decision. When
ScanCode disagrees with the registry answer, neither is taken automatically — the
package fails the gate as a distinct `conflict:scancode` finding, and the
document grows an "Assessment conflicts (in-depth scan vs quick check)" section
naming both readings. You resolve it with a `[[clarify]]` entry recording which
to trust. For a package the registry calls `MIT` while ScanCode reads
`BSD-3-Clause`, trusting the scan:

```toml
[[clarify]]
package = { name = "example-pkg", version = "1.2.3" }
expects = "MIT"             # the quick-check answer you are overriding away from
expression = "BSD-3-Clause" # the reading you trust
reason = "ScanCode read BSD-3-Clause from the vendored LICENSE file."
```

The `expects` guard keeps the decision honest: if the registry later relicenses
off `MIT`, the override no longer matches and the gate fails as
[stale](../glossary.md#staleness), so a resolved conflict cannot silently mask a
real relicence. See the [policy reference](policy.md#clarify) for the full
`[[clarify]]` semantics.

ScanCode's answers live in their own committed memo, `scancode.cache.json`, keyed
by package version — override its path with `--scancode-cache`. The memo also
records the versions that were scanned and found no licence, so an
already-assessed version is never re-scanned. A package whose sources are not
present locally is skipped and reported on stderr, never memoised, so a later
install can still scan it.

When `--intensive` is requested but the scanner isn't on `PATH`, the run fails
loudly rather than skipping the scan silently:

```
scancode binary not found on PATH — run mise install
```

### .NET targets

.NET targets are discovered from committed `packages.lock.json` files, one
target per project — NuGet writes one lockfile per project directory, and the
lockfile is opt-in
([getting started](../getting-started.md#if-your-repository-is-net) has the
setup). The collector parses the lockfile in process: no generator
subprocess, and no .NET toolchain needed on the scanning machine
([ADR-0022](../explanation/adr/0022-dotnet-lockfile-in-process.md)). Lock
format versions 1 and 2 are both read, so central package management
(`Directory.Packages.props`, including its `CentralTransitive` entries) works
with no extra configuration.

The lane's limits, stated plainly:

- The lockfile carries no dev/prod marker, so every NuGet package gates as
  **production** — the safe direction; nothing can hide in a dev scope.
- [Dependency provenance](../glossary.md#dependency-provenance) is not
  available; the "Why" column shows `—`.
- A package that is not on nuget.org — a private-feed package — resolves as
  license **unknown**, recorded as a negative cache entry; it never fails the
  run.
- A package whose license ships only as a file embedded in the package (no
  SPDX expression in its registry metadata) also resolves as **unknown**
  rather than a guess.
- paket lockfiles are not supported; only `packages.lock.json` is read.

### Maven targets

Maven targets are discovered from a committed `maven.sbom.json`, one target
per module — a multi-module reactor scans as one target per module
directory, no expansion machinery. The sidecar is produced by the pinned
`cyclonedx-maven-plugin` in the consumer's own CI, never by this tool
([getting started](../getting-started.md#if-your-repository-is-maven) has
the setup; [ADR-0023](../explanation/adr/0023-maven-committed-sidecar.md)
records why). The collector parses the committed document in process: no
generator subprocess, and no Maven toolchain needed on the scanning machine.
A sibling module referenced inside a dependent module's own sidecar is
excluded by an exact purl match against every discovered module's own root
purl, computed before any module is collected — a module bumped without
regenerating every sidecar in the reactor surfaces the stale reference as an
ordinary third-party component instead of silently vanishing.

The lane's limits, stated plainly:

- Test-scope dependencies are absent from the sidecar entirely — the
  plugin's default `makeBom` goal excludes them, so they are not inventoried,
  not merely hidden in a dev column. `includeTestScope=true` is not the way
  to recover them: the flag makes every test dependency indistinguishable
  from production in the sidecar, so all of them would gate as production
  too. A future sidecar carrying both the default document and a
  test-inclusive one is the documented way to add real dev/prod
  classification for Maven; it is not built.
- Every other Maven package gates as **production** — compile, runtime,
  provided, and system scope alike — because the sidecar carries no
  per-component scope to classify by. This is the safe direction: nothing,
  including a `system`-scoped commercial jar, can hide in a dev scope it was
  never assigned.
- [Dependency provenance](../glossary.md#dependency-provenance) is not
  available; the "Why" column shows `—`.
- A package with no public record on Maven Central resolves as license
  **unknown** through [deps.dev](https://deps.dev), an aggregator of
  Central's own metadata: its declared licence, not a scan of the package's
  source, recorded as a negative cache entry when it has none; it never
  fails the run.
- A commercial or system-scoped jar with no public licence record resolves
  the same way: an honest unknown, not a guess.

The system-scoped jars a `<dependency>` with `<scope>system</scope>` declares
are exactly this last case — a commercial licence with no public claim to
enrich from. Record the decision with a `LicenseRef-` [[clarify]] expression,
the sanctioned spelling for that case:

```toml
[[clarify]]
package = { name = "reporting-engine-pro", version = "9.0.0" }
expression = "LicenseRef-reporting-engine-pro-commercial"
reason = "Commercial reporting-engine licence, vendored under lib/; no public SPDX id exists."
```

## check

The CI gate. It runs the same scan as `generate` entirely in memory, then reads
each committed document once and compares it byte-for-byte against what `generate`
would write now. It writes nothing and never touches the network. Every licence
gap is answered from the committed enrichment cache, and a gap the cache does not
cover is reported as [stale](../glossary.md#staleness), not fetched.

`check` accepts the same flags as `generate` so that the set of files it verifies
is exactly the set `generate` writes. Two flags it rejects: `--dump-model`, because
the gate performs no writes, so it will not let you point a dump path at the files
it is meant to verify; and `--intensive`, because the gate never scans. Passing
either is a config error (exit 3).

| Flag | Meaning | Default |
| --- | --- | --- |
| `--repo-root <path>` | Discovery mode: regenerate from every target under this root. | current directory |
| `--target <path>` | Single-target mode: regenerate from one target. | — |
| `--exclude <glob>` | Drop targets whose identity matches the glob. Repeatable. | none |
| `--policy <path>` | TOML policy file. A fail verdict makes the gate exit 1. | none |
| `--output <path>` | The `THIRD_PARTY_LICENSES.md` to compare against. | `THIRD_PARTY_LICENSES.md` |
| `--notices <path>` | The `THIRD_PARTY_NOTICES.md` to compare against. | beside `--output` |
| `--cyclonedx <path>` | Also compare a committed CycloneDX export at this path. | not compared |
| `--base-dir <path>` | Anchor every relative path flag to this directory. | working directory |
| `--enrichment-cache <path>` | The committed enrichment cache to read. | tool default |
| `--scancode-cache <path>` | The committed ScanCode memo to replay. | tool default |
| `--verbose` | Print per-stage progress to stderr. | off |
| `--dump-model <path>` | Rejected — valid only on `generate`. | — |
| `--intensive` | Rejected — the gate never scans; valid only on `generate`. | — |

`--target` and `--repo-root` are mutually exclusive here too.

`--target` on a Yarn workspaces root still expands per workspace member, the
same as `generate` (above).

A committed document that is missing, that differs from the regenerated bytes, or a
licence gap the committed cache cannot answer all count as stale and exit 2. A
policy fail verdict exits 1 and takes priority over staleness. See the
[exit codes](#exit-codes) for the full mapping.

## verify-cache

The cache-integrity audit, and the only subcommand that re-reads the registries
on purpose. It loads the committed
[enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache),
re-resolves every entry against the registry that produced it — npm, PyPI, the
NuGet registration API, deps.dev for `pkg:maven`, or the GitHub License API
for `pkg:terraform` providers — and compares each fresh answer
to the stored licence. A single equality on the raw licence string catches every
way the cache can go wrong: a value that changed upstream or was edited, an entry
for a package the registry no longer resolves, and a no-licence entry the registry
contradicts with a real licence.

Run it before a release or an audit, or whenever the committed cache changes — not
on every build. It needs the network; a registry failure is a tool error (exit 3),
never a silent pass.

| Flag | Meaning | Default |
| --- | --- | --- |
| `--enrichment-cache <path>` | The committed cache to audit. | `.sbomlet.cache/licenses.cache.json` at `--base-dir` |
| `--base-dir <path>` | Anchor the cache path to this directory instead of the working directory. | working directory |
| `--verbose` | Print per-stage progress to stderr. | off |

The report prints to stderr, one block per divergence — the purl, the committed
value, the registry's current answer, and why they differ — followed by a summary
line. The exit code is the machine signal: `0` every entry matches, `1` at least
one diverges, `3` the audit could not complete (an unreachable registry or a
malformed cache). Set `GITHUB_TOKEN` to lift the GitHub License API rate limit for
Terraform entries; the audit works without it, just slower.

## generate-docker-sbom

Maintainer-only. This is the only subcommand that touches Docker. It produces the
`.sbomlet.cache/docker.sbom.json` that you commit to the repository, and that `generate` and
`check` later read as an OS-scope merge input. Neither of those subcommands runs
this one or touches Docker; they read the bytes this subcommand writes.

It has three lanes, chosen by which flag you pass. Whichever lane you use, the run
ends the same way: [syft](../glossary.md#generator) scans a real image's full
contents — the OS packages and the application packages alike — and the result is
written to the committed SBOM.

`--dockerfile` builds each named Dockerfile and scans the image it produces. Pass it
more than once to build and scan several. Each Dockerfile is built to a local tag
derived from its path, so the same Dockerfile always scans under the same identity.
Needs a running Docker daemon.

`--repo-root` discovers the repository's Dockerfiles, builds each, and scans the
images. It runs the same policy-aware walk `--list-dockerfiles` uses: a Dockerfile
matched by the policy's `[docker]` ignore globs, or by `--exclude`, is left out of
the build set. This is the lane the Docker-scan workflow drives. Needs a Docker
daemon.

`--image` scans image references you already have locally or that live in a
registry, and pins each by content digest. An image that is absent locally is
pulled first with `docker pull`; one already present is scanned as-is and never
re-pulled, so a run never races a newer registry copy into the committed bytes. A
locally built, never-pushed tag has no registry digest, so its entry records an
empty one. Needs a Docker daemon.

`--list-dockerfiles` prints the repository's Dockerfiles instead of building
anything. It runs the same discovery walk `--repo-root` uses, prints each
Dockerfile's repository-relative path to standard output one per line, and exits —
no Docker, no syft, no file written. A Dockerfile matched by the policy's `[docker]`
ignore globs is left out. Point a CI workflow at it to build the exact set the tool
would discover itself. It requires `--repo-root`, the root it walks.

| Flag | Meaning | Default |
| --- | --- | --- |
| `--dockerfile <path>` | Build this Dockerfile and scan the image it produces. Repeatable. Needs a Docker daemon. | — |
| `--repo-root <path>` | Discover the repository's Dockerfiles, build each, and scan. Needs a Docker daemon. | — |
| `--image <ref>` | Scan this image reference; pull it first if absent locally. Repeatable. Needs a Docker daemon. | — |
| `--list-dockerfiles` | Print discovered Dockerfile paths and exit. Requires `--repo-root`. No Docker. | off |
| `--exclude <glob>` | Drop Dockerfiles whose identity matches the glob. Repeatable. | none |
| `--policy <path>` | TOML policy; its `[docker]` ignore globs prune Dockerfiles in the discovery lane. | none |
| `--docker-sbom <path>` | Where to write the committed `.sbomlet.cache/docker.sbom.json`. | tool default |
| `--base-dir <path>` | Anchor every relative path flag to this directory. | working directory |
| `--verbose` | Print per-stage progress to stderr. | off |

The three lanes are mutually exclusive: one run is one way in. `--dockerfile`,
`--repo-root`, and `--image` cannot be combined with each other — pass exactly one.
A run with no lane and no `--list-dockerfiles` is a usage error, since there is no
default image set. `--list-dockerfiles` combines with no scan lane and requires
`--repo-root`, the walk root it lists.

## Taskfile entry points

Run the tool through the Taskfile in CI and locally. A consumer repository includes
this Taskfile from its root:

```yaml
includes:
  sbomlet:
    taskfile: ./tools/sbomlet/Taskfile.yml
    dir: ./tools/sbomlet
```

The `dir` key is required, so the tasks run inside `tools/sbomlet` and pick up that
directory's pinned runtime. The include namespaces the tasks under the `sbomlet:`
prefix, so you run `task sbomlet:generate`, not a bare `task generate` — the
prefix can never collide with a task name of your own. (`flatten: true` on the
include drops the prefix, for a repository with no clashing task names.)

| Task | What it runs | When |
| --- | --- | --- |
| `task sbomlet:generate` | `generate` over the repository; writes the committed documents. With `DOCKER=1` it first refreshes the committed docker OS SBOM (build & scan; needs a Docker daemon). | After a dependency changes; commit the result. |
| `task sbomlet:check` | `check`; the CI gate. | In CI, and locally before you push. |
| `task sbomlet:verify:cache` | `verify-cache`; the online cache-integrity audit. | Before a release/audit, or when the cache changes; needs the network. |
| `task sbomlet:docker:list` | `generate-docker-sbom --list-dockerfiles`; prints the discovered Dockerfile paths. | To preview the build set a `DOCKER=1` run would discover. No Docker, no writes. |

Every task installs the tool's dependencies first through a shared `install`
dependency, so there is no separate install step. Tasks for changing the tool
itself (lint, test, quality, ...) live in `Taskfile.dev.yml`, included optionally
and kept out of `task --list` on purpose; see
[contributing](../contributing.md#the-task-surface). Each task documents its
variables — read them with `--summary`, as in `task sbomlet:generate --summary`.

Each task reads variables you can override on the command line. Set a variable by
appending `NAME=value`:

```
task sbomlet:generate POLICY=.sbomlet.policy.toml
task sbomlet:check REPO_ROOT=/path/to/some/other/repo
task sbomlet:generate DOCKER=1 IMAGES="app:latest worker:latest"
```

| Var | Used by | Meaning | Default |
| --- | --- | --- | --- |
| `REPO_ROOT` | `generate`, `check`, `verify:cache`, `docker:list` | Repository root to scan; also the walk root for Dockerfile discovery. | the root Taskfile's directory |
| `OUTPUT` | `generate`, `check` | `THIRD_PARTY_LICENSES.md` path. | `THIRD_PARTY_LICENSES.md` beside `REPO_ROOT` |
| `NOTICES` | `generate`, `check` | `THIRD_PARTY_NOTICES.md` path. | `THIRD_PARTY_NOTICES.md` beside `REPO_ROOT` |
| `POLICY` | `generate`, `check`, `docker:list` | Policy file; the `--policy` flag is added only when set. | unset (no policy) |
| `CYCLONEDX` | `generate`, `check` | CycloneDX export path; the `--cyclonedx` flag is added only when set. | unset (no export) |
| `INTENSIVE` | `generate` | Set (`INTENSIVE=1`) to add `--intensive`: scan still-unresolved packages' local sources with ScanCode after registry enrichment. | unset |
| `DOCKER` | `generate` | Set (`DOCKER=1`) to build & scan the repository's Dockerfiles and refresh the committed docker OS SBOM before generating. Needs a Docker daemon. | unset |
| `DOCKERFILES` | `generate` with `DOCKER=1` | Space-separated Dockerfile paths to build & scan instead of discovering (the targeted lane). | unset (discover) |
| `IMAGES` | `generate` with `DOCKER=1` | Space-separated pre-existing image refs to scan instead of building (the image lane). | unset (discover) |
| `DOCKER_SBOM` | `generate` with `DOCKER=1` | `.sbomlet.cache/docker.sbom.json` output path. | `.sbomlet.cache/docker.sbom.json` beside `REPO_ROOT` |

Relative paths you pass are anchored to the directory you ran `task` from, not to
`tools/sbomlet`, because each task forwards `--base-dir` set to your invocation
directory.

## Exit codes

Codes 1 and 2 come only from a structured result — `check` produces both,
`verify-cache` produces 1 — never from an exception. Every error, in any
subcommand, exits 3 or higher.

| Code | Meaning |
| --- | --- |
| `0` | Success. `generate` wrote its outputs, `check` found everything current and clean, or `verify-cache` found every entry matching upstream. |
| `1` | A structured failure: a `check` policy fail verdict (priority over staleness), or a `verify-cache` entry that diverges from upstream. |
| `2` | `check` only: a committed document is stale or missing, or a licence gap needs enrichment the committed cache can't answer. |
| `3` | Tool or config error: unknown subcommand, mutually-exclusive flags, an invalid policy file, a scan or pipeline failure, a registry unreachable during `verify-cache`, or `--dump-model` on `check`. |

Warn verdicts and unused-policy-entry warnings print to stderr but never gate; only
a fail verdict reaches exit 1.
