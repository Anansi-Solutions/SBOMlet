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
  `.sbomlet.cache/docker-os.sbom.json` that `generate` and `check` read as an
  [OS-scope](../glossary.md#scope-app-and-os) input.

You run the tool through the Taskfile; the [Taskfile entry points](#taskfile-entry-points)
are at the bottom of this page. The flags documented below are what each `task`
forwards to the CLI.

## generate

Scans the repository and writes `THIRD_PARTY_LICENSES.md`,
`THIRD_PARTY_NOTICES.md`, and the [enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache),
plus a [CycloneDX](../glossary.md#cyclonedx) export when you ask for one. It does
not write `.sbomlet.cache/docker-os.sbom.json` — that is the maintainer-only
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
| `--intensive` | Scan the local sources of packages still unresolved after registry enrichment, with ScanCode. Generate-only; meant for occasional, scheduled CI, not every build. | off |
| `--verbose` | Print per-stage progress to stderr. | off |

`--target` and `--repo-root` are mutually exclusive; pass at most one. With
neither, discovery runs from the current directory.

`--intensive` runs after registry enrichment, against whatever [target](../glossary.md#target)
directories `generate` already collected — it never triggers a second discovery
walk. It has no effect on a package the registry already resolved; it only
scans the local source tree of a package still unknown or imprecise once
enrichment finishes, and if nothing is left unresolved it does nothing. When
requested but the scanner isn't on `PATH`, the run fails loudly rather than
skipping the scan silently:

```
scancode binary not found on PATH — install it with pipx install "scancode-toolkit[full]==32.5.0"
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
| `--verbose` | Print per-stage progress to stderr. | off |
| `--dump-model <path>` | Rejected — valid only on `generate`. | — |
| `--intensive` | Rejected — the gate never scans; valid only on `generate`. | — |

`--target` and `--repo-root` are mutually exclusive here too.

A committed document that is missing, that differs from the regenerated bytes, or a
licence gap the committed cache cannot answer all count as stale and exit 2. A
policy fail verdict exits 1 and takes priority over staleness. See the
[exit codes](#exit-codes) for the full mapping.

## verify-cache

The cache-integrity audit, and the only subcommand that re-reads the registries
on purpose. It loads the committed
[enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache),
re-resolves every entry against the registry that produced it — npm, PyPI, or the
GitHub License API for `pkg:terraform` providers — and compares each fresh answer
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
`.sbomlet.cache/docker-os.sbom.json` that you commit to the repository, and that `generate` and
`check` later read as an OS-scope merge input. Neither of those subcommands runs
this one or touches Docker; they read the bytes this subcommand writes.

It has five modes, chosen by which flag you pass.

`--image` runs a live [syft](../glossary.md#generator) scan and needs a running
Docker daemon. It scans the given image references and pins each by content digest.
With no `--image` and no other mode flag, it falls back to a built-in default image
set, which is what the zero-flag Taskfile entry uses.

`--repo-root` is discovery mode. It walks the repository for Dockerfiles, derives
the base image each shipped Dockerfile builds `FROM`, and scans those resolved base
images. It can be combined with explicit `--image` references, which are unioned
into the scan set. It records the base image's OS packages, not the packages a
Dockerfile installs itself in a `RUN apt`/`apk` step.

`--dockerfile` is targeted mode: the same derive-then-scan as discovery, but over
an explicit list of Dockerfile paths instead of a repository walk. Pass it more than
once to target several Dockerfiles. It can be combined with explicit `--image`
references, which are unioned into the scan set. If you also pass `--repo-root`, it
no longer triggers a discovery walk — it only anchors the cache directory the
committed SBOM is written to.

`--from-sbom` is the CI-attestation consumer path. It ingests pre-made
syft/CycloneDX SBOMs from disk with no Docker and no network. The build CI attests
an image's SBOM by registry digest and this tool ingests that attested SBOM. Point
it at a platform-specific (single-architecture) image SBOM so the recorded digest is
the real image digest rather than a multi-arch manifest-list digest.

`--pull` pulls each resolved image with `docker pull` before scanning it. It
applies to the live modes only (`--image`, `--repo-root`, `--dockerfile`), never to
`--from-sbom` or `--built-image`. It is off by default, so the everyday maintainer
path fails loudly on a missing image instead of racing a network fetch. The GitHub
Action turns it on because it derives its base image set only at runtime and cannot
pre-pull.

`--built-image` is built-image mode: it scans image tags you already built locally
and never pushed. It scans full contents (application packages as well as OS
packages), never resolves a registry digest, and records each ref in the sidecar
with an empty digest, since a local-only tag has none. Pass it more than once to
scan several built images. It never combines with `--pull` — a locally built image
cannot be pulled — and it is never inferred: you always request it explicitly.

`--list-dockerfiles` prints the repository's Dockerfiles instead of scanning
anything. It runs the same policy-aware walk discovery mode uses, prints each
discovered Dockerfile's repository-relative path to standard output, one per line,
and exits — no Docker, no syft, no file written. A Dockerfile matched by the
policy's `[docker]` ignore globs is left out of the list. Point a CI workflow at it
to build the exact Dockerfile set the tool would otherwise discover itself, rather
than reimplementing the walk in shell. It requires `--repo-root`.

| Flag | Meaning | Default |
| --- | --- | --- |
| `--image <ref>` | Live mode: scan this image reference with syft. Repeatable. Needs a Docker daemon. | built-in default image set |
| `--from-sbom <path>` | Consumer mode: ingest this pre-made SBOM. Repeatable. No Docker, no network. | — |
| `--repo-root <path>` | Discovery mode: derive base images from the repository's Dockerfiles. | — |
| `--dockerfile <path>` | Targeted mode: derive the base image of this Dockerfile. Repeatable. | — |
| `--built-image <ref>` | Built-image mode: scan this locally built, never-pushed tag. Repeatable. Needs a Docker daemon, never `--pull`. | — |
| `--list-dockerfiles` | List mode: print discovered Dockerfile paths and exit. Requires `--repo-root`. | off |
| `--pull` | Run `docker pull` on each resolved image before scanning it. Live modes only, never with `--built-image`. | off |
| `--exclude <glob>` | Drop targets whose identity matches the glob. Repeatable. | none |
| `--policy <path>` | TOML policy; its `[docker]` ignore globs prune Dockerfiles in discovery mode. | none |
| `--docker-os-sbom <path>` | Where to write the committed `.sbomlet.cache/docker-os.sbom.json`. | tool default |
| `--base-dir <path>` | Anchor every relative path flag to this directory. | working directory |
| `--verbose` | Print per-stage progress to stderr. | off |

`--image` and `--from-sbom` are mutually exclusive: a single run is either a live
scan or an ingest, not a mix. `--repo-root` (discovery) and `--from-sbom` (ingest)
are also mutually exclusive, since a pre-made ingest is not a live discovery scan.
`--dockerfile` (targeted) and `--from-sbom` (ingest) are mutually exclusive for the
same reason. `--repo-root` may be combined with `--image` or with `--dockerfile`
(where it serves only as the cache-dir anchor).

`--built-image` is exclusive with `--from-sbom`, `--image`, `--dockerfile`, and
`--pull`. It may be combined with `--repo-root`, where it too serves only as the
cache-dir anchor. `--list-dockerfiles` is exclusive with every scan-mode flag
(`--image`, `--from-sbom`, `--dockerfile`, `--built-image`) and requires
`--repo-root`, since that is the root it walks.

## Taskfile entry points

Run the tool through the Taskfile in CI and locally. A consumer repository includes
this Taskfile from its root:

```yaml
includes:
  sbomlet:
    taskfile: ./tools/sbomlet/Taskfile.yml
    dir: ./tools/sbomlet
    flatten: true
```

The `dir` key is required, so the tasks run inside `tools/sbomlet` and pick up that
directory's pinned runtime. With `flatten: true` SBOMlet's tasks are exposed unprefixed, so you run `task generate`, not `task sbomlet:generate`.

| Task | What it runs | When |
| --- | --- | --- |
| `task generate` | `generate` over the repository; writes the committed documents. | After a dependency changes; commit the result. |
| `task check` | `check`; the CI gate. | In CI, and locally before you push. |
| `task verify-cache` | `verify-cache`; the online cache-integrity audit. | Before a release/audit, or when the cache changes; needs the network. |
| `task generate-docker-sbom` | `generate-docker-sbom`; scans the image set and writes `.sbomlet.cache/docker-os.sbom.json`. | Maintainer-only, needs Docker; not part of `check`. |
| `task list-dockerfiles` | `generate-docker-sbom --list-dockerfiles`; prints the discovered Dockerfile paths. | To find the build set a CI workflow should use. No Docker, no writes. |
| `task quality` | Lint, format check, and typecheck for the tool itself. | When changing the tool. |

Each task reads variables you can override on the command line. Set a variable by
appending `NAME=value`:

```
task generate POLICY=.sbomlet.policy.toml
task check REPO_ROOT=/path/to/some/other/repo
task generate-docker-sbom IMAGES="app:latest worker:latest"
```

| Var | Used by | Meaning | Default |
| --- | --- | --- | --- |
| `REPO_ROOT` | `generate`, `check` | Repository root to scan. | the root Taskfile's directory |
| `OUTPUT` | `generate`, `check` | `THIRD_PARTY_LICENSES.md` path. | `THIRD_PARTY_LICENSES.md` beside `REPO_ROOT` |
| `NOTICES` | `generate`, `check` | `THIRD_PARTY_NOTICES.md` path. | `THIRD_PARTY_NOTICES.md` beside `REPO_ROOT` |
| `POLICY` | `generate`, `check`, `list-dockerfiles` | Policy file; the `--policy` flag is added only when set. | unset (no policy) |
| `CYCLONEDX` | `generate`, `check` | CycloneDX export path; the `--cyclonedx` flag is added only when set. | unset (no export) |
| `IMAGES` | `generate-docker-sbom` | Space-separated image references to scan. | unset (built-in default image set) |
| `FROM_SBOM` | `generate-docker-sbom` | Space-separated pre-built syft SBOM paths to ingest (no Docker). | unset |
| `DISCOVER_ROOT` | `generate-docker-sbom`, `list-dockerfiles` | Repository root whose Dockerfiles to derive or list (discovery mode; the repository root for `list-dockerfiles`). | this Taskfile's directory for `list-dockerfiles`, unset otherwise |
| `DOCKERFILES` | `generate-docker-sbom` | Space-separated Dockerfile paths to target (targeted mode). | unset |
| `BUILT_IMAGES` | `generate-docker-sbom` | Space-separated locally built image tags to scan (built-image mode). | unset |
| `PULL` | `generate-docker-sbom` | Set to a non-empty value to `docker pull` each resolved image before scanning. | unset (off) |
| `DOCKER_OS_SBOM` | `generate-docker-sbom` | `.sbomlet.cache/docker-os.sbom.json` output path. | `.sbomlet.cache/docker-os.sbom.json` beside `REPO_ROOT` |

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
