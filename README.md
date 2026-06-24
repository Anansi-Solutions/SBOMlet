<p align="center">
  <img src="assets/sbomlet-logo.png" alt="SBOMlet" width="200">
</p>

<h1 align="center">SBOMlet</h1>

<p align="center">
  <em>Know every licence in your dependency tree — and fail the build before a bad one ships.</em>
</p>

---

Every repository pulls in hundreds of third-party packages, each under its own
licence. Usually nobody has the full list — until a customer's legal team asks for
it, or a copyleft licence quietly lands in something you ship and no one notices.

**SBOMlet gives you that list and keeps it honest.** Point it at a repository and it
inventories every dependency and its licence, writes the attribution files you're
obliged to redistribute, and turns the result into a CI gate: a licence that breaks
your policy fails the build instead of reaching production. It spans JS/TS, Python,
Terraform/OpenTofu, and the OS packages inside your Docker base images, and it has no
ties to the project it audits — you adopt it by dropping in one directory and writing
one short policy file.

## What you get

One command — `generate` — reads your lockfiles and writes:

- **`THIRD_PARTY_LICENSES.md`** — the readable inventory: every package, version,
  licence, and where it's used.
- **`THIRD_PARTY_NOTICES.md`** — the verbatim licence texts you're required to ship.
- **A [CycloneDX](docs/glossary.md#cyclonedx) SBOM** (optional) — the machine-readable
  standard, for anything downstream that consumes one.

The inventory reads like this:

```markdown
# Third-Party Licenses

**Package counts:**
- Total packages: 1,284
- Production packages: 951
- Unknown license: 0

## Production dependencies

| Name | Ecosystem | Version | License | Used in |
| --- | --- | --- | --- | --- |
| react | npm | 19.2.0 | MIT | apps/web |
| cryptography | pypi | 44.0.1 | Apache-2.0 OR BSD-3-Clause | services/api |
| hashicorp/aws | terraform | 5.92.0 | MPL-2.0 | infra |
```

## The gate

`check` is what makes it more than a report. It regenerates the inventory offline,
byte-compares it against the committed copy so the file can't silently drift, and
evaluates your `policy.toml`. A clean run:

```console
$ task sbomlet:check
policy: 0 fail, 0 warn, 0 suppressed, 1284 ok (1284 verdicts)
```

Introduce a dependency your policy forbids, and the same command fails — and exits
non-zero, so CI stops:

```console
$ task sbomlet:check
policy: 1 fail, 0 warn, 0 suppressed, 1283 ok (1284 verdicts)
policy fail: pkg:npm/some-agpl-tool@2.1.0 in services/api — deny: AGPL-3.0 is denied outside a copyleft-distributed workspace
```

That non-zero exit is the point — a licence that breaks your rules can't ship.

## How it works

1. **Point.** SBOMlet walks the repo and finds every place dependencies are declared
   — `yarn.lock`, `package-lock.json`, `pnpm-lock.yaml`, `bun.lock`, `poetry.lock`,
   `uv.lock`, `.terraform.lock.hcl`.
2. **Read.** Each is read by a pinned, industry-standard generator
   ([cdxgen](https://github.com/CycloneDX/cdxgen),
   [syft](https://github.com/anchore/syft)) or a small in-house parser, and the
   results merge into one inventory keyed by [package URL](docs/glossary.md#purl).
3. **Gate.** Your `policy.toml` decides what's allowed; `check` fails CI on the first
   violation.

When a licence is genuinely ambiguous, SBOMlet marks it `unknown` and surfaces it
rather than guessing — see
[honest residual](docs/explanation/design-principles.md). The number you can't stand
behind is the one it refuses to invent.

## Quickstart

You need [mise](https://mise.jdx.dev), which resolves the pinned toolchain, and
[Task](https://taskfile.dev) v3. Add SBOMlet to your repository — a git submodule or a
vendored copy under, say, `tools/sbomlet` — then include its Taskfile from your root
`Taskfile.yml`:

```yaml
includes:
  sbomlet:
    taskfile: ./tools/sbomlet/Taskfile.yml
    dir: ./tools/sbomlet
```

Copy [`policy.example.toml`](policy.example.toml) to `policy.toml`, then:

```sh
task sbomlet:generate POLICY=policy.toml   # write the inventory
task sbomlet:check    POLICY=policy.toml   # run the gate
```

Commit the generated `THIRD_PARTY_*.md` and `enrichment-cache.json`, then run
`task sbomlet:check` in CI. The full walkthrough — install, first run, reading the
output, wiring CI — is in [getting-started](docs/getting-started.md).

## Supported ecosystems

| Ecosystem | Read from |
| --- | --- |
| JS / TypeScript | `yarn.lock`, `package-lock.json`, `pnpm-lock.yaml`, `bun.lock` |
| Python | `poetry.lock`, `uv.lock` |
| Terraform / OpenTofu | `.terraform.lock.hcl` |
| Docker base images (OS packages) | a committed `docker-os-sbom.json` (see below) |

Discovery walks the repository and hands each [target](docs/glossary.md#target) to its
[collector](docs/glossary.md#collector). The per-ecosystem detail — which generator
runs, what it reports, and where
[dependency provenance](docs/glossary.md#dependency-provenance) is available — is in
the [CLI reference](docs/reference/cli.md).

## Documentation

New here? Start with **getting-started** for a first run. Reach for a how-to guide
when you have a task in front of you, and an explanation when you want to know why
SBOMlet is shaped the way it is.

| Read this if you want to… | Page |
| --- | --- |
| Install SBOMlet and get a first inventory and a passing gate | [getting-started](docs/getting-started.md) |
| Look up a command, flag, exit code, or the `policy.toml` schema | [CLI reference](docs/reference/cli.md) |
| Write a `policy.toml` — add a `[[deny]]` rule, clarify an imprecise licence | [writing-policy](docs/guides/writing-policy.md) |
| Understand the determinism, honest-residual, and safety properties | [design-principles](docs/explanation/design-principles.md) |
| See the module layout and the collector registry | [architecture](docs/explanation/architecture.md) |
| Follow the discover → merge → enrich → normalize → evaluate → render pipeline | [data-flow](docs/explanation/data-flow.md) |
| Know the canonical model — `PackageEntry`, `LicenseFinding`, `Verdict` | [data-model](docs/explanation/data-model.md) |
| Find the reasoning behind a specific design choice | [ADRs](docs/explanation/adr/) |

## Good to know

- **Docker OS packages** aren't discovered from lockfiles. A maintainer runs
  `generate-docker-sbom` once to produce a committed `docker-os-sbom.json`, and
  `generate`/`check` merge it in. It's the only subcommand that talks to a Docker
  daemon or registry; `generate` and `check` never do.
- **The network.** `generate` reaches out only to fill a gap a cold cache can't
  answer — a registry lookup for an otherwise-unknown licence. Once
  `enrichment-cache.json` is committed it serves every claim, and `check` never goes
  online. To re-validate the warm cache against upstream before a release, run
  `task sbomlet:verify-cache`.
- **Line endings.** SBOMlet writes LF-only bytes so `check` can byte-compare. On
  Windows, pin the committed outputs to LF in your `.gitattributes`, or `check` reads
  them as permanently stale:

```gitattributes
THIRD_PARTY_LICENSES.md text eol=lf
THIRD_PARTY_NOTICES.md  text eol=lf
enrichment-cache.json   text eol=lf
docker-os-sbom.json     text eol=lf
```
