# Troubleshooting

This page is for an operator: someone running the tool and wiring it into CI who
hit something that doesn't look right. Each entry starts from the symptom you'd
actually see (a stderr line, an exit code, a row in the output), names the cause,
and gives you the fix.

If you haven't done a first run yet, start from
[`../getting-started.md`](../getting-started.md). Much of the confusion here
disappears once the inventory, the [enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache),
and the `.gitattributes` pins are all committed. Linked terms point to the
[glossary](../glossary.md) on first use.

## `check` says stale and exits 2

`check` prints a line like this and the build goes red:

```text
check stale: THIRD_PARTY_LICENSES.md differs from generated output
```

The cause is usually the ordinary one: a dependency changed and the committed
documents weren't regenerated. The [gate](../glossary.md#the-gate-check) rebuilds
the whole inventory in memory and compares it byte-for-byte against the files on
disk. When they differ, the committed copy is [stale](../glossary.md#staleness)
and you get exit 2.

To fix it, regenerate, look at the diff, and commit it:

```sh
task generate POLICY=.sbomlet.policy.toml
git diff THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md
git add THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md .sbomlet.cache/licenses.cache.json
git commit -m "chore: regenerate license inventory"
```

Read the diff before you commit it. It tells you which dependency moved, and
occasionally it surfaces something you'd want to know about, such as a new
transitive dependency under a license you don't allow. Commit the regenerated
cache alongside the documents. `generate` may have fetched a new license during
[enrichment](../glossary.md#enrichment-and-the-enrichment-cache), and leaving the cache
behind would make the next `check` stale again.

A `missing` variant of the same line means the committed file was never written
at all:

```text
check stale: THIRD_PARTY_LICENSES.md is missing
```

A never-generated output is stale by definition, so this is the same exit 2 with
the same fix: run `generate` and commit what it produces.

If `check` keeps reporting stale right after a clean `generate`, and the diff
looks like every line changed, the cause is line endings rather than content. See
[Windows reports everything stale](#windows-reports-everything-stale) below.

## Lots of dependencies show an unknown or blank license

You scan a repository and a large number of rows come back with no license, or
the run is much slower than you expected. There are two causes, and they often
appear together on a first run.

The first is a cold enrichment cache. Some lockfiles don't record a license at
all, so the tool fills those gaps by asking the package registry (npm or PyPI)
during enrichment, and writes the answers to the committed
[enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache). On the very
first `generate` that cache is empty, so every gap is a live network call and
the run is slow. This is expected once. Run `generate`, commit the cache, and
the next run reads from it instead of the network:

```sh
task generate POLICY=.sbomlet.policy.toml
git add .sbomlet.cache/licenses.cache.json
git commit -m "chore: commit enrichment cache"
```

The second cause is a genuine registry gap: the registry itself has no license
metadata for that package version, so enrichment has nothing to return. The tool
leaves the license blank rather than guessing, which records an
[honest residual](../glossary.md#honest-residual). A handful of these is normal
and not an error; they're the rows a person should look at.

A related shape is a row that reads something like `BSD (imprecise)` rather than
blank. That's an [imprecise family](../glossary.md#imprecise-family): the source
named the license only by family, with no clause or version, so it can't be
turned into a precise SPDX id without guessing. The tool flags it for you to pin
down.

For both the genuine gap and the imprecise family, the resolution is the same.
Find the real license (the package's repository or its `LICENSE` file is the
authority) and record it with a `[[clarify]]` entry in your policy. Clarify is
the lane that corrects a package's [license finding](../glossary.md#license-finding)
to a precise expression, and the override carries a written reason so the policy
file stays your audit trail. The lanes and their syntax are covered in
[`writing-policy.md`](./writing-policy.md), and reading these rows is covered in
[`reading-the-output.md`](./reading-the-output.md).

## `check` wants the network or fails offline

`check` is meant to run with no network access, which is what makes it safe in
a locked-down CI runner. If it fails complaining that a package needs enrichment,
you'll see a line naming the package and the remedy:

```text
check stale: pkg:npm/some-package@1.2.3 needs enrichment — run task generate to refresh the committed cache
```

The cause is a missing cache entry. `check` never fetches anything; when it finds
a dependency whose license isn't in the committed
[enrichment cache](../glossary.md#enrichment-and-the-enrichment-cache), it can't fill
the gap, so it treats that exactly like a missing output (stale, exit 2) rather
than reaching for the network. The package named in the line is one your
committed cache doesn't cover yet, usually because a dependency was added or
bumped without regenerating.

To fix it, run `generate` (which is allowed to fetch and write) and commit the
refreshed cache:

```sh
task generate POLICY=.sbomlet.policy.toml
git add .sbomlet.cache/licenses.cache.json THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md
git commit -m "chore: refresh enrichment cache"
```

The cache is committed on purpose. It's the artifact that lets the gate run
offline and deterministically, so treat it as part of the inventory: whenever you
regenerate the documents, regenerate and commit the cache with them.

## A Terraform target fails loudly asking you to run `tofu init`

A scan of a Terraform directory stops with an error like:

```text
target "infra/network": `tofu init`/`tofu get` has not run (it materializes the
`.terraform/` directory and writes .terraform/modules/modules.json for any module
call) — not found at infra/network/.terraform/modules/modules.json
```

The cause is that the directory hasn't been initialized. The Terraform
[collector](../glossary.md#collector) reads two artifacts that init produces:
`.terraform.lock.hcl` for the provider versions, which is committed, and
`.terraform/modules/modules.json` for the exact resolved module versions, which
isn't. The whole `.terraform/` directory is gitignored and absent until you
init. The tool uses the presence of those files as a filesystem signal that init
has run. When the directory is empty or partially initialized, it can't tell a
real "no modules here" directory from one that hasn't been set up, so it refuses
to guess and stops.

To fix it, initialize the directory before you scan it:

```sh
cd infra/network
tofu init   # or: terraform init
```

Then re-run `generate`. In CI, the same init has to run before the license task,
as it would before a `tofu plan`. This isn't a special requirement of this
tool; an uninitialized Terraform directory is incomplete for any purpose.

One narrow case resolves on its own: a directory that declares providers but no
modules at all leaves `.terraform/providers/` without a
`.terraform/modules/` directory, and the tool recognizes that exact shape and
collects the providers from the committed lock without complaint. The loud error
fires only when the filesystem shape is incoherent (an empty `.terraform/`, or a
`.terraform/modules/` with no `modules.json` inside it), which means init didn't
finish.

## A Docker base image shows up as unresolved

A Dockerfile is discovered but its base image comes back unresolved, and Docker
[scope (os)](../glossary.md#scope-app-and-os) packages for it are skipped with a
warning. The reason names what the tool couldn't get past:

```text
heredoc present — base not derived; pin the base via --image
escape directive present — base not derived; pin via --image
continuation altered FROM structure — base uncertain; pin via --image
```

The cause is an ambiguous Dockerfile. The tool reads each Dockerfile only far
enough to resolve the final `FROM`'s base image, and it [abstains](../glossary.md#abstain)
the moment the structure becomes ambiguous rather than risk naming the wrong
base. The common triggers are a heredoc anywhere in the file (a `<<EOF` block),
a `# escape=` parser directive that remaps the line-continuation character (most
often on Windows Dockerfiles where a path like `C:\dist\` would otherwise look
like a continuation), and a backslash continuation that merges or swallows a
`FROM` line. In a compliance tool, abstaining and asking you to pin the base is
safer than silently inheriting the wrong image's packages.

Note that this is only about the *declared base image's* OS packages. The tool
does not build the image or capture what the Dockerfile's own `RUN apt install`
steps add; that's a separate path described below.

To fix it, pin the base image explicitly so resolution doesn't depend on parsing
the Dockerfile. Pass the resolved base ref to `--image` when you produce the
Docker OS SBOM:

```sh
task generate-docker-sbom IMAGES="debian:12 node:22-slim"
```

This is the maintainer-only `generate-docker-sbom` subcommand, and what touches
Docker and what doesn't matters here. `generate` and `check` never run Docker and
never scan an image. They only read a separately committed `.sbomlet.cache/docker-os.sbom.json`
as a [scope (os)](../glossary.md#scope-app-and-os) input. That file is produced
ahead of time by a maintainer running `generate-docker-sbom`, which requires a
Docker daemon and uses syft to scan the images. So when a base shows unresolved,
you pin it with `--image`, regenerate `.sbomlet.cache/docker-os.sbom.json`, commit it, and from
then on the offline `generate`/`check` flow reads those committed bytes.

If you'd rather not have the tool try to derive a particular Dockerfile's base at
all, you can exclude it with an `[docker] ignore` glob in your policy instead of
pinning it.

## A copyleft or denied dependency fails the gate (exit 1)

`check` exits 1 and the policy summary names a dependency with a `fail`
[verdict](../glossary.md#verdict). This is different in kind from the staleness
cases above: exit 1 means the inventory is current and correct, and a dependency
in it violates your policy. A `fail` takes precedence over staleness, so a real
violation can never hide behind an out-of-date document.

The two usual triggers are a [copyleft](../glossary.md#copyleft) dependency
flagged because it carries a distribution obligation, and a
[source-available](../glossary.md#source-available) or otherwise named license
caught by the [deny lane](../glossary.md#policy-lanes). This is the gate doing its
job, so there's no single mechanical fix; the right response depends on the
dependency and on what your project ships.

Two pages cover the decision rather than repeat it here.
[`reading-the-output.md`](./reading-the-output.md) explains how to read the
flagged row (the verdict, the rule that decided it, and the reason) so you know
exactly what tripped. [`writing-policy.md`](./writing-policy.md) covers what to do
about it: removing or replacing the dependency, allowing the license with a
documented reason, or, for copyleft that's expected because your own workspace
ships under the same terms, suppressing it with the workspace copyleft rule.

## Windows reports everything stale

You run `generate`, then `check` immediately, and `check` reports the documents
stale even though nothing changed. The diff looks like every single line is
different.

The cause is line endings. The tool writes LF-only files, and the gate compares
against those bytes. On Windows, git's default checkout setting
(`core.autocrlf=true`) rewrites text files to CRLF when it checks them out, so the
working-tree copy is CRLF while the freshly generated bytes are LF, and the gate
sees every line as changed.

To fix it, pin the committed outputs to LF so git can't rewrite them. Add these
lines to a `.gitattributes` file at your repository root:

```gitattributes
THIRD_PARTY_LICENSES.md text eol=lf
THIRD_PARTY_NOTICES.md text eol=lf
.sbomlet.cache/licenses.cache.json text eol=lf
.sbomlet.cache/docker-os.sbom.json text eol=lf
```

Then renormalize the files already in the working tree and commit:

```sh
git add --renormalize .
git commit -m "chore: pin license outputs to LF"
```

The gate itself defends against this too: it normalizes the committed copy from
CRLF to LF before comparing, so a single stray checkout won't fail you. The
`.gitattributes` pins are still the durable fix, because they keep the *committed*
bytes LF for everyone, including a teammate on Windows who'd otherwise hit the
stale gate even on an unchanged repository.

## Where to go next

- [`reading-the-output.md`](./reading-the-output.md) — how to read a flagged row,
  an imprecise family, or a residual once one of these shows up.
- [`writing-policy.md`](./writing-policy.md) — the policy lanes for clarifying a
  license, allowing one, or suppressing expected copyleft.
- [`../getting-started.md`](../getting-started.md) — the full first-run
  walkthrough, including the `.gitattributes` pins and committing the cache.
