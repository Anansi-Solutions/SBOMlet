# Getting started

This is a guided first run for an operator: someone adding the tool to a
repository, generating a license inventory, and wiring up the CI gate. By the
end you'll have a committed `THIRD_PARTY_LICENSES.md`, a passing
[`check`](./glossary.md#the-gate-check), and the configuration that keeps both
current.

If you only need a quick reference after your first run, the
[`README.md`](../README.md) is the condensed version. If you're changing the
tool itself, start from [`contributing.md`](./contributing.md) instead.

## Pick your route

There are two ways to run the tool. Pick one now; the guide follows your
choice from here.

- **[Route A — use the GitHub Action](#route-a--use-the-github-action)**, if
  your repository runs CI on GitHub Actions and that's the only place the tool
  needs to run. Nothing is vendored and nothing lands on your machine: a
  workflow step checks the tool out on the runner and runs it there.
- **[Route B — SBOMlet as a submodule](#route-b--sbomlet-as-a-submodule)**,
  for any other CI vendor, or when you also want to run the tool locally. You
  vendor the tool into your repository and drive it through
  [Task](https://taskfile.dev) or Make.

Both routes produce the same committed files and the same gate, and they share
the sections after the routes — reading the output and pinning line endings.
Whichever you pick, start with the policy file.

## Step 1 — Copy the example policy

Without a policy file the tool only inventories licenses. A policy file turns
that inventory into a gate by attaching a [verdict](./glossary.md#verdict) of
`ok`, `warn`, `fail`, or `suppressed` to every dependency. Start from the
commented example that ships with the tool; download it to your repository
root as `.sbomlet.policy.toml`:

```sh
curl -fsSL -o .sbomlet.policy.toml \
  https://raw.githubusercontent.com/Anansi-Solutions/SBOMlet/main/policy.example.toml
```

On route B you can copy it from the vendored tree instead, once the tool is in
place: `cp tools/sbomlet/policy.example.toml .sbomlet.policy.toml`.

`policy.example.toml` is heavily annotated and a reasonable default to begin
with. You don't need to understand every lane yet. The example denies the
[source-available](./glossary.md#source-available) licenses that matter most
(BUSL, SSPL, Elastic) and accepts the common permissive ones. You'll tune it
later, after you've seen what your repository contains. Every override you add
requires a written reason, because the policy file doubles as your audit trail.

## Route A — use the GitHub Action

On this route your repository carries the policy file from step 1, a workflow,
and the committed inventory the gate compares against. The action checks
SBOMlet out on the runner at the version you pin, provisions its pinned
toolchain there, and runs the gate against your checkout.

### Step A1 — Add the gate workflow

Create `.github/workflows/licenses.yml`:

```yaml
name: Licenses
on: [push, pull_request]
permissions:
  contents: read
jobs:
  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: Anansi-Solutions/SBOMlet@main # pin a tag or SHA in production
        with:
          mode: check
          policy: .sbomlet.policy.toml
```

`mode: check` is the default; it's written out because you'll meet the other
mode, `generate`, in the next step. The step passes when the committed
inventory matches what the tool would generate now and no dependency trips a
`fail` verdict in your policy, and fails the build otherwise. The exit codes,
and what to do about each, are in
[ci-integration](./guides/ci-integration.md#what-the-exit-code-means).

### Step A2 — Produce the first inventory

The gate compares against a committed inventory, and you haven't generated one
yet, so the first run fails as "stale or missing". The inventory has to be
generated once and committed. Two ways to do it:

**Let a refresh PR deliver it.** Ship a second workflow that turns a failed
gate into a refresh: on every pull request it runs the action in `check` mode;
when the check fails, it re-runs in `generate` mode, opens a
`licenses-refresh/<branch>` pull request carrying the regenerated files
against your branch, comments the link on your PR, and still fails the gate.
Merge the refresh PR into your branch and the gate goes green. A ready-made
workflow is shipped at
[`examples/licenses-refresh.yml`](../examples/licenses-refresh.yml); copy it
into `.github/workflows/` and fill in the dependency-install placeholder
(marked in the file) for your stack. On your first pull request it delivers
the initial inventory the same way.

**Or generate once from a clone.** If you have [mise](https://mise.jdx.dev) on
some machine, clone SBOMlet anywhere and point its `generate` task at your
repository:

```sh
git clone https://github.com/Anansi-Solutions/SBOMlet
cd SBOMlet && mise install
mise x -- task generate REPO_ROOT=/path/to/your/repo POLICY=/path/to/your/repo/.sbomlet.policy.toml
```

Either way the outputs land at your repository root. Commit them —
`THIRD_PARTY_LICENSES.md`, `THIRD_PARTY_NOTICES.md`, and
`.sbomlet.cache/licenses.cache.json` — and the gate passes. The cache file is
committed on purpose: it's what lets the gate run offline.

That's the route. Now read [what it produced](#look-at-what-it-produced) — on
this route, the refresh PR's diff is a good place to do it — and
[pin the outputs to LF](#pin-the-outputs-to-lf-do-this-on-windows).

## Route B — SBOMlet as a submodule

On this route you need one tool on your machine: [mise](https://mise.jdx.dev).
Install it with `curl https://mise.run | sh`, or your package manager.
Everything else the tool needs — its pinned runtime and
[Task](https://taskfile.dev), which drives it — is declared in the tool's own
`mise.toml`, and a single `mise install` in the next step fetches all of it.
There's no Node install, no build step, and nothing to compile.

To confirm mise is present:

```sh
mise --version
```

### Step B1 — Put the tool in your repository

The tool lives in one self-contained directory. Add it to your repository as a
git submodule at `tools/sbomlet`:

```sh
# from your repository root
git submodule add https://github.com/Anansi-Solutions/SBOMlet tools/sbomlet
```

The submodule pins an exact version, so every machine and every CI run uses
the same tool, and you move to a newer one deliberately with
`git submodule update --remote tools/sbomlet`. A fresh clone of your
repository leaves `tools/sbomlet` empty until someone runs
`git submodule update --init` (or clones with `git clone --recurse-submodules`).

If your repository avoids submodules, vendor a plain copy instead:

```sh
# from your repository root
git clone --depth 1 https://github.com/Anansi-Solutions/SBOMlet tools/sbomlet
rm -rf tools/sbomlet/.git
```

Either way, the directory carries its own `mise.toml` with the toolchain pins,
so it works the same on every machine. Fetch the toolchain once:

```sh
(cd tools/sbomlet && mise install)
```

That fetches the pinned toolchain — the runtime, Task, and the scanners the
tool drives — into mise's store; nothing lands globally. The tool's own
dependencies arrive on the first generate.

### Step B2 — Wire it into your build

The tool's `Taskfile.yml` is its interface: everything runs through
`task sbomlet:generate` and `task sbomlet:check`. How you reach that Taskfile
depends on what your repository already builds with; pick one of the two.

#### If your repository uses Task

Open your root `Taskfile.yml` (create one if you don't have it) and add the
include:

```yaml
version: "3"

includes:
  sbomlet:
    taskfile: ./tools/sbomlet/Taskfile.yml
    dir: ./tools/sbomlet
```

The `dir:` line is required. The tasks have to run inside `tools/sbomlet` so
that mise resolves that directory's toolchain pins. Without it, Task would run
at your repository root, where there's no pin. The include exposes SBOMlet's
tasks under the `sbomlet:` prefix — `task sbomlet:generate`,
`task sbomlet:check` — so they can never collide with task names of your own,
and the prefix says where a task comes from. (If nothing in your Taskfile
clashes, `flatten: true` on the include drops the prefix.)

This route needs a `task` binary of your own to run the include. If you don't
have one yet, mise provides that too: `mise use task` at your repository root
pins it in your own config.

To check the include took:

```sh
task --list
```

You should see `sbomlet:generate` and `sbomlet:check` among the tasks.

#### If your repository uses Make

You don't need Task on your machine for this route: the pinned copy from
`tools/sbomlet/mise.toml` runs the Taskfile. Add two targets to your root
`Makefile`:

```make
SBOMLET_POLICY ?= .sbomlet.policy.toml

.PHONY: sbomlet-generate sbomlet-check
sbomlet-generate:
	cd tools/sbomlet && mise x -- task generate REPO_ROOT="$(CURDIR)" POLICY="$(CURDIR)/$(SBOMLET_POLICY)"

sbomlet-check:
	cd tools/sbomlet && mise x -- task check REPO_ROOT="$(CURDIR)" POLICY="$(CURDIR)/$(SBOMLET_POLICY)"
```

The recipes change into `tools/sbomlet` so that mise resolves that directory's
toolchain pins, for the same reason the Task route needs `dir:`. They run the
tool's own Taskfile directly, so the task names carry no prefix there.
`REPO_ROOT="$(CURDIR)"` points the scan back at your repository root, which is
also where the outputs land, and the policy path is passed absolute so it
names the same file no matter where the task executes.

The rest of this guide shows the Task commands. On this route, run
`make sbomlet-generate` wherever you see `task sbomlet:generate POLICY=…`, and
`make sbomlet-check` for `task sbomlet:check POLICY=…`.

### Step B3 — Generate the inventory

Now run it:

```sh
task sbomlet:generate POLICY=.sbomlet.policy.toml
```

The first run is the slow one. The tool walks your repository for every
dependency [target](./glossary.md#target), meaning each directory
that holds a `yarn.lock`, `poetry.lock`, `.terraform.lock.hcl`, and so on. Each target goes to
its [collector](./glossary.md#collector), which either drives a standard SBOM
[generator](./glossary.md#generator) or reads the lockfile itself. A large
JavaScript workspace can take a minute or so on a cold run, partly because the
generators are fetched the first time and partly because some of them are slow.
It also reaches the package registries to fill in licenses that lockfiles leave
blank. That step is
[enrichment](./glossary.md#enrichment-and-the-enrichment-cache), and its answers
are written to a cache so later runs don't repeat the network calls.

`POLICY=.sbomlet.policy.toml` is a relative path, and it resolves against the directory
you ran `task` from, not against `tools/sbomlet`, even though the task executes
in there. So you can run this from your repository root and point at a policy
file there.

### Step B4 — Run the gate

You generated the documents a moment ago, so the gate should be clean. Run it:

```sh
task sbomlet:check POLICY=.sbomlet.policy.toml
echo "exit code: $?"
```

You want to see `exit code: 0`. That's the gate confirming two things at once:
the committed documents match exactly what the tool would generate right now,
and no dependency tripped a `fail` verdict in your policy.

`check` works differently from `generate`. It regenerates the inventory in
memory and compares it byte-for-byte against the files on disk. It writes
nothing, and it never touches the network; every license it needs comes from the
committed `.sbomlet.cache/licenses.cache.json`. That's what lets it run in CI
deterministically.

The exit code tells you which class of thing is wrong, if anything:

| Exit code | Meaning | What to do |
| --------- | ------- | ---------- |
| `0` | Clean — documents match, no violations | Nothing; the gate passes |
| `1` | A dependency tripped a `fail` verdict | Fix the dependency, or add a documented policy override |
| `2` | A committed document is [stale](./glossary.md#staleness) or missing | Re-run `task sbomlet:generate`, review the diff, commit |
| `3+` | Tool or config error — bad flag, invalid policy | Fix the invocation or the policy file |

A `fail` verdict (exit 1) takes precedence over staleness (exit 2), so a real
policy violation can't hide behind an out-of-date document. The code you'll meet
most often is `2`: someone changed a dependency and forgot to regenerate. The
fix is to generate, look at the diff, and commit.

### Step B5 — Commit everything

Commit the generated outputs, the policy, and the wiring together:

```sh
git add THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md .sbomlet.cache/licenses.cache.json
git add .sbomlet.policy.toml
git add tools/sbomlet Taskfile.yml
git commit -m "docs: add third-party license inventory and CI gate"
```

Swap `Taskfile.yml` for your `Makefile` if you took the Make wiring. If you
added the tool as a submodule, step B1 already staged `.gitmodules`; it rides
along in this commit.

The `.sbomlet.cache/licenses.cache.json` is committed on purpose, because it's what lets
`check` run offline in CI.

### Step B6 — Wire it into CI

The gate is one command, and it works on any CI vendor because it has nothing
vendor-specific. Wherever your pipeline runs checks, add:

```sh
task sbomlet:check POLICY=.sbomlet.policy.toml
```

It passes when the committed inventory is current and your policy is satisfied,
and fails the build otherwise, with the exit code telling you which case it is.
A reviewer who sees the build go red on exit 2 knows someone needs to
regenerate; on exit 1, that a dependency needs attention. Concrete per-vendor
shapes are in [ci-integration](./guides/ci-integration.md).

From here on, the routine task is the one you already know: when a dependency
changes, run `task sbomlet:generate POLICY=.sbomlet.policy.toml`, review the
diff, and commit it.

## Look at what it produced

Whichever route you took, you now have three new files at your repository root
(on route A, the refresh PR's diff shows them):

| File | What it is |
| ---- | ---------- |
| `THIRD_PARTY_LICENSES.md` | The inventory: every dependency, its license, its version, where it's used, and why it's present |
| `THIRD_PARTY_NOTICES.md` | The attribution companion: copyright lines, NOTICE contents, and full license texts |
| `.sbomlet.cache/licenses.cache.json` | The licenses fetched from registries during enrichment, so `check` can run offline |

The first generate always produces the cache file, even if every dependency's
license came straight from a lockfile and there was nothing to look up — an
empty cache is still a cache. A later run rewrites it with the same bytes
unless it fetches a new license.

Open `THIRD_PARTY_LICENSES.md` and read the top. The header doesn't carry a
date; it carries the command that regenerates the file. A date would change on
every run, and the gate could never tell a real change from the clock ticking.

Scan the table. Most rows will name a precise SPDX license like `MIT` or
`Apache-2.0`. Some may show `BSD (imprecise)` or a blank license. Those are
cases the tool couldn't pin down and reports as-is rather than guessing, an
[honest residual](./glossary.md#honest-residual). They aren't errors; they're
the things a human might want to look at. The "Why" column shows `—` for
ecosystems where provenance isn't available.

## Pin the outputs to LF (do this on Windows)

The tool writes LF-only line endings, and that byte-stability is what `check`
compares against. On Windows, git's default checkout setting
(`core.autocrlf=true`) rewrites text files to CRLF when it checks them out. Then
`check` would see the working-tree copy as CRLF and the regenerated bytes as LF,
and report the documents perpetually stale.

Pin the committed outputs to LF so git can't rewrite them. Add these lines to a
`.gitattributes` file at your repository root:

```gitattributes
THIRD_PARTY_LICENSES.md text eol=lf
THIRD_PARTY_NOTICES.md text eol=lf
.sbomlet.cache/licenses.cache.json text eol=lf
```

This matters even if you develop on macOS or Linux: a teammate on Windows would
hit the stale gate without it. The pins protect every future checkout, so
commit the file:

```sh
git add .gitattributes
git commit -m "chore: pin the license inventory to LF"
```

## Where to go next

- [`guides/ci-integration.md`](./guides/ci-integration.md) — the exit codes in
  depth, the cache audit you run before a release, and the Docker scan.
- [`guides/writing-policy.md`](./guides/writing-policy.md) — how to tune the
  policy lanes once you've seen what your repository contains: deny a license,
  clarify an imprecise one, or suppress in-workspace copyleft.
- [`guides/reading-the-output.md`](./guides/reading-the-output.md) — how to read
  `THIRD_PARTY_LICENSES.md` and decide what to do about a flagged dependency.
- [`reference/cli.md`](./reference/cli.md) — the full command, flag, and
  exit-code reference once you've been through this once.
- [`explanation/design-principles.md`](./explanation/design-principles.md) — why
  the gate is built around determinism and honest residuals, if you want the
  reasoning behind what you set up.
