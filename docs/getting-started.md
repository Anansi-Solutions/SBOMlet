# Getting started

This is a guided first run for an operator: someone adding the tool to a
repository, generating a license inventory, and wiring up the CI gate. By the
end you'll have a committed `THIRD_PARTY_LICENSES.md`, a passing
[`check`](./glossary.md#the-gate-check), and the configuration that keeps both
current. It follows one path from start to finish.

If you only need a quick reference after your first run, the
[`README.md`](../README.md) is the condensed version. If you're changing the
tool itself, start from [`contributing.md`](./contributing.md) instead.

## Before you start

You need two things on your machine. The tool runs on a pinned runtime, but you don't install
it yourself; [mise](https://mise.jdx.dev) reads the pinned version and fetches
it for you.

| Tool | Why you need it | Install |
| ---- | --------------- | ------- |
| [mise](https://mise.jdx.dev) | Resolves and runs the pinned runtime the tool ships with | `curl https://mise.run \| sh` (or your package manager) |
| [Task](https://taskfile.dev) | Runs `task generate` and `task check` | `mise use -g task` (or your package manager) |

That's the whole list. The tool keeps a small dependency footprint, since it
audits dependencies. There's no Node install, no build step, and nothing to
compile.

To confirm both are present:

```sh
mise --version
task --version
```

## Step 1 — Put the tool in your repository

The tool lives in one self-contained directory. Copy `` into your
repository, keeping that path:

```sh
# from your repository root
cp -r /path/to/tools/sbomlet tools/sbomlet
```

It carries its own `mise.toml` with the runtime pin, so it works the same on every
machine. You don't need to install anything inside it yet. The first
`task generate` will do that.

## Step 2 — Add the Taskfile include

Open your repository's root `Taskfile.yml` (create one if you don't have it) and
add the include:

```yaml
version: "3"

includes:
  sbomlet:
    taskfile: ./tools/sbomlet/Taskfile.yml
    dir: ./tools/sbomlet
    flatten: true
```

The `dir:` line is required. The tasks have to run inside `tools/sbomlet` so
that mise resolves that directory's runtime pin. Without it, Task would run at your
repository root, where there's no pin. `flatten: true` exposes SBOMlet's tasks unprefixed, so you run
`task generate` and `task check`; nothing else is wired in.

To check the include took:

```sh
task --list
```

You should see `generate` and `check` among the tasks.

## Step 3 — Copy the example policy

Without a policy file the tool only inventories licenses. A policy file turns
that inventory into a gate by attaching a [verdict](./glossary.md#verdict) of
`ok`, `warn`, `fail`, or `suppressed` to every dependency. Start from the
commented example and rename it:

```sh
cp policy.example.toml .sbomlet.toml
```

`policy.example.toml` is heavily annotated and a reasonable default to begin
with. You don't need to understand every lane yet. The example denies the
[source-available](./glossary.md#source-available) licenses that matter most
(BUSL, SSPL, Elastic) and accepts the common permissive ones. You'll tune it
later, after you've seen what your repository contains. Every override you add
requires a written reason, because the policy file doubles as your audit trail.

## Step 4 — Generate the inventory

Now run it:

```sh
task generate POLICY=.sbomlet.toml
```

The first run is the slow one. The tool walks your repository for every
dependency [target](./glossary.md#target), meaning each `yarn.lock`,
`poetry.lock`, `.terraform.lock.hcl` directory, and so on. Each target goes to
its [collector](./glossary.md#collector), which either drives a standard SBOM
[generator](./glossary.md#generator) or reads the lockfile itself. A large
JavaScript workspace can take a minute or so on a cold run, partly because the
generators are fetched the first time and partly because some of them are slow.
It also reaches the package registries to fill in licenses that lockfiles leave
blank. That step is
[enrichment](./glossary.md#enrichment-and-the-enrichment-cache), and its answers
are written to a cache so later runs don't repeat the network calls.

`POLICY=.sbomlet.toml` is a relative path, and it resolves against the directory
you ran `task` from, not against `tools/sbomlet`, even though the task executes
in there. So you can run this from your repository root and point at a policy
file there.

## Step 5 — Look at what it produced

When it finishes, you'll have three new files at your repository root:

| File | What it is |
| ---- | ---------- |
| `THIRD_PARTY_LICENSES.md` | The inventory: every dependency, its license, its version, where it's used, and why it's present |
| `THIRD_PARTY_NOTICES.md` | The attribution companion: copyright lines, NOTICE contents, and full license texts |
| `.sbomlet.cache.json` | The licenses fetched from registries during enrichment, so `check` can run offline |

The cache is written only when `generate` fetches something new. Your first run
fills it from empty, so you'll have it; a later run that finds every license in
the cache leaves it untouched.

Open `THIRD_PARTY_LICENSES.md` and read the top. The header doesn't carry a
date; it carries the command that regenerates the file. A date would change on
every run, and the gate could never tell a real change from the clock ticking.

Scan the table. Most rows will name a precise SPDX license like `MIT` or
`Apache-2.0`. Some may show `BSD (imprecise)` or a blank license. Those are
cases the tool couldn't pin down and reports as-is rather than guessing, an
[honest residual](./glossary.md#honest-residual). They aren't errors; they're
the things a human might want to look at. The "Why" column shows `—` for
ecosystems where provenance isn't available.

There's nothing to fix here yet. This first look is so the gate's output later
makes sense.

## Step 6 — Run the gate

You generated the documents a moment ago, so the gate should be clean. Run it:

```sh
task check POLICY=.sbomlet.toml
echo "exit code: $?"
```

You want to see `exit code: 0`. That's the gate confirming two things at once:
the committed documents match exactly what the tool would generate right now,
and no dependency tripped a `fail` verdict in your policy.

`check` works differently from `generate`. It regenerates the inventory in
memory and compares it byte-for-byte against the files on disk. It writes
nothing, and it never touches the network; every license it needs comes from the
committed `.sbomlet.cache.json`. That's what lets it run in CI
deterministically.

The exit code tells you which class of thing is wrong, if anything:

| Exit code | Meaning | What to do |
| --------- | ------- | ---------- |
| `0` | Clean — documents match, no violations | Nothing; the gate passes |
| `1` | A dependency tripped a `fail` verdict | Fix the dependency, or add a documented policy override |
| `2` | A committed document is [stale](./glossary.md#staleness) or missing | Re-run `task generate`, review the diff, commit |
| `3+` | Tool or config error — bad flag, invalid policy | Fix the invocation or the policy file |

A `fail` verdict (exit 1) takes precedence over staleness (exit 2), so a real
policy violation can't hide behind an out-of-date document. The code you'll meet
most often is `2`: someone changed a dependency and forgot to regenerate. The
fix is to generate, look at the diff, and commit.

## Step 7 — Pin the outputs to LF (do this on Windows)

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
.sbomlet.cache.json text eol=lf
```

This matters even if you develop on macOS or Linux: a teammate on Windows would
hit the stale gate without it.

## Step 8 — Commit everything

Commit the generated outputs, the policy, and the pins together:

```sh
git add THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md .sbomlet.cache.json
git add .sbomlet.toml .gitattributes
git add tools/sbomlet
git commit -m "docs: add third-party license inventory and CI gate"
```

The `.sbomlet.cache.json` is committed on purpose, because it's what lets
`check` run offline in CI.

## Step 9 — Wire it into CI

The gate is one command, and it works on any CI vendor because it has nothing
vendor-specific. Wherever your pipeline runs checks, add:

```sh
task check POLICY=.sbomlet.toml
```

It passes when the committed inventory is current and your policy is satisfied,
and fails the build otherwise, with the exit code telling you which case it is.
A reviewer who sees the build go red on exit 2 knows someone needs to
regenerate; on exit 1, that a dependency needs attention.

From here on, the routine task is the one you already know: when a dependency
changes, run `task generate POLICY=.sbomlet.toml`, review the diff, and
commit it.

## Where to go next

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
