# ADR-0010: JS generator routing — yarn-plugin for Yarn 4, cdxgen otherwise, a custom bun.lock parser

- **Status:** Accepted
- **Date:** 2026-06-12

## Context and problem

JavaScript is most of what the tool inventories — roughly 95% of the first
consumer's dependencies sit behind a JS lockfile. But "a JS lockfile" is several
things: Yarn 4, an older Yarn 3 lockfile, npm, pnpm, bun. Each package manager
records its tree and licence data differently, and no single generator reads all
of them well, so the question was which generator to point at each, and what to
do when none produced a usable answer.

The measure is licences, not components: a generator that lists every component
but fills no licences is no use here, so "handles it best" is measured on licence
fill rate against the real repo, not component counts.

## Decision drivers

- **Licence fill rate, measured on the real lockfiles.** Lockfiles carry no licence
  data, and fill rate per ecosystem had to be measured before committing to a
  toolchain.
- **No silently empty inventory.** A target that scans to zero components is a hard
  error, not a quiet skip.
- **Minimal dependencies.** External generators run pinned through mise and add no
  runtime footprint; writing our own parser is the expensive option and has to earn
  it.
- **Config, not code.** Adding a package manager should be a new row in a dispatch
  table, not a new code path.

## Considered options

1. **One generator for all of JS** — cdxgen against every JS lockfile kind.
2. **yarn-plugin for every Yarn target** — the official plugin wherever a yarn.lock
   exists, regardless of version.
3. **Route per lockfile, settled by a spike** — measure the candidates against the
   repo's real lockfiles and send each kind to whichever generator fills licences;
   write our own parser only where nothing works.

## Decision

We route each lockfile to the generator a head-to-head spike showed fills its
licences, and wrote one parser of our own only where the spike found a real gap.
Yarn 4 targets go to `@cyclonedx/yarn-plugin-cyclonedx` (via `yarn dlx`), which
reads each licence from inside Yarn's own resolution: on the real repo it filled
99.6–99.8% of licences offline where cdxgen filled 0.0%. Everything cdxgen
handles well goes to cdxgen — Yarn 3 (the plugin hard-fails below Yarn 4), npm,
pnpm, and Python; npm is the happy case, with licences in the lockfile since npm
7. The routing key is the lockfile's own content, never the `packageManager`
field in `package.json`, so a mislabelled or absent pin cannot misroute the scan.

bun needed code: a separate spike found no off-the-shelf generator reads
`bun.lock` correctly — cdxgen and syft both emitted zero components, and the one
tool that produced output corrupted 14% of package identities. With nothing to
orchestrate, we wrote a small in-process parser, the deliberate exception to
"orchestrate, don't parse" (ADR-0002) — `bun.lock` is JSONC, a tractable grammar
that just strips trailing commas before `JSON.parse`.

One generator for all of JS fails on fill (cdxgen's empty Yarn 4 output is
disqualifying); yarn-plugin everywhere fails on the Yarn 3 and bun targets it
cannot read. Routing per lockfile sends each kind where it fills and confines
hand-written parsing to the one format with no alternative.

## Consequences

- **Good:** every JS lockfile kind in the repo is covered, and Yarn 4 targets carry
  real licences offline. The router is a pure function of lockfile content, so
  adding npm and pnpm was a config change with no diff to the cdxgen adapter.
- **Bad / cost:** we own a `bun.lock` parser; bun could change its lockfile and we
  would follow, but the output is pinned by a committed exact-purl expectation, so
  a silent drift fails the tests, not the inventory. pnpm and bun fill 0% of
  licences at this stage and render as `unknown`, left to enrichment.
- **Neutral:** a directory with more than one JS lockfile collapses to one target
  by a fixed precedence (bun, pnpm, yarn, npm), warning and naming every lockfile
  it ignored.

## See also

- Related: [ADR-0002](0002-orchestrate-standard-generators.md) (orchestrate, don't
  parse — bun is the earned exception)
- Code: `collectors/dispatch.ts` (`selectJsGenerator`), `scanners/yarnPlugin.ts`,
  `scanners/cdxgen.ts`, `scanners/bunLock.ts`
