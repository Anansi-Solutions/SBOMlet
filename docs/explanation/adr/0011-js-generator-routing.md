# ADR-0011: JS generator routing: yarn-plugin for Yarn 4, cdxgen otherwise, a custom bun.lock parser

- **Status:** Accepted
- **Date:** 2026-06-12

## Context and problem

JavaScript is most of what this tool inventories — roughly 95% of the first
consumer's dependencies live behind a JS lockfile. But "a JS lockfile" is not one
thing. The same repo can carry Yarn 4 lockfiles, an older Yarn 3 lockfile, npm,
pnpm, and bun, and each package manager records its dependency tree and its
license data differently. No single generator reads all of them well. The
question was which generator to point at each lockfile, and what to do when none
of the off-the-shelf generators produced a usable answer.

The non-obvious part is licences. A generator that lists every component but
fills in no licences is close to useless here — the whole point is the
attribution document and the policy gate, both of which need the licence, not
just the name. So "handles it best" had to be measured on licence fill rate
against the real repo, not on component counts.

## Decision drivers

- **Licence fill rate, measured on the real lockfiles.** The research flagged
  early that lockfiles carry no licence data and that fill rate per ecosystem had
  to be measured, not assumed, before committing to a toolchain.
- **A generator must not emit a silently empty or partial inventory.** A target
  that scans to zero components is a hard error, never a quiet skip — so a route
  that returns an empty document is a route we cannot take.
- **Minimal dependencies and no new runtime footprint.** External generators run
  pinned through mise and are never added as dependencies of our own code, so
  reaching for one is cheap; writing our own parser is the expensive option and
  has to earn it.
- **Config, not code.** Adding a package manager should ideally be a new row in a
  dispatch table, not a new code path, so the routing stays easy to read and hard
  to get subtly wrong.

## Considered options

1. **One generator for all of JS** — pick cdxgen (the broadest multi-ecosystem
   tool) and run it against every JS lockfile kind.
2. **yarn-plugin for every Yarn target** — use the official CycloneDX Yarn plugin
   wherever a yarn.lock exists, regardless of Yarn version.
3. **Route per lockfile, settled by a spike** — measure the candidates against the
   repo's real lockfiles and send each kind to whichever generator fills licences;
   write our own parser only for the kind nothing handles.

## Decision

We route each lockfile to the generator a head-to-head spike showed fills its
licences, and we wrote one parser of our own only where the spike showed a real
gap. Three routes came out of it.

Yarn 4 targets go to `@cyclonedx/yarn-plugin-cyclonedx`, run through `yarn dlx`.
The plugin reads each package's licence from inside Yarn's own resolution, which
is exactly the data cdxgen misses without network calls: on the real repo the
plugin filled 99.6–99.8% of licences offline where cdxgen filled 0.0%. cdxgen on
a Yarn 4 lockfile emitted a populated component list with empty licence fields —
a document that looks complete and tells you nothing, the failure this tool
exists to prevent. The plugin is the default hypothesis the research recommended,
and the measurement confirmed it.

Everything cdxgen does handle well goes to cdxgen: Yarn 3 lockfiles (the plugin
hard-fails on Yarn below 4), npm, pnpm, and the Python ecosystems. npm is the
happy case here — licences have been embedded in the lockfile since npm 7, so
cdxgen reads them locally and fills near 100%. The routing key is the lockfile's
own content, never the `packageManager` field in `package.json`: a yarn lockfile
declares `__metadata.version`, and version 8 or above means Yarn 4 and the
plugin, anything else means cdxgen. Reading the lockfile rather than a declared
field means a mislabelled or absent pin cannot misroute the scan.

bun is the exception that needed code. A separate spike found no off-the-shelf
generator reads `bun.lock` correctly — cdxgen and syft both emitted zero
components, and the one tool that produced output corrupted 14% of package
identities. With nothing to orchestrate, we wrote a small in-process parser for
`bun.lock` instead. It is the consciously-taken exception to "orchestrate, don't
parse": `bun.lock` is JSONC (JSON with trailing commas), which is a tractable
grammar, not a hand-rolled lexer over an open-ended format, and the parser adds
no runtime dependency — it strips trailing commas and hands the rest to
`JSON.parse`. It emits the same minimal CycloneDX document every other route
feeds into, so the merge downstream cannot tell which generator produced a row.

Comparing on the driver that decided each:

- **One generator for all of JS** fails on licence fill. cdxgen's empty-licence
  output on Yarn 4 was the disqualifying result — broad coverage is worth nothing
  if the licence column is blank. Rejected on fill rate.
- **yarn-plugin everywhere** fails on the Yarn-3 and bun targets the plugin cannot
  read at all (it hard-errors below Yarn 4 and does not speak bun's lockfile).
  Rejected because it leaves real targets uncovered.
- **Route per lockfile** sends each kind where it fills, keeps the common cases as
  dispatch-table rows with no new code, and confines hand-written parsing to the
  single format that left us no alternative.

## Consequences

- **Good:** every JS lockfile kind in the repo is covered, and Yarn 4 targets —
  the bulk of the dependencies — carry real licences offline, with no network
  enrichment needed for them. The router is a pure function of lockfile content,
  so adding npm and pnpm was a config change with no diff to the cdxgen adapter.
  Choosing the generator from the lockfile, not a declared field, makes
  misrouting from a wrong `packageManager` pin impossible.
- **Bad / cost:** we own a `bun.lock` parser. It is small and the format is
  stable, but bun could change its lockfile and we would have to follow; the
  parser's output is pinned by a committed exact-purl expectation so a silent
  drift fails the test suite rather than the inventory. pnpm and bun targets fill
  0% of licences at this stage and render their rows as `unknown` — the same
  accepted posture as Python, left to the later enrichment phase.
- **Neutral:** a directory holding more than one JS lockfile collapses to a single
  target by a fixed precedence (bun, then pnpm, yarn, npm), warning and naming
  every lockfile it ignored, so two generators never scan the same code twice. The
  adapters are pluggable behind one dispatch seam, so swapping a generator later —
  if, say, cdxgen gains offline Yarn 4 licences — is a routing change, not a
  rewrite.

## See also

- Research: `.planning/research/SUMMARY.md` (Conflict B), `.planning/research/STACK.md`
- Plan summaries: `.planning/phases/02-multi-target-collectors-js-python/02-05-SUMMARY.md`,
  `.planning/phases/04.5-js-package-manager-coverage-npm-pnpm-bun-inserted/04.5-02-SUMMARY.md`
- Code: `collectors/dispatch.ts` (`selectJsGenerator`),
  `scanners/yarnPlugin.ts`, `scanners/cdxgen.ts`, `scanners/bunLock.ts`
