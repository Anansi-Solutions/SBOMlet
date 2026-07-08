# ADR-0020: Yarn workspace scan units from lockfile resolutions

- **Status:** Accepted
- **Date:** 2026-07-06

## Context and problem

A Yarn 4 monorepo keeps one `yarn.lock` at the root, shared by every
workspace, so the tool scanned the whole repository as a single unit from the
root. Scanned that way, the production half of the scan sees only the root
package's own dependencies, and every workspace dependency comes out marked
development-only. The policy is lenient with development dependencies, so a
shipped dependency could pass a license gate it should have failed.

The fix is to scan each workspace on its own. This record settles one
question: where the list of workspaces comes from.

## Decision drivers

- The report must not silently understate what ships (ADR-0007).
- Don't re-parse what Yarn has already resolved (ADR-0015).
- The pipeline already handles several scan targets; give it more targets
  rather than change it.

## Considered options

1. **Read the `workspaces` globs in `package.json`** — means re-implementing
   Yarn's glob matching (`*`, `**`, object form, negations).
2. **List workspaces while discovering scan targets** — discovery is a plain
   directory walk that reads no file contents; this would change its contract.
3. **Read the lockfile — chosen.** `yarn.lock` already names every workspace
   as a plain path (`resolution: "<name>@workspace:<path>"`), globs expanded,
   in a file the tool already reads.

## Decision

The list of workspaces comes from the `resolution:` lines of the root
`yarn.lock`. Each workspace is then scanned as its own target: its own
directory, its own name in the report (`<target>/<workspace-path>`), the
root lockfile shared. Reading `package.json` was rejected because Yarn has
already expanded its globs into the lockfile; listing during discovery was
rejected because discovery deliberately reads no file contents (the boundary
ADR-0010 draws).

Two guards keep the change contained. A lockfile that names only the root
workspace is scanned exactly as before, so repositories without workspaces
are untouched. And since a lockfile is untrusted input, every workspace path
is resolved and must land inside the repository — one that points outside is
rejected (ADR-0015's posture).

## Consequences

- **Good:** every workspace's dependencies are classified correctly and
  attributed to that workspace. No downstream code changed.
- **Bad / cost:** a monorepo with N workspaces runs 2(N+1) scans instead
  of 2 (each directory is scanned twice: with and without development
  dependencies). Workspace counts are small in practice, so the cost stays
  minor.
- **Neutral:** repositories without workspaces produce byte-identical output.

## See also

- [ADR-0010](0010-js-generator-routing.md) — the Yarn scan this extends;
  routing itself is unchanged
- [ADR-0009](0009-dev-prod-os-scopes.md) — the production/development split
  each workspace now gets on its own
- [ADR-0015](0015-abstain-over-fragile-parsing.md) — trust the resolved
  structural signal; contain untrusted paths
- Code: `src/pipeline/targets.ts` (`expandYarnWorkspaceUnits`,
  `scanWorkspaceUnits`), `src/targets/firstParty.ts`
  (`yarnWorkspaceMembers`)
