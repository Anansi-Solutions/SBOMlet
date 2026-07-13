/**
 * Target resolution and the per-target collect loop: dispatches through the
 * collector registry, owning the "collecting X via Y" stderr line via the
 * caller-provided log sink (collectors never write stderr themselves).
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

import { assertBunLockSize } from "../collectors/bunLock";
import { manifestFilesFor, selectJsGenerator } from "../collectors/dispatch";
import { assertNugetLockSize } from "../collectors/nugetLock";
import { collectors } from "../collectors/registry";
import { compareCodeUnits } from "../model/dependencies";
import { type CollectedSbom } from "../merge/merge";
import {
  discoverTargets,
  discoverTargetsWithWarnings,
  lockfileNameFor,
  type DiscoveredTarget,
} from "../targets/discover";
import { yarnWorkspaceMembers } from "../targets/firstParty";
import { resolveTarget } from "../targets/target";
import {
  classifyCoverage,
  componentCountOf,
  coverageSkipReason,
} from "./coverage";
import { resolveFrom } from "./paths";
import { type GenerateOptions } from "./pipeline";

/**
 * Generator wall-clock budget PER SCAN (cold plugin runs hit ~70s on large
 * targets; the first cdxgen run downloads the generator once). Deliberately
 * no all-targets timeout — a full cold discovery run may take minutes.
 */
const DEFAULT_TIMEOUT_MS = 300000;

/**
 * Resolve the list of targets to scan. Single-target mode wraps the
 * resolved target as a yarn-lockfile DiscoveredTarget so it flows through
 * the exact same dispatch loop as discovery mode.
 */
function resolveTargets(opts: GenerateOptions): DiscoveredTarget[] {
  if (opts.targetArg !== undefined) {
    return [
      {
        ...resolveTarget(resolveFrom(opts.baseDir, opts.targetArg)),
        lockfile: "yarn",
      },
    ];
  }
  const root = resolveFrom(opts.baseDir, opts.repoRoot ?? ".");
  // This module lives in src/pipeline/, so two levels up is the tool's own
  // directory — excluded from the walk with zero hardcoded paths.
  const toolDir = join(import.meta.dir, "..", "..");
  const { targets: discovered, warnings } = discoverTargetsWithWarnings(root, {
    toolDir,
    excludes: opts.excludes,
    // Warning-format detail only (the aggregated csproj-no-lock warning
    // expands to per-directory lines under --verbose) — never the target set.
    verbose: opts.verbose,
  });
  // Discovery warnings print here, before the scan loop — discover stays pure
  // and returns them as data; the CLI owns stderr.
  for (const warning of warnings) {
    process.stderr.write(`warning: ${warning}\n`);
  }
  if (discovered.length === 0) {
    // Distinguish a wrong --repo-root (no lockfiles anywhere — likely a
    // typo'd path) from an intentional full exclusion (a legitimate, loud
    // empty inventory: every exclusion is visible on the command line).
    const unfiltered =
      opts.excludes !== undefined && opts.excludes.length > 0
        ? discoverTargets(root, { toolDir })
        : [];
    if (unfiltered.length === 0) {
      throw new Error(
        `--repo-root "${opts.repoRoot ?? "."}" contains no lockfile targets: searched ${root}`,
      );
    }
  }
  return discovered;
}

/**
 * The per-target collect result: the merge inputs plus every target directory
 * that actually contributed one (compareCodeUnits-sorted, deduped) — the same
 * dirs the collectors ran in. {@link IntensiveOptions.targetDirs} (generate
 * --intensive) is built from this so the residual ScanCode lane
 * probes exactly the source trees this run already walked, never a
 * freshly-discovered set that could drift from what was actually collected.
 */
export interface CollectResult {
  inputs: CollectedSbom[];
  /** compareCodeUnits-sorted, deduped absolute target directories. */
  targetDirs: string[];
}

/**
 * A yarn workspace scan unit: a DiscoveredTarget carrying the two
 * lockfileDir/workspacePath fields, always set together. The root member
 * (".") in the lock reuses the ORIGINAL target unchanged — it keeps identity
 * "." and carries neither field — only non-"." members
 * become a distinct unit.
 */
type WorkspaceScanUnit = DiscoveredTarget;

/**
 * A scan unit paired with the hasDependencies flag OF THE EXACT LOCK ENTRY
 * that produced it, captured at construction time. Never re-derive this by
 * looking the unit's workspacePath back up in a relPath-keyed Map: two lock
 * entries can legally declare the SAME relPath under different member names
 * (a malformed/hand-edited lock, or two historical package renames left
 * stale) — a lookup Map collapses to one (last-wins) entry and would then
 * apply the WRONG entry's flag to an EARLIER unit sharing that path,
 * silently skipping a workspace that actually declares dependencies.
 */
interface ExpandedUnit {
  unit: WorkspaceScanUnit;
  hasDependencies: boolean;
}

/**
 * Lexical containment predicate for a lock-declared workspace member path:
 * true when the path escapes the workspace root. The fourth disjunct
 * mirrors the realpath branch's third: on win32 a cross-drive lock path
 * ("C:/evil" scanned from another drive) or a drive-relative one ("C:evil")
 * slips past the first three — resolve() normalizes separators so the
 * string-equality absolute check misses, and relative() across roots
 * returns an ABSOLUTE path, never a ".."-prefixed one. An absolute
 * relative() result is by definition outside target.dir, on any platform.
 */
function escapesWorkspaceRoot(relPath: string, relFromRoot: string): boolean {
  return (
    resolve(relPath) === relPath ||
    relFromRoot === ".." ||
    relFromRoot.startsWith(".." + sep) ||
    resolve(relFromRoot) === relFromRoot
  );
}

/**
 * Enumerate a yarn-plugin-routed target's workspace members into scan units,
 * or return undefined when expansion does not apply — never invents a unit
 * the lock does not declare (comment at the call site names the exact
 * gate). Containment is enforced HERE, before any unit is returned: a
 * `@workspace:` relPath that resolves outside target.dir (traversal or an
 * absolute path) throws immediately, naming the offending identity and path
 * — a tampered lockfile can never move a subprocess cwd outside the scanned
 * repo and can never silently hide a workspace.
 */
function expandYarnWorkspaceUnits(
  target: DiscoveredTarget,
  lockfileText: string,
): ExpandedUnit[] | undefined {
  if (
    target.lockfile !== "yarn" ||
    selectJsGenerator(lockfileText) !== "yarn-plugin"
  ) {
    return undefined;
  }
  const members = yarnWorkspaceMembers(lockfileText);
  const hasRoot = members.some((member) => member.relPath === ".");
  const hasNonRoot = members.some((member) => member.relPath !== ".");
  // Belt-and-braces fallback: a Berry lock always carries the root workspace
  // entry, so a lock without one is not trustworthy expansion input — take
  // today's single-scan path rather than invent units from a shape the lock
  // never declared.
  if (!hasRoot || !hasNonRoot) {
    return undefined;
  }

  const targetRoot = resolve(target.dir);
  const units: ExpandedUnit[] = [];
  for (const member of members) {
    if (member.relPath === ".") {
      units.push({ unit: target, hasDependencies: member.hasDependencies });
      continue;
    }
    const memberDir = resolve(target.dir, member.relPath);
    const relFromRoot = relative(targetRoot, memberDir);
    // Containment: neither absolute nor a traversal outside target.dir.
    if (escapesWorkspaceRoot(member.relPath, relFromRoot)) {
      throw new Error(
        `target "${target.identity}/${member.relPath}" escapes the workspace root — refusing to scan ${memberDir}`,
      );
    }
    // Real-filesystem containment (symlink escape): a lock-declared
    // relPath can be lexically fine yet point, via a symlink, at a
    // directory outside the repo. Only checked when the member directory
    // already exists — a missing directory is not this check's job
    // (assertManifestsExist fails loud on that separately, after
    // expansion).
    if (existsSync(memberDir)) {
      const realMemberDir = realpathSync(memberDir);
      const realTargetRoot = realpathSync(targetRoot);
      const realRelFromRoot = relative(realTargetRoot, realMemberDir);
      if (
        realRelFromRoot === ".." ||
        realRelFromRoot.startsWith(".." + sep) ||
        resolve(realRelFromRoot) === realRelFromRoot
      ) {
        throw new Error(
          `target "${target.identity}/${member.relPath}" escapes the workspace root via a symlink — refusing to scan ${memberDir} (resolves to ${realMemberDir})`,
        );
      }
    }
    units.push({
      unit: {
        ...target,
        dir: memberDir,
        identity:
          target.identity === "."
            ? member.relPath
            : `${target.identity}/${member.relPath}`,
        lockfileDir: target.dir,
        workspacePath: member.relPath,
      },
      hasDependencies: member.hasDependencies,
    });
  }
  return units.sort((a, b) =>
    compareCodeUnits(a.unit.identity, b.unit.identity),
  );
}

/**
 * Dispatch one target/unit through the collector registry and apply the
 * coverage policy — shared by the non-expanded per-target path and every
 * expanded workspace unit, so the two can never drift apart. `rootLockfileText`
 * is the text the collector receives via ctx.lockfileText: for a workspace
 * unit this is the governing ROOT lock (yarn's cross-workspace-dep filter,
 * firstPartyNames, reads the root lock, never the unit's own directory,
 * which has no yarn.lock of its own). Returns undefined for a
 * coverage-skip verdict (never pushed into the merge); throws on a
 * scannable-but-zero-component result (the coverage hard-fail).
 */
async function dispatchAndCollect(
  target: DiscoveredTarget,
  rootLockfileText: string,
  lockfileName: string,
  opts: GenerateOptions,
  log: (line: string) => void,
): Promise<CollectedSbom | undefined> {
  // Registry dispatch: the map is exhaustive over LockfileKind; the guard is
  // belt-and-braces, routing an unregistered kind to the tool-error exit
  // path.
  const collector = collectors.get(target.lockfile);
  if (collector === undefined) {
    throw new Error(
      `no collector is registered for lockfile kind "${target.lockfile}"`,
    );
  }
  // The CLI owns stderr: the collecting line is emitted HERE, never inside
  // a collector, with the identity the registration reports for this
  // lockfile text (yarn's generator choice is content-dependent).
  const tool = collector.tool(rootLockfileText);
  log(`collecting ${target.identity} via ${tool.name}@${tool.version}`);
  const input = await collector.collect(target, {
    lockfileText: rootLockfileText,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    verbose: opts.verbose,
    log,
  });

  // Coverage enforcement point: the verdict is authoritative — a
  // "skip"-classified target is never pushed into the merge, so this gate
  // and the pre-scan warn+skip can never drift apart (both delegate to
  // coverageSkipReason). The hard branch — a scannable lockfile whose scan
  // produced zero components — throws and aborts the run (exit 3 via the
  // CLI's fail path).
  const verdict = classifyCoverage(
    target.identity,
    lockfileName,
    rootLockfileText,
    componentCountOf(input.sbom),
    target.dir,
  );
  if (verdict === "skip") return undefined;
  return input;
}
/**
 * Fail fast on a missing manifest: discovery requires only the lockfile to
 * exist, so a vendored/fixture lockfile without its manifest (poetry.lock
 * sans pyproject.toml, yarn.lock sans package.json) would otherwise burn
 * the full scan budget before the adapters' own computeCacheKey check
 * throws. Same error shape as computeCacheKey; this cheap pre-check just
 * runs first, before any subprocess. `files` is the set to check relative
 * to `dir` — the non-expanded path checks both lockfile+manifest at
 * target.dir; a workspace unit checks only package.json at its own dir (the
 * root yarn.lock's existence was already proven by the read at the root).
 */
function assertManifestsExist(
  identity: string,
  dir: string,
  files: readonly string[],
): void {
  for (const file of files) {
    const manifestPath = join(dir, file);
    if (!existsSync(manifestPath)) {
      throw new Error(
        `target "${identity}" is missing ${file}: expected ${manifestPath}`,
      );
    }
  }
}

/**
 * Scan every expanded workspace unit in sorted order: the whole-target
 * coverage pre-check on the ROOT lock first (the expanded-path twin of the
 * non-expanded pre-scan warn+skip branch), then per-unit zero-dep skip
 * (keyed on each unit's OWN captured hasDependencies flag from expansion
 * time, covering the dep-less root unit too), the re-routed manifest
 * pre-check (only the unit's own package.json; the root yarn.lock was
 * already proven to exist by the caller's read), then the shared
 * dispatch+coverage path with the ROOT lock text.
 */
async function scanWorkspaceUnits(
  target: DiscoveredTarget,
  expandedUnits: readonly ExpandedUnit[],
  rootLockfileText: string,
  lockfileName: string,
  opts: GenerateOptions,
  log: (line: string) => void,
): Promise<CollectedSbom[]> {
  // Every unit's coverage verdict is decided by the SAME root lock text
  // dispatchAndCollect classifies after the scan, so a skip-classified
  // lock (e.g. all entries workspace:-protocol — a monorepo whose
  // workspaces depend only on each other) is known before any unit runs:
  // warn ONCE, loudly, and never burn a generator spawn on a verdict that
  // is already decided. Without this, the post-scan "skip" branch would be
  // the only SILENT skip in the collect loop, reached after both plugin
  // runs were spawned per unit.
  const skipReason = coverageSkipReason(
    lockfileName,
    rootLockfileText,
    target.dir,
  );
  if (skipReason !== undefined) {
    log(`warning: skipping ${target.identity} — ${skipReason}`);
    return [];
  }
  const results: CollectedSbom[] = [];
  for (const { unit, hasDependencies } of expandedUnits) {
    if (!hasDependencies) {
      // Loud, never silent — covers the dep-less root unit as well as any
      // dep-less workspace.
      log(
        `warning: skipping ${unit.identity} — workspace declares no dependencies in yarn.lock`,
      );
      continue;
    }
    assertManifestsExist(unit.identity, unit.dir, ["package.json"]);
    const input = await dispatchAndCollect(
      unit,
      rootLockfileText,
      lockfileName,
      opts,
      log,
    );
    if (input !== undefined) results.push(input);
  }
  return results;
}

/**
 * Fold a batch of expanded workspace inputs into the running collect-loop
 * accumulators: pushes each input and adds its unit's OWN dir (never the
 * root dir) — extracted so the caller's for-loop stays within max-depth 3.
 */
function absorbUnitInputs(
  unitInputs: readonly CollectedSbom[],
  expandedUnits: readonly ExpandedUnit[],
  inputs: CollectedSbom[],
  dirs: Set<string>,
): void {
  const dirByIdentity = new Map(
    expandedUnits.map(({ unit }) => [unit.identity, unit.dir]),
  );
  for (const input of unitInputs) {
    inputs.push(input);
    const unitDir = dirByIdentity.get(input.targetIdentity);
    if (unitDir !== undefined) dirs.add(unitDir);
  }
}
/**
 * The per-target collect loop: resolve targets, dispatch each through the
 * collector registry, and apply the coverage policy. The loop owns the
 * "collecting"/"skipping" stderr lines, routed through the caller-provided log
 * sink, so the fixed line shapes are emitted from one place.

 *
 * A yarn-plugin-routed target whose lock declares workspace members expands
 * into one scan unit per member: the non-expanded path below is the exact
 * body shared verbatim by every other lockfile kind and by a
 * single-workspace (`@workspace:.`-only) yarn-plugin lock, which never
 * triggers expansion (structural no-op).
 */
export async function collectTargets(
  opts: GenerateOptions,
  log: (line: string) => void,
): Promise<CollectResult> {
  const targets = resolveTargets(opts);
  const inputs: CollectedSbom[] = [];
  const dirs = new Set<string>();

  // Sequential scan in sorted (identity, kind) order — discoverTargets
  // already sorts; single-target mode is a one-element list.
  for (const target of targets) {
    const lockfileName = lockfileNameFor(target.lockfile);
    const lockfilePath = join(target.dir, lockfileName);
    // The lockfile DoS bounds must hold at every entry point that reads the
    // file: this loop reads the full text for the coverage counter before an
    // in-process collector's own in-module gate could ever fire, so the
    // shared stat gates run here first — before any read or parse.
    if (target.lockfile === "bun") {
      assertBunLockSize(lockfilePath);
    }
    if (target.lockfile === "nuget") {
      assertNugetLockSize(lockfilePath);
    }
    // Read once; reused for the empty-check, generator dispatch, expansion,
    // and the first-party member set.
    const lockfileText = readFileSync(lockfilePath, "utf8");

    const expandedUnits = expandYarnWorkspaceUnits(target, lockfileText);
    if (expandedUnits !== undefined) {
      const unitInputs = await scanWorkspaceUnits(
        target,
        expandedUnits,
        lockfileText,
        lockfileName,
        opts,
        log,
      );
      absorbUnitInputs(unitInputs, expandedUnits, inputs, dirs);
      continue;
    }

    const skipReason = coverageSkipReason(
      lockfileName,
      lockfileText,
      target.dir,
    );
    if (skipReason !== undefined) {
      // Loud, never silent: the skip names the target and the reason. Skipping
      // before dispatch also means a zero-dependency Yarn-4 workspace never
      // spawns a generator at all.
      log(`warning: skipping ${target.identity} — ${skipReason}`);
      continue;
    }

    assertManifestsExist(
      target.identity,
      target.dir,
      manifestFilesFor(target.lockfile),
    );

    const input = await dispatchAndCollect(
      target,
      lockfileText,
      lockfileName,
      opts,
      log,
    );
    if (input === undefined) continue;
    inputs.push(input);
    dirs.add(target.dir);
  }

  return {
    inputs,
    targetDirs: [...dirs].sort(compareCodeUnits),
  };
}
