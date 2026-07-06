/**
 * Target resolution and the per-target collect loop: dispatches through the
 * collector registry, owning the "collecting X via Y" stderr line via the
 * caller-provided log sink (collectors never write stderr themselves).
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { assertBunLockSize } from "../collectors/bunLock";
import { manifestFilesFor } from "../collectors/dispatch";
import { collectors } from "../collectors/registry";
import { compareCodeUnits } from "../model/dependencies";
import { type CollectedSbom } from "../merge/merge";
import {
  discoverTargets,
  discoverTargetsWithWarnings,
  lockfileNameFor,
  type DiscoveredTarget,
} from "../targets/discover";
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
 * dirs the collectors ran in. {@link IntensiveOptions.targetDirs} (10-05,
 * generate --intensive) is built from this so the residual ScanCode lane
 * probes exactly the source trees this run already walked, never a
 * freshly-discovered set that could drift from what was actually collected.
 */
export interface CollectResult {
  inputs: CollectedSbom[];
  /** compareCodeUnits-sorted, deduped absolute target directories. */
  targetDirs: string[];
}

/**
 * The per-target collect loop: resolve targets, dispatch each through the
 * collector registry, and apply the coverage policy. The loop owns the
 * "collecting"/"skipping" stderr lines, routed through the caller-provided log
 * sink, so the locked line shapes are emitted from one place.
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
    // The bun.lock DoS bound must hold at every entry point that reads the
    // file: this loop reads the full text for the coverage counter before the
    // bun collector's own in-module gate could ever fire, so the shared stat
    // gate runs here first — before any read or parse.
    if (target.lockfile === "bun") {
      assertBunLockSize(lockfilePath);
    }
    // Read once; reused for the empty-check, generator dispatch, and the
    // first-party member set.
    const lockfileText = readFileSync(lockfilePath, "utf8");

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

    // Fail fast on a missing manifest: discovery requires only the lockfile to
    // exist, so a vendored/fixture lockfile without its manifest (poetry.lock
    // sans pyproject.toml, yarn.lock sans package.json) would otherwise burn
    // the full scan budget before the adapters' own computeCacheKey check
    // throws. Same error shape as computeCacheKey; this cheap pre-check just
    // runs first, before any subprocess.
    for (const file of manifestFilesFor(target.lockfile)) {
      const manifestPath = join(target.dir, file);
      if (!existsSync(manifestPath)) {
        throw new Error(
          `target "${target.identity}" is missing ${file}: expected ${manifestPath}`,
        );
      }
    }

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
    const tool = collector.tool(lockfileText);
    log(`collecting ${target.identity} via ${tool.name}@${tool.version}`);
    const input = await collector.collect(target, {
      lockfileText,
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
      lockfileText,
      componentCountOf(input.sbom),
      target.dir,
    );
    if (verdict === "skip") continue;
    inputs.push(input);
    dirs.add(target.dir);
  }

  return {
    inputs,
    targetDirs: [...dirs].sort(compareCodeUnits),
  };
}
