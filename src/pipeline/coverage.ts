/**
 * The coverage policy: the one place that decides a lockfile has nothing to
 * inventory — a silent incomplete inventory is the failure mode this tool
 * exists to prevent, so anything else either scans or fails loudly.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type } from "arktype";

import { bunThirdPartyEntryCount } from "../collectors/bunLock";
import { isLockfileEmpty } from "../collectors/dispatch";
import {
  absentModulesJsonShouldFail,
  assertTerraformLockSize,
  modulesJsonIsPresentFile,
  terraformComponentCount,
} from "../collectors/terraform";
import {
  npmThirdPartyEntryCount,
  nugetThirdPartyEntryCount,
  pnpmThirdPartyEntryCount,
  pythonThirdPartyEntryCount,
  thirdPartyEntryCount,
} from "../targets/firstParty";
import { SbomDocument } from "../validate/sbom";

/**
 * Terraform skip arm. The init-has-run gate is a FILESYSTEM signal:
 * modules.json presence-as-a-regular-file + the
 * `.terraform/providers/`+`.terraform/modules/` artifact shape decide, with no
 * HCL parsing. It mirrors the collector EXACTLY via the shared
 * {@link absentModulesJsonShouldFail} / {@link modulesJsonIsPresentFile} verbs so
 * the two cannot diverge.
 * - modules.json ABSENT (or directory-named) and the shape is not the
 *   exact providers-only artifact set → undefined: route to the collect path so
 *   the collector's loud "run tofu init/tofu get first" throw fires. NEVER a
 *   skip-to-zero — a silent incomplete inventory is exactly the failure this tool
 *   prevents.
 * - modules.json ABSENT and the providers-only shape holds (`.terraform/providers/`
 *   present, `.terraform/modules/` absent) → init ran with no module calls.
 *   Mirror the collector: route to scan; if the lock yields zero providers too,
 *   skip with a reason (a providers-empty dir is a legitimate no-op, not a loud
 *   failure).
 * - PRESENT (regular file): the size gate fires BEFORE the read. Then
 *   terraformComponentCount === 0 (zero-provider lock with a local-only
 *   modules.json) → skip with a reason; a positive count → undefined: scan.
 */
function terraformSkipReason(
  lockfileName: string,
  lockfileText: string,
  lockfileDir: string | undefined,
): string | undefined {
  if (lockfileDir === undefined) return undefined;
  const modulesJsonPath = join(
    lockfileDir,
    ".terraform",
    "modules",
    "modules.json",
  );
  // The PRESENCE check requires a REGULAR FILE: a
  // directory-named modules.json is treated as ABSENT, routing to the
  // filesystem-signal gate (which fails loud) instead of a raw EISDIR read.
  // Mirrors the collector via the shared {@link modulesJsonIsPresentFile} verb.
  if (!modulesJsonIsPresentFile(modulesJsonPath)) {
    // Mirror the collector's filesystem-signal gate. No real init artifact →
    // route to the loud-fail collect path. The gate returns
    // false only for the providers-only shape (`.terraform/providers/` present,
    // `.terraform/modules/` absent): scan it. A providers-empty such dir scans
    // to zero — skip-classify it rather than hard-fail, the same as the
    // present-but-empty modules.json case below.
    if (absentModulesJsonShouldFail(lockfileDir)) return undefined;
    if (terraformComponentCount(lockfileText, "") === 0) {
      return `${lockfileName} has no providers and no external modules`;
    }
    return undefined;
  }
  // Size gate FIRST — before the read, mirroring the
  // collector at terraform.ts and the bun.lock precedent so the "size gate fires
  // before any read, both files, every entry point" invariant is exact.
  assertTerraformLockSize(modulesJsonPath);
  const modulesJsonText = readFileSync(modulesJsonPath, "utf8");
  if (terraformComponentCount(lockfileText, modulesJsonText) === 0) {
    return `${lockfileName} has no providers and no external modules`;
  }
  return undefined;
}

/**
 * Skip classification of the coverage policy, pure and shared: the one place
 * that decides a lockfile has nothing to inventory. Both the loop's pre-scan
 * warn+skip branch and classifyCoverage delegate here, so the two checks can
 * never drift apart.
 *
 * - empty/whitespace-only lockfile → skip;
 * - yarn lockfile whose only entries are workspace:/portal: members (the
 *   legitimate zero-dependency Yarn-4 workspace: `__metadata:` plus the
 *   project's own self-entry) → skip — its scan yields zero components[],
 *   which must not hard-fail the run;
 * - poetry/uv lockfile with zero third-party [[package]] tables: a
 *   dependency-free poetry project still has a non-empty poetry.lock
 *   (metadata block, no packages) and a dependency-free uv project's uv.lock
 *   carries only the project's own local self entry — both scan to zero
 *   components and must take the same loud warn+skip branch, never hard-fail
 *   the whole run. A python lockfile with third-party entries that scans to
 *   zero components still hard-fails (classifyCoverage);
 * - npm/pnpm/bun lockfiles with a positively-determined zero third-party
 *   count: package-lock.json whose packages map holds only the
 *   root/workspace-link entries, an importers-only pnpm-lock.yaml, a bun.lock
 *   whose packages are all @workspace: members. The npm and bun counters
 *   return undefined for v1/garbage text (unknown count) — the strict `=== 0`
 *   comparison below lets undefined fall through, so unknown routes to the
 *   scan and a zero-component result hard-fails loudly, never a silent skip;
 * - nuget: a packages.lock.json whose every dependency section is empty or
 *   holds only type=Project entries (first-party project references) counts a
 *   positively-determined zero → warn+skip. The counter returns undefined for
 *   garbage/failed-narrow/no-dependencies-map text — the same strict `=== 0`
 *   fall-through, so an unreadable lock routes to the scan where the
 *   collector's loud parse throw or the zero-component hard-fail fires.
 *
 * - terraform: a `.terraform.lock.hcl` whose sibling
 *   `.terraform/modules/modules.json` is ABSENT AND whose `<dir>/.terraform/`
 *   directory is also ABSENT (init never ran) is NOT skip-classified and NOT a
 *   zero — it routes to the collect path (returns undefined) so the collector's
 *   loud "run tofu init/tofu get first" throw fires. When `<dir>/.terraform/`
 *   exists (init ran, providers-only) it is scanned. With modules.json present,
 *   terraformComponentCount(lock, modules) === 0 (a zero-provider lock with a
 *   local-only modules.json) → skip; a positive count → scan. (Routing the
 *   never-init'd case to a skip-to-zero would be the exact
 *   silent-incomplete-inventory failure this tool prevents.)
 *
 * Returns the human-readable reason for the warning line, or undefined when
 * the target must be scanned. lockfileDir is required for the terraform arm
 * (its init-has-run gate is a filesystem fact, not lockfile text); the
 * text-only kinds ignore it.
 */
export function coverageSkipReason(
  lockfileName: string,
  lockfileText: string,
  lockfileDir?: string,
): string | undefined {
  if (isLockfileEmpty(lockfileText)) {
    return `${lockfileName} is empty (whitespace only)`;
  }
  if (lockfileName === ".terraform.lock.hcl") {
    return terraformSkipReason(lockfileName, lockfileText, lockfileDir);
  }
  // Strict === 0 on a number|undefined counter: undefined (v1/garbage —
  // unknown count) falls through to the scan, where the collector's loud
  // throw or the zero-component hard-fail fires.
  const arm = ZERO_THIRD_PARTY_ARMS.get(lockfileName);
  if (arm !== undefined && arm.count(lockfileText) === 0) {
    return `${lockfileName} has no third-party entries (${arm.reason})`;
  }
  return undefined;
}

/**
 * The text-only zero-third-party arms of {@link coverageSkipReason}: one
 * counter and one positively-determined-zero reason per lockfile kind. The
 * counters that return number|undefined (npm/bun/nuget) keep the strict
 * `=== 0` fall-through above — undefined (unknown) is never a skip.
 */
const ZERO_THIRD_PARTY_ARMS = new Map<
  string,
  { count: (lockfileText: string) => number | undefined; reason: string }
>([
  [
    "yarn.lock",
    { count: thirdPartyEntryCount, reason: "only workspace/portal members" },
  ],
  [
    "poetry.lock",
    {
      count: pythonThirdPartyEntryCount,
      reason: "no [[package]] tables, or only the project's own local entries",
    },
  ],
  [
    "uv.lock",
    {
      count: pythonThirdPartyEntryCount,
      reason: "no [[package]] tables, or only the project's own local entries",
    },
  ],
  [
    "package-lock.json",
    {
      count: npmThirdPartyEntryCount,
      reason: "only the project root / workspace links",
    },
  ],
  [
    "pnpm-lock.yaml",
    {
      count: pnpmThirdPartyEntryCount,
      reason: "importers only — no packages section",
    },
  ],
  [
    "bun.lock",
    { count: bunThirdPartyEntryCount, reason: "only @workspace: members" },
  ],
  [
    "packages.lock.json",
    {
      count: nugetThirdPartyEntryCount,
      reason: "only Project entries, or empty dependency sections",
    },
  ],
]);

/**
 * The coverage policy, pure and unit-testable:
 * - skip-classified lockfile (see coverageSkipReason) → "skip" (the CLI
 *   warns loudly first);
 * - otherwise, a scan that produced zero components → throw (a silent
 *   incomplete inventory is the failure mode this tool exists to prevent);
 * - otherwise → "include".
 */
export function classifyCoverage(
  identity: string,
  lockfileName: string,
  lockfileText: string,
  componentCount: number,
  lockfileDir?: string,
): "include" | "skip" {
  if (
    coverageSkipReason(lockfileName, lockfileText, lockfileDir) !== undefined
  ) {
    return "skip";
  }
  if (componentCount === 0) {
    throw new Error(
      `target ${identity}: ${lockfileName} is non-empty but the scan ` +
        `produced zero components — coverage assertion failed`,
    );
  }
  return "include";
}

/** components[] length of a parsed SBOM document; 0 when absent/malformed. */
export function componentCountOf(sbom: unknown): number {
  // Derive the count from the shared SbomDocument boundary (which already owns
  // the "components?": "unknown[]" shape) instead of a fourth ad-hoc narrow.
  const doc = SbomDocument(sbom);
  if (doc instanceof type.errors) return 0;
  return doc.components?.length ?? 0;
}
