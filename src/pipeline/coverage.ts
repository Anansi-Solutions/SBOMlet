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
  pnpmThirdPartyEntryCount,
  pythonThirdPartyEntryCount,
  thirdPartyEntryCount,
} from "../targets/firstParty";
import { SbomDocument } from "../validate/sbom";

/**
 * Terraform skip arm. The init-has-run gate is a FILESYSTEM signal (07-14,
 * strengthened 07-15): modules.json presence-as-a-regular-file + the strengthened
 * `.terraform/providers/`+`.terraform/modules/` artifact shape decide, with no
 * HCL parsing. It mirrors the collector EXACTLY via the shared
 * {@link absentModulesJsonShouldFail} / {@link modulesJsonIsPresentFile} verbs so
 * the two cannot diverge.
 * - modules.json ABSENT (or directory-named, Fix 3) and the shape is not the
 *   exact providers-only artifact set → undefined: route to the collect path so
 *   the collector's loud "run tofu init/tofu get first" throw fires. NEVER a
 *   skip-to-zero — a silent incomplete inventory is exactly the failure this tool
 *   prevents.
 * - modules.json ABSENT and the providers-only shape holds (`.terraform/providers/`
 *   present, `.terraform/modules/` absent) → init ran with no module calls.
 *   Mirror the collector: route to scan; if the lock yields zero providers too,
 *   skip with a reason (a providers-empty dir is a legitimate no-op, not a loud
 *   failure).
 * - PRESENT (regular file): the size gate fires BEFORE the read (Fix 4). Then
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
  // The PRESENCE check requires a REGULAR FILE (Fix 3, review #5): a
  // directory-named modules.json is treated as ABSENT, routing to the
  // filesystem-signal gate (which fails loud) instead of a raw EISDIR read.
  // Mirrors the collector via the shared {@link modulesJsonIsPresentFile} verb.
  if (!modulesJsonIsPresentFile(modulesJsonPath)) {
    // Mirror the collector's filesystem-signal gate. No real init artifact →
    // route to the loud-fail collect path. The strengthened gate (Fix 1) returns
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
  // Size gate FIRST — before the read (Fix 4, review #6), mirroring the
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
 *   scan and a zero-component result hard-fails loudly, never a silent skip.
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
  if (
    lockfileName === "yarn.lock" &&
    thirdPartyEntryCount(lockfileText) === 0
  ) {
    return `${lockfileName} has no third-party entries (only workspace/portal members)`;
  }
  if (
    (lockfileName === "poetry.lock" || lockfileName === "uv.lock") &&
    pythonThirdPartyEntryCount(lockfileText) === 0
  ) {
    return `${lockfileName} has no third-party entries (no [[package]] tables, or only the project's own local entries)`;
  }
  // Strict === 0 on a number|undefined counter: undefined (v1/garbage —
  // unknown count) falls through to the scan.
  if (
    lockfileName === "package-lock.json" &&
    npmThirdPartyEntryCount(lockfileText) === 0
  ) {
    return `${lockfileName} has no third-party entries (only the project root / workspace links)`;
  }
  if (
    lockfileName === "pnpm-lock.yaml" &&
    pnpmThirdPartyEntryCount(lockfileText) === 0
  ) {
    return `${lockfileName} has no third-party entries (importers only — no packages section)`;
  }
  if (
    lockfileName === "bun.lock" &&
    bunThirdPartyEntryCount(lockfileText) === 0
  ) {
    return `${lockfileName} has no third-party entries (only @workspace: members)`;
  }
  return undefined;
}

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
