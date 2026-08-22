/**
 * TOML policy text → validated Policy.
 *
 * Validation rejects - never skips - with every semantic problem collected into one PolicyError,
 * each problem naming its table path and key (the opposite tolerance posture from merge.ts, which
 * skips malformed SBOM entries). TOML syntax errors propagate smol-toml's TomlError untouched: its
 * message already embeds line, column, and a caret-annotated source line.
 *
 * Every SPDX pattern, clarify expression, and workspace license is parsed eagerly here so
 * evaluate() never sees an unparseable rule. Compatible license patterns are pre-decomposed into
 * spdx-satisfies-safe OR-leaf allowlists via orLeaves; AND-containing patterns are rejected
 * up-front because satisfies throws on AND allowlist entries. No substring matching on license
 * values anywhere - patterns flow through spdx-expression-parse + orLeaves only.
 *
 * Policy text is untrusted config (repo-tampered or user-authored). Suppression paths are validated
 * - non-empty, forward slashes only, no ".." segments, no leading/trailing slash, no drive
 * specifier - so a crafted path can never suppress everything, escape the target namespace, or name
 * a file outside the repository; compatible `where` scopes reuse the same validation, so a crafted
 * scope cannot escape the identity namespace either. smol-toml is a spec-compliant TOML 1.0 parser
 * with no eval; duplicate tables throw per spec.
 *
 * Pure function: no I/O, no logging - the CLI reads the file and owns stderr.
 */
import { type } from "arktype";
import { parse as parseToml } from "smol-toml";

import { PolicyRoot, TOP_LEVEL_KEYS } from "../../validate/policy";
import { recordOf } from "../../validate/record";

import { validateCache, type CacheConfig } from "./cache";
import {
  validateDevDependencies,
  validateOsDependencies,
  validateUnknown,
  type DevDependencyHandling,
  type OsDependencyHandling,
} from "./categories";
import { validateClarificationsPath, validateClarifyTables, type ClarifyRule } from "./clarify";
import { validateCompatible, type CompatibleRule } from "./compatible";
import { validateDocker, type DockerConfig } from "./container";
import { validateDeny } from "./deny";
import { PolicyError } from "./diagnostics";
import { validateDocument, type DocumentConfig } from "./document";
import {
  validateAllowSourceAvailable,
  validateSuppressions,
  type AllowSourceAvailable,
  type SuppressedWorkspace,
} from "./exemptions";
import { validateTarget, type TargetConfig } from "./targetProfile";

import type { DenyRule } from "../denylist";

export { PolicyError, ruleReason } from "./diagnostics";
export { EVERYWHERE_SCOPE } from "./scope";
export { SELF_PARENT } from "./dependencyChain";
export { RATIONALE_VALUES } from "./compatible";
export {
  clarifyCitation,
  clarifyInvalidRuleId,
  JUSTIFICATION_VALUES,
  validateClarifyTables,
} from "./clarify";

export type { DenyRule } from "../denylist";
export type {
  Rationale,
  CompatibleLicenseRule,
  CompatiblePackageRule,
  CompatibleRule,
} from "./compatible";
export type { CompatiblePackageElement } from "./package";
export type { Justification, ClarifyIdentity, ClarifyRule } from "./clarify";
export type { SuppressedWorkspace, AllowSourceAvailable } from "./exemptions";
export type { DevDependencyHandling, OsDependencyHandling } from "./categories";
export type { DocumentConfig } from "./document";
export type { DockerDevelopmentEntry, DockerConfig } from "./container";
export type { CacheConfig } from "./cache";
export type { TargetWorkspaceEntry, TargetConfig } from "./targetProfile";

export interface Policy {
  /** Default "warn" when the [unknown] table is absent. */
  unknownHandling: "warn" | "fail";
  /** Default "warn" when the [dev_dependencies] table is absent. */
  devDependencies: DevDependencyHandling;
  /** Default "warn" when the [os_dependencies] table is absent. */
  osDependencies: OsDependencyHandling;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  compatible: ReadonlyArray<CompatibleRule>;
  clarify: ReadonlyArray<ClarifyRule>;
  /**
   * The declared path of a file holding further `[[clarify]]` entries, repo-root-relative. Absent
   * when the policy declares none; the entries themselves arrive appended to `clarify`.
   */
  clarifications?: string;
  /**
   * Terminal deny-list: the HIGHEST-precedence lane. A matching package FORCE-FAILS regardless of
   * compatible/suppression/dev-scope. Absent [[deny]] table yields [].
   */
  deny: ReadonlyArray<DenyRule>;
  /**
   * Per-licence exemptions from the shipped source-available deny defaults (ADR-0013). A listed
   * licence is no longer force-failed by the default - the package surfaces as a WARN citing the
   * exemption, never silently. Does NOT affect a consumer's own [[deny]] (an explicit deny still
   * wins). Absent → [].
   */
  allowSourceAvailable: ReadonlyArray<AllowSourceAvailable>;
  /**
   * Author-supplied document presentation. Absent [document] table yields undefined; an empty
   * [document] yields {} (both keys optional).
   */
  document?: DocumentConfig;
  /**
   * Dockerfile-discovery exclusion globs. Absent [docker] table yields undefined; a present
   * [docker] (with or without `ignore`) yields a DockerConfig whose `ignore` defaults to [].
   */
  docker?: DockerConfig;
  /**
   * Where tool-generated committed artifacts live (the enrichment cache, the Docker OS SBOM, and
   * any added later). Absent maps to DEFAULT_CACHE_DIR.
   */
  cache?: CacheConfig;
  /**
   * The declared target usage profile that activates the compatibility lane. Absent [target] table
   * yields undefined - today's walk stays byte-identical.
   */
  target?: TargetConfig;
}

/**
 * Parse and validate TOML policy text. smol-toml's TomlError propagates untouched (its message
 * embeds line/column/caret context); every semantic problem is collected and thrown as ONE
 * PolicyError naming table paths.
 *
 * PolicyRoot ("+": "reject") narrows the root shape; the unknown-top-level-key message stays
 * hand-written (arktype's text differs from the PolicyError contract).
 */
export function parsePolicy(text: string): Policy {
  const root = recordOf(parseToml(text)) ?? {};
  const problems: string[] = [];

  const narrowed = PolicyRoot(root);

  if (narrowed instanceof type.errors) {
    const accepted: readonly string[] = TOP_LEVEL_KEYS;

    for (const key of Object.keys(root)) {
      if (!accepted.includes(key)) {
        problems.push(`unknown top-level key "${key}"`);
      }
    }
  }

  const suppressedWorkspaces = validateSuppressions(root, problems);
  const compatible = validateCompatible(root, problems);
  const clarify = validateClarifyTables(root["clarify"], "clarify", problems);
  const clarifications = validateClarificationsPath(root, problems);
  const deny = validateDeny(root, problems);
  const unknownHandling = validateUnknown(root, problems);
  const devDependencies = validateDevDependencies(root, problems);
  const osDependencies = validateOsDependencies(root, problems);
  const document = validateDocument(root, problems);
  const docker = validateDocker(root, problems);
  const cache = validateCache(root, problems);
  const allowSourceAvailable = validateAllowSourceAvailable(root, problems);
  const target = validateTarget(root, problems);

  if (problems.length > 0) {
    throw new PolicyError(problems);
  }

  return {
    unknownHandling,
    devDependencies,
    osDependencies,
    suppressedWorkspaces,
    compatible,
    clarify,
    deny,
    allowSourceAvailable,
    ...(clarifications !== undefined ? { clarifications } : {}),
    ...(document !== undefined ? { document } : {}),
    ...(docker !== undefined ? { docker } : {}),
    ...(cache !== undefined ? { cache } : {}),
    ...(target !== undefined ? { target } : {}),
  };
}
