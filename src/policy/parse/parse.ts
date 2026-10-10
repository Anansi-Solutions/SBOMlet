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

import { validateCache } from "../schema/cache";
import {
  validateDevDependencies,
  validateOsDependencies,
  validateUnknown,
} from "../schema/categories";
import { validateClarificationsPath, validateClarifyTables } from "../schema/clarify";
import { validateCompatible } from "../schema/compatible";
import { validateDocker } from "../schema/container";
import { validateDeny } from "../schema/deny";
import { PolicyError } from "../schema/diagnostics";
import { validateDocument } from "../schema/document";
import { validateAllowSourceAvailable, validateSuppressions } from "../schema/exemptions";
import { validateTarget } from "../schema/targetProfile";

import type { Policy } from "../schema";

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
