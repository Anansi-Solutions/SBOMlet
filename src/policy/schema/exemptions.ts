import { recordOf } from "../../validate/record";

import { SOURCE_AVAILABLE_LICENSE_IDS } from "./deny";
import { checkKeys, parseSpdxChecked, requireText } from "./diagnostics";
import { validatePath } from "./scope";

export interface SuppressedWorkspace {
  /** Repo-relative target-identity prefix, e.g. "apps/studio". */
  path: string;
  /**
   * SPDX ID the workspace itself is distributed under. Validated to be a single license id (leaf,
   * optionally WITH/+) - never a compound expression: this field is verdict-affecting (the
   * family-aware suppression check compares it to the finding's copyleft obligations).
   */
  license: string;
  /** Mandatory documentation: why suppression is justified. */
  description: string;
}

export function validateSuppressions(
  root: Record<string, unknown>,
  problems: string[],
): SuppressedWorkspace[] {
  const suppressed: SuppressedWorkspace[] = [];

  if (!("workspace" in root)) {
    return suppressed;
  }

  const workspace = recordOf(root["workspace"]);

  if (workspace === undefined) {
    problems.push(
      "workspace: must be a table containing [[workspace.copyleft_suppressed]] entries",
    );
    return suppressed;
  }

  checkKeys(workspace, ["copyleft_suppressed"], "workspace", problems);
  const entries = workspace["copyleft_suppressed"];

  if (entries === undefined) {
    return suppressed;
  }

  if (!Array.isArray(entries)) {
    problems.push(
      "workspace.copyleft_suppressed: must be an array of tables ([[workspace.copyleft_suppressed]])",
    );
    return suppressed;
  }

  entries.forEach((raw, index) => {
    const where = `workspace.copyleft_suppressed[${index}]`;
    const entry = recordOf(raw);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    checkKeys(entry, ["path", "license", "description"], where, problems);
    const path = requireText(entry, "path", where, problems);
    const license = requireText(entry, "license", where, problems);
    const description = requireText(entry, "description", where, problems);

    if (path !== undefined) {
      validatePath(path, where, problems);
      if (path.startsWith("docker:")) {
        problems.push(
          `${where}: path "${path}" must not start with "docker:" (a container image is not a workspace; accept a container's copyleft package with a scoped [[compatible]] rule instead)`,
        );
      }
    }

    let licenseValid = false;

    if (license !== undefined) {
      const node = parseSpdxChecked(license, `${where}: license`, problems);

      if (node !== undefined) {
        if ("license" in node) {
          licenseValid = true;
        } else {
          // Verdict-affecting - a compound expression has no single family/identity to verify
          // suppression against.
          problems.push(
            `${where}: license "${license}" must be a single SPDX license ID (the workspace's own distribution license), not a compound expression`,
          );
        }
      }
    }

    if (path !== undefined && license !== undefined && licenseValid && description !== undefined) {
      suppressed.push({ path, license, description });
    }
  });
  return suppressed;
}

/**
 * One [[allow_source_available]] exemption (ADR-0013): a built-in source-available licence the
 * consumer has explicitly, auditably accepted, so it surfaces as a warn instead of failing the gate
 * by default.
 */
export interface AllowSourceAvailable {
  /** A built-in source-available SPDX id (BUSL-1.1, SSPL-1.0, Elastic-2.0). */
  license: string;
  /** Mandatory documentation: why this source-available licence is accepted. */
  reason: string;
}

/** The shipped source-available licence ids - the only ones an exemption may name. */
const BUILTIN_DENY_PATTERNS: ReadonlyArray<string> = SOURCE_AVAILABLE_LICENSE_IDS;

/**
 * Parse [[allow_source_available]] (ADR-0013 opt-out): each entry exempts ONE built-in
 * source-available licence from the shipped deny default. `license` must be one of the shipped
 * patterns (a consumer's own [[deny]] is absolute and not exempted here); `reason` is mandatory
 * documentation. An absent table yields [].
 */
export function validateAllowSourceAvailable(
  root: Record<string, unknown>,
  problems: string[],
): AllowSourceAvailable[] {
  const exemptions: AllowSourceAvailable[] = [];
  const raw = root["allow_source_available"];

  if (raw === undefined) {
    return exemptions;
  }

  if (!Array.isArray(raw)) {
    problems.push(
      "allow_source_available: must be an array of tables ([[allow_source_available]])",
    );
    return exemptions;
  }

  raw.forEach((rawEntry, index) => {
    const where = `allow_source_available[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    checkKeys(entry, ["license", "reason"], where, problems);
    const license = requireText(entry, "license", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (license !== undefined && !BUILTIN_DENY_PATTERNS.includes(license)) {
      problems.push(
        `${where}: license "${license}" is not a built-in source-available default — only ${BUILTIN_DENY_PATTERNS.join(", ")} can be exempted (a consumer's own [[deny]] is absolute and not exempted here)`,
      );
      return;
    }

    if (license !== undefined && reason !== undefined) {
      exemptions.push({ license, reason });
    }
  });
  return exemptions;
}
