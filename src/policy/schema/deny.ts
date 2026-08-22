import { orLeaves } from "../../normalize/expression";
import { recordOf, stringOf } from "../../validate/record";

import { checkKeys, parseSpdxChecked, requireText } from "./diagnostics";

import type { DenyRule } from "../denylist";

/**
 * One [[deny]] entry → a DenyRule, mirroring validateCompatible EXACTLY. A license-mode entry
 * pre-decomposes its pattern via orLeaves into a satisfies allowlist (AND patterns rejected up
 * front, same as compatible - satisfies cannot hold AND allowlist entries); a name-mode entry
 * stores the verbatim pattern. Every malformed field pushes the aggregated PolicyError message
 * naming `deny[i]`.
 */
function validateDenyEntry(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): DenyRule | undefined {
  const match = stringOf(entry["match"]);

  if (match === "license") {
    checkKeys(entry, ["match", "pattern", "reason"], where, problems);
    const pattern = requireText(entry, "pattern", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (pattern === undefined) {
      return undefined;
    }

    const node = parseSpdxChecked(pattern, `${where}: pattern`, problems);

    if (node === undefined) {
      return undefined;
    }

    const allowlist = orLeaves(node);

    if (allowlist === null) {
      problems.push(
        `${where}: pattern "${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
      );
      return undefined;
    }

    if (reason === undefined) {
      return undefined;
    }

    return { match: "license", pattern, allowlist, reason };
  }

  if (match === "name") {
    checkKeys(entry, ["match", "pattern", "reason"], where, problems);
    const pattern = requireText(entry, "pattern", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (pattern === undefined || reason === undefined) {
      return undefined;
    }

    return { match: "name", pattern, reason };
  }

  problems.push(`${where}: key "match" must be "license" or "name"`);
  return undefined;
}

export function validateDeny(root: Record<string, unknown>, problems: string[]): DenyRule[] {
  const deny: DenyRule[] = [];
  const raw = root["deny"];

  if (raw === undefined) {
    return deny;
  }

  if (!Array.isArray(raw)) {
    problems.push("deny: must be an array of tables ([[deny]])");
    return deny;
  }

  raw.forEach((rawEntry, index) => {
    const where = `deny[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const rule = validateDenyEntry(entry, where, problems);

    if (rule !== undefined) {
      deny.push(rule);
    }
  });
  return deny;
}
