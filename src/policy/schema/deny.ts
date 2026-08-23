import { type } from "arktype";

import { recordOf, stringOf } from "../../validate/record";

import { collectArkProblems, nonBlankString } from "./arkAdapter";
import { checkKeys } from "./diagnostics";
import { licenseAllowlist } from "./spdx";

/**
 * A validated deny entry. License mode carries the pre-decomposed allowlist (orLeaves), name mode
 * carries only the verbatim package name to compare.
 */
export type DenyRule =
  | {
      match: "license";
      /** The pattern exactly as written in the policy file. */
      pattern: string;
      /** Pre-decomposed satisfies allowlist (OR-leaves), computed at validation. */
      allowlist: ReadonlyArray<string>;
      reason: string;
    }
  | { match: "name"; pattern: string; reason: string };

/**
 * The shipped source-available SPDX ids denied out of the box (ADR-0013): the closed vocabulary an
 * [[allow_source_available]] exemption may name, and the defaults the engine pairs with rationale.
 */
export const SOURCE_AVAILABLE_LICENSE_IDS = ["BUSL-1.1", "SSPL-1.0", "Elastic-2.0"] as const;

const DENY_KEYS = ["match", "pattern", "reason"] as const;

/**
 * The license form: the SPDX `pattern` decomposed into a satisfies allowlist (an AND pattern is
 * rejected up front, same as [[compatible]]) plus the mandatory `reason`.
 */
const denyLicense = type({
  match: "'license'",
  pattern: nonBlankString,
  reason: nonBlankString,
}).pipe((entry, ctx): DenyRule => {
  const { allowlist, problem } = licenseAllowlist(entry.pattern);

  if (problem !== undefined) {
    return ctx.reject({ relativePath: ["pattern"], message: problem }) as never;
  }

  return {
    match: "license",
    pattern: entry.pattern,
    allowlist: allowlist ?? [],
    reason: entry.reason,
  };
});

/** The name form: a verbatim package name and the mandatory `reason`. */
const denyName = type({
  match: "'name'",
  pattern: nonBlankString,
  reason: nonBlankString,
}).pipe((entry): DenyRule => ({ match: "name", pattern: entry.pattern, reason: entry.reason }));

/**
 * One [[deny]] entry → a DenyRule, discriminated on `match`. A license-mode entry pre-decomposes
 * its pattern into a satisfies allowlist; a name-mode entry stores the verbatim pattern. Every
 * malformed field pushes the aggregated PolicyError message naming `deny[i]`.
 */
function validateDenyEntry(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): DenyRule | undefined {
  const before = problems.length;
  const match = stringOf(entry["match"]);

  if (match !== "license" && match !== "name") {
    problems.push(`${where}: key "match" must be "license" or "name"`);
    return undefined;
  }

  checkKeys(entry, DENY_KEYS, where, problems);

  const result = match === "license" ? denyLicense(entry) : denyName(entry);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, where));
    return undefined;
  }

  return problems.length === before ? result : undefined;
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
