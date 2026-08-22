import parseSpdx from "spdx-expression-parse";

import { stringOf } from "../../validate/record";

import type { ExpressionNode } from "../../normalize/expression";

/**
 * The reason an entry surfaces wherever a verdict cites it: the closed-set value it chose, and the
 * comment appended after an em-dash when it carries one. One derivation for every entry kind, so a
 * rendered reason reads the same whatever cited it.
 */
export function ruleReason(value: string, comment: string | undefined): string {
  return comment === undefined ? value : `${value} — ${comment}`;
}

/** All semantic problems aggregated; message = problems joined with "\n". */
export class PolicyError extends Error {
  readonly problems: ReadonlyArray<string>;

  constructor(problems: ReadonlyArray<string>) {
    super(problems.join("\n"));
    this.name = "PolicyError";
    this.problems = problems;
  }
}

/**
 * Reject every key outside `allowed`. A key an earlier schema used is reported with the replacement
 * `replaced` names, so a file written against that schema is told what to write instead of only
 * that something is wrong.
 */
export function checkKeys(
  entry: Record<string, unknown>,
  allowed: ReadonlyArray<string>,
  where: string,
  problems: string[],
  replaced: ReadonlyMap<string, string> = new Map(),
): void {
  for (const key of Object.keys(entry)) {
    if (allowed.includes(key)) {
      continue;
    }

    const replacement = replaced.get(key);

    problems.push(
      replacement === undefined
        ? `${where}: unknown key "${key}"`
        : `${where}: ${replacement} (see docs/reference/policy.md)`,
    );
  }
}

/**
 * Mandatory non-empty string field. Reasons and descriptions are documentation - an empty or
 * whitespace-only value does not count.
 */
export function requireText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  if (!(key in entry)) {
    problems.push(`${where}: missing required key "${key}"`);
    return undefined;
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    problems.push(`${where}: key "${key}" must be a string`);
    return undefined;
  }

  if (value.trim() === "") {
    problems.push(`${where}: key "${key}" must be a non-empty string`);
    return undefined;
  }

  return value;
}

/**
 * OPTIONAL non-empty string field of [document]. Absent → undefined, no problem. Present but
 * non-string or empty/whitespace-only → undefined + a problem (mirroring requireText's posture for
 * the present-and-invalid case).
 */
export function optionalText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  if (!(key in entry)) {
    return undefined;
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    problems.push(`${where}: key "${key}" must be a string`);
    return undefined;
  }

  if (value.trim() === "") {
    problems.push(`${where}: key "${key}" must be a non-empty string`);
    return undefined;
  }

  return value;
}

/** Eager SPDX parse; a problem is recorded on failure. */
export function parseSpdxChecked(
  value: string,
  where: string,
  problems: string[],
): ExpressionNode | undefined {
  try {
    return parseSpdx(value) as ExpressionNode;
  } catch {
    problems.push(`${where} "${value}" is not a valid SPDX expression`);
    return undefined;
  }
}

/**
 * A closed-set key: required, a string, and one of `values`. The error names the whole set, so a
 * mistyped or invented value is told what may be written instead.
 */
export function validateClosedSet<T extends string>(
  entry: Record<string, unknown>,
  key: string,
  values: ReadonlyArray<T>,
  where: string,
  problems: string[],
): T | undefined {
  const value = requireText(entry, key, where, problems);

  if (value === undefined) {
    return undefined;
  }

  if (!(values as ReadonlyArray<string>).includes(value)) {
    problems.push(`${where}: key "${key}" must be one of ${values.join(", ")} (got "${value}")`);
    return undefined;
  }

  return value as T;
}
