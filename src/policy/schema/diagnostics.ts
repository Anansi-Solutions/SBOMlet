import parseSpdx from "spdx-expression-parse";

import { stringOf } from "../../validate/record";

import { type DomainProblem } from "./arkAdapter";

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
 * Every key outside `allowed`, as a fault naming what to write instead. A key an earlier schema
 * used is reported through the replacement `replaced` names, so a file written against that schema
 * is told its migration rather than only that something is wrong.
 */
export function unknownKeyProblems(
  entry: Record<string, unknown>,
  allowed: ReadonlyArray<string>,
  replaced: ReadonlyMap<string, string> = new Map(),
): DomainProblem[] {
  const problems: DomainProblem[] = [];

  for (const key of Object.keys(entry)) {
    if (allowed.includes(key)) {
      continue;
    }

    const replacement = replaced.get(key);

    problems.push({
      message:
        replacement === undefined
          ? `unknown key "${key}"`
          : `${replacement} (see docs/reference/policy.md)`,
    });
  }

  return problems;
}

/** {@link unknownKeyProblems} pushed onto a string sink under the caller's `where`. */
export function checkKeys(
  entry: Record<string, unknown>,
  allowed: ReadonlyArray<string>,
  where: string,
  problems: string[],
  replaced: ReadonlyMap<string, string> = new Map(),
): void {
  for (const problem of unknownKeyProblems(entry, allowed, replaced)) {
    problems.push(`${where}: ${problem.message}`);
  }
}

/** A parsed text field: its value when present-and-valid, else the fault that ruled it out. */
export interface TextResult {
  value?: string;
  problems: DomainProblem[];
}

/**
 * A mandatory non-empty string field. Reasons and descriptions are documentation - a missing key, a
 * non-string, or an empty/whitespace-only value each rule the field out with its own fault.
 */
export function requiredText(entry: Record<string, unknown>, key: string): TextResult {
  if (!(key in entry)) {
    return { problems: [{ message: `missing required key "${key}"` }] };
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    return { problems: [{ message: `key "${key}" must be a string` }] };
  }

  if (value.trim() === "") {
    return { problems: [{ message: `key "${key}" must be a non-empty string` }] };
  }

  return { value, problems: [] };
}

/** {@link requiredText} pushed onto a string sink under the caller's `where`. */
export function requireText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  const result = requiredText(entry, key);

  for (const problem of result.problems) {
    problems.push(`${where}: ${problem.message}`);
  }

  return result.value;
}

/**
 * OPTIONAL non-empty string field of [document]. Absent → undefined, no problem. Present but
 * non-string or empty/whitespace-only → undefined + a problem (mirroring requireText's posture for
 * the present-and-invalid case).
 */
export function optionalTextOf(entry: Record<string, unknown>, key: string): TextResult {
  if (!(key in entry)) {
    return { problems: [] };
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    return { problems: [{ message: `key "${key}" must be a string` }] };
  }

  if (value.trim() === "") {
    return { problems: [{ message: `key "${key}" must be a non-empty string` }] };
  }

  return { value, problems: [] };
}

/** {@link optionalTextOf} pushed onto a string sink under the caller's `where`. */
export function optionalText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  const result = optionalTextOf(entry, key);

  for (const problem of result.problems) {
    problems.push(`${where}: ${problem.message}`);
  }

  return result.value;
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
 * A closed-set key: required, a string, and one of `values`. The fault names the whole set, so a
 * mistyped or invented value is told what may be written instead.
 */
export function closedSetOf<T extends string>(
  entry: Record<string, unknown>,
  key: string,
  values: ReadonlyArray<T>,
): { value?: T; problems: DomainProblem[] } {
  const text = requiredText(entry, key);

  if (text.value === undefined) {
    return { problems: text.problems };
  }

  if (!(values as ReadonlyArray<string>).includes(text.value)) {
    return {
      problems: [
        { message: `key "${key}" must be one of ${values.join(", ")} (got "${text.value}")` },
      ],
    };
  }

  return { value: text.value as T, problems: [] };
}

/** {@link closedSetOf} pushed onto a string sink under the caller's `where`. */
export function validateClosedSet<T extends string>(
  entry: Record<string, unknown>,
  key: string,
  values: ReadonlyArray<T>,
  where: string,
  problems: string[],
): T | undefined {
  const result = closedSetOf(entry, key, values);

  for (const problem of result.problems) {
    problems.push(`${where}: ${problem.message}`);
  }

  return result.value;
}
