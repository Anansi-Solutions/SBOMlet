import { stringOf } from "../../validate/record";

import { type DomainProblem } from "./arkAdapter";

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
 * A mandatory non-blank string field, normalized by trimming. Reasons and descriptions are
 * documentation - a missing key, a non-string, or an empty/whitespace-only value each rule the
 * field out with its own fault. The accepted value is returned trimmed, so surrounding padding
 * never survives into a stored field.
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

  return { value: value.trim(), problems: [] };
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
