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
