import { stringOf } from "../../validate/record";

import { type DomainProblem } from "./arkAdapter";

/**
 * The reserved `as-dependency-of` element naming the project itself. On a target with a dependency
 * graph it is the direct edge from the project; on a target without one every package is a direct
 * dependency of the project, so it is the honest value there.
 */
export const SELF_PARENT = "self";

/** The `as-dependency-of` TOML key. */
const KEY = "as-dependency-of";

/**
 * The required `as-dependency-of` list on a package-form entry: the packages whose use of this one
 * the acceptance was judged against, by display name, or {@link SELF_PARENT}. Parsed as text here
 * and nothing more - which introduction paths a listed parent covers is decided against the model,
 * not against the file. Faults are entry-relative for the arktype adapter to place under the entry.
 */
export function asDependencyOfProblems(entry: Record<string, unknown>): {
  asDependencyOf?: ReadonlyArray<string>;
  problems: DomainProblem[];
} {
  if (!(KEY in entry)) {
    return {
      problems: [
        {
          message: `missing required key "${KEY}" (the package names this acceptance was judged under, or ["${SELF_PARENT}"] for the project itself)`,
        },
      ],
    };
  }

  const raw = entry[KEY];

  if (!Array.isArray(raw) || raw.length === 0) {
    return {
      problems: [
        {
          message: `key "${KEY}" must be a non-empty array of package names, or ["${SELF_PARENT}"]`,
        },
      ],
    };
  }

  const parents: string[] = [];
  const problems: DomainProblem[] = [];

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push({ message: `${KEY}[${index}] must be a non-empty package name` });
      return;
    }

    parents.push(text);
  });
  return problems.length === 0 ? { asDependencyOf: parents, problems } : { problems };
}
