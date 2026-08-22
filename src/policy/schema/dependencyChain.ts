import { stringOf } from "../../validate/record";

/**
 * The reserved `as-dependency-of` element naming the project itself. On a target with a dependency
 * graph it is the direct edge from the project; on a target without one every package is a direct
 * dependency of the project, so it is the honest value there.
 */
export const SELF_PARENT = "self";

/**
 * The required `as-dependency-of` list on a package-form entry: the packages whose use of this one
 * the acceptance was judged against, by display name, or {@link SELF_PARENT}. Parsed as text here
 * and nothing more - which introduction paths a listed parent covers is decided against the model,
 * not against the file.
 */
export function validateAsDependencyOf(
  entry: Record<string, unknown>,
  context: string,
  problems: string[],
): { asDependencyOf?: ReadonlyArray<string>; valid: boolean } {
  const key = "as-dependency-of";

  if (!(key in entry)) {
    problems.push(
      `${context}: missing required key "${key}" (the package names this acceptance was judged under, or ["${SELF_PARENT}"] for the project itself)`,
    );
    return { valid: false };
  }

  const raw = entry[key];

  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(
      `${context}: key "${key}" must be a non-empty array of package names, or ["${SELF_PARENT}"]`,
    );
    return { valid: false };
  }

  const parents: string[] = [];
  const before = problems.length;

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(`${context}: ${key}[${index}] must be a non-empty package name`);
      return;
    }

    parents.push(text);
  });
  return problems.length === before ? { asDependencyOf: parents, valid: true } : { valid: false };
}
