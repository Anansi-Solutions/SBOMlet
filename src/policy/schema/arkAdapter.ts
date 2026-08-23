/**
 * The bridge between arktype and the policy's aggregated-problem contract.
 *
 * Every construct validates in ONE arktype call whose {@link ArkErrors} carry shape faults (missing
 * key, wrong type, closed-set miss, unparseable morph) and the hand-rolled domain faults a narrow
 * rejected. {@link collectArkProblems} flattens both into the `${where}: <problem>` lines the rest
 * of the parser already speaks, so a caller pushes them onto its shared problem list unchanged.
 */
import type { ArkErrors, Traversal } from "arktype";

/**
 * A single domain fault a pure cross-field check reports. `path` locates it relative to the entry
 * under narrow - a field key, an element index, or empty for an entry-level fault; `message` is the
 * actionable text, already free of any construct prefix (the adapter adds it).
 */
export interface DomainProblem {
  readonly path?: ReadonlyArray<string | number>;
  readonly message: string;
}

/**
 * A path segment {@link wrapErrors} appends to keep sibling rejections distinct. arktype folds two
 * rejections that share a path into one intersection node whose message getter throws on an
 * anonymous predicate, so every rejection must land on its own path; the adapter strips these
 * before rendering a location.
 */
const DISAMBIGUATOR = "\u00a7";

function isDisambiguator(segment: PropertyKey): boolean {
  return typeof segment === "string" && segment.startsWith(DISAMBIGUATOR);
}

/**
 * Bind a pure cross-field check as an arktype narrow. Each returned {@link DomainProblem} is
 * rejected on its own disambiguated path so the faults accumulate as siblings rather than
 * collapsing into one; the narrow passes only when the check returns nothing.
 *
 * @returns a predicate suitable for `.narrow(...)`, typed against the entry the shape infers.
 */
export function wrapErrors<T>(
  check: (entry: T) => ReadonlyArray<DomainProblem>,
): (entry: T, ctx: Traversal) => boolean {
  return (entry, ctx) => {
    const problems = check(entry);

    problems.forEach((problem, index) => {
      ctx.reject({
        relativePath: [...(problem.path ?? []), `${DISAMBIGUATOR}${index}`],
        message: problem.message,
      });
    });
    return problems.length === 0;
  };
}

/** Render a location suffix from an arktype path: `.key` for a field, `[i]` for an index. */
function renderLocation(path: ReadonlyArray<PropertyKey>): string {
  return path
    .map((segment) => (typeof segment === "number" ? `[${segment}]` : `.${String(segment)}`))
    .join("");
}

/**
 * arktype restates the full path in a nested message (`value at [1].version must be ...`), which
 * duplicates the location the adapter already prints; the prefix is trimmed to the bare predicate.
 * A message a narrow supplied verbatim carries no such prefix and passes through untouched.
 */
function trimMessage(message: string): string {
  return message.replace(/^value at \S+ /, "");
}

/**
 * Flatten one construct's {@link ArkErrors} into `${where}: <problem>` lines. `where` is the
 * construct's top key (e.g. `compatible`); each error's path extends it. A missing-key fault is
 * reworded to `missing required key "<key>"` at the parent location, matching the parser's own
 * phrasing for an absent field.
 */
export function collectArkProblems(errors: ArkErrors, where: string): string[] {
  const lines: string[] = [];

  for (const error of errors) {
    const path = [...error.path].filter((segment) => !isDisambiguator(segment));

    if (error.hasCode("required")) {
      const key = path[path.length - 1];

      lines.push(
        `${where}${renderLocation(path.slice(0, -1))}: missing required key "${String(key)}"`,
      );
      continue;
    }

    lines.push(`${where}${renderLocation(path)}: ${trimMessage(error.message)}`);
  }

  return lines;
}
