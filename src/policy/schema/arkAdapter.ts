/**
 * The bridge between arktype and the policy's aggregated-problem contract.
 *
 * Every construct validates in ONE arktype call whose {@link ArkErrors} carry shape faults (missing
 * key, wrong type, closed-set miss, unparseable morph) and the hand-rolled domain faults a narrow
 * rejected. {@link collectArkProblems} flattens both into the `${where}: <problem>` lines the rest
 * of the parser already speaks, so a caller pushes them onto its shared problem list unchanged.
 */
import { type, type ArkErrors, type Traversal } from "arktype";

/**
 * A required, present, non-blank string, normalized by trimming. A missing key is a required fault;
 * a non-string is a type fault; an empty or whitespace-only value is rejected, since a reason or
 * description that is only spaces documents nothing. Leading and trailing whitespace is stripped,
 * so every field carries the padding-free text the policy meant, compared and rendered the same
 * everywhere. Shared by every non-blank field kind across the schema constructs.
 */
export const nonBlankString = type("string.trim").to(
  type("string > 0").configure({ message: "must be a non-empty string" }),
);

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
 * Re-root a group of faults under `prefix`. A core check reports its faults relative to the value
 * it was handed; a caller that embeds that value - a `packages` member inside its entry - prepends
 * the sub-location so the composed fault points all the way down.
 */
export function atPath(
  prefix: ReadonlyArray<string | number>,
  problems: ReadonlyArray<DomainProblem>,
): DomainProblem[] {
  return problems.map((problem) => ({
    path: [...prefix, ...(problem.path ?? [])],
    message: problem.message,
  }));
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
 * arktype prefixes a fault with the location it already printed - the full path on a nested value
 * (`value at [1].version must be ...`), the key name on a field (`handling must be ...`) - both of
 * which duplicate what the adapter renders. The redundant lead is trimmed to the bare predicate. A
 * message a narrow supplied verbatim leads with neither and passes through untouched (its own text
 * never opens with the field key, by construction).
 */
function trimMessage(message: string, lastKey: PropertyKey | undefined): string {
  const trimmed = message.replace(/^value at \S+ /, "");

  return typeof lastKey === "string" && trimmed.startsWith(`${lastKey} `)
    ? trimmed.slice(lastKey.length + 1)
    : trimmed;
}

/**
 * Render domain faults as `${where}: <problem>` lines - the counterpart of {@link
 * collectArkProblems} for a check run outside arktype, so a hybrid construct places both through
 * one contract.
 */
export function formatProblems(where: string, problems: ReadonlyArray<DomainProblem>): string[] {
  return problems.map(
    (problem) => `${where}${renderLocation(problem.path ?? [])}: ${problem.message}`,
  );
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

    lines.push(
      `${where}${renderLocation(path)}: ${trimMessage(error.message, path[path.length - 1])}`,
    );
  }

  return lines;
}

/**
 * Map one value-shape validation's {@link ArkErrors} to {@link DomainProblem}s rooted at
 * `basePath`. The {@link DomainProblem} counterpart of {@link collectArkProblems}, for a check
 * whose faults a caller still composes as domain problems - a list element, a selector union
 * - before formatting.
 */
export function toDomainProblems(
  errors: ArkErrors,
  basePath: ReadonlyArray<string | number> = [],
): DomainProblem[] {
  return [...errors].map((error) => {
    const path = [...error.path].filter(
      (segment): segment is string | number =>
        typeof segment === "number" || (typeof segment === "string" && !isDisambiguator(segment)),
    );

    return { path: [...basePath, ...path], message: trimMessage(error.message, path.at(-1)) };
  });
}
