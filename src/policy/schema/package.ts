import { type } from "arktype";

import { recordOf } from "../../validate/record";
import { compileNamePattern, isGlobPattern } from "../engine/namePattern";

import { atPath, nonBlankString, toDomainProblems, type DomainProblem } from "./arkAdapter";
import { requiredText, unknownKeyProblems } from "./diagnostics";
import { whereIsEntirelyContainerScope } from "./scope";

/**
 * One member of a package-form entry's `packages` list: an exact display name and the required
 * version pin covering it. No glob here - the family selector stays the entry-level `pattern` mode.
 */
export interface CompatiblePackageElement {
  /** Exact display name, compared verbatim by the shared matcher. */
  name: string;
  /** The exact version, or exact versions, covered - required on every list member. */
  version: string | ReadonlyArray<string>;
}

/**
 * The presence problems of an exactly-one-of selector: the entry is projected to just the selector
 * keys and matched against a union whose branches each reject the sibling keys, so both-present and
 * neither-present both fail. An empty result means exactly one is present; a non-empty one carries
 * the configured message naming which keys the entry actually held.
 */
function presenceProblems(
  selector: (data: unknown) => unknown,
  entry: Record<string, unknown>,
  keys: ReadonlyArray<string>,
): DomainProblem[] {
  const projected: Record<string, unknown> = {};

  for (const key of keys) {
    if (key in entry) {
      projected[key] = entry[key];
    }
  }

  const result = selector(projected);

  return result instanceof type.errors ? toDomainProblems(result) : [];
}

/**
 * A `pattern` selector value: it must use the glob dialect (a glob-free pattern names one package
 * and belongs under `name`) and must compile - which refuses a pattern with no literal character to
 * anchor it. The verbatim text flows through.
 */
const globNamePattern = type("string").pipe((value, ctx): string => {
  if (!isGlobPattern(value)) {
    return ctx.reject({
      message: `pattern "${value}" carries no wildcard - use "name" to select a single package`,
    }) as never;
  }

  try {
    compileNamePattern(value);
  } catch (error) {
    return ctx.reject({ message: (error as Error).message }) as never;
  }

  return value;
});

/**
 * A `packages` member's `name`: one exact package, never a glob - the family selector is the
 * entry-level `pattern` mode. The verbatim text flows through.
 */
const exactPackageName = type("string").pipe((value, ctx): string =>
  isGlobPattern(value)
    ? (ctx.reject({
        message: `name "${value}" carries a wildcard - a "packages" member names one exact package; use the entry-level "pattern" selector for a family`,
      }) as never)
    : value,
);

/**
 * Exactly one of `name` and `pattern`: each branch rejects the other key, so both-present and
 * neither-present both fail on arktype's own union wording.
 */
const nameOrPatternSelector = type({ name: "unknown" })
  .onUndeclaredKey("reject")
  .or(type({ pattern: "unknown" }).onUndeclaredKey("reject"));

/**
 * The `name`/`pattern` pair: exactly one is required. `name` is compared verbatim; `pattern` must
 * use the glob dialect - a glob-free pattern names one package and belongs under `name` - and must
 * compile, which refuses a pattern with no literal character to anchor it. Faults are
 * entry-relative, so a caller reports them under its own location.
 */
export function nameOrPatternProblems(entry: Record<string, unknown>): {
  selector: { name?: string; pattern?: string };
  problems: DomainProblem[];
} {
  const presence = presenceProblems(nameOrPatternSelector, entry, ["name", "pattern"]);

  if (presence.length > 0) {
    return { selector: {}, problems: presence };
  }

  if ("name" in entry) {
    const name = requiredText(entry, "name");

    return {
      selector: name.value !== undefined ? { name: name.value } : {},
      problems: name.problems,
    };
  }

  const pattern = requiredText(entry, "pattern");

  if (pattern.value === undefined) {
    return { selector: {}, problems: pattern.problems };
  }

  const validated = globNamePattern(pattern.value);

  if (validated instanceof type.errors) {
    return { selector: {}, problems: toDomainProblems(validated) };
  }

  return { selector: { pattern: validated }, problems: [] };
}

/**
 * The version pin shape: one non-blank version string, or a non-empty list of them. Every value is
 * trimmed and compared literally - the schema has no wildcard version anywhere. The list branch's
 * `atLeastLength` rejects an empty list; an element failure lands on its own index.
 */
const versionList = nonBlankString.array().atLeastLength(1);

const versionPin = nonBlankString.or(versionList);

/** How {@link versionPinProblems} treats an absent `version` key. */
interface VersionPinOptions {
  /** True when an absent `version` is a rejection; false leaves an absent key valid. */
  required: boolean;
  /**
   * True on a package-form `[[compatible]]` entry, whose missing-version fault names the container
   * os-scope exemption. False elsewhere (a `[[clarify]]` entry or a `packages` member), where no
   * such exemption exists.
   */
  osScopeExemptible: boolean;
}

/**
 * The `version` pin: one exact version, or a non-empty list of them. The schema has no wildcard
 * version anywhere - version churn is a maintenance task, not a matching rule - so every element is
 * compared literally. An absent key is rejected when `required`, with a pointed fault that names
 * the os-scope exemption where one applies; otherwise an absent key covers every version.
 */
export function versionPinProblems(
  entry: Record<string, unknown>,
  options: VersionPinOptions,
): { version?: string | ReadonlyArray<string>; problems: DomainProblem[] } {
  if (!("version" in entry)) {
    if (!options.required) {
      return { problems: [] };
    }

    return {
      problems: [
        {
          message: options.osScopeExemptible
            ? `missing required key "version" - pin the exact version(s) this acceptance covers, a single string like "1.2.3" or a non-empty list. Only an entry whose "where" is entirely a container os-scope (every element "docker:...") may omit it, since base-image OS-package versions are not author-controlled and drift on every rebuild.`
            : `missing required key "version" - pin the exact version(s) this entry covers, a single string like "1.2.3" or a non-empty list.`,
        },
      ],
    };
  }

  const result = versionPin(entry["version"]);

  if (result instanceof type.errors) {
    return { problems: toDomainProblems(result, ["version"]) };
  }

  return { version: result, problems: [] };
}

/**
 * The `packages` list: a non-empty array of `{ name, version }` members. Each names one exact
 * package (a glob is refused - the family selector is the entry-level `pattern` mode) and pins its
 * own required version. Member faults are reported under `packages[i]`; only a fully-valid list
 * materializes.
 */
function packagesListProblems(entry: Record<string, unknown>): {
  packages?: ReadonlyArray<CompatiblePackageElement>;
  problems: DomainProblem[];
} {
  const raw = entry["packages"];

  if (!Array.isArray(raw) || raw.length === 0) {
    return {
      problems: [
        {
          path: ["packages"],
          message: `key "packages" must be a non-empty array of { name = "...", version = "..." } tables`,
        },
      ],
    };
  }

  const packages: CompatiblePackageElement[] = [];
  const problems: DomainProblem[] = [];

  raw.forEach((rawElement, index) => {
    const element = recordOf(rawElement);
    const at = ["packages", index];

    if (element === undefined) {
      problems.push({ path: at, message: `must be a table { name = "...", version = "..." }` });
      return;
    }

    problems.push(...atPath(at, unknownKeyProblems(element, ["name", "version"])));

    const name = requiredText(element, "name");

    problems.push(...atPath(at, name.problems));

    const exactName = name.value !== undefined ? exactPackageName(name.value) : undefined;

    if (exactName instanceof type.errors) {
      problems.push(...atPath(at, toDomainProblems(exactName)));
    }

    const pin = versionPinProblems(element, { required: true, osScopeExemptible: false });

    problems.push(...atPath(at, pin.problems));
    if (
      exactName !== undefined &&
      !(exactName instanceof type.errors) &&
      pin.version !== undefined
    ) {
      packages.push({ name: exactName, version: pin.version });
    }
  });
  return problems.length === 0 ? { packages, problems } : { problems };
}

/** The parsed package-form selector - see {@link compatibleSelectorProblems}. */
export interface CompatibleSelector {
  name?: string;
  pattern?: string;
  packages?: ReadonlyArray<CompatiblePackageElement>;
  version?: string | ReadonlyArray<string>;
}

/**
 * Exactly one of `name`, `pattern`, and `packages`: each branch rejects the sibling keys, so any
 * count other than one fails. The three-branch union's own summary reads as a confusing mix of
 * "must be removed" and "must be present" across branches, so a single flat message names the rule.
 */
const compatibleSelector = type({ name: "unknown" })
  .onUndeclaredKey("reject")
  .or(type({ pattern: "unknown" }).onUndeclaredKey("reject"))
  .or(type({ packages: "unknown" }).onUndeclaredKey("reject"))
  .configure({
    message: 'exactly one selector is required - "name", "pattern", or "packages"',
  });

/**
 * The package-form selector: exactly one of `name`, `pattern`, and `packages`. The `name`/`pattern`
 * forms carry an entry-level `version`, required unless `scopeWhere` is entirely a container
 * os-scope; the `packages` form bundles disparate packages that each pin their own version and
 * takes no entry-level `version`. Faults are entry-relative for the arktype adapter to place under
 * the entry.
 */
export function compatibleSelectorProblems(
  entry: Record<string, unknown>,
  scopeWhere: ReadonlyArray<string>,
): { selector: CompatibleSelector; problems: DomainProblem[] } {
  const modeProblems = presenceProblems(compatibleSelector, entry, ["name", "pattern", "packages"]);

  if (modeProblems.length > 0) {
    return { selector: {}, problems: modeProblems };
  }

  if ("packages" in entry) {
    const problems: DomainProblem[] = [];

    if ("version" in entry) {
      problems.push({
        message: `key "version" does not apply to a "packages" entry - pin each package's version inside its own { name = "...", version = "..." } table instead`,
      });
    }

    const list = packagesListProblems(entry);

    problems.push(...list.problems);
    return list.packages !== undefined && problems.length === 0
      ? { selector: { packages: list.packages }, problems: [] }
      : { selector: {}, problems };
  }

  const required = !whereIsEntirelyContainerScope(scopeWhere);
  const pin = versionPinProblems(entry, { required, osScopeExemptible: true });
  const nameOrPattern = nameOrPatternProblems(entry);
  const problems = [...nameOrPattern.problems, ...pin.problems];

  if (problems.length !== 0) {
    return { selector: {}, problems };
  }

  return {
    selector: {
      ...nameOrPattern.selector,
      ...(pin.version !== undefined ? { version: pin.version } : {}),
    },
    problems: [],
  };
}
