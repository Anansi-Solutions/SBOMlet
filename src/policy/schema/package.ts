import { recordOf, stringOf } from "../../validate/record";
import { compileNamePattern, isGlobPattern } from "../engine/namePattern";

import { atPath, type DomainProblem } from "./arkAdapter";
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

/** The parsed `name`/`pattern` selector - see {@link nameOrPatternProblems}. */
interface NameOrPattern {
  name?: string;
  pattern?: string;
}

/**
 * The `name`/`pattern` pair: exactly one is required. `name` is compared verbatim; `pattern` must
 * use the glob dialect - a glob-free pattern names one package and belongs under `name` - and must
 * compile, which refuses a pattern with no literal character to anchor it. Faults are
 * entry-relative, so a caller reports them under its own location.
 */
export function nameOrPatternProblems(entry: Record<string, unknown>): {
  selector: NameOrPattern;
  problems: DomainProblem[];
} {
  const hasName = "name" in entry;
  const hasPattern = "pattern" in entry;

  if (hasName === hasPattern) {
    return {
      selector: {},
      problems: [
        {
          message: `exactly one of "name" and "pattern" is required (${hasName ? "both are present" : "neither is present"})`,
        },
      ],
    };
  }

  if (hasName) {
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

  if (!isGlobPattern(pattern.value)) {
    return {
      selector: {},
      problems: [
        {
          message: `pattern "${pattern.value}" carries no wildcard - use "name" to select a single package`,
        },
      ],
    };
  }

  try {
    compileNamePattern(pattern.value);
  } catch (error) {
    return { selector: {}, problems: [{ message: (error as Error).message }] };
  }

  return { selector: { pattern: pattern.value }, problems: [] };
}

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

  const raw = entry["version"];

  if (!Array.isArray(raw)) {
    const version = stringOf(raw);

    if (version === undefined || version.trim() === "") {
      return {
        problems: [
          {
            message: `key "version" must be an exact version string, or a non-empty array of them`,
          },
        ],
      };
    }

    return { version, problems: [] };
  }

  if (raw.length === 0) {
    return { problems: [{ message: `key "version" must be a non-empty array of exact versions` }] };
  }

  const versions: string[] = [];
  const problems: DomainProblem[] = [];

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push({ message: `version[${index}] must be a non-empty string` });
      return;
    }

    versions.push(text);
  });
  return problems.length === 0 ? { version: versions, problems } : { problems };
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
    if (name.value !== undefined && isGlobPattern(name.value)) {
      problems.push({
        path: at,
        message: `name "${name.value}" carries a wildcard - a "packages" member names one exact package; use the entry-level "pattern" selector for a family`,
      });
    }

    const pin = versionPinProblems(element, { required: true, osScopeExemptible: false });

    problems.push(...atPath(at, pin.problems));
    if (name.value !== undefined && !isGlobPattern(name.value) && pin.version !== undefined) {
      packages.push({ name: name.value, version: pin.version });
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
  const modes = ["name", "pattern", "packages"].filter((key) => key in entry);

  if (modes.length !== 1) {
    return {
      selector: {},
      problems: [
        {
          message: `exactly one selector is required - "name", "pattern", or "packages" (${modes.length === 0 ? "none is present" : `${modes.map((key) => `"${key}"`).join(", ")} are present`})`,
        },
      ],
    };
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
