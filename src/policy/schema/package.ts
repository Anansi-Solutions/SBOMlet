import { recordOf, stringOf } from "../../validate/record";
import { compileNamePattern, isGlobPattern } from "../namePattern";

import { checkKeys, requireText } from "./diagnostics";
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

/** The parsed package-form selector - see {@link validateCompatiblePackageSelector}. */
interface CompatibleSelector {
  name?: string;
  pattern?: string;
  packages?: ReadonlyArray<CompatiblePackageElement>;
  version?: string | ReadonlyArray<string>;
  valid: boolean;
}

/**
 * The package-form selector: exactly one of `name`, `pattern`, and `packages`. The `name`/`pattern`
 * forms carry an entry-level `version`, required unless `scopeWhere` is entirely a container
 * os-scope; the `packages` form bundles disparate packages that each pin their own version and
 * takes no entry-level `version`. `scopeWhere` is the already-validated `where` (undefined when it
 * did not validate, which forces `version` required - the conservative reading).
 */
export function validateCompatiblePackageSelector(
  entry: Record<string, unknown>,
  scopeWhere: ReadonlyArray<string> | undefined,
  where: string,
  problems: string[],
): CompatibleSelector {
  const modes = ["name", "pattern", "packages"].filter((key) => key in entry);

  if (modes.length !== 1) {
    problems.push(
      `${where}: exactly one selector is required - "name", "pattern", or "packages" (${modes.length === 0 ? "none is present" : `${modes.map((key) => `"${key}"`).join(", ")} are present`})`,
    );
    return { valid: false };
  }

  if ("packages" in entry) {
    let valid = true;

    if ("version" in entry) {
      problems.push(
        `${where}: key "version" does not apply to a "packages" entry - pin each package's version inside its own { name = "...", version = "..." } table instead`,
      );
      valid = false;
    }

    const list = validatePackagesList(entry, where, problems);

    return list.packages !== undefined && valid
      ? { packages: list.packages, valid: true }
      : { valid: false };
  }

  const required = !whereIsEntirelyContainerScope(scopeWhere);
  const pin = validateVersionPin(entry, where, problems, { required, osScopeExemptible: true });
  const nameOrPattern = validateNameOrPattern(entry, where, problems);

  if (!nameOrPattern.valid || !pin.valid) {
    return { valid: false };
  }

  return {
    ...(nameOrPattern.name !== undefined ? { name: nameOrPattern.name } : {}),
    ...(nameOrPattern.pattern !== undefined ? { pattern: nameOrPattern.pattern } : {}),
    ...(pin.version !== undefined ? { version: pin.version } : {}),
    valid: true,
  };
}

/**
 * The `packages` list: a non-empty array of `{ name, version }` members. Each names one exact
 * package (a glob is refused - the family selector is the entry-level `pattern` mode) and pins its
 * own required version. Malformed members push aggregated problems naming the member's position;
 * only a fully-valid list materializes.
 */
function validatePackagesList(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): { packages?: ReadonlyArray<CompatiblePackageElement>; valid: boolean } {
  const raw = entry["packages"];

  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(
      `${where}: key "packages" must be a non-empty array of { name = "...", version = "..." } tables`,
    );
    return { valid: false };
  }

  const packages: CompatiblePackageElement[] = [];
  const before = problems.length;

  raw.forEach((rawElement, index) => {
    const elementWhere = `${where}.packages[${index}]`;
    const element = recordOf(rawElement);

    if (element === undefined) {
      problems.push(`${elementWhere}: must be a table { name = "...", version = "..." }`);
      return;
    }

    checkKeys(element, ["name", "version"], elementWhere, problems);
    const name = requireText(element, "name", elementWhere, problems);

    if (name !== undefined && isGlobPattern(name)) {
      problems.push(
        `${elementWhere}: name "${name}" carries a wildcard - a "packages" member names one exact package; use the entry-level "pattern" selector for a family`,
      );
    }

    const pin = validateVersionPin(element, elementWhere, problems, {
      required: true,
      osScopeExemptible: false,
    });

    if (name !== undefined && !isGlobPattern(name) && pin.version !== undefined) {
      packages.push({ name, version: pin.version });
    }
  });
  return problems.length === before ? { packages, valid: true } : { valid: false };
}

/** Package selector fields shared by every entry that names the packages it governs. */
interface SelectorFields {
  name?: string;
  pattern?: string;
  valid: boolean;
}

/**
 * The `name`/`pattern` pair: exactly one is required. `name` is compared verbatim; `pattern` must
 * use the glob dialect - a glob-free pattern names one package and belongs under `name` - and must
 * compile, which refuses a pattern with no literal character to anchor it.
 */
export function validateNameOrPattern(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): SelectorFields {
  const hasName = "name" in entry;
  const hasPattern = "pattern" in entry;

  if (hasName === hasPattern) {
    problems.push(
      `${where}: exactly one of "name" and "pattern" is required (${hasName ? "both are present" : "neither is present"})`,
    );
    return { valid: false };
  }

  if (hasName) {
    const name = requireText(entry, "name", where, problems);

    return name === undefined ? { valid: false } : { name, valid: true };
  }

  const pattern = requireText(entry, "pattern", where, problems);

  if (pattern === undefined) {
    return { valid: false };
  }

  if (!isGlobPattern(pattern)) {
    problems.push(
      `${where}: pattern "${pattern}" carries no wildcard - use "name" to select a single package`,
    );
    return { valid: false };
  }

  try {
    compileNamePattern(pattern);
  } catch (error) {
    problems.push(`${where}: ${(error as Error).message}`);
    return { valid: false };
  }

  return { pattern, valid: true };
}

/** The parsed `version` pin - see {@link validateVersionPin}. */
interface VersionPin {
  version?: string | ReadonlyArray<string>;
  valid: boolean;
}

/** How {@link validateVersionPin} treats an absent `version` key. */
interface VersionPinOptions {
  /** True when an absent `version` is a rejection; false leaves an absent key as valid. */
  required: boolean;
  /**
   * True on a package-form `[[compatible]]` entry, whose missing-version error names the container
   * os-scope exemption. False elsewhere (a `[[clarify]]` entry or a `packages` member), where no
   * such exemption exists.
   */
  osScopeExemptible: boolean;
}

/**
 * The `version` pin: one exact version, or a non-empty list of them. The schema has no wildcard
 * version anywhere - version churn is a maintenance task, not a matching rule - so every element is
 * compared literally. An absent key is rejected when `required`, with a pointed error that names
 * the os-scope exemption where one applies; otherwise an absent key covers every version.
 */
export function validateVersionPin(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
  options: VersionPinOptions,
): VersionPin {
  if (!("version" in entry)) {
    if (!options.required) {
      return { valid: true };
    }

    problems.push(
      options.osScopeExemptible
        ? `${where}: missing required key "version" - pin the exact version(s) this acceptance covers, a single string like "1.2.3" or a non-empty list. Only an entry whose "where" is entirely a container os-scope (every element "docker:...") may omit it, since base-image OS-package versions are not author-controlled and drift on every rebuild.`
        : `${where}: missing required key "version" - pin the exact version(s) this entry covers, a single string like "1.2.3" or a non-empty list.`,
    );
    return { valid: false };
  }

  const raw = entry["version"];

  if (!Array.isArray(raw)) {
    const version = stringOf(raw);

    if (version === undefined || version.trim() === "") {
      problems.push(
        `${where}: key "version" must be an exact version string, or a non-empty array of them`,
      );
      return { valid: false };
    }

    return { version, valid: true };
  }

  if (raw.length === 0) {
    problems.push(`${where}: key "version" must be a non-empty array of exact versions`);
    return { valid: false };
  }

  const versions: string[] = [];
  const before = problems.length;

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(`${where}: version[${index}] must be a non-empty string`);
      return;
    }

    versions.push(text);
  });
  return problems.length === before ? { version: versions, valid: true } : { valid: false };
}
