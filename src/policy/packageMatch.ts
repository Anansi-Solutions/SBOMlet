import { compileNamePattern } from "./namePattern";

import type { PackageEntry } from "../model/dependencies";

/** The package fields a selector compares against. */
export type PackageMatchTarget = Pick<PackageEntry, "name" | "version">;

/**
 * How a policy entry picks the packages it governs: one exact display name or a pattern over
 * display names, optionally narrowed to specific versions.
 */
export interface PackageSelector {
  /** Exact display name, compared verbatim and never read as a pattern. */
  name?: string;
  /** Display-name pattern, in the dialect of {@link compileNamePattern}. */
  pattern?: string;
  /** The exact version, or exact versions, covered. Absent covers every version. */
  version?: string | readonly string[];
}

/** Absent covers every version; a string is equality; a list is membership. */
function coversVersion(version: string | readonly string[] | undefined, actual: string): boolean {
  if (version === undefined) {
    return true;
  }

  return typeof version === "string" ? version === actual : version.includes(actual);
}

/**
 * Does this selector cover this package? The single matcher behind every policy surface that
 * decides which packages an entry governs, so evaluation, annotation and unused-entry accounting
 * can never drift apart.
 *
 * Each stated criterion must hold, and a selector stating neither a name nor a pattern covers
 * nothing: fail closed, since an entry that named no package would otherwise govern the whole
 * model. Versions are compared literally - the schema has no wildcard version, so a version that
 * looks like a pattern is simply a version nothing carries.
 */
export function matchesPackage(selector: PackageSelector, target: PackageMatchTarget): boolean {
  if (selector.name === undefined && selector.pattern === undefined) {
    return false;
  }

  if (selector.name !== undefined && selector.name !== target.name) {
    return false;
  }

  if (selector.pattern !== undefined && !compileNamePattern(selector.pattern).test(target.name)) {
    return false;
  }

  return coversVersion(selector.version, target.version);
}
