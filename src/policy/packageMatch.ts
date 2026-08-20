import { matchesIdentityPrefix, type PackageEntry } from "../model/dependencies";
import { compileNamePattern } from "./namePattern";
import { EVERYWHERE_SCOPE } from "./schema";

/** The package fields a selector compares against. */
export type PackageMatchTarget = Pick<PackageEntry, "name" | "version">;

/**
 * How a policy entry picks the packages it governs: one exact display name or a pattern over
 * display names narrowed to specific versions, or an explicit bundle of `{ name, version }` members
 * the occurrence may match any of.
 */
export interface PackageSelector {
  /** Exact display name, compared verbatim and never read as a pattern. */
  name?: string;
  /** Display-name pattern, in the dialect of {@link compileNamePattern}. */
  pattern?: string;
  /** The exact version, or exact versions, covered. Absent covers every version. */
  version?: string | readonly string[];
  /** An explicit bundle of disparate packages; an occurrence matches when it matches any member. */
  packages?: readonly { name: string; version: string | readonly string[] }[];
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
 * Each stated criterion must hold, and a selector naming no package at all - no name, no pattern,
 * no packages list - covers nothing: fail closed, since an entry that named no package would
 * otherwise govern the whole model. A `packages` list matches when any member does, its own name
 * and version compared the same way. Versions are compared literally - the schema has no wildcard
 * version, so a version that looks like a pattern is simply a version nothing carries.
 */
export function matchesPackage(selector: PackageSelector, target: PackageMatchTarget): boolean {
  if (selector.packages !== undefined) {
    return selector.packages.some(
      (member) => member.name === target.name && coversVersion(member.version, target.version),
    );
  }

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

/**
 * Does a `where` scope cover this occurrence target? An element covers the target when it IS the
 * target or the target sits under it as a whole path segment, and the everywhere token covers every
 * one. The single scope comparison behind every policy surface that decides which occurrences an
 * entry reaches.
 */
export function scopeCoversTarget(where: ReadonlyArray<string>, target: string): boolean {
  return where.some((path) => path === EVERYWHERE_SCOPE || matchesIdentityPrefix(target, path));
}
