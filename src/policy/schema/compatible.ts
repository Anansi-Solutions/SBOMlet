import { type } from "arktype";

import { recordOf, stringOf } from "../../validate/record";

import { collectArkProblems, formatProblems, wrapErrors } from "./arkAdapter";
import { asDependencyOfProblems } from "./dependencyChain";
import { checkKeys } from "./diagnostics";
import { compatibleSelectorProblems, type CompatiblePackageElement } from "./package";
import { nonEmptyString } from "./scalars";
import { whereProblems } from "./scope";
import { licenseAllowlist } from "./spdx";

/**
 * Why an otherwise-incompatible package is accepted.
 *
 * - `build-time-only`: consumed while building, absent from what ships.
 * - `development-tool-only`: a tool for working on the repository, never reached by the product.
 * - `license-reviewed`: a human read the license and accepted its obligations. The sanctioned
 *   fallback when no structural reason applies.
 * - `os-package-unmodified`: a distribution package shipped inside a container image exactly as it
 *   arrived, not linked into the software.
 * - `unused-transitive`: pulled in by a dependency but never reached at runtime.
 */
export const RATIONALE_VALUES = [
  "build-time-only",
  "development-tool-only",
  "license-reviewed",
  "os-package-unmodified",
  "unused-transitive",
] as const;

/** The reason an entry gives for accepting a package. */
export type Rationale = (typeof RATIONALE_VALUES)[number];

export interface CompatibleLicenseRule {
  match: "license";
  /** The SPDX pattern exactly as written in the policy file. */
  pattern: string;
  /**
   * Pre-decomposed satisfies allowlist: rendered OR-leaves of the pattern (single ID, optionally
   * WITH ⇒ one entry). Computed at validation time, never at evaluate time.
   */
  allowlist: ReadonlyArray<string>;
  /** Why this licence is accepted where the scope below covers it. */
  rationale: Rationale;
  /**
   * The occurrence scope: identity prefixes the rule is limited to, matched with the same
   * segment-aware prefix comparison as suppression paths, or the everywhere token {@link
   * EVERYWHERE_SCOPE} for a deliberately repository-wide acceptance.
   */
  where: ReadonlyArray<string>;
  /** Free prose, for what the rationale alone cannot carry. */
  comment?: string;
}

export interface CompatiblePackageRule {
  match: "package";
  /** Exact display name; exactly one selector of `name`, `pattern`, `packages` is present. */
  name?: string;
  /**
   * Display-name pattern, in the dialect of {@link compileNamePattern}. The license form reads the
   * same key as an SPDX expression instead - `match` decides which, as it does on the deny lane.
   */
  pattern?: string;
  /**
   * An explicit bundle of disparate packages that share this entry's `where`, `as-dependency-of`,
   * `rationale`, and `comment`. Present in place of `name`/`pattern`; each member carries its own
   * required version. An occurrence matches the entry when it matches ANY member.
   */
  packages?: ReadonlyArray<CompatiblePackageElement>;
  /**
   * The exact version, or exact versions, covered on a `name`/`pattern` entry. Required unless the
   * entry's `where` is entirely a container os-scope; never present on a `packages` entry, whose
   * members pin their own.
   */
  version?: string | ReadonlyArray<string>;
  /**
   * The packages whose use of this one the acceptance was judged under, by display name, or the
   * reserved {@link SELF_PARENT} token. Parsed and carried here; which introduction paths a listed
   * parent covers is not decided in this file.
   */
  asDependencyOf: ReadonlyArray<string>;
  /** Why this package is accepted where the scope below covers it. */
  rationale: Rationale;
  /** The occurrence scope - see CompatibleLicenseRule.where. */
  where: ReadonlyArray<string>;
  /** Free prose, for what the rationale alone cannot carry. */
  comment?: string;
}

export type CompatibleRule = CompatibleLicenseRule | CompatiblePackageRule;

/** The closed vocabulary of `rationale`, as an arktype enum. */
const rationaleValue = type.enumerated(...RATIONALE_VALUES);

/** Keys an earlier [[compatible]] schema used, each naming what replaced it. */
const COMPATIBLE_REPLACED_KEYS: ReadonlyMap<string, string> = new Map([
  ["reason", 'key "reason" was replaced by "rationale" (a closed set) plus an optional "comment"'],
]);

/** {@link COMPATIBLE_REPLACED_KEYS} plus the license form's own inapplicable key. */
const COMPATIBLE_LICENSE_REPLACED_KEYS: ReadonlyMap<string, string> = new Map([
  ...COMPATIBLE_REPLACED_KEYS,
  [
    "as-dependency-of",
    'key "as-dependency-of" is not applicable at license level - a licence is accepted wherever "where" covers it, not through one package\'s use of another',
  ],
]);

const COMPATIBLE_LICENSE_KEYS = ["match", "pattern", "rationale", "where", "comment"] as const;
const COMPATIBLE_PACKAGE_KEYS = [
  "match",
  "name",
  "pattern",
  "packages",
  "version",
  "as-dependency-of",
  "rationale",
  "where",
  "comment",
] as const;

/**
 * The license form's declarative shape: the SPDX `pattern`, the closed `rationale`, and the `where`
 * scope (its element paths checked by the bound narrow). The trailing pipe decomposes `pattern`
 * into the satisfies allowlist the evaluator reads via {@link licenseAllowlist}. Here `pattern` is
 * the SPDX expression the acceptance covers; the package form reads the same key as a name glob
 * instead.
 */
const compatibleLicense = type({
  match: "'license'",
  pattern: nonEmptyString,
  rationale: rationaleValue,
  where: "string[]",
  "comment?": nonEmptyString,
})
  .narrow(wrapErrors((entry) => whereProblems(entry.where)))
  .pipe((entry, ctx): CompatibleLicenseRule => {
    const { allowlist, problem } = licenseAllowlist(entry.pattern);

    if (problem !== undefined) {
      return ctx.reject({ relativePath: ["pattern"], message: problem }) as never;
    }

    return {
      match: "license",
      pattern: entry.pattern,
      allowlist: allowlist ?? [],
      rationale: entry.rationale,
      where: entry.where,
      ...(entry.comment !== undefined ? { comment: entry.comment } : {}),
    };
  });

/**
 * The package form's declarative envelope: the closed `rationale`, the `where` scope, and an
 * optional `comment`. The selector (`name`/`pattern`/`packages`), the version pin, and
 * `as-dependency-of` are cross-field and imperative, validated by the pure checks the orchestrator
 * runs alongside.
 */
const compatiblePackageEnvelope = type({
  match: "'package'",
  rationale: rationaleValue,
  where: "string[]",
  "comment?": nonEmptyString,
});

export function validateCompatible(
  root: Record<string, unknown>,
  problems: string[],
): CompatibleRule[] {
  const compatible: CompatibleRule[] = [];
  const raw = root["compatible"];

  if (raw === undefined) {
    return compatible;
  }

  if (!Array.isArray(raw)) {
    problems.push("compatible: must be an array of tables ([[compatible]])");
    return compatible;
  }

  raw.forEach((rawEntry, index) => {
    const where = `compatible[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const match = stringOf(entry["match"]);

    if (match === "license") {
      const rule = validateCompatibleLicense(entry, where, problems);

      if (rule !== undefined) {
        compatible.push(rule);
      }
    } else if (match === "package") {
      const rule = validateCompatiblePackage(entry, where, problems);

      if (rule !== undefined) {
        compatible.push(rule);
      }
    } else {
      problems.push(`${where}: key "match" must be "license" or "package"`);
    }
  });
  return compatible;
}

/** License-form [[compatible]] entry -> rule, or undefined when invalid. */
function validateCompatibleLicense(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatibleLicenseRule | undefined {
  const before = problems.length;

  checkKeys(entry, COMPATIBLE_LICENSE_KEYS, where, problems, COMPATIBLE_LICENSE_REPLACED_KEYS);

  const result = compatibleLicense(entry);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, where));
    return undefined;
  }

  return problems.length === before ? result : undefined;
}

/**
 * The `where` value as a string array, or undefined when it is not one (arktype reports the shape).
 */
function whereArrayOf(raw: unknown): ReadonlyArray<string> | undefined {
  return Array.isArray(raw) && raw.every((element) => typeof element === "string")
    ? (raw as string[])
    : undefined;
}

/** Package-form [[compatible]] entry -> rule, or undefined when invalid. */
function validateCompatiblePackage(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatiblePackageRule | undefined {
  const before = problems.length;

  checkKeys(entry, COMPATIBLE_PACKAGE_KEYS, where, problems, COMPATIBLE_REPLACED_KEYS);

  const envelope = compatiblePackageEnvelope(entry);

  if (envelope instanceof type.errors) {
    problems.push(...collectArkProblems(envelope, where));
  }

  const scope = whereArrayOf(entry["where"]);

  if (scope !== undefined) {
    problems.push(...formatProblems(where, whereProblems(scope)));
  }

  const selector = compatibleSelectorProblems(entry, scope ?? []);

  problems.push(...formatProblems(where, selector.problems));

  const parents = asDependencyOfProblems(entry);

  problems.push(...formatProblems(where, parents.problems));

  if (
    envelope instanceof type.errors ||
    parents.asDependencyOf === undefined ||
    problems.length !== before
  ) {
    return undefined;
  }

  return {
    match: "package",
    ...selector.selector,
    asDependencyOf: parents.asDependencyOf,
    rationale: envelope.rationale,
    where: envelope.where,
    ...(envelope.comment !== undefined ? { comment: envelope.comment } : {}),
  };
}
