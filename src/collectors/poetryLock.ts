/**
 * Poetry prod-purl-set derivation - the python counterpart of the yarn dual-run prod diff.
 *
 * cdxgen invoked with --no-install-deps emits NO group marker on poetry components (no
 * cdx:pyproject:group property), so merge.ts's property-based dev marker can never fire for poetry
 * - every poetry dep classifies prod. This module reads the authoritative source instead:
 * poetry.lock records each
 * package's `groups` array. A package is PROD iff its groups include "main";
 * otherwise it is dev-only. poetryProdPurlSet returns the {@link pypiPurl} set of all PROD
 * packages, which the collector threads into CollectedSbom.prodPurlSet - merge.ts then derives
 * occurrence dev = not in the set, authoritative over the absent markers, and prod-wins for a
 * package in both main and a dev group (it lands in the set).
 *
 * Pure functions: no I/O (the caller reads the file). The prod set is a scope signal whose absence
 * would demote every package to dev, so an unparseable lock throws; malformed individual entries
 * are skipped. smol-toml is already a tool dependency (policy parsing).
 */

import { parse as parseToml } from "smol-toml";

import {
  asPurl,
  compareCodeUnits,
  encodePurlSegment,
  type Purl,
  type TargetIdentity,
} from "../model/dependencies";
import { recordOf, stringOf } from "../validate/record";

/**
 * PEP 503 name normalization - the exact transform cdxgen applies before emitting a
 * `pkg:pypi/<name>` purl: lowercase, and replace every run of `[-_.]+` with a single hyphen.
 * Verified against the dogfood run: every one of the 114 poetry.lock package names maps 1:1 to a
 * cdxgen pypi purl under this rule (e.g. jinja2-ansible-filters, argon2-cffi-bindings).
 */
export function normalizePep503(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/** The `pkg:pypi/<pep503-name>@<version>` purl cdxgen emits for a poetry.lock package. */
export function pypiPurl(name: string, version: string): Purl {
  return asPurl(
    `pkg:pypi/${encodePurlSegment(normalizePep503(name))}@${encodePurlSegment(version)}`,
  );
}

/**
 * True iff the package's `groups` value marks it as a production dependency. poetry.lock's `groups`
 * is an array of strings; a package belongs to prod iff the array includes "main". An absent or
 * non-array `groups` defaults to ["main"] (prod) - matching poetry's own default group and the
 * conservative "unknown → prod" posture (a shipped dep must never be silently dev-dropped).
 */
function isProdGroups(groups: unknown): boolean {
  if (!Array.isArray(groups)) {
    return true;
  } // absent/garbage → default "main"

  return groups.some((g) => stringOf(g) === "main");
}

/**
 * The `[[package]]` entries of a poetry.lock, unvalidated; empty when the lock has none.
 *
 * @throws When the text is not TOML, or `package` is present but not an array of tables.
 */
function lockPackagesOf(lockfileText: string, lockPath: string): readonly unknown[] {
  let parsed: unknown;

  try {
    parsed = parseToml(lockfileText);
  } catch (error) {
    throw new Error(`poetry.lock at ${lockPath} is not valid TOML: ${String(error)}`, {
      cause: error,
    });
  }

  const packages = recordOf(parsed)?.["package"];

  if (packages === undefined) {
    return [];
  }

  if (!Array.isArray(packages)) {
    throw new Error(
      `poetry.lock at ${lockPath} has a "package" key that is not an array of tables`,
    );
  }

  return packages;
}

/**
 * Parse poetry.lock text and return the prod-purl set: one {@link pypiPurl} per `[[package]]` whose
 * groups include "main". A package missing a string name or version contributes nothing (cannot
 * form a purl).
 *
 * @param lockPath - Named in the error message only.
 * @returns An empty set when the lock lists no main-group package.
 * @throws When the lockfile cannot be read as a poetry.lock.
 */
export function poetryProdPurlSet(lockfileText: string, lockPath: string): ReadonlySet<Purl> {
  const purls = new Set<Purl>();

  for (const raw of lockPackagesOf(lockfileText, lockPath)) {
    const pkg = recordOf(raw);

    if (pkg === undefined) {
      continue;
    }

    if (!isProdGroups(pkg["groups"])) {
      continue;
    }

    const name = stringOf(pkg["name"]);
    const version = stringOf(pkg["version"]);

    if (name === undefined || version === undefined) {
      continue;
    }

    purls.add(pypiPurl(name, version));
  }

  return purls;
}

/** Most unmatched purls named in the warning before the rest are summarised as a count. */
const UNMATCHED_PURLS_LISTED = 10;

/**
 * The warning for production packages in poetry.lock that match no scanned component purl. A miss
 * is informational, not a gate: a lock entry can be legitimately absent from the scan
 * (platform-conditional dependencies the generator skipped on this host), so the line points at
 * possible spelling drift without failing the run.
 *
 * @returns undefined when either set is empty or every production purl is scanned. When none
 * match, a stronger message states that the whole target is classified development-only.
 */
export function unmatchedProdPurlSetWarning(
  identity: TargetIdentity,
  prodPurlSet: ReadonlySet<Purl>,
  componentPurls: ReadonlySet<Purl>,
): string | undefined {
  if (prodPurlSet.size === 0 || componentPurls.size === 0) {
    return undefined;
  }

  const unmatched = [...prodPurlSet].filter((purl) => !componentPurls.has(purl));

  if (unmatched.length === 0) {
    return undefined;
  }

  if (unmatched.length === prodPurlSet.size) {
    return (
      `${identity}: none of the ${prodPurlSet.size} production packages in poetry.lock matches a` +
      " scanned component purl, so every package of this target is classified development-only"
    );
  }

  unmatched.sort(compareCodeUnits);
  const listed = unmatched.slice(0, UNMATCHED_PURLS_LISTED).join(", ");
  const rest = unmatched.length - UNMATCHED_PURLS_LISTED;
  const more = rest > 0 ? `, +${rest} more` : "";

  return (
    `${identity}: ${unmatched.length} of ${prodPurlSet.size} production packages in poetry.lock` +
    ` matched no scanned component: ${listed}${more}`
  );
}
