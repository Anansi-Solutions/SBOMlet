/**
 * Poetry prod-purl-set derivation — the python counterpart of the yarn
 * dual-run prod diff.
 *
 * cdxgen invoked with --no-install-deps emits NO group marker on poetry
 * components (no cdx:pyproject:group property), so merge.ts's property-based
 * dev marker can never fire for poetry — every poetry dep classifies prod.
 * This module reads the authoritative source instead: poetry.lock records each
 * package's `groups` array. A package is PROD iff its groups include "main";
 * otherwise it is dev-only. poetryProdPurlSet returns the
 * `pkg:pypi/<pep503-name>@<version>` purl set of all PROD packages, which the
 * collector threads into CollectedSbom.prodPurlSet — merge.ts then derives
 * occurrence dev = not in the set, authoritative over the absent markers, and
 * prod-wins for a package in both main and a dev group (it lands in the set).
 *
 * Pure function: no I/O (the caller reads the file). Untrusted-text posture
 * matching firstParty.ts and merge.ts: malformed input yields an empty set,
 * never throws. smol-toml is already a tool dependency (policy parsing).
 */

import { parse as parseToml } from "smol-toml";

import { recordOf, stringOf } from "../validate/record";

/**
 * PEP 503 name normalization — the exact transform cdxgen applies before
 * emitting a `pkg:pypi/<name>` purl: lowercase, and replace every run of
 * `[-_.]+` with a single hyphen. Verified against the dogfood run:
 * every one of the 114 poetry.lock package names maps 1:1 to a cdxgen pypi
 * purl under this rule (e.g. jinja2-ansible-filters, argon2-cffi-bindings).
 */
function normalizePep503(name: string): string {
  return name.replace(/[-_.]+/g, "-").toLowerCase();
}

/**
 * True iff the package's `groups` value marks it as a production dependency.
 * poetry.lock's `groups` is an array of strings; a package belongs to prod iff
 * the array includes "main". An absent or non-array `groups` defaults to
 * ["main"] (prod) — matching poetry's own default group and the conservative
 * "unknown → prod" posture (a shipped dep must never be silently dev-dropped).
 */
function isProdGroups(groups: unknown): boolean {
  if (!Array.isArray(groups)) return true; // absent/garbage → default "main"
  return groups.some((g) => stringOf(g) === "main");
}

/**
 * Parse poetry.lock text and return the prod-purl set: one
 * `pkg:pypi/<pep503-name>@<version>` per `[[package]]` whose groups include
 * "main". A package missing a string name or version contributes nothing
 * (cannot form a purl). Returns an empty set for non-TOML / garbage input.
 */
export function poetryProdPurlSet(lockfileText: string): ReadonlySet<string> {
  const purls = new Set<string>();
  let parsed: unknown;
  try {
    parsed = parseToml(lockfileText);
  } catch {
    return purls;
  }
  const doc = recordOf(parsed);
  if (doc === undefined) return purls;
  const packages = doc["package"];
  if (!Array.isArray(packages)) return purls;
  for (const raw of packages) {
    const pkg = recordOf(raw);
    if (pkg === undefined) continue;
    if (!isProdGroups(pkg["groups"])) continue;
    const name = stringOf(pkg["name"]);
    const version = stringOf(pkg["version"]);
    if (name === undefined || version === undefined) continue;
    purls.add(`pkg:pypi/${normalizePep503(name)}@${version}`);
  }
  return purls;
}
