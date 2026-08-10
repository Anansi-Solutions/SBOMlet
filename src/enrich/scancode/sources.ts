/**
 * purl → ordered locally-present scan-candidate mapper (no registry/collector analog exists for
 * this). npm: the decoded package name under `<targetDir>/node_modules`, with the installed
 * `package.json` version MANDATORILY equal to the purl's version (a stale node_modules must never
 * poison the cache with the wrong version's license). pypi: an in-project `.venv`'s site-packages,
 * keyed by the PEP-503 structural fold of the dist-info dir name (ADR-0015: the dir name IS the
 * signal, no PEP-440/508 parsing) - the dist-info dir itself is the first candidate (a wheel's
 * METADATA and legal files live there, not in the import package), the top_level.txt import package
 * dir the second. Everything else, or any structural mismatch, returns [] - an honest skip, never a
 * fabricated guess. A `..`-shaped or absolute-path-shaped decoded name (or top_level.txt line) can
 * never escape the target's containment root (resolve + strict prefix-check).
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";

import { compareCodeUnits } from "../../model/dependencies";
import { parsePurl } from "../enrich";

/** A `pkg:npm`/`pkg:pypi` purl's ecosystem-relevant fields, from parsePurl. */
interface EcosystemPurl {
  type: string;
  encodedName: string;
  version: string;
}

/**
 * decodeURIComponent wrapped so a malformed percent-encoding (e.g. "%ZZ" in a crafted SBOM purl
 * - SBOM documents are an untrusted shape) is an honest undefined, never a URIError that would kill
 * the whole intensive run (the mapper contract: undefined on ANY structural mismatch).
 */
function safeDecode(encoded: string): string | undefined {
  try {
    return decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
}

/**
 * Decode + validate an npm purl's encoded name against a candidate `node_modules` root, requiring
 * the installed package.json `version` field to equal the purl version (mandatory - never
 * optional). Returns the resolved source dir, or undefined on ANY structural mismatch: dir absent,
 * package.json absent/unparseable (a garbage node_modules must never throw and kill the run
 * - honest skip), version mismatch, or a decoded name that would escape the node_modules root
 * (resolve + strict prefix-check, never best-effort).
 */
function npmSourceDir(
  purl: EcosystemPurl,
  targetDir: string,
): string | undefined {
  // The decode exactly mirrors npmPackumentUrl's scoped-name decode (enrich.ts npmPackumentUrl):
  // "%40scope/pkg" -> "@scope/pkg".
  const name = safeDecode(purl.encodedName);
  if (name === undefined) return undefined;

  const nodeModulesRoot = resolve(targetDir, "node_modules");
  const candidate = resolve(nodeModulesRoot, name);

  // Strict prefix-check under the RESOLVED node_modules root: a ".."-shaped or absolute-path-shaped
  // decoded name can never produce a non-null result outside it. A path-separator-suffixed prefix
  // guards against a sibling-directory false-positive (e.g. "node_modules-evil").
  const rootWithSep = nodeModulesRoot.endsWith(sep)
    ? nodeModulesRoot
    : `${nodeModulesRoot}${sep}`;
  if (candidate !== nodeModulesRoot && !candidate.startsWith(rootWithSep)) {
    return undefined;
  }

  const packageJsonPath = join(candidate, "package.json");
  if (!existsSync(packageJsonPath)) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  } catch {
    // Unparseable package.json -> honest skip, never a throw (a garbage node_modules must not kill
    // the run).
    return undefined;
  }
  const version = (parsed as { version?: unknown }).version;
  if (typeof version !== "string" || version !== purl.version) {
    return undefined;
  }

  return candidate;
}

/**
 * readdirSync wrapped so a missing/unreadable directory is an honest empty list rather than a throw
 * (a garbage or absent venv/node_modules tree must never kill the run).
 */
function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/**
 * The PEP-503 structural fold used ONLY to match a dist-info directory name - literal lower-case +
 * every run of `-`/`_`/`.` collapsed to a single `_` (ADR-0015: abstain over fragile PEP-440/508
 * parsing; the dist-info dir name IS the structural signal, nothing is parsed out of it).
 */
function pep503Fold(value: string): string {
  return value.toLowerCase().replace(/[-_.]+/g, "_");
}

/** Find the first `lib/pythonX.Y/site-packages` dir under a POSIX venv. */
function posixSitePackagesDir(venvDir: string): string {
  const libDir = join(venvDir, "lib");
  const fallback = join(libDir, "site-packages");
  if (!existsSync(libDir)) return fallback;

  const pythonDirs = safeReaddir(libDir)
    .filter((e) => e.startsWith("python"))
    .sort(compareCodeUnits);
  const chosen = pythonDirs[0];
  return chosen === undefined
    ? fallback
    : join(libDir, chosen, "site-packages");
}

/** The platform-appropriate site-packages path under a project `.venv`. */
function sitePackagesDir(venvDir: string): string {
  return process.platform === "win32"
    ? join(venvDir, "Lib", "site-packages")
    : posixSitePackagesDir(venvDir);
}

/**
 * Resolve a pypi purl to its ordered locally-present scan candidates via an in-project `.venv`'s
 * site-packages. The dist-info dir name is the PEP-503 structural fold of `<name>-<version>`
 * (literal lower-case + `-`/`_`/`.` folded); the matched dist-info dir itself is ALWAYS the first
 * candidate - a wheel install puts `METADATA` and the `LICENSE`/`licenses/` legal files there, not
 * inside the import package, so it is where the election lanes' evidence actually lives. The
 * `top_level.txt`-named import package dir (sorted, first entry that exists as a sibling dir)
 * follows as the second candidate when present. Absent venv or absent dist-info -> [] (honest skip,
 * never a fabricated guess). top_level.txt content is fully controlled by the installed package, so
 * a `..`-shaped or absolute-path-shaped line can never name a directory outside site-packages
 * (resolve + strict prefix-check, the npmSourceDir guard).
 */
function pypiSourceDirs(purl: EcosystemPurl, targetDir: string): string[] {
  const venvDir = join(targetDir, ".venv");
  // Resolved once up front so both sides of the containment check below compare canonical absolute
  // paths.
  const sitePackages = resolve(sitePackagesDir(venvDir));
  if (!existsSync(sitePackages)) return [];

  const name = safeDecode(purl.encodedName);
  if (name === undefined) return [];
  const folded = pep503Fold(`${name}-${purl.version}`);

  const entries = safeReaddir(sitePackages);
  const distInfoName = entries.find(
    (e) =>
      e.endsWith(".dist-info") &&
      pep503Fold(e.slice(0, -".dist-info".length)) === folded,
  );
  if (distInfoName === undefined) return [];

  const distInfoDir = join(sitePackages, distInfoName);
  const packageDir = topLevelPackageDir(sitePackages, distInfoDir);
  return packageDir === undefined ? [distInfoDir] : [distInfoDir, packageDir];
}

/**
 * The `top_level.txt`-named import package dir inside site-packages, or undefined when
 * absent/unreadable/empty or when no named sibling exists.
 */
function topLevelPackageDir(
  sitePackages: string,
  distInfoDir: string,
): string | undefined {
  const topLevelPath = join(distInfoDir, "top_level.txt");
  if (!existsSync(topLevelPath)) return undefined;

  let topLevelRaw: string;
  try {
    topLevelRaw = readFileSync(topLevelPath, "utf8");
  } catch {
    return undefined;
  }
  const candidates = topLevelRaw
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .sort(compareCodeUnits);

  // Strict prefix-check under the RESOLVED site-packages root: an attacker-controlled top_level.txt
  // line can never produce a non-null result outside it (or site-packages itself). The
  // separator-suffixed prefix guards against a sibling false-positive ("site-packages-evil").
  const rootWithSep = sitePackages.endsWith(sep)
    ? sitePackages
    : `${sitePackages}${sep}`;
  for (const candidate of candidates) {
    const packageDir = resolve(sitePackages, candidate);
    if (!packageDir.startsWith(rootWithSep)) continue; // escape attempt: skip
    if (existsSync(packageDir)) return packageDir;
  }
  return undefined;
}

/**
 * Map a purl to its ordered locally-present scan candidates across a set of candidate target dirs
 * (probed in {@link compareCodeUnits}-sorted order, first target dir with a structural match wins
 * - determinism regardless of caller-supplied order). npm yields at most one dir; pypi yields the
 * matched dist-info dir first and the top_level.txt import package dir second (the caller scans in
 * order until the first positive answer). npm and pypi are the only supported ecosystems (Pattern
 * 4); every other type - including an unparseable purl - returns [] with zero fs probes beyond the
 * initial parse.
 */
export function sourceDirsFor(purl: string, targetDirs: string[]): string[] {
  const parsed = parsePurl(purl);
  if (parsed === undefined) return [];
  if (parsed.type !== "npm" && parsed.type !== "pypi") return [];

  const sortedDirs = [...targetDirs].sort(compareCodeUnits);
  for (const targetDir of sortedDirs) {
    if (parsed.type === "npm") {
      const found = npmSourceDir(parsed, targetDir);
      if (found !== undefined) return [found];
    } else {
      const found = pypiSourceDirs(parsed, targetDir);
      if (found.length > 0) return found;
    }
  }
  return [];
}
