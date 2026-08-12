/**
 * purl → ordered locally-present scan-candidate mapper (no registry/collector analog exists for
 * this). npm: an index of EVERY installed package dir under `<targetDir>/node_modules`, at any
 * nesting depth (a yarn node-modules-linker install hoists one version to the workspace root and
 * nests every other required version inside a dependent's own node_modules - see {@link
 * buildNpmSourceIndex}), looked up by decoded name + the purl's version MANDATORILY equal to the
 * installed `package.json` version (a stale node_modules must never poison the cache with the wrong
 * version's license). pypi: an in-project `.venv`'s site-packages, keyed by the PEP-503 structural
 * fold of the dist-info dir name (ADR-0015: the dir name IS the signal, no PEP-440/508 parsing)
 * - the dist-info dir itself is the first candidate (a wheel's METADATA and legal files live there,
 * not in the import package), the top_level.txt import package dir the second. Everything else, or
 * any structural mismatch, returns [] - an honest skip, never a fabricated guess. A `..`-shaped or
 * absolute-path-shaped top_level.txt line can never escape site-packages (resolve + strict
 * prefix-check); the npm index carries no equivalent risk by construction - it is built entirely
 * from real directory entries the walk itself discovered, never from a join against caller- or
 * purl-controlled input.
 */
import { existsSync, readdirSync, readFileSync, type Dirent } from "node:fs";
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

/** `name@version` -> the winning installed dir, as produced by {@link buildNpmSourceIndex}. */
export type NpmSourceIndex = Map<string, string>;

/**
 * Per-run cache of {@link NpmSourceIndex}, keyed by the resolved target dir it was built from.
 * Built lazily by the first npm lookup for a given target dir and reused for the rest of the run
 * - callers own the cache's lifetime (assess.ts's ScanContext, built once per intensive scan pass)
 * so this module carries no module-level state and needs no test-visible reset.
 */
export type NpmSourceIndexCache = Map<string, NpmSourceIndex>;

/**
 * Defensive nesting-depth backstop for the node_modules walk. The real loop/cost guard is
 * symlink-refusal in {@link walkNodeModules} - this only bounds a pathological non-symlink
 * structure that would otherwise recurse indefinitely.
 */
const MAX_NODE_MODULES_DEPTH = 30;

/**
 * The package.json `version` field at dir, or undefined on ANY structural mismatch - absent,
 * unparseable, or a non-string field (a garbage node_modules entry must never throw and kill the
 * walk, the honest-skip posture this whole module keeps).
 */
function readInstalledVersion(pkgDir: string): string | undefined {
  const packageJsonPath = join(pkgDir, "package.json");

  if (!existsSync(packageJsonPath)) {
    return undefined;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  } catch {
    return undefined;
  }

  const version = (parsed as { version?: unknown }).version;

  return typeof version === "string" ? version : undefined;
}

/**
 * The deterministic winner between two dirs indexed under the same `name@version`: the shorter path
 * wins (closer to the workspace root is the more "normal" install), a tie broken lexicographically
 * ({@link compareCodeUnits}) - never insertion/walk order, so the result is identical regardless of
 * readdir's platform-dependent ordering.
 */
function preferShorterThenLexicographic(a: string, b: string): string {
  if (a.length !== b.length) {
    return a.length < b.length ? a : b;
  }

  return compareCodeUnits(a, b) <= 0 ? a : b;
}

/** readdirSync(withFileTypes) wrapped so a missing/unreadable dir is an honest empty list. */
function safeReaddirDirents(dir: string): Dirent[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/**
 * Index one candidate package dir (its package.json version, if present and parseable) and then
 * descend into its OWN nested node_modules, if any - the one recursive step that finds a
 * non-hoisted version installed under a dependent's node_modules.
 */
function indexPackageDir(pkgDir: string, name: string, index: NpmSourceIndex, depth: number): void {
  const version = readInstalledVersion(pkgDir);

  if (version !== undefined) {
    const key = `${name}@${version}`;
    const existing = index.get(key);

    index.set(
      key,
      existing === undefined ? pkgDir : preferShorterThenLexicographic(existing, pkgDir),
    );
  }

  walkNodeModules(join(pkgDir, "node_modules"), index, depth + 1);
}

/** Index every package dir directly under a `node_modules/@scope` namespace dir. */
function indexScopeDir(
  scopeDir: string,
  scopeName: string,
  index: NpmSourceIndex,
  depth: number,
): void {
  const entries = [...safeReaddirDirents(scopeDir)].sort((a, b) =>
    compareCodeUnits(a.name, b.name),
  );

  for (const entry of entries) {
    // Symlinks report isDirectory() === false on Dirent entries (discover.ts's walk idiom), so a
    // directory symlink - a yarn/npm workspace member is one - is never followed: excluding it is
    // correct (it names first-party workspace code, not an installed copy) and it is what keeps a
    // symlink cycle from ever being entered in the first place.
    if (!entry.isDirectory()) {
      continue;
    }

    indexPackageDir(join(scopeDir, entry.name), `${scopeName}/${entry.name}`, index, depth);
  }
}

/**
 * Recursively index every installed package dir under a node_modules root, at ANY nesting depth, by
 * descending ONLY through `node_modules -> package -> node_modules` chains - never a package's
 * other subdirectories (src/, dist/, test fixtures, ...), which carry no further node_modules of
 * interest and would make the walk needlessly expensive. Both `node_modules/<name>` and
 * `node_modules/@scope/<name>` shapes are indexed. Entries are visited in {@link
 * compareCodeUnits}-sorted order so the walk itself is deterministic (the duplicate tie-break in
 * {@link preferShorterThenLexicographic} does not depend on it, but determinism here costs nothing
 * and rules out any platform-readdir-order surprise).
 */
function walkNodeModules(nodeModulesDir: string, index: NpmSourceIndex, depth: number): void {
  if (depth > MAX_NODE_MODULES_DEPTH) {
    return;
  }

  const entries = [...safeReaddirDirents(nodeModulesDir)].sort((a, b) =>
    compareCodeUnits(a.name, b.name),
  );

  for (const entry of entries) {
    // Symlinks report isDirectory() === false on Dirent entries; see indexScopeDir for why that is
    // exactly the loop guard this walk needs.
    if (!entry.isDirectory()) {
      continue;
    }

    if (entry.name.startsWith("@")) {
      indexScopeDir(join(nodeModulesDir, entry.name), entry.name, index, depth);
      continue;
    }

    indexPackageDir(join(nodeModulesDir, entry.name), entry.name, index, depth);
  }
}

/**
 * Build the full `name@version` -> dir index for one target dir's node_modules tree: ONE
 * readdir-walk regardless of how many npm purls are subsequently looked up against it. Only ever
 * runs under `--intensive`, and only when the first npm purl actually needs a lookup for this
 * target dir (a pypi-only analysis set, or a target dir with nothing left unmemoized, never pays
 * for this walk).
 */
function buildNpmSourceIndex(targetDir: string): NpmSourceIndex {
  const index: NpmSourceIndex = new Map();

  walkNodeModules(resolve(targetDir, "node_modules"), index, 0);

  return index;
}

/**
 * The index for a resolved target dir - built once and cached under it, or built fresh every call
 * when no cache is supplied (the direct-call/test shape, where reuse across lookups does not
 * matter).
 */
function npmSourceIndexFor(
  targetDir: string,
  cache: NpmSourceIndexCache | undefined,
): NpmSourceIndex {
  if (cache === undefined) {
    return buildNpmSourceIndex(targetDir);
  }

  const key = resolve(targetDir);
  const cached = cache.get(key);

  if (cached !== undefined) {
    return cached;
  }

  const built = buildNpmSourceIndex(targetDir);

  cache.set(key, built);

  return built;
}

/**
 * Decode an npm purl's encoded name and look it up in the target dir's npm source index at the
 * exact `name@version` key, returning the winning installed dir or undefined on ANY structural
 * mismatch - the name never matches any installed package, or it does but no installed copy (at any
 * nesting depth) carries this exact version.
 */
function npmSourceDir(
  purl: EcosystemPurl,
  targetDir: string,
  cache?: NpmSourceIndexCache,
): string | undefined {
  // The decode exactly mirrors npmPackumentUrl's scoped-name decode (enrich.ts npmPackumentUrl):
  // "%40scope/pkg" -> "@scope/pkg".
  const name = safeDecode(purl.encodedName);

  if (name === undefined) {
    return undefined;
  }

  return npmSourceIndexFor(targetDir, cache).get(`${name}@${purl.version}`);
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

  if (!existsSync(libDir)) {
    return fallback;
  }

  const pythonDirs = safeReaddir(libDir)
    .filter((e) => e.startsWith("python"))
    .sort(compareCodeUnits);
  const chosen = pythonDirs[0];

  return chosen === undefined ? fallback : join(libDir, chosen, "site-packages");
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
 * (resolve + strict prefix-check, mirrored below in {@link topLevelPackageDir}).
 */
function pypiSourceDirs(purl: EcosystemPurl, targetDir: string): string[] {
  const venvDir = join(targetDir, ".venv");
  // Resolved once up front so both sides of the containment check below compare canonical absolute
  // paths.
  const sitePackages = resolve(sitePackagesDir(venvDir));

  if (!existsSync(sitePackages)) {
    return [];
  }

  const name = safeDecode(purl.encodedName);

  if (name === undefined) {
    return [];
  }

  const folded = pep503Fold(`${name}-${purl.version}`);

  const entries = safeReaddir(sitePackages);
  const distInfoName = entries.find(
    (e) => e.endsWith(".dist-info") && pep503Fold(e.slice(0, -".dist-info".length)) === folded,
  );

  if (distInfoName === undefined) {
    return [];
  }

  const distInfoDir = join(sitePackages, distInfoName);
  const packageDir = topLevelPackageDir(sitePackages, distInfoDir);

  return packageDir === undefined ? [distInfoDir] : [distInfoDir, packageDir];
}

/**
 * The `top_level.txt`-named import package dir inside site-packages, or undefined when
 * absent/unreadable/empty or when no named sibling exists.
 */
function topLevelPackageDir(sitePackages: string, distInfoDir: string): string | undefined {
  const topLevelPath = join(distInfoDir, "top_level.txt");

  if (!existsSync(topLevelPath)) {
    return undefined;
  }

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
  const rootWithSep = sitePackages.endsWith(sep) ? sitePackages : `${sitePackages}${sep}`;

  for (const candidate of candidates) {
    const packageDir = resolve(sitePackages, candidate);

    if (!packageDir.startsWith(rootWithSep)) {
      continue;
    } // escape attempt: skip

    if (existsSync(packageDir)) {
      return packageDir;
    }
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
 *
 * `npmIndexCache` is optional and purely a performance seam: when supplied, each target dir's npm
 * source index ({@link buildNpmSourceIndex}) is built at most once and reused across every purl
 * looked up against this same cache - the one-readdir-walk-per-workspace contract. Omitted, a fresh
 * index is built on every call (correct, just uncached - the direct-call/test shape).
 */
export function sourceDirsFor(
  purl: string,
  targetDirs: string[],
  npmIndexCache?: NpmSourceIndexCache,
): string[] {
  const parsed = parsePurl(purl);

  if (parsed === undefined) {
    return [];
  }

  if (parsed.type !== "npm" && parsed.type !== "pypi") {
    return [];
  }

  const sortedDirs = [...targetDirs].sort(compareCodeUnits);

  for (const targetDir of sortedDirs) {
    if (parsed.type === "npm") {
      const found = npmSourceDir(parsed, targetDir, npmIndexCache);

      if (found !== undefined) {
        return [found];
      }
    } else {
      const found = pypiSourceDirs(parsed, targetDir);

      if (found.length > 0) {
        return found;
      }
    }
  }

  return [];
}
