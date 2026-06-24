/**
 * Custom bun.lock collector — the one conscious exception to
 * orchestrate-don't-parse, because no upstream tool reads bun.lock correctly:
 * - cdxgen (`-t js` and `-t bun`) and syft emit 0 components (no bun.lock
 *   parser/cataloger);
 * - trivy parses bun.lock but corrupts identity on nested version-conflict
 *   entries, producing purls that can never resolve as a merge/enrichment key.
 *
 * bun.lock is machine-written JSONC (JSON + trailing commas, never comments):
 * a trailing-comma strip + JSON.parse reads it with zero new dependencies.
 * Identity always comes from packages[key][0] ("name@version", split at the
 * first "@" after the optional leading scope — the version part of
 * non-registry resolutions can itself contain "@", see splitSpec) — never from
 * the key, which is the trivy failure mode. First-party exclusion lives here:
 * `@workspace:` protocol entries plus workspaces[*].name members are never
 * emitted.
 *
 * The emitted document is a minimal, deterministic CycloneDX 1.6 bom.json (no
 * serialNumber, no timestamp, components sorted compareCodeUnits by purl)
 * written into the per-run temp dir — the existing SBOM parse path consumes it
 * unchanged. The cache key reuses computeCacheKey with the shared framing
 * contract.
 *
 * Fully in-process — no subprocess, no eval, no cwd change; a
 * MAX_BUN_LOCK_BYTES stat gate bounds memory before any read/parse; whole-file
 * parse failure throws loudly (the scan-failure path) while malformed
 * individual entries are skipped via a tolerant walk.
 */

import {
  existsSync,
  mkdtempSync,
  statSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type } from "arktype";

import { BunLockDocument } from "../validate/bunLock";
import { recordOf } from "../validate/record";
import { computeCacheKey, type CollectorSbomFile } from "./cdxgen";
import { manifestFilesFor } from "./dispatch";
import type { Target } from "../targets/target";

/**
 * Collector identity (the CLI prints `${name}@${version}`). Version bumps when
 * the emission or scope semantics change — it is hashed into the cache key, so
 * a bump invalidates cache entries on purpose.
 */
export const BUN_COLLECTOR_TOOL = {
  name: "bun-lock-collector",
  version: "1",
} as const;

/**
 * DoS bound: real bun.lock files are <2 MB; 32 MiB is generous headroom. The
 * stat gate fires before any read or parse so a hostile file can never balloon
 * memory.
 */
export const MAX_BUN_LOCK_BYTES = 32 * 1024 * 1024;

/**
 * Stat-gate a bun.lock path against MAX_BUN_LOCK_BYTES before any read or
 * parse. Shared by collectWithBunLock and the CLI loop — the CLI reads the
 * full lockfile text for the coverage counter before the collector ever runs,
 * so every entry point that touches bun.lock must honor the same
 * single-sourced cap and loud message.
 */
export function assertBunLockSize(lockPath: string): void {
  const size = statSync(lockPath).size;
  if (size > MAX_BUN_LOCK_BYTES) {
    throw new Error(
      `bun.lock at ${lockPath} is ${size} bytes, over the ` +
        `${MAX_BUN_LOCK_BYTES}-byte cap — refusing to parse it ` +
        `(real bun lockfiles are <2 MB)`,
    );
  }
}

/**
 * The constant pseudo-argv hashed into the cache key. There is no real
 * subprocess invocation to hash — this sentinel plays the role cdxgenCacheArgs
 * plays for cdxgen targets, and changes only when the collector's observable
 * behavior changes (alongside the tool version).
 */
const BUN_CACHE_ARGS = ["bun-collector-v1"];

/**
 * Manifest files hashed into the cache key — derived from the single source
 * (dispatch.ts) so the collector's cache-key framing can never drift from the
 * dispatch table's bun entry.
 */
const BUN_MANIFEST_FILES = manifestFilesFor("bun");

/**
 * Property name cdxgen uses to mark JS dev dependencies — emitted here so
 * merge.ts's propertyDevMarker consumes bun components unchanged. Local
 * constant on purpose: merge/ is a different layer and is never imported from
 * scanners.
 */
const DEV_PROPERTY = "cdx:npm:package:development";

/**
 * Strip trailing commas so machine-written JSONC parses with JSON.parse. The
 * regex only touches a comma directly before a `}`/`]` closer; bun.lock string
 * values (names, semvers, sha512 base64, workspace paths) cannot contain
 * `}`/`]` after a comma, so it is a no-op on strict JSON.
 */
function stripTrailingCommas(text: string): string {
  return text.replace(/,(\s*[}\]])/g, "$1");
}

/** packages[key] value[0] when it is a string in an array, else undefined. */
function specOf(value: unknown): string | undefined {
  if (!Array.isArray(value)) return undefined;
  const first: unknown = value[0];
  return typeof first === "string" ? first : undefined;
}

/**
 * Split "name@version" at the first "@" after the optional leading scope
 * marker. npm package names cannot contain "@" past the scope, so that "@" is
 * always the name/version separator — for registry semvers
 * ("@types/bun@1.3.14") and for non-registry resolutions whose version part
 * embeds further "@"s, which a last-"@" split silently corrupts:
 *
 *   "pkg@git+ssh://git@github.com/owner/repo#abc" → name "pkg"
 *   "alias@npm:@scope/real@1.2.3"                 → name "alias"
 *
 * Returns undefined for specs without a version separator (malformed →
 * tolerant skip).
 */
function splitSpec(
  spec: string,
): { name: string; version: string } | undefined {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  if (at <= 0) return undefined; // no separator, or a bare leading-@ scope
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/**
 * purl with the scope's leading "@" encoded as %40 and "+" in the version
 * encoded as %2B (purl-spec percent-encoding) — byte-identical to cdxgen's npm
 * purl output, so a build-metadata version ("1.0.0+build") reached via both a
 * bun target and an npm/yarn target folds into one row.
 */
function purlOf(name: string, version: string): string {
  const encodedName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  const encodedVersion = version.replaceAll("+", "%2B");
  return `pkg:npm/${encodedName}@${encodedVersion}`;
}

/**
 * Third-party entry count for the coverage policy:
 * - a number when the grammar positively determines it (entries whose value[0]
 *   is a string lacking "@workspace:"; malformed entries contribute nothing);
 * - undefined when the text is unparseable or carries no packages record
 *   (unknown → route to scan; the collector itself then throws loudly and zero
 *   components hard-fail, never a silent skip).
 */
export function bunThirdPartyEntryCount(
  lockfileText: string,
): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripTrailingCommas(lockfileText));
  } catch {
    return undefined;
  }
  // A failed document narrow is the unknown path — same as no packages map.
  const doc = BunLockDocument(parsed);
  if (doc instanceof type.errors) return undefined;
  const packages = doc.packages;
  if (packages === undefined) return undefined;
  let count = 0;
  for (const value of Object.values(packages)) {
    const spec = specOf(value);
    if (spec !== undefined && !spec.includes("@workspace:")) {
      count += 1;
    }
  }
  return count;
}

/** Importer/metadata maps whose keys are PROD dependency roots/edges. */
const PROD_DEP_FIELDS = [
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

/** Tolerantly collect dependency names from the given maps of a record. */
function depNamesOf(
  record: Record<string, unknown>,
  fields: readonly string[],
): string[] {
  const names: string[] = [];
  for (const field of fields) {
    const deps = recordOf(record[field]);
    if (deps !== undefined) {
      names.push(...Object.keys(deps));
    }
  }
  return names;
}

/**
 * Transitive dev/prod scope: BFS over the lockfile's dependency edges, prod
 * roots first, mirroring cdxgen's _markTreeDevelopment semantics — a package
 * reachable from both a prod and a dev root stays prod (prod-direct-wins).
 *
 * Roots: every workspaces[path] importer contributes its
 * dependencies/optionalDependencies/peerDependencies names as prod roots and
 * its devDependencies names as dev roots.
 *
 * Edge resolution uses bun's hoisting lookup: a dep name in the context of a
 * parent resolves to packages["<parentChain>/<depName>"], then progressively
 * shorter parent chains, then the bare packages["<depName>"] — so nested
 * version-conflict entries are reached via their parent and their scope
 * follows the parent's path. The chain is an array of whole package names,
 * shortened one name per step: scoped names contain "/", so shortening the raw
 * key string one path segment at a time could cross a scope boundary and
 * resolve a bare dep "y" of parent "@scope/pkg" against an unrelated top-level
 * "@scope/y".
 *
 * Conservative direction: unknown dep names (no packages entry at any lookup)
 * are silent leaves; unvisited packages stay prod. A visited set bounds the
 * traversal to one visit per packages key; dep edges are read tolerantly from
 * each entry's value[2] metadata object (absent or malformed → leaf).
 */
function transitiveDevKeys(
  packages: Record<string, unknown>,
  workspaces: Record<string, unknown>,
): ReadonlySet<string> {
  // Hoisting lookup: candidate keys are rebuilt from the parent's chain of
  // whole package names — "<chain>/<depName>" with the chain truncated one
  // name (which may itself contain "/" for scoped packages) per step, down to
  // the bare top-level "<depName>". Never substring or path-segment prefixes:
  // those can cross a scope boundary.
  const resolveChain = (
    parentChain: readonly string[],
    depName: string,
  ): readonly string[] | undefined => {
    for (let length = parentChain.length; length >= 0; length -= 1) {
      const chain = [...parentChain.slice(0, length), depName];
      if (chain.join("/") in packages) return chain;
    }
    return undefined;
  };

  // Dep edges of a packages entry: the dependency maps in value[2].
  const depsOf = (key: string): string[] => {
    const value = packages[key];
    const metadata = Array.isArray(value) ? recordOf(value[2]) : undefined;
    if (metadata === undefined) return [];
    return depNamesOf(metadata, PROD_DEP_FIELDS);
  };

  // Roots from every importer. Root names resolve in the importer's own
  // parent context (a one-name chain of its package name) so member-nested
  // conflict keys like "libb/dep" are honored; the chain walk degrades to
  // the bare lookup.
  const prodRoots: Array<{ parentChain: readonly string[]; name: string }> = [];
  const devRoots: Array<{ parentChain: readonly string[]; name: string }> = [];
  for (const rawImporter of Object.values(workspaces)) {
    const importer = recordOf(rawImporter);
    if (importer === undefined) continue;
    const rawName = importer["name"];
    const importerName = typeof rawName === "string" ? rawName : undefined;
    const parentChain =
      importerName === undefined || importerName === "" ? [] : [importerName];
    for (const name of depNamesOf(importer, PROD_DEP_FIELDS)) {
      prodRoots.push({ parentChain, name });
    }
    for (const name of depNamesOf(importer, ["devDependencies"])) {
      devRoots.push({ parentChain, name });
    }
  }

  const visited = new Set<string>();
  const dev = new Set<string>();
  const traverse = (
    roots: Array<{ parentChain: readonly string[]; name: string }>,
    markDev: boolean,
  ): void => {
    const queue: Array<readonly string[]> = [];
    const enqueue = (chain: readonly string[] | undefined): void => {
      if (chain === undefined) return;
      const key = chain.join("/");
      if (visited.has(key)) return;
      visited.add(key);
      if (markDev) dev.add(key);
      queue.push(chain);
    };
    for (const root of roots) {
      enqueue(resolveChain(root.parentChain, root.name));
    }
    for (let i = 0; i < queue.length; i += 1) {
      const chain = queue[i] as readonly string[];
      for (const depName of depsOf(chain.join("/"))) {
        enqueue(resolveChain(chain, depName));
      }
    }
  };
  // Prod first, marking visited; the dev pass then marks only unvisited keys —
  // anything prod-reachable was already fully traversed, so a dev path can
  // never re-mark it (prod-direct-wins).
  traverse(prodRoots, false);
  traverse(devRoots, true);
  return dev;
}

interface BunComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  properties?: Array<{ name: string; value: string }>;
}

/**
 * Emit one component per third-party packages entry (duplicate purls from
 * nested conflict keys kept; the fold to one row happens at merge).
 *
 * First-party exclusion belt-and-braces: workspaces[*].name members are
 * never emitted even if an entry lacks the @workspace: protocol.
 */
function componentsOf(
  packages: Record<string, unknown>,
  workspaces: Record<string, unknown>,
): BunComponent[] {
  const memberNames = new Set<string>();
  for (const member of Object.values(workspaces)) {
    const name = recordOf(member)?.["name"];
    if (typeof name === "string") {
      memberNames.add(name);
    }
  }

  const devKeys = transitiveDevKeys(packages, workspaces);

  const components: BunComponent[] = [];
  for (const [key, value] of Object.entries(packages)) {
    const spec = specOf(value);
    if (spec === undefined) continue; // malformed entry — tolerant skip
    if (spec.includes("@workspace:")) continue; // first-party member
    const identity = splitSpec(spec);
    if (identity === undefined) continue; // malformed spec — tolerant skip
    if (memberNames.has(identity.name)) continue; // belt-and-braces
    const component: BunComponent = {
      type: "library",
      name: identity.name,
      version: identity.version,
      purl: purlOf(identity.name, identity.version),
    };
    if (devKeys.has(key)) {
      component.properties = [{ name: DEV_PROPERTY, value: "true" }];
    }
    components.push(component);
  }

  // compareCodeUnits by purl. Array.prototype.sort is stable, so
  // duplicate-purl nested entries keep the lockfile's key order — the whole
  // emission is a pure function of the lockfile bytes.
  components.sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  return components;
}

/** Options mirror the cdxgen adapter's per-run temp-dir injection point. */
export interface BunCollectOptions {
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/**
 * Scan a bun target by reading only bun.lock inside it (no subprocess, no cwd
 * change) and writing a minimal deterministic CycloneDX 1.6 bom.json into the
 * per-run temp dir.
 *
 * Async for interface symmetry with collectWithCdxgen (keeps a future
 * generator swap cheap).
 *
 * Failure modes:
 * - missing bun.lock / package.json → target.ts-shaped error;
 * - bun.lock over MAX_BUN_LOCK_BYTES → loud error naming path, size, cap,
 *   before any read or parse;
 * - non-JSONC text → loud error naming the path (the scan-failure path);
 * - malformed individual packages entries → skipped silently.
 */
export async function collectWithBunLock(
  target: Target,
  opts: BunCollectOptions = {},
): Promise<CollectorSbomFile> {
  const lockPath = join(target.dir, "bun.lock");
  if (!existsSync(lockPath)) {
    throw new Error(
      `target "${target.identity}" is missing bun.lock: expected ${lockPath}`,
    );
  }

  // Size gate FIRST — before read, before parse (DoS bound).
  assertBunLockSize(lockPath);

  const text = readFileSync(lockPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripTrailingCommas(text));
  } catch (error) {
    throw new Error(
      `bun.lock at ${lockPath} is not valid JSONC: ${String(error)}`,
      { cause: error },
    );
  }

  // Each map is narrowed INDEPENDENTLY (recordOf), so a wrong-typed sibling
  // field never zeroes the other: a failed narrow yields {} (the old
  // record-narrow-undefined path → empty map, zero components, loud
  // zero-component hard fail).
  const narrowed = BunLockDocument(parsed);
  const packages =
    (narrowed instanceof type.errors ? undefined : narrowed.packages) ?? {};
  const workspaces =
    recordOf((parsed as { workspaces?: unknown })?.workspaces) ?? {};

  const components = componentsOf(packages, workspaces);

  // Minimal deterministic CycloneDX 1.6: bomFormat/specVersion/components
  // only — deliberately no serialNumber, no metadata.timestamp, so the
  // volatile fields the merge must never see cannot leak.
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components,
  };

  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const sbomPath = join(tempDir, "bom.json");
  writeFileSync(sbomPath, `${JSON.stringify(doc, null, 2)}\n`);

  return {
    sbomPath,
    // Shared cache-key framing contract — reused, never duplicated.
    cacheKey: computeCacheKey(
      target,
      BUN_COLLECTOR_TOOL,
      BUN_CACHE_ARGS,
      BUN_MANIFEST_FILES,
    ),
    tool: BUN_COLLECTOR_TOOL,
  };
}
