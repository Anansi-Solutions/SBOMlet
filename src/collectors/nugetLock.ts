/**
 * Custom packages.lock.json (NuGet) collector - a conscious exception to orchestrate-don't-parse,
 * because no upstream generator earns the subprocess on this input:
 * - cdxgen `-t dotnet` reads packages.lock.json but hard-fails (its own schema validation: a
 *   duplicated project ref violates `uniqueItems`, exit 1, no output file) on single-project
 *   layouts - the most common
 *   real-world shape - and emits zero license/scope data when it succeeds;
 * - syft's lock cataloger re-emits the same lock entries with no
 *   per-target scoping and no cross-lockfile dedup;
 * - cyclonedx-dotnet runs a package restore inside the scanned target (the exact side effect the
 *   wrapper posture forbids), or silently emits zero
 *   components on a fresh clone with restore disabled;
 * - Microsoft sbom-tool emits SPDX only, every license NOASSERTION, with a volatile per-run
 *   document namespace.
 * The decision and its fixture evidence are recorded in ADR-0022
 * (docs/explanation/adr/0022-dotnet-lockfile-in-process.md).
 *
 * packages.lock.json is committed, plain strict JSON with a documented schema - the same parsing
 * class as the in-tree package-lock.json handling. The `dependencies` map holds one section per
 * target framework (and per `<tfm>/<rid>` pair when runtime identifiers are set); every entry
 * carries `type` (Direct | Transitive | Project | CentralTransitive) and, except for first-party
 * Project references, a `resolved` exact version. Restore normalizes package ids in the lock to
 * their canonical registry casing, so the emitted purls keep the lock keys VERBATIM (never
 * lowercased) and fold across targets and tools.
 *
 * First-party exclusion lives here: entries with `type === "Project"` (a project reference
 * - lowercased, version-less) are never emitted. The exclusion is that one type check ONLY, never
 * an inclusion list, so an unknown future entry type can never silently drop a real dependency. The
 * lock carries NO dev/prod marker (development-only packages appear as plain Direct entries), so no
 * prodPurlSet is derived: every NuGet occurrence classifies prod, the safe direction that always
 * gates.
 *
 * The emitted document is a minimal, deterministic CycloneDX 1.6 bom.json (no serialNumber, no
 * timestamp, components sorted compareCodeUnits by purl) written into the per-run temp dir - the
 * existing SBOM parse path consumes it unchanged. The cache key reuses computeCacheKey with the
 * shared framing contract.
 *
 * Fully in-process - no subprocess, no eval, no cwd change; a
 * MAX_NUGET_LOCK_BYTES stat gate bounds memory before any read/parse;
 * whole-file parse failure and an unsupported lock format version throw loudly (the scan-failure
 * path) while malformed individual entries are skipped via a tolerant walk.
 */

import { existsSync, mkdtempSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type } from "arktype";

import { NugetLockDocument } from "../validate/nugetLock";
import { recordOf, stringOf } from "../validate/record";
import { asPurl, type Purl } from "../model/dependencies";
import { computeCacheKey, type CollectorSbomFile } from "./cdxgen";
import { manifestFilesFor } from "./dispatch";
import type { Target } from "../targets/target";

/**
 * Collector identity (the CLI prints `${name}@${version}`). Version bumps when the emission or
 * scope semantics change - it is hashed into the cache key, so a bump invalidates cache entries on
 * purpose.
 */
export const NUGET_COLLECTOR_TOOL = {
  name: "nuget-lock-collector",
  version: "1",
} as const;

/**
 * DoS bound: real packages.lock.json files are well under 2 MB even on large multi-TFM projects; 32
 * MiB is generous headroom. The stat gate fires before any read or parse so a hostile file can
 * never balloon memory.
 */
export const MAX_NUGET_LOCK_BYTES = 32 * 1024 * 1024;

/**
 * Stat-gate a packages.lock.json path against MAX_NUGET_LOCK_BYTES before any read or parse. Shared
 * by collectWithNugetLock and the CLI loop - the CLI reads the full lockfile text for the coverage
 * counter before the collector ever runs, so every entry point that touches the lock must honor the
 * same single-sourced cap and loud message.
 */
export function assertNugetLockSize(lockPath: string): void {
  const size = statSync(lockPath).size;

  if (size > MAX_NUGET_LOCK_BYTES) {
    throw new Error(
      `packages.lock.json at ${lockPath} is ${size} bytes, over the ` +
        `${MAX_NUGET_LOCK_BYTES}-byte cap — refusing to parse it ` +
        `(real NuGet lock files are well under 2 MB)`,
    );
  }
}

/**
 * The constant pseudo-argv hashed into the cache key. There is no real subprocess invocation to
 * hash - this sentinel plays the role cdxgenCacheArgs plays for cdxgen targets, and changes only
 * when the collector's observable behavior changes (alongside the tool version).
 */
const NUGET_CACHE_ARGS = ["nuget-collector-v1"];

/**
 * Manifest files hashed into the cache key - derived from the single source (dispatch.ts) so the
 * collector's cache-key framing can never drift from the dispatch table's nuget entry.
 */
const NUGET_MANIFEST_FILES = manifestFilesFor("nuget");

interface NugetComponent {
  type: "library";
  name: string;
  version: string;
  purl: Purl;
}

/**
 * pkg:nuget purl: no namespace, id verbatim from the lock key (restore already normalized it to the
 * canonical registry casing - lowercasing here would break cross-target folding), "+" in the
 * version percent-encoded as %2B (purl-spec). NuGet ids are URL-safe by the package-id grammar
 * (letters, digits, ".", "_", "-"), so no further encoding is needed.
 */
function purlOf(id: string, resolved: string): Purl {
  return asPurl(`pkg:nuget/${id}@${resolved.replaceAll("+", "%2B")}`);
}

/**
 * Walk EVERY section of the dependencies map (one per TFM, plus `<tfm>/<rid>` sub-sections) and
 * collect the distinct (id, resolved) pairs as components: a pair repeated across sections emits
 * once; an id resolved to two different versions emits twice (both are honest inventory). Entries
 * with
 * `type === "Project"` are first-party project references and never emit;
 * malformed entries (non-record value, missing/empty `resolved`) and non-record section values are
 * skipped tolerantly.
 */
function componentsOf(dependencies: Record<string, unknown>): NugetComponent[] {
  const seen = new Set<string>();
  const components: NugetComponent[] = [];

  for (const rawSection of Object.values(dependencies)) {
    const section = recordOf(rawSection);

    if (section === undefined) {
      continue;
    } // non-record section - tolerant skip

    for (const [id, rawEntry] of Object.entries(section)) {
      const entry = recordOf(rawEntry);

      if (entry === undefined) {
        continue;
      } // malformed entry - tolerant skip

      if (entry["type"] === "Project") {
        continue;
      } // first-party project reference

      const resolved = stringOf(entry["resolved"]);

      if (resolved === undefined || resolved === "") {
        continue;
      } // malformed

      const key = `${id}\0${resolved}`;

      if (seen.has(key)) {
        continue;
      } // same (id, resolved) in another section

      seen.add(key);
      components.push({
        type: "library",
        name: id,
        version: resolved,
        purl: purlOf(id, resolved),
      });
    }
  }

  // compareCodeUnits by purl - the emission is a pure function of the lockfile's entry set,
  // independent of JSON key order.
  components.sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  return components;
}

/** Options mirror the cdxgen adapter's per-run temp-dir injection point. */
export interface NugetCollectOptions {
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/**
 * Scan a nuget target by reading only packages.lock.json inside it (no subprocess, no cwd change)
 * and writing a minimal deterministic CycloneDX 1.6 bom.json into the per-run temp dir.
 *
 * Async for interface symmetry with collectWithCdxgen (keeps a future generator swap cheap).
 *
 * Failure modes:
 * - missing packages.lock.json → target.ts-shaped error;
 * - lock over MAX_NUGET_LOCK_BYTES → loud error naming path, size, cap,
 *   before any read or parse;
 * - non-JSON text → loud error naming the path (the scan-failure path);
 * - unsupported lock format version → loud error naming the version;
 * - malformed individual entries → skipped silently.
 */
export async function collectWithNugetLock(
  target: Target,
  opts: NugetCollectOptions = {},
): Promise<CollectorSbomFile> {
  const lockPath = join(target.dir, "packages.lock.json");

  if (!existsSync(lockPath)) {
    throw new Error(
      `target "${target.identity}" is missing packages.lock.json: expected ${lockPath}`,
    );
  }

  // Size gate FIRST - before read, before parse (DoS bound).
  assertNugetLockSize(lockPath);

  const text = readFileSync(lockPath, "utf8");
  let parsed: unknown;

  try {
    // Restore writes strict JSON - no JSONC strip needed.
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`packages.lock.json at ${lockPath} is not valid JSON: ${String(error)}`, {
      cause: error,
    });
  }

  // Tolerant narrow: a failed document narrow yields the empty-map path (zero components → the loud
  // zero-component hard fail downstream).
  const narrowed = NugetLockDocument(parsed);
  const lockDoc = narrowed instanceof type.errors ? undefined : narrowed;
  const version = lockDoc?.version;

  if (version !== undefined && version !== 1 && version !== 2) {
    throw new Error(
      `packages.lock.json at ${lockPath} version ${version} is not ` +
        `supported (supported versions: 1 and 2)`,
    );
  }

  const components = componentsOf(lockDoc?.dependencies ?? {});

  // Minimal deterministic CycloneDX 1.6: bomFormat/specVersion/components only - deliberately no
  // serialNumber, no metadata.timestamp, so the volatile fields the merge must never see cannot
  // leak.
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
    /** Shared cache-key framing contract - reused, never duplicated. */
    cacheKey: computeCacheKey(target, NUGET_COLLECTOR_TOOL, NUGET_CACHE_ARGS, NUGET_MANIFEST_FILES),
    tool: NUGET_COLLECTOR_TOOL,
  };
}
