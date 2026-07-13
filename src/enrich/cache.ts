/**
 * Committed purl-keyed enrichment cache: deterministic read/write.
 *
 * The cache is a JSON file committed to the repo (NOT gitignored) so `check`
 * regenerates fully offline. Generate reads it, fetches on miss, and writes
 * results back (including negative entries); check only reads it. The key is
 * the verbatim purl (URL-encoding intact, e.g. `pkg:npm/%40babel/core@7.27.7`)
 * — name@version is immutable upstream, so a hit is valid until the lockfile
 * changes the purl. No hashing, no TTL.
 *
 * Serialization reuses the tool-wide determinism contract (`toSortedJson`):
 * sorted keys, indent 2, LF-only, trailing newline, no timestamp — there is one
 * sorter, not two, so the cache diffs cleanly and the staleness gate stays
 * honest.
 *
 * The cache stores only what it is given. It does NOT decide `resolvable:false`
 * on a fetch failure — the clean-200-empty-only policy lives in the
 * orchestrator, so a transient outage can never become a false negative here.
 * A malformed envelope throws loudly (a poisoned/garbage cache is a
 * config error, distinct from a benign missing file which is empty). The
 * envelope reader is generic ({@link readEnvelope}) so the dedicated ScanCode
 * memo reuses the identical loud-on-malformed posture — one reader, not two.
 */
import { existsSync, readFileSync } from "node:fs";

import { toSortedJson } from "../model/dependencies";

/** Schema version — bump for a clean future invalidation of the whole cache. */
const CACHE_VERSION = 1;

/**
 * One cached resolution, keyed by purl. `license` is the RAW string (resolution
 * to SPDX happens downstream via normalizeRaw), or null for a negative entry.
 * Every entry is produced by a PyPI/npm/GitHub/NuGet lookup — this is the
 * registry enrichment lane and the only lane this file serves. `fetchedFrom`
 * records which registry answered; `via` records which resolver layer won
 * (audit/debug); `resolvable:false` marks a negative entry that must never be
 * re-fetched.
 *
 * `fetchedAt` is an OPTIONAL ISO timestamp stamped (via an injectable clock)
 * ONLY on a NEW `fetchedFrom:"github"` entry on first resolve — it is the
 * audit record for the version-tag license read. It is NEVER written for
 * pypi/npm entries (no backfill, no churn of the existing entries), NEVER for
 * nuget entries (registration/catalog blobs are stable versioned CDN content
 * like the pypi/npm documents — zero churn on warm generates), and NEVER
 * rewritten on a cache hit, so a warm double-generate is byte-identical. It
 * lives ONLY here — never in any output (the determinism control).
 */
export interface CacheEntry {
  license: string | null;
  fetchedFrom: "pypi" | "npm" | "github" | "nuget";
  via: string;
  resolvable: boolean;
  /** ISO timestamp on NEW github entries only (injectable-clock-stamped). */
  fetchedAt?: string;
}

/** The on-disk envelope: a schema version plus the purl→entry table. */
interface CacheFile {
  version: number;
  entries: Record<string, CacheEntry>;
}

/**
 * Read a committed cache file into a purl→entry Map. A missing/unreadable file
 * yields an empty Map (never an error — generate populates it). A malformed
 * envelope (bad JSON, missing/ill-typed `entries`) throws loudly with the path.
 */
export function readCache(path: string): Map<string, CacheEntry> {
  return readEnvelope<CacheEntry>(path, "enrichment cache");
}

/**
 * Read a committed {version,entries} envelope file into a purl→entry Map,
 * generic over the entry type. A missing/unreadable file yields an empty Map
 * (never an error). A malformed envelope (bad JSON, missing/ill-typed
 * `entries`) throws loudly, naming the path and the given `label` so the
 * enrichment cache and the ScanCode memo each name themselves in the error. An
 * optional `expectedVersion`, when given, rejects any OTHER schema version
 * loudly — the ScanCode memo opts into that strictness; the registry
 * cache passes none, preserving its historical version-agnostic read. This is
 * the single envelope reader — the memo reuses it rather than hand-rolling a
 * second loud-on-malformed parser.
 */
export function readEnvelope<T>(
  path: string,
  label: string,
  expectedVersion?: number,
): Map<string, T> {
  if (!existsSync(path)) return new Map();

  const raw = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`malformed ${label} (invalid JSON): ${path}`, {
      cause: error,
    });
  }

  const entries = envelopeEntries<T>(parsed, path, label);
  if (
    expectedVersion !== undefined &&
    (parsed as { version?: unknown }).version !== expectedVersion
  ) {
    throw new Error(
      `malformed ${label} (unsupported schema version, expected ${expectedVersion}): ${path}`,
    );
  }
  return new Map(Object.entries(entries));
}

/** Validate the {version,entries} envelope, throwing loudly on any deviation. */
function envelopeEntries<T>(
  parsed: unknown,
  path: string,
  label: string,
): Record<string, T> {
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !("entries" in parsed)
  ) {
    throw new Error(
      `malformed ${label} (missing {version,entries} envelope): ${path}`,
    );
  }
  const entries = (parsed as { entries: unknown }).entries;
  if (
    entries === null ||
    typeof entries !== "object" ||
    Array.isArray(entries)
  ) {
    throw new Error(`malformed ${label} (entries is not an object): ${path}`);
  }
  return entries as Record<string, T>;
}

/**
 * Serialize a cache Map to its deterministic on-disk bytes. Reuses
 * {@link toSortedJson} so the bytes follow the identical tool-wide
 * sorted-key/LF/indent-2 contract; double-serialize is byte-identical.
 */
export function serializeCache(cache: Map<string, CacheEntry>): string {
  const file: CacheFile = {
    version: CACHE_VERSION,
    entries: Object.fromEntries(cache),
  };
  return toSortedJson(file);
}

/** Store an entry under its verbatim purl key (mutates the Map in place). */
export function putEntry(
  cache: Map<string, CacheEntry>,
  purl: string,
  entry: CacheEntry,
): void {
  cache.set(purl, entry);
}

/** Look up a purl: the entry on a hit, undefined on a miss (zero I/O). */
export function getEntry(
  cache: Map<string, CacheEntry>,
  purl: string,
): CacheEntry | undefined {
  return cache.get(purl);
}
