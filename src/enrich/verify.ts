/**
 * Cache-integrity audit: re-resolve every re-resolvable committed
 * enrichment-cache entry against its registry and compare the stored raw
 * license.
 *
 * The committed cache is what `check` trusts OFFLINE, so a hand-edited entry —
 * a flipped license, a fabricated package, or a `resolvable:false` hiding a real
 * copyleft license — would pass the gate silently. `verify-cache` is the ONLINE
 * counterpart: for every registry-sourced entry it re-derives the registry's
 * current answer with the SAME resolvers `generate` uses (enrich.ts) and flags
 * any divergence. A divergence is either tampering or a genuine upstream
 * license change; both warrant a human look before a release or audit.
 *
 * The comparison is a single equality on the raw license string: a cached value
 * (string for a positive entry, null for a negative one) versus the freshly
 * resolved value. That one check covers every tamper shape — a changed string, a
 * fabricated entry the registry now 404s (→ null), and a negative entry the
 * registry contradicts with a real license. A registry/network FAILURE is a loud
 * inability to verify (it propagates and the CLI exits 3), NEVER silently treated
 * as agreement — exactly the reliability posture `generate` already takes.
 */
import { compareCodeUnits } from "../model/dependencies";
import {
  githubLicenseUrl,
  npmPackumentUrl,
  parsePurl,
  pypiJsonUrl,
  resolveFromDocument,
  type ParsedPurl,
} from "./enrich";
import { readCache, type CacheEntry } from "./cache";
import { fetchGithubLicense, fetchJson, mapLimit } from "./fetch";
import {
  githubLicenseRefsFor,
  githubRepoFor,
  resolveGithubLicense,
} from "./github";

/** Bounded concurrency over the audit fetch set (mirrors enrich's FETCH_CONCURRENCY). */
const VERIFY_CONCURRENCY = 8;

/** The purl types the cache can hold and this audit can re-resolve. */
const VERIFIABLE_TYPES = new Set(["pypi", "npm", "terraform"]);

export interface VerifyOptions {
  /** Committed cache path (base-dir-resolved by the caller). */
  cachePath: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to the fetchers (tests pass a small value). */
  backoffBaseMs?: number;
}

/** One entry whose committed license disagrees with the registry's current answer. */
export interface CacheMismatch {
  purl: string;
  /** The committed raw license (null = a committed negative entry). */
  cached: string | null;
  /** The registry's current raw license (null = no license / not found). */
  current: string | null;
  /** A short, human reason for the divergence. */
  reason: string;
}

export interface VerifyResult {
  /** Entries actually re-resolved against a registry. */
  audited: number;
  /** Divergences, sorted by purl for deterministic reporting. */
  mismatches: CacheMismatch[];
}

/** Memoizing document fetcher: one network call per distinct URL, shared across entries. */
type FetchDoc = (url: string) => Promise<unknown>;

/**
 * The registry's CURRENT raw license for a parsed purl, or null for a definitive
 * no-license answer. This is exactly `generate`'s per-package resolution
 * (enrich.ts) with the cache-write and claim-append stripped out: pypi/npm read
 * one registry document; terraform walks the ordered version-tag refs and takes
 * the first resolvable one. A transient fetch failure throws (loud), never null.
 */
async function currentRegistryLicense(
  parsed: ParsedPurl,
  fetchDoc: FetchDoc,
  fetchOpts: { backoffBaseMs?: number },
): Promise<string | null> {
  if (parsed.type === "pypi" || parsed.type === "npm") {
    const url =
      parsed.type === "pypi"
        ? pypiJsonUrl(parsed.encodedName, parsed.version)
        : npmPackumentUrl(parsed.encodedName);
    const resolved = resolveFromDocument(parsed, await fetchDoc(url));
    return resolved === null ? null : resolved.raw;
  }
  // terraform → GitHub License API at the version tag (same ordered-ref walk as
  // generate: v<version> then <version>; first resolvable wins, 404 advances).
  const repo = githubRepoFor(parsed);
  if (repo === null) return null;
  for (const ref of githubLicenseRefsFor(parsed.version)) {
    const result = await fetchGithubLicense(
      githubLicenseUrl(repo.owner, repo.repo, ref),
      fetchOpts,
    );
    if (result.status === 404) continue;
    const resolved = resolveGithubLicense(result.body);
    if (resolved === null) continue;
    return resolved.raw;
  }
  return null;
}

/** Describe a divergence between the committed value and the registry's answer. */
function reasonFor(cached: string | null, current: string | null): string {
  if (cached !== null && current === null) {
    return "committed a license; the registry now resolves none (yanked, retagged, or fabricated)";
  }
  if (cached === null && current !== null) {
    return "committed as no-license; the registry resolves a real license (a hidden obligation)";
  }
  return "license changed since the cache was written";
}

/**
 * Audit one entry: re-resolve and compare. Returns a mismatch, or null when the
 * committed license still matches the registry. An entry whose key is not a
 * re-resolvable purl is itself a finding — `generate` only ever writes
 * pypi/npm/terraform entries, so anything else was not written by this tool.
 */
async function auditEntry(
  purl: string,
  entry: CacheEntry,
  fetchDoc: FetchDoc,
  fetchOpts: { backoffBaseMs?: number },
): Promise<CacheMismatch | null> {
  const parsed = parsePurl(purl);
  if (parsed === undefined || !VERIFIABLE_TYPES.has(parsed.type)) {
    return {
      purl,
      cached: entry.license,
      current: null,
      reason: "not a re-resolvable purl — this tool never writes such an entry",
    };
  }
  const current = await currentRegistryLicense(parsed, fetchDoc, fetchOpts);
  if (entry.license === current) return null;
  return {
    purl,
    cached: entry.license,
    current,
    reason: reasonFor(entry.license, current),
  };
}

/**
 * Re-verify every committed cache entry against its registry. Reads the cache
 * (a malformed envelope throws loudly, as in `check`), re-resolves each entry
 * with bounded concurrency and per-URL fetch de-duplication, and returns the
 * divergences sorted by purl. A network failure propagates (the caller maps it
 * to a tool error), so an unreachable registry never reads as "all clean".
 */
export async function verifyCache(opts: VerifyOptions): Promise<VerifyResult> {
  const cache = readCache(opts.cachePath);
  const fetchOpts =
    opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs };

  // One network call per distinct URL: many npm versions share a packument, and
  // a repeated URL reuses the in-flight promise (dedup survives concurrency).
  const documents = new Map<string, Promise<unknown>>();
  const fetchDoc: FetchDoc = (url) => {
    let pending = documents.get(url);
    if (pending === undefined) {
      pending = fetchJson(url, fetchOpts);
      documents.set(url, pending);
    }
    return pending;
  };

  const entries = [...cache.entries()];
  const audited = await mapLimit(entries, VERIFY_CONCURRENCY, ([purl, entry]) =>
    auditEntry(purl, entry, fetchDoc, fetchOpts),
  );
  const mismatches = audited
    .filter((m): m is CacheMismatch => m !== null)
    .sort((a, b) => compareCodeUnits(a.purl, b.purl));

  return {
    audited: entries.length,
    mismatches,
  };
}
