/**
 * The verify-cache run wrapper. Resolves the committed enrichment-cache path
 * EXACTLY as generate/check do: ENRICHMENT_CACHE_FILE inside the resolved cache
 * dir (the policy `[cache] dir`, or the default, anchored to the scanned repo), so
 * the audit targets the same committed file the gate trusts offline. An explicit
 * --enrichment-cache overrides it. The audit itself — re-resolve every entry and
 * compare — lives in enrich/verify.ts; this layer owns only the path rule.
 */
import { verifyCache, type VerifyResult } from "../enrich/verify";
import { resolveFrom } from "./paths";
import { ENRICHMENT_CACHE_FILE, resolveCacheDir } from "./pipeline";

export interface VerifyCacheOptions {
  /** Base dir for resolving the repo root, policy, and override path. */
  baseDir?: string;
  /** Scanned repo root — anchors the cache dir (matches generate/check). */
  repoRoot?: string;
  /** Policy file, read for its `[cache] dir` (matches generate/check discovery). */
  policyPath?: string;
  /** Explicit override; when set it wins over the cache-dir default. */
  enrichmentCachePath?: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to the fetchers (tests pass a small value). */
  backoffBaseMs?: number;
}

export function runVerifyCache(
  opts: VerifyCacheOptions,
): Promise<VerifyResult> {
  const cachePath =
    opts.enrichmentCachePath !== undefined
      ? resolveFrom(opts.baseDir, opts.enrichmentCachePath)
      : resolveFrom(resolveCacheDir(opts), ENRICHMENT_CACHE_FILE);
  return verifyCache({
    cachePath,
    verbose: opts.verbose,
    ...(opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs }),
  });
}
