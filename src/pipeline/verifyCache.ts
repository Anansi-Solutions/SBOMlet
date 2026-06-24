/**
 * The verify-cache run wrapper. Resolves the committed enrichment-cache path
 * EXACTLY as generate/check do (resolveFrom(baseDir, ...) over the shared
 * DEFAULT_ENRICHMENT_CACHE), so the audit targets the same committed file the
 * gate trusts offline. The audit itself — re-resolve every entry and compare —
 * lives in enrich/verify.ts; this layer owns only the path rule.
 */
import { verifyCache, type VerifyResult } from "../enrich/verify";
import { resolveFrom } from "./paths";
import { DEFAULT_ENRICHMENT_CACHE } from "./pipeline";

export interface VerifyCacheOptions {
  /** Base dir for resolving the cache path (matches generate/check). */
  baseDir?: string;
  /** The committed enrichment cache path; defaults to DEFAULT_ENRICHMENT_CACHE. */
  enrichmentCachePath?: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to the fetchers (tests pass a small value). */
  backoffBaseMs?: number;
}

export function runVerifyCache(
  opts: VerifyCacheOptions,
): Promise<VerifyResult> {
  const cachePath = resolveFrom(
    opts.baseDir,
    opts.enrichmentCachePath ?? DEFAULT_ENRICHMENT_CACHE,
  );
  return verifyCache({
    cachePath,
    verbose: opts.verbose,
    ...(opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs }),
  });
}
