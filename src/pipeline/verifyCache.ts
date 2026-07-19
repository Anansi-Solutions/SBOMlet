/**
 * The verify-cache run wrapper. Resolves the committed enrichment-cache path
 * EXACTLY as generate/check do: ENRICHMENT_CACHE_FILE inside the resolved cache
 * dir (the policy `[cache] dir`, or the default, anchored to the scanned repo), so
 * the audit targets the same committed file the gate trusts offline. An explicit
 * --enrichment-cache overrides it. The audit itself — re-resolve every entry and
 * compare — lives in enrich/verify.ts; this layer owns only the path rule, plus
 * shaping the policy's evidence-pinned `[[clarify]]` entries into the
 * TOML-free {@link EvidencePin} shape enrich/verify.ts accepts.
 */
import {
  verifyCache,
  type EvidencePin,
  type VerifyResult,
} from "../enrich/verify";
import { resolveFrom } from "./paths";
import { ENRICHMENT_CACHE_FILE, resolveCacheDirAndPolicy } from "./pipeline";

export interface VerifyCacheOptions {
  /** Base dir for resolving the repo root, policy, and override path. */
  baseDir?: string;
  /** Scanned repo root — anchors the cache dir (matches generate/check). */
  repoRoot?: string;
  /** Policy file, read for its `[cache] dir` and `[[clarify]]` evidence_url entries. */
  policyPath?: string;
  /** Explicit override; when set it wins over the cache-dir default. */
  enrichmentCachePath?: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to the fetchers (tests pass a small value). */
  backoffBaseMs?: number;
}

/**
 * The evidence-pinned `[[clarify]]` entries, shaped for enrich/verify.ts —
 * ONE pin per LISTED package (the multi-package clarify form fans a single
 * rule out into N pins sharing one evidence_url, so the drift audit names
 * every package that cites it, not just the first). The schema
 * (validateClarifyEvidenceUrl) already requires a version on EVERY listed
 * package wherever `evidence_url` is present, so this filter alone is
 * enough to produce a fully-typed {@link EvidencePin} list — no second
 * validation needed. Exported for direct unit testing (the sanitizeForLog
 * precedent).
 */
export function evidencePinsOf(
  clarify: ReadonlyArray<{
    packages: ReadonlyArray<{ name: string; version?: string }>;
    evidence_url?: string;
  }>,
): EvidencePin[] {
  const pins: EvidencePin[] = [];
  for (const entry of clarify) {
    if (entry.evidence_url === undefined) continue;
    for (const pkg of entry.packages) {
      if (pkg.version === undefined) continue;
      pins.push({
        name: pkg.name,
        version: pkg.version,
        evidenceUrl: entry.evidence_url,
      });
    }
  }
  return pins;
}

export function runVerifyCache(
  opts: VerifyCacheOptions,
): Promise<VerifyResult> {
  // ONE parsePolicy call (via resolveCacheDirAndPolicy) serves both the cache
  // dir and the clarify list — no second parse of the same policy file.
  const { dir, policy } = resolveCacheDirAndPolicy(opts);
  const cachePath =
    opts.enrichmentCachePath !== undefined
      ? resolveFrom(opts.baseDir, opts.enrichmentCachePath)
      : resolveFrom(dir, ENRICHMENT_CACHE_FILE);
  return verifyCache({
    cachePath,
    verbose: opts.verbose,
    evidencePins: evidencePinsOf(policy?.clarify ?? []),
    ...(opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs }),
  });
}
