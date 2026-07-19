/**
 * The suggest-clarifications read-only runner: reads the committed
 * enrichment cache and assembles the current dependency set with the exact
 * offline collect/merge path `check` uses — zero fetches, zero writes — then
 * renders a ready-to-paste, fully-commented `[[clarify]]` stub set for the
 * url-only honest-unknown nuget packages that have no clarify decision yet.
 * The tool states facts (name, version, the verbatim observed url); a human
 * reads the evidence and decides the license.
 */
import { getEntry, readCache, type CacheEntry } from "../enrich/cache";
import { mergeSboms } from "../merge/merge";
import { findClarifyMatch } from "../normalize/normalize";
import {
  renderClarifyStubs,
  type ClarifyStubCandidate,
} from "../policy/clarifyStub";
import { resolveFrom } from "./paths";
import {
  ENRICHMENT_CACHE_FILE,
  resolveCacheDirAndPolicy,
  type GenerateOptions,
} from "./pipeline";
import { collectTargets } from "./targets";

/**
 * The suggest-clarifications option surface — the verifyCache.ts shape: only
 * the fields this read-only command needs, not the full generate/check
 * GenerateOptions (output/notices/cyclonedx/dump-model/intensive are
 * meaningless here).
 */
export interface SuggestClarificationsOptions {
  /** Single-target debug mode; mutually exclusive with repoRoot. */
  targetArg?: string;
  /** Discovery-mode root; defaults to the current working directory. */
  repoRoot?: string;
  /** Repeatable --exclude globs, matched against target identities. */
  excludes?: string[];
  /** Base dir for resolving every relative path option (matches generate/check). */
  baseDir?: string;
  /** Policy file, read for its `[cache] dir` and `[[clarify]]` entries. */
  policyPath?: string;
  /** Explicit override; when set it wins over the cache-dir default. */
  enrichmentCachePath?: string;
  verbose: boolean;
}

export interface SuggestClarificationsResult {
  /** The rendered, fully-commented stub set — empty means nothing to suggest. */
  stub: string;
  /** Number of url-only honest-unknown candidates the stub covers. */
  candidateCount: number;
  /**
   * Nuget negatives in the committed cache written before this tool recorded
   * the url-only field — the delete-the-negatives-and-regenerate advisory
   * count (see docs/reference/cli.md).
   */
  fieldlessNegativeCount: number;
}

/** True for a nuget negative that predates the recorded url-only field. */
function isFieldlessNugetNegative(entry: CacheEntry): boolean {
  return (
    entry.fetchedFrom === "nuget" &&
    entry.resolvable === false &&
    entry.urlOnlyLicenseUrl === undefined
  );
}

/**
 * Adapt the thin option surface into the shape {@link collectTargets} needs.
 * outputPath/noticesPath are never read on this read-only path — buildOutputs
 * is never called — so the placeholder strings are structural only.
 */
function collectOptionsFrom(
  opts: SuggestClarificationsOptions,
): GenerateOptions {
  return {
    targetArg: opts.targetArg,
    repoRoot: opts.repoRoot,
    excludes: opts.excludes,
    baseDir: opts.baseDir,
    verbose: opts.verbose,
    outputPath: "",
    noticesPath: "",
  };
}

/**
 * Read-only, offline: resolves the policy + committed cache via the
 * verifyCache idiom (one parsePolicy call), assembles the package set with
 * the SAME collect/merge path check uses (enrichUnknowns is never called —
 * no fetches, no writes), and joins the two on purl. A candidate is a
 * package whose committed cache entry is a nuget negative carrying the
 * recorded url-only licenseUrl AND has no existing `[[clarify]]` match (the
 * shared findClarifyMatch authority) — so repeated runs converge to empty
 * as onboarding completes.
 */
export async function runSuggestClarifications(
  opts: SuggestClarificationsOptions,
): Promise<SuggestClarificationsResult> {
  const { dir, policy } = resolveCacheDirAndPolicy(opts);
  const cachePath =
    opts.enrichmentCachePath !== undefined
      ? resolveFrom(opts.baseDir, opts.enrichmentCachePath)
      : resolveFrom(dir, ENRICHMENT_CACHE_FILE);
  const cache = readCache(cachePath);

  const { inputs } = await collectTargets(
    collectOptionsFrom(opts),
    (line): void => {
      process.stderr.write(`${line}\n`);
    },
  );
  const model = mergeSboms(inputs);

  const clarify = policy?.clarify ?? [];
  const candidates: ClarifyStubCandidate[] = [];
  for (const pkg of model.packages) {
    const entry = getEntry(cache, pkg.purl);
    if (
      entry === undefined ||
      entry.fetchedFrom !== "nuget" ||
      entry.resolvable !== false ||
      entry.urlOnlyLicenseUrl === undefined
    ) {
      continue;
    }
    if (findClarifyMatch(clarify, pkg.name, pkg.version) !== undefined) {
      continue; // already covered by an existing clarify decision
    }
    candidates.push({
      name: pkg.name,
      version: pkg.version,
      url: entry.urlOnlyLicenseUrl,
    });
  }

  let fieldlessNegativeCount = 0;
  for (const entry of cache.values()) {
    if (isFieldlessNugetNegative(entry)) fieldlessNegativeCount++;
  }

  return {
    stub: renderClarifyStubs(candidates),
    candidateCount: candidates.length,
    fieldlessNegativeCount,
  };
}
