/**
 * ScanCode peer assessment stage: replay every memoized answer and, under `generate --intensive`,
 * analyze the full package set.
 *
 * ScanCode is an in-depth, source-level license assessment - far more accurate than reading a
 * registry or a declared manifest field - so it stands as its OWN pipeline stage rather than a
 * gap-filler nested inside registry enrichment. It owns a dedicated committed memo (see
 * scancode/cache.ts) and runs AFTER registry enrichment so that, for the same package, both a
 * quick-check answer and the in-depth answer exist: agreement lets the assessment become the
 * finding, disagreement surfaces as a conflict a human must resolve (annotateFindings owns that
 * comparison downstream - this stage only appends the assessment as a claim).
 *
 * Two responsibilities, in order:
 *
 *  1. Scan pass (generate --intensive ONLY): the analysis set is EVERY package not already in the
 *     memo - a package with a precise declared or registry answer is analyzed too, because a
 *     second, deeper opinion is exactly the point. A memo hit (a positive result OR a recorded
 *     no-result) is skipped and never re-analyzed, so a repeat run over unchanged inputs analyzes
 *     nothing and leaves the committed memo byte-identical. A package whose sources are not locally
 *     present (unsupported ecosystem, or an absent / version-mismatched install tree) is reported
 *     and NEVER memoized: a memo entry provably means "this tree was analyzed", never "it wasn't
 *     installed that day". A fresh positive is memoized with its elected expression and provenance;
 *     a fresh no-result is memoized as `license: null` so it is skipped next run rather than
 *     re-analyzed.
 *
 *  2. Replay pass (BOTH modes, unconditional, over EVERY package): each package with a positive
 *     memo entry gains a ScanCode claim (and, when it carries no attribution yet, the memo's
 *     copyright lines). This must touch every package - a memoized answer has to land on a
 *     precisely-declared package too, or the downstream precedence and conflict detection are blind
 *     to it. A no-result entry appends nothing: it is a scan-skip marker, never a disagreement with
 *     a positive answer.
 *
 * `check` replays the committed memo exactly like generate and never analyzes, so an intensive
 * generate and a later offline check produce byte-identical outputs, conflict verdicts included. A
 * missing memo file replays to a no-op, so a repository without ScanCode results is untouched and
 * byte-identical. The scan mechanics (source mapping, traversal/size guards, version assertion,
 * expression election) live in the scancode/ module (sources.ts, invocation.ts, election.ts) and
 * are used verbatim; this stage only decides WHICH packages to analyze and how their results flow.
 */
import { type CanonicalDependencies, type PackageEntry } from "../model/dependencies";
import { writeArtifact } from "../pipeline/paths";
import { sanitizeForLog } from "../pipeline/summary";
import { parsePurl, withCacheClaim, withReplayAttribution } from "./enrich";
import {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  scanPackageSources,
  serializeScancodeMemo,
  ScancodeEnvironmentError,
  SCANCODE_TOOL,
  sourceDirsFor,
  type IntensiveOptions,
  type NpmSourceIndexCache,
  type ScanCandidate,
  type ScancodeMemoEntry,
  type ScancodeResolution,
  type ScancodeScanOptions,
} from "./scancode";

export interface AssessOptions {
  /** generate may analyze + write the memo; check only replays it. */
  mode: "generate" | "check";
  /** Committed memo path (cache-dir-resolved by the caller). */
  memoPath: string;
  verbose: boolean;
  /**
   * Present ONLY on `generate --intensive`: the full-set analysis lane. check never receives it,
   * and a default generate never constructs it, so the scan pass is gated on this field's mere
   * presence (additionally inside generate mode). Absent → the stage is replay-only.
   */
  intensive?: IntensiveOptions;
  /**
   * Injectable now-source for the memo's creation-only `scannedAt` stamp. Defaults to the real
   * clock; tests pass a fixed source. Mirrors the memo module's own injectable clock - never a bare
   * inline `new Date()`.
   */
  now?: () => Date;
}

export interface AssessResult {
  model: CanonicalDependencies;
}

/** The production now-source for the injectable scannedAt clock. */
function defaultNow(): Date {
  return new Date();
}

/**
 * Replay the committed memo across the whole package set and, under `generate --intensive`, analyze
 * every package not yet memoized. The input model is never mutated: entries are replaced via
 * spread, mirroring enrichUnknowns.
 */
export async function assessPackages(
  model: CanonicalDependencies,
  opts: AssessOptions,
): Promise<AssessResult> {
  const memo = readScancodeMemo(opts.memoPath);
  const packages = [...model.packages];

  // Scan pass FIRST so a freshly-memoized positive replays in this same run; gated on generate
  // --intensive. The write lives in a finally so a fatal abort (a broken local tool install - see
  // ScanContext.scanOpts / analyzeOne) still persists every completed scan from this run, not just
  // a clean full-set pass; see persistMemo for the merge-on-write contract that makes that write
  // safe.
  if (opts.mode === "generate" && opts.intensive !== undefined) {
    try {
      await scanFullSet(packages, memo, opts.intensive, opts);
    } finally {
      persistMemo(opts.memoPath, memo);
    }
  }

  // Replay pass: unconditional, EVERY package (a memoized answer must land on a precisely-declared
  // package too, or precedence/conflict detection go blind).
  replayMemo(packages, memo);

  return { model: { packages } };
}

/**
 * Write the memo merged with whatever is on disk at write time, never a blind overwrite of this
 * run's in-memory Map. The merge only protects against clobbering entries present on disk at that
 * instant; it is not cross-process synchronization, so two writers racing on the same purl can
 * still each drop the other's addition. On a same-purl collision the in-memory entry wins.
 */
function persistMemo(path: string, memo: Map<string, ScancodeMemoEntry>): void {
  const onDisk = readScancodeMemo(path);
  const merged = new Map(onDisk);

  for (const [purl, entry] of memo) {
    merged.set(purl, entry);
  }

  writeArtifact(path, serializeScancodeMemo(merged));
}

/** Append the memo's positive answers as ScanCode claims across ALL packages. */
function replayMemo(packages: PackageEntry[], memo: Map<string, ScancodeMemoEntry>): void {
  packages.forEach((entry, index) => {
    const memoEntry = getMemoEntry(memo, entry.purl);

    // A no-result entry (license null) appends nothing - a scan-skip marker, never a disagreement
    // with a positive registry answer.
    if (memoEntry === undefined || memoEntry.license === null) {
      return;
    }

    const withClaim = withCacheClaim(entry, memoEntry.license, "scancode");

    packages[index] = withReplayAttribution(withClaim, memoEntry);
  });
}

/** Running partition of the analysis set, reported once on stderr. */
interface ScanCounts {
  scanned: number;
  hits: number;
  noLocalSources: number;
  unsupported: number;
  /**
   * A per-package scan that rejected (timeout, non-zero exit with no usable output, oversized or
   * malformed output) and was CONTAINED rather than aborting the run - see {@link
   * ScancodeEnvironmentError} for the fatal class this excludes. Never memoized, so the package is
   * retried on the next run.
   */
  failed: number;
}

/** Everything analyzeOne needs, bundled so the per-package call stays readable. */
interface ScanContext {
  memo: Map<string, ScancodeMemoEntry>;
  intensive: IntensiveOptions;
  scanOpts: ScancodeScanOptions;
  now: () => Date;
  verbose: boolean;
  counts: ScanCounts;
  /**
   * Per-run npm source-index cache (sources.ts): built lazily, one readdir-walk per target dir,
   * reused across every package this scan pass looks up - explicit plumbing through this context
   * rather than module-level state, and freshly constructed per {@link scanFullSet} call so no
   * cross-run staleness is possible.
   */
  npmIndexCache: NpmSourceIndexCache;
}

/**
 * Analyze every package not already in the memo (the full set - a precisely answered package is
 * analyzed too when unmemoized). Populates the memo in place and reports the partition on stderr.
 */
async function scanFullSet(
  packages: PackageEntry[],
  memo: Map<string, ScancodeMemoEntry>,
  intensive: IntensiveOptions,
  opts: AssessOptions,
): Promise<void> {
  const ctx: ScanContext = {
    memo,
    intensive,
    scanOpts: scanOptionsFrom(intensive),
    now: opts.now ?? defaultNow,
    verbose: opts.verbose,
    counts: { scanned: 0, hits: 0, noLocalSources: 0, unsupported: 0, failed: 0 },
    npmIndexCache: new Map(),
  };

  for (const entry of packages) {
    await analyzeOne(entry, ctx);
  }

  reportCounts(ctx.counts);
}

/**
 * Classify one package into the analysis partition and, when it is a fresh scannable target, run
 * the scan and memoize the outcome. A memo hit is skipped; an unsupported ecosystem or an absent
 * local tree is counted and reported but NEVER memoized (a memo entry means the tree was analyzed).
 *
 * A per-package scan failure is CONTAINED, never memoized (retried next run), and reported by name
 * unconditionally on stderr - not gated on --verbose like the routine no-local-sources skip above,
 * because an unexpected rejection (a timeout, a crash) is exceptional and must stay visible even in
 * a quiet run. A {@link ScancodeEnvironmentError} - the local tool install itself is broken - is
 * the one exception: it is NOT a per-package condition, so it propagates uncaught and aborts the
 * whole scan pass (scanFullSet's loop, and assessPackages's finally, still persist every entry
 * already memoized before the abort).
 */
async function analyzeOne(entry: PackageEntry, ctx: ScanContext): Promise<void> {
  if (getMemoEntry(ctx.memo, entry.purl) !== undefined) {
    ctx.counts.hits += 1;
    return;
  }

  const parsed = parsePurl(entry.purl);

  if (parsed === undefined || (parsed.type !== "npm" && parsed.type !== "pypi")) {
    ctx.counts.unsupported += 1;
    return;
  }

  const candidates = sourceDirsFor(entry.purl, ctx.intensive.targetDirs, ctx.npmIndexCache);

  if (candidates.length === 0) {
    ctx.counts.noLocalSources += 1;
    if (ctx.verbose) {
      process.stderr.write(
        `intensive skip: ${sanitizeForLog(entry.purl)} — ` + `sources not locally present\n`,
      );
    }

    return;
  }

  let resolved: ScancodeResolution | null;

  try {
    resolved = await scanDirs(candidates, ctx.scanOpts);
  } catch (error) {
    if (error instanceof ScancodeEnvironmentError) {
      throw error;
    }

    ctx.counts.failed += 1;
    process.stderr.write(
      `intensive failed: ${sanitizeForLog(entry.purl)} — ${scanFailureReason(error)}\n`,
    );

    return;
  }

  ctx.counts.scanned += 1;
  putMemoEntry(ctx.memo, entry.purl, memoEntryFor(resolved), ctx.now);
}

/**
 * The one-line reason a contained scan rejection prints, mirroring the tool's error-message idiom.
 */
function scanFailureReason(error: unknown): string {
  return error instanceof Error ? error.message.split("\n")[0]! : String(error);
}

/** Scan the ordered scan candidates, returning the first positive answer, or null. */
async function scanDirs(
  candidates: ScanCandidate[],
  scanOpts: ScancodeScanOptions,
): Promise<ScancodeResolution | null> {
  for (const candidate of candidates) {
    const resolved = await scanPackageSources(candidate, scanOpts);

    if (resolved !== null) {
      return resolved;
    }
  }

  return null;
}

/**
 * The memo entry for a scan outcome: a positive carries the elected expression, its provenance, and
 * (when non-empty) its copyright lines; a no-answer is a `license: null` entry on the no-answer
 * lane so it is skipped next run.
 */
function memoEntryFor(resolved: ScancodeResolution | null): ScancodeMemoEntry {
  if (resolved === null) {
    return {
      license: null,
      via: `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/no-answer`,
    };
  }

  return {
    license: resolved.raw,
    via: resolved.via,
    ...(resolved.copyrights.length > 0 ? { copyrights: resolved.copyrights } : {}),
  };
}

/** Project IntensiveOptions onto the scan-invocation options (conditional spread). */
function scanOptionsFrom(intensive: IntensiveOptions): ScancodeScanOptions {
  return {
    ...(intensive.scancodeBin !== undefined ? { scancodeBin: intensive.scancodeBin } : {}),
    ...(intensive.timeoutMs !== undefined ? { timeoutMs: intensive.timeoutMs } : {}),
    ...(intensive.tempDir !== undefined ? { tempDir: intensive.tempDir } : {}),
  };
}

/** The house-style stderr partition line for an intensive run. */
function reportCounts(counts: ScanCounts): void {
  process.stderr.write(
    `intensive: scanned ${counts.scanned}, memoized ${counts.hits} (hits), ` +
      `no local sources ${counts.noLocalSources}, ` +
      `unsupported ${counts.unsupported}, failed ${counts.failed}\n`,
  );
}
