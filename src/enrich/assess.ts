/**
 * ScanCode peer assessment stage: replay every memoized answer and, under
 * `generate --intensive`, analyze the full package set.
 *
 * ScanCode is an in-depth, source-level license assessment — far more accurate
 * than reading a registry or a declared manifest field — so it stands as its
 * OWN pipeline stage rather than a gap-filler nested inside registry
 * enrichment. It owns a dedicated committed memo (see scancode-cache.ts) and
 * runs AFTER registry enrichment so that, for the same package, both a
 * quick-check answer and the in-depth answer exist: agreement lets the
 * assessment become the finding, disagreement surfaces as a conflict a human
 * must resolve (annotateFindings owns that comparison downstream — this stage
 * only appends the assessment as a claim).
 *
 * Two responsibilities, in order:
 *
 *  1. Scan pass (generate --intensive ONLY): the analysis set is EVERY package
 *     not already in the memo — a package with a precise declared or registry
 *     answer is analyzed too, because a second, deeper opinion is exactly the
 *     point. A memo hit (a positive result OR a recorded no-result) is skipped
 *     and never re-analyzed, so a repeat run over unchanged inputs analyzes
 *     nothing and leaves the committed memo byte-identical. A package whose
 *     sources are not locally present (unsupported ecosystem, or an absent /
 *     version-mismatched install tree) is reported and NEVER memoized: a memo
 *     entry provably means "this tree was analyzed", never "it wasn't installed
 *     that day". A fresh positive is memoized with its elected expression and
 *     provenance; a fresh no-result is memoized as `license: null` so it is
 *     skipped next run rather than re-analyzed.
 *
 *  2. Replay pass (BOTH modes, unconditional, over EVERY package): each package
 *     with a positive memo entry gains a ScanCode claim (and, when it carries no
 *     attribution yet, the memo's copyright lines). This must touch every
 *     package — a memoized answer has to land on a precisely-declared package
 *     too, or the downstream precedence and conflict detection are blind to it.
 *     A no-result entry appends nothing: it is a scan-skip marker, never a
 *     disagreement with a positive answer.
 *
 * `check` replays the committed memo exactly like generate and never analyzes,
 * so an intensive generate and a later offline check produce byte-identical
 * outputs, conflict verdicts included. A missing memo file replays to a no-op,
 * so a repository without ScanCode results is untouched and byte-identical. The
 * scan mechanics (source mapping, traversal/size guards, version assertion,
 * expression election) live in scancode.ts and are used verbatim; this stage
 * only decides WHICH packages to analyze and how their results flow.
 */
import {
  type CanonicalDependencies,
  type PackageEntry,
} from "../model/dependencies";
import { writeArtifact } from "../pipeline/paths";
import { sanitizeForLog } from "../pipeline/summary";
import { parsePurl, withCacheClaim, withReplayAttribution } from "./enrich";
import {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  serializeScancodeMemo,
  type ScancodeMemoEntry,
} from "./scancode-cache";
import {
  scanPackageSources,
  SCANCODE_TOOL,
  sourceDirsFor,
  type IntensiveOptions,
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
   * Present ONLY on `generate --intensive`: the full-set analysis lane. check
   * never receives it, and a default generate never constructs it, so the scan
   * pass is gated on this field's mere presence (additionally inside generate
   * mode). Absent → the stage is replay-only.
   */
  intensive?: IntensiveOptions;
  /**
   * Injectable now-source for the memo's creation-only `scannedAt` stamp.
   * Defaults to the real clock; tests pass a fixed source. Mirrors the memo
   * module's own injectable clock — never a bare inline `new Date()`.
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
 * Replay the committed memo across the whole package set and, under
 * `generate --intensive`, analyze every package not yet memoized. The input
 * model is never mutated: entries are replaced via spread, mirroring
 * enrichUnknowns.
 */
export async function assessPackages(
  model: CanonicalDependencies,
  opts: AssessOptions,
): Promise<AssessResult> {
  const memo = readScancodeMemo(opts.memoPath);
  const packages = [...model.packages];

  // Scan pass FIRST so a freshly-memoized positive replays in this same run;
  // gated on generate --intensive. The memo is materialized once at the end.
  if (opts.mode === "generate" && opts.intensive !== undefined) {
    await scanFullSet(packages, memo, opts.intensive, opts);
    writeArtifact(opts.memoPath, serializeScancodeMemo(memo));
  }

  // Replay pass: unconditional, EVERY package (a memoized answer must land on a
  // precisely-declared package too, or precedence/conflict detection go blind).
  replayMemo(packages, memo);

  return { model: { packages } };
}

/** Append the memo's positive answers as ScanCode claims across ALL packages. */
function replayMemo(
  packages: PackageEntry[],
  memo: Map<string, ScancodeMemoEntry>,
): void {
  packages.forEach((entry, index) => {
    const memoEntry = getMemoEntry(memo, entry.purl);
    // A no-result entry (license null) appends nothing — a scan-skip marker,
    // never a disagreement with a positive registry answer.
    if (memoEntry === undefined || memoEntry.license === null) return;
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
}

/** Everything analyzeOne needs, bundled so the per-package call stays readable. */
interface ScanContext {
  memo: Map<string, ScancodeMemoEntry>;
  intensive: IntensiveOptions;
  scanOpts: ScancodeScanOptions;
  now: () => Date;
  verbose: boolean;
  counts: ScanCounts;
}

/**
 * Analyze every package not already in the memo (the full set — a precisely
 * answered package is analyzed too when unmemoized). Populates the memo in
 * place and reports the partition on stderr.
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
    counts: { scanned: 0, hits: 0, noLocalSources: 0, unsupported: 0 },
  };
  for (const entry of packages) await analyzeOne(entry, ctx);
  reportCounts(ctx.counts);
}

/**
 * Classify one package into the analysis partition and, when it is a fresh
 * scannable target, run the scan and memoize the outcome. A memo hit is
 * skipped; an unsupported ecosystem or an absent local tree is counted and
 * reported but NEVER memoized (a memo entry means the tree was analyzed).
 */
async function analyzeOne(
  entry: PackageEntry,
  ctx: ScanContext,
): Promise<void> {
  if (getMemoEntry(ctx.memo, entry.purl) !== undefined) {
    ctx.counts.hits += 1;
    return;
  }
  const parsed = parsePurl(entry.purl);
  if (
    parsed === undefined ||
    (parsed.type !== "npm" && parsed.type !== "pypi")
  ) {
    ctx.counts.unsupported += 1;
    return;
  }
  const dirs = sourceDirsFor(entry.purl, ctx.intensive.targetDirs);
  if (dirs.length === 0) {
    ctx.counts.noLocalSources += 1;
    if (ctx.verbose) {
      process.stderr.write(
        `intensive skip: ${sanitizeForLog(entry.purl)} — ` +
          `sources not locally present\n`,
      );
    }
    return;
  }
  const resolved = await scanDirs(dirs, ctx.scanOpts);
  ctx.counts.scanned += 1;
  putMemoEntry(ctx.memo, entry.purl, memoEntryFor(resolved), ctx.now);
}

/** Scan the ordered candidate dirs, returning the first positive answer, or null. */
async function scanDirs(
  dirs: string[],
  scanOpts: ScancodeScanOptions,
): Promise<ScancodeResolution | null> {
  for (const dir of dirs) {
    const resolved = await scanPackageSources(dir, scanOpts);
    if (resolved !== null) return resolved;
  }
  return null;
}

/**
 * The memo entry for a scan outcome: a positive carries the elected expression,
 * its provenance, and (when non-empty) its copyright lines; a no-answer is a
 * `license: null` entry on the no-answer lane so it is skipped next run.
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
    ...(resolved.copyrights.length > 0
      ? { copyrights: resolved.copyrights }
      : {}),
  };
}

/** Project IntensiveOptions onto the scan-invocation options (conditional spread). */
function scanOptionsFrom(intensive: IntensiveOptions): ScancodeScanOptions {
  return {
    ...(intensive.scancodeBin !== undefined
      ? { scancodeBin: intensive.scancodeBin }
      : {}),
    ...(intensive.timeoutMs !== undefined
      ? { timeoutMs: intensive.timeoutMs }
      : {}),
    ...(intensive.tempDir !== undefined ? { tempDir: intensive.tempDir } : {}),
  };
}

/** The locked house-style stderr partition line for an intensive run. */
function reportCounts(counts: ScanCounts): void {
  process.stderr.write(
    `intensive: scanned ${counts.scanned}, memoized ${counts.hits} (hits), ` +
      `no local sources ${counts.noLocalSources}, ` +
      `unsupported ${counts.unsupported}\n`,
  );
}
