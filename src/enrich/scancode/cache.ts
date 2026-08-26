/**
 * Committed purl-keyed ScanCode analysis memo: deterministic read/write.
 *
 * A dedicated committed cache, separate from the registry enrichment cache and carrying its own
 * schema version - the intensive ScanCode lane's results live here, not in licenses.cache.json, so
 * the two caches keep independent lifecycles. Like the enrichment cache the file is committed (not
 * gitignored) so `check` replays it fully offline; a missing file reads as an empty memo (no error,
 * no file created) - repositories without ScanCode results are untouched.
 *
 * The key is the verbatim purl (URL-encoding intact, e.g. `pkg:npm/%40scope/pkg@1.2.3`) - opaque in
 * this module: never decoded, split, or joined into a filesystem path (the scanned source dirs come
 * from sourceDirsFor with its own traversal guards, unchanged). name@version is immutable upstream,
 * so an already-analyzed package version is never re-analyzed. See {@link ScancodeMemoEntry} for
 * the field-by-field shape.
 *
 * A `license: null` entry means analyzed with no evidence found - a scan-skip marker, not an
 * absence marker and not a disagreement with a positive registry answer (the replay stage enforces
 * that meaning). There is no `resolvable` twin (the registry cache's is historical redundancy) and
 * no `source`/`fetchedFrom` field, because this file is itself the provenance.
 *
 * `scannedAt` lives only here (the fetchedAt determinism precedent) so a warm double-generate is
 * byte-identical.
 *
 * Serialization reuses the one tool-wide sorter ({@link toSortedJson}): sorted keys, indent 2,
 * LF-only, trailing newline, no timestamp - the memo diffs cleanly and the byte-exact gate stays
 * honest. The loud-on-malformed envelope read is the enrichment cache's ({@link readEnvelope}) with
 * an added schema-version check, so a poisoned/garbage/wrong-version memo is a config error, never
 * a silent empty.
 */
import { asRawLicense, toSortedJson, type Purl } from "../../model/dependencies";
import { canonicalizeExpression } from "../../normalize/expression";
import { readEnvelope } from "../cache";

/** Schema version - bump for a clean future invalidation of the whole memo. */
const MEMO_VERSION = 1;

/**
 * One memoized ScanCode analysis, keyed by verbatim purl. `license` is the raw elected expression,
 * or null for an analyzed-no-license-evidence result (NOT an absence marker). `via` is the
 * tool@version/election-lane provenance. `copyrights` is the optional collector list (absent = zero
 * churn). `scannedAt` is the optional creation stamp - set once, never rewritten, never rendered.
 */
export interface ScancodeMemoEntry {
  license: string | null;
  via: string;
  copyrights?: readonly string[];
  scannedAt?: string;
}

/** The on-disk envelope: the memo's own schema version plus the purl→entry table. */
interface ScancodeMemoFile {
  version: number;
  entries: Record<string, ScancodeMemoEntry>;
}

/**
 * Read a committed memo file into a purl→entry Map. A missing file yields an empty Map (never an
 * error - the scan stage populates it). A malformed envelope (bad JSON, missing/ill-typed
 * `entries`) or a wrong schema version throws loudly with the path - same posture as the registry
 * cache read, plus the version guard: a poisoned or future-version memo is a config error, never a
 * silent empty.
 *
 * This is the single chokepoint every consumer reads through (the replay pass, the scan pass's
 * merge-on-write re-read in persistMemo, verifyCache's count), so each entry's positive `license`
 * is simplified via {@link canonicalizeExpression} right here: an old committed memo with
 * ScanCode's
 * boolean-algebra noise reads back canonical with zero re-scanning, and the next `generate
 * --intensive` write persists that simplification (merge-on-write, cache.ts's own contract). A
 * `license: null` no-answer entry is untouched, and an unparseable string passes through unchanged
 * per canonicalizeExpression's own honest-residual rule.
 */
export function readScancodeMemo(path: string): Map<Purl, ScancodeMemoEntry> {
  const memo = readEnvelope<ScancodeMemoEntry>(path, "scancode memo", MEMO_VERSION);

  for (const [purl, entry] of memo) {
    if (entry.license !== null) {
      memo.set(purl, { ...entry, license: canonicalizeExpression(asRawLicense(entry.license)) });
    }
  }

  return memo;
}

/**
 * Serialize a memo Map to its deterministic on-disk bytes via {@link toSortedJson} (sorted keys,
 * indent 2, LF, trailing newline, no timestamp) - double-serialize is byte-identical. There is one
 * sorter tool-wide, never a second JSON writer.
 */
export function serializeScancodeMemo(memo: Map<Purl, ScancodeMemoEntry>): string {
  const file: ScancodeMemoFile = {
    version: MEMO_VERSION,
    entries: Object.fromEntries(memo),
  };

  return toSortedJson(file);
}

/**
 * Store a memo entry under its verbatim purl key (mutates the Map in place). An entry for a purl
 * ALREADY present is left untouched - the memo is never rewritten on a hit, so existing bytes
 * (including `scannedAt`) stay stable. A NEW entry is stamped with `scannedAt` via the injectable
 * clock unless the caller already supplied one (round-trip reconstruction). The stamp is the
 * fetchedAt precedent: creation-only, never rendered.
 */
export function putMemoEntry(
  memo: Map<Purl, ScancodeMemoEntry>,
  purl: Purl,
  entry: ScancodeMemoEntry,
  now: () => Date = defaultNow,
): void {
  if (memo.has(purl)) {
    return;
  }

  memo.set(purl, {
    ...entry,
    ...(entry.scannedAt === undefined ? { scannedAt: now().toISOString() } : {}),
  });
}

/** Look up a purl: the entry on a hit, undefined on a miss (zero I/O). */
export function getMemoEntry(
  memo: Map<Purl, ScancodeMemoEntry>,
  purl: Purl,
): ScancodeMemoEntry | undefined {
  return memo.get(purl);
}

/** The production now-source for the injectable scannedAt clock. */
function defaultNow(): Date {
  return new Date();
}
