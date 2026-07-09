/**
 * Committed purl-keyed ScanCode analysis memo: deterministic read/write.
 *
 * A DEDICATED committed cache (D-04, SCAN-06), separate from the registry
 * enrichment cache and carrying its OWN schema version — the intensive ScanCode
 * lane's results live here, not in licenses.cache.json, so the two caches keep
 * independent lifecycles. Like the enrichment cache the file is committed (NOT
 * gitignored) so `check` replays it fully offline; a MISSING file reads as an
 * EMPTY memo (no error, no file created) — repositories without ScanCode
 * results are untouched (D-06).
 *
 * Each entry means: "this purl@version was analyzed by this ScanCode tool
 * version." The key is the VERBATIM purl (URL-encoding intact, e.g.
 * `pkg:npm/%40scope/pkg@1.2.3`) — opaque in this module: never decoded, split,
 * or joined into a filesystem path (the scanned source dirs come from
 * sourceDirsFor with its own traversal guards, unchanged). name@version is
 * immutable upstream, so an already-analyzed package version is never
 * re-analyzed (D-11).
 *
 * `license` is the RAW elected SPDX expression string (normalizeRaw stays the
 * downstream authority), or `null` for a NO-RESULT entry: analyzed with no
 * license evidence found (D-11). `license: null` ALONE encodes that — there is
 * no `resolvable` twin (the registry cache's is historical redundancy) and no
 * `source`/`fetchedFrom` field (this file IS the provenance). A no-result is a
 * scan-SKIP marker, NOT an absence marker and NOT a disagreement with a
 * positive registry answer; the 12-04 replay stage enforces that meaning, and
 * enforces that a sources-absent package never gains an entry at all.
 *
 * `via` is the tool@version/election-lane provenance
 * (`scancode-toolkit@32.5.0/license-file`). `copyrights` is the OPTIONAL
 * sorted/deduped/capped list carried over from the collector (absent = zero
 * churn on existing entries, the fetchedAt optional-field precedent).
 *
 * `scannedAt` is an OPTIONAL ISO timestamp stamped (via an injectable clock)
 * ONLY on a NEW entry, NEVER rewritten on a hit, and NEVER rendered into any
 * output — it lives ONLY here (the fetchedAt/T-06-14 determinism control), so a
 * warm double-generate is byte-identical.
 *
 * Serialization reuses the one tool-wide sorter ({@link toSortedJson}): sorted
 * keys, indent 2, LF-only, trailing newline, no timestamp — the memo diffs
 * cleanly and the byte-exact gate stays honest. The loud-on-malformed envelope
 * read is the enrichment cache's ({@link readEnvelope}) with an added schema-
 * version check (T-12-07), so a poisoned/garbage/wrong-version memo is a config
 * error, never a silent empty.
 */
import { toSortedJson } from "../model/dependencies";
import { readEnvelope } from "./cache";

/** Schema version — bump for a clean future invalidation of the whole memo. */
const MEMO_VERSION = 1;

/**
 * One memoized ScanCode analysis, keyed by verbatim purl. `license` is the raw
 * elected expression, or null for an analyzed-no-license-evidence result (D-11,
 * NOT an absence marker). `via` is the tool@version/election-lane provenance.
 * `copyrights` is the optional collector list (absent = zero churn). `scannedAt`
 * is the optional creation stamp — set once, never rewritten, never rendered.
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
 * Read a committed memo file into a purl→entry Map. A missing file yields an
 * empty Map (never an error — the scan stage populates it). A malformed
 * envelope (bad JSON, missing/ill-typed `entries`) OR a wrong schema version
 * throws loudly with the path — same posture as the registry cache read, plus
 * the version guard (T-12-07): a poisoned or future-version memo is a config
 * error, never a silent empty.
 */
export function readScancodeMemo(path: string): Map<string, ScancodeMemoEntry> {
  return readEnvelope<ScancodeMemoEntry>(path, "scancode memo", MEMO_VERSION);
}

/**
 * Serialize a memo Map to its deterministic on-disk bytes via
 * {@link toSortedJson} (sorted keys, indent 2, LF, trailing newline, no
 * timestamp) — double-serialize is byte-identical. There is one sorter tool-
 * wide, never a second JSON writer.
 */
export function serializeScancodeMemo(
  memo: Map<string, ScancodeMemoEntry>,
): string {
  const file: ScancodeMemoFile = {
    version: MEMO_VERSION,
    entries: Object.fromEntries(memo),
  };
  return toSortedJson(file);
}

/**
 * Store a memo entry under its verbatim purl key (mutates the Map in place).
 * An entry for a purl ALREADY present is left untouched — the memo is never
 * rewritten on a hit, so existing bytes (including `scannedAt`) stay stable. A
 * NEW entry is stamped with `scannedAt` via the injectable clock unless the
 * caller already supplied one (round-trip reconstruction). The stamp is the
 * fetchedAt precedent: creation-only, never rendered.
 */
export function putMemoEntry(
  memo: Map<string, ScancodeMemoEntry>,
  purl: string,
  entry: ScancodeMemoEntry,
  now: () => Date = defaultNow,
): void {
  if (memo.has(purl)) return;
  memo.set(purl, {
    ...entry,
    ...(entry.scannedAt === undefined
      ? { scannedAt: now().toISOString() }
      : {}),
  });
}

/** Look up a purl: the entry on a hit, undefined on a miss (zero I/O). */
export function getMemoEntry(
  memo: Map<string, ScancodeMemoEntry>,
  purl: string,
): ScancodeMemoEntry | undefined {
  return memo.get(purl);
}

/** The production now-source for the injectable scannedAt clock. */
function defaultNow(): Date {
  return new Date();
}
