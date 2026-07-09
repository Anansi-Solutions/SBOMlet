/**
 * ScanCode analysis memo (12-03, SCAN-06 / D-04 / D-11): the dedicated
 * committed cache's read/write contract, its deterministic serialization, and
 * its loud-on-malformed + version-guarded envelope read. No behavior is wired
 * to the memo yet (that lands in 12-04); these lock the exported module
 * contract 12-04 builds on. (The path/CLI plumbing is locked below in Task 2.)
 */
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  serializeScancodeMemo,
  type ScancodeMemoEntry,
} from "../src/enrich/scancode-cache";
import {
  ENRICHMENT_CACHE_FILE,
  SCANCODE_CACHE_FILE,
  scancodeCachePath,
  type GenerateOptions,
} from "../src/pipeline/pipeline";
import { optionsFrom } from "../src/cli";

/** The committed memo filename (kept as a literal so the block above stays module-only). */
const MEMO_FILE = "scancode.cache.json";

/** A minimal valid GenerateOptions for exercising the path resolver directly. */
const baseOpts: GenerateOptions = {
  outputPath: "THIRD_PARTY_LICENSES.md",
  noticesPath: "THIRD_PARTY_NOTICES.md",
  verbose: false,
};

/** A positive memo entry: raw expression + copyrights + a fixed creation stamp. */
const positive: ScancodeMemoEntry = {
  license: "MIT",
  via: "scancode-toolkit@32.5.0/license-file",
  copyrights: ["Copyright (c) 2020 Example Author"],
  scannedAt: "2026-08-01T04:17:23.000Z",
};

/** A no-result entry: analyzed, no license evidence (D-11) — license null alone. */
const noResult: ScancodeMemoEntry = {
  license: null,
  via: "scancode-toolkit@32.5.0/no-answer",
  scannedAt: "2026-08-01T04:19:41.000Z",
};

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "scancode-memo-"));
}

describe("scancode memo — envelope, entry shape, deterministic read/write (SCAN-06 / D-04 / D-11)", () => {
  test("a round-trip through serialize → readScancodeMemo is lossless for positive and no-result entries", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);
      const memo = new Map<string, ScancodeMemoEntry>();
      memo.set("pkg:pypi/anyio@4.12.1", positive);
      memo.set("pkg:npm/no-license-pkg@2.0.0", noResult);
      writeFileSync(path, serializeScancodeMemo(memo));

      const loaded = readScancodeMemo(path);
      expect(getMemoEntry(loaded, "pkg:pypi/anyio@4.12.1")).toEqual(positive);
      expect(getMemoEntry(loaded, "pkg:npm/no-license-pkg@2.0.0")).toEqual(
        noResult,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("serialization is deterministic: sorted keys (insertion-order independent), indent 2, LF, trailing newline, no timestamp key; double-serialize byte-identical", () => {
    const memo = new Map<string, ScancodeMemoEntry>();
    // Insert out of sorted order to prove the serializer sorts.
    memo.set("pkg:pypi/anyio@4.12.1", positive);
    memo.set("pkg:npm/no-license-pkg@2.0.0", noResult);

    const bytes = serializeScancodeMemo(memo);
    expect(bytes.endsWith("\n")).toBe(true);
    expect(bytes.includes("\r")).toBe(false);
    expect(bytes).toContain('  "version": 1');
    // "pkg:npm/..." sorts before "pkg:pypi/..." by code unit.
    expect(bytes.indexOf("pkg:npm/no-license-pkg@2.0.0")).toBeLessThan(
      bytes.indexOf("pkg:pypi/anyio@4.12.1"),
    );
    // Insertion order must not change the bytes.
    const reordered = new Map<string, ScancodeMemoEntry>();
    reordered.set("pkg:npm/no-license-pkg@2.0.0", noResult);
    reordered.set("pkg:pypi/anyio@4.12.1", positive);
    expect(serializeScancodeMemo(reordered)).toBe(bytes);
    // Double-serialize is byte-identical.
    expect(serializeScancodeMemo(memo)).toBe(bytes);
  });

  test("readScancodeMemo on a missing file yields an empty memo, never throws, never creates the file (D-06)", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);
      const loaded = readScancodeMemo(path);
      expect(loaded.size).toBe(0);
      expect(existsSync(path)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a well-formed empty version-1 envelope reads as an empty memo (no throw)", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);
      writeFileSync(path, JSON.stringify({ version: 1, entries: {} }));
      expect(readScancodeMemo(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a malformed envelope throws loudly — truncated JSON, missing entries, non-object entries, and a WRONG schema version each abort (T-12-07), never a silent empty", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);

      writeFileSync(path, "{ not valid json ");
      expect(() => readScancodeMemo(path)).toThrow(/scancode memo/);

      writeFileSync(path, JSON.stringify({ version: 1 })); // missing entries
      expect(() => readScancodeMemo(path)).toThrow(/scancode memo/);

      writeFileSync(path, JSON.stringify({ version: 1, entries: [] })); // entries not an object
      expect(() => readScancodeMemo(path)).toThrow(/scancode memo/);

      writeFileSync(path, JSON.stringify({ version: 2, entries: {} })); // future/unsupported version
      expect(() => readScancodeMemo(path)).toThrow(/scancode memo/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a read-modify-write that adds one entry leaves the existing entry's bytes (including scannedAt) untouched, and stamps ONLY the new entry", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);
      const memo = new Map<string, ScancodeMemoEntry>();
      memo.set("pkg:pypi/anyio@4.12.1", positive);
      const before = serializeScancodeMemo(memo);
      writeFileSync(path, before);

      // Read-then-write with no mutation is a byte-identical no-op (existing
      // scannedAt preserved verbatim).
      expect(serializeScancodeMemo(readScancodeMemo(path))).toBe(before);

      // Adding a new entry stamps ONLY the new one, via the injectable clock.
      const loaded = readScancodeMemo(path);
      putMemoEntry(
        loaded,
        "pkg:npm/added@1.0.0",
        { license: "Apache-2.0", via: "scancode-toolkit@32.5.0/license-file" },
        () => new Date("2030-01-01T00:00:00.000Z"),
      );
      expect(getMemoEntry(loaded, "pkg:pypi/anyio@4.12.1")).toEqual(positive);
      expect(getMemoEntry(loaded, "pkg:npm/added@1.0.0")).toEqual({
        license: "Apache-2.0",
        via: "scancode-toolkit@32.5.0/license-file",
        scannedAt: "2030-01-01T00:00:00.000Z",
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("putMemoEntry never rewrites an existing entry — a second put for the same purl is a no-op (byte stability)", () => {
    const memo = new Map<string, ScancodeMemoEntry>();
    memo.set("pkg:pypi/anyio@4.12.1", positive);
    const bytes = serializeScancodeMemo(memo);
    putMemoEntry(
      memo,
      "pkg:pypi/anyio@4.12.1",
      { license: "GPL-3.0-only", via: "scancode-toolkit@32.5.0/license-file" },
      () => new Date("2030-01-01T00:00:00.000Z"),
    );
    expect(getMemoEntry(memo, "pkg:pypi/anyio@4.12.1")).toEqual(positive);
    expect(serializeScancodeMemo(memo)).toBe(bytes);
  });

  test("a no-result entry (license null) is stamped like any new entry and carries no resolvable/source/fetchedFrom twin — license:null alone encodes analyzed-no-evidence (D-11)", () => {
    const memo = new Map<string, ScancodeMemoEntry>();
    putMemoEntry(
      memo,
      "pkg:npm/no-license-pkg@2.0.0",
      { license: null, via: "scancode-toolkit@32.5.0/no-answer" },
      () => new Date("2026-08-01T04:19:41.000Z"),
    );
    const entry = getMemoEntry(memo, "pkg:npm/no-license-pkg@2.0.0");
    expect(entry?.license).toBeNull();
    expect(entry).toEqual(noResult);

    const bytes = serializeScancodeMemo(memo);
    expect(bytes).not.toContain("resolvable");
    expect(bytes).not.toContain("fetchedFrom");
    expect(bytes).not.toContain('"source"');
  });

  test("a verbatim URL-encoded purl key (%40scope) round-trips exactly — keys are opaque, never decoded or split (T-12-08)", () => {
    const dir = tempDir();
    try {
      const path = join(dir, MEMO_FILE);
      const key = "pkg:npm/%40scope/pkg@1.2.3";
      const memo = new Map<string, ScancodeMemoEntry>();
      memo.set(key, positive);
      writeFileSync(path, serializeScancodeMemo(memo));

      const loaded = readScancodeMemo(path);
      expect(getMemoEntry(loaded, key)).toEqual(positive);
      // The DECODED form is NOT a key — the encoding is preserved verbatim.
      expect(getMemoEntry(loaded, "pkg:npm/@scope/pkg@1.2.3")).toBeUndefined();
      // The raw bytes carry the encoded key, never a decoded/split one.
      expect(readFileSync(path, "utf8")).toContain(
        "pkg:npm/%40scope/pkg@1.2.3",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("an entry serialized WITHOUT copyrights contains no 'copyrights' key (optional-field zero-churn)", () => {
    const memo = new Map<string, ScancodeMemoEntry>();
    memo.set("pkg:npm/no-license-pkg@2.0.0", noResult);
    expect(serializeScancodeMemo(memo)).not.toContain("copyrights");
  });
});

describe("scancode memo path resolution + --scancode-cache flag (SCAN-06 / D-04)", () => {
  test("SCANCODE_CACHE_FILE is scancode.cache.json — a distinct sibling of the enrichment cache filename", () => {
    expect(SCANCODE_CACHE_FILE).toBe("scancode.cache.json");
    expect(SCANCODE_CACHE_FILE).not.toBe(ENRICHMENT_CACHE_FILE);
  });

  test("the default memo path is the sibling of licenses.cache.json inside the resolved cache dir", () => {
    const dir = join(tmpdir(), "repo", ".sbomlet.cache");
    const resolved = scancodeCachePath(baseOpts, dir);
    expect(basename(resolved)).toBe("scancode.cache.json");
    expect(dirname(resolved)).toBe(dir);
  });

  test("the memo path honors whatever cache dir it is given — the [cache] dir override mechanism, shared with the enrichment path via cacheDir", () => {
    const overrideDir = join(tmpdir(), "custom-cache-dir");
    const resolved = scancodeCachePath(baseOpts, overrideDir);
    expect(dirname(resolved)).toBe(overrideDir);
    expect(basename(resolved)).toBe("scancode.cache.json");
  });

  test("--scancode-cache <path> overrides the resolved path, symmetric with --enrichment-cache", () => {
    const dir = join(tmpdir(), "repo", ".sbomlet.cache");
    const resolved = scancodeCachePath(
      { ...baseOpts, scancodeCachePath: "custom/memo.json" },
      dir,
    );
    expect(basename(resolved)).toBe("memo.json");
    expect(resolved.endsWith(join("custom", "memo.json"))).toBe(true);
  });

  test("optionsFrom threads --scancode-cache into scancodeCachePath (undefined when absent) — the shared parser both generate and check consume", () => {
    expect(optionsFrom({}).scancodeCachePath).toBeUndefined();
    expect(
      optionsFrom({ "scancode-cache": "custom/memo.json" }).scancodeCachePath,
    ).toBe("custom/memo.json");
  });
});
