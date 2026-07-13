import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  TROVE_TO_SPDX,
  isAmbiguousTroveClassifier,
  troveToSpdx,
} from "../src/enrich/trove";
import {
  narrowNpmPackument,
  narrowNugetCatalogEntry,
  narrowNugetLeaf,
  narrowPypiResponse,
} from "../src/validate/registry";
import { fetchJson, fetchJsonOr404, mapLimit } from "../src/enrich/fetch";
import {
  catalogEntryUrlOf,
  nugetRegistrationLeafUrl,
  resolveNugetCatalogLicense,
} from "../src/enrich/nuget";
import { resolvePypiLicense } from "../src/enrich/pypi";
import { resolveNpmLicense } from "../src/enrich/npm";
import {
  getEntry,
  putEntry,
  readCache,
  serializeCache,
  type CacheEntry,
} from "../src/enrich/cache";
import { enrichUnknowns } from "../src/enrich/enrich";
import { annotateFindings } from "../src/normalize/normalize";
import type {
  CanonicalDependencies,
  LicenseClaim,
  PackageEntry,
} from "../src/model/dependencies";

/** Load a captured registry fixture as parsed JSON (the live response shape). */
function registryFixture(name: string): unknown {
  return JSON.parse(
    readFileSync(join(import.meta.dir, "fixtures", "registry", name), "utf8"),
  ) as unknown;
}

/** SPDX ids known to spdx-license-ids (current + deprecated), as the parser sees them. */
function knownSpdxIds(): Set<string> {
  const dataDir = join(
    import.meta.dir,
    "..",
    "node_modules",
    "spdx-license-ids",
  );
  const current = JSON.parse(
    readFileSync(join(dataDir, "index.json"), "utf8"),
  ) as string[];
  const deprecated = JSON.parse(
    readFileSync(join(dataDir, "deprecated.json"), "utf8"),
  ) as string[];
  return new Set([...current, ...deprecated]);
}

describe("trove classifier -> SPDX map", () => {
  test("fills the spdx-correct gaps (PSF label, ISCL)", () => {
    expect(
      troveToSpdx(
        "License :: OSI Approved :: Python Software Foundation License",
      ),
    ).toBe("Python-2.0");
    expect(troveToSpdx("License :: OSI Approved :: ISC License (ISCL)")).toBe(
      "ISC",
    );
  });

  test("the bare 'ISC license' label maps to ISC (INV-04 suffix fix — pexpect false-negative)", () => {
    // pexpect's PyPI license field is the bare label "ISC license", which
    // spdx-correct returns null for; the trove map carries it so normalizeRaw
    // resolves it to ISC instead of dropping the package to unknown.
    expect(troveToSpdx("ISC license")).toBe("ISC");
    expect(troveToSpdx("ISC License")).toBe("ISC");
  });

  test("maps precise classifiers exactly (MIT/ISC/MPL)", () => {
    expect(troveToSpdx("License :: OSI Approved :: MIT License")).toBe("MIT");
    expect(
      troveToSpdx(
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      ),
    ).toBe("MPL-2.0");
  });

  test("returns undefined for an unknown classifier (never throws)", () => {
    expect(
      troveToSpdx("License :: OSI Approved :: Totally Made Up License"),
    ).toBeUndefined();
    expect(troveToSpdx("not a classifier at all")).toBeUndefined();
  });

  test("flags ambiguous BSD/Apache classifiers LOW (not silently HIGH)", () => {
    expect(
      isAmbiguousTroveClassifier("License :: OSI Approved :: BSD License"),
    ).toBe(true);
    expect(
      isAmbiguousTroveClassifier(
        "License :: OSI Approved :: Apache Software License",
      ),
    ).toBe(true);
    // Precise classifiers are NOT ambiguous.
    expect(
      isAmbiguousTroveClassifier("License :: OSI Approved :: MIT License"),
    ).toBe(false);
    expect(
      isAmbiguousTroveClassifier(
        "License :: OSI Approved :: ISC License (ISCL)",
      ),
    ).toBe(false);
  });

  test("every SPDX value in the map is a real SPDX id (typo-proof)", () => {
    const known = knownSpdxIds();
    const typos = TROVE_TO_SPDX.map(([, spdx]) => spdx).filter(
      (spdx) => !known.has(spdx),
    );
    expect(typos).toEqual([]);
  });
});

describe("PyPI response narrow (tolerant)", () => {
  test("reads info.license_expression / license / classifiers", () => {
    const info = narrowPypiResponse({
      info: {
        license_expression: "MIT",
        license: "MIT License",
        classifiers: [
          "License :: OSI Approved :: MIT License",
          "Programming Language :: Python",
        ],
      },
    });
    expect(info?.licenseExpression).toBe("MIT");
    expect(info?.license).toBe("MIT License");
    expect(info?.classifiers).toEqual([
      "License :: OSI Approved :: MIT License",
      "Programming Language :: Python",
    ]);
  });

  test("info: null narrows to undefined fields, never throws", () => {
    const info = narrowPypiResponse({ info: null });
    expect(info).toBeDefined();
    expect(info?.licenseExpression).toBeUndefined();
    expect(info?.license).toBeUndefined();
    expect(info?.classifiers).toBeUndefined();
  });

  test("wrong-typed fields narrow each to undefined", () => {
    const info = narrowPypiResponse({
      info: {
        license_expression: 5,
        license: { nested: true },
        classifiers: "not-an-array",
      },
    });
    expect(info?.licenseExpression).toBeUndefined();
    expect(info?.license).toBeUndefined();
    expect(info?.classifiers).toBeUndefined();
  });

  test("non-string classifier entries are dropped, string entries kept", () => {
    const info = narrowPypiResponse({
      info: {
        classifiers: ["License :: OSI Approved :: MIT License", 5, null],
      },
    });
    expect(info?.classifiers).toEqual([
      "License :: OSI Approved :: MIT License",
    ]);
  });

  test("a non-object top-level value narrows to undefined, never throws", () => {
    expect(narrowPypiResponse(null)).toBeUndefined();
    expect(narrowPypiResponse("nope")).toBeUndefined();
    expect(narrowPypiResponse(42)).toBeUndefined();
  });
});

describe("npm packument narrow (tolerant)", () => {
  test("reads versions[v].license and top-level license", () => {
    const doc = narrowNpmPackument({
      license: "ISC",
      versions: {
        "1.2.3": { license: "MIT" },
        "1.0.0": { license: "Apache-2.0" },
      },
    });
    expect(doc?.license).toBe("ISC");
    expect(doc?.versions?.["1.2.3"]?.license).toBe("MIT");
  });

  test("legacy license object { type } and licenses [{ type }] array are recognizable", () => {
    const doc = narrowNpmPackument({
      license: { type: "MIT" },
      licenses: [{ type: "MIT" }, { type: "Apache-2.0" }],
    });
    expect(doc?.licenseObject?.type).toBe("MIT");
    expect(doc?.licensesArray?.map((l) => l.type)).toEqual([
      "MIT",
      "Apache-2.0",
    ]);
  });

  test("version-level legacy license object and licenses array are narrowed too", () => {
    const doc = narrowNpmPackument({
      versions: {
        "1.0.0": { license: { type: "ISC" } },
        "2.0.0": { licenses: [{ type: "MIT" }, { type: "Apache-2.0" }] },
      },
    });
    expect(doc?.versions?.["1.0.0"]?.licenseObject?.type).toBe("ISC");
    expect(doc?.versions?.["2.0.0"]?.licensesArray?.map((l) => l.type)).toEqual(
      ["MIT", "Apache-2.0"],
    );
  });

  test("versions: null narrows to absent, never throws", () => {
    const doc = narrowNpmPackument({ versions: null, license: "MIT" });
    expect(doc).toBeDefined();
    expect(doc?.versions).toBeUndefined();
    expect(doc?.license).toBe("MIT");
  });

  test("a wrong-typed version entry narrows its license to undefined", () => {
    const doc = narrowNpmPackument({
      versions: { "1.0.0": 5, "2.0.0": { license: "MIT" } },
    });
    expect(doc?.versions?.["1.0.0"]?.license).toBeUndefined();
    expect(doc?.versions?.["2.0.0"]?.license).toBe("MIT");
  });

  test("a non-object top-level value narrows to undefined, never throws", () => {
    expect(narrowNpmPackument(null)).toBeUndefined();
    expect(narrowNpmPackument([])).toBeUndefined();
    expect(narrowNpmPackument("nope")).toBeUndefined();
  });
});

describe("mapLimit", () => {
  test("never exceeds the concurrency limit", async () => {
    let active = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const results = await mapLimit(items, 3, async (n) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((res) => setTimeout(res, 5));
      active -= 1;
      return n * 2;
    });
    expect(peak).toBeLessThanOrEqual(3);
    expect(results).toEqual(items.map((n) => n * 2));
  });

  test("preserves input order even when later items resolve first", async () => {
    const items = [3, 1, 2];
    const results = await mapLimit(items, 3, async (n) => {
      await new Promise((res) => setTimeout(res, n * 10));
      return `v${n}`;
    });
    expect(results).toEqual(["v3", "v1", "v2"]);
  });

  test("limit greater than item count spawns no idle over-workers", async () => {
    let started = 0;
    const items = [1, 2];
    await mapLimit(items, 8, async (n) => {
      started += 1;
      return n;
    });
    expect(started).toBe(items.length);
  });
});

describe("fetchJson", () => {
  type FetchImpl = (url: string, init?: RequestInit) => Promise<Response>;
  function withFetch<T>(impl: FetchImpl, run: () => Promise<T>): Promise<T> {
    const orig = globalThis.fetch;
    globalThis.fetch = impl as unknown as typeof fetch;
    return run().finally(() => {
      globalThis.fetch = orig;
    });
  }

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status });
  }

  // Tiny backoff keeps retry tests fast; production uses the 500ms default.
  const fastBackoff = { backoffBaseMs: 1 };

  test("returns the parsed JSON body on 200", async () => {
    const body = await withFetch(
      async () => jsonResponse({ ok: true }),
      () => fetchJson("https://registry.example/x"),
    );
    expect(body).toEqual({ ok: true });
  });

  test("retries a 429 with backoff, then resolves on a later 200", async () => {
    let calls = 0;
    const body = await withFetch(
      async () => {
        calls += 1;
        return calls < 3 ? jsonResponse({}, 429) : jsonResponse({ ok: true });
      },
      () => fetchJson("https://registry.example/retry", fastBackoff),
    );
    expect(calls).toBe(3);
    expect(body).toEqual({ ok: true });
  });

  test("throws a loud error naming status + URL on persistent 500", async () => {
    let calls = 0;
    const url = "https://registry.example/boom";
    await expect(
      withFetch(
        async () => {
          calls += 1;
          return jsonResponse({}, 500);
        },
        () => fetchJson(url, fastBackoff),
      ),
    ).rejects.toThrow(
      new RegExp(`500.*${url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    expect(calls).toBeGreaterThan(1); // retried before giving up
  });

  test("throws loudly on a 404 (never a silent sentinel)", async () => {
    await expect(
      withFetch(
        async () => jsonResponse({}, 404),
        () => fetchJson("https://registry.example/missing"),
      ),
    ).rejects.toThrow(/404/);
  });

  test("sends no custom Accept header (the npm 406 gotcha)", async () => {
    let seen: HeadersInit | undefined;
    await withFetch(
      async (_url: string, init?: RequestInit) => {
        seen = init?.headers;
        return jsonResponse({ ok: true });
      },
      () => fetchJson("https://registry.example/headers"),
    );
    const headers = new Headers(seen);
    expect(headers.has("accept")).toBe(false);
    expect(headers.get("user-agent")).toContain("sbom-license-tool");
  });
});

describe("PyPI 3-layer resolver", () => {
  test("Layer 1: license_expression wins, raw verbatim, via license-expression HIGH", () => {
    const result = resolvePypiLicense(registryFixture("pypi-anyio.json"));
    expect(result).toEqual({
      raw: "MIT",
      via: "license-expression",
      confidence: "high",
    });
  });

  test("Layer 2: a short single-line license field resolves HIGH (raw only, no correction)", () => {
    const result = resolvePypiLicense({
      info: { license_expression: "", license: "MPL 2.0", classifiers: [] },
    });
    expect(result).toEqual({
      raw: "MPL 2.0",
      via: "license-field",
      confidence: "high",
    });
  });

  test("Layer 2 guard: a full-text license field (comm) is rejected and falls through to Layer 3", () => {
    // The comm fixture carries the full BSD-3 license TEXT in info.license and
    // an ambiguous BSD classifier — the field must NOT be treated as an id.
    const result = resolvePypiLicense(
      registryFixture("pypi-comm-fulltext.json"),
    );
    expect(result).toEqual({
      raw: "BSD License",
      via: "classifier",
      confidence: "low",
    });
  });

  test("Layer 2 guard: a >=60-char single-line license field also falls through", () => {
    const long = "x".repeat(60); // length >= 60 → not an id
    const result = resolvePypiLicense({
      info: { license: long, classifiers: [] },
    });
    expect(result).toBeNull();
  });

  test("Layer 3: an ambiguous BSD classifier (jinja2) resolves raw via the label, tagged LOW", () => {
    const result = resolvePypiLicense(
      registryFixture("pypi-jinja2-classifier.json"),
    );
    expect(result).toEqual({
      raw: "BSD License",
      via: "classifier",
      confidence: "low",
    });
  });

  test("Layer 3: a precise mapped classifier (MIT) resolves to the SPDX id, HIGH", () => {
    const result = resolvePypiLicense({
      info: {
        classifiers: ["License :: OSI Approved :: MIT License"],
      },
    });
    expect(result).toEqual({
      raw: "MIT",
      via: "classifier",
      confidence: "high",
    });
  });

  test("empty expression + empty license + no License classifier → null (matplotlib-inline-style)", () => {
    const result = resolvePypiLicense({
      info: {
        license_expression: "",
        license: "",
        classifiers: ["Programming Language :: Python :: 3"],
      },
    });
    expect(result).toBeNull();
  });

  test("a malformed/non-object response narrows to null, never throws", () => {
    expect(resolvePypiLicense(null)).toBeNull();
    expect(resolvePypiLicense("nope")).toBeNull();
    expect(resolvePypiLicense({ info: null })).toBeNull();
  });
});

describe("npm packument resolver", () => {
  test("versions[version].license wins over top-level (color-convert)", () => {
    const result = resolveNpmLicense(
      registryFixture("npm-color-convert.json"),
      "1.9.3",
    );
    expect(result).toEqual({ raw: "MIT", via: "version-license" });
  });

  test("falls back to the top-level license when the exact version has none (cjs alias)", () => {
    // The *-cjs alias packument: the exact version omits license, but the
    // top-level legacy { type } object resolves it via the packument path.
    const result = resolveNpmLicense(
      registryFixture("npm-cjs-alias.json"),
      "8.1.1",
    );
    expect(result).toEqual({ raw: "ISC", via: "top-license-object" });
  });

  test("a legacy top-level license object { type } resolves to its type", () => {
    const result = resolveNpmLicense(
      { license: { type: "ISC" }, versions: { "1.0.0": {} } },
      "1.0.0",
    );
    expect(result).toEqual({ raw: "ISC", via: "top-license-object" });
  });

  test("a legacy licenses [{ type }] array OR-joins into an SPDX OR expression", () => {
    const result = resolveNpmLicense(
      {
        licenses: [{ type: "MIT" }, { type: "Apache-2.0" }],
        versions: { "1.0.0": {} },
      },
      "1.0.0",
    );
    expect(result).toEqual({
      raw: "(MIT OR Apache-2.0)",
      via: "top-licenses-array",
    });
  });

  test("a single-element licenses [{ type }] array is not parenthesized", () => {
    const result = resolveNpmLicense(
      { licenses: [{ type: "MIT" }], versions: { "1.0.0": {} } },
      "1.0.0",
    );
    expect(result).toEqual({ raw: "MIT", via: "top-licenses-array" });
  });

  test("a top-level string license is used when the version has none", () => {
    const result = resolveNpmLicense(
      { license: "BSD-3-Clause", versions: { "2.0.0": {} } },
      "2.0.0",
    );
    expect(result).toEqual({ raw: "BSD-3-Clause", via: "top-license" });
  });

  test("a legacy versions[v].licenses [{ type }] array resolves at the version level (compute-gcd shape)", () => {
    // Older packages (compute-gcd, memorystream, svg-tags, validate.io-*)
    // publish MIT ONLY in the version-level legacy licenses array, with NO
    // top-level field — dropping it was a false-negative bug.
    const result = resolveNpmLicense(
      {
        versions: {
          "1.2.1": { licenses: [{ type: "MIT" }] },
        },
      },
      "1.2.1",
    );
    expect(result).toEqual({ raw: "MIT", via: "version-licenses-array" });
  });

  test("a legacy versions[v].license { type } object resolves at the version level", () => {
    const result = resolveNpmLicense(
      { versions: { "1.0.0": { license: { type: "ISC" } } } },
      "1.0.0",
    );
    expect(result).toEqual({ raw: "ISC", via: "version-license-object" });
  });

  test("a multi-element version-level licenses array OR-joins", () => {
    const result = resolveNpmLicense(
      {
        versions: {
          "1.0.0": { licenses: [{ type: "MIT" }, { type: "Apache-2.0" }] },
        },
      },
      "1.0.0",
    );
    expect(result).toEqual({
      raw: "(MIT OR Apache-2.0)",
      via: "version-licenses-array",
    });
  });

  test("the version-level string license wins over a version-level legacy array", () => {
    const result = resolveNpmLicense(
      {
        versions: {
          "1.0.0": { license: "MIT", licenses: [{ type: "Apache-2.0" }] },
        },
      },
      "1.0.0",
    );
    expect(result).toEqual({ raw: "MIT", via: "version-license" });
  });

  test("a version-level legacy array wins over a top-level string", () => {
    const result = resolveNpmLicense(
      {
        license: "BSD-3-Clause",
        versions: { "1.0.0": { licenses: [{ type: "MIT" }] } },
      },
      "1.0.0",
    );
    expect(result).toEqual({ raw: "MIT", via: "version-licenses-array" });
  });

  test("an empty-license packument everywhere (node-clone) → null", () => {
    const result = resolveNpmLicense(
      registryFixture("npm-node-clone-null.json"),
      "0.1.1",
    );
    expect(result).toBeNull();
  });

  test("an unknown version with no top-level license → null", () => {
    const result = resolveNpmLicense(
      { versions: { "1.0.0": { license: "MIT" } } },
      "9.9.9",
    );
    expect(result).toBeNull();
  });

  test("a malformed/non-object packument narrows to null, never throws", () => {
    expect(resolveNpmLicense(null, "1.0.0")).toBeNull();
    expect(resolveNpmLicense("nope", "1.0.0")).toBeNull();
    expect(resolveNpmLicense([], "1.0.0")).toBeNull();
  });
});

describe("committed purl-keyed cache", () => {
  const positive: CacheEntry = {
    license: "MIT",
    fetchedFrom: "pypi",
    via: "license-expression",
    resolvable: true,
  };
  const negative: CacheEntry = {
    license: null,
    fetchedFrom: "npm",
    via: "unresolved",
    resolvable: false,
  };

  function tempDir(): string {
    return mkdtempSync(join(tmpdir(), "enrich-cache-"));
  }

  test("serializeCache is deterministic: sorted keys, indent 2, LF, trailing newline, no timestamp", () => {
    const cache = new Map<string, CacheEntry>();
    // Insert out of sorted order to prove the serializer sorts.
    putEntry(cache, "pkg:npm/node-clone@0.1.1", negative);
    putEntry(cache, "pkg:pypi/anyio@4.12.1", positive);

    const bytes = serializeCache(cache);
    expect(bytes.endsWith("\n")).toBe(true);
    expect(bytes.includes("\r")).toBe(false);
    expect(bytes).not.toMatch(/timestamp|fetchedAt|\d{4}-\d{2}-\d{2}T/);
    // Keys sorted by code unit: "pkg:npm/..." < "pkg:pypi/..."; indent 2.
    expect(bytes.indexOf("pkg:npm/node-clone@0.1.1")).toBeLessThan(
      bytes.indexOf("pkg:pypi/anyio@4.12.1"),
    );
    expect(bytes).toContain('  "version": 1');
    // Double-serialize is byte-identical.
    expect(serializeCache(cache)).toBe(bytes);
  });

  test("a round-trip through serialize → readCache is lossless for positive and negative entries", () => {
    const dir = tempDir();
    try {
      const path = join(dir, "enrichment-cache.json");
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:pypi/anyio@4.12.1", positive);
      putEntry(cache, "pkg:npm/node-clone@0.1.1", negative);
      writeFileSync(path, serializeCache(cache));

      const loaded = readCache(path);
      expect(getEntry(loaded, "pkg:pypi/anyio@4.12.1")).toEqual(positive);
      expect(getEntry(loaded, "pkg:npm/node-clone@0.1.1")).toEqual(negative);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a verbatim URL-encoded purl key (%40babel/core) round-trips intact", () => {
    const dir = tempDir();
    try {
      const path = join(dir, "enrichment-cache.json");
      const key = "pkg:npm/%40babel/core@7.27.7";
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, key, { ...positive, fetchedFrom: "npm" });
      writeFileSync(path, serializeCache(cache));

      const loaded = readCache(path);
      expect(getEntry(loaded, key)?.license).toBe("MIT");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("readCache on a missing file yields an empty cache, never throws", () => {
    const loaded = readCache(join(tmpdir(), "definitely-absent-cache.json"));
    expect(loaded.size).toBe(0);
  });

  test("getEntry returns the entry on a hit and undefined on a miss (zero I/O)", () => {
    const cache = new Map<string, CacheEntry>();
    putEntry(cache, "pkg:pypi/anyio@4.12.1", positive);
    expect(getEntry(cache, "pkg:pypi/anyio@4.12.1")).toEqual(positive);
    expect(getEntry(cache, "pkg:pypi/absent@1.0.0")).toBeUndefined();
  });

  test("a negative entry is distinguishable from a positive one after a round-trip", () => {
    const dir = tempDir();
    try {
      const path = join(dir, "enrichment-cache.json");
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:npm/node-clone@0.1.1", negative);
      writeFileSync(path, serializeCache(cache));

      const entry = getEntry(readCache(path), "pkg:npm/node-clone@0.1.1");
      expect(entry?.resolvable).toBe(false);
      expect(entry?.license).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a malformed envelope throws loudly (a poisoned cache is a config error, not silent)", () => {
    const dir = tempDir();
    try {
      const path = join(dir, "enrichment-cache.json");
      writeFileSync(path, "{ not valid json ");
      expect(() => readCache(path)).toThrow();

      writeFileSync(path, JSON.stringify({ version: 1 })); // missing entries
      expect(() => readCache(path)).toThrow();

      writeFileSync(path, JSON.stringify({ version: 1, entries: [] })); // entries not an object
      expect(() => readCache(path)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a cache serialized WITHOUT copyrights contains no 'copyrights' key (optional-field zero-churn)", () => {
    const cache = new Map<string, CacheEntry>();
    putEntry(cache, "pkg:npm/node-clone@0.1.1", negative);
    putEntry(cache, "pkg:pypi/anyio@4.12.1", positive);
    const bytes = serializeCache(cache);
    expect(bytes).not.toContain("copyrights");
  });

  test("an existing registry-shaped envelope (no copyrights) reads and re-serializes byte-identically (regression)", () => {
    const dir = tempDir();
    try {
      const path = join(dir, "enrichment-cache.json");
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:npm/node-clone@0.1.1", negative);
      putEntry(cache, "pkg:pypi/anyio@4.12.1", positive);
      const bytes = serializeCache(cache);
      writeFileSync(path, bytes);

      const loaded = readCache(path);
      expect(serializeCache(loaded)).toBe(bytes);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("enrichUnknowns orchestrator (cache-first, generate-fetch, check-stale)", () => {
  /** A package with at least one usable claim (resolves, never enriched). */
  function knownPackage(): PackageEntry {
    return {
      purl: "pkg:npm/mit-lib@3.0.0",
      name: "mit-lib",
      version: "3.0.0",
      occurrences: [{ target: "proj", isDevDependency: false }],
      licenseClaims: [{ raw: "MIT", kind: "spdx-id", source: "generator" }],
      scope: "app",
    };
  }

  /** A package with zero usable claims (findingFromClaims → unknown). */
  function unknownNpm(): PackageEntry {
    return {
      purl: "pkg:npm/no-claims@2.0.0",
      name: "no-claims",
      version: "2.0.0",
      occurrences: [{ target: "proj", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  /** A pypi unknown. */
  function unknownPypi(): PackageEntry {
    return {
      purl: "pkg:pypi/anyio@4.12.1",
      name: "anyio",
      version: "4.12.1",
      occurrences: [{ target: "apps/jupyter", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  function model(...packages: PackageEntry[]): CanonicalDependencies {
    return { packages };
  }

  function tempCachePath(): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), "enrich-orch-"));
    return { dir, path: join(dir, "enrichment-cache.json") };
  }

  /** A fetch stub returning a parsed-JSON Response body for any URL matched. */
  function fetchReturning(bodyFor: (url: string) => unknown): {
    fetch: typeof fetch;
    calls: string[];
  } {
    const calls: string[] = [];
    const impl = (async (input: string | URL | Request): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push(url);
      return new Response(JSON.stringify(bodyFor(url)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    return { fetch: impl, calls };
  }

  /** Run `fn` with globalThis.fetch swapped, always restored in finally. */
  async function withFetch<T>(
    impl: typeof fetch,
    fn: () => Promise<T>,
  ): Promise<T> {
    const original = globalThis.fetch;
    globalThis.fetch = impl;
    try {
      return await fn();
    } finally {
      globalThis.fetch = original;
    }
  }

  /** The registry claim appended to a package, or undefined when none was. */
  function registryClaim(
    entry: PackageEntry | undefined,
  ): LicenseClaim | undefined {
    return entry?.licenseClaims.find((c) => c.source === "registry");
  }

  test("a package with a usable claim is untouched (never enriched, zero fetch)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchReturning(() => ({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(knownPackage()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual([]);
      expect(result.staleUnknowns).toEqual([]);
      const pkg = result.model.packages[0];
      expect(registryClaim(pkg)).toBeUndefined();
      expect(pkg?.licenseClaims).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a cache HIT appends the registry claim with zero fetch (either mode)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:npm/no-claims@2.0.0", {
        license: "MIT",
        fetchedFrom: "npm",
        via: "version-license",
        resolvable: true,
      });
      writeFileSync(path, serializeCache(cache));

      for (const mode of ["generate", "check"] as const) {
        const { fetch, calls } = fetchReturning(() => ({}));
        const result = await withFetch(fetch, () =>
          enrichUnknowns(model(unknownNpm()), {
            mode,
            cachePath: path,
            verbose: false,
          }),
        );
        expect(calls).toEqual([]);
        expect(result.staleUnknowns).toEqual([]);
        const claim = registryClaim(result.model.packages[0]);
        expect(claim).toEqual({
          raw: "MIT",
          kind: "expression",
          source: "registry",
        });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a NEGATIVE cache hit leaves the package unknown with no fetch (either mode)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:npm/no-claims@2.0.0", {
        license: null,
        fetchedFrom: "npm",
        via: "unresolved",
        resolvable: false,
      });
      writeFileSync(path, serializeCache(cache));

      for (const mode of ["generate", "check"] as const) {
        const { fetch, calls } = fetchReturning(() => ({}));
        const result = await withFetch(fetch, () =>
          enrichUnknowns(model(unknownNpm()), {
            mode,
            cachePath: path,
            verbose: false,
          }),
        );
        expect(calls).toEqual([]);
        expect(result.staleUnknowns).toEqual([]);
        expect(registryClaim(result.model.packages[0])).toBeUndefined();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generate + miss: fetches npm packument, appends claim, records a positive cache entry", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchReturning((url) => {
        expect(url).toBe("https://registry.npmjs.org/no-claims");
        return { versions: { "2.0.0": { license: "MIT" } } };
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNpm()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toHaveLength(1);
      expect(registryClaim(result.model.packages[0])).toEqual({
        raw: "MIT",
        kind: "expression",
        source: "registry",
      });
      // Recorded a positive entry to the committed cache.
      const recorded = getEntry(readCache(path), "pkg:npm/no-claims@2.0.0");
      expect(recorded?.resolvable).toBe(true);
      expect(recorded?.license).toBe("MIT");
      expect(recorded?.fetchedFrom).toBe("npm");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generate + miss: fetches the PyPI JSON URL and records the resolution", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchReturning((url) => {
        expect(url).toBe("https://pypi.org/pypi/anyio/4.12.1/json");
        return { info: { license_expression: "MIT" } };
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownPypi()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual(["https://pypi.org/pypi/anyio/4.12.1/json"]);
      expect(registryClaim(result.model.packages[0])?.raw).toBe("MIT");
      const recorded = getEntry(readCache(path), "pkg:pypi/anyio@4.12.1");
      expect(recorded?.fetchedFrom).toBe("pypi");
      expect(recorded?.license).toBe("MIT");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a scoped npm purl (%40babel/core) fetches the URL-encoded packument name", async () => {
    const { dir, path } = tempCachePath();
    try {
      const scoped: PackageEntry = {
        purl: "pkg:npm/%40babel/core@7.27.7",
        name: "@babel/core",
        version: "7.27.7",
        occurrences: [{ target: "proj", isDevDependency: false }],
        licenseClaims: [],
        scope: "app",
      };
      const { fetch, calls } = fetchReturning(() => ({
        versions: { "7.27.7": { license: "MIT" } },
      }));
      await withFetch(fetch, () =>
        enrichUnknowns(model(scoped), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual(["https://registry.npmjs.org/@babel%2Fcore"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generate + clean 200-empty answer: records a NEGATIVE entry (resolvable:false)", async () => {
    const { dir, path } = tempCachePath();
    try {
      // A clean 200 with no license anywhere → the resolver returns null.
      const { fetch } = fetchReturning(() => ({
        versions: { "2.0.0": {} },
      }));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNpm()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      // Package stays unknown (no registry claim appended).
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      // But the clean-empty answer IS cached as a negative entry.
      const recorded = getEntry(readCache(path), "pkg:npm/no-claims@2.0.0");
      expect(recorded?.resolvable).toBe(false);
      expect(recorded?.license).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generate + fetch FAILURE: raises loudly and writes NO cache entry (never a false negative)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const failing = (async (): Promise<Response> => {
        throw new Error("NETWORK DOWN");
      }) as unknown as typeof fetch;
      await expect(
        withFetch(failing, () =>
          enrichUnknowns(model(unknownNpm()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            // small backoff so the retry loop doesn't take seconds
            backoffBaseMs: 1,
          }),
        ),
      ).rejects.toThrow();
      // No cache file was written (a transient outage must never poison).
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("check + miss: NO fetch, NO write — returns the purl as a stale unknown", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchReturning(() => ({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNpm()), {
          mode: "check",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual([]);
      expect(result.staleUnknowns).toEqual(["pkg:npm/no-claims@2.0.0"]);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      // Check writes nothing — the cache file was never created.
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the input model is never mutated (claims appended via spread)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const input = model(unknownNpm());
      const before = input.packages[0]!.licenseClaims;
      const { fetch } = fetchReturning(() => ({
        versions: { "2.0.0": { license: "MIT" } },
      }));
      await withFetch(fetch, () =>
        enrichUnknowns(input, {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      // The original array is untouched (no in-place push).
      expect(input.packages[0]!.licenseClaims).toBe(before);
      expect(input.packages[0]!.licenseClaims).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("one packument fetch is reused across multiple versions of the same npm name", async () => {
    const { dir, path } = tempCachePath();
    try {
      const v1: PackageEntry = {
        ...unknownNpm(),
        purl: "pkg:npm/dup@1.0.0",
        version: "1.0.0",
      };
      const v2: PackageEntry = {
        ...unknownNpm(),
        purl: "pkg:npm/dup@2.0.0",
        version: "2.0.0",
      };
      v1.name = "dup";
      v2.name = "dup";
      const { fetch, calls } = fetchReturning(() => ({
        versions: {
          "1.0.0": { license: "MIT" },
          "2.0.0": { license: "ISC" },
        },
      }));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(v1, v2), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      // Exactly ONE packument fetch served both versions.
      expect(calls).toEqual(["https://registry.npmjs.org/dup"]);
      const claims = result.model.packages.map((p) => registryClaim(p)?.raw);
      expect(claims).toEqual(["MIT", "ISC"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // INV-04 conscious-change proof: the committed cache stores the RAW registry
  // string ("BSD License") — UNCHANGED this plan. The INTERPRETATION changed:
  // a cached BSD-label entry now resolves to imprecise-BSD, never BSD-2-Clause.
  // The 23 Jupyter BSD rows ride this path; 05-06's tool-level override will
  // later disambiguate them to BSD-3-Clause. No override is authored here.
  test("a cached BSD-label entry resolves to imprecise-BSD (never BSD-2-Clause) end-to-end", async () => {
    const { dir, path } = tempCachePath();
    try {
      const cache = new Map<string, CacheEntry>();
      // The exact committed-cache shape for a Jupyter BSD row: raw label "BSD
      // License", resolved via the ambiguous classifier.
      putEntry(cache, "pkg:pypi/colorama@0.4.6", {
        license: "BSD License",
        fetchedFrom: "pypi",
        via: "classifier",
        resolvable: true,
      });
      writeFileSync(path, serializeCache(cache));

      const { fetch, calls } = fetchReturning(() => ({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(
          model({
            purl: "pkg:pypi/colorama@0.4.6",
            name: "colorama",
            version: "0.4.6",
            occurrences: [{ target: "apps/jupyter", isDevDependency: false }],
            licenseClaims: [],
            scope: "app",
          }),
          { mode: "check", cachePath: path, verbose: false },
        ),
      );
      // Cache hit — zero fetch — appended the raw "BSD License" claim.
      expect(calls).toEqual([]);
      expect(registryClaim(result.model.packages[0])?.raw).toBe("BSD License");

      // The finding INTERPRETS that raw as imprecise-BSD (INV-04).
      const { model: annotated } = annotateFindings(result.model, []);
      const finding = annotated.packages[0]!.finding!;
      expect(finding.confidence).toBe("imprecise");
      expect(finding.impreciseFamily).toBe("BSD");
      expect(finding.expression).toBeNull();
      expect(finding.expression).not.toBe("BSD-2-Clause");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("enrichUnknowns terraform/github (version-tag, transient-vs-definitive, fetchedAt)", () => {
  const FIXED_NOW = new Date("2026-06-14T00:00:00.000Z");
  const fixedClock = (): Date => FIXED_NOW;
  // Tiny backoff so the transient retry loop doesn't take seconds.
  const fastBackoff = 1;

  function model(...packages: PackageEntry[]): CanonicalDependencies {
    return { packages };
  }

  function tempCachePath(): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), "enrich-tf-"));
    return { dir, path: join(dir, "enrichment-cache.json") };
  }

  /** A pkg:terraform provider unknown (hashicorp/aws @ 6.42.0). */
  function unknownProvider(): PackageEntry {
    return {
      purl: "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      name: "hashicorp/aws",
      version: "6.42.0",
      occurrences: [{ target: "infrastructure", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  /**
   * A pkg:terraform module unknown (terraform-aws-modules/vpc/aws @ 5.1.2). The
   * 4-segment purl (host + ns/name/provider) marks it a MODULE by COUNT —
   * OpenTofu rewrites the host to registry.opentofu.org for modules too.
   */
  function unknownModule(): PackageEntry {
    return {
      purl: "pkg:terraform/registry.opentofu.org/terraform-aws-modules/vpc/aws@5.1.2",
      name: "terraform-aws-modules/vpc/aws",
      version: "5.1.2",
      occurrences: [{ target: "infrastructure", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  function registryClaim(
    entry: PackageEntry | undefined,
  ): LicenseClaim | undefined {
    return entry?.licenseClaims.find((c) => c.source === "registry");
  }

  /** A fetch stub mapping a full URL → a Response (status + body). */
  function fetchByUrl(responder: (url: string) => Response): {
    fetch: typeof fetch;
    calls: string[];
  } {
    const calls: string[] = [];
    const impl = (async (input: string | URL | Request): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push(url);
      return responder(url);
    }) as typeof fetch;
    return { fetch: impl, calls };
  }

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }

  async function withFetch<T>(
    impl: typeof fetch,
    fn: () => Promise<T>,
  ): Promise<T> {
    const original = globalThis.fetch;
    globalThis.fetch = impl;
    try {
      return await fn();
    } finally {
      globalThis.fetch = original;
    }
  }

  test("a fresh pkg:terraform unknown with NO cache entry is STALE in check (exit 2) — Pitfall 3 closed", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl(() => jsonResponse({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "check",
          cachePath: path,
          verbose: false,
        }),
      );
      // The load-bearing parsePurl edit: terraform is now in the allow-list, so
      // the miss is COUNTED stale (before the fix it was silently skipped → a
      // missing license slipped past check).
      expect(calls).toEqual([]);
      expect(result.staleUnknowns).toEqual([
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      ]);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generate + provider miss: resolves MPL-2.0 at the v<version> ref, positive entry with fetchedFrom:github + fetchedAt", async () => {
    const { dir, path } = tempCachePath();
    try {
      const expectedUrl =
        "https://api.github.com/repos/hashicorp/terraform-provider-aws/license?ref=v6.42.0";
      const { fetch, calls } = fetchByUrl((url) => {
        expect(url).toBe(expectedUrl);
        return jsonResponse({
          license: { spdx_id: "MPL-2.0" },
          download_url: "https://raw.example/LICENSE",
        });
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      expect(calls).toEqual([expectedUrl]); // first ref won, no fallback
      expect(registryClaim(result.model.packages[0])?.raw).toBe("MPL-2.0");

      const recorded = getEntry(
        readCache(path),
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      );
      expect(recorded?.resolvable).toBe(true);
      expect(recorded?.license).toBe("MPL-2.0");
      expect(recorded?.fetchedFrom).toBe("github");
      expect(recorded?.via).toBe("github-license@v6.42.0");
      expect(recorded?.fetchedAt).toBe("2026-06-14T00:00:00.000Z");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("module resolves Apache-2.0 (terraform-aws-modules → terraform-aws-vpc)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const expectedUrl =
        "https://api.github.com/repos/terraform-aws-modules/terraform-aws-vpc/license?ref=v5.1.2";
      const { fetch } = fetchByUrl((url) => {
        expect(url).toBe(expectedUrl);
        return jsonResponse({ license: { spdx_id: "Apache-2.0" } });
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownModule()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      expect(registryClaim(result.model.packages[0])?.raw).toBe("Apache-2.0");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("ref fallback: v<version> 404 → <version> 200 selects the SECOND ref", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl((url) => {
        if (url.endsWith("?ref=v6.42.0")) return jsonResponse({}, 404);
        if (url.endsWith("?ref=6.42.0")) {
          return jsonResponse({ license: { spdx_id: "MPL-2.0" } });
        }
        throw new Error(`unexpected url ${url}`);
      });
      await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      expect(calls).toEqual([
        "https://api.github.com/repos/hashicorp/terraform-provider-aws/license?ref=v6.42.0",
        "https://api.github.com/repos/hashicorp/terraform-provider-aws/license?ref=6.42.0",
      ]);
      const recorded = getEntry(
        readCache(path),
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      );
      expect(recorded?.via).toBe("github-license@6.42.0");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("W#4: both version tags 404 → NO default-branch fetch, recorded as a definitive negative (no wrong-version license)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl((url) => {
        // Both v<version> and <version> tags 404; a no-?ref request (the old
        // default-branch fallback) would return MPL-2.0 — but it must NEVER be
        // issued now, so this branch is unreachable in the fixed behavior.
        if (url.includes("?ref=")) return jsonResponse({}, 404);
        return jsonResponse({ license: { spdx_id: "MPL-2.0" } });
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      // NO call is the bare (no-?ref) default-branch URL — every fetch carries ?ref=.
      expect(
        calls.some(
          (u) =>
            u ===
            "https://api.github.com/repos/hashicorp/terraform-provider-aws/license",
        ),
      ).toBe(false);
      expect(calls.every((u) => u.includes("?ref="))).toBe(true);
      const recorded = getEntry(
        readCache(path),
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      );
      // A definitive negative (no license) — never the default-branch MPL-2.0.
      expect(recorded?.license).toBeNull();
      expect(recorded?.resolvable).toBe(false);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("TRANSIENT 403 on a needed miss HARD-FAILS the run loudly and writes NO entry", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch } = fetchByUrl(() => jsonResponse({}, 403));
      await expect(
        withFetch(fetch, () =>
          enrichUnknowns(model(unknownProvider()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            backoffBaseMs: fastBackoff,
          }),
        ),
      ).rejects.toThrow(/github 403/);
      // No cache written — a transient throttle must never poison as a negative.
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a network error (after retries) on a needed miss HARD-FAILS and writes NO entry", async () => {
    const { dir, path } = tempCachePath();
    try {
      const failing = (async (): Promise<Response> => {
        throw new Error("NETWORK DOWN");
      }) as unknown as typeof fetch;
      await expect(
        withFetch(failing, () =>
          enrichUnknowns(model(unknownProvider()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            backoffBaseMs: fastBackoff,
          }),
        ),
      ).rejects.toThrow();
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a persistent 5xx on a needed miss HARD-FAILS and writes NO entry", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch } = fetchByUrl(() => jsonResponse({}, 503));
      await expect(
        withFetch(fetch, () =>
          enrichUnknowns(model(unknownProvider()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            backoffBaseMs: fastBackoff,
          }),
        ),
      ).rejects.toThrow(/github 503/);
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a clean 404 across ALL candidate refs writes a NEGATIVE entry → unknown (POL-04)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl(() => jsonResponse({}, 404));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      // Both version-tag refs tried, all 404 (no default-branch ref — W#4).
      expect(calls).toHaveLength(2);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(
        readCache(path),
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      );
      expect(recorded?.resolvable).toBe(false);
      expect(recorded?.license).toBeNull();
      expect(recorded?.fetchedFrom).toBe("github");
      expect(recorded?.fetchedAt).toBeUndefined(); // negative entries carry no stamp
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a NOASSERTION body across all refs writes a NEGATIVE entry → unknown", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch } = fetchByUrl(() =>
        jsonResponse({ license: { spdx_id: "NOASSERTION" } }),
      );
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(
        readCache(path),
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
      );
      expect(recorded?.resolvable).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a cache HIT never refetches and a warm second generate is BYTE-IDENTICAL (fetchedAt unchanged)", async () => {
    const { dir, path } = tempCachePath();
    try {
      // First generate stamps fetchedAt from the fixed clock.
      const { fetch: fetch1 } = fetchByUrl(() =>
        jsonResponse({ license: { spdx_id: "MPL-2.0" } }),
      );
      await withFetch(fetch1, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: fixedClock,
        }),
      );
      const firstBytes = readFileSync(path, "utf8");

      // Warm second generate with a DIFFERENT clock and a fetch that would throw
      // if called — the hit must not refetch nor rewrite.
      const throwingFetch = (async (): Promise<Response> => {
        throw new Error("must not fetch on a warm hit");
      }) as unknown as typeof fetch;
      const result = await withFetch(throwingFetch, () =>
        enrichUnknowns(model(unknownProvider()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
          now: () => new Date("2099-01-01T00:00:00.000Z"),
        }),
      );
      const secondBytes = readFileSync(path, "utf8");

      expect(secondBytes).toBe(firstBytes); // byte-identical, fetchedAt unchanged
      expect(registryClaim(result.model.packages[0])?.raw).toBe("MPL-2.0");
      expect(firstBytes).toContain('"fetchedAt": "2026-06-14T00:00:00.000Z"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("GITHUB_TOKEN is sent as a Bearer header when set; absent header when unset", async () => {
    const { dir, path } = tempCachePath();
    try {
      const seen: { auth: string | null } = { auth: "sentinel" };
      const impl = (async (
        _input: string | URL | Request,
        init?: RequestInit,
      ): Promise<Response> => {
        seen.auth = new Headers(init?.headers).get("authorization");
        return jsonResponse({ license: { spdx_id: "MPL-2.0" } });
      }) as typeof fetch;

      const prior = process.env.GITHUB_TOKEN;
      try {
        process.env.GITHUB_TOKEN = "ghp_test_token";
        await withFetch(impl, () =>
          enrichUnknowns(model(unknownProvider()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            backoffBaseMs: fastBackoff,
            now: fixedClock,
          }),
        );
        expect(seen.auth).toBe("Bearer ghp_test_token");

        // Unset → no Authorization header.
        delete process.env.GITHUB_TOKEN;
        seen.auth = "sentinel";
        const { dir: dir2, path: path2 } = tempCachePath();
        try {
          await withFetch(impl, () =>
            enrichUnknowns(model(unknownProvider()), {
              mode: "generate",
              cachePath: path2,
              verbose: false,
              backoffBaseMs: fastBackoff,
              now: fixedClock,
            }),
          );
          expect(seen.auth).toBeNull();
        } finally {
          rmSync(dir2, { recursive: true, force: true });
        }
      } finally {
        if (prior === undefined) delete process.env.GITHUB_TOKEN;
        else process.env.GITHUB_TOKEN = prior;
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a malformed terraform purl (wrong segment count) resolves to a NEGATIVE entry with no fetch", async () => {
    const { dir, path } = tempCachePath();
    try {
      // encodedName has only 2 segments (<host>/<one>) — neither a 3-segment
      // provider nor a 4-segment module → null repo → never a fetch.
      const malformedPurl = "pkg:terraform/registry.opentofu.org/onlyone@1.0.0";
      const weird: PackageEntry = {
        purl: malformedPurl,
        name: "onlyone",
        version: "1.0.0",
        occurrences: [{ target: "infrastructure", isDevDependency: false }],
        licenseClaims: [],
        scope: "app",
      };
      const { fetch, calls } = fetchByUrl(() => jsonResponse({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(weird), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toEqual([]); // never a wrong guess, no fetch attempted
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(readCache(path), malformedPurl);
      expect(recorded?.resolvable).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("fetchJsonOr404 (fetchJson posture, 404 as a value)", () => {
  type FetchImpl = (url: string, init?: RequestInit) => Promise<Response>;
  function withFetch<T>(impl: FetchImpl, run: () => Promise<T>): Promise<T> {
    const orig = globalThis.fetch;
    globalThis.fetch = impl as unknown as typeof fetch;
    return run().finally(() => {
      globalThis.fetch = orig;
    });
  }

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status });
  }

  // Tiny backoff keeps retry tests fast; production uses the 500ms default.
  const fastBackoff = { backoffBaseMs: 1 };

  test("200 → { status: 200, body } with the parsed JSON", async () => {
    const result = await withFetch(
      async () => jsonResponse({ ok: true }),
      () => fetchJsonOr404("https://api.nuget.org/v3/x"),
    );
    expect(result).toEqual({ status: 200, body: { ok: true } });
  });

  test("404 → { status: 404 } as a VALUE, never a throw", async () => {
    const result = await withFetch(
      async () => jsonResponse({}, 404),
      () => fetchJsonOr404("https://api.nuget.org/v3/missing"),
    );
    expect(result).toEqual({ status: 404 });
  });

  test("retries a 429 with backoff, then resolves on a later 200", async () => {
    let calls = 0;
    const result = await withFetch(
      async () => {
        calls += 1;
        return calls < 3 ? jsonResponse({}, 429) : jsonResponse({ ok: true });
      },
      () => fetchJsonOr404("https://api.nuget.org/v3/retry", fastBackoff),
    );
    expect(calls).toBe(3);
    expect(result).toEqual({ status: 200, body: { ok: true } });
  });

  test("persistent 5xx throws the loud registry error (fetchJson parity)", async () => {
    let calls = 0;
    await expect(
      withFetch(
        async () => {
          calls += 1;
          return jsonResponse({}, 503);
        },
        () => fetchJsonOr404("https://api.nuget.org/v3/boom", fastBackoff),
      ),
    ).rejects.toThrow(/registry 503 for https:\/\/api\.nuget\.org\/v3\/boom/);
    expect(calls).toBeGreaterThan(1); // retried before giving up
  });

  test("a network error after retries throws loudly", async () => {
    await expect(
      withFetch(
        async () => {
          throw new Error("NETWORK DOWN");
        },
        () => fetchJsonOr404("https://api.nuget.org/v3/down", fastBackoff),
      ),
    ).rejects.toThrow(/registry fetch failed/);
  });

  test("sends the User-Agent and NO custom Accept (the fetchJson contract)", async () => {
    let seen: HeadersInit | undefined;
    await withFetch(
      async (_url: string, init?: RequestInit) => {
        seen = init?.headers;
        return jsonResponse({ ok: true });
      },
      () => fetchJsonOr404("https://api.nuget.org/v3/headers"),
    );
    const headers = new Headers(seen);
    expect(headers.has("accept")).toBe(false);
    expect(headers.get("user-agent")).toContain("sbom-license-tool");
  });
});

describe("nuget registration URL builder + catalogEntry host pin", () => {
  test("lowercases BOTH the id and the version in the leaf URL (the casing 404 differential)", () => {
    expect(nugetRegistrationLeafUrl("EntityFramework", "7.0.0-Beta1")).toBe(
      "https://api.nuget.org/v3/registration5-gz-semver2/entityframework/7.0.0-beta1.json",
    );
  });

  test("URL-decodes the purl parts, then re-encodes each path segment (%2B round-trip)", () => {
    expect(nugetRegistrationLeafUrl("Meta.Package", "1.0.0%2Bbuild.5")).toBe(
      "https://api.nuget.org/v3/registration5-gz-semver2/meta.package/1.0.0%2Bbuild.5.json",
    );
  });

  test("catalogEntryUrlOf returns an api.nuget.org catalogEntry URL (the leaf fixture)", () => {
    expect(catalogEntryUrlOf(registryFixture("nuget-leaf.json"))).toBe(
      "https://api.nuget.org/v3/catalog0/data/2024.03.27.08.21.03/newtonsoft.json.13.0.4.json",
    );
  });

  test("an attacker leaf pointing at a foreign host yields undefined (SSRF pin)", () => {
    expect(
      catalogEntryUrlOf({ catalogEntry: "https://evil.example/steal" }),
    ).toBeUndefined();
  });

  test("a lookalike host (api.nuget.org.evil.example) fails the trailing-slash prefix", () => {
    expect(
      catalogEntryUrlOf({
        catalogEntry: "https://api.nuget.org.evil.example/catalog.json",
      }),
    ).toBeUndefined();
  });

  test("a missing/non-string/malformed catalogEntry yields undefined, never throws", () => {
    expect(catalogEntryUrlOf({})).toBeUndefined();
    expect(catalogEntryUrlOf({ catalogEntry: 42 })).toBeUndefined();
    expect(catalogEntryUrlOf(null)).toBeUndefined();
    expect(catalogEntryUrlOf("nope")).toBeUndefined();
  });
});

describe("nuget catalogEntry resolver (four-class ladder)", () => {
  test("class 1: licenseExpression wins verbatim, via license-expression HIGH", () => {
    expect(
      resolveNugetCatalogLicense(registryFixture("nuget-expression.json")),
    ).toEqual({ raw: "MIT", via: "license-expression", confidence: "high" });
  });

  test("class 2: an embedded licenseFile is an honest unknown (null) — the aka.ms sentinel never reads as a URL", () => {
    expect(
      resolveNugetCatalogLicense(registryFixture("nuget-licensefile.json")),
    ).toBeNull();
  });

  test("class 2 ladder order: licenseFile is checked BEFORE a decodable licenses.nuget.org URL", () => {
    // If the URL arm ran first this would (wrongly) resolve MIT — the embedded
    // file must win and stay an honest unknown.
    expect(
      resolveNugetCatalogLicense({
        licenseFile: "LICENSE.txt",
        licenseUrl: "https://licenses.nuget.org/MIT",
      }),
    ).toBeNull();
  });

  test("class 3: a licenses.nuget.org licenseUrl decodes its URL path to the SPDX expression", () => {
    expect(
      resolveNugetCatalogLicense({
        licenseUrl: "https://licenses.nuget.org/Apache-2.0",
      }),
    ).toEqual({
      raw: "Apache-2.0",
      via: "license-url-spdx",
      confidence: "high",
    });
  });

  test("class 3: an encoded compound expression decodes (normalizeRaw downstream stays the SPDX authority)", () => {
    expect(
      resolveNugetCatalogLicense({
        licenseUrl: "https://licenses.nuget.org/MIT%20OR%20Apache-2.0",
      }),
    ).toEqual({
      raw: "MIT OR Apache-2.0",
      via: "license-url-spdx",
      confidence: "high",
    });
  });

  test("class 3: an EMPTY decoded remainder → null (never an empty raw)", () => {
    expect(
      resolveNugetCatalogLicense({
        licenseUrl: "https://licenses.nuget.org/",
      }),
    ).toBeNull();
  });

  test("class 3: a malformed percent-escape in the path → null, never a throw", () => {
    expect(
      resolveNugetCatalogLicense({
        licenseUrl: "https://licenses.nuget.org/%E0%A4%A",
      }),
    ).toBeNull();
  });

  test("class 4: a pre-2019 url-only entry (github blob) is an honest unknown", () => {
    expect(
      resolveNugetCatalogLicense(registryFixture("nuget-urlonly.json")),
    ).toBeNull();
  });

  test("class 4: no license fields at all (the none fixture) → null", () => {
    expect(
      resolveNugetCatalogLicense(registryFixture("nuget-none.json")),
    ).toBeNull();
  });

  test("an empty licenseExpression falls through (never an empty raw)", () => {
    expect(
      resolveNugetCatalogLicense({
        licenseExpression: "  ",
        licenseUrl: "https://licenses.nuget.org/MIT",
      }),
    ).toEqual({ raw: "MIT", via: "license-url-spdx", confidence: "high" });
  });

  test("a malformed/garbage document narrows to null, never throws", () => {
    expect(resolveNugetCatalogLicense(null)).toBeNull();
    expect(resolveNugetCatalogLicense("nope")).toBeNull();
    expect(resolveNugetCatalogLicense([])).toBeNull();
    expect(resolveNugetCatalogLicense(42)).toBeNull();
  });
});

describe("nuget narrows (tolerant)", () => {
  test("narrowNugetLeaf reads catalogEntry; wrong-typed/absent → undefined field", () => {
    expect(
      narrowNugetLeaf({ catalogEntry: "https://api.nuget.org/x" }),
    ).toEqual({ catalogEntry: "https://api.nuget.org/x" });
    expect(narrowNugetLeaf({ catalogEntry: 42 })?.catalogEntry).toBeUndefined();
    expect(narrowNugetLeaf({})?.catalogEntry).toBeUndefined();
  });

  test("narrowNugetLeaf: a non-object top-level value → undefined, never throws", () => {
    expect(narrowNugetLeaf(null)).toBeUndefined();
    expect(narrowNugetLeaf([])).toBeUndefined();
    expect(narrowNugetLeaf("nope")).toBeUndefined();
  });

  test("narrowNugetCatalogEntry reads the three license fields, all optional", () => {
    const entry = narrowNugetCatalogEntry({
      licenseExpression: "MIT",
      licenseFile: "LICENSE.txt",
      licenseUrl: "https://licenses.nuget.org/MIT",
    });
    expect(entry).toEqual({
      licenseExpression: "MIT",
      licenseFile: "LICENSE.txt",
      licenseUrl: "https://licenses.nuget.org/MIT",
    });
  });

  test("narrowNugetCatalogEntry: wrong-typed fields coerce to undefined (skip-don't-throw)", () => {
    const entry = narrowNugetCatalogEntry({
      licenseExpression: 5,
      licenseFile: { nested: true },
      licenseUrl: ["array"],
    });
    expect(entry?.licenseExpression).toBeUndefined();
    expect(entry?.licenseFile).toBeUndefined();
    expect(entry?.licenseUrl).toBeUndefined();
  });

  test("narrowNugetCatalogEntry: a non-object top-level value → undefined", () => {
    expect(narrowNugetCatalogEntry(null)).toBeUndefined();
    expect(narrowNugetCatalogEntry([])).toBeUndefined();
    expect(narrowNugetCatalogEntry(7)).toBeUndefined();
  });
});

describe("enrichUnknowns nuget (two-step fetch, negative discipline, offline check)", () => {
  // Tiny backoff so the transient retry loop doesn't take seconds.
  const fastBackoff = 1;

  function model(...packages: PackageEntry[]): CanonicalDependencies {
    return { packages };
  }

  function tempCachePath(): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), "enrich-nuget-"));
    return { dir, path: join(dir, "enrichment-cache.json") };
  }

  /** A pkg:nuget unknown with a MIXED-CASE purl — the verbatim cache key. */
  function unknownNuget(): PackageEntry {
    return {
      purl: "pkg:nuget/Newtonsoft.Json@13.0.4",
      name: "Newtonsoft.Json",
      version: "13.0.4",
      occurrences: [{ target: "Fixture.App", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  // The stubbed URLs are LOWERCASE while the purl above is mixed-case — the
  // casing differential the URL builder owns.
  const LEAF_URL =
    "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/13.0.4.json";
  const CATALOG_URL =
    "https://api.nuget.org/v3/catalog0/data/2024.03.27.08.21.03/newtonsoft.json.13.0.4.json";

  function registryClaim(
    entry: PackageEntry | undefined,
  ): LicenseClaim | undefined {
    return entry?.licenseClaims.find((c) => c.source === "registry");
  }

  /** A fetch stub mapping a full URL → a Response (status + body). */
  function fetchByUrl(responder: (url: string) => Response): {
    fetch: typeof fetch;
    calls: string[];
  } {
    const calls: string[] = [];
    const impl = (async (input: string | URL | Request): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push(url);
      return responder(url);
    }) as typeof fetch;
    return { fetch: impl, calls };
  }

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }

  async function withFetch<T>(
    impl: typeof fetch,
    fn: () => Promise<T>,
  ): Promise<T> {
    const original = globalThis.fetch;
    globalThis.fetch = impl;
    try {
      return await fn();
    } finally {
      globalThis.fetch = original;
    }
  }

  test("positive path: leaf → catalogEntry (expression class) → registry claim + positive entry keyed by the VERBATIM purl, NO fetchedAt", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl((url) => {
        if (url === LEAF_URL)
          return jsonResponse({ catalogEntry: CATALOG_URL });
        if (url === CATALOG_URL) {
          return jsonResponse({
            licenseExpression: "MIT",
            licenseUrl: "https://licenses.nuget.org/MIT",
          });
        }
        throw new Error(`unexpected url ${url}`);
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      // Both fetches hit the LOWERCASED api.nuget.org URLs, in two-step order.
      expect(calls).toEqual([LEAF_URL, CATALOG_URL]);
      expect(registryClaim(result.model.packages[0])).toEqual({
        raw: "MIT",
        kind: "expression",
        source: "registry",
      });
      // Cache keyed by the VERBATIM mixed-case purl (never the lowercase URL id).
      const recorded = getEntry(
        readCache(path),
        "pkg:nuget/Newtonsoft.Json@13.0.4",
      );
      expect(recorded).toEqual({
        license: "MIT",
        fetchedFrom: "nuget",
        via: "license-expression",
        resolvable: true,
      });
      expect(recorded?.fetchedAt).toBeUndefined();
      // No timestamp anywhere in the committed bytes (zero warm-generate churn).
      expect(readFileSync(path, "utf8")).not.toContain("fetchedAt");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("private-feed path: leaf 404 → a governed NEGATIVE entry, package stays unknown, generate does NOT throw", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl(() => jsonResponse({}, 404));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toEqual([LEAF_URL]); // the leaf 404 is terminal — no second hop
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(
        readCache(path),
        "pkg:nuget/Newtonsoft.Json@13.0.4",
      );
      expect(recorded).toEqual({
        license: null,
        fetchedFrom: "nuget",
        via: "unresolved",
        resolvable: false,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("catalogEntry 404 → NEGATIVE (definitive, same as the leaf)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl((url) =>
        url === LEAF_URL
          ? jsonResponse({ catalogEntry: CATALOG_URL })
          : jsonResponse({}, 404),
      );
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toEqual([LEAF_URL, CATALOG_URL]);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(
        readCache(path),
        "pkg:nuget/Newtonsoft.Json@13.0.4",
      );
      expect(recorded?.resolvable).toBe(false);
      expect(recorded?.license).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("clean-empty: a none-class catalogEntry (no license fields) → NEGATIVE", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch } = fetchByUrl((url) =>
        url === LEAF_URL
          ? jsonResponse({ catalogEntry: CATALOG_URL })
          : jsonResponse({ id: "Newtonsoft.Json", version: "13.0.4" }),
      );
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      const recorded = getEntry(
        readCache(path),
        "pkg:nuget/Newtonsoft.Json@13.0.4",
      );
      expect(recorded?.resolvable).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a leaf with a MISSING catalogEntry → NEGATIVE after ONE fetch (malformed = clean no-answer)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch, calls } = fetchByUrl(() => jsonResponse({ listed: true }));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toEqual([LEAF_URL]); // never a second hop without a pinned URL
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      expect(
        getEntry(readCache(path), "pkg:nuget/Newtonsoft.Json@13.0.4")
          ?.resolvable,
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a leaf whose catalogEntry points at a FOREIGN host → NEGATIVE, and the stub saw NO request to the evil host (SSRF pin)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const evil = "https://evil.example/catalog.json";
      const { fetch, calls } = fetchByUrl((url) => {
        if (url === LEAF_URL) return jsonResponse({ catalogEntry: evil });
        throw new Error(`unexpected url ${url}`);
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toEqual([LEAF_URL]);
      expect(calls.some((u) => u.includes("evil.example"))).toBe(false);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      expect(
        getEntry(readCache(path), "pkg:nuget/Newtonsoft.Json@13.0.4")
          ?.resolvable,
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("TRANSIENT: a persistent 500 on the leaf THROWS loudly and writes NO entry (negative-poison impossible)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const { fetch } = fetchByUrl(() => jsonResponse({}, 500));
      await expect(
        withFetch(fetch, () =>
          enrichUnknowns(model(unknownNuget()), {
            mode: "generate",
            cachePath: path,
            verbose: false,
            backoffBaseMs: fastBackoff,
          }),
        ),
      ).rejects.toThrow(/registry 500/);
      expect(readCache(path).size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a pre-seeded POSITIVE nuget entry resolves with ZERO fetches", async () => {
    const { dir, path } = tempCachePath();
    try {
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:nuget/Newtonsoft.Json@13.0.4", {
        license: "MIT",
        fetchedFrom: "nuget",
        via: "license-expression",
        resolvable: true,
      });
      writeFileSync(path, serializeCache(cache));

      const { fetch, calls } = fetchByUrl(() => jsonResponse({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual([]);
      expect(registryClaim(result.model.packages[0])?.raw).toBe("MIT");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a pre-seeded NEGATIVE nuget entry stays unknown with ZERO fetches", async () => {
    const { dir, path } = tempCachePath();
    try {
      const cache = new Map<string, CacheEntry>();
      putEntry(cache, "pkg:nuget/Newtonsoft.Json@13.0.4", {
        license: null,
        fetchedFrom: "nuget",
        via: "unresolved",
        resolvable: false,
      });
      writeFileSync(path, serializeCache(cache));

      const { fetch, calls } = fetchByUrl(() => jsonResponse({}));
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(calls).toEqual([]);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      expect(result.staleUnknowns).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("check mode: a nuget unknown with NO cache entry is a stale unknown — NO network, NO cache write (offline check)", async () => {
    const { dir, path } = tempCachePath();
    try {
      const throwingFetch = (async (): Promise<Response> => {
        throw new Error("check must never fetch");
      }) as unknown as typeof fetch;
      const result = await withFetch(throwingFetch, () =>
        enrichUnknowns(model(unknownNuget()), {
          mode: "check",
          cachePath: path,
          verbose: false,
        }),
      );
      expect(result.staleUnknowns).toEqual([
        "pkg:nuget/Newtonsoft.Json@13.0.4",
      ]);
      expect(registryClaim(result.model.packages[0])).toBeUndefined();
      expect(readCache(path).size).toBe(0); // no file was ever written
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("mixed misses: pypi + npm + nuget unknowns all resolve through their own arms in one run", async () => {
    const { dir, path } = tempCachePath();
    try {
      const pypiUnknown: PackageEntry = {
        purl: "pkg:pypi/anyio@4.12.1",
        name: "anyio",
        version: "4.12.1",
        occurrences: [{ target: "apps/jupyter", isDevDependency: false }],
        licenseClaims: [],
        scope: "app",
      };
      const npmUnknown: PackageEntry = {
        purl: "pkg:npm/no-claims@2.0.0",
        name: "no-claims",
        version: "2.0.0",
        occurrences: [{ target: "proj", isDevDependency: false }],
        licenseClaims: [],
        scope: "app",
      };
      const { fetch, calls } = fetchByUrl((url) => {
        if (url === "https://pypi.org/pypi/anyio/4.12.1/json") {
          return jsonResponse({ info: { license_expression: "MIT" } });
        }
        if (url === "https://registry.npmjs.org/no-claims") {
          return jsonResponse({ versions: { "2.0.0": { license: "ISC" } } });
        }
        if (url === LEAF_URL)
          return jsonResponse({ catalogEntry: CATALOG_URL });
        if (url === CATALOG_URL) {
          return jsonResponse({ licenseExpression: "Apache-2.0" });
        }
        throw new Error(`unexpected url ${url}`);
      });
      const result = await withFetch(fetch, () =>
        enrichUnknowns(model(pypiUnknown, npmUnknown, unknownNuget()), {
          mode: "generate",
          cachePath: path,
          verbose: false,
          backoffBaseMs: fastBackoff,
        }),
      );
      expect(calls).toHaveLength(4);
      const claims = result.model.packages.map((p) => registryClaim(p)?.raw);
      expect(claims).toEqual(["MIT", "ISC", "Apache-2.0"]);
      const loaded = readCache(path);
      expect(getEntry(loaded, "pkg:nuget/Newtonsoft.Json@13.0.4")?.via).toBe(
        "license-expression",
      );
      expect(loaded.size).toBe(3);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
