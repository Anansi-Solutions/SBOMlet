/**
 * verify-cache: the online cache-integrity audit. Each test writes a committed
 * cache, swaps a deterministic fetch stub for the registries, and asserts the
 * re-resolution either matches or surfaces a divergence. The comparison is a
 * single equality on the raw license, so the tests cover every tamper shape:
 * a changed value, a positive entry the registry no longer resolves, and a
 * negative entry the registry contradicts with a real license. Network/cache
 * FAILURES must propagate loudly — never a false "all clean".
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { putEntry, serializeCache, type CacheEntry } from "../src/enrich/cache";
import { verifyCache } from "../src/enrich/verify";

const tempDirs: string[] = [];

function tempCachePath(): string {
  const dir = mkdtempSync(join(tmpdir(), "verify-cache-"));
  tempDirs.push(dir);
  return join(dir, "enrichment-cache.json");
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function writeCache(path: string, entries: Record<string, CacheEntry>): void {
  const cache = new Map<string, CacheEntry>();
  for (const [purl, entry] of Object.entries(entries))
    putEntry(cache, purl, entry);
  writeFileSync(path, serializeCache(cache));
}

function positive(
  license: string,
  fetchedFrom: CacheEntry["fetchedFrom"],
): CacheEntry {
  return {
    license,
    fetchedFrom,
    via: "x",
    resolvable: true,
  };
}

function negative(fetchedFrom: CacheEntry["fetchedFrom"]): CacheEntry {
  return {
    license: null,
    fetchedFrom,
    via: "unresolved",
    resolvable: false,
  };
}

/** Build an npm packument with per-version (and optional top-level) licenses. */
function npmPackument(
  versionLicenses: Record<string, string | undefined>,
  topLicense?: string,
): unknown {
  return {
    ...(topLicense !== undefined ? { license: topLicense } : {}),
    versions: Object.fromEntries(
      Object.entries(versionLicenses).map(([version, license]) => [
        version,
        license === undefined ? {} : { license },
      ]),
    ),
  };
}

/** Build a PyPI JSON document carrying `info.license`. */
function pypiDoc(license: string | undefined): unknown {
  return {
    info: { ...(license !== undefined ? { license } : {}), classifiers: [] },
  };
}

/** Build a GitHub License API body carrying `license.spdx_id`. */
function githubLicense(spdxId: string): unknown {
  return { license: { spdx_id: spdxId } };
}

/** A URL-routed fetch stub recording every requested URL. */
function fetchMock(
  route: (url: string) => { status: number; body?: unknown },
): {
  fetch: typeof fetch;
  calls: string[];
} {
  const calls: string[] = [];
  const impl = (async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);
    const { status, body } = route(url);
    return new Response(body === undefined ? "" : JSON.stringify(body), {
      status,
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

describe("verifyCache", () => {
  test("every entry matching upstream → zero mismatches (npm + pypi + negative)", async () => {
    const path = tempCachePath();
    writeCache(path, {
      "pkg:npm/lodash@4.17.21": positive("MIT", "npm"),
      "pkg:pypi/anyio@4.12.1": positive("MIT", "pypi"),
      "pkg:npm/no-license-lib@1.0.0": negative("npm"),
    });
    const { fetch } = fetchMock((url) => {
      if (url.includes("registry.npmjs.org/lodash")) {
        return { status: 200, body: npmPackument({ "4.17.21": "MIT" }) };
      }
      if (url.includes("registry.npmjs.org/no-license-lib")) {
        return { status: 200, body: npmPackument({ "1.0.0": undefined }) };
      }
      if (url.includes("pypi.org/pypi/anyio/4.12.1")) {
        return { status: 200, body: pypiDoc("MIT") };
      }
      return { status: 500 };
    });
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.audited).toBe(3);
    expect(result.mismatches).toEqual([]);
  });

  test("an npm license changed upstream → mismatch (cached vs current, reason 'changed')", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:npm/foo@1.2.3": positive("MIT", "npm") });
    const { fetch } = fetchMock(() => ({
      status: 200,
      body: npmPackument({ "1.2.3": "GPL-3.0-only" }),
    }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      purl: "pkg:npm/foo@1.2.3",
      cached: "MIT",
      current: "GPL-3.0-only",
    });
    expect(result.mismatches[0]?.reason).toContain("changed");
  });

  test("a pypi license changed upstream → mismatch (per-version URL exercised)", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:pypi/anyio@4.12.1": positive("MIT", "pypi") });
    const { fetch, calls } = fetchMock(() => ({
      status: 200,
      body: pypiDoc("Apache-2.0"),
    }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(calls[0]).toContain("pypi.org/pypi/anyio/4.12.1/json");
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: "MIT",
      current: "Apache-2.0",
    });
  });

  test("a positive entry the registry no longer resolves → mismatch (current none)", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:npm/ghost@9.9.9": positive("MIT", "npm") });
    // The packument exists but has neither that version nor a top-level license.
    const { fetch } = fetchMock(() => ({
      status: 200,
      body: npmPackument({ "1.0.0": "MIT" }),
    }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: "MIT",
      current: null,
    });
    expect(result.mismatches[0]?.reason).toContain("none");
  });

  test("a NEGATIVE entry the registry contradicts with a real license → mismatch (hidden obligation)", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:npm/sneaky@1.0.0": negative("npm") });
    const { fetch } = fetchMock(() => ({
      status: 200,
      body: npmPackument({ "1.0.0": "AGPL-3.0-only" }),
    }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: null,
      current: "AGPL-3.0-only",
    });
    expect(result.mismatches[0]?.reason).toContain("hidden obligation");
  });

  test("a terraform entry matching its GitHub License version tag → no mismatch", async () => {
    const path = tempCachePath();
    writeCache(path, {
      "pkg:terraform/registry.terraform.io/hashicorp/aws@5.0.0": positive(
        "MPL-2.0",
        "github",
      ),
    });
    const { fetch, calls } = fetchMock((url) =>
      url.includes("/hashicorp/terraform-provider-aws/license?ref=v5.0.0")
        ? { status: 200, body: githubLicense("MPL-2.0") }
        : { status: 404 },
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toEqual([]);
    expect(calls.some((u) => u.includes("ref=v5.0.0"))).toBe(true);
  });

  test("a terraform entry whose GitHub License changed → mismatch", async () => {
    const path = tempCachePath();
    writeCache(path, {
      "pkg:terraform/registry.terraform.io/hashicorp/aws@5.0.0": positive(
        "MPL-2.0",
        "github",
      ),
    });
    const { fetch } = fetchMock((url) =>
      url.includes("ref=v5.0.0")
        ? { status: 200, body: githubLicense("BUSL-1.1") }
        : { status: 404 },
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: "MPL-2.0",
      current: "BUSL-1.1",
    });
  });

  test("an entry whose purl this tool never writes is flagged unverifiable, with NO fetch", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:gem/rails@7.0.0": positive("MIT", "npm") });
    const { fetch, calls } = fetchMock(() => ({ status: 200, body: {} }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(calls).toEqual([]);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]?.reason).toContain("re-resolvable");
  });

  test("two cached versions of one npm package share a single packument fetch (dedup)", async () => {
    const path = tempCachePath();
    writeCache(path, {
      "pkg:npm/multi@1.0.0": positive("MIT", "npm"),
      "pkg:npm/multi@2.0.0": positive("MIT", "npm"),
    });
    const { fetch, calls } = fetchMock(() => ({
      status: 200,
      body: npmPackument({ "1.0.0": "MIT", "2.0.0": "MIT" }),
    }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toEqual([]);
    expect(calls).toHaveLength(1);
  });

  test("mismatches are sorted by purl deterministically", async () => {
    const path = tempCachePath();
    writeCache(path, {
      "pkg:npm/zeta@1.0.0": positive("MIT", "npm"),
      "pkg:npm/alpha@1.0.0": positive("MIT", "npm"),
    });
    const { fetch } = fetchMock((url) =>
      url.includes("/zeta")
        ? { status: 200, body: npmPackument({ "1.0.0": "GPL-3.0-only" }) }
        : { status: 200, body: npmPackument({ "1.0.0": "Apache-2.0" }) },
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches.map((m) => m.purl)).toEqual([
      "pkg:npm/alpha@1.0.0",
      "pkg:npm/zeta@1.0.0",
    ]);
  });

  test("a persistent 503 propagates loudly with the status in the message", async () => {
    const path = tempCachePath();
    writeCache(path, { "pkg:npm/foo@1.0.0": positive("MIT", "npm") });
    const { fetch } = fetchMock(() => ({ status: 503 }));
    await expect(
      withFetch(fetch, () =>
        verifyCache({ cachePath: path, verbose: false, backoffBaseMs: 1 }),
      ),
    ).rejects.toThrow(/registry 503/);
  });

  test("a malformed cache file throws (a poisoned cache is a config error)", async () => {
    const path = tempCachePath();
    writeFileSync(path, "{ not valid json");
    const { fetch } = fetchMock(() => ({ status: 200, body: {} }));
    await expect(
      withFetch(fetch, () => verifyCache({ cachePath: path, verbose: false })),
    ).rejects.toThrow(/malformed enrichment cache/);
  });

  test("an empty cache audits zero entries with no fetch", async () => {
    const path = tempCachePath();
    writeCache(path, {});
    const { fetch, calls } = fetchMock(() => ({ status: 200, body: {} }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.audited).toBe(0);
    expect(result.mismatches).toEqual([]);
    expect(calls).toEqual([]);
  });
});

describe("verifyCache nuget (two-step re-resolution, the same resolver generate uses)", () => {
  const NUGET_PURL = "pkg:nuget/Newtonsoft.Json@13.0.4";
  const LEAF_URL =
    "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/13.0.4.json";
  const CATALOG_URL =
    "https://api.nuget.org/v3/catalog0/data/2024.03.27.08.21.03/newtonsoft.json.13.0.4.json";

  /** Route the two-step: leaf → host-pinned catalogEntry with the given body. */
  function nugetRoute(
    catalogBody: unknown,
  ): (url: string) => { status: number; body?: unknown } {
    return (url) => {
      if (url === LEAF_URL) {
        return { status: 200, body: { catalogEntry: CATALOG_URL } };
      }
      if (url === CATALOG_URL) return { status: 200, body: catalogBody };
      return { status: 500 };
    };
  }

  test("a committed positive entry matching the registry → audited, no mismatch", async () => {
    const path = tempCachePath();
    writeCache(path, { [NUGET_PURL]: positive("MIT", "nuget") });
    const { fetch, calls } = fetchMock(
      nugetRoute({ licenseExpression: "MIT" }),
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.audited).toBe(1);
    expect(result.mismatches).toEqual([]);
    // The two-step went to the LOWERCASED leaf URL, then the pinned catalogEntry.
    expect(calls).toEqual([LEAF_URL, CATALOG_URL]);
  });

  test("a flipped license (cache says MIT, registry says Apache-2.0) → mismatch with the changed reason", async () => {
    const path = tempCachePath();
    writeCache(path, { [NUGET_PURL]: positive("MIT", "nuget") });
    const { fetch } = fetchMock(
      nugetRoute({ licenseExpression: "Apache-2.0" }),
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      purl: NUGET_PURL,
      cached: "MIT",
      current: "Apache-2.0",
    });
    expect(result.mismatches[0]?.reason).toContain("changed");
  });

  test("a fabricated entry the registry 404s → mismatch (cached string vs current null), never a crash", async () => {
    const path = tempCachePath();
    writeCache(path, { [NUGET_PURL]: positive("MIT", "nuget") });
    const { fetch } = fetchMock(() => ({ status: 404 }));
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: "MIT",
      current: null,
    });
    expect(result.mismatches[0]?.reason).toContain("none");
  });

  test("a NEGATIVE entry the registry now resolves → mismatch (hidden obligation)", async () => {
    const path = tempCachePath();
    writeCache(path, { [NUGET_PURL]: negative("nuget") });
    const { fetch } = fetchMock(
      nugetRoute({ licenseExpression: "AGPL-3.0-only" }),
    );
    const result = await withFetch(fetch, () =>
      verifyCache({ cachePath: path, verbose: false }),
    );
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toMatchObject({
      cached: null,
      current: "AGPL-3.0-only",
    });
    expect(result.mismatches[0]?.reason).toContain("hidden obligation");
  });

  test("a transient failure during a nuget verify propagates loudly (exit-3 posture), never silent agreement", async () => {
    const path = tempCachePath();
    writeCache(path, { [NUGET_PURL]: positive("MIT", "nuget") });
    const { fetch } = fetchMock(() => ({ status: 503 }));
    await expect(
      withFetch(fetch, () =>
        verifyCache({ cachePath: path, verbose: false, backoffBaseMs: 1 }),
      ),
    ).rejects.toThrow(/registry 503/);
  });
});
