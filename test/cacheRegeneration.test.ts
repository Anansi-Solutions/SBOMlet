/**
 * Behavior suite for enrichment cache creation on `generate`: the committed
 * cache is the offline foundation `check` reads, so it must exist after every
 * generate run — including one whose scan needs no enrichment at all.
 */

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";

import * as cdxgenModule from "../src/collectors/cdxgen";
import { serializeCache } from "../src/enrich/cache";
import { runCheck } from "../src/gate/check";
import { runGenerate } from "../src/pipeline/pipeline";

/** Original exports captured BEFORE any mock.module call (restore target). */
const REAL_CDXGEN = { ...cdxgenModule };

/** All-licensed fixture: every component resolves, so nothing needs enrichment. */
const ALL_LICENSED_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      purl: "pkg:npm/mit-lib@3.0.0",
      name: "mit-lib",
      version: "3.0.0",
      licenses: [{ license: { id: "MIT" } }],
    },
    {
      purl: "pkg:npm/apache-lib@1.2.0",
      name: "apache-lib",
      version: "1.2.0",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
  ],
};

/** One claim-less component alongside a resolved one: exactly one cache miss. */
const ONE_MISS_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      purl: "pkg:npm/mit-lib@3.0.0",
      name: "mit-lib",
      version: "3.0.0",
      licenses: [{ license: { id: "MIT" } }],
    },
    {
      purl: "pkg:npm/no-claims@2.0.0",
      name: "no-claims",
      version: "2.0.0",
    },
  ],
};

let fixtureSbom: unknown = ALL_LICENSED_SBOM;

async function fakeScanWithCdxgen(): Promise<cdxgenModule.CollectorSbomFile> {
  const tempDir = mkdtempSync(join(tmpdir(), "licenses-cacheregen-scan-"));
  const sbomPath = join(tempDir, "bom.json");
  writeFileSync(sbomPath, JSON.stringify(fixtureSbom));
  return { sbomPath, cacheKey: "fake", tool: REAL_CDXGEN.CDXGEN_TOOL };
}

/** Yarn-1-style lockfile: cdxgen dispatch, one third-party entry. */
const V1_LOCKFILE = [
  "# yarn lockfile v1",
  "",
  "lodash@^4.17.21:",
  '  version "4.17.21"',
  "",
].join("\n");

/** Temp consumer-shaped repo root, no cache-dir configuration. */
function makeScannableTree(): { root: string } {
  const root = mkdtempSync(join(tmpdir(), "licenses-cacheregen-"));
  const projDir = join(root, "proj");
  mkdirSync(projDir);
  writeFileSync(join(projDir, "package.json"), '{ "name": "proj" }\n');
  writeFileSync(join(projDir, "yarn.lock"), V1_LOCKFILE);
  return { root };
}

/**
 * Capture process.stderr.write for the duration of a callback; always
 * restores in finally so a failing assertion can never poison later tests.
 */
async function withCapturedStderr(fn: () => Promise<void>): Promise<string> {
  const original = process.stderr.write.bind(process.stderr);
  let captured = "";
  process.stderr.write = ((chunk: unknown): boolean => {
    captured += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    await fn();
  } finally {
    process.stderr.write = original;
  }
  return captured;
}

/** A fetch stub returning a parsed-JSON Response body for any URL matched. */
function fetchReturning(bodyFor: (url: string) => unknown): typeof fetch {
  return (async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    return new Response(JSON.stringify(bodyFor(url)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

describe("enrichment cache creation on generate", () => {
  let originalFetch: typeof fetch;

  beforeAll(() => {
    originalFetch = globalThis.fetch;
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("a generate with nothing to enrich still creates the cache at the default path", async () => {
    fixtureSbom = ALL_LICENSED_SBOM;
    globalThis.fetch = (async (): Promise<Response> => {
      throw new Error("network must not be touched");
    }) as unknown as typeof fetch;

    const { root } = makeScannableTree();
    const outputPath = join(root, "THIRD_PARTY_LICENSES.md");
    const noticesPath = join(root, "THIRD_PARTY_NOTICES.md");

    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        outputPath,
        noticesPath,
        verbose: false,
      });
    });

    expect(existsSync(outputPath)).toBe(true);
    expect(existsSync(noticesPath)).toBe(true);

    const cachePath = join(root, ".sbomlet.cache", "licenses.cache.json");
    expect(existsSync(cachePath)).toBe(true);
    expect(readFileSync(cachePath, "utf8")).toBe(serializeCache(new Map()));
  });

  test("a consumer who commits the empty envelope, then adds a dependency needing enrichment, gets a loud stale check — not a silent pass on the stale empty cache", async () => {
    // First commit: nothing to enrich, so generate writes the empty envelope
    // ({version:1, entries:{}}) — exactly the artifact this fix now produces.
    fixtureSbom = ALL_LICENSED_SBOM;
    globalThis.fetch = (async (): Promise<Response> => {
      throw new Error("network must not be touched");
    }) as unknown as typeof fetch;

    const { root } = makeScannableTree();
    const outputPath = join(root, "THIRD_PARTY_LICENSES.md");
    const noticesPath = join(root, "THIRD_PARTY_NOTICES.md");

    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        outputPath,
        noticesPath,
        verbose: false,
      });
    });

    const cachePath = join(root, ".sbomlet.cache", "licenses.cache.json");
    expect(readFileSync(cachePath, "utf8")).toBe(serializeCache(new Map()));

    // The consumer's lockfile later adds a dependency needing enrichment,
    // but the committed cache is still the empty envelope from before —
    // never re-fetched by check.
    fixtureSbom = ONE_MISS_SBOM;

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    await withCapturedStderr(async () => {
      result = await runCheck({
        repoRoot: root,
        outputPath,
        noticesPath,
        verbose: false,
      });
    });

    // The stale-empty-cache shape must fail loud (exit 2 territory via
    // staleUnknowns), never pass silently because the file merely exists.
    expect(result?.staleFiles).toContain("pkg:npm/no-claims@2.0.0");
    // The empty envelope itself is untouched — check never fetches or writes.
    expect(readFileSync(cachePath, "utf8")).toBe(serializeCache(new Map()));
  });

  test("a generate with a cache miss creates the cache at the default path with the fetched entry, and check accepts it", async () => {
    fixtureSbom = ONE_MISS_SBOM;
    globalThis.fetch = fetchReturning(() => ({
      versions: { "2.0.0": { license: "MIT" } },
    }));

    const { root } = makeScannableTree();
    const outputPath = join(root, "THIRD_PARTY_LICENSES.md");
    const noticesPath = join(root, "THIRD_PARTY_NOTICES.md");

    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        outputPath,
        noticesPath,
        verbose: false,
      });
    });

    const cachePath = join(root, ".sbomlet.cache", "licenses.cache.json");
    expect(existsSync(cachePath)).toBe(true);
    const cache = JSON.parse(readFileSync(cachePath, "utf8"));
    expect(cache.entries["pkg:npm/no-claims@2.0.0"]).toEqual({
      fetchedFrom: "npm",
      license: "MIT",
      resolvable: true,
      source: "registry",
      via: "version-license",
    });

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    await withCapturedStderr(async () => {
      result = await runCheck({
        repoRoot: root,
        outputPath,
        noticesPath,
        verbose: false,
      });
    });
    expect(result?.violations).toBe(0);
    expect(result?.staleFiles).toEqual([]);
  });
});
