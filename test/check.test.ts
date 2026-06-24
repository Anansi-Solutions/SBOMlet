/**
 * Behavior suite for the check CI gate: runCheck and exitCodeFor are driven
 * directly through the import seam — no subprocess — with the scanner stubbed
 * via mock.module (originals restored in afterAll), so the full pipeline
 * (discovery, dispatch, coverage, merge, annotate, evaluate, render, compare)
 * runs for real against temp trees.
 *
 * The exit taxonomy under test: 0 clean, 1 any fail verdict (priority over
 * stale), 2 stale/missing committed output, 3+ tool/config error — and
 * exceptions can never surface as 0/1/2: errors propagate out of runCheck and
 * only main()'s catch -> fail() maps them.
 */

import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";

import * as cdxgenModule from "../src/collectors/cdxgen";
import { exitCodeFor, runCheck } from "../src/gate/check";
import { buildOutputs, runGenerate } from "../src/pipeline/pipeline";

/** Original exports captured BEFORE any mock.module call (restore target). */
const REAL_CDXGEN = { ...cdxgenModule };

/**
 * Fixture SBOM the stubbed scanner returns (cli.test.ts shape): one
 * copyleft package (AGPL, no covering rule -> fail), one claim-less package
 * (-> unknown handling), one permissive package (-> default:ok).
 */
const FIXTURE_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      purl: "pkg:npm/copyleft-lib@1.0.0",
      name: "copyleft-lib",
      version: "1.0.0",
      licenses: [{ license: { id: "AGPL-3.0-only" } }],
    },
    {
      purl: "pkg:npm/no-claims@2.0.0",
      name: "no-claims",
      version: "2.0.0",
    },
    {
      purl: "pkg:npm/mit-lib@3.0.0",
      name: "mit-lib",
      version: "3.0.0",
      licenses: [{ license: { id: "MIT" } }],
    },
  ],
};

async function fakeScanWithCdxgen(): Promise<cdxgenModule.CollectorSbomFile> {
  const tempDir = mkdtempSync(join(tmpdir(), "licenses-check-scan-"));
  const sbomPath = join(tempDir, "bom.json");
  writeFileSync(sbomPath, JSON.stringify(FIXTURE_SBOM));
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

/** Temp repo root with one cdxgen-dispatched yarn project named "proj". */
function makeScannableTree(): { root: string } {
  const root = mkdtempSync(join(tmpdir(), "licenses-check-"));
  const projDir = join(root, "proj");
  mkdirSync(projDir);
  writeFileSync(join(projDir, "package.json"), '{ "name": "proj" }\n');
  writeFileSync(join(projDir, "yarn.lock"), V1_LOCKFILE);
  return { root };
}

/** Write `text` as a policy file inside `root`; returns its path. */
function writePolicy(root: string, text: string): string {
  const policyPath = join(root, "policy.toml");
  writeFileSync(policyPath, text);
  return policyPath;
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

/**
 * Full byte snapshot of every file under root (relative path -> base64
 * content) — the write-free proof surface: identical maps before and after
 * runCheck mean check created, modified, and deleted nothing.
 */
function snapshotTree(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else out[relative(root, path)] = readFileSync(path).toString("base64");
    }
  };
  walk(root);
  return out;
}

/**
 * The configured output paths for a tree, with or without the export. The
 * enrichment cache is committed INSIDE the tree (like the real tool-root cache)
 * so generate writes it once up front and check reads it offline — the same
 * path threads through both, and Test 8's snapshot already contains it.
 */
function pathsFor(
  root: string,
  withCyclonedx: boolean,
): {
  outputPath: string;
  noticesPath: string;
  enrichmentCachePath: string;
  cyclonedxPath?: string;
} {
  return {
    outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
    noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
    enrichmentCachePath: join(root, "enrichment-cache.json"),
    ...(withCyclonedx ? { cyclonedxPath: join(root, "sbom.cdx.json") } : {}),
  };
}

/**
 * Warn-only policy (Pitfall 2 fixture): the AGPL package is ACCEPTED by a
 * compatible license rule, the claim-less package warns via [unknown]
 * handling, and a second compatible rule matches nothing -> the
 * unused-entry warning path prints without gating.
 */
const WARN_ONLY_POLICY = [
  "[unknown]",
  'handling = "warn"',
  "",
  "[[compatible]]",
  'match = "license"',
  'pattern = "AGPL-3.0-only"',
  'reason = "copyleft accepted for the warn-only fixture"',
  "",
  "[[compatible]]",
  'match = "license"',
  'pattern = "0BSD"',
  'reason = "unused-entry-marker"',
  "",
].join("\n");

const squish = (s: string): string => s.replace(/ {2,}/g, " ");

describe("runCheck + exitCodeFor — the CI gate (GATE-01, GATE-02)", () => {
  // These pre-enrichment tests must stay offline now that generate runs the
  // ENRICH stage: stub globalThis.fetch to a clean 200-empty registry response
  // so the fixture's no-claims package stays unknown (the resolver returns
  // null) — generate writes a negative cache entry into the tree, check reads
  // it offline, and every existing golden/count is byte-identical.
  let originalFetch: typeof fetch;
  beforeAll(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (): Promise<Response> =>
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("Test 1: clean tree — zero violations, zero stale, exit 0", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    await withCapturedStderr(async () => {
      await runGenerate({ repoRoot: root, ...paths, verbose: false });
    });

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withCapturedStderr(async () => {
      result = await runCheck({ repoRoot: root, ...paths, verbose: false });
    });

    expect(result!.violations).toBe(0);
    expect(result!.staleFiles).toEqual([]);
    expect(exitCodeFor(result!)).toBe(0);
    expect(stderr).toContain("check: ok (2 outputs verified)");
  });

  test("Test 2: a byte-edited committed file is stale — for each configured output (GATE-02)", async () => {
    // One fresh tree per edited file so each mismatch is isolated.
    for (const editTarget of [
      "outputPath",
      "noticesPath",
      "cyclonedxPath",
    ] as const) {
      const { root } = makeScannableTree();
      const paths = pathsFor(root, true);
      await withCapturedStderr(async () => {
        await runGenerate({ repoRoot: root, ...paths, verbose: false });
      });

      const editedPath = paths[editTarget]!;
      writeFileSync(editedPath, readFileSync(editedPath, "utf8") + "x");

      let result: Awaited<ReturnType<typeof runCheck>> | undefined;
      const stderr = await withCapturedStderr(async () => {
        result = await runCheck({ repoRoot: root, ...paths, verbose: false });
      });

      expect(result!.staleFiles).toEqual([editedPath]);
      expect(exitCodeFor(result!)).toBe(2);
      expect(stderr).toContain(
        `check stale: ${editedPath} differs from generated output`,
      );
    }
  });

  test("Test 3: a missing committed output is stale by definition — exit 2", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    await withCapturedStderr(async () => {
      await runGenerate({ repoRoot: root, ...paths, verbose: false });
    });
    rmSync(paths.noticesPath);

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withCapturedStderr(async () => {
      result = await runCheck({ repoRoot: root, ...paths, verbose: false });
    });

    expect(result!.staleFiles).toEqual([paths.noticesPath]);
    expect(exitCodeFor(result!)).toBe(2);
    expect(stderr).toContain(`check stale: ${paths.noticesPath} is missing`);
  });

  test("Test 4: a CRLF-checked-out committed file still checks clean", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    await withCapturedStderr(async () => {
      await runGenerate({ repoRoot: root, ...paths, verbose: false });
    });

    // Simulate an unpinned autocrlf checkout: same content, CRLF endings.
    const lf = readFileSync(paths.outputPath, "utf8");
    expect(lf).toContain("\n");
    writeFileSync(paths.outputPath, lf.replaceAll("\n", "\r\n"));

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    await withCapturedStderr(async () => {
      result = await runCheck({ repoRoot: root, ...paths, verbose: false });
    });

    // The COMMITTED read is normalized; the in-memory render is untouched.
    expect(result!.staleFiles).toEqual([]);
    expect(exitCodeFor(result!)).toBe(0);
  });

  test("Test 5: violation beats stale — exit 1 with both reports printed", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    // Minimal policy: AGPL has no covering rule and no suppression -> fail.
    const policyPath = writePolicy(root, '[unknown]\nhandling = "warn"\n');
    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        ...paths,
        policyPath,
        verbose: false,
      });
    });
    writeFileSync(
      paths.outputPath,
      readFileSync(paths.outputPath, "utf8") + "tampered",
    );

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withCapturedStderr(async () => {
      result = await runCheck({
        repoRoot: root,
        ...paths,
        policyPath,
        verbose: false,
      });
    });

    expect(result!.violations).toBeGreaterThanOrEqual(1);
    expect(result!.staleFiles).toEqual([paths.outputPath]);
    // Violation takes priority over stale.
    expect(exitCodeFor(result!)).toBe(1);
    // Both report classes are visible on stderr.
    expect(stderr).toContain("policy fail:");
    expect(stderr).toContain("check stale:");
  });

  test("Test 6: warn verdicts and unused-entry warnings print but never gate — exit 0", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    const policyPath = writePolicy(root, WARN_ONLY_POLICY);
    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        ...paths,
        policyPath,
        verbose: false,
      });
    });

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withCapturedStderr(async () => {
      result = await runCheck({
        repoRoot: root,
        ...paths,
        policyPath,
        verbose: false,
      });
    });

    // Warn-only verdict stream: zero fails, clean files -> exit 0.
    expect(result!.violations).toBe(0);
    expect(result!.staleFiles).toEqual([]);
    expect(exitCodeFor(result!)).toBe(0);
    // The warnings still PRINT (gate-theater prevention)...
    expect(stderr).toContain("policy warn:");
    expect(stderr).toContain(
      "policy warning: unused entry compatible[1] — unused-entry-marker",
    );
    // ...and zero fail lines exist to gate on.
    expect(stderr).not.toContain("policy fail:");
  });

  test("Test 7: check without --policy performs staleness only", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    await withCapturedStderr(async () => {
      await runGenerate({ repoRoot: root, ...paths, verbose: false });
    });

    // Clean tree -> 0, and NO policy summary printed.
    let clean: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderrClean = await withCapturedStderr(async () => {
      clean = await runCheck({ repoRoot: root, ...paths, verbose: false });
    });
    expect(clean!.violations).toBe(0);
    expect(exitCodeFor(clean!)).toBe(0);
    expect(stderrClean).not.toContain("policy");

    // Edited file -> 2 (staleness still gates without a policy).
    writeFileSync(
      paths.noticesPath,
      readFileSync(paths.noticesPath, "utf8") + "x",
    );
    let stale: Awaited<ReturnType<typeof runCheck>> | undefined;
    await withCapturedStderr(async () => {
      stale = await runCheck({ repoRoot: root, ...paths, verbose: false });
    });
    expect(exitCodeFor(stale!)).toBe(2);
  });

  test("Test 8: check is write-free — byte-identical tree before/after; --dump-model is a config error", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, true);
    const policyPath = writePolicy(root, '[unknown]\nhandling = "warn"\n');
    await withCapturedStderr(async () => {
      await runGenerate({
        repoRoot: root,
        ...paths,
        policyPath,
        verbose: false,
      });
    });

    const before = snapshotTree(root);
    await withCapturedStderr(async () => {
      await runCheck({ repoRoot: root, ...paths, policyPath, verbose: false });
    });
    // check created, modified, and deleted NOTHING.
    expect(snapshotTree(root)).toEqual(before);

    // Passing --dump-model to check is a config error: it throws (-> main's
    // catch -> fail() -> exit 3 path) and never reaches exitCodeFor.
    await withCapturedStderr(async () => {
      await expect(
        runCheck({
          repoRoot: root,
          ...paths,
          dumpModelPath: join(root, "dump.json"),
          verbose: false,
        }),
      ).rejects.toThrow("check performs no writes");
    });
    expect(snapshotTree(root)).toEqual(before);
  });

  test("Test 9: exit-taxonomy boundaries — and errors never reach the mapping", async () => {
    // Pure mapping boundaries.
    expect(exitCodeFor({ violations: 0, staleFiles: [] })).toBe(0);
    expect(exitCodeFor({ violations: 0, staleFiles: ["a.md"] })).toBe(2);
    expect(exitCodeFor({ violations: 1, staleFiles: [] })).toBe(1);
    // Violations take priority REGARDLESS of staleness.
    expect(exitCodeFor({ violations: 3, staleFiles: ["a.md", "b.md"] })).toBe(
      1,
    );

    // A thrown error (invalid policy) PROPAGATES out of runCheck — it can
    // never be conflated into 0/1/2; only main's catch -> fail() -> 3 sees
    // it (Pitfall 6).
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    const brokenPolicy = writePolicy(root, "[unknown\nhandling =\n");
    await withCapturedStderr(async () => {
      await expect(
        runCheck({
          repoRoot: root,
          ...paths,
          policyPath: brokenPolicy,
          verbose: false,
        }),
      ).rejects.toThrow();
    });
  });
});

// ---------------------------------------------------------------------------
// The offline check contract (INTG-03 + GATE-02 zero-network clause): a
// miss-needing-enrichment with no committed cache entry is exit-2 stale (never
// a fetch), and a populated committed cache makes a fetch-stubbed-to-throw
// check pass clean and write-free. Same scanner stub as above; per-test fetch
// stubs (the describe-wide stub does NOT apply across describe boundaries).
// ---------------------------------------------------------------------------

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

/** A fetch stub that resolves the no-claims fixture to MIT via its packument. */
const RESOLVING_FETCH = (async (): Promise<Response> =>
  new Response(JSON.stringify({ versions: { "2.0.0": { license: "MIT" } } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as unknown as typeof fetch;

/** A fetch stub that throws — proves a code path made ZERO network calls. */
const THROWING_FETCH = (async (): Promise<Response> => {
  throw new Error("NETWORK DISABLED");
}) as unknown as typeof fetch;

describe("offline check contract — enrichment staleness (INTG-03, GATE-02)", () => {
  beforeAll(() => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("a no-cache-entry unknown is exit-2 stale naming the purl + the regenerate remedy", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    // Generate the committed outputs with a stub that resolves no-claims, then
    // DELETE the committed cache so the outputs match but the cache lacks the
    // unknown's entry — exactly the "cache fell behind the lockfile" condition.
    await withFetch(RESOLVING_FETCH, async () => {
      await withCapturedStderr(async () => {
        await runGenerate({ repoRoot: root, ...paths, verbose: false });
      });
    });
    rmSync(paths.enrichmentCachePath);

    // check NEVER fetches: a miss-needing-enrichment is stale, not a network
    // call. Stub fetch to throw to prove zero egress even on the stale path.
    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withFetch(THROWING_FETCH, () =>
      withCapturedStderr(async () => {
        result = await runCheck({ repoRoot: root, ...paths, verbose: false });
      }),
    );

    expect(result!.staleFiles).toContain("pkg:npm/no-claims@2.0.0");
    expect(exitCodeFor(result!)).toBe(2);
    expect(stderr).toContain(
      "check stale: pkg:npm/no-claims@2.0.0 needs enrichment — " +
        "run task generate to refresh the committed cache",
    );
  });

  test("a populated committed cache makes a fetch-stubbed-to-throw check pass clean (hermetic, zero fetch)", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, false);
    // Generate WITH the network (resolving stub) → committed cache + outputs
    // both carry the resolved no-claims license.
    await withFetch(RESOLVING_FETCH, async () => {
      await withCapturedStderr(async () => {
        await runGenerate({ repoRoot: root, ...paths, verbose: false });
      });
    });

    // Now check with fetch stubbed to THROW: a single egress would explode.
    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withFetch(THROWING_FETCH, () =>
      withCapturedStderr(async () => {
        result = await runCheck({ repoRoot: root, ...paths, verbose: false });
      }),
    );

    // Clean: the committed cache satisfied every unknown offline.
    expect(result!.staleFiles).toEqual([]);
    expect(result!.violations).toBe(0);
    expect(exitCodeFor(result!)).toBe(0);
    expect(stderr).toContain("check: ok (2 outputs verified)");
  });

  test("check is write-free against the committed cache — byte-identical tree before/after", async () => {
    const { root } = makeScannableTree();
    const paths = pathsFor(root, true);
    await withFetch(RESOLVING_FETCH, async () => {
      await withCapturedStderr(async () => {
        await runGenerate({ repoRoot: root, ...paths, verbose: false });
      });
    });

    const before = snapshotTree(root);
    await withFetch(THROWING_FETCH, () =>
      withCapturedStderr(async () => {
        await runCheck({ repoRoot: root, ...paths, verbose: false });
      }),
    );
    // check created, modified, and deleted NOTHING — the committed cache and
    // every output are byte-unchanged (the offline write-free proof).
    expect(snapshotTree(root)).toEqual(before);
  });
});

// ===========================================================================
// COLL-04: the committed docker-os-sbom.json is threaded into the merge as a
// scope:"os" INPUT (07-01's emitter output), base-dir-resolved. A MISSING file
// is the enrichment-cache-miss equivalent: NO os entries, NO scan, NO docker.
// buildOutputs is write-free so these run directly against a temp base dir.
// ===========================================================================

/** A committed Docker OS-SBOM (07-01 emitter shape): one deb + one apk. */
const DOCKER_OS_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      type: "library",
      name: "libc6",
      version: "2.36-9",
      purl: "pkg:deb/debian/libc6@2.36-9",
    },
    {
      type: "library",
      name: "musl",
      version: "1.2.4-r2",
      purl: "pkg:apk/alpine/musl@1.2.4-r2",
    },
  ],
  dockerImages: [{ image: "postgres:18", digest: "postgres@sha256:deadbeef" }],
};

/** A clean 200-empty registry response so os-package unknowns stay offline. */
const EMPTY_FETCH = (async (): Promise<Response> =>
  new Response(JSON.stringify({}), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as unknown as typeof fetch;

describe("COLL-04 committed docker-os-sbom.json as a scope:os merge input", () => {
  beforeAll(() => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });
  afterAll(() => {
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("a committed docker-os-sbom.json at the base dir threads os-scope deb/apk entries into the merged model", async () => {
    const { root } = makeScannableTree();
    writeFileSync(
      join(root, "docker-os-sbom.json"),
      JSON.stringify(DOCKER_OS_SBOM),
    );
    const paths = pathsFor(root, false);

    let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        outputs = await buildOutputs({
          repoRoot: root,
          baseDir: root,
          ...paths,
          verbose: false,
        });
      }),
    );

    // The rendered document carries the dedicated OS section AND the deb/apk
    // rows — proof the committed SBOM crossed into the merge as scope:os.
    const md = outputs!.licensesMd;
    expect(md.includes("## Docker base-image OS packages")).toBe(true);
    const osSection = squish(
      md.slice(md.indexOf("## Docker base-image OS packages")),
    );
    expect(osSection.includes("| libc6 | deb | 2.36-9 |")).toBe(true);
    expect(osSection.includes("| musl | apk | 1.2.4-r2 |")).toBe(true);
  });

  test("NO committed file → NO os entries and NO docker/syft scan (offline, the cache-miss equivalent)", async () => {
    const { root } = makeScannableTree();
    // No docker-os-sbom.json written.
    const paths = pathsFor(root, false);

    let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        outputs = await buildOutputs({
          repoRoot: root,
          baseDir: root,
          ...paths,
          verbose: false,
        });
      }),
    );

    const md = outputs!.licensesMd;
    // The OS section heading still renders (stable shape) but carries NO rows.
    const osSection = squish(
      md.slice(md.indexOf("## Docker base-image OS packages")),
    );
    expect(osSection.includes("libc6")).toBe(false);
    expect(osSection.includes("musl")).toBe(false);
    expect(osSection.includes("pkg:deb/")).toBe(false);
    expect(osSection.includes("pkg:apk/")).toBe(false);
    // No docker base-image packages counted.
    expect(md.includes("- Docker OS packages: 0")).toBe(true);
  });
});
