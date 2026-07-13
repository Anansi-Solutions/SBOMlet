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
import { imageTag } from "../src/collectors/dockerBuild";
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
 * Warn-only policy fixture: the AGPL package is ACCEPTED by a
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

describe("runCheck + exitCodeFor — the CI gate", () => {
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

  test("Test 2: a byte-edited committed file is stale — for each configured output", async () => {
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

  test("Test 8b: --intensive is a config error on check — the shared option table cannot leak the flag into the offline gate", async () => {
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
    // Passing --intensive to check is a config error: it throws (-> main's
    // catch -> fail() -> exit 3 path) and never reaches exitCodeFor. This is
    // the FIRST guard, checked before the dump-model one, in runCheck.
    await withCapturedStderr(async () => {
      await expect(
        runCheck({
          repoRoot: root,
          ...paths,
          policyPath,
          intensive: true,
          verbose: false,
        }),
      ).rejects.toThrow("check never scans");
    });
    // check never wrote anything on its way to the throw.
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
    // it.
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
// The offline check contract (the zero-network clause): a
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

describe("offline check contract — enrichment staleness", () => {
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
// The committed docker.sbom.json is threaded into the merge as a
// scope:"os" INPUT (the emitter's output), repo-root-resolved. A MISSING file
// is the enrichment-cache-miss equivalent: NO os entries, NO scan, NO docker.
// buildOutputs is write-free so these run directly against a temp base dir.
// ===========================================================================

/**
 * A committed docker SBOM (the emitter shape): one deb + one apk, each
 * attributed to the single scanned image. The image-lane source is the ref
 * verbatim (source === image), so the occurrence identity becomes
 * "docker:postgres:18" — colons are inert in identities.
 */
const DOCKER_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      type: "library",
      name: "libc6",
      version: "2.36-9",
      purl: "pkg:deb/debian/libc6@2.36-9",
      images: ["postgres:18"],
    },
    {
      type: "library",
      name: "musl",
      version: "1.2.4-r2",
      purl: "pkg:apk/alpine/musl@1.2.4-r2",
      images: ["postgres:18"],
    },
  ],
  dockerImages: [
    {
      image: "postgres:18",
      digest: "postgres@sha256:deadbeef",
      source: "postgres:18",
    },
  ],
};

/** A clean 200-empty registry response so os-package unknowns stay offline. */
const EMPTY_FETCH = (async (): Promise<Response> =>
  new Response(JSON.stringify({}), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as unknown as typeof fetch;

describe("the committed docker.sbom.json as a scope:os merge input", () => {
  beforeAll(() => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });
  afterAll(() => {
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("a committed docker.sbom.json at the repo root threads os-scope deb/apk entries into the merged model", async () => {
    const { root } = makeScannableTree();
    mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
    writeFileSync(
      join(root, ".sbomlet.cache", "docker.sbom.json"),
      JSON.stringify(DOCKER_SBOM),
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
    expect(md.includes("## Docker image packages")).toBe(true);
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    expect(osSection.includes("| libc6 | deb | 2.36-9 |")).toBe(true);
    expect(osSection.includes("| musl | apk | 1.2.4-r2 |")).toBe(true);
    // The occurrence identity is per-image (image lane → the ref).
    expect(osSection.includes("docker:postgres:18")).toBe(true);
  });

  test("the committed docker.sbom.json is read from the REPO ROOT, not the base dir (the Action's divergent-dir case)", async () => {
    const { root } = makeScannableTree();
    // The Action shape: `task` runs from the action's own directory, so
    // base-dir is NOT the scanned repo; the consumer commits the SBOM at
    // THEIR repo root.
    const baseDir = mkdtempSync(join(tmpdir(), "licenses-check-basedir-"));
    mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
    writeFileSync(
      join(root, ".sbomlet.cache", "docker.sbom.json"),
      JSON.stringify(DOCKER_SBOM),
    );
    const paths = pathsFor(root, false);

    let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        outputs = await buildOutputs({
          repoRoot: root,
          baseDir,
          ...paths,
          verbose: false,
        });
      }),
    );

    // Read from the repo root, so the OS section and deb/apk rows are present.
    const md = outputs!.licensesMd;
    expect(md.includes("## Docker image packages")).toBe(true);
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    expect(osSection.includes("| libc6 | deb | 2.36-9 |")).toBe(true);
    expect(osSection.includes("| musl | apk | 1.2.4-r2 |")).toBe(true);
  });

  test("a docker.sbom.json beside the base dir is IGNORED when the base dir differs from the repo root (no base-dir leakage)", async () => {
    const { root } = makeScannableTree();
    const baseDir = mkdtempSync(join(tmpdir(), "licenses-check-basedir-"));
    // A cache dir in the invocation dir (e.g. the action's own checkout) must
    // NOT leak into a scan of a different repo root.
    mkdirSync(join(baseDir, ".sbomlet.cache"), { recursive: true });
    writeFileSync(
      join(baseDir, ".sbomlet.cache", "docker.sbom.json"),
      JSON.stringify(DOCKER_SBOM),
    );
    const paths = pathsFor(root, false);

    let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        outputs = await buildOutputs({
          repoRoot: root,
          baseDir,
          ...paths,
          verbose: false,
        });
      }),
    );

    const md = outputs!.licensesMd;
    // The OS section heading still renders, but the base-dir SBOM did NOT leak
    // in: none of its rows appear and the count is zero.
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    expect(osSection.includes("libc6")).toBe(false);
    expect(osSection.includes("musl")).toBe(false);
    expect(md.includes("- Docker image packages: 0")).toBe(true);
  });

  test("NO committed file → NO os entries and NO docker/syft scan (offline, the cache-miss equivalent)", async () => {
    const { root } = makeScannableTree();
    // No docker.sbom.json written.
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
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    expect(osSection.includes("libc6")).toBe(false);
    expect(osSection.includes("musl")).toBe(false);
    expect(osSection.includes("pkg:deb/")).toBe(false);
    expect(osSection.includes("pkg:apk/")).toBe(false);
    // No docker base-image packages counted.
    expect(md.includes("- Docker image packages: 0")).toBe(true);
  });

  test("a LEGACY docker-os.sbom.json without the current file fails LOUDLY naming the remedy", async () => {
    const { root } = makeScannableTree();
    mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
    // A repo generated before the rename: only the old filename exists.
    writeFileSync(
      join(root, ".sbomlet.cache", "docker-os.sbom.json"),
      JSON.stringify(DOCKER_SBOM),
    );
    const paths = pathsFor(root, false);

    await expect(
      withFetch(EMPTY_FETCH, () =>
        withCapturedStderr(async () => {
          await buildOutputs({
            repoRoot: root,
            baseDir: root,
            ...paths,
            verbose: false,
          });
        }),
      ),
    ).rejects.toThrow(/re-run the docker scan \(task generate DOCKER=1\)/);
  });

  test("a lingering legacy file beside the current docker.sbom.json is ignored — its content is never read", async () => {
    const { root } = makeScannableTree();
    mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
    writeFileSync(
      join(root, ".sbomlet.cache", "docker.sbom.json"),
      JSON.stringify(DOCKER_SBOM),
    );
    // Deliberately unparseable: reading it would throw, proving it is not read.
    writeFileSync(
      join(root, ".sbomlet.cache", "docker-os.sbom.json"),
      "not json",
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

    const osSection = squish(
      outputs!.licensesMd.slice(
        outputs!.licensesMd.indexOf("## Docker image packages"),
      ),
    );
    expect(osSection.includes("| libc6 | deb | 2.36-9 |")).toBe(true);
  });

  test("an explicit --docker-sbom override reads that file only — no legacy-file guard", async () => {
    const { root } = makeScannableTree();
    mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
    // Legacy file present at the default location, but the caller names an
    // explicit path: the override wins and the guard stays silent.
    writeFileSync(
      join(root, ".sbomlet.cache", "docker-os.sbom.json"),
      "not json",
    );
    const override = join(root, "custom.sbom.json");
    writeFileSync(override, JSON.stringify(DOCKER_SBOM));
    const paths = pathsFor(root, false);

    let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        outputs = await buildOutputs({
          repoRoot: root,
          baseDir: root,
          ...paths,
          dockerSbomPath: override,
          verbose: false,
        });
      }),
    );

    const osSection = squish(
      outputs!.licensesMd.slice(
        outputs!.licensesMd.indexOf("## Docker image packages"),
      ),
    );
    expect(osSection.includes("| libc6 | deb | 2.36-9 |")).toBe(true);
  });
});

// ===========================================================================
// Sidecar fan-out: the committed docker SBOM (per-component images[],
// per-image source) becomes one merge input PER IMAGE with occurrence
// identities docker:<source>, so a purl shared across images gets one
// occurrence per image through the untouched mergeSboms — exactly like a
// package in two workspaces. A sidecar without full attribution is malformed
// and fails LOUDLY — never a partial per-image model, never silently dropped
// inventory.
// ===========================================================================

/** Write `doc` as the committed docker.sbom.json inside root's cache dir. */
function writeSidecar(root: string, doc: unknown): void {
  mkdirSync(join(root, ".sbomlet.cache"), { recursive: true });
  writeFileSync(
    join(root, ".sbomlet.cache", "docker.sbom.json"),
    JSON.stringify(doc),
  );
}

/** One sidecar component; `images` is omitted entirely when undefined. */
function sidecarComponent(
  name: string,
  images?: readonly string[],
): Record<string, unknown> {
  return {
    type: "library",
    name,
    version: "1.0.0",
    purl: `pkg:apk/alpine/${name}@1.0.0`,
    licenses: [{ license: { id: "MIT" } }],
    ...(images !== undefined ? { images: [...images] } : {}),
  };
}

/** Assemble a sidecar document from component and image entries. */
function sidecarDoc(
  components: ReadonlyArray<Record<string, unknown>>,
  dockerImages: ReadonlyArray<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [...components],
    dockerImages: [...dockerImages],
  };
}

const IMG_A = { image: "img-a", digest: "", source: "a/Dockerfile" };
const IMG_B = { image: "img-b", digest: "", source: "b/Dockerfile" };
const ATTRIBUTED_COMPONENTS = [
  sidecarComponent("only-a", ["img-a"]),
  sidecarComponent("only-b", ["img-b"]),
  sidecarComponent("shared-pkg", ["img-a", "img-b"]),
];

/** A sidecar over two images: one shared + one unique each. */
const TWO_IMAGE_SIDECAR = sidecarDoc(ATTRIBUTED_COMPONENTS, [IMG_A, IMG_B]);

/** A policy whose FIRST compatible rule is docker-scoped (musl, warn-only). */
const SCOPED_DOCKER_POLICY = [
  "[unknown]",
  'handling = "warn"',
  "",
  "[os_dependencies]",
  'handling = "warn"',
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "musl"',
  'reason = "scoped to the postgres image occurrence"',
  'where = ["docker:postgres:18"]',
  "",
  "[[compatible]]",
  'match = "license"',
  'pattern = "AGPL-3.0-only"',
  'reason = "app fixture acceptance"',
  "",
].join("\n");

/** buildOutputs over root with a stubbed registry and captured stderr. */
async function buildAgainst(
  root: string,
  policyPath?: string,
): Promise<{
  outputs: Awaited<ReturnType<typeof buildOutputs>>;
  stderr: string;
}> {
  const paths = pathsFor(root, false);
  let outputs: Awaited<ReturnType<typeof buildOutputs>> | undefined;
  const stderr = await withFetch(EMPTY_FETCH, () =>
    withCapturedStderr(async () => {
      outputs = await buildOutputs({
        repoRoot: root,
        baseDir: root,
        ...paths,
        ...(policyPath !== undefined ? { policyPath } : {}),
        verbose: false,
      });
    }),
  );
  return { outputs: outputs!, stderr };
}

describe("sidecar fan-out and the malformed-sidecar failure", () => {
  beforeAll(() => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });
  afterAll(() => {
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("the sidecar fans out per image: a shared purl carries BOTH per-image identities, unique purls one each", async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, TWO_IMAGE_SIDECAR);

    const { outputs } = await buildAgainst(root);

    const md = outputs.licensesMd;
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    // The shared purl crossed the untouched merge as TWO occurrences whose
    // targets are the sorted per-image identities.
    expect(
      osSection.includes(
        "| shared-pkg | apk | 1.0.0 | MIT | docker:a/Dockerfile, docker:b/Dockerfile |",
      ),
    ).toBe(true);
    expect(
      osSection.includes(
        "| only-a | apk | 1.0.0 | MIT | docker:a/Dockerfile |",
      ),
    ).toBe(true);
    expect(
      osSection.includes(
        "| only-b | apk | 1.0.0 | MIT | docker:b/Dockerfile |",
      ),
    ).toBe(true);
    // Still one ROW per purl (the fan-out multiplies occurrences, not rows).
    expect(md.includes("- Docker image packages: 3")).toBe(true);
  });

  const MALFORMED_VARIANTS: ReadonlyArray<{ label: string; doc: unknown }> = [
    {
      label: "a component lacking images[]",
      doc: sidecarDoc(
        [
          sidecarComponent("only-a"),
          sidecarComponent("only-b", ["img-b"]),
          sidecarComponent("shared-pkg", ["img-a", "img-b"]),
        ],
        [IMG_A, IMG_B],
      ),
    },
    {
      label: "a non-string entry inside images[]",
      doc: sidecarDoc(
        [
          { ...sidecarComponent("only-a"), images: ["img-a", 7] },
          sidecarComponent("only-b", ["img-b"]),
          sidecarComponent("shared-pkg", ["img-a", "img-b"]),
        ],
        [IMG_A, IMG_B],
      ),
    },
    {
      label: "an EMPTY images[] membership",
      doc: sidecarDoc(
        [
          { ...sidecarComponent("only-a"), images: [] },
          sidecarComponent("only-b", ["img-b"]),
          sidecarComponent("shared-pkg", ["img-a", "img-b"]),
        ],
        [IMG_A, IMG_B],
      ),
    },
    {
      label: "a dockerImages entry lacking source",
      doc: sidecarDoc(ATTRIBUTED_COMPONENTS, [
        { image: "img-a", digest: "" },
        IMG_B,
      ]),
    },
    {
      label: "a membership naming an image absent from dockerImages",
      doc: sidecarDoc(
        [
          sidecarComponent("only-a", ["img-a"]),
          sidecarComponent("only-b", ["img-b"]),
          sidecarComponent("shared-pkg", ["img-a", "img-ghost"]),
        ],
        [IMG_A, IMG_B],
      ),
    },
    {
      label: "duplicate image names in dockerImages",
      doc: sidecarDoc(ATTRIBUTED_COMPONENTS, [
        IMG_A,
        { image: "img-a", digest: "", source: "other/Dockerfile" },
        IMG_B,
      ]),
    },
  ];

  for (const { label, doc } of MALFORMED_VARIANTS) {
    test(`a malformed sidecar (${label}) fails LOUDLY — never a partial model, never dropped inventory`, async () => {
      const { root } = makeScannableTree();
      writeSidecar(root, doc);

      await expect(buildAgainst(root)).rejects.toThrow(
        /re-run the docker scan/,
      );
    });
  }

  test("a compatible rule scoped to a per-image occurrence matches — not unused", async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, DOCKER_SBOM);
    const policyPath = writePolicy(root, SCOPED_DOCKER_POLICY);

    const { stderr } = await buildAgainst(root, policyPath);

    // The scoped rule matched at docker:postgres:18 — not unused.
    expect(stderr.includes("policy warning: unused entry compatible[0]")).toBe(
      false,
    );
  });

  test("double-read determinism: two builds over one sidecar are byte-identical", async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, TWO_IMAGE_SIDECAR);

    const first = await buildAgainst(root);
    const second = await buildAgainst(root);

    expect(second.outputs.licensesMd).toBe(first.outputs.licensesMd);
    expect(second.outputs.noticesMd).toBe(first.outputs.noticesMd);
  });
});

// ===========================================================================
// THE DESIGN TEST: two Dockerfiles,
// busybox accepted via `where` in image A only — image B's busybox occurrence
// warns per [os_dependencies] handling (fails under handling="fail"), VISIBLY
// in the rendered output and in a stderr policy line naming the B target; the
// unscoped variant accepts busybox at BOTH occurrences (narrowing is opt-in).
// The sidecar is synthetic but shaped exactly like the emitter's output —
// field names and sort orders, image tags derived via imageTag() from the
// same Dockerfile identities the built lanes record as sources.
// ===========================================================================

const TAG_A = imageTag("a/Dockerfile");
const TAG_B = imageTag("b/Dockerfile");

const BUSYBOX_PURL =
  "pkg:apk/alpine/busybox@1.37.0-r19?arch=x86_64&distro=alpine-3.23.4";

/** The two-Dockerfile scenario sidecar: busybox in A+B, musl in A, zlib in B. */
const SCENARIO_SIDECAR = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  components: [
    {
      type: "library",
      name: "busybox",
      version: "1.37.0-r19",
      purl: BUSYBOX_PURL,
      licenses: [{ license: { id: "GPL-2.0-only" } }],
      images: [TAG_A, TAG_B],
    },
    {
      type: "library",
      name: "musl",
      version: "1.2.5-r10",
      purl: "pkg:apk/alpine/musl@1.2.5-r10",
      licenses: [{ expression: "MIT" }],
      images: [TAG_A],
    },
    {
      type: "library",
      name: "zlib",
      version: "1.3.1-r2",
      purl: "pkg:apk/alpine/zlib@1.3.1-r2",
      licenses: [{ license: { id: "Zlib" } }],
      images: [TAG_B],
    },
  ],
  dockerImages: [
    { image: TAG_A, digest: "", source: "a/Dockerfile" },
    { image: TAG_B, digest: "", source: "b/Dockerfile" },
  ],
};

/**
 * The scenario policy: busybox accepted by compatible[0] (scoped to image A's
 * Dockerfile identity when `scoped`), [os_dependencies] handling variable, and
 * the app-fixture AGPL package accepted by compatible[1] so only the docker
 * side decides the verdict stream's fails/warns.
 */
function scenarioPolicy(osHandling: string, scoped: boolean): string {
  return [
    "[unknown]",
    'handling = "warn"',
    "",
    "[os_dependencies]",
    `handling = "${osHandling}"`,
    "",
    "[[compatible]]",
    'match = "package"',
    'name = "busybox"',
    'reason = "reviewed in the image-A OS layer"',
    ...(scoped ? ['where = ["docker:a/Dockerfile"]'] : []),
    "",
    "[[compatible]]",
    'match = "license"',
    'pattern = "AGPL-3.0-only"',
    'reason = "app fixture acceptance"',
    "",
  ].join("\n");
}

describe("the two-Dockerfile scenario end-to-end", () => {
  beforeAll(() => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeScanWithCdxgen,
    }));
  });
  afterAll(() => {
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  test("scoped acceptance: busybox ok via compatible[0] at image A ONLY; the B occurrence WARNS visibly in render and stderr", async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, SCENARIO_SIDECAR);
    const policyPath = writePolicy(root, scenarioPolicy("warn", true));

    const { outputs, stderr } = await buildAgainst(root, policyPath);

    // Verdict stream: ok citing the scoped rule at A; os-downgraded warn at B.
    const verdicts = outputs.verdicts!;
    const atA = verdicts.find(
      (v) =>
        v.purl === BUSYBOX_PURL && v.occurrenceTarget === "docker:a/Dockerfile",
    )!;
    const atB = verdicts.find(
      (v) =>
        v.purl === BUSYBOX_PURL && v.occurrenceTarget === "docker:b/Dockerfile",
    )!;
    expect(atA.status).toBe("ok");
    expect(atA.rule).toBe("compatible[0]");
    expect(atB.status).toBe("warn");
    expect(atB.rule).toBe("default:copyleft");

    // stderr: the warn line names the B target; nothing flags the A target;
    // the scoped rule matched at A, so no unused-entry warning for it.
    expect(
      stderr.includes(`policy warn: ${BUSYBOX_PURL} in docker:b/Dockerfile`),
    ).toBe(true);
    expect(stderr.includes(`${BUSYBOX_PURL} in docker:a/Dockerfile`)).toBe(
      false,
    );
    expect(stderr.includes("policy warning: unused entry compatible[0]")).toBe(
      false,
    );

    // Rendered warn surface: the copyleft section flags ONLY the B occurrence,
    // and the non-blocking roll-up names the copyleft warning.
    const md = outputs.licensesMd;
    const copyleft = squish(
      md.slice(
        md.indexOf("## Copyleft and special notices"),
        md.indexOf("## Production dependencies"),
      ),
    );
    expect(copyleft.includes("| busybox |")).toBe(true);
    expect(copyleft.includes("docker:b/Dockerfile")).toBe(true);
    expect(copyleft.includes("docker:a/Dockerfile")).toBe(false);
    expect(md.includes("1 copyleft warning(s)")).toBe(true);

    // The Docker section's Used-in still names BOTH occurrences (the flow
    // sidecar → merge → Used-in is per-image; only the FLAGGED surface narrows).
    const osSection = squish(md.slice(md.indexOf("## Docker image packages")));
    expect(
      osSection.includes(
        "| busybox | apk | 1.37.0-r19 | GPL-2.0-only | docker:a/Dockerfile, docker:b/Dockerfile |",
      ),
    ).toBe(true);
  });

  test('with [os_dependencies] handling="fail" the B occurrence FAILS — exit 1, blocking table names the B target', async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, SCENARIO_SIDECAR);
    const policyPath = writePolicy(root, scenarioPolicy("fail", true));
    const paths = pathsFor(root, false);
    await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        await runGenerate({
          repoRoot: root,
          ...paths,
          policyPath,
          verbose: false,
        });
      }),
    );

    let result: Awaited<ReturnType<typeof runCheck>> | undefined;
    const stderr = await withFetch(EMPTY_FETCH, () =>
      withCapturedStderr(async () => {
        result = await runCheck({
          repoRoot: root,
          ...paths,
          policyPath,
          verbose: false,
        });
      }),
    );

    expect(
      stderr.includes(`policy fail: ${BUSYBOX_PURL} in docker:b/Dockerfile`),
    ).toBe(true);
    expect(exitCodeFor(result!)).toBe(1);

    // The committed document's BLOCKING table carries the B-target row.
    const md = readFileSync(paths.outputPath, "utf8");
    const problematic = squish(
      md.slice(
        md.indexOf("## Problematic licenses"),
        md.indexOf("## Copyleft and special notices"),
      ),
    );
    expect(problematic.includes("| fail | default:copyleft | busybox |")).toBe(
      true,
    );
    expect(problematic.includes("docker:b/Dockerfile")).toBe(true);
    expect(problematic.includes("docker:a/Dockerfile")).toBe(false);
  });

  test("UNSCOPED variant: dropping where accepts busybox at BOTH occurrences (narrowing is opt-in)", async () => {
    const { root } = makeScannableTree();
    writeSidecar(root, SCENARIO_SIDECAR);
    const policyPath = writePolicy(root, scenarioPolicy("warn", false));

    const { outputs, stderr } = await buildAgainst(root, policyPath);

    const busybox = outputs
      .verdicts!.filter((v) => v.purl === BUSYBOX_PURL)
      .map((v) => [v.occurrenceTarget, v.status, v.rule]);
    expect(busybox).toEqual([
      ["docker:a/Dockerfile", "ok", "compatible[0]"],
      ["docker:b/Dockerfile", "ok", "compatible[0]"],
    ]);
    expect(stderr.includes(`policy warn: ${BUSYBOX_PURL}`)).toBe(false);
  });
});
