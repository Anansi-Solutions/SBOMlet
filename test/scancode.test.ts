/**
 * Subprocess-free tests for src/enrich/scancode.ts.
 *
 * This file starts with the PURE fs-based mapper tests (sourceDirFor and its
 * npm/pypi helpers) — no exec mock needed. The invocation-lane recorder
 * harness (mock.module over ../src/collectors/exec, the dockerOsBuilt.test.ts
 * shape) is added ABOVE these in this same file so the mock.module suite
 * stays isolated in its own file (dockerOsBuilt.test.ts:7-10 rationale) while
 * still sharing the module under test.
 */

import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";

import * as execModule from "../src/collectors/exec";
import {
  electExpression,
  scancodeArgs,
  scanPackageSources,
  sourceDirFor,
  SCANCODE_TOOL,
} from "../src/enrich/scancode";
import { enrichUnknowns } from "../src/enrich/enrich";
import { getEntry, readCache, serializeCache } from "../src/enrich/cache";
import { annotateFindings } from "../src/normalize/normalize";

/** Original exec export captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

/** Every recorded execTool invocation: [cmd, ...args]. */
let invocations: string[][] = [];

/** The fixture path, loaded once and JSON.parse'd for in-test variant surgery. */
const FIXTURE_PATH = join(
  __dirname,
  "fixtures",
  "scancode-license-file-trimmed.json",
);

/**
 * A subprocess-free execTool recorder. For a scancode invocation (argv
 * containing "--json-pp"), copies the REAL fixture to the parsed out path
 * (the NEXT argv element) so the module's read-back succeeds without ever
 * spawning anything (the dockerOsBuilt.test.ts fakeExecTool shape, keyed
 * positionally instead of key=value).
 */
function fakeExecTool(
  cmd: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  invocations.push([cmd, ...args]);
  const jsonPpIndex = args.indexOf("--json-pp");
  if (jsonPpIndex !== -1) {
    const outFile = args[jsonPpIndex + 1] as string;
    copyFileSync(FIXTURE_PATH, outFile);
  }
  return Promise.resolve({ stdout: "", stderr: "" });
}

/** Build a fakeExecTool that writes a CALLER-SUPPLIED doc instead of the fixture. */
function makeFakeExecToolWithDoc(
  doc: unknown,
): (
  cmd: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string }> {
  return (cmd: string, args: string[]) => {
    invocations.push([cmd, ...args]);
    const jsonPpIndex = args.indexOf("--json-pp");
    if (jsonPpIndex !== -1) {
      const outFile = args[jsonPpIndex + 1] as string;
      writeFileSync(outFile, JSON.stringify(doc));
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  };
}

/** A fakeExecTool that writes a file bigger than the size gate at the out path. */
function makeFakeExecToolOversized(): (
  cmd: string,
  args: string[],
) => Promise<{ stdout: string; stderr: string }> {
  return (cmd: string, args: string[]) => {
    invocations.push([cmd, ...args]);
    const jsonPpIndex = args.indexOf("--json-pp");
    if (jsonPpIndex !== -1) {
      const outFile = args[jsonPpIndex + 1] as string;
      // Sparse-ish oversized file: 64 MiB cap + 1 byte, written cheaply via a
      // pre-sized buffer of zero bytes (still a real file on disk, no special
      // sparse-file API needed cross-platform).
      writeFileSync(outFile, Buffer.alloc(64 * 1024 * 1024 + 1));
    }
    return Promise.resolve({ stdout: "", stderr: "" });
  };
}

/** A fakeExecTool that throws an ENOENT-shaped error, simulating a missing tool binary. */
function fakeExecToolEnoent(): Promise<{ stdout: string; stderr: string }> {
  invocations.push(["scancode", "ENOENT-SIMULATED"]);
  const error = new Error("spawn scancode ENOENT") as NodeJS.ErrnoException;
  error.code = "ENOENT";
  return Promise.reject(error);
}

describe("scanPackageSources (subprocess-free, exec recorder harness)", () => {
  let tempDir: string;

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  afterEach(() => {
    invocations = [];
    if (tempDir !== undefined) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test("the recorded invocation equals exactly [scancodeBin, --license, --copyright, --json-pp, outFile, --, sourceDir]", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "scancode-invoke-"));
    await scanPackageSources("/some/source/dir", { tempDir });

    expect(invocations.length).toBe(1);
    const [cmd, ...args] = invocations[0] as string[];
    expect(cmd).toBe("scancode");
    // The outFile is temp-dir-relative and not asserted verbatim; assert the
    // fixed argv shape around it (the 01-03 argv-lock discipline).
    expect(args[0]).toBe("--license");
    expect(args[1]).toBe("--copyright");
    expect(args[2]).toBe("--json-pp");
    expect(typeof args[3]).toBe("string");
    expect(args[4]).toBe("--");
    expect(args[5]).toBe("/some/source/dir");
    expect(args.length).toBe(6);
  });

  test("happy path: elects the root-LICENSE detection, via license-file, sorted+deduped copyrights", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "scancode-happy-"));
    const result = await scanPackageSources("/some/source/dir", { tempDir });

    expect(result).not.toBeNull();
    expect(result?.raw).toBe("MIT");
    expect(result?.via).toBe(
      `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/license-file`,
    );
    // Copyrights union across ALL files (LICENSE + the bundled snippet),
    // sorted + deduped.
    expect(result?.copyrights).toEqual(
      [...result!.copyrights].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    expect(result?.copyrights.length).toBeGreaterThan(0);
    expect(
      result?.copyrights.some((c) => c.includes("Evgeny Poberezkin")),
    ).toBe(true);
    expect(result?.copyrights.some((c) => c.includes("Gary Court"))).toBe(true);
  });

  test("manifest lane: with the LICENSE entry removed, elects the package.json manifest detection", async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
      files: { path: string }[];
    };
    const withoutLicenseFile = {
      ...fixture,
      files: fixture.files.filter((f) => f.path !== "ajv/LICENSE"),
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(withoutLicenseFile),
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-manifest-"));
    const result = await scanPackageSources("/some/source/dir", { tempDir });

    expect(result).not.toBeNull();
    expect(result?.raw).toBe("MIT");
    expect(result?.via).toBe(
      `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/manifest`,
    );

    // Restore the shared fixture-based stub for subsequent tests.
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("no answer: neither legal-file nor manifest detection present -> null", async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
      files: { path: string }[];
    };
    const onlyNoise = {
      ...fixture,
      files: fixture.files.filter((f) => f.path === "ajv/NOTICE.txt"),
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(onlyNoise),
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-noanswer-"));
    const result = await scanPackageSources("/some/source/dir", { tempDir });
    expect(result).toBeNull();

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("rejection lane: an expression containing LicenseRef-scancode- is treated as no answer", async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
      files: { path: string }[];
    };
    // Rewrite the NOTICE.txt entry's path to a root-level LEGAL_FILE_PATTERN
    // match ("LICENSE") so the election lane WOULD elect it if the
    // LicenseRef rejection did not fire — proving the rejection, not just an
    // absence of a legal file.
    const noiseAsLicense = {
      ...fixture,
      files: fixture.files
        .filter((f) => f.path === "ajv/NOTICE.txt")
        .map((f) => ({ ...f, path: "LICENSE" })),
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(noiseAsLicense),
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-rejection-"));
    const result = await scanPackageSources("/some/source/dir", { tempDir });
    expect(result).toBeNull();

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("version assert: a different headers tool version rejects loudly, naming the invocation and both versions", async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: { tool_version: string }[];
      files: unknown[];
    };
    const wrongVersion = {
      ...fixture,
      headers: [{ ...fixture.headers[0], tool_version: "31.0.0" }],
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(wrongVersion),
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-version-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/31\.0\.0.*32\.5\.0|invocation:/s);

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("size gate: an oversized output file rejects BEFORE any parse", async () => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolOversized(),
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-oversized-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/over the.*byte cap/);

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("missing tool: an ENOENT-shaped spawn error rejects with the pipx install command", async () => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecToolEnoent,
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-enoent-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/pipx install "scancode-toolkit\[full\]==32\.5\.0"/);

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("isolation proof: no scancode invocation is recorded unless scanPackageSources is called", () => {
    expect(invocations).toEqual([]);
  });
});

describe("scancodeArgs (argv exact-array lock)", () => {
  test("locks the exact argv shape", () => {
    expect(scancodeArgs("/tmp/out.json", "/some/dir")).toEqual([
      "--license",
      "--copyright",
      "--json-pp",
      "/tmp/out.json",
      "--",
      "/some/dir",
    ]);
  });
});

describe("electExpression / electCopyrights (pure narrow, no exec)", () => {
  test("elects the manifest lane when no root legal file is present", () => {
    const files = [
      {
        path: "pkg/package.json",
        detected_license_expression_spdx: "Apache-2.0",
      },
    ];
    const elected = electExpression(files);
    expect(elected?.raw).toBe("Apache-2.0");
    expect(elected?.via).toContain("/manifest");
  });

  test("never AND-combines expressions across multiple files — first legal-file match wins", () => {
    const files = [
      { path: "pkg/LICENSE", detected_license_expression_spdx: "MIT" },
      {
        path: "pkg/vendor/LICENSE",
        detected_license_expression_spdx: "BSD-3-Clause",
      },
    ];
    const elected = electExpression(files);
    expect(elected?.raw).toBe("MIT");
  });
});

// --- Task 1: purl -> source-dir mapper (pure fs, no exec mock) -------------

describe("sourceDirFor — npm mapping", () => {
  let targetDir: string;

  afterEach(() => {
    if (targetDir !== undefined) {
      rmSync(targetDir, { recursive: true, force: true });
    }
  });

  function writeNpmPackage(dir: string, name: string, version: string): string {
    const pkgDir = join(dir, "node_modules", ...name.split("/"));
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name, version }),
    );
    return pkgDir;
  }

  test("an npm purl whose decoded name dir exists with a MATCHING package.json version resolves to that dir", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-"));
    const pkgDir = writeNpmPackage(targetDir, "left-pad", "1.3.0");

    const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toBe(pkgDir);
  });

  test("a scoped purl pkg:npm/%40scope/pkg@1.0.0 resolves to node_modules/@scope/pkg (A6 locked)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-scoped-"));
    const pkgDir = writeNpmPackage(targetDir, "@scope/pkg", "1.0.0");

    const result = sourceDirFor("pkg:npm/%40scope/pkg@1.0.0", [targetDir]);
    expect(result).toBe(pkgDir);
  });

  test("package.json version MISMATCH returns undefined (Pitfall 8)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-mismatch-"));
    writeNpmPackage(targetDir, "left-pad", "1.2.0");

    const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toBeUndefined();
  });

  test("dir absent returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-absent-"));
    mkdirSync(join(targetDir, "node_modules"), { recursive: true });

    const result = sourceDirFor("pkg:npm/does-not-exist@1.0.0", [targetDir]);
    expect(result).toBeUndefined();
  });

  test("package.json absent returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-nopkgjson-"));
    mkdirSync(join(targetDir, "node_modules", "left-pad"), {
      recursive: true,
    });

    const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toBeUndefined();
  });

  test("package.json unparseable returns undefined (never throws)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-badjson-"));
    const pkgDir = join(targetDir, "node_modules", "left-pad");
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(join(pkgDir, "package.json"), "{ not valid json");

    expect(() =>
      sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]),
    ).not.toThrow();
    const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toBeUndefined();
  });

  test("a crafted purl whose decoded name contains '..' never escapes node_modules", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-traversal-"));
    // Create a sibling dir OUTSIDE node_modules that a traversal would reach.
    mkdirSync(join(targetDir, "node_modules"), { recursive: true });
    const secretDir = join(targetDir, "secret");
    mkdirSync(secretDir, { recursive: true });
    writeFileSync(
      join(secretDir, "package.json"),
      JSON.stringify({ name: "evil", version: "1.0.0" }),
    );

    // "..%2Fsecret" decodes to "../secret" — an escape attempt.
    const result = sourceDirFor("pkg:npm/..%2Fsecret@1.0.0", [targetDir]);
    expect(result).toBeUndefined();
  });

  test("every non-undefined result path-prefix-matches <targetDir>/node_modules after resolution", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-invariant-"));
    const pkgDir = writeNpmPackage(targetDir, "left-pad", "1.3.0");

    const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toBeDefined();
    const nodeModulesRoot = join(targetDir, "node_modules");
    expect(result!.startsWith(nodeModulesRoot)).toBe(true);
    expect(result).toBe(pkgDir);
  });

  test("two targetDirs both matching — the compareCodeUnits-first dir wins deterministically", () => {
    const dirA = mkdtempSync(join(tmpdir(), "scancode-npm-multi-a-"));
    const dirB = mkdtempSync(join(tmpdir(), "scancode-npm-multi-b-"));
    try {
      const pkgInA = writeNpmPackage(dirA, "left-pad", "1.3.0");
      writeNpmPackage(dirB, "left-pad", "1.3.0");

      const sortedFirst = [dirA, dirB].sort((a, b) =>
        a < b ? -1 : a > b ? 1 : 0,
      )[0];
      const expected =
        sortedFirst === dirA ? pkgInA : join(dirB, "node_modules", "left-pad");

      // Call with REVERSED argument order to prove determinism is a function
      // of the sorted set, not caller order.
      const result = sourceDirFor("pkg:npm/left-pad@1.3.0", [dirB, dirA]);
      expect(result).toBe(expected);
    } finally {
      rmSync(dirA, { recursive: true, force: true });
      rmSync(dirB, { recursive: true, force: true });
    }
  });
});

describe("sourceDirFor — pypi mapping", () => {
  let targetDir: string;

  afterEach(() => {
    if (targetDir !== undefined) {
      rmSync(targetDir, { recursive: true, force: true });
    }
  });

  function venvSitePackagesDir(dir: string): string {
    return process.platform === "win32"
      ? join(dir, ".venv", "Lib", "site-packages")
      : join(dir, ".venv", "lib", "python3.12", "site-packages");
  }

  test("a pypi purl with a temp .venv dist-info + top_level.txt naming an existing sibling dir resolves to that dir", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });

    const distInfoDir = join(sitePackages, "typing_extensions-4.9.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    writeFileSync(join(distInfoDir, "top_level.txt"), "typing_extensions\n");

    const packageDir = join(sitePackages, "typing_extensions");
    mkdirSync(packageDir, { recursive: true });

    const result = sourceDirFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    expect(result).toBe(packageDir);
  });

  test("absent venv returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-novenv-"));
    const result = sourceDirFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    expect(result).toBeUndefined();
  });

  test("absent top-level dir returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-notopdir-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });
    const distInfoDir = join(sitePackages, "typing_extensions-4.9.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    writeFileSync(join(distInfoDir, "top_level.txt"), "typing_extensions\n");
    // Deliberately do NOT create the sibling package dir.

    const result = sourceDirFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    expect(result).toBeUndefined();
  });
});

describe("sourceDirFor — unsupported ecosystems and malformed purls", () => {
  test("terraform purls return undefined with zero fs probes", () => {
    const result = sourceDirFor(
      "pkg:terraform/registry.opentofu.org/hashicorp/aws@5.0.0",
      ["/nonexistent/dir/that/would/throw/if/probed"],
    );
    expect(result).toBeUndefined();
  });

  test("apk purls return undefined", () => {
    const result = sourceDirFor("pkg:apk/alpine/musl@1.2.0", [
      "/nonexistent/dir",
    ]);
    expect(result).toBeUndefined();
  });

  test("unparseable purls return undefined", () => {
    const result = sourceDirFor("not-a-purl-at-all", ["/nonexistent/dir"]);
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The intensive lane in enrichUnknowns (10-04): residual scan, provenance
// write, hermetic check. Uses the SAME exec recorder harness as above
// (mock.module over ../src/collectors/exec) plus enrichUnknowns from
// ../src/enrich/enrich — the end-to-end mechanism proof (D-10) that appending
// a scancode claim actually changes the RENDERED finding, not just the cache
// entry (Pitfall 1's warning sign).
// ---------------------------------------------------------------------------

describe("enrichUnknowns intensive lane (10-04: residual scan, provenance write, hermetic check)", () => {
  let repoDir: string;
  let cacheDir: string;

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  afterEach(() => {
    invocations = [];
    if (repoDir !== undefined)
      rmSync(repoDir, { recursive: true, force: true });
    if (cacheDir !== undefined)
      rmSync(cacheDir, { recursive: true, force: true });
  });

  /** A minimal on-disk node_modules/<name> tree with a version-matched package.json + LICENSE. */
  function writeNpmSource(
    targetDir: string,
    name: string,
    version: string,
    licenseText = "MIT License\n\nCopyright (c) 2020 Example Author\n",
  ): string {
    const pkgDir = join(targetDir, "node_modules", ...name.split("/"));
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name, version }),
    );
    writeFileSync(join(pkgDir, "LICENSE"), licenseText);
    return pkgDir;
  }

  function tempCachePath(): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), "scancode-intensive-cache-"));
    return { dir, path: join(dir, "enrichment-cache.json") };
  }

  function zeroClaimNpmPackage(
    name: string,
    version: string,
  ): import("../src/model/dependencies").PackageEntry {
    return {
      purl: `pkg:npm/${name}@${version}`,
      name,
      version,
      occurrences: [{ target: "proj", isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
  }

  /** The scancode-sourced claim on a package, or undefined when none was appended. */
  function scancodeClaim(
    entry: import("../src/model/dependencies").PackageEntry | undefined,
  ): import("../src/model/dependencies").LicenseClaim | undefined {
    return entry?.licenseClaims.find((c) => c.source === "scancode");
  }

  test("mechanism proof (D-10): a zero-claim package with a locally-present node_modules source gains the scancode claim, attribution, a cache entry, and a PRECISE rendered finding end-to-end", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    writeNpmSource(repoDir, "left-pad", "1.3.0");
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("left-pad", "1.3.0")],
    };

    const fixedNow = (): Date => new Date("2026-01-01T00:00:00.000Z");
    const { fetch } = fetchStubReturningEmpty();
    const result = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        now: fixedNow,
        intensive: {
          targetDirs: [repoDir],
          tempDir: mkdtempSync(join(tmpdir(), "scancode-intensive-out-")),
        },
      }),
    );

    expect(invocations.length).toBe(1);
    const pkg = result.model.packages[0];
    const claim = scancodeClaim(pkg);
    expect(claim).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
    expect(pkg?.attribution?.copyrightLines.length).toBeGreaterThan(0);

    const cache = readCache(path);
    const entry = getEntry(cache, "pkg:npm/left-pad@1.3.0");
    expect(entry?.source).toBe("scancode");
    expect(entry?.fetchedFrom).toBe("scancode");
    expect(entry?.via).toBe(
      `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/license-file`,
    );
    expect(entry?.resolvable).toBe(true);
    expect(entry?.copyrights?.length).toBeGreaterThan(0);
    expect(entry?.fetchedAt).toBe("2026-01-01T00:00:00.000Z");

    // The mechanism proof: the RENDERED finding is precise, not just the
    // cache entry (Pitfall 1's warning sign — assert the finding, not the
    // claim alone).
    const { model: annotated } = annotateFindings(
      { packages: result.model.packages } as never,
      [],
    );
    const finding = (
      annotated.packages[0] as {
        finding?: { expression: string | null; confidence: string };
      }
    ).finding;
    expect(finding?.expression).toBe("MIT");
    expect(finding?.confidence).toBe("exact");
  });

  test("Pitfall 5a: a package pre-seeded with a registry NEGATIVE entry is still scanned under intensive; a positive result overwrites the negative", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    writeNpmSource(repoDir, "left-pad", "1.3.0");
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const seedCache = new Map();
    seedCache.set("pkg:npm/left-pad@1.3.0", {
      license: null,
      source: "registry",
      fetchedFrom: "npm",
      via: "unresolved",
      resolvable: false,
    });
    writeFileSync(path, serializeCache(seedCache));

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("left-pad", "1.3.0")],
    };
    const { fetch, calls } = fetchStubReturningEmpty();
    const result = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      }),
    );
    // The package IS a cache hit (negative) — zero registry fetches — yet
    // still an intensive scan target.
    expect(calls).toEqual([]);
    expect(invocations.length).toBe(1);

    const pkg = result.model.packages[0];
    expect(scancodeClaim(pkg)).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });

    const cache = readCache(path);
    const entry = getEntry(cache, "pkg:npm/left-pad@1.3.0");
    expect(entry?.resolvable).toBe(true);
    expect(entry?.source).toBe("scancode");
  });

  test("Pitfall 5b: a scancode no-answer leaves the registry negative byte-untouched and writes no new entry", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    // Source dir present but with NO legal file / manifest license, so
    // scanPackageSources elects nothing (a clean no-answer, fixture: only the
    // LicenseRef-scancode- noise entry survives via the manifest-lane mock).
    const pkgDir = join(repoDir, "node_modules", "no-answer-pkg");
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name: "no-answer-pkg", version: "1.0.0" }),
    );

    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
      files: unknown[];
    };
    const noiseOnly = {
      ...fixture,
      files: [
        {
          path: "no-answer-pkg/LICENSE",
          detected_license_expression_spdx: "LicenseRef-scancode-unknown",
          copyrights: [],
        },
      ],
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(noiseOnly),
    }));

    const { dir, path } = tempCachePath();
    cacheDir = dir;
    const negativeEntry = {
      license: null,
      source: "registry" as const,
      fetchedFrom: "npm" as const,
      via: "unresolved",
      resolvable: false,
    };
    const seedCache = new Map();
    seedCache.set("pkg:npm/no-answer-pkg@1.0.0", negativeEntry);
    const seededBytes = serializeCache(seedCache);
    writeFileSync(path, seededBytes);

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("no-answer-pkg", "1.0.0")],
    };
    try {
      const result = await enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      });
      expect(scancodeClaim(result.model.packages[0])).toBeUndefined();

      const cache = readCache(path);
      expect(getEntry(cache, "pkg:npm/no-answer-pkg@1.0.0")).toEqual(
        negativeEntry,
      );
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }
  });

  test("D-02: a residual package whose sources are absent is skipped — zero scancode invocations, no entry, finding stays unknown", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-empty-"));
    mkdirSync(join(repoDir, "node_modules"), { recursive: true });
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("absent-pkg", "1.0.0")],
    };
    // The registry side is a genuine miss too (absent-pkg has no registry
    // doc); stub fetch to a clean 200-empty so fetchMisses records its OWN
    // (registry) negative rather than throwing — this test isolates the
    // scancode D-02 skip, not the registry-miss path.
    const { fetch } = fetchStubReturningEmpty();
    const result = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      }),
    );

    expect(invocations.length).toBe(0);
    expect(scancodeClaim(result.model.packages[0])).toBeUndefined();
    const cache = readCache(path);
    // The registry-negative entry IS written (existing fetchMisses contract,
    // unchanged) — but it carries NO scancode provenance: the D-02 skip means
    // zero scancode invocations, never a scancode-sourced entry.
    const entry = getEntry(cache, "pkg:npm/absent-pkg@1.0.0");
    expect(entry?.source).toBe("registry");
  });

  test("hermetic check (Pitfall 2): after an intensive generate, check mode with the scanner stubbed to throw never invokes it and reproduces byte-identical claims", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    writeNpmSource(repoDir, "left-pad", "1.3.0");
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("left-pad", "1.3.0")],
    };
    const { fetch } = fetchStubReturningEmpty();
    const generated = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      }),
    );
    const generatedClaim = scancodeClaim(generated.model.packages[0]);
    invocations = [];

    // check mode NEVER receives `intensive` at all (the CLI/pipeline layer's
    // job — Pitfall 4) — this proves the plain check-mode replay path alone
    // (no exec mock even engaged) reproduces the identical claim from the
    // committed cache.
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: (): Promise<{ stdout: string; stderr: string }> => {
        throw new Error("check must never invoke scancode");
      },
    }));
    try {
      const checked = await enrichUnknowns(model as never, {
        mode: "check",
        cachePath: path,
        verbose: false,
      });
      expect(checked.staleUnknowns).toEqual([]);
      expect(scancodeClaim(checked.model.packages[0])).toEqual(generatedClaim);
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }
  });

  test("idempotent warm run: a second intensive generate over the warm cache records ZERO scancode invocations", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    writeNpmSource(repoDir, "left-pad", "1.3.0");
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("left-pad", "1.3.0")],
    };
    const { fetch } = fetchStubReturningEmpty();
    await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      }),
    );
    invocations = [];

    const second = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
        intensive: { targetDirs: [repoDir] },
      }),
    );
    expect(invocations.length).toBe(0);
    expect(scancodeClaim(second.model.packages[0])).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
  });

  test("isolation guard: enrichUnknowns mode generate WITHOUT intensive over the same fixture repo invokes zero scancode scans", async () => {
    repoDir = mkdtempSync(join(tmpdir(), "scancode-intensive-repo-"));
    writeNpmSource(repoDir, "left-pad", "1.3.0");
    const { dir, path } = tempCachePath();
    cacheDir = dir;

    const model: CanonicalDependenciesLike = {
      packages: [zeroClaimNpmPackage("left-pad", "1.3.0")],
    };
    const { fetch } = fetchStubReturningEmpty();
    const result = await withFetchGlobal(fetch, () =>
      enrichUnknowns(model as never, {
        mode: "generate",
        cachePath: path,
        verbose: false,
      }),
    );
    expect(invocations.length).toBe(0);
    expect(scancodeClaim(result.model.packages[0])).toBeUndefined();
  });
});

/** Structural alias so the test fixtures don't need the real model import at the top. */
type CanonicalDependenciesLike = {
  packages: import("../src/model/dependencies").PackageEntry[];
};

/** A fetch stub returning an empty-object 200 body for any URL (registry-miss-safe default). */
function fetchStubReturningEmpty(): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const impl = (async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);
    return new Response(JSON.stringify({}), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetch: impl, calls };
}

/** Run `fn` with globalThis.fetch swapped, always restored in finally. */
async function withFetchGlobal<T>(
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
