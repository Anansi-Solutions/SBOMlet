/**
 * Subprocess-free tests for src/enrich/scancode.ts.
 *
 * This file starts with the PURE fs-based mapper tests (sourceDirsFor and its
 * npm/pypi helpers) — no exec mock needed. The invocation-lane recorder
 * harness (mock.module over ../src/collectors/exec, the dockerOsBuilt.test.ts
 * shape) is added ABOVE these in this same file so the mock.module suite
 * stays isolated in its own file (dockerOsBuilt.test.ts:7-10 rationale) while
 * still sharing the module under test.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";

import * as cdxgenModule from "../src/collectors/cdxgen";
import * as execModule from "../src/collectors/exec";
import {
  electCopyrights,
  electExpression,
  scancodeArgs,
  scanPackageSources,
  sourceDirsFor,
  SCANCODE_TOOL,
} from "../src/enrich/scancode";
import { serializeCache } from "../src/enrich/cache";
import { annotateFindings } from "../src/normalize/normalize";
import { runGenerate } from "../src/pipeline/pipeline";
import { assessPackages } from "../src/enrich/assess";
import {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  serializeScancodeMemo,
} from "../src/enrich/scancode-cache";
import {
  toSortedDependenciesJson,
  type LicenseClaim,
  type PackageEntry,
} from "../src/model/dependencies";

/** Original exec export captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

/** Original cdxgen export captured BEFORE any mock.module call (restore target). */
const REAL_CDXGEN = { ...cdxgenModule };

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

  test("missing tool: an ENOENT-shaped spawn error rejects with the mise install hint", async () => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecToolEnoent,
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-enoent-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/run mise install/);

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("partial-file-error exit: a NON-ZERO scancode exit that still wrote a valid, version-asserted output is TOLERATED — the produced result is elected, the run is not aborted (a bundled undecodable file must not sink the whole scan)", async () => {
    // ScanCode exits code 1 when some files fail to scan (an undecodable or
    // oversized bundled data file) yet writes complete output for the rest.
    const failButWroteFixture = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      const i = args.indexOf("--json-pp");
      if (i !== -1) copyFileSync(FIXTURE_PATH, args[i + 1] as string);
      return Promise.reject(
        new Error(
          "scancode exited with code 1\nSome files failed to scan properly",
        ),
      );
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: failButWroteFixture,
    }));
    tempDir = mkdtempSync(join(tmpdir(), "scancode-partial-"));
    const result = await scanPackageSources("/some/source/dir", { tempDir });
    expect(result?.raw).toBe("MIT");
    expect(result?.via).toBe(
      `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/license-file`,
    );
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("non-zero exit with NO output file still throws (the failure is real — tolerance requires a produced result)", async () => {
    const failNoOutput = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      return Promise.reject(new Error("scancode exited with code 1"));
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: failNoOutput,
    }));
    tempDir = mkdtempSync(join(tmpdir(), "scancode-fail-noout-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/exited with code 1|produced no output/);
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("non-zero exit whose output fails the tool_version assert still throws (the integrity gate survives tolerance — a substituted binary is never silently accepted)", async () => {
    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: { tool_version: string }[];
      files: unknown[];
    };
    const wrongVersion = {
      ...fixture,
      headers: [{ ...fixture.headers[0], tool_version: "31.0.0" }],
    };
    const failWrongVersion = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      const i = args.indexOf("--json-pp");
      if (i !== -1)
        writeFileSync(args[i + 1] as string, JSON.stringify(wrongVersion));
      return Promise.reject(new Error("scancode exited with code 1"));
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: failWrongVersion,
    }));
    tempDir = mkdtempSync(join(tmpdir(), "scancode-fail-version-"));
    await expect(
      scanPackageSources("/some/source/dir", { tempDir }),
    ).rejects.toThrow(/31\.0\.0.*32\.5\.0|invocation:/s);
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  test("a shared tempDir never lets a previous scan's output masquerade as a later scan's result", async () => {
    // One caller-supplied tempDir threaded into two scans (exactly what
    // the assessment stage scan loop does when IntensiveOptions.tempDir is
    // set): the second
    // scan's exec writes NO output, so the 'produced no output' guard must
    // fire — never a parse of the FIRST package's leftover file.
    let call = 0;
    const writeOnceExecTool = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      if (call++ === 0) {
        const jsonPpIndex = args.indexOf("--json-pp");
        copyFileSync(FIXTURE_PATH, args[jsonPpIndex + 1] as string);
      }
      return Promise.resolve({ stdout: "", stderr: "" });
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: writeOnceExecTool,
    }));

    tempDir = mkdtempSync(join(tmpdir(), "scancode-shared-"));
    try {
      const first = await scanPackageSources("/pkg/first", { tempDir });
      expect(first?.raw).toBe("MIT");
      await expect(
        scanPackageSources("/pkg/second", { tempDir }),
      ).rejects.toThrow(/produced no output/);
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }
  });

  test("an owned (default) temp dir is cleaned up after the scan", async () => {
    const result = await scanPackageSources("/some/source/dir", {});
    expect(result?.raw).toBe("MIT");
    // argv shape: [cmd, --license, --copyright, --json-pp, outFile, --, dir]
    const outFile = (invocations[0] as string[])[4] as string;
    expect(existsSync(dirname(outFile))).toBe(false);
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

  test("BUG (10-07 adversarial review, Lens 5): a nested vendored/bundled LICENSE must never outrank the scanned tree's own ROOT legal file — election is basename-only today with no depth check, so array order alone can elect a deeply-nested vendor LICENSE over the real root LICENSE", () => {
    const files = [
      // scancode's files[] walk order is not guaranteed root-first; a nested
      // vendored/bundled dependency's LICENSE (a DIFFERENT, even copyleft
      // license) appears BEFORE the scanned package's own root LICENSE.
      {
        path: "pkg/dist/vendor/some-lib/LICENSE",
        detected_license_expression_spdx: "GPL-3.0-only",
      },
      { path: "pkg/LICENSE", detected_license_expression_spdx: "MIT" },
    ];
    const elected = electExpression(files);
    // The scanned package's OWN root license must win — a nested vendored
    // file two-or-more segments deep is never "the" root legal file.
    expect(elected?.raw).toBe("MIT");
  });

  test("a null element inside a copyrights[] array is skipped, never a TypeError", () => {
    const files = [
      {
        path: "pkg/LICENSE",
        detected_license_expression_spdx: "MIT",
        // A corrupted/substituted output can carry a null element; the parse
        // path's posture everywhere else is tolerant narrowing (skip).
        copyrights: [null, { copyright: "Copyright (c) 2020 Example Author" }],
      },
    ];
    expect(() => electCopyrights(files)).not.toThrow();
    expect(electCopyrights(files)).toEqual([
      "Copyright (c) 2020 Example Author",
    ]);
  });
});

// --- Task 1: purl -> source-dir mapper (pure fs, no exec mock) -------------

describe("sourceDirsFor — npm mapping", () => {
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

    const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toEqual([pkgDir]);
  });

  test("a scoped purl pkg:npm/%40scope/pkg@1.0.0 resolves to node_modules/@scope/pkg (A6 locked)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-scoped-"));
    const pkgDir = writeNpmPackage(targetDir, "@scope/pkg", "1.0.0");

    const result = sourceDirsFor("pkg:npm/%40scope/pkg@1.0.0", [targetDir]);
    expect(result).toEqual([pkgDir]);
  });

  test("package.json version MISMATCH returns undefined (Pitfall 8)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-mismatch-"));
    writeNpmPackage(targetDir, "left-pad", "1.2.0");

    const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toEqual([]);
  });

  test("dir absent returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-absent-"));
    mkdirSync(join(targetDir, "node_modules"), { recursive: true });

    const result = sourceDirsFor("pkg:npm/does-not-exist@1.0.0", [targetDir]);
    expect(result).toEqual([]);
  });

  test("package.json absent returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-nopkgjson-"));
    mkdirSync(join(targetDir, "node_modules", "left-pad"), {
      recursive: true,
    });

    const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toEqual([]);
  });

  test("package.json unparseable returns undefined (never throws)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-badjson-"));
    const pkgDir = join(targetDir, "node_modules", "left-pad");
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(join(pkgDir, "package.json"), "{ not valid json");

    expect(() =>
      sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]),
    ).not.toThrow();
    const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toEqual([]);
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
    const result = sourceDirsFor("pkg:npm/..%2Fsecret@1.0.0", [targetDir]);
    expect(result).toEqual([]);
  });

  test("every non-empty result path-prefix-matches <targetDir>/node_modules after resolution", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-invariant-"));
    const pkgDir = writeNpmPackage(targetDir, "left-pad", "1.3.0");

    const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [targetDir]);
    expect(result).toHaveLength(1);
    const nodeModulesRoot = join(targetDir, "node_modules");
    expect(result[0]!.startsWith(nodeModulesRoot)).toBe(true);
    expect(result).toEqual([pkgDir]);
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
      const result = sourceDirsFor("pkg:npm/left-pad@1.3.0", [dirB, dirA]);
      expect(result).toEqual([expected]);
    } finally {
      rmSync(dirA, { recursive: true, force: true });
      rmSync(dirB, { recursive: true, force: true });
    }
  });
});

describe("sourceDirsFor — pypi mapping", () => {
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

  test("a pypi purl with a temp .venv dist-info + top_level.txt naming an existing sibling dir yields the dist-info dir first, then that dir", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });

    const distInfoDir = join(sitePackages, "typing_extensions-4.9.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    writeFileSync(join(distInfoDir, "top_level.txt"), "typing_extensions\n");

    const packageDir = join(sitePackages, "typing_extensions");
    mkdirSync(packageDir, { recursive: true });

    const result = sourceDirsFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    // The dist-info dir holds the wheel's METADATA and legal files — it is
    // the first scan candidate; the import package dir follows.
    expect(result).toEqual([distInfoDir, packageDir]);
  });

  test("absent venv returns undefined", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-novenv-"));
    const result = sourceDirsFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    expect(result).toEqual([]);
  });

  test("absent top-level dir still yields the dist-info dir (the wheel's own evidence)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-notopdir-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });
    const distInfoDir = join(sitePackages, "typing_extensions-4.9.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    writeFileSync(join(distInfoDir, "top_level.txt"), "typing_extensions\n");
    // Deliberately do NOT create the sibling package dir.

    const result = sourceDirsFor("pkg:pypi/typing-extensions@4.9.0", [
      targetDir,
    ]);
    expect(result).toEqual([distInfoDir]);
  });

  test("a hostile top_level.txt line containing '..' never escapes site-packages (mirrors the npm traversal guard)", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-traversal-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });
    const distInfoDir = join(sitePackages, "evil-1.0.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    // top_level.txt is fully controlled by the installed package: a "../"
    // line joined naively resolves OUTSIDE site-packages.
    writeFileSync(join(distInfoDir, "top_level.txt"), "../escape\n");
    // Create the dir a naive join() would reach, so ONLY the escape guard —
    // not a failing existsSync — can produce the undefined below.
    mkdirSync(join(sitePackages, "..", "escape"), { recursive: true });

    // The dist-info dir stays a legitimate candidate; the escaped path must
    // never appear among the candidates.
    const result = sourceDirsFor("pkg:pypi/evil@1.0.0", [targetDir]);
    expect(result).toEqual([distInfoDir]);
  });

  test("an absolute-path-shaped top_level.txt line never resolves outside site-packages", () => {
    targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-absline-"));
    const sitePackages = venvSitePackagesDir(targetDir);
    mkdirSync(sitePackages, { recursive: true });
    const distInfoDir = join(sitePackages, "evil-1.0.0.dist-info");
    mkdirSync(distInfoDir, { recursive: true });
    // An absolute path resolves to itself under resolve(); targetDir exists,
    // so only the containment guard can reject it.
    writeFileSync(join(distInfoDir, "top_level.txt"), `${targetDir}\n`);

    const result = sourceDirsFor("pkg:pypi/evil@1.0.0", [targetDir]);
    expect(result).toEqual([distInfoDir]);
  });
});

describe("sourceDirsFor — unsupported ecosystems and malformed purls", () => {
  test("terraform purls return undefined with zero fs probes", () => {
    const result = sourceDirsFor(
      "pkg:terraform/registry.opentofu.org/hashicorp/aws@5.0.0",
      ["/nonexistent/dir/that/would/throw/if/probed"],
    );
    expect(result).toEqual([]);
  });

  test("apk purls return undefined", () => {
    const result = sourceDirsFor("pkg:apk/alpine/musl@1.2.0", [
      "/nonexistent/dir",
    ]);
    expect(result).toEqual([]);
  });

  test("unparseable purls return undefined", () => {
    const result = sourceDirsFor("not-a-purl-at-all", ["/nonexistent/dir"]);
    expect(result).toEqual([]);
  });

  test("a malformed percent-encoding in an npm purl name is an honest skip, never a URIError", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "scancode-npm-badenc-"));
    try {
      mkdirSync(join(targetDir, "node_modules"), { recursive: true });
      // decodeURIComponent("%ZZ") throws URIError; the mapper's contract is
      // undefined on ANY structural mismatch — a crafted SBOM purl must
      // never crash the run.
      expect(() =>
        sourceDirsFor("pkg:npm/%ZZ@1.0.0", [targetDir]),
      ).not.toThrow();
      expect(sourceDirsFor("pkg:npm/%ZZ@1.0.0", [targetDir])).toEqual([]);
    } finally {
      rmSync(targetDir, { recursive: true, force: true });
    }
  });

  test("a malformed percent-encoding in a pypi purl name is an honest skip, never a URIError", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "scancode-pypi-badenc-"));
    try {
      // A present site-packages so the mapper reaches its decode step.
      const sitePackages =
        process.platform === "win32"
          ? join(targetDir, ".venv", "Lib", "site-packages")
          : join(targetDir, ".venv", "lib", "python3.12", "site-packages");
      mkdirSync(sitePackages, { recursive: true });
      expect(() =>
        sourceDirsFor("pkg:pypi/%ZZ@1.0.0", [targetDir]),
      ).not.toThrow();
      expect(sourceDirsFor("pkg:pypi/%ZZ@1.0.0", [targetDir])).toEqual([]);
    } finally {
      rmSync(targetDir, { recursive: true, force: true });
    }
  });
});

/**
 * Capture process.stderr.write for the duration of a callback; always restores
 * in finally so a failing assertion can never poison later tests.
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

// ---------------------------------------------------------------------------
// The ScanCode peer assessment STAGE (12-04): assessPackages replays the
// committed analysis memo across EVERY package in both modes and, under
// generate --intensive only, analyzes the FULL package set — memoizing
// positives and no-results, reporting honest skips, never memoizing an absent
// tree. Uses the SAME exec recorder harness as above plus the dedicated memo
// module (../src/enrich/scancode-cache). The end-to-end mechanism proof is that
// a replayed/analyzed answer actually changes the RENDERED finding, not just
// the memo entry.
// ---------------------------------------------------------------------------

describe("assessPackages — ScanCode peer assessment stage (12-04)", () => {
  let repoDir: string | undefined;
  let memoDir: string | undefined;

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
    if (memoDir !== undefined)
      rmSync(memoDir, { recursive: true, force: true });
    repoDir = undefined;
    memoDir = undefined;
  });

  function newRepo(): string {
    repoDir = mkdtempSync(join(tmpdir(), "assess-repo-"));
    return repoDir;
  }

  function newMemoPath(): string {
    memoDir = mkdtempSync(join(tmpdir(), "assess-memo-"));
    return join(memoDir, "scancode.cache.json");
  }

  /** A minimal node_modules/<name> tree with a version-matched package.json + LICENSE. */
  function writeNpmSource(
    targetDir: string,
    name: string,
    version: string,
    licenseText = "MIT License\n\nCopyright (c) 2020 Example Author\n",
  ): void {
    const pkgDir = join(targetDir, "node_modules", ...name.split("/"));
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name, version }),
    );
    writeFileSync(join(pkgDir, "LICENSE"), licenseText);
  }

  function npmPackage(
    name: string,
    version: string,
    claims: LicenseClaim[] = [],
  ): PackageEntry {
    return {
      purl: `pkg:npm/${name}@${version}`,
      name,
      version,
      occurrences: [{ target: "proj", isDevDependency: false }],
      licenseClaims: claims,
      scope: "app",
    };
  }

  function generatorClaim(raw: string): LicenseClaim {
    return { raw, kind: "expression", source: "generator" };
  }

  function scancodeClaim(
    entry: PackageEntry | undefined,
  ): LicenseClaim | undefined {
    return entry?.licenseClaims.find((c) => c.source === "scancode");
  }

  /** Seed a committed memo file with the given purl→entry map, returning the path. */
  function seedMemo(
    entries: Array<
      [string, import("../src/enrich/scancode-cache").ScancodeMemoEntry]
    >,
  ): string {
    const path = newMemoPath();
    const memo = new Map<
      string,
      import("../src/enrich/scancode-cache").ScancodeMemoEntry
    >();
    for (const [purl, entry] of entries) {
      putMemoEntry(
        memo,
        purl,
        entry,
        () => new Date("2026-01-01T00:00:00.000Z"),
      );
    }
    writeFileSync(path, serializeScancodeMemo(memo));
    return path;
  }

  /** The finding annotateFindings computes for the first package. */
  function findingOf(packages: PackageEntry[]): {
    expression: string | null;
    confidence: string;
    source?: string;
    conflict?: unknown;
  } {
    const { model } = annotateFindings({ packages } as never, []);
    return (
      model.packages[0] as {
        finding?: {
          expression: string | null;
          confidence: string;
          source?: string;
          conflict?: unknown;
        };
      }
    ).finding as {
      expression: string | null;
      confidence: string;
      source?: string;
      conflict?: unknown;
    };
  }

  const FIXED_NOW = (): Date => new Date("2026-01-01T00:00:00.000Z");

  // --- Replay (both modes, unconditional, EVERY package) -------------------

  test("replay: a positive memo entry lands a ScanCode claim on a PRECISELY-declared package — the finding becomes the assessment (the load-bearing full-replay change)", async () => {
    const path = seedMemo([
      [
        "pkg:npm/left-pad@1.3.0",
        { license: "MIT", via: "scancode-toolkit@32.5.0/license-file" },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("left-pad", "1.3.0", [generatorClaim("MIT")])],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "check",
      memoPath: path,
      verbose: false,
    });

    expect(scancodeClaim(assessed.packages[0])).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
    const finding = findingOf(assessed.packages);
    expect(finding.source).toBe("scancode");
    expect(finding.confidence).toBe("exact");
  });

  test("replay: a positive memo entry DISAGREEING with a precise declared claim sets the conflict marker — detection reaches declared packages too", async () => {
    const path = seedMemo([
      [
        "pkg:npm/disputed@2.0.0",
        { license: "Apache-2.0", via: "scancode-toolkit@32.5.0/license-file" },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("disputed", "2.0.0", [generatorClaim("MIT")])],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "check",
      memoPath: path,
      verbose: false,
    });

    const finding = findingOf(assessed.packages);
    expect(finding.conflict).toBeDefined();
  });

  test("replay: a zero-claim package gains the memo's answer WITH attribution (copyrights sanitized/sorted/deduped)", async () => {
    const path = seedMemo([
      [
        "pkg:npm/quiet@1.0.0",
        {
          license: "Apache-2.0",
          via: "scancode-toolkit@32.5.0/license-file",
          copyrights: [
            "Copyright (c) 2020 Zeta Corp",
            "Copyright (c) 2019 Alpha Author",
          ],
        },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("quiet", "1.0.0")],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "check",
      memoPath: path,
      verbose: false,
    });

    expect(assessed.packages[0]?.attribution).toEqual({
      copyrightLines: [
        "Copyright (c) 2019 Alpha Author",
        "Copyright (c) 2020 Zeta Corp",
      ],
      noticeTexts: [],
      hasVerbatimText: false,
    });
  });

  test("replay: a no-result memo entry (license null) appends NOTHING and never conflicts with a positive registry answer (Pitfall 4)", async () => {
    const path = seedMemo([
      [
        "pkg:npm/no-evidence@1.0.0",
        { license: null, via: "scancode-toolkit@32.5.0/no-answer" },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [
        npmPackage("no-evidence", "1.0.0", [
          { raw: "MIT", kind: "expression", source: "registry" },
        ]),
      ],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "check",
      memoPath: path,
      verbose: false,
    });

    expect(scancodeClaim(assessed.packages[0])).toBeUndefined();
    const finding = findingOf(assessed.packages);
    expect(finding.expression).toBe("MIT");
    expect(finding.conflict).toBeUndefined();
  });

  test("replay: a MISSING memo file is a no-op — no claim appended, no file created (D-06)", async () => {
    const path = newMemoPath();
    rmSync(path, { force: true }); // ensure absent
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("left-pad", "1.3.0", [generatorClaim("MIT")])],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "check",
      memoPath: path,
      verbose: false,
    });

    expect(scancodeClaim(assessed.packages[0])).toBeUndefined();
    expect(assessed.packages[0]?.licenseClaims).toEqual([
      generatorClaim("MIT"),
    ]);
    expect(existsSync(path)).toBe(false);
  });

  // --- Scan (generate --intensive only) ------------------------------------

  test("scan (D-09 full set): a package with a PRECISE declared answer and no memo entry IS analyzed — the analysis set is not the residual", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("left-pad", "1.3.0", [generatorClaim("MIT")])],
    };

    await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: FIXED_NOW,
      intensive: { targetDirs: [repo] },
    });

    expect(invocations.length).toBe(1);
    expect(
      getMemoEntry(readScancodeMemo(path), "pkg:npm/left-pad@1.3.0"),
    ).toBeDefined();
  });

  test("scan: a memo hit — positive OR no-result — is skipped, never re-analyzed (memo presence is the skip test, D-11)", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    writeNpmSource(repo, "silent", "1.0.0");

    const path = seedMemo([
      [
        "pkg:npm/left-pad@1.3.0",
        { license: "MIT", via: "scancode-toolkit@32.5.0/license-file" },
      ],
      [
        "pkg:npm/silent@1.0.0",
        { license: null, via: "scancode-toolkit@32.5.0/no-answer" },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [
        npmPackage("left-pad", "1.3.0"),
        npmPackage("silent", "1.0.0"),
      ],
    };

    await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      intensive: { targetDirs: [repo] },
    });

    expect(invocations.length).toBe(0);
  });

  test("scan: a package whose sources are absent is reported but NEVER memoized (Pitfall 3 — a memo entry means the tree was analyzed)", async () => {
    const repo = newRepo();
    mkdirSync(join(repo, "node_modules"), { recursive: true });
    const path = newMemoPath();
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("absent", "1.0.0")],
    };

    await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      intensive: { targetDirs: [repo] },
    });

    expect(invocations.length).toBe(0);
    expect(
      getMemoEntry(readScancodeMemo(path), "pkg:npm/absent@1.0.0"),
    ).toBeUndefined();
  });

  test("scan + replay (mechanism proof, D-10): a fresh positive is memoized {license, via, copyrights, scannedAt} and its claim + attribution + PRECISE finding land in the SAME run", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("left-pad", "1.3.0")],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: FIXED_NOW,
      intensive: { targetDirs: [repo] },
    });

    expect(invocations.length).toBe(1);
    const entry = getMemoEntry(
      readScancodeMemo(path),
      "pkg:npm/left-pad@1.3.0",
    );
    expect(entry?.license).toBe("MIT");
    expect(entry?.via).toBe("scancode-toolkit@32.5.0/license-file");
    expect(entry?.copyrights?.length).toBeGreaterThan(0);
    expect(entry?.scannedAt).toBe("2026-01-01T00:00:00.000Z");

    expect(scancodeClaim(assessed.packages[0])).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
    expect(
      assessed.packages[0]?.attribution?.copyrightLines.length,
    ).toBeGreaterThan(0);
    const finding = findingOf(assessed.packages);
    expect(finding.expression).toBe("MIT");
    expect(finding.confidence).toBe("exact");
  });

  test("scan: a fresh no-answer is memoized as license:null on the no-answer lane and appends no claim", async () => {
    const repo = newRepo();
    const pkgDir = join(repo, "node_modules", "no-answer-pkg");
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name: "no-answer-pkg", version: "1.0.0" }),
    );

    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
    };
    const noiseOnly = {
      headers: fixture.headers,
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

    const path = newMemoPath();
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("no-answer-pkg", "1.0.0")],
    };
    try {
      const { model: assessed } = await assessPackages(model as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        now: FIXED_NOW,
        intensive: { targetDirs: [repo] },
      });
      expect(invocations.length).toBe(1);
      const entry = getMemoEntry(
        readScancodeMemo(path),
        "pkg:npm/no-answer-pkg@1.0.0",
      );
      expect(entry?.license).toBeNull();
      expect(entry?.via).toBe("scancode-toolkit@32.5.0/no-answer");
      expect(entry?.scannedAt).toBe("2026-01-01T00:00:00.000Z");
      expect(scancodeClaim(assessed.packages[0])).toBeUndefined();
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }
  });

  // --- Honest skip reporting ------------------------------------------------

  test("the stderr counts line reports the full-set partition in the locked house style", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0"); // scanned 1
    const path = seedMemo([
      [
        "pkg:npm/hit@1.0.0",
        { license: "MIT", via: "scancode-toolkit@32.5.0/license-file" },
      ],
    ]);
    const model: CanonicalDependenciesLike = {
      packages: [
        npmPackage("left-pad", "1.3.0"),
        npmPackage("hit", "1.0.0"), // memoized 1 (hit)
        npmPackage("absent", "1.0.0"), // no local sources 1
        {
          purl: "pkg:apk/musl@1.2.3",
          name: "musl",
          version: "1.2.3",
          occurrences: [{ target: "proj", isDevDependency: false }],
          licenseClaims: [],
          scope: "os",
        }, // unsupported 1
      ],
    };

    const stderr = await withCapturedStderr(async () => {
      await assessPackages(model as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        intensive: { targetDirs: [repo] },
      });
    });

    expect(stderr).toContain(
      "intensive: scanned 1, memoized 1 (hits), no local sources 1, unsupported 1",
    );
  });

  test("per-package skip lines name the purl ONLY under --verbose (run mechanics, never rendered)", async () => {
    const repo = newRepo();
    mkdirSync(join(repo, "node_modules"), { recursive: true });
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("absent", "1.0.0")],
    };

    const verbose = await withCapturedStderr(async () => {
      await assessPackages(model as never, {
        mode: "generate",
        memoPath: newMemoPath(),
        verbose: true,
        intensive: { targetDirs: [repo] },
      });
    });
    expect(verbose).toContain("intensive skip: pkg:npm/absent@1.0.0");

    const quiet = await withCapturedStderr(async () => {
      await assessPackages(model as never, {
        mode: "generate",
        memoPath: newMemoPath(),
        verbose: false,
        intensive: { targetDirs: [repo] },
      });
    });
    expect(quiet).not.toContain("intensive skip:");
  });

  // --- Determinism ----------------------------------------------------------

  test("warm run: a second intensive generate records ZERO invocations and leaves the committed memo byte-identical (a different clock never restamps)", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();
    const model: CanonicalDependenciesLike = {
      packages: [npmPackage("left-pad", "1.3.0")],
    };

    await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });
    const firstBytes = readFileSync(path, "utf8");
    invocations = [];

    const { model: second } = await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-02-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });

    expect(invocations.length).toBe(0);
    expect(readFileSync(path, "utf8")).toBe(firstBytes);
    expect(scancodeClaim(second.packages[0])).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
  });

  test("hermetic check (Pitfall 2): an intensive generate that finds a CONFLICT, then an offline check with the scanner stubbed-to-throw, yields a byte-identical annotated model INCLUDING the conflict marker", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: unknown[];
    };
    // Declared MIT vs an in-depth Apache-2.0 → a conflict.
    const apacheDoc = {
      headers: fixture.headers,
      files: [
        {
          path: "left-pad/LICENSE",
          detected_license_expression_spdx: "Apache-2.0",
          copyrights: [{ copyright: "Copyright (c) 2020 Example Author" }],
        },
      ],
    };
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeFakeExecToolWithDoc(apacheDoc),
    }));

    const declaredModel = (): CanonicalDependenciesLike => ({
      packages: [npmPackage("left-pad", "1.3.0", [generatorClaim("MIT")])],
    });

    let dumpGenerated: string;
    try {
      const generated = await assessPackages(declaredModel() as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        intensive: { targetDirs: [repo] },
      });
      const { model } = annotateFindings(
        { packages: generated.model.packages } as never,
        [],
      );
      dumpGenerated = toSortedDependenciesJson(model as never);
      expect(dumpGenerated).toContain("conflict");
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }

    invocations = [];
    // check NEVER receives intensive; the scanner is stubbed to throw so any
    // scan attempt would fail loudly. The replay alone reproduces the conflict.
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: (): Promise<{ stdout: string; stderr: string }> => {
        throw new Error("check must never invoke scancode");
      },
    }));
    try {
      const checked = await assessPackages(declaredModel() as never, {
        mode: "check",
        memoPath: path,
        verbose: false,
      });
      const { model } = annotateFindings(
        { packages: checked.model.packages } as never,
        [],
      );
      const dumpChecked = toSortedDependenciesJson(model as never);
      expect(dumpChecked).toBe(dumpGenerated);
      expect(invocations.length).toBe(0);
    } finally {
      mock.module("../src/collectors/exec", () => ({
        ...REAL_EXEC,
        execTool: fakeExecTool,
      }));
    }
  });

  test("dedicated files: a fresh positive lands ONLY in the ScanCode memo — a pre-seeded registry enrichment cache is byte-untouched (separate files by design, the 5a reshape)", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const memoPath = newMemoPath();

    // A separate registry enrichment cache carrying a NEGATIVE for the package:
    // under the memo-presence skip test the package is STILL analyzed (the
    // enrichment cache is not consulted here), and the enrichment cache stays
    // byte-identical because this stage never writes it.
    const enrichPath = join(memoDir as string, "licenses.cache.json");
    const enrichCache = new Map();
    enrichCache.set("pkg:npm/left-pad@1.3.0", {
      license: null,
      fetchedFrom: "npm",
      via: "unresolved",
      resolvable: false,
    });
    const enrichBytes = serializeCache(enrichCache);
    writeFileSync(enrichPath, enrichBytes);

    await assessPackages(
      { packages: [npmPackage("left-pad", "1.3.0")] } as never,
      {
        mode: "generate",
        memoPath,
        verbose: false,
        now: FIXED_NOW,
        intensive: { targetDirs: [repo] },
      },
    );

    expect(invocations.length).toBe(1);
    expect(
      getMemoEntry(readScancodeMemo(memoPath), "pkg:npm/left-pad@1.3.0")
        ?.license,
    ).toBe("MIT");
    expect(readFileSync(enrichPath, "utf8")).toBe(enrichBytes);
  });

  test("isolation (D-07 stage analog): generate WITHOUT intensive analyzes nothing — zero invocations, replay only", async () => {
    const repo = newRepo();
    writeNpmSource(repo, "left-pad", "1.3.0");
    const { model: assessed } = await assessPackages(
      { packages: [npmPackage("left-pad", "1.3.0")] } as never,
      { mode: "generate", memoPath: newMemoPath(), verbose: false },
    );
    expect(invocations.length).toBe(0);
    expect(scancodeClaim(assessed.packages[0])).toBeUndefined();
  });

  test("replay attribution: a memo answer never overwrites EXISTING attribution (absent-not-empty)", async () => {
    const path = seedMemo([
      [
        "pkg:npm/held@1.0.0",
        {
          license: "Apache-2.0",
          via: "scancode-toolkit@32.5.0/license-file",
          copyrights: ["Copyright (c) 2020 Zeta Corp"],
        },
      ],
    ]);
    const held: PackageEntry = {
      ...npmPackage("held", "1.0.0"),
      attribution: {
        copyrightLines: ["Copyright (c) 1999 Original Holder"],
        noticeTexts: [],
        hasVerbatimText: false,
      },
    };
    const { model: assessed } = await assessPackages(
      { packages: [held] } as never,
      {
        mode: "check",
        memoPath: path,
        verbose: false,
      },
    );
    expect(assessed.packages[0]?.attribution).toEqual({
      copyrightLines: ["Copyright (c) 1999 Original Holder"],
      noticeTexts: [],
      hasVerbatimText: false,
    });
  });

  test("replay attribution: a memo answer WITHOUT copyrights attaches no attribution", async () => {
    const path = seedMemo([
      [
        "pkg:npm/bare@1.0.0",
        { license: "Apache-2.0", via: "scancode-toolkit@32.5.0/license-file" },
      ],
    ]);
    const { model: assessed } = await assessPackages(
      { packages: [npmPackage("bare", "1.0.0")] } as never,
      { mode: "check", memoPath: path, verbose: false },
    );
    expect(assessed.packages[0]?.attribution).toBeUndefined();
  });
});

/** Structural alias so the test fixtures don't need the real model import at the top. */
type CanonicalDependenciesLike = {
  packages: import("../src/model/dependencies").PackageEntry[];
};

// ---------------------------------------------------------------------------
// Structural default-path isolation lock (10-05, D-07, T-10-15): the SAME
// bait shape as the 10-04 mechanism proof above (an unknown-license package
// WITH version-matched local sources — scannable if the lane were reachable)
// driven through the FULL generate pipeline (runGenerate, CLI/pipeline
// level) WITHOUT --intensive. Both cdxgen (the SBOM generator) and scancode
// (execTool) are recorder-stubbed so this stays subprocess-free; the
// assertion that matters is that ZERO of the recorded invocations are a
// scancode invocation, even though the bait package is present on disk and
// would resolve via sourceDirsFor if the lane were active. This is the
// structural proof that the default path never even LOOKS at ScanCode — not
// just that enrichUnknowns wasn't passed an intensive option (that unit-level
// guard already exists; this is the end-to-end version of it).
// ---------------------------------------------------------------------------

describe("default generate path isolation lock (10-05, D-07 structural proof)", () => {
  let repoDir: string;

  beforeAll(() => {
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: fakeExecTool,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
    mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
  });

  afterEach(() => {
    invocations = [];
    if (repoDir !== undefined) {
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  /** The bait SBOM: one zero-claim (unknown-license) npm package cdxgen "found". */
  const BAIT_SBOM = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      {
        purl: "pkg:npm/left-pad@1.3.0",
        name: "left-pad",
        version: "1.3.0",
      },
    ],
  };

  async function fakeCollectWithCdxgen(): Promise<cdxgenModule.CollectorSbomFile> {
    const tempDir = mkdtempSync(join(tmpdir(), "licenses-isolation-scan-"));
    const sbomPath = join(tempDir, "bom.json");
    writeFileSync(sbomPath, JSON.stringify(BAIT_SBOM));
    return { sbomPath, cacheKey: "fake-bait", tool: REAL_CDXGEN.CDXGEN_TOOL };
  }

  /** Yarn-1-style lockfile: cdxgen dispatch, one third-party entry (left-pad). */
  const BAIT_LOCKFILE = [
    "# yarn lockfile v1",
    "",
    "left-pad@^1.3.0:",
    '  version "1.3.0"',
    "",
  ].join("\n");

  /** repoRoot/proj with a real, version-matched node_modules/left-pad SCANNABLE BAIT. */
  function makeBaitTree(): { root: string } {
    const root = mkdtempSync(join(tmpdir(), "licenses-isolation-repo-"));
    const projDir = join(root, "proj");
    mkdirSync(projDir, { recursive: true });
    writeFileSync(join(projDir, "package.json"), '{ "name": "proj" }\n');
    writeFileSync(join(projDir, "yarn.lock"), BAIT_LOCKFILE);
    const pkgDir = join(projDir, "node_modules", "left-pad");
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name: "left-pad", version: "1.3.0" }),
    );
    writeFileSync(
      join(pkgDir, "LICENSE"),
      "MIT License\n\nCopyright (c) 2020 Example Author\n",
    );
    return { root };
  }

  test("default generate over a repo with a scannable unknown-license bait spawns ZERO scancode invocations", async () => {
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: fakeCollectWithCdxgen,
    }));

    const { root } = makeBaitTree();
    repoDir = root;
    const outputPath = join(root, "out.md");
    const cacheDir = mkdtempSync(join(tmpdir(), "licenses-isolation-cache-"));

    try {
      await runGenerate({
        repoRoot: root,
        outputPath,
        noticesPath: join(root, "notices.md"),
        enrichmentCachePath: join(cacheDir, "licenses.cache.json"),
        verbose: false,
      });

      // The bait resolved via sourceDirsFor WOULD be scanned if the lane were
      // reachable (a real, version-matched node_modules/left-pad with a
      // LICENSE file) — yet the default (--intensive absent) path recorded
      // zero invocations whose argv names the scancode binary.
      const scancodeInvocations = invocations.filter((argv) =>
        argv.some((arg) => arg.includes("scancode")),
      );
      expect(scancodeInvocations).toEqual([]);
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
      mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
    }
  });
});
