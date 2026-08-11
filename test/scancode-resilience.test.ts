/**
 * The intensive scan's per-package failure containment, memo persistence, and merge-on-write
 * contract - the behavior that keeps ONE package's timeout from aborting an hours-long backfill and
 * discarding every result it already computed. Subprocess-free: the same execTool recorder harness
 * scancode.test.ts uses (mock.module over ../src/collectors/exec), kept in its own file because
 * these tests each construct their own execTool stub rather than sharing the fixture-replay one.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";

import * as execModule from "../src/collectors/exec";
import { assessPackages } from "../src/enrich/assess";
import {
  getMemoEntry,
  putMemoEntry,
  readScancodeMemo,
  serializeScancodeMemo,
  type ScancodeMemoEntry,
} from "../src/enrich/scancode";
import { type LicenseClaim, type PackageEntry } from "../src/model/dependencies";

/** Original exec export captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

/** Every recorded execTool invocation: [cmd, ...args]. */
let invocations: string[][] = [];

const FIXTURE_PATH = join(__dirname, "fixtures", "scancode-license-file-trimmed.json");

function npmPackage(name: string, version: string, claims: LicenseClaim[] = []): PackageEntry {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    occurrences: [{ target: "proj", isDevDependency: false }],
    licenseClaims: claims,
    scope: "app",
  };
}

function scancodeClaim(entry: PackageEntry | undefined): LicenseClaim | undefined {
  return entry?.licenseClaims.find((c) => c.source === "scancode");
}

/** A minimal node_modules/<name> tree with a version-matched package.json + LICENSE. */
function writeNpmSource(targetDir: string, name: string, version: string): void {
  const pkgDir = join(targetDir, "node_modules", name);

  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify({ name, version }));
  writeFileSync(join(pkgDir, "LICENSE"), "MIT License\n\nCopyright (c) 2020 Example Author\n");
}

/**
 * Capture process.stderr.write for the duration of a callback; always restores in finally so a
 * failing assertion can never poison later tests.
 */
async function withCapturedStderr(fn: () => Promise<unknown>): Promise<string> {
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

describe("per-package scan failure containment (assess.ts analyzeOne)", () => {
  let repoDir: string | undefined;
  let memoDir: string | undefined;

  afterEach(() => {
    invocations = [];
    if (repoDir !== undefined) {
      rmSync(repoDir, { recursive: true, force: true });
    }

    if (memoDir !== undefined) {
      rmSync(memoDir, { recursive: true, force: true });
    }

    repoDir = undefined;
    memoDir = undefined;
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  function newRepo(): string {
    repoDir = mkdtempSync(join(tmpdir(), "resilience-repo-"));
    return repoDir;
  }

  function newMemoPath(): string {
    memoDir = mkdtempSync(join(tmpdir(), "resilience-memo-"));
    return join(memoDir, "scancode.cache.json");
  }

  /**
   * A fake execTool that TIMES OUT (rejects, writes no output file) for any source dir whose path
   * contains `failMarker`, and otherwise replays the real fixture - the same shape execTool's real
   * timeout rejection takes (killProcessTree fires before scancode can write, so the exists-check in
   * runScancode never finds an output file; see exec.ts's setTimeout reject and invocation.ts's
   * `!existsSync(outFile)` rethrow).
   */
  function makeSelectiveTimeoutExecTool(
    failMarker: string,
  ): (cmd: string, args: string[]) => Promise<{ stdout: string; stderr: string }> {
    return (cmd: string, args: string[]) => {
      invocations.push([cmd, ...args]);
      const sourceDir = args[args.length - 1] as string;

      if (sourceDir.includes(failMarker)) {
        return Promise.reject(new Error(`${cmd} ${args[0]} timed out after 600000 ms`));
      }

      const jsonPpIndex = args.indexOf("--json-pp");

      if (jsonPpIndex !== -1) {
        writeFileSync(args[jsonPpIndex + 1] as string, readFileSync(FIXTURE_PATH, "utf8"));
      }

      return Promise.resolve({ stdout: "", stderr: "" });
    };
  }

  test("a timed-out package is contained: the run continues, the purl is named on stderr UNCONDITIONALLY (not gated on --verbose), the failed counter increments, and the package is NOT memoized", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "slow-pkg", "1.0.0");
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeSelectiveTimeoutExecTool("slow-pkg"),
    }));

    const model = {
      packages: [npmPackage("slow-pkg", "1.0.0"), npmPackage("left-pad", "1.3.0")],
    };

    const stderr = await withCapturedStderr(async () => {
      await assessPackages(model as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        now: () => new Date("2026-01-01T00:00:00.000Z"),
        intensive: { targetDirs: [repo] },
      });
    });

    // Both packages were attempted - the timeout on the first never aborted the loop.
    expect(invocations.length).toBe(2);

    // The house-style loud line, printed even though --verbose is false (unlike the routine
    // no-local-sources skip line, which IS verbose-gated).
    expect(stderr).toContain("intensive failed: pkg:npm/slow-pkg@1.0.0");
    expect(stderr).toContain("timed out after 600000 ms");
    expect(stderr).toContain(
      "intensive: scanned 1, memoized 0 (hits), no local sources 0, unsupported 0, failed 1",
    );

    // NOT memoized - retried next run, mirroring the absent-local-sources posture.
    expect(getMemoEntry(readScancodeMemo(path), "pkg:npm/slow-pkg@1.0.0")).toBeUndefined();
  });

  test("a completed sibling scanned in the SAME run as a timed-out package IS memoized and gains its ScanCode claim", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "slow-pkg", "1.0.0");
    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: makeSelectiveTimeoutExecTool("slow-pkg"),
    }));

    const model = {
      packages: [npmPackage("slow-pkg", "1.0.0"), npmPackage("left-pad", "1.3.0")],
    };

    const { model: assessed } = await assessPackages(model as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });

    const entry = getMemoEntry(readScancodeMemo(path), "pkg:npm/left-pad@1.3.0");

    expect(entry?.license).toBe("MIT");
    expect(scancodeClaim(assessed.packages[1])).toEqual({
      raw: "MIT",
      kind: "expression",
      source: "scancode",
    });
  });

  test("a version-assert mismatch (a broken/substituted local tool install) still ABORTS the whole run - it is not contained like a timeout", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "first-victim", "1.0.0");
    writeNpmSource(repo, "never-reached", "1.0.0");
    const path = newMemoPath();

    const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as {
      headers: { tool_version: string }[];
      files: unknown[];
    };
    const wrongVersion = {
      ...fixture,
      headers: [{ ...fixture.headers[0], tool_version: "31.0.0" }],
    };

    const wrongVersionExecTool = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      const jsonPpIndex = args.indexOf("--json-pp");

      if (jsonPpIndex !== -1) {
        writeFileSync(args[jsonPpIndex + 1] as string, JSON.stringify(wrongVersion));
      }

      return Promise.resolve({ stdout: "", stderr: "" });
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: wrongVersionExecTool,
    }));

    const model = {
      packages: [npmPackage("first-victim", "1.0.0"), npmPackage("never-reached", "1.0.0")],
    };

    await expect(
      assessPackages(model as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        intensive: { targetDirs: [repo] },
      }),
    ).rejects.toThrow(/31\.0\.0.*32\.5\.0|invocation:/s);

    // The abort happened on the FIRST package - the loop never reached the second.
    expect(invocations.length).toBe(1);
    // Neither package was memoized - a fatal error is never a per-package outcome.
    const memo = readScancodeMemo(path);

    expect(getMemoEntry(memo, "pkg:npm/first-victim@1.0.0")).toBeUndefined();
    expect(getMemoEntry(memo, "pkg:npm/never-reached@1.0.0")).toBeUndefined();
  });
});

describe("memo persistence across a fatal abort (assessPackages's finally-block write)", () => {
  let repoDir: string | undefined;
  let memoDir: string | undefined;

  afterEach(() => {
    invocations = [];
    if (repoDir !== undefined) {
      rmSync(repoDir, { recursive: true, force: true });
    }

    if (memoDir !== undefined) {
      rmSync(memoDir, { recursive: true, force: true });
    }

    repoDir = undefined;
    memoDir = undefined;
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  function newRepo(): string {
    repoDir = mkdtempSync(join(tmpdir(), "resilience-abort-repo-"));
    return repoDir;
  }

  function newMemoPath(): string {
    memoDir = mkdtempSync(join(tmpdir(), "resilience-abort-memo-"));
    return join(memoDir, "scancode.cache.json");
  }

  test("a completed scan survives a LATER fatal abort in the same run - the committed memo carries the completed entry even though assessPackages rejected", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "completed-first", "1.0.0");
    writeNpmSource(repo, "fatal-second", "1.0.0");
    const path = newMemoPath();

    const goodFixture = readFileSync(FIXTURE_PATH, "utf8");
    const fixtureParsed = JSON.parse(goodFixture) as { headers: { tool_version: string }[] };
    const wrongVersion = {
      ...fixtureParsed,
      headers: [{ ...fixtureParsed.headers[0], tool_version: "31.0.0" }],
      files: [],
    };

    // First invocation (completed-first) succeeds with the real fixture; the SECOND
    // (fatal-second) returns a wrong-tool-version output, aborting the run.
    let call = 0;
    const firstOkThenFatalExecTool = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      const jsonPpIndex = args.indexOf("--json-pp");
      const doc = call++ === 0 ? goodFixture : JSON.stringify(wrongVersion);

      if (jsonPpIndex !== -1) {
        writeFileSync(args[jsonPpIndex + 1] as string, doc);
      }

      return Promise.resolve({ stdout: "", stderr: "" });
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: firstOkThenFatalExecTool,
    }));

    const model = {
      packages: [npmPackage("completed-first", "1.0.0"), npmPackage("fatal-second", "1.0.0")],
    };

    await expect(
      assessPackages(model as never, {
        mode: "generate",
        memoPath: path,
        verbose: false,
        now: () => new Date("2026-01-01T00:00:00.000Z"),
        intensive: { targetDirs: [repo] },
      }),
    ).rejects.toThrow();

    // The finally-block write persisted the completed entry despite the abort.
    const memo = readScancodeMemo(path);

    expect(getMemoEntry(memo, "pkg:npm/completed-first@1.0.0")?.license).toBe("MIT");
    expect(getMemoEntry(memo, "pkg:npm/fatal-second@1.0.0")).toBeUndefined();
  });
});

describe("merge-on-write: the committed memo write NEVER overrides pre-existing data", () => {
  let repoDir: string | undefined;
  let memoDir: string | undefined;

  afterEach(() => {
    invocations = [];
    if (repoDir !== undefined) {
      rmSync(repoDir, { recursive: true, force: true });
    }

    if (memoDir !== undefined) {
      rmSync(memoDir, { recursive: true, force: true });
    }

    repoDir = undefined;
    memoDir = undefined;
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  function newRepo(): string {
    repoDir = mkdtempSync(join(tmpdir(), "resilience-merge-repo-"));
    return repoDir;
  }

  function newMemoPath(): string {
    memoDir = mkdtempSync(join(tmpdir(), "resilience-merge-memo-"));
    return join(memoDir, "scancode.cache.json");
  }

  function seedEntry(path: string, purl: string, entry: ScancodeMemoEntry): void {
    const memo = new Map<string, ScancodeMemoEntry>();

    putMemoEntry(memo, purl, entry, () => new Date("2020-01-01T00:00:00.000Z"));
    writeFileSync(path, serializeScancodeMemo(memo));
  }

  test("seeded entry A + this run's new entry B + a concurrent writer's entry C, landed BEHIND this run's back mid-scan, all survive the final write", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    seedEntry(path, "pkg:npm/existing-a@1.0.0", {
      license: "MIT",
      via: "scancode-toolkit@32.5.0/license-file",
    });

    const goodFixture = readFileSync(FIXTURE_PATH, "utf8");
    // Simulates ANOTHER writer landing entry C on disk while this run is still scanning -
    // reading the current committed file (which already carries A) and appending C, exactly
    // as a second process would. This runs synchronously inside the exec stub, BEFORE
    // assessPackages's own finally-block re-read, proving the re-read happens late enough to
    // observe it.
    const concurrentWriteExecTool = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      const concurrent = readScancodeMemo(path);

      putMemoEntry(
        concurrent,
        "pkg:npm/concurrent-c@9.0.0",
        { license: "Apache-2.0", via: "scancode-toolkit@32.5.0/license-file" },
        () => new Date("2025-01-01T00:00:00.000Z"),
      );
      writeFileSync(path, serializeScancodeMemo(concurrent));

      const jsonPpIndex = args.indexOf("--json-pp");

      if (jsonPpIndex !== -1) {
        writeFileSync(args[jsonPpIndex + 1] as string, goodFixture);
      }

      return Promise.resolve({ stdout: "", stderr: "" });
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: concurrentWriteExecTool,
    }));

    await assessPackages({ packages: [npmPackage("left-pad", "1.3.0")] } as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });

    const final = readScancodeMemo(path);

    expect(getMemoEntry(final, "pkg:npm/existing-a@1.0.0")?.license).toBe("MIT"); // A survives
    expect(getMemoEntry(final, "pkg:npm/left-pad@1.3.0")?.license).toBe("MIT"); // B, this run's own scan
    expect(getMemoEntry(final, "pkg:npm/concurrent-c@9.0.0")?.license).toBe("Apache-2.0"); // C survives
  });

  test("collision precedence: when the SAME purl is scanned by THIS run and also present on disk (a stale/racing write) with a DIFFERENT value, this run's in-memory entry wins", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    const goodFixture = readFileSync(FIXTURE_PATH, "utf8"); // elects MIT

    const collidingExecTool = (
      cmd: string,
      args: string[],
    ): Promise<{ stdout: string; stderr: string }> => {
      invocations.push([cmd, ...args]);
      // A racing writer lands a DIFFERENT value for the SAME purl this run is scanning right now.
      seedEntry(path, "pkg:npm/left-pad@1.3.0", {
        license: "GPL-3.0-only",
        via: "scancode-toolkit@32.5.0/license-file",
      });

      const jsonPpIndex = args.indexOf("--json-pp");

      if (jsonPpIndex !== -1) {
        writeFileSync(args[jsonPpIndex + 1] as string, goodFixture);
      }

      return Promise.resolve({ stdout: "", stderr: "" });
    };

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: collidingExecTool,
    }));

    await assessPackages({ packages: [npmPackage("left-pad", "1.3.0")] } as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });

    // This run actually analyzed the tree and elected MIT - that answer wins over the
    // racing writer's stale GPL-3.0-only value.
    expect(getMemoEntry(readScancodeMemo(path), "pkg:npm/left-pad@1.3.0")?.license).toBe("MIT");
  });

  test("a clean, uncontested run still leaves the committed memo byte-identical to a plain read-merge-write with no concurrent writer (the merge is a no-op when nothing else touched the file)", async () => {
    const repo = newRepo();

    writeNpmSource(repo, "left-pad", "1.3.0");
    const path = newMemoPath();

    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: (cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> => {
        invocations.push([cmd, ...args]);
        const jsonPpIndex = args.indexOf("--json-pp");

        if (jsonPpIndex !== -1) {
          writeFileSync(args[jsonPpIndex + 1] as string, readFileSync(FIXTURE_PATH, "utf8"));
        }

        return Promise.resolve({ stdout: "", stderr: "" });
      },
    }));

    await assessPackages({ packages: [npmPackage("left-pad", "1.3.0")] } as never, {
      mode: "generate",
      memoPath: path,
      verbose: false,
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      intensive: { targetDirs: [repo] },
    });

    const bytes = readFileSync(path, "utf8");
    const reparsed = readScancodeMemo(path);

    expect(serializeScancodeMemo(reparsed)).toBe(bytes);
  });
});
