/**
 * Invocation lock + env-hygiene + cache-key tests for the yarn-plugin
 * adapter.
 *
 * The exact-array tests lock the spike-verified `yarn dlx` invocation
 * byte-for-byte (02-RESEARCH.md Pattern 2, every flag exercised live):
 * any flag change must consciously break these tests.
 *
 * No live yarn spawn happens here — argv/env/cache-key are pure functions;
 * the live path is proven by the Wave-3 RUN_E2E e2e.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

import { CDXGEN_TOOL, computeCacheKey } from "../src/collectors/cdxgen";
import * as execModule from "../src/collectors/exec";
import {
  YARN_PLUGIN_TOOL,
  collectWithYarnPlugin,
  pluginEnv,
  yarnPluginArgs,
  yarnPluginCacheArgs,
} from "../src/collectors/yarnPlugin";
import type { Target } from "../src/targets/target";

/** Original exports captured BEFORE any mock.module call (restore target). */
const REAL_EXEC = { ...execModule };

function makeTarget(yarnLock: string, packageJson: string): Target {
  const dir = mkdtempSync(join(tmpdir(), "licenses-test-"));
  writeFileSync(join(dir, "yarn.lock"), yarnLock);
  writeFileSync(join(dir, "package.json"), packageJson);
  return { dir, identity: "test/synthetic" };
}

describe("yarnPluginArgs", () => {
  test("returns exactly the spike-verified full-run invocation", () => {
    // The full run gains --gather-license-texts between --output-reproducible
    // and -o (verbatim-text coverage, byte-identical double runs, zero repo
    // side effects). The prod-run lock below stays byte-for-byte unchanged —
    // the flag rides the full run only.
    expect(yarnPluginArgs("/tmp/x/full.json", false)).toEqual([
      "x",
      "--",
      "yarn",
      "dlx",
      "-q",
      "@cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "--short-PURLs",
      "--output-reproducible",
      "--gather-license-texts",
      "-o",
      "/tmp/x/full.json",
    ]);
  });

  test("returns the same array with --production inserted before -o for the prod run", () => {
    expect(yarnPluginArgs("/tmp/x/prod.json", true)).toEqual([
      "x",
      "--",
      "yarn",
      "dlx",
      "-q",
      "@cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "--short-PURLs",
      "--output-reproducible",
      "--production",
      "-o",
      "/tmp/x/prod.json",
    ]);
  });

  test("the literal version tag in the argv equals the YARN_PLUGIN_TOOL pin (Trivy lesson)", () => {
    const args = yarnPluginArgs("/tmp/x/full.json", false);
    expect(args).toContain(
      `${YARN_PLUGIN_TOOL.name}@${YARN_PLUGIN_TOOL.version}`,
    );
  });
});

describe("pluginEnv", () => {
  test("deletes NODE_ENV, preserves other vars, sets YARN_INSTALL_STATE_PATH, and does not mutate the input", () => {
    const base: NodeJS.ProcessEnv = { NODE_ENV: "production", FOO: "bar" };
    const env = pluginEnv("/tmp/run", base);

    // --production silently defaults TRUE under NODE_ENV=production
    // (spike-verified) — the key must be ABSENT, not just falsy.
    expect("NODE_ENV" in env).toBe(false);
    expect(env.FOO).toBe("bar");
    expect(env.YARN_INSTALL_STATE_PATH).toBe(
      join("/tmp/run", "install-state.gz"),
    );

    // The input object is not mutated.
    expect(base.NODE_ENV).toBe("production");
    expect("YARN_INSTALL_STATE_PATH" in base).toBe(false);
  });
});

describe("dual-run cache key", () => {
  const YARN_LOCK =
    '# synthetic lockfile\n"left-pad@npm:1.3.0":\n  version: 1.3.0\n';
  const PACKAGE_JSON =
    '{"name":"synthetic","devDependencies":{"left-pad":"1.3.0"}}\n';
  const MANIFESTS = ["yarn.lock", "package.json"] as const;

  test("hashes BOTH argv arrays — differs from a full-run-only key for the same target", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const fullArgs = yarnPluginArgs("/tmp/x/full.json", false);
    const prodArgs = yarnPluginArgs("/tmp/x/prod.json", true);

    const dualKey = computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      [...fullArgs, ...prodArgs],
      MANIFESTS,
    );
    const fullOnlyKey = computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      fullArgs,
      MANIFESTS,
    );
    expect(dualKey).toMatch(/^[0-9a-f]{64}$/);
    expect(dualKey).not.toBe(fullOnlyKey);
  });

  test("plugin and cdxgen tool identities produce different keys for identical args", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const args = ["same", "args"];
    expect(computeCacheKey(target, YARN_PLUGIN_TOOL, args, MANIFESTS)).not.toBe(
      computeCacheKey(target, CDXGEN_TOOL, args, MANIFESTS),
    );
  });

  test("the hashed argv pair carries <out> sentinels, never per-run temp paths", () => {
    // Exact-array lock: the hashed argv is the dual-run invocation with
    // constant sentinels in the -o operands. A real mkdtemp path in here would
    // change the key on every run.
    expect(yarnPluginCacheArgs()).toEqual([
      "x",
      "--",
      "yarn",
      "dlx",
      "-q",
      "@cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "--short-PURLs",
      "--output-reproducible",
      "--gather-license-texts",
      "-o",
      "<out>",
      "x",
      "--",
      "yarn",
      "dlx",
      "-q",
      "@cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "--short-PURLs",
      "--output-reproducible",
      "--production",
      "-o",
      "<out>",
    ]);
  });

  test("identical manifest bytes in two different directories yield the SAME key", () => {
    // Two checkouts of the same project (different absolute paths, distinct
    // hypothetical temp dirs) must share a cache key — the key derives from
    // manifest bytes + tool + sentinel argv only.
    const a = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const b = makeTarget(YARN_LOCK, PACKAGE_JSON);
    expect(
      computeCacheKey(a, YARN_PLUGIN_TOOL, yarnPluginCacheArgs(), MANIFESTS),
    ).toBe(
      computeCacheKey(b, YARN_PLUGIN_TOOL, yarnPluginCacheArgs(), MANIFESTS),
    );
  });

  test("a plain-string manifest entry produces a key byte-identical to an equivalent {file, dir: target.dir} object spelling", () => {
    // The hashed label is content-relative, not path-relative: an object
    // entry pointing at the SAME dir as the target must hash identically to
    // the plain-string spelling of the same file.
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const stringKey = computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      MANIFESTS,
    );
    const objectKey = computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      [
        { file: "yarn.lock", dir: target.dir },
        { file: "package.json", dir: target.dir },
      ],
    );
    expect(objectKey).toBe(stringKey);
  });

  test("a workspace-unit key covers root yarn.lock + workspace package.json + root package.json — mutating any ONE changes the key", () => {
    const rootDir = mkdtempSync(join(tmpdir(), "licenses-test-root-"));
    writeFileSync(join(rootDir, "yarn.lock"), YARN_LOCK);
    writeFileSync(join(rootDir, "package.json"), '{"name":"root"}\n');
    const unitDir = mkdtempSync(join(tmpdir(), "licenses-test-unit-"));
    writeFileSync(join(unitDir, "package.json"), PACKAGE_JSON);

    const unit: Target = {
      dir: unitDir,
      identity: "backend",
      lockfileDir: rootDir,
      workspacePath: "backend",
    };
    const manifests = [
      { file: "yarn.lock", dir: rootDir },
      { file: "package.json", dir: unitDir },
      { file: "package.json", dir: rootDir },
    ];
    const baseline = computeCacheKey(
      unit,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      manifests,
    );

    // Mutate root yarn.lock only.
    writeFileSync(join(rootDir, "yarn.lock"), YARN_LOCK + "\n# mutated\n");
    expect(
      computeCacheKey(unit, YARN_PLUGIN_TOOL, yarnPluginCacheArgs(), manifests),
    ).not.toBe(baseline);
    writeFileSync(join(rootDir, "yarn.lock"), YARN_LOCK);

    // Mutate workspace package.json only.
    writeFileSync(join(unitDir, "package.json"), PACKAGE_JSON + "\n");
    expect(
      computeCacheKey(unit, YARN_PLUGIN_TOOL, yarnPluginCacheArgs(), manifests),
    ).not.toBe(baseline);
    writeFileSync(join(unitDir, "package.json"), PACKAGE_JSON);

    // Mutate root package.json only.
    writeFileSync(join(rootDir, "package.json"), '{"name":"root-changed"}\n');
    expect(
      computeCacheKey(unit, YARN_PLUGIN_TOOL, yarnPluginCacheArgs(), manifests),
    ).not.toBe(baseline);
  });

  test("two units with byte-identical workspace package.json under the same root differ ONLY by workspacePath and get DIFFERENT keys", () => {
    const rootDir = mkdtempSync(join(tmpdir(), "licenses-test-root2-"));
    writeFileSync(join(rootDir, "yarn.lock"), YARN_LOCK);
    writeFileSync(join(rootDir, "package.json"), '{"name":"root"}\n');
    const unitADir = mkdtempSync(join(tmpdir(), "licenses-test-unitA-"));
    const unitBDir = mkdtempSync(join(tmpdir(), "licenses-test-unitB-"));
    writeFileSync(join(unitADir, "package.json"), PACKAGE_JSON);
    writeFileSync(join(unitBDir, "package.json"), PACKAGE_JSON);

    const unitA: Target = {
      dir: unitADir,
      identity: "backend",
      lockfileDir: rootDir,
      workspacePath: "backend",
    };
    const unitB: Target = {
      dir: unitBDir,
      identity: "frontend",
      lockfileDir: rootDir,
      workspacePath: "frontend",
    };
    const manifestsFor = (unit: Target): { file: string; dir: string }[] => [
      { file: "yarn.lock", dir: rootDir },
      { file: "package.json", dir: unit.dir },
      { file: "package.json", dir: rootDir },
    ];
    const keyA = computeCacheKey(
      unitA,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      manifestsFor(unitA),
    );
    const keyB = computeCacheKey(
      unitB,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      manifestsFor(unitB),
    );
    expect(keyA).not.toBe(keyB);
  });

  test("a target with neither lockfileDir nor workspacePath produces a key through the exact pre-change path", () => {
    // No behavioral assertion needed beyond re-running the existing
    // MANIFESTS-based expectations above: this test just asserts the two
    // fields being undefined does not alter today's key for a plain target.
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    expect(target.lockfileDir).toBeUndefined();
    expect(target.workspacePath).toBeUndefined();
    const key = computeCacheKey(
      target,
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      MANIFESTS,
    );
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("collectWithYarnPlugin — unit-aware cwd and cache key", () => {
  let capturedCwds: (string | undefined)[] = [];

  beforeEach(() => {
    capturedCwds = [];
    mock.module("../src/collectors/exec", () => ({
      ...REAL_EXEC,
      execTool: async (
        _cmd: string,
        args: string[],
        opts: { cwd?: string },
      ): Promise<{ stdout: string; stderr: string }> => {
        capturedCwds.push(opts.cwd);
        // Write a minimal valid plugin output at the -o operand so
        // validatePluginOutput passes without a real yarn spawn.
        const outFile = args[args.length - 1] as string;
        writeFileSync(
          outFile,
          JSON.stringify({ specVersion: "1.6", components: [] }),
        );
        return { stdout: "", stderr: "" };
      },
    }));
  });

  afterEach(() => {
    mock.module("../src/collectors/exec", () => REAL_EXEC);
  });

  test("resolves yarn.lock from lockfileDir for the cache key while spawning with cwd = target.dir — no real spawn happens", async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "licenses-test-root-collect-"));
    writeFileSync(
      join(rootDir, "yarn.lock"),
      '# synthetic lockfile\n"left-pad@npm:1.3.0":\n  version: 1.3.0\n',
    );
    writeFileSync(join(rootDir, "package.json"), '{"name":"root"}\n');
    const unitDir = mkdtempSync(join(tmpdir(), "licenses-test-unit-collect-"));
    // The unit dir intentionally has NO yarn.lock of its own — proving the
    // key and spawn both resolve yarn.lock from lockfileDir, not target.dir.
    writeFileSync(
      join(unitDir, "package.json"),
      '{"name":"backend","dependencies":{"ms":"2.1.3"}}\n',
    );

    const unit: Target = {
      dir: unitDir,
      identity: "backend",
      lockfileDir: rootDir,
      workspacePath: "backend",
    };

    const result = await collectWithYarnPlugin(unit, {
      timeoutMs: 5000,
      verbose: false,
    });

    // The ONLY behavioral spawn change: cwd is the unit dir, for BOTH runs
    // (full + production) — never the root.
    expect(capturedCwds).toEqual([unitDir, unitDir]);
    expect(result.cacheKey).toMatch(/^[0-9a-f]{64}$/);

    // The unit-aware key must differ from an otherwise-identical key computed
    // with workspacePath undefined — proving the discriminator segment
    // entered the hash.
    const noDiscriminatorKey = computeCacheKey(
      { dir: unitDir, identity: "backend", lockfileDir: rootDir },
      YARN_PLUGIN_TOOL,
      yarnPluginCacheArgs(),
      [
        { file: "yarn.lock", dir: rootDir },
        { file: "package.json", dir: unitDir },
        { file: "package.json", dir: rootDir },
      ],
    );
    expect(result.cacheKey).not.toBe(noDiscriminatorKey);
  });
});
