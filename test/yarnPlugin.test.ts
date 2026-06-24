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
import { describe, expect, test } from "bun:test";

import { CDXGEN_TOOL, computeCacheKey } from "../src/collectors/cdxgen";
import {
  YARN_PLUGIN_TOOL,
  pluginEnv,
  yarnPluginArgs,
  yarnPluginCacheArgs,
} from "../src/collectors/yarnPlugin";
import type { Target } from "../src/targets/target";

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
});
