/**
 * Invocation lock + cache-key determinism tests for the cdxgen adapter.
 *
 * The exact-array tests lock the empirically verified cdxgen 12.5.1
 * invocations byte-for-byte (01-RESEARCH.md verified live twice;
 * 02-RESEARCH.md verified `-t python` against the real poetry target):
 * any flag change must consciously break these tests and invalidate goldens.
 *
 * No live cdxgen spawn happens here — that is the gated e2e's job.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  CDXGEN_TOOL,
  cdxgenArgs,
  cdxgenCacheArgs,
  computeCacheKey,
} from "../src/collectors/cdxgen";
import type { Target } from "../src/targets/target";

/** Writes the given files into a fresh temp dir and returns it as a Target. */
function makeTargetWithFiles(files: Record<string, string>): Target {
  const dir = mkdtempSync(join(tmpdir(), "licenses-test-"));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return { dir, identity: "test/synthetic" };
}

function makeTarget(yarnLock: string, packageJson: string): Target {
  return makeTargetWithFiles({
    "yarn.lock": yarnLock,
    "package.json": packageJson,
  });
}

const JS_MANIFESTS = ["yarn.lock", "package.json"] as const;
const POETRY_MANIFESTS = ["poetry.lock", "pyproject.toml"] as const;

describe("cdxgenArgs", () => {
  test("returns exactly the verified cdxgen 12.5.1 js invocation", () => {
    expect(cdxgenArgs("/abs/target", "/tmp/x/bom.json", "js")).toEqual([
      "x",
      "@cyclonedx/cdxgen@12.5.1",
      "-t",
      "js",
      "--no-install-deps",
      "--no-recurse",
      "--spec-version",
      "1.6",
      "-o",
      "/tmp/x/bom.json",
      "/abs/target",
    ]);
  });

  test("returns exactly the verified cdxgen 12.5.1 python invocation", () => {
    expect(cdxgenArgs("/abs/target", "/tmp/x/bom.json", "python")).toEqual([
      "x",
      "@cyclonedx/cdxgen@12.5.1",
      "-t",
      "python",
      "--no-install-deps",
      "--no-recurse",
      "--spec-version",
      "1.6",
      "-o",
      "/tmp/x/bom.json",
      "/abs/target",
    ]);
  });
});

describe("cdxgenCacheArgs", () => {
  test("replaces the volatile target and output operands with constant sentinels", () => {
    // Exact-array lock: the hashed argv is the verified invocation shape with
    // <target>/<out> sentinels — a real mkdtemp output path or an absolute
    // target dir in here would make the key per-run and per-checkout.
    expect(cdxgenCacheArgs("js")).toEqual([
      "x",
      "@cyclonedx/cdxgen@12.5.1",
      "-t",
      "js",
      "--no-install-deps",
      "--no-recurse",
      "--spec-version",
      "1.6",
      "-o",
      "<out>",
      "<target>",
    ]);
  });

  test("identical manifest bytes in two different directories yield the SAME key", () => {
    const YARN_LOCK = "# lock\n";
    const PACKAGE_JSON = '{"name":"x"}\n';
    const a = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const b = makeTarget(YARN_LOCK, PACKAGE_JSON);
    expect(
      computeCacheKey(a, CDXGEN_TOOL, cdxgenCacheArgs("js"), JS_MANIFESTS),
    ).toBe(
      computeCacheKey(b, CDXGEN_TOOL, cdxgenCacheArgs("js"), JS_MANIFESTS),
    );
    // The ecosystem still differentiates keys (it is a REAL input).
    expect(
      computeCacheKey(a, CDXGEN_TOOL, cdxgenCacheArgs("js"), JS_MANIFESTS),
    ).not.toBe(
      computeCacheKey(a, CDXGEN_TOOL, cdxgenCacheArgs("python"), JS_MANIFESTS),
    );
  });
});

describe("computeCacheKey", () => {
  const YARN_LOCK =
    '# synthetic lockfile\n"left-pad@npm:1.3.0":\n  version: 1.3.0\n';
  const PACKAGE_JSON =
    '{"name":"synthetic","devDependencies":{"left-pad":"1.3.0"}}\n';
  const ARGS = cdxgenArgs("/abs/target", "/tmp/x/bom.json", "js");

  test("returns a 64-char lowercase hex string", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const key = computeCacheKey(target, CDXGEN_TOOL, ARGS, JS_MANIFESTS);
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  test("is deterministic for identical inputs", () => {
    const a = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const b = makeTarget(YARN_LOCK, PACKAGE_JSON);
    expect(computeCacheKey(a, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).toBe(
      computeCacheKey(b, CDXGEN_TOOL, ARGS, JS_MANIFESTS),
    );
    expect(computeCacheKey(a, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).toBe(
      computeCacheKey(a, CDXGEN_TOOL, ARGS, JS_MANIFESTS),
    );
  });

  test("changes when one byte of yarn.lock changes", () => {
    const a = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const b = makeTarget(YARN_LOCK.replace("1.3.0", "1.3.1"), PACKAGE_JSON);
    expect(computeCacheKey(a, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(b, CDXGEN_TOOL, ARGS, JS_MANIFESTS),
    );
  });

  test("changes when the args array changes", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const otherArgs = cdxgenArgs("/abs/target", "/tmp/y/bom.json", "js");
    expect(computeCacheKey(target, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(target, CDXGEN_TOOL, otherArgs, JS_MANIFESTS),
    );
  });

  test("changes when the tool version changes", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const otherTool = { name: CDXGEN_TOOL.name, version: "12.5.2" };
    expect(computeCacheKey(target, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(target, otherTool, ARGS, JS_MANIFESTS),
    );
  });

  test("moving bytes across the yarn.lock/package.json boundary changes the key", () => {
    // Same concatenated byte stream, different field split — must differ.
    const a = makeTarget("AB", "C");
    const b = makeTarget("A", "BC");
    expect(computeCacheKey(a, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(b, CDXGEN_TOOL, ARGS, JS_MANIFESTS),
    );
  });

  test("moving characters across the name/version boundary changes the key", () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    const toolA = { name: "cdxgenX", version: "1.0" };
    const toolB = { name: "cdxgen", version: "X1.0" };
    expect(computeCacheKey(target, toolA, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(target, toolB, ARGS, JS_MANIFESTS),
    );
  });

  test('["a b"] and ["a", "b"] produce different keys', () => {
    const target = makeTarget(YARN_LOCK, PACKAGE_JSON);
    expect(
      computeCacheKey(target, CDXGEN_TOOL, ["a b"], JS_MANIFESTS),
    ).not.toBe(computeCacheKey(target, CDXGEN_TOOL, ["a", "b"], JS_MANIFESTS));
  });

  test("a poetry manifest list reads poetry.lock and pyproject.toml", () => {
    const POETRY_LOCK = '[[package]]\nname = "attrs"\nversion = "25.1.0"\n';
    const PYPROJECT = '[tool.poetry]\nname = "synthetic"\n';
    const a = makeTargetWithFiles({
      "poetry.lock": POETRY_LOCK,
      "pyproject.toml": PYPROJECT,
    });
    const b = makeTargetWithFiles({
      "poetry.lock": POETRY_LOCK.replace("25.1.0", "25.2.0"),
      "pyproject.toml": PYPROJECT,
    });
    const pyArgs = cdxgenArgs("/abs/target", "/tmp/x/bom.json", "python");
    const keyA = computeCacheKey(a, CDXGEN_TOOL, pyArgs, POETRY_MANIFESTS);
    expect(keyA).toMatch(/^[0-9a-f]{64}$/);
    // A poetry.lock byte change must change the key — proof the files were read.
    expect(keyA).not.toBe(
      computeCacheKey(b, CDXGEN_TOOL, pyArgs, POETRY_MANIFESTS),
    );
  });

  test("same target and args with different manifest lists produce different keys", () => {
    const CONTENT = "identical bytes\n";
    const target = makeTargetWithFiles({
      "yarn.lock": CONTENT,
      "package.json": CONTENT,
      "poetry.lock": CONTENT,
      "pyproject.toml": CONTENT,
    });
    expect(computeCacheKey(target, CDXGEN_TOOL, ARGS, JS_MANIFESTS)).not.toBe(
      computeCacheKey(target, CDXGEN_TOOL, ARGS, POETRY_MANIFESTS),
    );
  });

  test("a missing manifest file throws an error naming the expected path", () => {
    const target = makeTargetWithFiles({ "poetry.lock": "[[package]]\n" });
    expect(() =>
      computeCacheKey(target, CDXGEN_TOOL, ARGS, POETRY_MANIFESTS),
    ).toThrow(/pyproject\.toml/);
    expect(() =>
      computeCacheKey(target, CDXGEN_TOOL, ARGS, POETRY_MANIFESTS),
    ).toThrow(new RegExp(target.dir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});
