/**
 * Mechanism test for the yarn workspace collect-loop expansion: a
 * workspaces-monorepo tree with a root yarn.lock and two workspaces
 * carrying production dependencies must yield THREE per-workspace scan
 * inputs, not one whole-root scan. Before the expansion this test fails
 * structurally (one input, root identity only, workspace production
 * dependencies entirely absent).
 *
 * No live yarn spawn happens here: collectWithYarnPlugin is stubbed via
 * mock.module, keyed on the scanned unit's own directory basename, in the
 * test/cacheRegeneration.test.ts house style (REAL-module capture before
 * mock.module, beforeAll/afterAll restore, mkdtemp tree, captured stderr).
 */

import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";

import * as yarnPluginModule from "../src/collectors/yarnPlugin";
import { mergeSboms } from "../src/merge/merge";
import { collectTargets } from "../src/pipeline/targets";
import { runGenerate, type GenerateOptions } from "../src/pipeline/pipeline";
import type { Target } from "../src/targets/target";

/** Original exports captured BEFORE any mock.module call (restore target). */
const REAL_YARN_PLUGIN = { ...yarnPluginModule };

const WORKSPACE_LOCK = join(
  import.meta.dir,
  "fixtures",
  "workspace-berry.lock",
);

/** basename(target.dir) -> fixture pair name ("root" default for the root unit). */
const FIXTURE_PAIRS: Record<string, string> = {
  backend: "workspace-backend",
  frontend: "workspace-frontend",
};

/**
 * Fake collectWithYarnPlugin: copies the fixture pair matching the unit's
 * own directory basename into a fresh temp dir and returns their paths — no
 * real yarn spawn. The root unit's directory name is the mkdtemp-random
 * root, so it is not a key in FIXTURE_PAIRS; it falls through to the
 * "workspace-root" default, matching the plan's "default any unmatched dir
 * to the root fixture pair" instruction.
 */
async function fakeCollectWithYarnPlugin(
  target: Target,
): Promise<yarnPluginModule.YarnPluginScanResult> {
  const pairName = FIXTURE_PAIRS[basename(target.dir)] ?? "workspace-root";
  const tempDir = mkdtempSync(join(tmpdir(), "licenses-yarnws-scan-"));
  const sbomPath = join(tempDir, "full.json");
  const prodSbomPath = join(tempDir, "prod.json");
  copyFileSync(
    join(import.meta.dir, "fixtures", `${pairName}-full.json`),
    sbomPath,
  );
  copyFileSync(
    join(import.meta.dir, "fixtures", `${pairName}-prod.json`),
    prodSbomPath,
  );
  return {
    sbomPath,
    prodSbomPath,
    cacheKey: "fake",
    tool: REAL_YARN_PLUGIN.YARN_PLUGIN_TOOL,
  };
}

/** Builds a workspaces-monorepo mkdtemp tree: root + backend + frontend. */
function makeWorkspaceTree(): { root: string } {
  const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-"));
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "demo-root",
      workspaces: ["frontend", "backend"],
      devDependencies: { "left-pad": "1.3.0" },
    }) + "\n",
  );
  writeFileSync(join(root, "yarn.lock"), fixtureLockText());
  const backendDir = join(root, "backend");
  const frontendDir = join(root, "frontend");
  mkdirSync(backendDir);
  mkdirSync(frontendDir);
  writeFileSync(
    join(backendDir, "package.json"),
    JSON.stringify({
      name: "backend",
      dependencies: { ms: "2.1.3", isarray: "2.0.5" },
    }) + "\n",
  );
  writeFileSync(
    join(frontendDir, "package.json"),
    JSON.stringify({
      name: "frontend",
      dependencies: { sax: "1.4.1", "imaging-native": "2.0.0" },
    }) + "\n",
  );
  return { root };
}

function fixtureLockText(): string {
  return readFileSync(WORKSPACE_LOCK, "utf8");
}

function baseOpts(root: string): GenerateOptions {
  return {
    repoRoot: root,
    baseDir: root,
    outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
    noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
    verbose: false,
  };
}

describe("collectTargets — yarn workspace expansion (mechanism test)", () => {
  beforeAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: fakeCollectWithYarnPlugin,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => REAL_YARN_PLUGIN);
  });

  test("HEADLINE: a workspaces-monorepo tree yields three per-workspace inputs with per-workspace prodPurlSet, ms production in backend, left-pad dev in root", async () => {
    const { root } = makeWorkspaceTree();
    const log: string[] = [];

    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // (a) exactly three inputs, identities in sorted order.
    expect(result.inputs.map((input) => input.targetIdentity)).toEqual([
      ".",
      "backend",
      "frontend",
    ]);

    // (b) backend's prodPurlSet contains ms, excludes isarray.
    const backendInput = result.inputs.find(
      (input) => input.targetIdentity === "backend",
    );
    expect(backendInput?.prodPurlSet?.has("pkg:npm/ms@2.1.3")).toBe(true);
    expect(backendInput?.prodPurlSet?.has("pkg:npm/isarray@2.0.5")).toBe(false);

    // (c) both reported symptoms die in one test: ms classifies prod in
    // backend; left-pad classifies dev in the root.
    const model = mergeSboms(result.inputs);
    const ms = model.packages.find((pkg) => pkg.purl === "pkg:npm/ms@2.1.3");
    expect(ms?.occurrences).toEqual([
      { target: "backend", isDevDependency: false },
    ]);
    const leftPad = model.packages.find(
      (pkg) => pkg.purl === "pkg:npm/left-pad@1.3.0",
    );
    expect(leftPad?.occurrences).toEqual([
      { target: ".", isDevDependency: true },
    ]);

    // (d) exactly three "collecting <identity> via ..." lines, sorted.
    const collectingLines = log.filter((line) =>
      line.startsWith("collecting "),
    );
    expect(collectingLines).toEqual([
      "collecting . via @cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "collecting backend via @cyclonedx/yarn-plugin-cyclonedx@3.3.1",
      "collecting frontend via @cyclonedx/yarn-plugin-cyclonedx@3.3.1",
    ]);
  });

  test("unit identities never contain a backslash on Windows", async () => {
    const { root } = makeWorkspaceTree();
    const result = await collectTargets(baseOpts(root), () => {});
    for (const input of result.inputs) {
      expect(input.targetIdentity).not.toContain("\\");
    }
  });
});
const ZERO_DEP_LOCK_LINES = [
  "__metadata:",
  "  version: 8",
  "  cacheKey: 10c0",
  "",
  '"demo-root@workspace:.":',
  "  version: 0.0.0-use.local",
  '  resolution: "demo-root@workspace:."',
  "  languageName: unknown",
  "  linkType: soft",
  "",
  '"backend@workspace:backend":',
  "  version: 0.0.0-use.local",
  '  resolution: "backend@workspace:backend"',
  "  dependencies:",
  '    ms: "npm:2.1.3"',
  "  languageName: unknown",
  "  linkType: soft",
  "",
  '"frontend@workspace:frontend":',
  "  version: 0.0.0-use.local",
  '  resolution: "frontend@workspace:frontend"',
  "  dependencies:",
  '    sax: "npm:1.4.1"',
  "  languageName: unknown",
  "  linkType: soft",
  "",
  '"ms@npm:2.1.3":',
  "  version: 2.1.3",
  '  resolution: "ms@npm:2.1.3"',
  "  languageName: node",
  "  linkType: hard",
  "",
  '"sax@npm:1.4.1":',
  "  version: 1.4.1",
  '  resolution: "sax@npm:1.4.1"',
  "  languageName: node",
  "  linkType: hard",
  "",
];

const TRAVERSAL_LOCK_LINES = [
  "__metadata:",
  "  version: 8",
  "  cacheKey: 10c0",
  "",
  '"demo-root@workspace:.":',
  "  version: 0.0.0-use.local",
  '  resolution: "demo-root@workspace:."',
  "  dependencies:",
  '    left-pad: "npm:1.3.0"',
  "  languageName: unknown",
  "  linkType: soft",
  "",
  '"evil@workspace:../outside":',
  "  version: 0.0.0-use.local",
  '  resolution: "evil@workspace:../outside"',
  "  dependencies:",
  '    ms: "npm:2.1.3"',
  "  languageName: unknown",
  "  linkType: soft",
  "",
  '"left-pad@npm:1.3.0":',
  "  version: 1.3.0",
  '  resolution: "left-pad@npm:1.3.0"',
  "  languageName: node",
  "  linkType: hard",
  "",
  '"ms@npm:2.1.3":',
  "  version: 2.1.3",
  '  resolution: "ms@npm:2.1.3"',
  "  languageName: node",
  "  linkType: hard",
  "",
];
const ABSOLUTE_LOCK_LINES =
  process.platform === "win32"
    ? [
        "__metadata:",
        "  version: 8",
        "  cacheKey: 10c0",
        "",
        '"demo-root@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "demo-root@workspace:."',
        "  dependencies:",
        '    left-pad: "npm:1.3.0"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"evil@workspace:C:/windows/evil":',
        "  version: 0.0.0-use.local",
        '  resolution: "evil@workspace:C:/windows/evil"',
        "  dependencies:",
        '    ms: "npm:2.1.3"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "  languageName: node",
        "  linkType: hard",
        "",
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ]
    : [
        "__metadata:",
        "  version: 8",
        "  cacheKey: 10c0",
        "",
        '"demo-root@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "demo-root@workspace:."',
        "  dependencies:",
        '    left-pad: "npm:1.3.0"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"evil@workspace:/etc/evil":',
        "  version: 0.0.0-use.local",
        '  resolution: "evil@workspace:/etc/evil"',
        "  dependencies:",
        '    ms: "npm:2.1.3"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "  languageName: node",
        "  linkType: hard",
        "",
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ];
describe("collectTargets — yarn workspace expansion edge behavior", () => {
  beforeAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: fakeCollectWithYarnPlugin,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => REAL_YARN_PLUGIN);
  });

  test("structural no-op: a single-workspace (@workspace:.-only) lock takes the exact current path — one input, identity '.' , no unit fields set", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-noop-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        name: "single-workspace-repo",
        dependencies: { ms: "2.1.3" },
      }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
        "__metadata:",
        "  version: 8",
        "  cacheKey: 10c0",
        "",
        '"single-workspace-repo@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "single-workspace-repo@workspace:."',
        "  dependencies:",
        '    ms: "npm:2.1.3"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );

    const result = await collectTargets(baseOpts(root), () => {});
    expect(result.inputs.map((input) => input.targetIdentity)).toEqual(["."]);
  });

  test("--target mode: expansion fires identically, unit identities are [base, base/backend, base/frontend]", async () => {
    const { root } = makeWorkspaceTree();
    const base = basename(root);

    const result = await collectTargets(
      {
        targetArg: root,
        baseDir: root,
        outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
        noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
        verbose: false,
      },
      () => {},
    );

    expect(result.inputs.map((input) => input.targetIdentity)).toEqual([
      base,
      `${base}/backend`,
      `${base}/frontend`,
    ]);
  });

  test("zero-dep workspace (including the dep-less root): skip is loud, the run completes, other workspaces still scan", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-zerodep-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        name: "demo-root",
        workspaces: ["frontend", "backend"],
      }) + "\n",
    );
    writeFileSync(join(root, "yarn.lock"), ZERO_DEP_LOCK_LINES.join("\n"));
    const backendDir = join(root, "backend");
    const frontendDir = join(root, "frontend");
    mkdirSync(backendDir);
    mkdirSync(frontendDir);
    writeFileSync(
      join(backendDir, "package.json"),
      JSON.stringify({ name: "backend", dependencies: { ms: "2.1.3" } }) + "\n",
    );
    writeFileSync(
      join(frontendDir, "package.json"),
      JSON.stringify({ name: "frontend", dependencies: { sax: "1.4.1" } }) +
        "\n",
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // The dep-less root unit skips loudly; backend and frontend still scan.
    expect(log).toContain(
      "warning: skipping . — workspace declares no dependencies in yarn.lock",
    );
    expect(result.inputs.map((input) => input.targetIdentity)).toEqual([
      "backend",
      "frontend",
    ]);
  });

  test("containment: a traversal @workspace: path throws before any spawn, naming the identity and offending path", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-traversal-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root" }) + "\n",
    );
    writeFileSync(join(root, "yarn.lock"), TRAVERSAL_LOCK_LINES.join("\n"));

    let spawnCount = 0;
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: async (
        target: Target,
      ): Promise<yarnPluginModule.YarnPluginScanResult> => {
        spawnCount += 1;
        return fakeCollectWithYarnPlugin(target);
      },
    }));

    await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
      /outside/,
    );
    expect(spawnCount).toBe(0);

    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: fakeCollectWithYarnPlugin,
    }));
  });

  test("containment: an absolute @workspace: path throws before any spawn, naming the identity and offending path", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-absolute-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root" }) + "\n",
    );
    writeFileSync(join(root, "yarn.lock"), ABSOLUTE_LOCK_LINES.join("\n"));

    let spawnCount = 0;
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: async (
        target: Target,
      ): Promise<yarnPluginModule.YarnPluginScanResult> => {
        spawnCount += 1;
        return fakeCollectWithYarnPlugin(target);
      },
    }));

    await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
      /evil/,
    );
    expect(spawnCount).toBe(0);

    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: fakeCollectWithYarnPlugin,
    }));
  });
});

/**
 * Capture process.stderr.write for the duration of a callback; always
 * restores in finally (test/cli.test.ts idiom).
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

/** Collapse multi-space runs (markdown table padding) before matching. */
const squish = (s: string): string => s.replace(/ {2,}/g, " ");

describe("collectTargets — yarn workspace expansion (fixture-mirror document)", () => {
  // Document-level acceptance evidence: the corrected reporting shape on the
  // SAME workspaces-monorepo tree as the mechanism test above — Production
  // > 0, per-workspace Used-in cells, the copyleft package in the Production
  // section, and (with an inline policy) a policy FAIL naming it "in
  // frontend". This is the inversion of the pre-fix collapse (one target,
  // zero production packages). No live yarn spawn: reuses the
  // fakeCollectWithYarnPlugin stub and mkdtemp tree builder (module-scope
  // above), keyed on directory
  // basename against the workspace-{backend,frontend}-{full,prod} fixture
  // pairs, which already carry ms/isarray (backend) and sax/imaging-native
  // (frontend, imaging-native under LGPL-3.0-or-later) plus the root's
  // left-pad dev dependency — every fixture component carries a license, so
  // the enrichment lane stays fetch-free without needing a fetch stub.
  beforeAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: fakeCollectWithYarnPlugin,
    }));
  });

  afterAll(() => {
    mock.module("../src/collectors/yarnPlugin", () => REAL_YARN_PLUGIN);
  });

  function generateOpts(root: string, policyPath?: string): GenerateOptions {
    const opts: GenerateOptions = {
      repoRoot: root,
      baseDir: root,
      outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
      noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
      enrichmentCachePath: join(root, "enrichment-cache.json"),
      verbose: false,
    };
    if (policyPath !== undefined) opts.policyPath = policyPath;
    return opts;
  }

  test("HEADLINE: the rendered document shows the corrected shape — Total 5, Production 3, Development-only 2, per-workspace Used-in, imaging-native in Production", async () => {
    const { root } = makeWorkspaceTree();

    const md = await runGenerate(generateOpts(root));

    // (a) counts block: Total 5, Production 3 (ms, sax, imaging-native),
    // Development-only 2 (isarray, left-pad).
    expect(md).toContain("- Total packages: 5");
    expect(md).toContain("- Production packages: 3");
    expect(md).toContain("- Development-only packages: 2");

    // (b) per-workspace Used-in attribution at the rendered surface:
    // ms->backend, sax/imaging-native->frontend, left-pad->'.'. The
    // renderer pads table columns to their widest cell, so multi-space runs
    // are squished before matching (test/cli.test.ts idiom).
    const squished = squish(md);
    expect(squished).toContain("| ms | npm | 2.1.3 | MIT | backend |");
    expect(squished).toContain("| sax | npm | 1.4.1 | ISC | frontend |");
    expect(squished).toContain("| left-pad | npm | 1.3.0 | WTFPL | . |");

    // (c) imaging-native (LGPL-3.0-or-later) renders in the Production
    // dependencies section, not Development-only.
    const productionIdx = md.indexOf("## Production dependencies");
    const developmentIdx = md.indexOf("## Development-only dependencies");
    const imagingIdx = md.indexOf("imaging-native");
    expect(productionIdx).toBeGreaterThan(-1);
    expect(developmentIdx).toBeGreaterThan(-1);
    expect(imagingIdx).toBeGreaterThan(productionIdx);
    expect(imagingIdx).toBeLessThan(developmentIdx);
  });

  test("policy run: the FAIL line names imaging-native 'in frontend' under a default posture (dev_dependencies=warn)", async () => {
    const { root } = makeWorkspaceTree();
    const policyPath = join(root, "policy.toml");
    writeFileSync(
      policyPath,
      ["[unknown]", 'handling = "warn"', ""].join("\n"),
    );

    const stderr = await withCapturedStderr(async () => {
      await runGenerate(generateOpts(root, policyPath));
    });

    // Locked shape: 'policy <status>: <purl> in <target> — <rule>: <reason>'.
    expect(stderr).toContain(
      "policy fail: pkg:npm/imaging-native@2.0.0 in frontend — default:copyleft:",
    );
    expect(stderr).toContain('copyleft license "LGPL-3.0-or-later"');
  });
});
