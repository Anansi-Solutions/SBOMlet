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
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";

import * as cdxgenModule from "../src/collectors/cdxgen";
import * as yarnPluginModule from "../src/collectors/yarnPlugin";
import { mergeSboms } from "../src/merge/merge";
import { collectTargets } from "../src/pipeline/targets";
import { runGenerate, type GenerateOptions } from "../src/pipeline/pipeline";
import type { Target } from "../src/targets/target";

/** Original exports captured BEFORE any mock.module call (restore target). */
const REAL_YARN_PLUGIN = { ...yarnPluginModule };

/** Original cdxgen exports captured before any mock.module call. */
const REAL_CDXGEN = { ...cdxgenModule };

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

  test("workspace member NAMES never affect behavior — a scoped package name at a deep path, and a member name that differs entirely from its own directory, expand and attribute identically to a plain single-segment name", async () => {
    // The workspace package NAME ("@acme/web-app", "api") is never used for
    // path resolution, containment, identity, or cache-keying -- only
    // relPath is. This proves that end-to-end: identity is derived purely
    // from the LOCK-DECLARED PATH, and a production dependency in either
    // workspace classifies correctly regardless of how exotic or
    // mismatched its package name is.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-nameshape-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        name: "demo-root",
        workspaces: ["packages/web-app", "services/backend-api"],
        devDependencies: { "left-pad": "1.3.0" },
      }) + "\n",
    );
    const webAppDir = join(root, "packages", "web-app");
    const apiDir = join(root, "services", "backend-api");
    mkdirSync(webAppDir, { recursive: true });
    mkdirSync(apiDir, { recursive: true });
    writeFileSync(
      join(webAppDir, "package.json"),
      JSON.stringify({ name: "@acme/web-app", dependencies: { ms: "2.1.3" } }) +
        "\n",
    );
    writeFileSync(
      join(apiDir, "package.json"),
      JSON.stringify({ name: "api", dependencies: { sax: "1.4.1" } }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
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
        '"@acme/web-app@workspace:packages/web-app":',
        "  version: 0.0.0-use.local",
        '  resolution: "@acme/web-app@workspace:packages/web-app"',
        "  dependencies:",
        '    ms: "npm:2.1.3"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"api@workspace:services/backend-api":',
        "  version: 0.0.0-use.local",
        '  resolution: "api@workspace:services/backend-api"',
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
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );

    // A dedicated stub keyed on the REAL directory basenames this test
    // uses ("web-app", "backend-api") -- the shared
    // fakeCollectWithYarnPlugin only recognizes "backend"/"frontend" and
    // would silently fall back to the root fixture for any other
    // directory name, which would prove nothing about THIS test's exotic-
    // name shapes.
    const sbomFor = (
      components: { name: string; version: string; purl: string }[],
    ): string =>
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: components.map((c) => ({
          ...c,
          licenses: [{ license: { id: "MIT" } }],
        })),
      });

    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: async (
        target: Target,
      ): Promise<yarnPluginModule.YarnPluginScanResult> => {
        const tempDir = mkdtempSync(
          join(tmpdir(), "licenses-yarnws-nameshape-scan-"),
        );
        const sbomPath = join(tempDir, "full.json");
        const prodSbomPath = join(tempDir, "prod.json");
        const dirName = basename(target.dir);
        const full =
          dirName === "web-app"
            ? sbomFor([
                { name: "ms", version: "2.1.3", purl: "pkg:npm/ms@2.1.3" },
              ])
            : dirName === "backend-api"
              ? sbomFor([
                  {
                    name: "sax",
                    version: "1.4.1",
                    purl: "pkg:npm/sax@1.4.1",
                  },
                ])
              : sbomFor([
                  {
                    name: "left-pad",
                    version: "1.3.0",
                    purl: "pkg:npm/left-pad@1.3.0",
                  },
                ]);
        const prod =
          dirName === "web-app" || dirName === "backend-api"
            ? full
            : sbomFor([]);
        writeFileSync(sbomPath, full);
        writeFileSync(prodSbomPath, prod);
        return {
          sbomPath,
          prodSbomPath,
          cacheKey: "fake",
          tool: REAL_YARN_PLUGIN.YARN_PLUGIN_TOOL,
        };
      },
    }));

    try {
      const result = await collectTargets(baseOpts(root), () => {});

      // Identity is the lock-declared PATH, never the package name.
      expect(result.inputs.map((input) => input.targetIdentity)).toEqual([
        ".",
        "packages/web-app",
        "services/backend-api",
      ]);

      const model = mergeSboms(result.inputs);
      const ms = model.packages.find((pkg) => pkg.purl === "pkg:npm/ms@2.1.3");
      const sax = model.packages.find(
        (pkg) => pkg.purl === "pkg:npm/sax@1.4.1",
      );
      expect(ms?.occurrences).toEqual([
        { target: "packages/web-app", isDevDependency: false },
      ]);
      expect(sax?.occurrences).toEqual([
        { target: "services/backend-api", isDevDependency: false },
      ]);
    } finally {
      mock.module("../src/collectors/yarnPlugin", () => ({
        ...REAL_YARN_PLUGIN,
        collectWithYarnPlugin: fakeCollectWithYarnPlugin,
      }));
    }
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

  test("unit order is stable and alphabetic regardless of the lock entry order — a REVERSED lock (frontend, backend, root) still yields [., backend, frontend]", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-reversed-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        name: "demo-root",
        workspaces: ["frontend", "backend"],
        devDependencies: { "left-pad": "1.3.0" },
      }) + "\n",
    );
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
    // The lock entries themselves are in REVERSE alphabetic order
    // (frontend, then backend, then root) — expandYarnWorkspaceUnits'
    // own explicit .sort(compareCodeUnits) must still produce the
    // canonical alphabetic order in the output, never the encounter
    // order the lock happened to declare.
    writeFileSync(
      join(root, "yarn.lock"),
      [
        "__metadata:",
        "  version: 8",
        "  cacheKey: 10c0",
        "",
        '"frontend@workspace:frontend":',
        "  version: 0.0.0-use.local",
        '  resolution: "frontend@workspace:frontend"',
        "  dependencies:",
        '    sax: "npm:1.4.1"',
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
        '"demo-root@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "demo-root@workspace:."',
        "  dependencies:",
        '    left-pad: "npm:1.3.0"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"sax@npm:1.4.1":',
        "  version: 1.4.1",
        '  resolution: "sax@npm:1.4.1"',
        "  languageName: node",
        "  linkType: hard",
        "",
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );

    const result = await collectTargets(baseOpts(root), () => {});
    expect(result.inputs.map((input) => input.targetIdentity)).toEqual([
      ".",
      "backend",
      "frontend",
    ]);
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
/**
 * Lock lines with a parametric hostile @workspace: path — the cross-drive
 * containment arms below need drive letters chosen at runtime (relative to
 * whatever drive the temp tree landed on), so this cannot be a constant.
 * The npm entries keep the lock's third-party count positive: containment
 * must fire on its own, never shadowed by a zero-third-party skip.
 */
function evilPathLockLines(evilPath: string): string[] {
  return [
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
    `"evil@workspace:${evilPath}":`,
    "  version: 0.0.0-use.local",
    `  resolution: "evil@workspace:${evilPath}"`,
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
}

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

  test("two workspace lock entries declaring the SAME relPath (a malformed/hand-edited lock) never silently misattribute the zero-dep skip decision", async () => {
    // pkg-a@workspace:backend HAS a dependencies: block; pkg-b@workspace:backend
    // (a second, different member NAME resolving to the identical path) has
    // NONE. Both parse as distinct entries from yarnWorkspaceMembers, but
    // expansion collapses them to units sharing the same identity/dir —
    // the property under test is that the run completes deterministically
    // (no crash, no NaN/undefined identity) and never SILENTLY drops the
    // workspace's real production dependency because a later, dep-less
    // duplicate entry's flag won the lookup.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-duprelpath-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root", workspaces: ["backend"] }) + "\n",
    );
    const backendDir = join(root, "backend");
    mkdirSync(backendDir);
    writeFileSync(
      join(backendDir, "package.json"),
      JSON.stringify({ name: "backend", dependencies: { ms: "2.1.3" } }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
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
        '"pkg-a@workspace:backend":',
        "  version: 0.0.0-use.local",
        '  resolution: "pkg-a@workspace:backend"',
        "  dependencies:",
        '    ms: "npm:2.1.3"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"pkg-b@workspace:backend":',
        "  version: 0.0.0-use.local",
        '  resolution: "pkg-b@workspace:backend"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // The run completes without throwing. Both duplicate-relPath units
    // resolve to the SAME identity/dir, so the collected inputs list may
    // legitimately contain a repeated identity (a redundant re-scan of the
    // same directory) — the safety property is that a real production
    // dependency (ms) is never lost from the merged model as a result.
    const model = mergeSboms(result.inputs);
    const ms = model.packages.find((pkg) => pkg.purl === "pkg:npm/ms@2.1.3");
    expect(ms?.occurrences.some((o) => !o.isDevDependency)).toBe(true);
  });

  test("EVERY unit dep-less (root and its only workspace) yields a loud, empty inventory through the full pipeline — never a crash, never a misleadingly non-empty result", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-allskipped-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root", workspaces: ["backend"] }) + "\n",
    );
    const backendDir = join(root, "backend");
    mkdirSync(backendDir);
    writeFileSync(
      join(backendDir, "package.json"),
      JSON.stringify({ name: "backend" }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
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
        "  languageName: unknown",
        "  linkType: soft",
        "",
      ].join("\n"),
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // A lock whose every entry is workspace:-protocol skip-classifies at
    // the TARGET level (zero third-party entries), before any per-unit
    // processing: one loud warning naming the target and the reason, and
    // the run completes (no throw) with a genuinely empty (not merely
    // small) input list.
    expect(log).toContain(
      "warning: skipping . — yarn.lock has no third-party entries (only workspace/portal members)",
    );
    expect(result.inputs).toEqual([]);

    // The full pipeline (merge + render) on a genuinely empty input list
    // must not crash and must render an honest zero-count document, never
    // a stale/misleading non-empty one.
    const model = mergeSboms(result.inputs);
    expect(model.packages).toEqual([]);
  });

  test("an all-workspace-protocol lock (workspaces depending only on each other) skips the whole target LOUDLY before any unit spawn — never a silent post-scan drop", async () => {
    // Every entry in this lock resolves via workspace: (the monorepo's
    // workspaces depend only on each other), so thirdPartyEntryCount is 0
    // and there is nothing to inventory. The non-expanded path pre-checks
    // coverageSkipReason and warns BEFORE dispatch; the expanded path must
    // hold the same two guarantees: the skip is loud (a warning line names
    // the target and the reason), and no generator spawn is burned on units
    // whose coverage verdict is already decided by the root lock.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-allws-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({
        name: "demo-root",
        workspaces: ["backend"],
        dependencies: { backend: "workspace:^" },
      }) + "\n",
    );
    const backendDir = join(root, "backend");
    mkdirSync(backendDir);
    writeFileSync(
      join(backendDir, "package.json"),
      JSON.stringify({ name: "backend" }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
        "__metadata:",
        "  version: 8",
        "  cacheKey: 10c0",
        "",
        '"backend@workspace:^, backend@workspace:backend":',
        "  version: 0.0.0-use.local",
        '  resolution: "backend@workspace:backend"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
        '"demo-root@workspace:.":',
        "  version: 0.0.0-use.local",
        '  resolution: "demo-root@workspace:."',
        "  dependencies:",
        '    backend: "workspace:^"',
        "  languageName: unknown",
        "  linkType: soft",
        "",
      ].join("\n"),
    );

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

    try {
      const log: string[] = [];
      const result = await collectTargets(baseOpts(root), (line) => {
        log.push(line);
      });

      expect(log).toContain(
        "warning: skipping . — yarn.lock has no third-party entries (only workspace/portal members)",
      );
      expect(spawnCount).toBe(0);
      expect(result.inputs).toEqual([]);
    } finally {
      mock.module("../src/collectors/yarnPlugin", () => ({
        ...REAL_YARN_PLUGIN,
        collectWithYarnPlugin: fakeCollectWithYarnPlugin,
      }));
    }
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

  test("containment: a workspace member directory that is a SYMLINK escaping the repo root must never spawn with cwd resolving outside the repo", async () => {
    // The lexical resolve()/relative() containment check never touches
    // the filesystem, so a lock-declared relPath that resolves INSIDE
    // target.dir LEXICALLY, but is ON DISK a symlink pointing OUTSIDE the
    // repo, is not caught by path-string comparison alone. Discovery's own
    // walk never follows symlinks (Dirent.isDirectory() is false for a
    // symlink entry) — this test proves whether the unit-expansion path
    // holds the same REAL-filesystem guarantee, comparing realpathSync
    // (what the OS actually resolves at spawn time), not just the lexical
    // string.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-symlink-"));
    const outside = mkdtempSync(join(tmpdir(), "licenses-yarnws-outside-"));
    writeFileSync(
      join(outside, "package.json"),
      JSON.stringify({ name: "escaped", dependencies: { ms: "2.1.3" } }) + "\n",
    );
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root", workspaces: ["escape-link"] }) + "\n",
    );
    const linkPath = join(root, "escape-link");
    try {
      symlinkSync(outside, linkPath, "junction");
    } catch {
      // Symlink privileges unavailable in this environment (e.g.
      // non-admin Windows without Developer Mode) — skip rather than
      // false-fail; the property is proven wherever symlinks ARE
      // available (CI, most dev machines with Developer Mode on).
      return;
    }
    writeFileSync(
      join(root, "yarn.lock"),
      [
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
        '"escaped@workspace:escape-link":',
        "  version: 0.0.0-use.local",
        '  resolution: "escaped@workspace:escape-link"',
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

    try {
      // GREEN: the real-filesystem containment check throws before ANY
      // spawn, exactly like the lexical traversal/absolute checks above.
      await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
        /symlink/,
      );
      expect(spawnCount).toBe(0);
    } finally {
      mock.module("../src/collectors/yarnPlugin", () => ({
        ...REAL_YARN_PLUGIN,
        collectWithYarnPlugin: fakeCollectWithYarnPlugin,
      }));
    }
  });

  test("a workspace unit that declares real dependencies but whose scan yields zero components hard-fails, never silently skips via the ROOT lock text passed to classifyCoverage", async () => {
    // classifyCoverage receives the ROOT lockfile text (not the unit's own
    // slice) for its coverageSkipReason pre-check. This proves that check
    // never masks a genuine zero-component scan as a skip for a unit that
    // itself declares dependencies: the componentCount===0 branch must
    // still throw.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-hardfail-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root", workspaces: ["backend"] }) + "\n",
    );
    const backendDir = join(root, "backend");
    mkdirSync(backendDir);
    writeFileSync(
      join(backendDir, "package.json"),
      JSON.stringify({ name: "backend", dependencies: { ms: "2.1.3" } }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
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
        '"ms@npm:2.1.3":',
        "  version: 2.1.3",
        '  resolution: "ms@npm:2.1.3"',
        "  languageName: node",
        "  linkType: hard",
        "",
      ].join("\n"),
    );

    // Stub the plugin to return an EMPTY SBOM for the backend unit only
    // (a scan that legitimately produced nothing, despite a real
    // dependencies: entry in the lock).
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: async (
        _target: Target,
      ): Promise<yarnPluginModule.YarnPluginScanResult> => {
        const tempDir = mkdtempSync(
          join(tmpdir(), "licenses-yarnws-hardfail-scan-"),
        );
        const sbomPath = join(tempDir, "full.json");
        const prodSbomPath = join(tempDir, "prod.json");
        const empty = JSON.stringify({
          bomFormat: "CycloneDX",
          specVersion: "1.6",
          components: [],
        });
        writeFileSync(sbomPath, empty);
        writeFileSync(prodSbomPath, empty);
        return {
          sbomPath,
          prodSbomPath,
          cacheKey: "fake",
          tool: REAL_YARN_PLUGIN.YARN_PLUGIN_TOOL,
        };
      },
    }));

    try {
      await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
        /coverage assertion failed/,
      );
    } finally {
      mock.module("../src/collectors/yarnPlugin", () => ({
        ...REAL_YARN_PLUGIN,
        collectWithYarnPlugin: fakeCollectWithYarnPlugin,
      }));
    }
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

  test.if(process.platform === "win32")(
    "containment: a CROSS-DRIVE absolute @workspace: path throws the containment error before any spawn — never the missing-manifest fallback",
    async () => {
      // win32 path semantics gap: for a lock path on ANOTHER drive,
      // resolve("Q:/evil") returns "Q:\evil" (separator normalization), so
      // the string-equality absolute check is false, and relative(root,
      // "Q:\evil") returns the ABSOLUTE "Q:\evil" — neither ".." nor
      // "..\\"-prefixed. The lexical gate itself must reject that shape:
      // the directory does not exist, so the realpath branch never runs,
      // and falling through to assertManifestsExist would burn the root
      // unit's spawn first and report a misleading missing-package.json
      // error. resolve()/relative() are purely lexical — the drive letter
      // need not exist on the machine.
      const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-xdrive-"));
      writeFileSync(
        join(root, "package.json"),
        JSON.stringify({ name: "demo-root" }) + "\n",
      );
      const otherDrive = root[0]?.toUpperCase() === "Q" ? "Z" : "Q";
      writeFileSync(
        join(root, "yarn.lock"),
        evilPathLockLines(`${otherDrive}:/evil`).join("\n"),
      );

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

      try {
        await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
          /escapes the workspace root — refusing/,
        );
        expect(spawnCount).toBe(0);
      } finally {
        mock.module("../src/collectors/yarnPlugin", () => ({
          ...REAL_YARN_PLUGIN,
          collectWithYarnPlugin: fakeCollectWithYarnPlugin,
        }));
      }
    },
  );

  test.if(process.platform === "win32")(
    "containment: a DRIVE-RELATIVE @workspace: path (Q:evil) throws the containment error before any spawn",
    async () => {
      // "Q:evil" is drive-relative: isAbsolute() is FALSE for it, and
      // resolve() sends it to drive Q's current directory ("Q:\evil" when
      // the drive is not the process's own) — outside the repo root on
      // another drive entirely. Same lexical-gate obligation as the
      // cross-drive absolute arm above.
      const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-drvrel-"));
      writeFileSync(
        join(root, "package.json"),
        JSON.stringify({ name: "demo-root" }) + "\n",
      );
      const otherDrive = root[0]?.toUpperCase() === "Q" ? "Z" : "Q";
      writeFileSync(
        join(root, "yarn.lock"),
        evilPathLockLines(`${otherDrive}:evil`).join("\n"),
      );

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

      try {
        await expect(collectTargets(baseOpts(root), () => {})).rejects.toThrow(
          /escapes the workspace root — refusing/,
        );
        expect(spawnCount).toBe(0);
      } finally {
        mock.module("../src/collectors/yarnPlugin", () => ({
          ...REAL_YARN_PLUGIN,
          collectWithYarnPlugin: fakeCollectWithYarnPlugin,
        }));
      }
    },
  );
  test("a classic (pre-Berry) yarn.lock containing @workspace:-shaped text scans as ONE whole-root cdxgen target — expansion never fires without a __metadata version >= 8 block", async () => {
    // A pre-Berry lock has no __metadata block, so selectJsGenerator routes
    // it to cdxgen and expandYarnWorkspaceUnits must bail before the member
    // scan ever runs. The lock below is the worst admissible shape: a
    // decorative @workspace: comment PLUS Berry-shaped
    // resolution: "...@workspace:..." body lines (root + one member, both
    // with dependencies:) that WOULD enumerate as a valid expansion set if
    // the version gate were bypassed — and the member directory exists on
    // disk with its own package.json, so no downstream check would trip
    // incidentally. The dispatch gate alone stands between this lock and a
    // spurious workspace expansion.
    const root = mkdtempSync(join(tmpdir(), "licenses-yarnws-classic-"));
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "demo-root", dependencies: { ms: "2.1.3" } }) +
        "\n",
    );
    const evilDir = join(root, "packages", "evil");
    mkdirSync(evilDir, { recursive: true });
    writeFileSync(
      join(evilDir, "package.json"),
      JSON.stringify({ name: "evil", dependencies: { ms: "2.1.3" } }) + "\n",
    );
    writeFileSync(
      join(root, "yarn.lock"),
      [
        "# yarn lockfile v1",
        "# see evil@workspace:packages/evil for layout",
        "",
        "ms@^2.1.3:",
        '  version "2.1.3"',
        '  resolved "https://registry.example.com/ms/-/ms-2.1.3.tgz#cafe"',
        "",
        '"demo-root@workspace:.":',
        '  version "0.0.0-use.local"',
        '  resolution: "demo-root@workspace:."',
        "  dependencies:",
        '    ms "^2.1.3"',
        "",
        '"evil@workspace:packages/evil":',
        '  version "0.0.0-use.local"',
        '  resolution: "evil@workspace:packages/evil"',
        "  dependencies:",
        '    ms "^2.1.3"',
        "",
      ].join("\n"),
    );

    let cdxgenCalls = 0;
    let pluginCalls = 0;
    mock.module("../src/collectors/cdxgen", () => ({
      ...REAL_CDXGEN,
      collectWithCdxgen: async (): Promise<cdxgenModule.CollectorSbomFile> => {
        cdxgenCalls += 1;
        const tempDir = mkdtempSync(
          join(tmpdir(), "licenses-yarnws-classic-scan-"),
        );
        const sbomPath = join(tempDir, "bom.json");
        writeFileSync(
          sbomPath,
          JSON.stringify({
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            components: [
              {
                name: "ms",
                version: "2.1.3",
                purl: "pkg:npm/ms@2.1.3",
                licenses: [{ license: { id: "MIT" } }],
              },
            ],
          }),
        );
        return { sbomPath, cacheKey: "fake", tool: REAL_CDXGEN.CDXGEN_TOOL };
      },
    }));
    mock.module("../src/collectors/yarnPlugin", () => ({
      ...REAL_YARN_PLUGIN,
      collectWithYarnPlugin: async (
        target: Target,
      ): Promise<yarnPluginModule.YarnPluginScanResult> => {
        pluginCalls += 1;
        return fakeCollectWithYarnPlugin(target);
      },
    }));

    try {
      const log: string[] = [];
      const result = await collectTargets(baseOpts(root), (line) => {
        log.push(line);
      });

      // Exactly ONE input with the root identity — never a unit for the
      // on-disk packages/evil directory the lock's text points at.
      expect(result.inputs.map((input) => input.targetIdentity)).toEqual(["."]);

      // One cdxgen scan, zero yarn-plugin scans, one collecting line: the
      // whole-root single-scan path, identical to any other cdxgen target.
      expect(cdxgenCalls).toBe(1);
      expect(pluginCalls).toBe(0);
      const tool = REAL_CDXGEN.CDXGEN_TOOL;
      expect(log.filter((line) => line.startsWith("collecting "))).toEqual([
        `collecting . via ${tool.name}@${tool.version}`,
      ]);
    } finally {
      mock.module("../src/collectors/cdxgen", () => REAL_CDXGEN);
      mock.module("../src/collectors/yarnPlugin", () => ({
        ...REAL_YARN_PLUGIN,
        collectWithYarnPlugin: fakeCollectWithYarnPlugin,
      }));
    }
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

describe("collectTargets — nuget packages.lock.json coverage integration", () => {
  test("an empty-sections packages.lock.json logs the warn+skip line and collects nothing", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-nuget-cov-"));
    writeFileSync(
      join(root, "packages.lock.json"),
      '{"version":2,"dependencies":{"net9.0":{}}}\n',
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    expect(log).toContain(
      "warning: skipping . — packages.lock.json has no third-party entries (only Project entries, or empty dependency sections)",
    );
    expect(result.inputs).toEqual([]);
  });

  test("a real lock collects via the in-process collector (the collecting stderr shape)", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-nuget-cov-"));
    writeFileSync(
      join(root, "packages.lock.json"),
      JSON.stringify({
        version: 2,
        dependencies: {
          "net9.0": {
            "Newtonsoft.Json": {
              type: "Direct",
              requested: "[13.0.4, )",
              resolved: "13.0.4",
            },
          },
        },
      }) + "\n",
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    expect(log).toContain("collecting . via nuget-lock-collector@1");
    expect(result.inputs.map((input) => input.targetIdentity)).toEqual(["."]);
    expect(result.targetDirs).toEqual([root]);
  });
});

// ---------------------------------------------------------------------------
// collectTargets — maven reactor attribution (17-02): the pipeline pre-pass +
// post-collect sibling filter, exercised end-to-end via the in-process maven
// collector (no mocking — no subprocess exists to stub).
// ---------------------------------------------------------------------------

/** Reactor aggregator pom: zero components, root type=pom. */
const REACTOR_AGGREGATOR_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: {
      purl: "pkg:maven/com.example.fixture/reactor-parent@1.0.0?type=pom",
    },
  },
  components: [],
});

/** Module liba: one ordinary third-party dependency. */
const REACTOR_LIBA_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: { purl: "pkg:maven/com.example.fixture/liba@1.0.0?type=jar" },
  },
  components: [
    {
      purl: "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
  ],
});

/**
 * Module appb: depends on liba (the sibling leak — a plain component with no
 * marker) plus liba's own transitive and appb's own dependency.
 */
const REACTOR_APPB_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: { purl: "pkg:maven/com.example.fixture/appb@1.0.0?type=jar" },
  },
  components: [
    { purl: "pkg:maven/com.example.fixture/liba@1.0.0?type=jar" },
    {
      purl: "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
    {
      purl: "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
  ],
});

/**
 * Module allsiblings: its ONLY component is a sibling module — a real
 * cyclonedx-maven-plugin edge case (a module depending on nothing but
 * another reactor module). Post-filter this collapses to zero components,
 * which must merge as an empty contribution, never a hard fail.
 */
const REACTOR_ALLSIBLINGS_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: {
      purl: "pkg:maven/com.example.fixture/allsiblings@1.0.0?type=jar",
    },
  },
  components: [{ purl: "pkg:maven/com.example.fixture/liba@1.0.0?type=jar" }],
});

function componentPurlsOf(sbom: unknown): string[] {
  const doc = sbom as { components?: Array<Record<string, unknown>> };
  return (doc.components ?? []).map((c) => String(c["purl"]));
}

describe("collectTargets — maven reactor attribution", () => {
  test("three module targets collect; the aggregator pom skips; sibling exclusion and the all-siblings empty contribution both hold", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-maven-reactor-"));
    writeFileSync(join(root, "maven.sbom.json"), REACTOR_AGGREGATOR_SBOM);
    const libaDir = join(root, "liba");
    const appbDir = join(root, "appb");
    const allsiblingsDir = join(root, "allsiblings");
    mkdirSync(libaDir);
    mkdirSync(appbDir);
    mkdirSync(allsiblingsDir);
    writeFileSync(join(libaDir, "maven.sbom.json"), REACTOR_LIBA_SBOM);
    writeFileSync(join(appbDir, "maven.sbom.json"), REACTOR_APPB_SBOM);
    writeFileSync(
      join(allsiblingsDir, "maven.sbom.json"),
      REACTOR_ALLSIBLINGS_SBOM,
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // The aggregator pom is never pushed into the merge, and never hard-fails.
    expect(result.inputs.some((input) => input.targetIdentity === ".")).toBe(
      false,
    );
    expect(
      log.some(
        (line) =>
          line.startsWith("warning: skipping . —") &&
          line.includes("maven.sbom.json has no third-party entries"),
      ),
    ).toBe(true);

    expect(result.inputs.map((input) => input.targetIdentity).sort()).toEqual([
      "allsiblings",
      "appb",
      "liba",
    ]);

    const appbInput = result.inputs.find(
      (input) => input.targetIdentity === "appb",
    );
    expect(componentPurlsOf(appbInput?.sbom)).toEqual([
      "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
    ]);

    const libaInput = result.inputs.find(
      (input) => input.targetIdentity === "liba",
    );
    expect(componentPurlsOf(libaInput?.sbom)).toEqual([
      "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
    ]);

    const allsiblingsInput = result.inputs.find(
      (input) => input.targetIdentity === "allsiblings",
    );
    expect(componentPurlsOf(allsiblingsInput?.sbom)).toEqual([]);
  });
});

/**
 * liba's test-inclusive sidecar: a superset adding one test-only dependency
 * beside liba's existing commons-lang3 — same root purl as REACTOR_LIBA_SBOM
 * (the pre-pass and sibling exclusion key on the DEFAULT doc's root purl
 * only, per the locked design; this fixture never touches that).
 */
const REACTOR_LIBA_TEST_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: { purl: "pkg:maven/com.example.fixture/liba@1.0.0?type=jar" },
  },
  components: [
    {
      purl: "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
    {
      purl: "pkg:maven/com.example.fixture/junit-fixture@5.0.0?type=jar",
      licenses: [{ license: { id: "EPL-2.0" } }],
    },
  ],
});

describe("collectTargets — maven reactor attribution with a test-inclusive sidecar present", () => {
  test("a test doc on ONE reactor module changes only that module's own inventory — the aggregator skip, target set, and sibling exclusion for every module are unchanged", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-maven-reactor-dual-"));
    writeFileSync(join(root, "maven.sbom.json"), REACTOR_AGGREGATOR_SBOM);
    const libaDir = join(root, "liba");
    const appbDir = join(root, "appb");
    const allsiblingsDir = join(root, "allsiblings");
    mkdirSync(libaDir);
    mkdirSync(appbDir);
    mkdirSync(allsiblingsDir);
    writeFileSync(join(libaDir, "maven.sbom.json"), REACTOR_LIBA_SBOM);
    // The ONLY difference from the plain reactor test above: liba also
    // commits a test-inclusive sidecar.
    writeFileSync(
      join(libaDir, "maven.test.sbom.json"),
      REACTOR_LIBA_TEST_SBOM,
    );
    writeFileSync(join(appbDir, "maven.sbom.json"), REACTOR_APPB_SBOM);
    writeFileSync(
      join(allsiblingsDir, "maven.sbom.json"),
      REACTOR_ALLSIBLINGS_SBOM,
    );

    const log: string[] = [];
    const result = await collectTargets(baseOpts(root), (line) => {
      log.push(line);
    });

    // The aggregator pom still skips exactly as before — the counter and
    // coverage arm never see the test doc (they read maven.sbom.json only).
    expect(result.inputs.some((input) => input.targetIdentity === ".")).toBe(
      false,
    );
    expect(
      log.some(
        (line) =>
          line.startsWith("warning: skipping . —") &&
          line.includes("maven.sbom.json has no third-party entries"),
      ),
    ).toBe(true);

    // The target set is unchanged — one target per module, never a second
    // target for the test doc.
    expect(result.inputs.map((input) => input.targetIdentity).sort()).toEqual([
      "allsiblings",
      "appb",
      "liba",
    ]);

    // liba's OWN inventory now carries the composed dual-doc set (its
    // default component plus the test-only addition).
    const libaInput = result.inputs.find(
      (input) => input.targetIdentity === "liba",
    );
    expect(componentPurlsOf(libaInput?.sbom).sort()).toEqual(
      [
        "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
        "pkg:maven/com.example.fixture/junit-fixture@5.0.0?type=jar",
      ].sort(),
    );

    // appb's sibling exclusion is UNCHANGED: liba's purl (from the default
    // doc's own root, the only thing the pre-pass ever reads) still drops
    // out of appb's inventory exactly as in the no-test-doc reactor test.
    const appbInput = result.inputs.find(
      (input) => input.targetIdentity === "appb",
    );
    expect(componentPurlsOf(appbInput?.sbom)).toEqual([
      "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
    ]);

    // allsiblings is untouched by liba's test doc — still collapses to zero.
    const allsiblingsInput = result.inputs.find(
      (input) => input.targetIdentity === "allsiblings",
    );
    expect(componentPurlsOf(allsiblingsInput?.sbom)).toEqual([]);
  });
});

/**
 * appb's test-inclusive sidecar OMITS the sibling (liba) and one third-party
 * dep (commons-lang3): both come back through the composed inventory's
 * residual, and the post-collect filter must still drop the sibling.
 */
const REACTOR_APPB_NON_SUPERSET_TEST_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: { purl: "pkg:maven/com.example.fixture/appb@1.0.0?type=jar" },
  },
  components: [
    {
      purl: "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    },
    {
      purl: "pkg:maven/com.example.fixture/mockito-fixture@4.0.0?type=jar",
      licenses: [{ license: { id: "MIT" } }],
    },
  ],
});

describe("collectTargets — maven reactor: the residual never re-introduces a sibling", () => {
  test("a sibling carried back by the composed inventory's residual is still excluded", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-maven-reactor-res-"));
    const libaDir = join(root, "liba");
    const appbDir = join(root, "appb");
    mkdirSync(libaDir);
    mkdirSync(appbDir);
    writeFileSync(join(libaDir, "maven.sbom.json"), REACTOR_LIBA_SBOM);
    writeFileSync(join(appbDir, "maven.sbom.json"), REACTOR_APPB_SBOM);
    writeFileSync(
      join(appbDir, "maven.test.sbom.json"),
      REACTOR_APPB_NON_SUPERSET_TEST_SBOM,
    );

    const result = await collectTargets(baseOpts(root), () => {});
    const appbInput = result.inputs.find(
      (input) => input.targetIdentity === "appb",
    );
    // liba (the residual-carried sibling) is gone; commons-lang3 (the
    // residual-carried third-party dep) survives; the test-only dep joins.
    expect(componentPurlsOf(appbInput?.sbom).sort()).toEqual(
      [
        "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
        "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
        "pkg:maven/com.example.fixture/mockito-fixture@4.0.0?type=jar",
      ].sort(),
    );
    // The prod purl set (the default doc's own purls) rides the filter spread.
    expect(
      appbInput?.prodPurlSet?.has(
        "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      ),
    ).toBe(true);
  });
});
