/**
 * Unit suite for the custom bun.lock collector.
 *
 * Fixtures are inline string constants derived from the research-verified
 * lockfile shapes in 04.5-RESEARCH.md Pattern 2 ("bun workspace lockfile
 * shape (verified)"): bun.lock is machine-written JSONC (JSON + trailing
 * commas, never comments); packages[key][0] is ALWAYS "name@version" (or
 * "name@workspace:path" for first-party members); nested version-conflict
 * keys ("parent/dep") carry the CORRECT identity in [0] — the trivy failure
 * mode (14% identity corruption) this collector exists to avoid.
 *
 * No subprocess is spawned anywhere here: the collector is fully in-process.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  BUN_COLLECTOR_TOOL,
  bunThirdPartyEntryCount,
  collectWithBunLock,
} from "../src/collectors/bunLock";
import { computeCacheKey } from "../src/collectors/cdxgen";
import { mergeSboms } from "../src/merge/merge";
import type { Target } from "../src/targets/target";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * The research-verified workspace lockfile (04.5-RESEARCH Pattern 2), with
 * the machine-written trailing commas bun emits. 4 packages entries, of
 * which 3 are third-party (libb is the `@workspace:` first-party member).
 */
const WORKSPACE_LOCK = `{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-ws-root",
      "dependencies": { "smol-toml": "1.6.1" },
      "devDependencies": { "typescript": "5.9.3" },
    },
    "packages/libb": {
      "name": "libb",
      "version": "0.1.0",
      "dependencies": { "array-find-index": "1.0.2" },
    },
  },
  "packages": {
    "array-find-index": ["array-find-index@1.0.2", "", {}, "sha512-aaa"],
    "libb": ["libb@workspace:packages/libb"],
    "smol-toml": ["smol-toml@1.6.1", "", {}, "sha512-bbb"],
    "typescript": ["typescript@5.9.3", "", {}, "sha512-ccc"],
  },
}
`;

/**
 * The SAME lockfile content as WORKSPACE_LOCK, serialized as strict JSON
 * (no trailing commas) from an independent object literal — locks the
 * trailing-comma strip as a no-op on real-shape content (research
 * Anti-Patterns: the regex only touches commas directly before closers).
 */
const WORKSPACE_LOCK_PLAIN = JSON.stringify(
  {
    lockfileVersion: 1,
    configVersion: 1,
    workspaces: {
      "": {
        name: "bun-ws-root",
        dependencies: { "smol-toml": "1.6.1" },
        devDependencies: { typescript: "5.9.3" },
      },
      "packages/libb": {
        name: "libb",
        version: "0.1.0",
        dependencies: { "array-find-index": "1.0.2" },
      },
    },
    packages: {
      "array-find-index": ["array-find-index@1.0.2", "", {}, "sha512-aaa"],
      libb: ["libb@workspace:packages/libb"],
      "smol-toml": ["smol-toml@1.6.1", "", {}, "sha512-bbb"],
      typescript: ["typescript@5.9.3", "", {}, "sha512-ccc"],
    },
  },
  null,
  2,
);

/**
 * Scoped name + nested version-conflict key (04.5-RESEARCH Pitfall 4):
 * "spdx-compare/spdx-expression-parse" is a NESTED key whose value[0]
 * carries the correct "spdx-expression-parse@3.0.1" identity. Plain JSON
 * on purpose (a strict-JSON bun.lock must parse identically to JSONC).
 */
const SCOPED_NESTED_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "scoped-root",
      "dependencies": { "spdx-compare": "1.0.0" },
      "devDependencies": { "@types/bun": "1.3.14" }
    }
  },
  "packages": {
    "@types/bun": ["@types/bun@1.3.14", "", {}, "sha512-ddd"],
    "spdx-compare": ["spdx-compare@1.0.0", "", { "dependencies": { "spdx-expression-parse": "^3.0.0" } }, "sha512-eee"],
    "spdx-compare/spdx-expression-parse": ["spdx-expression-parse@3.0.1", "", {}, "sha512-fff"],
    "spdx-expression-parse": ["spdx-expression-parse@4.0.0", "", {}, "sha512-ggg"]
  }
}
`;

/**
 * Malformed individual entries must be skipped tolerantly: non-array value,
 * non-string [0], a spec with no "@" separator,
 * and a scoped name with no version "@" — only "good" survives.
 */
const MALFORMED_ENTRIES_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "tolerant-root" } },
  "packages": {
    "bad-shape": { "not": "an array" },
    "bad-first": [42],
    "no-at-spec": ["noversion"],
    "scope-only": ["@scoped/name"],
    "good": ["good@1.0.0", "", {}, "sha512-hhh"]
  }
}
`;

/**
 * Belt-and-braces first-party exclusion: "libb" appears in packages WITHOUT
 * the @workspace: protocol but IS a workspaces[*].name member — it must
 * still never be emitted (plan must_have: bun first-party exclusion lives
 * in the collector).
 */
const NAME_ONLY_MEMBER_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "belt-root" },
    "packages/libb": { "name": "libb", "version": "0.1.0" }
  },
  "packages": {
    "libb": ["libb@1.0.0", "", {}, "sha512-iii"],
    "smol-toml": ["smol-toml@1.6.1", "", {}, "sha512-bbb"]
  }
}
`;

/**
 * Non-registry resolution protocols: bun.lock stores the resolution string in
 * value[0] for every protocol, and several real protocols embed
 * an "@" inside the version part — a last-"@" split corrupts the name
 * silently (the trivy failure mode on a different input class). The split
 * must happen at the FIRST "@" after the optional leading scope. The
 * build-metadata entry additionally locks the purl version "+" → %2B
 * encoding (IN-02, cdxgen byte-compat).
 */
const NON_REGISTRY_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "proto-root" } },
  "packages": {
    "alias": ["alias@npm:@scope/real@1.2.3", "", {}, "sha512-jjj"],
    "gh-pkg": ["gh-pkg@github:user/repo", "", {}, "sha512-kkk"],
    "meta": ["meta@1.0.0+build.5", "", {}, "sha512-lll"],
    "ssh-pkg": ["ssh-pkg@git+ssh://git@github.com/owner/repo#abc", "", {}, "sha512-mmm"]
  }
}
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Writes the given files into a fresh temp dir and returns it as a Target. */
function makeTargetWithFiles(files: Record<string, string>): Target {
  const dir = mkdtempSync(join(tmpdir(), "licenses-test-"));
  tempDirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return { dir, identity: "test/synthetic" };
}

function makeBunTarget(bunLock: string): Target {
  return makeTargetWithFiles({ "bun.lock": bunLock, "package.json": "{}\n" });
}

function makeOutDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "licenses-test-out-"));
  tempDirs.push(dir);
  return dir;
}

interface ScannedDoc {
  target: Target;
  sbomPath: string;
  cacheKey: string;
  tool: { name: string; version: string };
  raw: string;
  doc: Record<string, unknown>;
  components: Array<Record<string, unknown>>;
}

async function scanLock(bunLock: string): Promise<ScannedDoc> {
  const target = makeBunTarget(bunLock);
  const result = await collectWithBunLock(target, { tempDir: makeOutDir() });
  const raw = readFileSync(result.sbomPath, "utf8");
  const doc = JSON.parse(raw) as Record<string, unknown>;
  const components = (doc["components"] ?? []) as Array<
    Record<string, unknown>
  >;
  return { target, ...result, raw, doc, components };
}

function componentNames(components: Array<Record<string, unknown>>): string[] {
  return components.map((c) => String(c["name"]));
}

// ---------------------------------------------------------------------------
// Tool identity
// ---------------------------------------------------------------------------

describe("BUN_COLLECTOR_TOOL", () => {
  test("identity the CLI prints as name@version", () => {
    expect(BUN_COLLECTOR_TOOL).toEqual({
      name: "bun-lock-collector",
      version: "1",
    });
  });
});

// ---------------------------------------------------------------------------
// bunThirdPartyEntryCount (unknown-vs-zero semantics)
// ---------------------------------------------------------------------------

describe("bunThirdPartyEntryCount", () => {
  test("the verified workspace fixture counts 3 (libb's @workspace: entry excluded)", () => {
    expect(bunThirdPartyEntryCount(WORKSPACE_LOCK)).toBe(3);
  });

  test("plain-JSON bun.lock counts identically to the JSONC variant", () => {
    expect(bunThirdPartyEntryCount(WORKSPACE_LOCK_PLAIN)).toBe(3);
  });

  test("a workspace-only packages section counts 0 (positively determined → warn+skip)", () => {
    const lock = `{
      "lockfileVersion": 1,
      "workspaces": { "": { "name": "ws-only" } },
      "packages": { "liba": ["liba@workspace:packages/liba"] }
    }`;
    expect(bunThirdPartyEntryCount(lock)).toBe(0);
  });

  test("unparseable text returns undefined (unknown → route to scan)", () => {
    expect(bunThirdPartyEntryCount("this is not jsonc {{{")).toBeUndefined();
    expect(bunThirdPartyEntryCount("")).toBeUndefined();
  });

  test("valid JSON without a packages record returns undefined (grammar cannot determine zero)", () => {
    expect(bunThirdPartyEntryCount('{"lockfileVersion": 1}')).toBeUndefined();
  });

  test("malformed entries (non-array, non-string [0]) contribute nothing; unsplittable string specs still count", () => {
    // "bad-shape" and "bad-first" are skipped, but "no-at-spec"/"scope-only"
    // are strings lacking "@workspace:" — they count, so a garbage-spec
    // lockfile routes to scan and hard-fails loudly instead of silently
    // warn+skipping at 0.
    expect(bunThirdPartyEntryCount(MALFORMED_ENTRIES_LOCK)).toBe(3);
  });

  // W2: lockfileVersion/workspaces must be narrowed INDEPENDENTLY of packages.
  // A wrong-typed sibling field that the counter never reads must not zero a
  // valid packages map (which would route a clean run to a fatal exit 3).
  test("a string lockfileVersion alongside a valid packages map still counts the packages", () => {
    const lock = `{
      "lockfileVersion": "1",
      "packages": {
        "express": ["express@4.18.2", {}, "sha"],
        "left-pad": ["left-pad@1.3.0", {}, "sha"]
      }
    }`;
    expect(bunThirdPartyEntryCount(lock)).toBe(2);
  });

  test("an array-valued workspaces alongside a valid packages map still counts the packages", () => {
    const lock = `{
      "lockfileVersion": 1,
      "workspaces": ["a", "b"],
      "packages": {
        "express": ["express@4.18.2", {}, "sha"]
      }
    }`;
    expect(bunThirdPartyEntryCount(lock)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// collectWithBunLock — identity and emission
// ---------------------------------------------------------------------------

describe("collectWithBunLock — identity and emission", () => {
  test("emits a minimal CycloneDX 1.6 document through the unchanged parse path", async () => {
    const { doc } = await scanLock(WORKSPACE_LOCK);
    expect(doc["bomFormat"]).toBe("CycloneDX");
    expect(doc["specVersion"]).toBe("1.6");
    expect(Array.isArray(doc["components"])).toBe(true);
  });

  test("identity comes from packages[key][0]: name, version, purl", async () => {
    const { components } = await scanLock(WORKSPACE_LOCK);
    const afi = components.find((c) => c["name"] === "array-find-index");
    expect(afi).toMatchObject({
      type: "library",
      name: "array-find-index",
      version: "1.0.2",
      purl: "pkg:npm/array-find-index@1.0.2",
    });
  });

  test("scoped names split at the version @ and encode the scope as %40 (cdxgen byte-compat)", async () => {
    const { components } = await scanLock(SCOPED_NESTED_LOCK);
    const scoped = components.find((c) => c["name"] === "@types/bun");
    expect(scoped).toMatchObject({
      name: "@types/bun",
      version: "1.3.14",
      purl: "pkg:npm/%40types/bun@1.3.14",
    });
  });

  test("nested conflict keys yield identity from value[0], NEVER the key (the trivy failure mode)", async () => {
    const { components } = await scanLock(SCOPED_NESTED_LOCK);
    // No component may carry the nested KEY as its name.
    expect(
      componentNames(components).includes("spdx-compare/spdx-expression-parse"),
    ).toBe(false);
    // The nested entry resolves to the same purl as a top-level twin would
    // (the 3-nested-entries-to-1-purl fold happens at merge, not here).
    const v301 = components.filter(
      (c) => c["purl"] === "pkg:npm/spdx-expression-parse@3.0.1",
    );
    expect(v301).toHaveLength(1);
    expect(v301[0]).toMatchObject({
      name: "spdx-expression-parse",
      version: "3.0.1",
    });
    // The top-level entry of the other version is also present.
    expect(
      components.some(
        (c) => c["purl"] === "pkg:npm/spdx-expression-parse@4.0.0",
      ),
    ).toBe(true);
  });

  test("@workspace: entries are never emitted", async () => {
    const { components } = await scanLock(WORKSPACE_LOCK);
    expect(componentNames(components)).toEqual([
      "array-find-index",
      "smol-toml",
      "typescript",
    ]);
  });

  test("workspaces[*].name members are never emitted even without the @workspace: protocol (belt-and-braces)", async () => {
    const { components } = await scanLock(NAME_ONLY_MEMBER_LOCK);
    expect(componentNames(components)).toEqual(["smol-toml"]);
  });

  test("malformed individual entries are skipped silently (tolerant walk)", async () => {
    const { components } = await scanLock(MALFORMED_ENTRIES_LOCK);
    expect(componentNames(components)).toEqual(["good"]);
    expect(components[0]).toMatchObject({
      name: "good",
      version: "1.0.0",
      purl: "pkg:npm/good@1.0.0",
    });
  });

  test("git-over-ssh resolutions keep the package name intact (split at the first @)", async () => {
    const { components } = await scanLock(NON_REGISTRY_LOCK);
    const ssh = components.find((c) => c["name"] === "ssh-pkg");
    expect(ssh).toMatchObject({
      name: "ssh-pkg",
      version: "git+ssh://git@github.com/owner/repo#abc",
      purl: "pkg:npm/ssh-pkg@git%2Bssh://git@github.com/owner/repo#abc",
    });
  });

  test("npm aliases of scoped packages keep the alias name intact", async () => {
    const { components } = await scanLock(NON_REGISTRY_LOCK);
    const alias = components.find((c) => c["name"] === "alias");
    expect(alias).toMatchObject({
      name: "alias",
      version: "npm:@scope/real@1.2.3",
      purl: "pkg:npm/alias@npm:@scope/real@1.2.3",
    });
  });

  test("plain github: protocol resolutions split unchanged", async () => {
    const { components } = await scanLock(NON_REGISTRY_LOCK);
    const gh = components.find((c) => c["name"] === "gh-pkg");
    expect(gh).toMatchObject({
      name: "gh-pkg",
      version: "github:user/repo",
      purl: "pkg:npm/gh-pkg@github:user/repo",
    });
  });

  test("build-metadata versions percent-encode + as %2B in the purl (IN-02 cdxgen byte-compat)", async () => {
    const { components } = await scanLock(NON_REGISTRY_LOCK);
    const meta = components.find((c) => c["name"] === "meta");
    expect(meta).toMatchObject({
      name: "meta",
      version: "1.0.0+build.5",
      purl: "pkg:npm/meta@1.0.0%2Bbuild.5",
    });
  });
});

// ---------------------------------------------------------------------------
// collectWithBunLock — determinism
// ---------------------------------------------------------------------------

describe("collectWithBunLock — determinism", () => {
  test("raw bytes carry NO serialNumber and NO timestamp", async () => {
    const { raw } = await scanLock(WORKSPACE_LOCK);
    expect(raw.includes("serialNumber")).toBe(false);
    expect(raw.includes("timestamp")).toBe(false);
  });

  test("components are sorted compareCodeUnits by purl", async () => {
    const { components } = await scanLock(SCOPED_NESTED_LOCK);
    const purls = components.map((c) => String(c["purl"]));
    const sorted = [...purls].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(purls).toEqual(sorted);
  });

  test("two runs over the same lockfile produce byte-identical bom.json", async () => {
    const first = await scanLock(WORKSPACE_LOCK);
    const second = await scanLock(WORKSPACE_LOCK);
    expect(first.raw).toBe(second.raw);
  });

  test("JSONC (trailing commas) and strict JSON of the same content emit identical bytes", async () => {
    const jsonc = await scanLock(WORKSPACE_LOCK);
    const plain = await scanLock(WORKSPACE_LOCK_PLAIN);
    expect(jsonc.raw).toBe(plain.raw);
  });

  test("the serialized document ends with a trailing LF", async () => {
    const { raw } = await scanLock(WORKSPACE_LOCK);
    expect(raw.endsWith("\n")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// collectWithBunLock — CollectorSbomFile contract + cache key
// ---------------------------------------------------------------------------

describe("collectWithBunLock — contract and cache key", () => {
  test("returns { sbomPath, cacheKey, tool } with bom.json inside the given temp dir", async () => {
    const target = makeBunTarget(WORKSPACE_LOCK);
    const outDir = makeOutDir();
    const result = await collectWithBunLock(target, { tempDir: outDir });
    expect(result.sbomPath).toBe(join(outDir, "bom.json"));
    expect(result.tool).toEqual(BUN_COLLECTOR_TOOL);
    expect(typeof result.cacheKey).toBe("string");
  });

  test("cacheKey reuses computeCacheKey with the locked framing (bun-collector-v1 + bun.lock/package.json)", async () => {
    const target = makeBunTarget(WORKSPACE_LOCK);
    const result = await collectWithBunLock(target, { tempDir: makeOutDir() });
    expect(result.cacheKey).toBe(
      computeCacheKey(
        target,
        BUN_COLLECTOR_TOOL,
        ["bun-collector-v1"],
        ["bun.lock", "package.json"],
      ),
    );
  });

  test("missing package.json throws the target.ts-shaped error (from computeCacheKey)", async () => {
    const target = makeTargetWithFiles({ "bun.lock": WORKSPACE_LOCK });
    await expect(
      collectWithBunLock(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/missing package\.json/);
  });
});

// ---------------------------------------------------------------------------
// collectWithBunLock — loud failure modes
// ---------------------------------------------------------------------------

describe("collectWithBunLock — failure modes", () => {
  test("oversized bun.lock fails loudly naming path, size, and cap BEFORE any parse", async () => {
    const cap = 32 * 1024 * 1024;
    // One byte over the cap; content deliberately VALID JSON-adjacent so a
    // failure can only come from the size gate, not the parser.
    const oversize = `{${" ".repeat(cap)}}`;
    const target = makeBunTarget(oversize);
    expect.assertions(3);
    try {
      await collectWithBunLock(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain(join(target.dir, "bun.lock"));
      expect(message).toContain(String(cap + 2)); // actual size
      expect(message).toContain(String(cap)); // the cap
    }
  });

  test("non-JSONC garbage fails loudly naming the path (the scan-failure path)", async () => {
    const target = makeBunTarget("this is not jsonc {{{");
    expect.assertions(2);
    try {
      await collectWithBunLock(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("not valid JSONC");
      expect(message).toContain(join(target.dir, "bun.lock"));
    }
  });
});

// ---------------------------------------------------------------------------
// collectWithBunLock — transitive dev/prod scope BFS (research MEDIUM A4)
//
// These fixtures land BEFORE the algorithm (the plan's fixture-first lock):
// dev scope = BFS from importer dev roots with prod-wins, mirroring cdxgen's
// _markTreeDevelopment semantics (source-verified in 04.5-RESEARCH); the
// conservative direction is unmarked → prod (A4).
// ---------------------------------------------------------------------------

/** The exact property string merge.ts propertyDevMarker consumes. */
const DEV_PROPERTY = "cdx:npm:package:development";

function isDevMarked(component: Record<string, unknown>): boolean {
  const properties = component["properties"];
  if (!Array.isArray(properties)) return false;
  return properties.some((raw) => {
    const property = raw as Record<string, unknown>;
    return property["name"] === DEV_PROPERTY && property["value"] === "true";
  });
}

function byPurl(
  components: Array<Record<string, unknown>>,
  purl: string,
): Record<string, unknown> {
  const found = components.find((c) => c["purl"] === purl);
  if (found === undefined) throw new Error(`no component with purl ${purl}`);
  return found;
}

/**
 * Transitive propagation: a dev root with transitives (one edge via
 * optionalDependencies in the entry metadata) → all dev; "shared" is
 * reachable from BOTH the prod root and the dev root → prod (prod wins).
 */
const TRANSITIVE_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "transitive-root",
      "dependencies": { "keep-prod": "1.0.0" },
      "devDependencies": { "dev-root": "1.0.0" }
    }
  },
  "packages": {
    "dev-leaf": ["dev-leaf@1.0.0", "", {}, "sha512-1"],
    "dev-opt-leaf": ["dev-opt-leaf@1.0.0", "", {}, "sha512-2"],
    "dev-root": ["dev-root@1.0.0", "", { "dependencies": { "dev-leaf": "1.0.0", "shared": "1.0.0" }, "optionalDependencies": { "dev-opt-leaf": "1.0.0" } }, "sha512-3"],
    "keep-prod": ["keep-prod@1.0.0", "", { "dependencies": { "shared": "1.0.0" } }, "sha512-4"],
    "shared": ["shared@1.0.0", "", {}, "sha512-5"]
  }
}
`;

/**
 * Hoisting lookup (research Pattern 2): the nested conflict entry
 * "dev-parent/shared-dep" must be reached via the parent-prefixed lookup
 * BEFORE the bare "shared-dep"; its deps then resolve through
 * progressively shorter parent prefixes ("dev-parent/inner").
 */
const HOISTING_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "hoist-root",
      "dependencies": { "prod-parent": "1.0.0" },
      "devDependencies": { "dev-parent": "1.0.0" }
    }
  },
  "packages": {
    "dev-parent": ["dev-parent@1.0.0", "", { "dependencies": { "shared-dep": "^2.0.0" } }, "sha512-6"],
    "dev-parent/inner": ["inner@9.9.9", "", {}, "sha512-8"],
    "dev-parent/shared-dep": ["shared-dep@2.0.0", "", { "dependencies": { "inner": "1.0.0" } }, "sha512-7"],
    "prod-parent": ["prod-parent@1.0.0", "", { "dependencies": { "shared-dep": "^1.0.0" } }, "sha512-9"],
    "shared-dep": ["shared-dep@1.0.0", "", {}, "sha512-10"]
  }
}
`;

/**
 * Prod roots include optionalDependencies and peerDependencies of every
 * importer — and they win over a dev path reaching the same packages.
 */
const PROD_ROOTS_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "roots-root",
      "optionalDependencies": { "opt-pkg": "1.0.0" },
      "peerDependencies": { "peer-pkg": "1.0.0" },
      "devDependencies": { "dev-pkg": "1.0.0" }
    }
  },
  "packages": {
    "dev-pkg": ["dev-pkg@1.0.0", "", { "dependencies": { "opt-pkg": "1.0.0", "peer-pkg": "1.0.0" } }, "sha512-15"],
    "opt-pkg": ["opt-pkg@1.0.0", "", {}, "sha512-16"],
    "peer-pkg": ["peer-pkg@1.0.0", "", {}, "sha512-17"]
  }
}
`;

/** Unknown dep names (no packages entry at any lookup) are silent leaves. */
const UNKNOWN_LEAF_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "ghost-root", "devDependencies": { "ghost": "1.0.0", "real-dev": "1.0.0" } }
  },
  "packages": {
    "orphan": ["orphan@1.0.0", "", {}, "sha512-11"],
    "real-dev": ["real-dev@1.0.0", "", { "dependencies": { "ghost-transitive": "1.0.0" } }, "sha512-12"]
  }
}
`;

/**
 * Scope-boundary hoisting: the dev root "@scope/pkg" has a bare dep "y". A raw
 * path-segment prefix walk would shorten "@scope/pkg" to the
 * lone scope "@scope" and resolve "y" to the UNRELATED top-level package
 * "@scope/y" (wrongly dev-marking it, while the real "y" stays unvisited).
 * Shortening by whole package names must resolve to the bare "y".
 */
const SCOPE_BOUNDARY_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "scope-root", "devDependencies": { "@scope/pkg": "1.0.0" } }
  },
  "packages": {
    "@scope/pkg": ["@scope/pkg@1.0.0", "", { "dependencies": { "y": "1.0.0" } }, "sha512-18"],
    "@scope/y": ["@scope/y@1.0.0", "", {}, "sha512-19"],
    "y": ["y@1.0.0", "", {}, "sha512-20"]
  }
}
`;

/**
 * POL-08 prod-fail-masking regression. A transitive ("twin") reached at the
 * SAME version via BOTH a production parent and a dev-only parent, while the
 * top-level slot is held by a different version (twin@2.0.0 as a direct prod
 * dep) — so twin@1.0.0 cannot hoist and appears as two nested conflict keys
 * "prod-parent/twin" (prod-reached) and "dev-parent/twin" (dev-reached). The
 * collector emits TWO components for pkg:npm/twin@1.0.0 with divergent dev
 * markers; the merge MUST fold them prod-wins so the shipped (production)
 * occurrence is never masked to dev. This is the exact reachable shape behind
 * the load-bearing POL-08 safety property.
 */
const SAME_VERSION_TWIN_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "twin-root",
      "dependencies": { "prod-parent": "1.0.0", "twin": "2.0.0" },
      "devDependencies": { "dev-parent": "1.0.0" }
    }
  },
  "packages": {
    "dev-parent": ["dev-parent@1.0.0", "", { "dependencies": { "twin": "^1.0.0" } }, "sha512-t1"],
    "dev-parent/twin": ["twin@1.0.0", "", {}, "sha512-t2"],
    "prod-parent": ["prod-parent@1.0.0", "", { "dependencies": { "twin": "^1.0.0" } }, "sha512-t3"],
    "prod-parent/twin": ["twin@1.0.0", "", {}, "sha512-t4"],
    "twin": ["twin@2.0.0", "", {}, "sha512-t5"]
  }
}
`;

/** A dependency cycle must terminate (visited set — DoS bound). */
const CYCLE_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "cycle-root", "devDependencies": { "cyc-a": "1.0.0" } } },
  "packages": {
    "cyc-a": ["cyc-a@1.0.0", "", { "dependencies": { "cyc-b": "1.0.0" } }, "sha512-13"],
    "cyc-b": ["cyc-b@1.0.0", "", { "dependencies": { "cyc-a": "1.0.0" } }, "sha512-14"]
  }
}
`;

describe("collectWithBunLock — transitive dev/prod scope BFS (research A4)", () => {
  test("workspace fixture: typescript dev; smol-toml and array-find-index (via the libb member importer) prod", async () => {
    const { components } = await scanLock(WORKSPACE_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/typescript@5.9.3"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/smol-toml@1.6.1"))).toBe(
      false,
    );
    expect(
      isDevMarked(byPurl(components, "pkg:npm/array-find-index@1.0.2")),
    ).toBe(false);
  });

  test("same-version twin via a prod AND a dev parent emits divergent same-purl components that merge prod-wins (POL-08 safety)", async () => {
    const { components, doc } = await scanLock(SAME_VERSION_TWIN_LOCK);

    // Collector origin: twin@1.0.0 surfaces as TWO components (the two nested
    // conflict keys) — exactly one dev-marked, one not.
    const twins = components.filter((c) => c["purl"] === "pkg:npm/twin@1.0.0");
    expect(twins.length).toBe(2);
    expect(twins.filter(isDevMarked).length).toBe(1);

    // Merge safety: the production occurrence wins — the folded occurrence is
    // production, so a shipped copyleft/unknown on twin@1.0.0 can never be
    // dev-downgraded out of the gate.
    const model = mergeSboms([{ sbom: doc, targetIdentity: "." }]);
    const twin = model.packages.find((p) => p.purl === "pkg:npm/twin@1.0.0");
    expect(twin?.occurrences).toEqual([
      { target: ".", isDevDependency: false },
    ]);
  });

  test("dev components carry exactly the merge-consumed property; prod components carry none", async () => {
    const { components } = await scanLock(WORKSPACE_LOCK);
    expect(
      byPurl(components, "pkg:npm/typescript@5.9.3")["properties"],
    ).toEqual([{ name: DEV_PROPERTY, value: "true" }]);
    expect(
      byPurl(components, "pkg:npm/smol-toml@1.6.1")["properties"],
    ).toBeUndefined();
  });

  test("transitive deps of a dev root are dev-marked, including optionalDependencies edges", async () => {
    const { components } = await scanLock(TRANSITIVE_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/dev-root@1.0.0"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/dev-leaf@1.0.0"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/dev-opt-leaf@1.0.0"))).toBe(
      true,
    );
  });

  test("a package reachable from BOTH a prod root and a dev root stays prod (prod wins)", async () => {
    const { components } = await scanLock(TRANSITIVE_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/keep-prod@1.0.0"))).toBe(
      false,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/shared@1.0.0"))).toBe(false);
  });

  test("nested conflict entries are reached via the parent-prefixed lookup and follow the parent's path", async () => {
    const { components } = await scanLock(HOISTING_LOCK);
    // The nested entry under the dev parent is dev …
    expect(isDevMarked(byPurl(components, "pkg:npm/shared-dep@2.0.0"))).toBe(
      true,
    );
    // … while the top-level twin name at another version, reached from the
    // prod parent via the bare fallback, stays prod.
    expect(isDevMarked(byPurl(components, "pkg:npm/shared-dep@1.0.0"))).toBe(
      false,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/dev-parent@1.0.0"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/prod-parent@1.0.0"))).toBe(
      false,
    );
  });

  test("dep edges resolve through progressively shorter parent prefixes", async () => {
    const { components } = await scanLock(HOISTING_LOCK);
    // "inner" is depended on by "dev-parent/shared-dep"; no
    // "dev-parent/shared-dep/inner" key exists, so the walk falls back to
    // the shorter prefix "dev-parent/inner" — still on the dev path.
    expect(isDevMarked(byPurl(components, "pkg:npm/inner@9.9.9"))).toBe(true);
  });

  test("prod roots include optionalDependencies and peerDependencies of every importer", async () => {
    const { components } = await scanLock(PROD_ROOTS_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/opt-pkg@1.0.0"))).toBe(
      false,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/peer-pkg@1.0.0"))).toBe(
      false,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/dev-pkg@1.0.0"))).toBe(true);
  });

  test("unknown dep names are leaves; unvisited packages stay prod (conservative A4)", async () => {
    const { components } = await scanLock(UNKNOWN_LEAF_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/real-dev@1.0.0"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/orphan@1.0.0"))).toBe(false);
  });

  test("dependency cycles terminate (visited set — DoS bound)", async () => {
    const { components } = await scanLock(CYCLE_LOCK);
    expect(isDevMarked(byPurl(components, "pkg:npm/cyc-a@1.0.0"))).toBe(true);
    expect(isDevMarked(byPurl(components, "pkg:npm/cyc-b@1.0.0"))).toBe(true);
  });

  test("hoisting never crosses a scope-name boundary: bare dep of @scope/pkg resolves to y, not @scope/y", async () => {
    const { components } = await scanLock(SCOPE_BOUNDARY_LOCK);
    // The dev root and its REAL bare dep are dev-marked …
    expect(isDevMarked(byPurl(components, "pkg:npm/%40scope/pkg@1.0.0"))).toBe(
      true,
    );
    expect(isDevMarked(byPurl(components, "pkg:npm/y@1.0.0"))).toBe(true);
    // … and the unrelated scope sibling stays prod (unvisited, A4).
    expect(isDevMarked(byPurl(components, "pkg:npm/%40scope/y@1.0.0"))).toBe(
      false,
    );
  });
});
