/**
 * Unit suite for the custom packages.lock.json (NuGet) collector.
 *
 * Fixtures are inline string constants matching the lockfile shapes
 * `dotnet restore` writes with RestorePackagesWithLockFile=true: version 1
 * or 2 documents whose `dependencies` map holds one section per target
 * framework (and per `<tfm>/<rid>` pair when runtime identifiers are set);
 * every entry carries `type` (Direct | Transitive | Project |
 * CentralTransitive) and — except for first-party Project references — a
 * `resolved` exact version. Restore normalizes package ids in the lock to
 * their canonical registry casing, so the emitted purls keep the lock keys
 * VERBATIM; lowercasing anywhere here would break cross-target dedup.
 *
 * No subprocess is spawned anywhere here: the collector is fully in-process.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { computeCacheKey } from "../src/collectors/cdxgen";
import {
  collectWithNugetLock,
  NUGET_COLLECTOR_TOOL,
} from "../src/collectors/nugetLock";
import { collectors } from "../src/collectors/registry";
import type { Target } from "../src/targets/target";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * A version-1 single-project lock: two Direct entries, one plain Transitive,
 * and one `runtime.*` RID package (a real Transitive entry — RID-specific
 * native shims are honest inventory, never filtered). Mixed-case ids lock
 * the casing-verbatim contract.
 */
const V1_LOCK = `{
  "version": 1,
  "dependencies": {
    "net9.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.4, )",
        "resolved": "13.0.4",
        "contentHash": "sha512-aaa"
      },
      "Serilog": {
        "type": "Direct",
        "requested": "[4.3.1, )",
        "resolved": "4.3.1",
        "contentHash": "sha512-bbb"
      },
      "Microsoft.NETCore.Platforms": {
        "type": "Transitive",
        "resolved": "1.1.0",
        "contentHash": "sha512-ccc"
      },
      "runtime.native.System": {
        "type": "Transitive",
        "resolved": "4.3.0",
        "contentHash": "sha512-ddd"
      }
    }
  }
}
`;

/**
 * A version-2 central-package-management lock: CPM writes "version": 2 and
 * pins transitives as CentralTransitive entries (third-party — they emit
 * like Transitive). The Project entry is the fixture-observed first-party
 * shape: lowercased id, no resolved version.
 */
const V2_CPM_LOCK = `{
  "version": 2,
  "dependencies": {
    "net9.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.4, )",
        "resolved": "13.0.4",
        "contentHash": "sha512-aaa"
      },
      "Microsoft.Extensions.Logging": {
        "type": "CentralTransitive",
        "requested": "[9.0.9, )",
        "resolved": "9.0.9",
        "contentHash": "sha512-eee"
      },
      "fixture.lib": {
        "type": "Project"
      }
    }
  }
}
`;

/**
 * Multi-section lock: two TFM sections plus one `<tfm>/<rid>` section. The
 * same (id, resolved) pair repeats across all three sections (emits ONCE);
 * one id resolves to two DIFFERENT versions across sections (emits TWICE).
 */
const MULTI_SECTION_LOCK = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Shared.Package": {
        "type": "Direct",
        "requested": "[1.0.0, )",
        "resolved": "1.0.0",
        "contentHash": "sha512-1"
      },
      "Multi.Version": {
        "type": "Transitive",
        "resolved": "1.0.0",
        "contentHash": "sha512-2"
      }
    },
    "net9.0": {
      "Shared.Package": {
        "type": "Direct",
        "requested": "[1.0.0, )",
        "resolved": "1.0.0",
        "contentHash": "sha512-1"
      },
      "Multi.Version": {
        "type": "Transitive",
        "resolved": "2.0.0",
        "contentHash": "sha512-3"
      }
    },
    "net9.0/win-x64": {
      "Shared.Package": {
        "type": "Transitive",
        "resolved": "1.0.0",
        "contentHash": "sha512-1"
      },
      "runtime.win-x64.native.Shim": {
        "type": "Transitive",
        "resolved": "4.3.0",
        "contentHash": "sha512-4"
      }
    }
  }
}
`;

/**
 * The SAME content as V1_LOCK with every JSON key order permuted (top-level,
 * section, and entry keys). The emit sorts by purl AFTER the walk, so input
 * key order must be byte-irrelevant.
 */
const V1_LOCK_PERMUTED = `{
  "dependencies": {
    "net9.0": {
      "runtime.native.System": {
        "contentHash": "sha512-ddd",
        "resolved": "4.3.0",
        "type": "Transitive"
      },
      "Serilog": {
        "resolved": "4.3.1",
        "contentHash": "sha512-bbb",
        "requested": "[4.3.1, )",
        "type": "Direct"
      },
      "Microsoft.NETCore.Platforms": {
        "resolved": "1.1.0",
        "type": "Transitive",
        "contentHash": "sha512-ccc"
      },
      "Newtonsoft.Json": {
        "contentHash": "sha512-aaa",
        "requested": "[13.0.4, )",
        "type": "Direct",
        "resolved": "13.0.4"
      }
    }
  },
  "version": 1
}
`;

/**
 * Tolerant-walk fixture: an UNKNOWN entry type (must emit — exclusion is
 * `type === "Project"` only, so an unrecognized type can never silently drop
 * a real dependency), malformed entries (non-object value, missing/empty
 * `resolved` on non-Project entries — skipped silently), a non-record
 * section value (skipped whole), and a build-metadata version locking the
 * purl "+" → %2B encoding.
 */
const TOLERANT_LOCK = `{
  "version": 1,
  "dependencies": {
    "net9.0": {
      "Future.Kind": {
        "type": "SomeNewType",
        "resolved": "1.2.3",
        "contentHash": "sha512-5"
      },
      "No.Resolved": {
        "type": "Transitive"
      },
      "Bad.Entry": "not an object",
      "Empty.Resolved": {
        "type": "Transitive",
        "resolved": ""
      },
      "Meta.Package": {
        "type": "Transitive",
        "resolved": "1.0.0+build.5",
        "contentHash": "sha512-6"
      },
      "Good.Package": {
        "type": "Transitive",
        "resolved": "2.0.0",
        "contentHash": "sha512-7"
      }
    },
    "bad-section": "not a record"
  }
}
`;

/** An unsupported lock format version must throw naming it. */
const V3_LOCK = `{
  "version": 3,
  "dependencies": {
    "net9.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.4, )",
        "resolved": "13.0.4",
        "contentHash": "sha512-aaa"
      }
    }
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

function makeNugetTarget(lock: string): Target {
  return makeTargetWithFiles({ "packages.lock.json": lock });
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

async function scanLock(lock: string): Promise<ScannedDoc> {
  const target = makeNugetTarget(lock);
  const result = await collectWithNugetLock(target, { tempDir: makeOutDir() });
  const raw = readFileSync(result.sbomPath, "utf8");
  const doc = JSON.parse(raw) as Record<string, unknown>;
  const components = (doc["components"] ?? []) as Array<
    Record<string, unknown>
  >;
  return { target, ...result, raw, doc, components };
}

function componentPurls(components: Array<Record<string, unknown>>): string[] {
  return components.map((c) => String(c["purl"]));
}

// ---------------------------------------------------------------------------
// Determinism (the load-bearing contract — written first)
// ---------------------------------------------------------------------------

describe("collectWithNugetLock — determinism", () => {
  test("two runs over the same lockfile produce byte-identical bom.json", async () => {
    const first = await scanLock(V1_LOCK);
    const second = await scanLock(V1_LOCK);
    expect(first.raw).toBe(second.raw);
  });

  test("the document is exactly { bomFormat, specVersion, components } with no volatile fields", async () => {
    const { doc, raw } = await scanLock(V1_LOCK);
    expect(Object.keys(doc)).toEqual([
      "bomFormat",
      "specVersion",
      "components",
    ]);
    expect(doc["bomFormat"]).toBe("CycloneDX");
    expect(doc["specVersion"]).toBe("1.6");
    expect(raw.includes("serialNumber")).toBe(false);
    expect(raw.includes("timestamp")).toBe(false);
  });

  test("components are sorted compareCodeUnits by purl", async () => {
    const { components } = await scanLock(MULTI_SECTION_LOCK);
    const purls = componentPurls(components);
    const sorted = [...purls].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(purls).toEqual(sorted);
  });

  test("a key-order-permuted lock emits byte-identical output (sort happens after the walk)", async () => {
    const original = await scanLock(V1_LOCK);
    const permuted = await scanLock(V1_LOCK_PERMUTED);
    expect(permuted.raw).toBe(original.raw);
  });

  test("the serialized document ends with a trailing LF", async () => {
    const { raw } = await scanLock(V1_LOCK);
    expect(raw.endsWith("\n")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tool identity
// ---------------------------------------------------------------------------

describe("NUGET_COLLECTOR_TOOL", () => {
  test("identity the CLI prints as name@version", () => {
    expect(NUGET_COLLECTOR_TOOL).toEqual({
      name: "nuget-lock-collector",
      version: "1",
    });
  });
});

// ---------------------------------------------------------------------------
// collectWithNugetLock — identity and emission
// ---------------------------------------------------------------------------

describe("collectWithNugetLock — identity and emission", () => {
  test("a v1 lock emits exactly its non-Project entries as pkg:nuget purls", async () => {
    const { components } = await scanLock(V1_LOCK);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Microsoft.NETCore.Platforms@1.1.0",
      "pkg:nuget/Newtonsoft.Json@13.0.4",
      "pkg:nuget/Serilog@4.3.1",
      "pkg:nuget/runtime.native.System@4.3.0",
    ]);
  });

  test("id casing is VERBATIM from the lock key; version is resolved, never requested", async () => {
    const { components } = await scanLock(V1_LOCK);
    const json = components.find((c) => c["name"] === "Newtonsoft.Json");
    expect(json).toMatchObject({
      type: "library",
      name: "Newtonsoft.Json",
      version: "13.0.4",
      purl: "pkg:nuget/Newtonsoft.Json@13.0.4",
    });
    // The Direct entry's requested range never leaks into any component.
    expect(componentPurls(components).some((p) => p.includes("["))).toBe(false);
  });

  test("a v2 CPM lock emits Direct and CentralTransitive entries alike", async () => {
    const { components } = await scanLock(V2_CPM_LOCK);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Microsoft.Extensions.Logging@9.0.9",
      "pkg:nuget/Newtonsoft.Json@13.0.4",
    ]);
  });

  test("type Project entries are excluded — no version-less first-party purl ever exists", async () => {
    const { components, raw } = await scanLock(V2_CPM_LOCK);
    expect(components.some((c) => c["name"] === "fixture.lib")).toBe(false);
    expect(raw.includes("fixture.lib")).toBe(false);
  });

  test("an UNKNOWN entry type emits (exclusion is type === 'Project' only)", async () => {
    const { components } = await scanLock(TOLERANT_LOCK);
    expect(componentPurls(components)).toContain("pkg:nuget/Future.Kind@1.2.3");
  });

  test("distinct (id, resolved) pairs across ALL sections emit once each; a two-version id emits twice", async () => {
    const { components } = await scanLock(MULTI_SECTION_LOCK);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Multi.Version@1.0.0",
      "pkg:nuget/Multi.Version@2.0.0",
      "pkg:nuget/Shared.Package@1.0.0",
      "pkg:nuget/runtime.win-x64.native.Shim@4.3.0",
    ]);
  });

  test("malformed entries and non-record sections are skipped silently (tolerant walk)", async () => {
    const { components } = await scanLock(TOLERANT_LOCK);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Future.Kind@1.2.3",
      "pkg:nuget/Good.Package@2.0.0",
      "pkg:nuget/Meta.Package@1.0.0%2Bbuild.5",
    ]);
  });

  test("build-metadata versions percent-encode + as %2B in the purl", async () => {
    const { components } = await scanLock(TOLERANT_LOCK);
    const meta = components.find((c) => c["name"] === "Meta.Package");
    expect(meta).toMatchObject({
      name: "Meta.Package",
      version: "1.0.0+build.5",
      purl: "pkg:nuget/Meta.Package@1.0.0%2Bbuild.5",
    });
  });

  // The four tests below pin behaviors a review pass questioned; nothing
  // earlier covered them.

  test("a RID-ONLY section (no plain TFM twin) still emits its entries — completeness never keys on section names", async () => {
    const lock = JSON.stringify({
      version: 2,
      dependencies: {
        "net9.0/win-x64": {
          "Rid.Only": { type: "Transitive", resolved: "1.0.0" },
        },
      },
    });
    const { components } = await scanLock(lock);
    expect(componentPurls(components)).toEqual(["pkg:nuget/Rid.Only@1.0.0"]);
  });

  test("a CentralTransitive-ONLY lock emits its full set (no entry type is load-bearing for completeness)", async () => {
    const lock = JSON.stringify({
      version: 2,
      dependencies: {
        "net9.0": {
          "Cpm.A": { type: "CentralTransitive", resolved: "1.0.0" },
          "Cpm.B": { type: "CentralTransitive", resolved: "2.0.0" },
        },
      },
    });
    const { components } = await scanLock(lock);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Cpm.A@1.0.0",
      "pkg:nuget/Cpm.B@2.0.0",
    ]);
  });

  test("a Unicode id (illegal per the NuGet grammar — a hostile lock) emits VERBATIM, never crashes and never re-encodes", async () => {
    const lock = JSON.stringify({
      version: 2,
      dependencies: {
        "net9.0": {
          "Ünïcode.Päckage": { type: "Direct", resolved: "1.0.0" },
        },
      },
    });
    const { components } = await scanLock(lock);
    expect(componentPurls(components)).toEqual([
      "pkg:nuget/Ünïcode.Päckage@1.0.0",
    ]);
  });

  test("a THIRD-PARTY entry sharing a Project entry's id (another section) SURVIVES — exclusion is per-entry by type, never by name", async () => {
    const lock = JSON.stringify({
      version: 2,
      dependencies: {
        "net8.0": { "Shared.Name": { type: "Project" } },
        "net9.0": {
          "Shared.Name": { type: "Direct", resolved: "1.0.0" },
        },
      },
    });
    const { components } = await scanLock(lock);
    expect(componentPurls(components)).toEqual(["pkg:nuget/Shared.Name@1.0.0"]);
  });
});

// ---------------------------------------------------------------------------
// Registry contract (honest omission + internal first-party exclusion)
// ---------------------------------------------------------------------------

describe("nuget registry collector — CollectedSbom shape", () => {
  test("returns { sbom, targetIdentity } ONLY: no prodPurlSet, no firstPartyNames", async () => {
    const target = makeNugetTarget(V2_CPM_LOCK);
    const collector = collectors.get("nuget");
    expect(collector).toBeDefined();
    const result = await collector!.collect(
      { ...target, lockfile: "nuget" },
      {
        timeoutMs: 0,
        verbose: false,
        log: () => {},
      },
    );
    expect(Object.keys(result).sort()).toEqual(["sbom", "targetIdentity"]);
    expect("prodPurlSet" in result).toBe(false);
    expect("firstPartyNames" in result).toBe(false);
    expect(result.targetIdentity).toBe(target.identity);
  });
});

// ---------------------------------------------------------------------------
// collectWithNugetLock — CollectorSbomFile contract + cache key
// ---------------------------------------------------------------------------

describe("collectWithNugetLock — contract and cache key", () => {
  test("returns { sbomPath, cacheKey, tool } with bom.json inside the given temp dir", async () => {
    const target = makeNugetTarget(V1_LOCK);
    const outDir = makeOutDir();
    const result = await collectWithNugetLock(target, { tempDir: outDir });
    expect(result.sbomPath).toBe(join(outDir, "bom.json"));
    expect(result.tool).toEqual(NUGET_COLLECTOR_TOOL);
    expect(typeof result.cacheKey).toBe("string");
  });

  test("cacheKey reuses computeCacheKey with the locked framing (nuget-collector-v1 + packages.lock.json only)", async () => {
    const target = makeNugetTarget(V1_LOCK);
    const result = await collectWithNugetLock(target, {
      tempDir: makeOutDir(),
    });
    expect(result.cacheKey).toBe(
      computeCacheKey(
        target,
        NUGET_COLLECTOR_TOOL,
        ["nuget-collector-v1"],
        ["packages.lock.json"],
      ),
    );
  });
});

// ---------------------------------------------------------------------------
// collectWithNugetLock — loud failure modes
// ---------------------------------------------------------------------------

describe("collectWithNugetLock — failure modes", () => {
  test("missing packages.lock.json throws the target.ts-shaped error", async () => {
    const target = makeTargetWithFiles({});
    await expect(
      collectWithNugetLock(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/missing packages\.lock\.json/);
  });

  test("oversized lock fails loudly naming path, size, and cap BEFORE any parse", async () => {
    const cap = 32 * 1024 * 1024;
    // One byte over the cap; content deliberately VALID JSON-adjacent so a
    // failure can only come from the size gate, not the parser.
    const oversize = `{${" ".repeat(cap)}}`;
    const target = makeNugetTarget(oversize);
    expect.assertions(3);
    try {
      await collectWithNugetLock(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain(join(target.dir, "packages.lock.json"));
      expect(message).toContain(String(cap + 2)); // actual size
      expect(message).toContain(String(cap)); // the cap
    }
  });

  test("non-JSON garbage fails loudly naming the path (the scan-failure path)", async () => {
    const target = makeNugetTarget("this is not json {{{");
    expect.assertions(2);
    try {
      await collectWithNugetLock(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("not valid JSON");
      expect(message).toContain(join(target.dir, "packages.lock.json"));
    }
  });

  test("an unsupported lock version throws naming it", async () => {
    const target = makeNugetTarget(V3_LOCK);
    await expect(
      collectWithNugetLock(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/version 3 is not supported/);
  });
});
