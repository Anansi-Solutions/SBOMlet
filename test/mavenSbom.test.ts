/**
 * Unit suite for the in-process maven.sbom.json collector.
 *
 * Fixtures are inline string constants matching a per-module CycloneDX 1.6
 * document as cyclonedx-maven-plugin writes it (17-RESEARCH §1.1): a single
 * `metadata.component.purl` naming the module's own GAV, plus a components
 * array whose license claims arrive in one of CycloneDX's three shapes
 * (expression / license.id / license.name) or none at all. Every GAV in
 * these fixtures is synthetic (`com.example*`) — never a real commercial
 * package name.
 *
 * No subprocess is spawned anywhere here: the collector is fully in-process.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { computeCacheKey } from "../src/collectors/cdxgen";
import {
  collectWithMavenSbom,
  excludeMavenFirstParty,
  MAVEN_COLLECTOR_TOOL,
  mavenRootPurlOf,
} from "../src/collectors/mavenSbom";
import { collectors } from "../src/collectors/registry";
import { mergeSboms } from "../src/merge/merge";
import type { Target } from "../src/targets/target";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * A single-module BOM covering every license-claim shape the collector must
 * pass through verbatim: an SPDX-id claim, an expression claim, a MIXED
 * component carrying BOTH an id claim and a name claim (never assert
 * single-claim shapes — research Pitfall 9), a name-only claim (raw name +
 * url), a no-license synthetic commercial-looking GAV (the system-scoped
 * class, Q3 — enters the inventory with zero claims), and a classifier purl
 * (a DISTINCT identity from its non-classifier sibling — Pitfall 3) carrying
 * a `hashes` array (read-through data, untouched).
 */
const HAPPY_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2020-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "group": "com.example",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example",
      "name": "commons-id",
      "version": "1.2.0",
      "purl": "pkg:maven/com.example/commons-id@1.2.0?type=jar",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "type": "library",
      "group": "com.example",
      "name": "expr-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example/expr-lib@1.0.0?type=jar",
      "licenses": [{"expression": "Apache-2.0 OR MIT"}]
    },
    {
      "type": "library",
      "group": "com.example",
      "name": "mixed-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example/mixed-lib@1.0.0?type=jar",
      "licenses": [
        {"license": {"id": "BSD-3-Clause"}},
        {"license": {"name": "Custom Secondary Text"}}
      ]
    },
    {
      "type": "library",
      "group": "com.example",
      "name": "name-only-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example/name-only-lib@1.0.0?type=jar",
      "licenses": [
        {"license": {"name": "Custom License Text", "url": "https://example.com/license"}}
      ]
    },
    {
      "type": "library",
      "group": "com.example.commercial",
      "name": "proprietary-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.commercial/proprietary-lib@1.0.0?type=jar"
    },
    {
      "type": "library",
      "group": "com.example",
      "name": "lib",
      "version": "2.0.0",
      "purl": "pkg:maven/com.example/lib@2.0.0?classifier=jakarta&type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "hashes": [{"alg": "SHA-256", "content": "abcdef1234567890"}]
    }
  ]
}
`;

/** Valid JSON, but no `bomFormat` — not a CycloneDX document at all. */
const NON_CYCLONEDX_JSON = `{
  "notes": "just some unrelated JSON document",
  "components": []
}
`;

/** A structurally valid CycloneDX doc whose root purl is the WRONG ecosystem. */
const WRONG_ROOT_PURL_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "purl": "pkg:npm/not-maven-at-all@1.0.0"
    }
  },
  "components": []
}
`;

/**
 * Reactor fixture pair (17-RESEARCH §6, synthetic GAVs per P-08): a
 * 2-module reactor whose dependent module (appb) carries its sibling
 * (liba) as a PLAIN component — no marker distinguishes it from a real
 * third-party dependency, which is exactly the leak excludeMavenFirstParty
 * exists to close. liba's transitive (commons-lang3) and appb's own
 * dependency (gson) are ordinary third-party and must survive the filter.
 */
const MODULE_A_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "library",
      "group": "com.example.fixture",
      "name": "liba",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.fixture/liba@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.fixture",
      "name": "commons-lang3",
      "version": "3.12.0",
      "purl": "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    }
  ]
}
`;

const MODULE_B_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "library",
      "group": "com.example.fixture",
      "name": "appb",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.fixture/appb@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.fixture",
      "name": "liba",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.fixture/liba@1.0.0?type=jar"
    },
    {
      "type": "library",
      "group": "com.example.fixture",
      "name": "commons-lang3",
      "version": "3.12.0",
      "purl": "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    },
    {
      "type": "library",
      "group": "com.example.fixture",
      "name": "gson",
      "version": "2.10.1",
      "purl": "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    }
  ]
}
`;

/** The reactor aggregator pom's own sidecar: zero components, root type=pom. */
const AGGREGATOR_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.fixture",
      "name": "reactor-parent",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.fixture/reactor-parent@1.0.0?type=pom"
    }
  },
  "components": []
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

function makeMavenTarget(sbom: string): Target {
  return makeTargetWithFiles({ "maven.sbom.json": sbom });
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
  prodPurlSet?: ReadonlySet<string>;
  raw: string;
  doc: Record<string, unknown>;
  components: Array<Record<string, unknown>>;
}

async function scanSbom(sbom: string): Promise<ScannedDoc> {
  const target = makeMavenTarget(sbom);
  const result = await collectWithMavenSbom(target, { tempDir: makeOutDir() });
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

describe("collectWithMavenSbom — determinism", () => {
  test("two runs over the same committed bytes produce byte-identical output", async () => {
    const first = await scanSbom(HAPPY_SBOM);
    const second = await scanSbom(HAPPY_SBOM);
    expect(first.raw).toBe(second.raw);
  });

  test("the written bytes are the committed bytes VERBATIM — never re-sorted or re-serialized", async () => {
    const { raw } = await scanSbom(HAPPY_SBOM);
    expect(raw).toBe(HAPPY_SBOM);
  });

  test("the parsed output document deep-equals the committed input document", async () => {
    const { doc } = await scanSbom(HAPPY_SBOM);
    expect(doc).toEqual(JSON.parse(HAPPY_SBOM));
  });
});

// ---------------------------------------------------------------------------
// Tool identity
// ---------------------------------------------------------------------------

describe("MAVEN_COLLECTOR_TOOL", () => {
  test("identity the CLI prints as name@version", () => {
    expect(MAVEN_COLLECTOR_TOOL).toEqual({
      name: "maven-sbom-reader",
      version: "2",
    });
  });
});

// ---------------------------------------------------------------------------
// collectWithMavenSbom — identity and emission
// ---------------------------------------------------------------------------

describe("collectWithMavenSbom — identity and emission", () => {
  test("every fixture component's purl passes through verbatim, casing and qualifiers intact", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    expect(componentPurls(components)).toEqual([
      "pkg:maven/com.example/commons-id@1.2.0?type=jar",
      "pkg:maven/com.example/expr-lib@1.0.0?type=jar",
      "pkg:maven/com.example/mixed-lib@1.0.0?type=jar",
      "pkg:maven/com.example/name-only-lib@1.0.0?type=jar",
      "pkg:maven/com.example.commercial/proprietary-lib@1.0.0?type=jar",
      "pkg:maven/com.example/lib@2.0.0?classifier=jakarta&type=jar",
    ]);
  });

  test("an SPDX-id license claim passes through unchanged", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const commons = components.find((c) => c["name"] === "commons-id");
    expect(commons).toMatchObject({
      licenses: [{ license: { id: "MIT" } }],
    });
  });

  test("an expression license claim passes through unchanged", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const expr = components.find((c) => c["name"] === "expr-lib");
    expect(expr).toMatchObject({
      licenses: [{ expression: "Apache-2.0 OR MIT" }],
    });
  });

  test("a MIXED component carries BOTH an id claim and a name claim (never a single-claim shape)", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const mixed = components.find((c) => c["name"] === "mixed-lib");
    expect(mixed).toMatchObject({
      licenses: [
        { license: { id: "BSD-3-Clause" } },
        { license: { name: "Custom Secondary Text" } },
      ],
    });
  });

  test("a name-only claim carries the raw name and url untouched", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const nameOnly = components.find((c) => c["name"] === "name-only-lib");
    expect(nameOnly).toMatchObject({
      licenses: [
        {
          license: {
            name: "Custom License Text",
            url: "https://example.com/license",
          },
        },
      ],
    });
  });

  test("a no-license synthetic commercial-looking GAV still enters the inventory with zero claims", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const commercial = components.find((c) => c["name"] === "proprietary-lib");
    expect(commercial).toBeDefined();
    expect(commercial!["licenses"]).toBeUndefined();
  });

  test("a classifier purl is a distinct identity and carries its hashes array untouched", async () => {
    const { components } = await scanSbom(HAPPY_SBOM);
    const classified = components.find(
      (c) =>
        c["purl"] ===
        "pkg:maven/com.example/lib@2.0.0?classifier=jakarta&type=jar",
    );
    expect(classified).toMatchObject({
      hashes: [{ alg: "SHA-256", content: "abcdef1234567890" }],
    });
  });

  test("groupId/artifactId casing is never lowercased (Pitfall 2)", async () => {
    const { raw } = await scanSbom(HAPPY_SBOM);
    // The fixture carries no mixed-case ids on purpose (Maven Central
    // convention is lowercase groupIds), so this test instead locks the
    // absence of any case transform: the raw bytes are untouched entirely.
    expect(raw).toBe(HAPPY_SBOM);
  });
});

// ---------------------------------------------------------------------------
// Registry contract (honest omission)
// ---------------------------------------------------------------------------

describe("maven registry collector — CollectedSbom shape", () => {
  test("returns { sbom, targetIdentity } ONLY: no prodPurlSet, no firstPartyNames", async () => {
    const target = makeMavenTarget(HAPPY_SBOM);
    const collector = collectors.get("maven");
    expect(collector).toBeDefined();
    const result = await collector!.collect(
      { ...target, lockfile: "maven" },
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

  test('ALL_KINDS tool identity: collectors.get("maven")?.tool("") equals MAVEN_COLLECTOR_TOOL', () => {
    expect(collectors.get("maven")?.tool("")).toEqual(MAVEN_COLLECTOR_TOOL);
  });
});

// ---------------------------------------------------------------------------
// collectWithMavenSbom — CollectorSbomFile contract + cache key
// ---------------------------------------------------------------------------

describe("collectWithMavenSbom — contract and cache key", () => {
  test("returns { sbomPath, cacheKey, tool } with bom.json inside the given temp dir", async () => {
    const target = makeMavenTarget(HAPPY_SBOM);
    const outDir = makeOutDir();
    const result = await collectWithMavenSbom(target, { tempDir: outDir });
    expect(result.sbomPath).toBe(join(outDir, "bom.json"));
    expect(result.tool).toEqual(MAVEN_COLLECTOR_TOOL);
    expect(typeof result.cacheKey).toBe("string");
  });

  test("cacheKey reuses computeCacheKey with the locked framing (maven-sbom-reader-v1 + maven.sbom.json only)", async () => {
    const target = makeMavenTarget(HAPPY_SBOM);
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    expect(result.cacheKey).toBe(
      computeCacheKey(
        target,
        MAVEN_COLLECTOR_TOOL,
        ["maven-sbom-reader-v1"],
        ["maven.sbom.json"],
      ),
    );
  });
});

// ---------------------------------------------------------------------------
// collectWithMavenSbom — loud failure modes (T-17-01, T-17-02, T-17-04)
// ---------------------------------------------------------------------------

describe("collectWithMavenSbom — failure modes", () => {
  test("missing maven.sbom.json throws the target.ts-shaped error", async () => {
    const target = makeTargetWithFiles({});
    await expect(
      collectWithMavenSbom(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/missing maven\.sbom\.json/);
  });

  test("oversized sidecar fails loudly naming path, size, and cap BEFORE any parse", async () => {
    const cap = 32 * 1024 * 1024;
    // One byte over the cap; content deliberately VALID JSON-adjacent so a
    // failure can only come from the size gate, not the parser.
    const oversize = `{${" ".repeat(cap)}}`;
    const target = makeMavenTarget(oversize);
    expect.assertions(3);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain(join(target.dir, "maven.sbom.json"));
      expect(message).toContain(String(cap + 2)); // actual size
      expect(message).toContain(String(cap)); // the cap
    }
  });

  test("non-JSON garbage fails loudly naming the path (the scan-failure path)", async () => {
    const target = makeMavenTarget("this is not json {{{");
    expect.assertions(2);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("not valid JSON");
      expect(message).toContain(join(target.dir, "maven.sbom.json"));
    }
  });

  test("valid JSON that is not CycloneDX (no bomFormat) throws naming the expectation", async () => {
    const target = makeMavenTarget(NON_CYCLONEDX_JSON);
    await expect(
      collectWithMavenSbom(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/CycloneDX/);
  });

  test("a CycloneDX doc whose root purl is not pkg:maven/ throws naming BOTH the found purl and the expected prefix", async () => {
    const target = makeMavenTarget(WRONG_ROOT_PURL_SBOM);
    expect.assertions(3);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("pkg:npm/not-maven-at-all@1.0.0"); // found
      expect(message).toContain("pkg:maven/"); // expected
      expect(message).toContain(join(target.dir, "maven.sbom.json"));
    }
  });
});

// ---------------------------------------------------------------------------
// mavenRootPurlOf — the cross-target pre-pass primitive (17-02, P-07)
// ---------------------------------------------------------------------------

describe("mavenRootPurlOf — pre-pass root purl extraction", () => {
  test("returns metadata.component.purl for a valid sidecar", () => {
    expect(mavenRootPurlOf(MODULE_A_SBOM)).toBe(
      "pkg:maven/com.example.fixture/liba@1.0.0?type=jar",
    );
  });

  test("returns the aggregator pom's own root purl even with zero components", () => {
    expect(mavenRootPurlOf(AGGREGATOR_SBOM)).toBe(
      "pkg:maven/com.example.fixture/reactor-parent@1.0.0?type=pom",
    );
  });

  test("returns undefined for non-JSON garbage — never throws", () => {
    expect(mavenRootPurlOf("this is not json {{{")).toBeUndefined();
  });

  test("returns undefined for valid JSON that is not CycloneDX", () => {
    expect(mavenRootPurlOf(NON_CYCLONEDX_JSON)).toBeUndefined();
  });

  test("returns undefined when metadata.component.purl is missing", () => {
    const noPurl = JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
      metadata: { component: { name: "no-purl-here" } },
    });
    expect(mavenRootPurlOf(noPurl)).toBeUndefined();
  });

  test("returns undefined when metadata itself is absent", () => {
    const noMetadata = JSON.stringify({
      bomFormat: "CycloneDX",
      components: [],
    });
    expect(mavenRootPurlOf(noMetadata)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// excludeMavenFirstParty — reactor sibling exclusion (17-02, P-07)
// ---------------------------------------------------------------------------

describe("excludeMavenFirstParty — reactor sibling exclusion", () => {
  test("excludes an exact purl-string match; liba's transitive and appb's own dep remain", () => {
    const purls = new Set([
      "pkg:maven/com.example.fixture/liba@1.0.0?type=jar",
    ]);
    const filtered = excludeMavenFirstParty(
      JSON.parse(MODULE_B_SBOM),
      purls,
    ) as { components: Array<Record<string, unknown>> };
    expect(filtered.components.map((c) => c["purl"])).toEqual([
      "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
    ]);
  });

  test("a STALE sibling reference (version bumped) is NOT excluded — the loud direction (Pitfall 8)", () => {
    const purls = new Set([
      "pkg:maven/com.example.fixture/liba@2.0.0?type=jar",
    ]);
    const filtered = excludeMavenFirstParty(
      JSON.parse(MODULE_B_SBOM),
      purls,
    ) as { components: Array<Record<string, unknown>> };
    expect(filtered.components.map((c) => c["purl"])).toEqual([
      "pkg:maven/com.example.fixture/liba@1.0.0?type=jar",
      "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      "pkg:maven/com.example.fixture/gson@2.10.1?type=jar",
    ]);
  });

  test("an empty purl set deep-equals the input document", () => {
    const doc = JSON.parse(MODULE_B_SBOM);
    expect(excludeMavenFirstParty(doc, new Set())).toEqual(doc);
  });

  test("never mutates the input document", () => {
    const doc = JSON.parse(MODULE_B_SBOM) as { components: unknown[] };
    const originalLength = doc.components.length;
    excludeMavenFirstParty(
      doc,
      new Set(["pkg:maven/com.example.fixture/liba@1.0.0?type=jar"]),
    );
    expect(doc.components.length).toBe(originalLength);
  });

  test("module A's own inventory is untouched (no sibling purl present)", () => {
    const doc = JSON.parse(MODULE_A_SBOM);
    const purls = new Set([
      "pkg:maven/com.example.fixture/appb@1.0.0?type=jar",
    ]);
    expect(excludeMavenFirstParty(doc, purls)).toEqual(doc);
  });

  test("the aggregator pom's zero-component doc passes through with an empty array, never crashes", () => {
    const doc = JSON.parse(AGGREGATOR_SBOM);
    const purls = new Set([
      "pkg:maven/com.example.fixture/liba@1.0.0?type=jar",
    ]);
    const filtered = excludeMavenFirstParty(doc, purls) as {
      components: unknown[];
    };
    expect(filtered.components).toEqual([]);
  });

  test("order, claims, and extra fields pass through untouched for surviving components", () => {
    const doc = JSON.parse(MODULE_B_SBOM);
    const filtered = excludeMavenFirstParty(
      doc,
      new Set(["pkg:maven/com.example.fixture/liba@1.0.0?type=jar"]),
    ) as { components: Array<Record<string, unknown>> };
    expect(filtered.components[0]).toEqual({
      type: "library",
      group: "com.example.fixture",
      name: "commons-lang3",
      version: "3.12.0",
      purl: "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
      licenses: [{ license: { id: "Apache-2.0" } }],
    });
  });
});

// ---------------------------------------------------------------------------
// Dual-document composed inventory + prodPurlSet (TS-02, D-02 dual-doc)
// ---------------------------------------------------------------------------

/** Clean-superset pair: the test doc is default-doc-plus-test-only-deps. */
const CLEAN_SUPERSET_DEFAULT_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "compile-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
`;

const CLEAN_SUPERSET_TEST_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "compile-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "test-only-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/test-only-lib@1.0.0?type=jar",
      "licenses": [{"license": {"id": "EPL-2.0"}}]
    }
  ]
}
`;

/**
 * Mediation-shift pair (Q2): the SAME GA resolves to a DIFFERENT version in
 * each build — the default (prod) build mediates to 2.0.0, the test build to
 * 1.0.0. Neither purl may be dropped.
 */
const MEDIATION_DEFAULT_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "mediated-lib",
      "version": "2.0.0",
      "purl": "pkg:maven/com.example.dual/mediated-lib@2.0.0?type=jar",
      "licenses": [{"license": {"id": "BSD-3-Clause"}}]
    }
  ]
}
`;

const MEDIATION_TEST_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "mediated-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/mediated-lib@1.0.0?type=jar",
      "licenses": [{"license": {"id": "BSD-3-Clause"}}]
    }
  ]
}
`;

/** A package resolved to compile scope: identical purl in BOTH docs (Q2). */
const DUAL_SCOPE_DEFAULT_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "shared-scope-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/shared-scope-lib@1.0.0?type=jar",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    }
  ]
}
`;

const DUAL_SCOPE_TEST_SBOM = DUAL_SCOPE_DEFAULT_SBOM;

/** Non-superset pair: a default component the test build's run entirely omits. */
const NON_SUPERSET_DEFAULT_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": [
    {
      "type": "library",
      "group": "com.example.dual",
      "name": "system-lib",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/system-lib@1.0.0?type=jar"
    }
  ]
}
`;

const NON_SUPERSET_TEST_SBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "group": "com.example.dual",
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:maven/com.example.dual/app@1.0.0?type=jar"
    }
  },
  "components": []
}
`;

function makeDualMavenTarget(defaultSbom: string, testSbom: string): Target {
  return makeTargetWithFiles({
    "maven.sbom.json": defaultSbom,
    "maven.test.sbom.json": testSbom,
  });
}

describe("collectWithMavenSbom — dual-document composed inventory", () => {
  test("clean superset: inventory equals the test doc (residual empty); prodPurlSet is the default doc's purls", async () => {
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const doc = JSON.parse(readFileSync(result.sbomPath, "utf8")) as {
      components: Array<Record<string, unknown>>;
    };
    expect(componentPurls(doc.components)).toEqual([
      "pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar",
      "pkg:maven/com.example.dual/test-only-lib@1.0.0?type=jar",
    ]);
    expect(result.prodPurlSet).toEqual(
      new Set(["pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar"]),
    );
  });

  test("clean superset: merge classifies the default-doc purl prod and the test-only purl dev", async () => {
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const sbom = JSON.parse(readFileSync(result.sbomPath, "utf8"));
    const model = mergeSboms([
      {
        sbom,
        targetIdentity: target.identity,
        prodPurlSet: result.prodPurlSet,
      },
    ]);
    const compileLib = model.packages.find(
      (p) => p.purl === "pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar",
    );
    const testOnlyLib = model.packages.find(
      (p) =>
        p.purl === "pkg:maven/com.example.dual/test-only-lib@1.0.0?type=jar",
    );
    expect(compileLib?.occurrences[0]?.isDevDependency).toBe(false);
    expect(testOnlyLib?.occurrences[0]?.isDevDependency).toBe(true);
  });
});

describe("collectWithMavenSbom — dual-document envelope pass-through", () => {
  test("undeclared top-level fields of the test doc survive composing", async () => {
    // Composing spreads the test doc, so fields this reader never declares
    // (specVersion, serialNumber, the dependencies graph) must reach the
    // output untouched — a hand-rebuilt document would silently drop them.
    const testDocWithExtras = JSON.stringify({
      ...(JSON.parse(CLEAN_SUPERSET_TEST_SBOM) as Record<string, unknown>),
      serialNumber: "urn:uuid:22222222-2222-2222-2222-222222222222",
      dependencies: [
        { ref: "pkg:maven/com.example.dual/app@1.0.0?type=jar", dependsOn: [] },
      ],
    });
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      testDocWithExtras,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const doc = JSON.parse(readFileSync(result.sbomPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(doc["specVersion"]).toBe("1.6");
    expect(doc["serialNumber"]).toBe(
      "urn:uuid:22222222-2222-2222-2222-222222222222",
    );
    expect(doc["dependencies"]).toEqual([
      { ref: "pkg:maven/com.example.dual/app@1.0.0?type=jar", dependsOn: [] },
    ]);
  });
});

describe("collectWithMavenSbom — dual-document Q2 edge cases", () => {
  test("mediation shift: BOTH versions survive — the default version is prod, the test version is dev", async () => {
    const target = makeDualMavenTarget(
      MEDIATION_DEFAULT_SBOM,
      MEDIATION_TEST_SBOM,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const doc = JSON.parse(readFileSync(result.sbomPath, "utf8")) as {
      components: Array<Record<string, unknown>>;
    };
    expect(componentPurls(doc.components).sort()).toEqual(
      [
        "pkg:maven/com.example.dual/mediated-lib@1.0.0?type=jar",
        "pkg:maven/com.example.dual/mediated-lib@2.0.0?type=jar",
      ].sort(),
    );
    const model = mergeSboms([
      {
        sbom: doc,
        targetIdentity: target.identity,
        prodPurlSet: result.prodPurlSet,
      },
    ]);
    const prodVersion = model.packages.find(
      (p) =>
        p.purl === "pkg:maven/com.example.dual/mediated-lib@2.0.0?type=jar",
    );
    const devVersion = model.packages.find(
      (p) =>
        p.purl === "pkg:maven/com.example.dual/mediated-lib@1.0.0?type=jar",
    );
    expect(prodVersion?.occurrences[0]?.isDevDependency).toBe(false);
    expect(devVersion?.occurrences[0]?.isDevDependency).toBe(true);
  });

  test("a package resolved to compile scope (identical purl in both docs) classifies prod", async () => {
    const target = makeDualMavenTarget(
      DUAL_SCOPE_DEFAULT_SBOM,
      DUAL_SCOPE_TEST_SBOM,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const doc = JSON.parse(readFileSync(result.sbomPath, "utf8")) as {
      components: Array<Record<string, unknown>>;
    };
    expect(componentPurls(doc.components)).toEqual([
      "pkg:maven/com.example.dual/shared-scope-lib@1.0.0?type=jar",
    ]);
    const model = mergeSboms([
      {
        sbom: doc,
        targetIdentity: target.identity,
        prodPurlSet: result.prodPurlSet,
      },
    ]);
    const shared = model.packages.find(
      (p) =>
        p.purl === "pkg:maven/com.example.dual/shared-scope-lib@1.0.0?type=jar",
    );
    expect(shared?.occurrences[0]?.isDevDependency).toBe(false);
  });

  test("non-superset test doc: a default component entirely absent from the test doc is carried in as prod — never dropped", async () => {
    const target = makeDualMavenTarget(
      NON_SUPERSET_DEFAULT_SBOM,
      NON_SUPERSET_TEST_SBOM,
    );
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const doc = JSON.parse(readFileSync(result.sbomPath, "utf8")) as {
      components: Array<Record<string, unknown>>;
    };
    expect(componentPurls(doc.components)).toEqual([
      "pkg:maven/com.example.dual/system-lib@1.0.0?type=jar",
    ]);
    expect(result.prodPurlSet).toEqual(
      new Set(["pkg:maven/com.example.dual/system-lib@1.0.0?type=jar"]),
    );
  });

  test("default-doc-only (no test doc): prodPurlSet is undefined — the backward-compat regression lock", async () => {
    const result = await scanSbom(HAPPY_SBOM);
    expect(result.prodPurlSet).toBeUndefined();
  });

  test("default-doc-only (no test doc): the output bytes are STILL the verbatim committed default doc", async () => {
    const { raw } = await scanSbom(HAPPY_SBOM);
    expect(raw).toBe(HAPPY_SBOM);
  });
});

describe("collectWithMavenSbom — test doc loud narrow", () => {
  test("a present maven.test.sbom.json that is not CycloneDX throws naming the test doc's own path", async () => {
    const target = makeDualMavenTarget(HAPPY_SBOM, NON_CYCLONEDX_JSON);
    expect.assertions(2);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("CycloneDX");
      expect(message).toContain(join(target.dir, "maven.test.sbom.json"));
    }
  });

  test("a present maven.test.sbom.json whose root purl is not pkg:maven/ throws naming both purls", async () => {
    const target = makeDualMavenTarget(HAPPY_SBOM, WRONG_ROOT_PURL_SBOM);
    expect.assertions(3);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain("pkg:npm/not-maven-at-all@1.0.0");
      expect(message).toContain("pkg:maven/");
      expect(message).toContain(join(target.dir, "maven.test.sbom.json"));
    }
  });

  test("a test doc whose root purl differs from the default doc's throws naming BOTH roots — never composes", async () => {
    // The merge drops the inventory component matching a document's own root
    // purl. A test doc from another build or module can therefore name a REAL
    // dependency as its root and silently remove it from the inventory. A
    // mismatched pair must fail loudly instead.
    const mismatchedRootTestSbom = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "purl": "pkg:maven/com.example/commons-id@1.2.0?type=jar"
    }
  },
  "components": []
}
`;
    const target = makeDualMavenTarget(HAPPY_SBOM, mismatchedRootTestSbom);
    expect.assertions(3);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain(
        "pkg:maven/com.example/commons-id@1.2.0?type=jar",
      );
      expect(message).toContain("pkg:maven/com.example/app@1.0.0?type=jar");
      expect(message).toContain(join(target.dir, "maven.test.sbom.json"));
    }
  });

  test("an oversized maven.test.sbom.json fails loudly BEFORE any parse, naming its own path", async () => {
    const cap = 32 * 1024 * 1024;
    const oversize = `{${" ".repeat(cap)}}`;
    const target = makeDualMavenTarget(HAPPY_SBOM, oversize);
    expect.assertions(2);
    try {
      await collectWithMavenSbom(target, { tempDir: makeOutDir() });
    } catch (error) {
      const message = String(error);
      expect(message).toContain(join(target.dir, "maven.test.sbom.json"));
      expect(message).toContain(String(cap + 2));
    }
  });
});

describe("collectWithMavenSbom — dual-document cache key", () => {
  test("a present test doc yields a DIFFERENT cache key than the same default doc with no test doc", async () => {
    const noTestTarget = makeMavenTarget(CLEAN_SUPERSET_DEFAULT_SBOM);
    const withTestTarget = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const noTestResult = await collectWithMavenSbom(noTestTarget, {
      tempDir: makeOutDir(),
    });
    const withTestResult = await collectWithMavenSbom(withTestTarget, {
      tempDir: makeOutDir(),
    });
    expect(noTestResult.cacheKey).not.toBe(withTestResult.cacheKey);
  });

  test("changing the test doc's bytes changes the cache key", async () => {
    const targetA = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const targetB = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      MEDIATION_TEST_SBOM,
    );
    const resultA = await collectWithMavenSbom(targetA, {
      tempDir: makeOutDir(),
    });
    const resultB = await collectWithMavenSbom(targetB, {
      tempDir: makeOutDir(),
    });
    expect(resultA.cacheKey).not.toBe(resultB.cacheKey);
  });

  test("two reads of the same dual-doc pair yield a STABLE cache key", async () => {
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const first = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const second = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    expect(first.cacheKey).toBe(second.cacheKey);
  });

  test("absent test doc: cache key equals the locked framing (unchanged args + manifest)", async () => {
    const target = makeMavenTarget(CLEAN_SUPERSET_DEFAULT_SBOM);
    const result = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    expect(result.cacheKey).toBe(
      computeCacheKey(
        target,
        MAVEN_COLLECTOR_TOOL,
        ["maven-sbom-reader-v1"],
        ["maven.sbom.json"],
      ),
    );
  });
});

describe("collectWithMavenSbom — dual-document determinism", () => {
  test("two collect() calls over the same dual-doc pair emit byte-identical inventory bytes", async () => {
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const first = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    const second = await collectWithMavenSbom(target, {
      tempDir: makeOutDir(),
    });
    expect(readFileSync(first.sbomPath, "utf8")).toBe(
      readFileSync(second.sbomPath, "utf8"),
    );
  });
});

describe("maven registry collector — dual-doc prodPurlSet threading", () => {
  test("a target with both docs threads prodPurlSet into CollectedSbom", async () => {
    const target = makeDualMavenTarget(
      CLEAN_SUPERSET_DEFAULT_SBOM,
      CLEAN_SUPERSET_TEST_SBOM,
    );
    const collector = collectors.get("maven");
    const result = await collector!.collect(
      { ...target, lockfile: "maven" },
      { timeoutMs: 0, verbose: false, log: () => {} },
    );
    expect(result.prodPurlSet).toEqual(
      new Set(["pkg:maven/com.example.dual/compile-lib@1.0.0?type=jar"]),
    );
  });

  test("a target with only the default doc still carries no prodPurlSet key at all", async () => {
    const target = makeMavenTarget(HAPPY_SBOM);
    const collector = collectors.get("maven");
    const result = await collector!.collect(
      { ...target, lockfile: "maven" },
      { timeoutMs: 0, verbose: false, log: () => {} },
    );
    expect("prodPurlSet" in result).toBe(false);
  });
});
