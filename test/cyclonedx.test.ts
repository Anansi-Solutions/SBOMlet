/**
 * Contract tests for the CycloneDX 1.6 emitter.
 *
 * Models are HAND-BUILT: the emitter is
 * tested against the CanonicalDependencies/Verdict contract directly, independent
 * of mergeSboms/normalize. Validation is structural per the CONTEXT
 * decision — the schema facts asserted here (required = bomFormat +
 * specVersion only; expression tuple is additionalProperties:false;
 * duplicate property names allowed) were verified against the official
 * bom-1.6.schema.json in 04-RESEARCH.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { renderCyclonedx } from "../src/render/cyclonedx";
import type {
  CanonicalDependencies,
  PackageEntry,
  Verdict,
} from "../src/model/dependencies";

function golden(name: string): string {
  return readFileSync(join(import.meta.dir, "golden", name), "utf-8");
}

/** Hand-built PackageEntry with sensible defaults for contract tests. */
function entry(
  partial: Partial<PackageEntry> &
    Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: "apps/a", isDevDependency: false }],
    licenseClaims: [],
    scope: "app",
    ...partial,
  };
}

const exprEntry = entry({
  purl: "pkg:npm/expr-pkg@3.0.0",
  name: "expr-pkg",
  version: "3.0.0",
  licenseClaims: [
    { raw: "MIT OR Apache-2.0", kind: "expression", source: "generator" },
  ],
  finding: {
    expression: "MIT OR Apache-2.0",
    elected: "Apache-2.0",
    source: "generator",
    confidence: "exact",
  },
});

const namedEntry = entry({
  purl: "pkg:npm/jsonify@0.0.1",
  name: "jsonify",
  version: "0.0.1",
  licenseClaims: [
    { raw: "Public Domain", kind: "name", source: "generator" },
    // Duplicate raw under a different kind: the emitted named list must
    // dedup by raw, first-seen order.
    { raw: "Public Domain", kind: "spdx-id", source: "generator" },
  ],
});

const bareEntry = entry({
  purl: "pkg:npm/no-license-pkg@1.0.0",
  name: "no-license-pkg",
  version: "1.0.0",
});

const baseModel: CanonicalDependencies = {
  packages: [exprEntry, namedEntry, bareEntry],
};

const sharpEntry = entry({
  purl: "pkg:npm/sharp@0.33.0",
  name: "sharp",
  version: "0.33.0",
  occurrences: [
    { target: "backend", isDevDependency: false },
    { target: "frontend", isDevDependency: true },
  ],
});

const sharpVerdicts: Verdict[] = [
  {
    purl: "pkg:npm/sharp@0.33.0",
    occurrenceTarget: "backend",
    status: "ok",
    rule: "default:ok",
    reason: "no copyleft obligations",
  },
  {
    purl: "pkg:npm/sharp@0.33.0",
    occurrenceTarget: "frontend",
    status: "fail",
    rule: "default:copyleft",
    reason: "copyleft license",
  },
  // A verdict for a DIFFERENT purl must never leak into this component.
  {
    purl: "pkg:npm/other@1.0.0",
    occurrenceTarget: "frontend",
    status: "fail",
    rule: "default:copyleft",
    reason: "belongs to another package",
  },
];

interface CdxDoc {
  bomFormat: string;
  specVersion: string;
  version: number;
  metadata: { tools: { components: Array<Record<string, unknown>> } };
  components: Array<Record<string, unknown>>;
}

function parse(output: string): CdxDoc {
  return JSON.parse(output) as CdxDoc;
}

describe("renderCyclonedx — top-level shape", () => {
  test("Test 1: required fields present, volatile fields absent, tools entry locked", () => {
    const output = renderCyclonedx(baseModel);
    const doc = parse(output);

    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.6");
    expect(doc.version).toBe(1);

    // The volatile-field absence contract: the STRINGS never appear anywhere.
    expect(output.includes("serialNumber")).toBe(false);
    expect(output.includes("timestamp")).toBe(false);

    expect(doc.metadata.tools.components).toEqual([
      { type: "application", name: "licenses-tool" },
    ]);
  });
});

describe("renderCyclonedx — license dispatch", () => {
  const output = renderCyclonedx(baseModel);
  const doc = parse(output);
  const byPurl = new Map(doc.components.map((c) => [c["purl"], c]));

  test("Test 2a: a normalized expression emits a single-item expression tuple with ONLY the expression key", () => {
    const component = byPurl.get("pkg:npm/expr-pkg@3.0.0")!;
    const licenses = component["licenses"] as Array<Record<string, unknown>>;
    expect(licenses).toEqual([{ expression: "MIT OR Apache-2.0" }]);
    // The schema's expression object is additionalProperties:false — a stray
    // id/name key would invalidate the document.
    expect(Object.keys(licenses[0]!)).toEqual(["expression"]);
    expect(licenses.length).toBe(1);
  });

  test("Test 2b: a finding-less package with a named raw emits license.name entries deduped by raw", () => {
    const component = byPurl.get("pkg:npm/jsonify@0.0.1")!;
    expect(component["licenses"]).toEqual([
      { license: { name: "Public Domain" } },
    ]);
  });

  test("Test 2c: a package with neither finding expression nor claims has NO licenses key", () => {
    const component = byPurl.get("pkg:npm/no-license-pkg@1.0.0")!;
    expect("licenses" in component).toBe(false);
  });

  test("Test 2d: a finding with null expression falls back to the named-raw dispatch", () => {
    const unknownFinding = entry({
      purl: "pkg:npm/mystery@1.0.0",
      name: "mystery",
      version: "1.0.0",
      licenseClaims: [
        { raw: "Custom License", kind: "name", source: "generator" },
      ],
      finding: {
        expression: null,
        elected: null,
        source: "generator",
        confidence: "none",
      },
    });
    const doc2 = parse(renderCyclonedx({ packages: [unknownFinding] }));
    expect(doc2.components[0]!["licenses"]).toEqual([
      { license: { name: "Custom License" } },
    ]);
  });

  // #9: an os-scope partial finding carries unrecognizedTokens that the
  // machine-readable CycloneDX must NOT silently drop — they appear in the
  // Markdown render, so the SBOM must match. Emit each as an additional
  // {license:{name}} entry after the expression tuple.
  test("#9: an os-partial finding emits the expression tuple PLUS each unrecognized token as a named entry", () => {
    const osPartial = entry({
      purl: "pkg:deb/debian/os-partial@1.0",
      name: "os-partial",
      version: "1.0",
      scope: "os",
      finding: {
        expression: "GPL-2.0-only AND BSD-3-Clause",
        elected: "GPL-2.0-only AND BSD-3-Clause",
        source: "generator",
        confidence: "exact",
        unrecognizedTokens: ["Artistic", "public-domain"],
      },
    });
    const doc2 = parse(renderCyclonedx({ packages: [osPartial] }));
    expect(doc2.components[0]!["licenses"]).toEqual([
      { expression: "GPL-2.0-only AND BSD-3-Clause" },
      { license: { name: "Artistic" } },
      { license: { name: "public-domain" } },
    ]);
  });

  test("#9: an IMPRECISE os-partial (null expression) still emits its unrecognized tokens as named entries", () => {
    const imprecisePartial = entry({
      purl: "pkg:deb/debian/os-imprecise@1.0",
      name: "os-imprecise",
      version: "1.0",
      scope: "os",
      finding: {
        expression: null,
        elected: null,
        source: "generator",
        confidence: "imprecise",
        impreciseFamily: "GPL",
        unrecognizedTokens: ["some-custom-token"],
      },
    });
    const doc2 = parse(renderCyclonedx({ packages: [imprecisePartial] }));
    expect(doc2.components[0]!["licenses"]).toEqual([
      { license: { name: "some-custom-token" } },
    ]);
  });

  test("#9: a finding WITHOUT unrecognizedTokens emits exactly the expression tuple (no regression)", () => {
    const component = byPurl.get("pkg:npm/expr-pkg@3.0.0")!;
    expect(component["licenses"]).toEqual([
      { expression: "MIT OR Apache-2.0" },
    ]);
  });
});

describe("renderCyclonedx — component minimum + purl sort", () => {
  test("Test 3: every component carries type/name/version/purl/bom-ref; purl-sorted even from shuffled input", () => {
    // Deliberately shuffled: bare (n...) first, expr last — purl order is
    // expr-pkg < jsonify < no-license-pkg compareCodeUnits.
    const shuffled: CanonicalDependencies = {
      packages: [bareEntry, namedEntry, exprEntry],
    };
    const doc = parse(renderCyclonedx(shuffled));

    expect(doc.components.map((c) => c["purl"])).toEqual([
      "pkg:npm/expr-pkg@3.0.0",
      "pkg:npm/jsonify@0.0.1",
      "pkg:npm/no-license-pkg@1.0.0",
    ]);
    for (const component of doc.components) {
      expect(component["type"]).toBe("library");
      expect(typeof component["name"]).toBe("string");
      expect(typeof component["version"]).toBe("string");
      expect(typeof component["purl"]).toBe("string");
      expect(component["bom-ref"]).toBe(component["purl"]);
    }
    // Shuffled and pre-sorted input emit identical bytes (defensive sort).
    expect(renderCyclonedx(shuffled)).toBe(renderCyclonedx(baseModel));
  });
});

describe("renderCyclonedx — licenses-tool: properties", () => {
  const model: CanonicalDependencies = { packages: [sharpEntry] };

  test("Test 4a: occurrences + scope + verdict/rule properties in deterministic order", () => {
    const doc = parse(renderCyclonedx(model, sharpVerdicts));
    expect(doc.components[0]!["properties"]).toEqual([
      { name: "licenses-tool:used-in", value: "backend" },
      { name: "licenses-tool:used-in", value: "frontend" },
      { name: "licenses-tool:scope:backend", value: "prod" },
      { name: "licenses-tool:scope:frontend", value: "dev" },
      { name: "licenses-tool:verdict:backend", value: "ok" },
      { name: "licenses-tool:rule:backend", value: "default:ok" },
      { name: "licenses-tool:verdict:frontend", value: "fail" },
      { name: "licenses-tool:rule:frontend", value: "default:copyleft" },
    ]);
  });

  test("Test 4b: without verdicts, no verdict/rule properties exist", () => {
    const output = renderCyclonedx(model);
    expect(output.includes("licenses-tool:verdict")).toBe(false);
    expect(output.includes("licenses-tool:rule")).toBe(false);
    const doc = parse(output);
    expect(doc.components[0]!["properties"]).toEqual([
      { name: "licenses-tool:used-in", value: "backend" },
      { name: "licenses-tool:used-in", value: "frontend" },
      { name: "licenses-tool:scope:backend", value: "prod" },
      { name: "licenses-tool:scope:frontend", value: "dev" },
    ]);
  });

  test("Test 4c: an empty properties array is omitted, not emitted", () => {
    const orphan = entry({
      purl: "pkg:npm/orphan@1.0.0",
      name: "orphan",
      version: "1.0.0",
      occurrences: [],
    });
    const doc = parse(renderCyclonedx({ packages: [orphan] }));
    expect("properties" in doc.components[0]!).toBe(false);
  });
});

describe("renderCyclonedx — injection inertness", () => {
  test("Test 5: hostile package names round-trip through JSON.parse byte-exact", () => {
    const hostile = 'evil"name\\withcontrol\nchars\tand "quotes"';
    const model: CanonicalDependencies = {
      packages: [
        entry({
          purl: "pkg:npm/hostile@1.0.0",
          name: hostile,
          version: "1.0.0",
        }),
      ],
    };
    const doc = parse(renderCyclonedx(model));
    // JSON.stringify is the only encoder — the parsed value is the exact
    // original string, proving no concatenation built any JSON fragment.
    expect(doc.components[0]!["name"]).toBe(hostile);
  });
});

describe("renderCyclonedx — byte determinism", () => {
  test("Test 6: double emit is byte-identical; no CR; exactly one trailing LF", () => {
    const first = renderCyclonedx(baseModel);
    const second = renderCyclonedx(baseModel);
    expect(first).toBe(second);
    expect(first.includes("\r")).toBe(false);
    expect(first.endsWith("\n")).toBe(true);
    expect(first.endsWith("\n\n")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Golden byte-lock: one model exercising EVERY dispatch
// branch — expression tuple (expr-pkg), named raw with dedup (jsonify),
// omitted licenses key (no-license-pkg), multi-occurrence used-in/scope
// properties and verdict/rule properties (sharp). Verdicts include a
// foreign-purl entry to byte-lock the filtering.
// ---------------------------------------------------------------------------

const goldenModel: CanonicalDependencies = {
  packages: [exprEntry, namedEntry, bareEntry, sharpEntry],
};

describe("renderCyclonedx — golden byte equality", () => {
  test("the all-branch golden model matches test/golden/cyclonedx.json byte-for-byte", () => {
    expect(renderCyclonedx(goldenModel, sharpVerdicts)).toBe(
      golden("cyclonedx.json"),
    );
  });
});
