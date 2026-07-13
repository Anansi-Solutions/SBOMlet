/**
 * Fast, offline determinism sampling test: double-render byte-identity and
 * the volatile-field absence contract, driven entirely by checked-in
 * fixtures — no subprocess, runs in the default suite in well under 1s.
 *
 * The fixture deliberately RETAINS all four volatile cdxgen fields
 * (serialNumber, metadata.timestamp, annotations[].timestamp, and the prose
 * date inside annotations[].text — research Pitfall 2). The assertions read
 * those literal values out of the parsed fixture and prove they never reach
 * the rendered Markdown or the dump-model JSON.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "bun:test";

import { mergeSboms } from "../src/merge/merge";
import { collectWithBunLock } from "../src/collectors/bunLock";
import { collectWithNugetLock } from "../src/collectors/nugetLock";
import {
  toSortedDependenciesJson,
  type EvaluatedDependencies,
  type Verdict,
} from "../src/model/dependencies";
import { annotateFindings } from "../src/normalize/normalize";
import { evaluate } from "../src/policy/evaluate";
import { parsePolicy } from "../src/policy/schema";
import { renderCyclonedx } from "../src/render/cyclonedx";
import { renderMarkdown } from "../src/render/markdown";
import type { Target } from "../src/targets/target";

const TARGET = "libraries/iframe-rpc";

const fixtureRaw = readFileSync(
  join(import.meta.dir, "fixtures", "volatile-retained.json"),
  "utf-8",
);

const shapesRaw = readFileSync(
  join(import.meta.dir, "fixtures", "license-shapes.json"),
  "utf-8",
);
const fixture = JSON.parse(fixtureRaw) as {
  serialNumber: string;
  metadata: { timestamp: string };
};

function build(): { md: string; dump: string } {
  const model = mergeSboms([
    { sbom: JSON.parse(fixtureRaw), targetIdentity: TARGET },
  ]);
  return { md: renderMarkdown(model), dump: toSortedDependenciesJson(model) };
}

describe("determinism — double-render byte-identity", () => {
  test("building and rendering twice yields strictly equal strings", () => {
    const first = build();
    const second = build();
    expect(first.md).toBe(second.md);
  });

  test("toSortedDependenciesJson twice yields strictly equal strings", () => {
    const first = build();
    const second = build();
    expect(first.dump).toBe(second.dump);
  });

  test("double-build double-emit CycloneDX is byte-identical and keeps the LF contract (OUT-03)", () => {
    const first = mergeSboms([
      { sbom: JSON.parse(fixtureRaw), targetIdentity: TARGET },
    ]);
    const second = mergeSboms([
      { sbom: JSON.parse(fixtureRaw), targetIdentity: TARGET },
    ]);
    // Inline verdicts so the verdict-property path is part of the
    // regression surface, not just the bare emit.
    const verdicts: Verdict[] = [
      {
        purl: first.packages[0]!.purl,
        occurrenceTarget: TARGET,
        status: "fail",
        rule: "default:copyleft",
        reason: "inline verdict covering the verdict-property emit path",
      },
    ];
    const a = renderCyclonedx(first, verdicts);
    const b = renderCyclonedx(second, verdicts);
    expect(a).toBe(b);

    // The verdict path is actually exercised (not vacuously equal).
    expect(a).toContain(`licenses-tool:verdict:${TARGET}`);

    // Determinism regression for the new output surface: no CR, exactly one
    // trailing LF, and the fixture's volatile fields never reach it.
    expect(a.includes("\r")).toBe(false);
    expect(a.endsWith("\n")).toBe(true);
    expect(a.endsWith("\n\n")).toBe(false);
    expect(a.includes("serialNumber")).toBe(false);
    expect(a.includes("timestamp")).toBe(false);
  });
});

describe("determinism — multi-target merge", () => {
  // Two targets sharing the volatile fixture; target "a" carries an EMPTY
  // dual-run prod purl set (every occurrence dev=true via the plugin diff
  // path), target "b" uses the property-marker path — so the same package
  // carries occurrences that differ in dev flags across targets.
  function buildMulti(): { md: string; dump: string } {
    const model = mergeSboms([
      {
        sbom: JSON.parse(fixtureRaw),
        targetIdentity: "a",
        prodPurlSet: new Set<string>(),
      },
      { sbom: JSON.parse(fixtureRaw), targetIdentity: "b" },
    ]);
    return { md: renderMarkdown(model), dump: toSortedDependenciesJson(model) };
  }

  test("multi-target build twice yields byte-equal model JSON and markdown", () => {
    const first = buildMulti();
    const second = buildMulti();
    expect(first.dump).toBe(second.dump);
    expect(first.md).toBe(second.md);
  });

  test("occurrence objects carry per-target dev flags in the dump", () => {
    const { dump } = buildMulti();
    expect(dump.includes('"isDevDependency"')).toBe(true);
    // Target "a" (empty prod set) occurrences are all dev=true; the same
    // purl's target "b" occurrence keeps its own property-derived flag.
    const parsed = JSON.parse(dump) as {
      packages: Array<{
        occurrences: Array<{ target: string; isDevDependency: boolean }>;
      }>;
    };
    const sharedPackage = parsed.packages.find(
      (pkg) => pkg.occurrences.length === 2,
    );
    expect(sharedPackage).toBeDefined();
    const byTarget = new Map(
      sharedPackage!.occurrences.map((o) => [o.target, o.isDevDependency]),
    );
    expect(byTarget.get("a")).toBe(true);
  });
});

describe("determinism — policy-annotated dump", () => {
  // Suppression + compatible rule present so findings AND verdicts populate
  // the new dump surface; the ISC rule matches a real fixture claim, so a
  // compatible-cited verdict exists alongside ok/warn defaults.
  const POLICY_TOML = [
    "[[workspace.copyleft_suppressed]]",
    'path = "apps/shapes"',
    'license = "AGPL-3.0-only"',
    'description = "fixture workspace distributed under AGPL for the determinism case"',
    "",
    "[[compatible]]",
    'match = "license"',
    'pattern = "ISC"',
    'reason = "fixture compatible rule so a compatible-cited verdict exists"',
    "",
    "[unknown]",
    'handling = "warn"',
    "",
  ].join("\n");

  /** The FULL annotated pipeline from raw inputs: parse → merge → annotate → evaluate → serialize. */
  function buildAnnotated(): string {
    const policy = parsePolicy(POLICY_TOML);
    const model = mergeSboms([
      { sbom: JSON.parse(fixtureRaw), targetIdentity: TARGET },
      { sbom: JSON.parse(shapesRaw), targetIdentity: "apps/shapes" },
    ]);
    const { model: annotated } = annotateFindings(model, policy.clarify);
    const verdicts = evaluate(annotated, policy);
    const evaluated: EvaluatedDependencies = {
      packages: annotated.packages,
      verdicts,
    };
    return toSortedDependenciesJson(evaluated);
  }

  test("double-build of the policy-annotated dump is byte-identical", () => {
    const first = buildAnnotated();
    const second = buildAnnotated();
    expect(first).toBe(second);

    // The new surface is actually populated (not vacuously equal).
    expect(first).toContain('"finding"');
    expect(first).toContain('"verdicts"');
    expect(first).toContain('"compatible[0]"');
  });

  test("annotated dump keeps the LF contract: no CR, exactly one trailing LF", () => {
    const dump = buildAnnotated();
    expect(dump.includes("\r")).toBe(false);
    expect(dump.endsWith("\n")).toBe(true);
    expect(dump.endsWith("\n\n")).toBe(false);
  });
});

describe("determinism — LF and no-date contract", () => {
  const { md, dump } = build();

  test("output contains no CR and ends with exactly one trailing LF", () => {
    for (const output of [md, dump]) {
      expect(output.includes("\r")).toBe(false);
      expect(output.endsWith("\n")).toBe(true);
      expect(output.endsWith("\n\n")).toBe(false);
    }
  });

  test("the fixture's serialNumber UUID never reaches the output", () => {
    // Strip the urn:uuid: prefix so the assertion targets the UUID itself.
    const uuid = fixture.serialNumber.replace(/^urn:uuid:/, "");
    expect(uuid.length).toBeGreaterThan(0);
    expect(md.includes(uuid)).toBe(false);
    expect(dump.includes(uuid)).toBe(false);
  });

  test("the fixture's metadata.timestamp never reaches the output", () => {
    expect(fixture.metadata.timestamp.length).toBeGreaterThan(0);
    expect(md.includes(fixture.metadata.timestamp)).toBe(false);
    expect(dump.includes(fixture.metadata.timestamp)).toBe(false);
  });

  test("no year-shaped date appears near 'generated' (header carries no date)", () => {
    expect(/\b20\d\d\b.*generated/i.test(md)).toBe(false);
    expect(/\b20\d\d\b.*generated/i.test(dump)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Collector-path determinism, extended to the bun collector
// ---------------------------------------------------------------------------

/**
 * Temp bun fixture project for the collector double-run: a `@workspace:`
 * member (first-party, never emitted), a nested version-conflict key whose
 * value[0] carries the CORRECT identity, dev and prod roots, and the
 * machine-written trailing commas bun emits (04.5-RESEARCH Pattern 2
 * verified shapes). The top-level spdx-expression-parse@4.0.0 entry is
 * deliberately root-unreachable — unvisited stays prod (A4).
 */
const BUN_DET_LOCK = `{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "det-root",
      "dependencies": { "spdx-compare": "1.0.0" },
      "devDependencies": { "typescript": "5.9.3" },
    },
    "packages/libb": {
      "name": "libb",
      "version": "0.1.0",
      "dependencies": { "smol-toml": "1.6.1" },
    },
  },
  "packages": {
    "libb": ["libb@workspace:packages/libb"],
    "smol-toml": ["smol-toml@1.6.1", "", {}, "sha512-bbb"],
    "spdx-compare": ["spdx-compare@1.0.0", "", { "dependencies": { "spdx-expression-parse": "^3.0.0" } }, "sha512-eee"],
    "spdx-compare/spdx-expression-parse": ["spdx-expression-parse@3.0.1", "", {}, "sha512-fff"],
    "spdx-expression-parse": ["spdx-expression-parse@4.0.0", "", {}, "sha512-ggg"],
    "typescript": ["typescript@5.9.3", "", {}, "sha512-ccc"],
  },
}
`;

const BUN_TARGET_IDENTITY = "fixtures/bun-det";

const collectorTempDirs: string[] = [];

afterAll(() => {
  for (const dir of collectorTempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Writes the fixture lockfile + manifest into a fresh temp project dir. */
function makeBunFixtureTarget(): Target {
  const dir = mkdtempSync(join(tmpdir(), "licenses-det-bun-"));
  collectorTempDirs.push(dir);
  writeFileSync(join(dir, "bun.lock"), BUN_DET_LOCK);
  writeFileSync(
    join(dir, "package.json"),
    '{ "name": "det-root", "private": true }\n',
  );
  return { dir, identity: BUN_TARGET_IDENTITY };
}

/** One collector run into its own fresh temp dir; returns the raw bom bytes. */
async function collectBomText(target: Target): Promise<string> {
  const tempDir = mkdtempSync(join(tmpdir(), "licenses-det-out-"));
  collectorTempDirs.push(tempDir);
  const result = await collectWithBunLock(target, { tempDir });
  return readFileSync(result.sbomPath, "utf-8");
}

describe("determinism — bun collector double-run byte-identity", () => {
  test("two collector runs over the same lockfile write byte-identical bom.json", async () => {
    const target = makeBunFixtureTarget();
    const first = await collectBomText(target);
    const second = await collectBomText(target);
    expect(first).toBe(second);

    // Volatile-field absence contract extended to the collector's raw
    // output bytes: the fields are never WRITTEN, so they can never leak.
    expect(first.includes("serialNumber")).toBe(false);
    expect(first.includes("timestamp")).toBe(false);
  });

  test("double-build double-render of the collector bom is byte-identical", async () => {
    const bomText = await collectBomText(makeBunFixtureTarget());
    const build = (): { md: string; dump: string } => {
      const model = mergeSboms([
        { sbom: JSON.parse(bomText), targetIdentity: BUN_TARGET_IDENTITY },
      ]);
      return {
        md: renderMarkdown(model),
        dump: toSortedDependenciesJson(model),
      };
    };
    const first = build();
    const second = build();
    expect(first.md).toBe(second.md);
    expect(first.dump).toBe(second.dump);

    // Not vacuously equal: the nested-conflict purl reaches the model
    // alongside its 4.0.0 twin, and the first-party member never renders.
    expect(first.dump.includes("pkg:npm/spdx-expression-parse@3.0.1")).toBe(
      true,
    );
    expect(first.dump.includes("pkg:npm/spdx-expression-parse@4.0.0")).toBe(
      true,
    );
    expect(first.md.includes("libb")).toBe(false);

    // LF contract holds on the collector-fed render path too.
    expect(first.md.includes("\r")).toBe(false);
    expect(first.md.endsWith("\n")).toBe(true);
    expect(first.md.endsWith("\n\n")).toBe(false);
  });

  test("mixed bun + cdxgen-shaped npm fixture double-render is byte-identical (multi-PM)", async () => {
    const bomText = await collectBomText(makeBunFixtureTarget());
    const npmRaw = readFileSync(
      join(import.meta.dir, "fixtures", "npm-scope-properties.json"),
      "utf-8",
    );
    const build = (): { md: string; dump: string } => {
      const model = mergeSboms([
        { sbom: JSON.parse(bomText), targetIdentity: BUN_TARGET_IDENTITY },
        { sbom: JSON.parse(npmRaw), targetIdentity: "fixtures/npm-scope" },
      ]);
      return {
        md: renderMarkdown(model),
        dump: toSortedDependenciesJson(model),
      };
    };
    const first = build();
    const second = build();
    expect(first.md).toBe(second.md);
    expect(first.dump).toBe(second.dump);

    // Both kinds are present in the merged dump (multi-PM, not vacuous).
    expect(first.dump.includes("pkg:npm/smol-toml@1.6.1")).toBe(true);
    expect(
      first.dump.includes("pkg:npm/%40next/swc-win32-x64-msvc@16.0.10"),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Collector-path determinism, extended to the nuget collector
// ---------------------------------------------------------------------------

/**
 * Temp nuget fixture project for the collector double-run: a first-party
 * `"type": "Project"` entry (never emitted — the exclusion itself must be
 * deterministic), a CentralTransitive entry (the v2 CPM shape), and one
 * (id, resolved) pair repeated across two TFM sections so the cross-section
 * dedup is part of the double-run surface.
 */
const NUGET_DET_LOCK = `{
  "version": 2,
  "dependencies": {
    "net8.0": {
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
        "contentHash": "sha512-bbb"
      },
      "det.lib": {
        "type": "Project"
      }
    },
    "net9.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.4, )",
        "resolved": "13.0.4",
        "contentHash": "sha512-aaa"
      },
      "Serilog": {
        "type": "Transitive",
        "resolved": "4.3.1",
        "contentHash": "sha512-ccc"
      }
    }
  }
}
`;

const NUGET_TARGET_IDENTITY = "fixtures/nuget-det";

/** Writes the fixture lockfile into a fresh temp project dir. */
function makeNugetFixtureTarget(): Target {
  const dir = mkdtempSync(join(tmpdir(), "licenses-det-nuget-"));
  collectorTempDirs.push(dir);
  writeFileSync(join(dir, "packages.lock.json"), NUGET_DET_LOCK);
  return { dir, identity: NUGET_TARGET_IDENTITY };
}

/** One collector run into its own fresh temp dir; returns the raw bom bytes. */
async function collectNugetBomText(target: Target): Promise<string> {
  const tempDir = mkdtempSync(join(tmpdir(), "licenses-det-out-"));
  collectorTempDirs.push(tempDir);
  const result = await collectWithNugetLock(target, { tempDir });
  return readFileSync(result.sbomPath, "utf-8");
}

describe("determinism — nuget collector double-run byte-identity", () => {
  test("two collector runs over the same lockfile write byte-identical bom.json", async () => {
    const target = makeNugetFixtureTarget();
    const first = await collectNugetBomText(target);
    const second = await collectNugetBomText(target);
    expect(first).toBe(second);

    // Volatile-field absence contract on the collector's raw output bytes:
    // the fields are never WRITTEN, so they can never leak.
    expect(first.includes("serialNumber")).toBe(false);
    expect(first.includes("timestamp")).toBe(false);

    // The Project-entry exclusion is itself deterministic and total: the
    // first-party reference never appears in either run.
    expect(first.includes("det.lib")).toBe(false);
  });

  test("double-build double-render of the collector bom is byte-identical", async () => {
    const bomText = await collectNugetBomText(makeNugetFixtureTarget());
    const build = (): { md: string; dump: string } => {
      const model = mergeSboms([
        { sbom: JSON.parse(bomText), targetIdentity: NUGET_TARGET_IDENTITY },
      ]);
      return {
        md: renderMarkdown(model),
        dump: toSortedDependenciesJson(model),
      };
    };
    const first = build();
    const second = build();
    expect(first.md).toBe(second.md);
    expect(first.dump).toBe(second.dump);

    // Not vacuously equal: the CentralTransitive entry reaches the model,
    // the cross-section duplicate folds to one row, and the first-party
    // Project entry never renders.
    expect(
      first.dump.includes("pkg:nuget/Microsoft.Extensions.Logging@9.0.9"),
    ).toBe(true);
    expect(first.dump.includes("pkg:nuget/Newtonsoft.Json@13.0.4")).toBe(true);
    expect(first.md.includes("det.lib")).toBe(false);

    // LF contract holds on the collector-fed render path too.
    expect(first.md.includes("\r")).toBe(false);
    expect(first.md.endsWith("\n")).toBe(true);
    expect(first.md.endsWith("\n\n")).toBe(false);
  });
});
