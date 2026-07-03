import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { mergeSboms, purlSetOf } from "../src/merge/merge";
import {
  comparePackages,
  toSortedDependenciesJson,
  type CanonicalDependencies,
  type DependencyIntroduction,
  type PackageEntry,
} from "../src/model/dependencies";

const TARGET = "libraries/iframe-rpc";
const SYNTHETIC_TARGET = "apps/synthetic";

function loadFixture(name: string): unknown {
  return JSON.parse(
    readFileSync(join(import.meta.dir, "fixtures", name), "utf-8"),
  );
}

const volatileDoc = loadFixture("volatile-retained.json");
const trimmedDoc = loadFixture("iframe-rpc-trimmed.json");
const shapesDoc = loadFixture("license-shapes.json");
const pluginFullDoc = loadFixture("plugin-full.json");
const pluginProdDoc = loadFixture("plugin-prod.json");
const poetryGroupsDoc = loadFixture("poetry-groups.json");

function shapesByPurl(): Map<string, PackageEntry> {
  const model = mergeSboms([
    { sbom: shapesDoc, targetIdentity: SYNTHETIC_TARGET },
  ]);
  return new Map(model.packages.map((p) => [p.purl, p]));
}

describe("mergeSboms — volatile field immunity (INV-03)", () => {
  test("a doc RETAINING serialNumber/timestamp/annotations yields a model containing none of their values", () => {
    const json = toSortedDependenciesJson(
      mergeSboms([{ sbom: volatileDoc, targetIdentity: TARGET }]),
    );

    // serialNumber UUID substring
    expect(json.includes("3e671687")).toBe(false);
    // metadata.timestamp AND annotations[].timestamp share this date prefix
    expect(json.includes("2026-06-10")).toBe(false);
    // annotations[].text prose date (the hidden fourth volatile field)
    expect(json.includes("created on Wednesday")).toBe(false);
  });

  test("volatile-retained and trimmed fixtures produce byte-identical models", () => {
    const fromVolatile = toSortedDependenciesJson(
      mergeSboms([{ sbom: volatileDoc, targetIdentity: TARGET }]),
    );
    const fromTrimmed = toSortedDependenciesJson(
      mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]),
    );

    expect(fromVolatile).toBe(fromTrimmed);
  });
});

describe("mergeSboms — license claim shapes", () => {
  test("license.id becomes a spdx-id claim", () => {
    expect(shapesByPurl().get("pkg:npm/mit-pkg@1.0.0")?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("license.name becomes a name claim", () => {
    expect(
      shapesByPurl().get("pkg:npm/apache-name-pkg@2.0.0")?.licenseClaims,
    ).toEqual([
      { raw: "Apache License 2.0", kind: "name", source: "generator" },
    ]);
  });

  test("expression becomes an expression claim", () => {
    expect(shapesByPurl().get("pkg:npm/expr-pkg@3.0.0")?.licenseClaims).toEqual(
      [{ raw: "MIT OR Apache-2.0", kind: "expression", source: "generator" }],
    );
  });

  test("a component without a licenses key yields an empty claims array", () => {
    expect(
      shapesByPurl().get("pkg:npm/no-license-pkg@0.1.0")?.licenseClaims,
    ).toEqual([]);
  });
});

describe("mergeSboms — purl-keyed dedup and root exclusion", () => {
  test("two components sharing one purl produce exactly one PackageEntry", () => {
    const model = mergeSboms([
      { sbom: shapesDoc, targetIdentity: SYNTHETIC_TARGET },
    ]);
    const dups = model.packages.filter(
      (p) => p.purl === "pkg:npm/dup-pkg@1.2.3",
    );

    expect(dups.length).toBe(1);
    // Prod-wins dev fold (POL-08 safety): one contribution is dev-marked, the
    // other (production) carries no marker — the production contribution forces
    // the merged occurrence to production. A shipped occurrence is never masked
    // to dev.
    expect(dups[0]?.occurrences).toEqual([
      { target: SYNTHETIC_TARGET, isDevDependency: false },
    ]);
    // claims concatenated across the duplicate entries
    expect(dups[0]?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("duplicate purl entries BOTH carrying the same license claim yield exactly one claim", () => {
    // The real cdxgen dup shape: one entry sourced from yarn.lock, one from
    // package.json, both claiming MIT — must not render "MIT, MIT".
    const doc = {
      components: [
        {
          name: "twice-pkg",
          version: "1.0.0",
          purl: "pkg:npm/twice-pkg@1.0.0",
          licenses: [{ license: { id: "MIT" } }],
          properties: [{ name: "SrcFile", value: "yarn.lock" }],
        },
        {
          name: "twice-pkg",
          version: "1.0.0",
          purl: "pkg:npm/twice-pkg@1.0.0",
          licenses: [{ license: { id: "MIT" } }],
          properties: [{ name: "SrcFile", value: "package.json" }],
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages.length).toBe(1);
    expect(model.packages[0]?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("claims differing in raw value or kind all survive the dedup", () => {
    const doc = {
      components: [
        {
          name: "multi-pkg",
          version: "1.0.0",
          purl: "pkg:npm/multi-pkg@1.0.0",
          licenses: [{ license: { id: "MIT" } }],
        },
        {
          name: "multi-pkg",
          version: "1.0.0",
          purl: "pkg:npm/multi-pkg@1.0.0",
          licenses: [{ license: { name: "MIT" } }, { license: { id: "ISC" } }],
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages[0]?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
      { raw: "MIT", kind: "name", source: "generator" },
      { raw: "ISC", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("the same document merged for two targets does not duplicate claims", () => {
    // The multi-target merge shape: every shared dependency with a known
    // license would otherwise render "MIT, MIT".
    const model = mergeSboms([
      { sbom: shapesDoc, targetIdentity: "apps/a" },
      { sbom: shapesDoc, targetIdentity: "apps/b" },
    ]);
    const mitPkg = model.packages.find(
      (p) => p.purl === "pkg:npm/mit-pkg@1.0.0",
    );

    expect(mitPkg?.occurrences).toEqual([
      { target: "apps/a", isDevDependency: false },
      { target: "apps/b", isDevDependency: false },
    ]);
    expect(mitPkg?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("a components[] entry whose purl equals metadata.component.purl is excluded", () => {
    const entries = shapesByPurl();
    expect(entries.has("pkg:npm/synthetic-root@1.0.0")).toBe(false);
  });

  test("metadata.component itself never becomes a package", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    expect(model.packages.some((p) => p.purl === "pkg:npm/iframe-rpc")).toBe(
      false,
    );
    expect(model.packages.some((p) => p.name === "iframe-rpc")).toBe(false);
  });
});

describe("mergeSboms — dev marker, scope, and display name", () => {
  test("cdx:npm:package:development=true maps to a dev-marked occurrence", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    const remapping = model.packages.find(
      (p) => p.purl === "pkg:npm/%40ampproject/remapping@2.3.0",
    );

    expect(remapping?.occurrences).toEqual([
      { target: TARGET, isDevDependency: true },
    ]);
    expect(remapping?.rawScope).toBe("optional");
  });

  test("a component without the dev property maps to a prod occurrence", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    const semver = model.packages.find(
      (p) => p.purl === "pkg:npm/semver@7.6.0",
    );

    expect(semver?.occurrences).toEqual([
      { target: TARGET, isDevDependency: false },
    ]);
    expect(semver?.rawScope).toBe("required");
  });

  test("scope taxonomy is 'app' for every entry this phase", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    expect(model.packages.length).toBeGreaterThan(0);
    expect(model.packages.every((p) => p.scope === "app")).toBe(true);
  });

  test("group '@ampproject' + name 'remapping' gets display name '@ampproject/remapping'", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    const remapping = model.packages.find(
      (p) => p.purl === "pkg:npm/%40ampproject/remapping@2.3.0",
    );

    expect(remapping?.name).toBe("@ampproject/remapping");
  });

  // Inline doc modeling the real cdxgen shape from the live SBOM (gap 19):
  // ungrouped npm packages are emitted with group: "" — not an absent key.
  // Raw SBOM showed {"name":"abab","group":"","purl":"pkg:npm/abab@2.0.6"}.
  const groupShapesDoc = {
    components: [
      {
        name: "abab",
        version: "2.0.6",
        purl: "pkg:npm/abab@2.0.6",
        group: "",
      },
      {
        name: "pkg-a",
        version: "1.0.0",
        purl: "pkg:npm/%40scope/pkg-a@1.0.0",
        group: "@scope",
      },
      {
        name: "bare-pkg",
        version: "1.0.0",
        purl: "pkg:npm/bare-pkg@1.0.0",
      },
    ],
  };

  test("group '' (the real cdxgen ungrouped shape) yields the bare name with no leading slash", () => {
    const model = mergeSboms([
      { sbom: groupShapesDoc, targetIdentity: SYNTHETIC_TARGET },
    ]);
    const abab = model.packages.find((p) => p.purl === "pkg:npm/abab@2.0.6");

    expect(abab?.name).toBe("abab");
    expect(abab?.name.startsWith("/")).toBe(false);
  });

  test("fixture component with group '' yields a slash-free display name", () => {
    const entry = shapesByPurl().get("pkg:npm/empty-group-pkg@1.0.0");

    expect(entry?.name).toBe("empty-group-pkg");
    expect(entry?.name.startsWith("/")).toBe(false);
  });

  test("scoped group and absent group keep their existing display-name contracts", () => {
    const model = mergeSboms([
      { sbom: groupShapesDoc, targetIdentity: SYNTHETIC_TARGET },
    ]);
    const byPurl = new Map(model.packages.map((p) => [p.purl, p]));

    expect(byPurl.get("pkg:npm/%40scope/pkg-a@1.0.0")?.name).toBe(
      "@scope/pkg-a",
    );
    expect(byPurl.get("pkg:npm/bare-pkg@1.0.0")?.name).toBe("bare-pkg");
  });
});

describe("mergeSboms — ordering, occurrences, and malformed entries", () => {
  test("packages are sorted by comparePackages", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    const resorted = [...model.packages].sort(comparePackages);

    expect(model.packages).toEqual(resorted);
  });

  test("each entry's occurrences equal [targetIdentity]", () => {
    const model = mergeSboms([{ sbom: trimmedDoc, targetIdentity: TARGET }]);
    expect(model.packages.length).toBeGreaterThan(0);
    expect(model.packages.every((p) => p.occurrences.length === 1)).toBe(true);
    expect(
      model.packages.every((p) => p.occurrences[0]?.target === TARGET),
    ).toBe(true);
  });

  test("multiple inputs union occurrences, sorted ascending", () => {
    const model = mergeSboms([
      { sbom: trimmedDoc, targetIdentity: "libraries/iframe-rpc" },
      { sbom: trimmedDoc, targetIdentity: "apps/example" },
    ]);

    expect(model.packages.length).toBeGreaterThan(0);
    for (const pkg of model.packages) {
      expect(pkg.occurrences.map((o) => o.target)).toEqual([
        "apps/example",
        "libraries/iframe-rpc",
      ]);
    }
  });

  test("the same target identity twice is deduped in occurrences", () => {
    const model = mergeSboms([
      { sbom: trimmedDoc, targetIdentity: TARGET },
      { sbom: trimmedDoc, targetIdentity: TARGET },
    ]);

    expect(model.packages.every((p) => p.occurrences.length === 1)).toBe(true);
  });

  test("entries lacking a string purl, name, or version are skipped without throwing", () => {
    const model = mergeSboms([
      { sbom: shapesDoc, targetIdentity: SYNTHETIC_TARGET },
    ]);

    expect(model.packages.some((p) => p.name === "missing-everything")).toBe(
      false,
    );
    expect(model.packages.some((p) => p.name === "bad-version")).toBe(false);
  });
});

describe("mergeSboms — field-level tolerance at the boundary (C1, W1, I1)", () => {
  // The boundary's contract: a present-but-wrong-typed OPTIONAL field never
  // drops a component or a document — only an absent/non-string purl/name/
  // version triple is a drop gate. These prove the pre-refactor per-field
  // leniency is restored: a wrong-typed optional is treated as ABSENT, the
  // package is KEPT.

  // W1: one wrong-typed optional field on an otherwise-valid component.
  const wrongTypedOptionals: Array<[string, Record<string, unknown>]> = [
    ["group: 5", { group: 5 }],
    ["group: null", { group: null }],
    ["scope: 99", { scope: 99 }],
    ["author: array", { author: ["x"] }],
    ["licenses: string", { licenses: "MIT" }],
    ["properties: object", { properties: {} }],
    ["evidence: string", { evidence: "x" }],
  ];

  for (const [label, extra] of wrongTypedOptionals) {
    test(`a valid purl/name/version with wrong-typed ${label} is KEPT, the field absent`, () => {
      const doc = {
        components: [
          {
            name: "kept-pkg",
            version: "1.0.0",
            purl: "pkg:npm/kept-pkg@1.0.0",
            ...extra,
          },
        ],
      };
      const model = mergeSboms([
        { sbom: doc, targetIdentity: SYNTHETIC_TARGET },
      ]);

      expect(model.packages.length).toBe(1);
      const pkg = model.packages[0];
      // Wrong-typed group → displayName falls back to the bare name.
      expect(pkg?.name).toBe("kept-pkg");
      // Wrong-typed scope → no rawScope recorded.
      expect(pkg?.rawScope).toBeUndefined();
      // Wrong-typed licenses → empty claims (non-array coerces to absent).
      expect(pkg?.licenseClaims).toEqual([]);
      // Wrong-typed author/evidence → no attribution fabricated.
      expect(pkg?.attribution).toBeUndefined();
    });
  }

  test("valid group/scope still apply normally (leniency does not blanket-drop good values)", () => {
    const doc = {
      components: [
        {
          name: "pkg-a",
          version: "1.0.0",
          purl: "pkg:npm/%40scope/pkg-a@1.0.0",
          group: "@scope",
          scope: "required",
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages[0]?.name).toBe("@scope/pkg-a");
    expect(model.packages[0]?.rawScope).toBe("required");
  });

  // C1: malformed metadata must not drop the whole components array.
  test("metadata: null with two valid components yields TWO packages (root purl simply absent)", () => {
    const doc = {
      metadata: null,
      components: [
        { name: "a", version: "1.0.0", purl: "pkg:npm/a@1.0.0" },
        { name: "b", version: "2.0.0", purl: "pkg:npm/b@2.0.0" },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages.map((p) => p.purl).sort()).toEqual([
      "pkg:npm/a@1.0.0",
      "pkg:npm/b@2.0.0",
    ]);
  });

  test("metadata.component.purl: number (non-string) keeps all components, excludes nothing as root", () => {
    const doc = {
      metadata: { component: { purl: 12345 } },
      components: [
        { name: "a", version: "1.0.0", purl: "pkg:npm/a@1.0.0" },
        { name: "b", version: "2.0.0", purl: "pkg:npm/b@2.0.0" },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages.length).toBe(2);
  });

  test("a valid string root purl is still excluded from the inventory (no regression)", () => {
    const doc = {
      metadata: { component: { purl: "pkg:npm/root@0.0.0" } },
      components: [
        { name: "root", version: "0.0.0", purl: "pkg:npm/root@0.0.0" },
        { name: "a", version: "1.0.0", purl: "pkg:npm/a@1.0.0" },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages.map((p) => p.purl)).toEqual(["pkg:npm/a@1.0.0"]);
  });

  // I1: purlSetOf must read purl through an independent tolerant narrow —
  // malformed metadata or a mistyped sibling field never empties the set.
  test("purlSetOf with metadata: null still collects every component purl", () => {
    const doc = {
      metadata: null,
      components: [
        { name: "a", version: "1.0.0", purl: "pkg:npm/a@1.0.0" },
        { name: "b", version: "2.0.0", purl: "pkg:npm/b@2.0.0" },
      ],
    };

    expect([...purlSetOf(doc)].sort()).toEqual([
      "pkg:npm/a@1.0.0",
      "pkg:npm/b@2.0.0",
    ]);
  });

  test("purlSetOf keeps a component's purl even when a sibling optional field is wrong-typed", () => {
    const doc = {
      components: [
        {
          name: "p",
          version: "1.0.0",
          purl: "pkg:npm/p@1.0.0",
          group: 5,
        },
      ],
    };

    expect([...purlSetOf(doc)]).toEqual(["pkg:npm/p@1.0.0"]);
  });
});

describe("mergeSboms — occurrence-level dev/prod scope", () => {
  // The multi-target shape: the same purl consumed by two workspaces,
  // dev-marked in only one — "dev in docs, prod in frontend" is legal and both
  // flags must survive independently.
  const devProperty = { name: "cdx:npm:package:development", value: "true" };
  const sharedDevDoc = {
    components: [
      {
        name: "shared-pkg",
        version: "1.0.0",
        purl: "pkg:npm/shared-pkg@1.0.0",
        properties: [devProperty],
      },
    ],
  };
  const sharedProdDoc = {
    components: [
      {
        name: "shared-pkg",
        version: "1.0.0",
        purl: "pkg:npm/shared-pkg@1.0.0",
      },
    ],
  };

  test("a purl shared by two targets carries independent per-target dev flags", () => {
    const model = mergeSboms([
      { sbom: sharedDevDoc, targetIdentity: "apps/a" },
      { sbom: sharedProdDoc, targetIdentity: "apps/b" },
    ]);

    // One row per purl with one occurrence object per target.
    expect(model.packages.length).toBe(1);
    expect(model.packages[0]?.occurrences).toEqual([
      { target: "apps/a", isDevDependency: true },
      { target: "apps/b", isDevDependency: false },
    ]);
  });

  test("the same purl twice in ONE document folds dev flags prod-wins into one occurrence", () => {
    // Property-marker collectors (cdxgen/bun) can emit the same purl twice for
    // one target with DIVERGENT dev markers — here one component is dev-marked
    // and its twin is not (production). The fold is prod-wins: the production
    // twin forces the single occurrence to production, so a shipped copyleft can
    // never be masked to dev (POL-08 safety). The plugin dual-run path never
    // diverges — its duplicates share dev = !prodPurlSet.has(purl) — so this
    // fold direction is observable only on the property-marker collectors.
    const doc = {
      components: [
        {
          name: "dup-scope-pkg",
          version: "1.0.0",
          purl: "pkg:npm/dup-scope-pkg@1.0.0",
          properties: [devProperty],
        },
        {
          name: "dup-scope-pkg",
          version: "1.0.0",
          purl: "pkg:npm/dup-scope-pkg@1.0.0",
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: SYNTHETIC_TARGET }]);

    expect(model.packages.length).toBe(1);
    expect(model.packages[0]?.occurrences).toEqual([
      { target: SYNTHETIC_TARGET, isDevDependency: false },
    ]);
  });

  test("occurrences sort by target via compareCodeUnits regardless of input order", () => {
    // Merge inputs given in reverse target order still yield sorted output.
    const model = mergeSboms([
      { sbom: sharedProdDoc, targetIdentity: "apps/b" },
      { sbom: sharedDevDoc, targetIdentity: "apps/a" },
    ]);

    expect(model.packages[0]?.occurrences).toEqual([
      { target: "apps/a", isDevDependency: true },
      { target: "apps/b", isDevDependency: false },
    ]);
  });
});

describe("mergeSboms — CollectedSbom.scope threading (COLL-04)", () => {
  // A minimal Docker OS-SBOM (07-01 emitter shape): one deb + one apk component.
  const osDoc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      {
        type: "library",
        name: "libc6",
        version: "2.36-9",
        purl: "pkg:deb/debian/libc6@2.36-9",
      },
      {
        type: "library",
        name: "musl",
        version: "1.2.4-r2",
        purl: "pkg:apk/alpine/musl@1.2.4-r2",
      },
    ],
  };

  test('an input with scope:"os" tags every produced PackageEntry scope "os"', () => {
    const model = mergeSboms([
      { sbom: osDoc, targetIdentity: "docker:os-packages", scope: "os" },
    ]);
    expect(model.packages.length).toBe(2);
    expect(model.packages.every((p) => p.scope === "os")).toBe(true);
  });

  test('absent scope still defaults to "app" (regression — existing entries unchanged)', () => {
    const model = mergeSboms([
      { sbom: osDoc, targetIdentity: "docker:os-packages" },
    ]);
    expect(model.packages.length).toBe(2);
    expect(model.packages.every((p) => p.scope === "app")).toBe(true);
  });

  test("scope is per-input: app-scope and os-scope inputs coexist in one model", () => {
    const model = mergeSboms([
      { sbom: trimmedDoc, targetIdentity: TARGET },
      { sbom: osDoc, targetIdentity: "docker:os-packages", scope: "os" },
    ]);
    const os = model.packages.filter((p) => p.scope === "os");
    const app = model.packages.filter((p) => p.scope === "app");
    expect(os.map((p) => p.purl).sort()).toEqual([
      "pkg:apk/alpine/musl@1.2.4-r2",
      "pkg:deb/debian/libc6@2.36-9",
    ]);
    expect(app.length).toBeGreaterThan(0);
    expect(app.every((p) => p.purl.startsWith("pkg:npm/"))).toBe(true);
  });

  // #4: mergeInto never reconciled scope on a purl collision, so a purl shared
  // between a gating (app) input and a non-gating (os) input could be silently
  // demoted to "os" purely by input order. The gating "app" scope must WIN so a
  // shared dependency is never silently moved out of the gate.
  describe("scope reconciliation on a shared purl (#4: gating app wins over os)", () => {
    const SHARED = "pkg:deb/debian/libc6@2.36-9";
    const appDoc = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        { type: "library", name: "libc6", version: "2.36-9", purl: SHARED },
      ],
    };

    test("os-input FIRST, app-input second → shared purl resolves to app", () => {
      const model = mergeSboms([
        { sbom: osDoc, targetIdentity: "docker:os-packages", scope: "os" },
        { sbom: appDoc, targetIdentity: "backend" },
      ]);
      const shared = model.packages.find((p) => p.purl === SHARED);
      expect(shared?.scope).toBe("app");
    });

    test("app-input FIRST, os-input second → shared purl still resolves to app (order-independent)", () => {
      const model = mergeSboms([
        { sbom: appDoc, targetIdentity: "backend" },
        { sbom: osDoc, targetIdentity: "docker:os-packages", scope: "os" },
      ]);
      const shared = model.packages.find((p) => p.purl === SHARED);
      expect(shared?.scope).toBe("app");
    });

    test("a purl present ONLY in os input keeps os scope (no spurious promotion)", () => {
      const model = mergeSboms([
        { sbom: osDoc, targetIdentity: "docker:os-packages", scope: "os" },
      ]);
      const musl = model.packages.find(
        (p) => p.purl === "pkg:apk/alpine/musl@1.2.4-r2",
      );
      expect(musl?.scope).toBe("os");
    });
  });
});

// DOCK-03: full-image scan collision semantics. These are PROOF tests — the
// dedup behavior is already implemented by mergeInto's #4 app-wins scope
// reconciliation (merge.ts:458-465) and its prod-wins occurrence fold
// (merge.ts:424-441), plus mergeSboms' purl-verbatim byPurl key. Nothing here
// changes src/merge/merge.ts; a red test in this describe is a real finding.
describe("mergeSboms — full-image scope collision (app wins, image occurrence annotated)", () => {
  // A %40-scoped npm purl — the verified purl-encoding-compatible case between
  // the app generators (cdxgen/yarn plugin) and syft's image scan.
  const SHARED_NPM = "pkg:npm/%40scope/shared@1.0.0";

  const appDoc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      {
        type: "library",
        name: "shared",
        group: "@scope",
        version: "1.0.0",
        purl: SHARED_NPM,
      },
    ],
  };

  const imageDoc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      {
        type: "library",
        name: "shared",
        group: "@scope",
        version: "1.0.0",
        purl: SHARED_NPM,
      },
    ],
  };

  test("an npm purl shared between an app input and the image input folds to one app-scope row with the docker occurrence in Used-in — os-first order", () => {
    const model = mergeSboms([
      { sbom: imageDoc, targetIdentity: "docker:os-packages", scope: "os" },
      { sbom: appDoc, targetIdentity: "backend" },
    ]);
    const shared = model.packages.filter((p) => p.purl === SHARED_NPM);

    // ONE row, never two — the D-10 "annotated, never duplicated" posture.
    expect(shared.length).toBe(1);
    expect(shared[0]?.scope).toBe("app");
    expect(shared[0]?.occurrences).toEqual([
      { target: "backend", isDevDependency: false },
      { target: "docker:os-packages", isDevDependency: false },
    ]);
  });

  test("an npm purl shared between an app input and the image input folds to one app-scope row with the docker occurrence in Used-in — app-first order (#4 makes order irrelevant)", () => {
    const model = mergeSboms([
      { sbom: appDoc, targetIdentity: "backend" },
      { sbom: imageDoc, targetIdentity: "docker:os-packages", scope: "os" },
    ]);
    const shared = model.packages.filter((p) => p.purl === SHARED_NPM);

    expect(shared.length).toBe(1);
    expect(shared[0]?.scope).toBe("app");
    expect(shared[0]?.occurrences).toEqual([
      { target: "backend", isDevDependency: false },
      { target: "docker:os-packages", isDevDependency: false },
    ]);
  });

  // Pitfall 5, Option 1 (annotate): a package the app lockfile marks dev-only
  // still ships in the built image. The image occurrence is never dev (syft
  // carries no dev/prod concept), so mergeInto's prod-wins occurrence fold
  // NEVER collapses the two into one dev-only occurrence — each target keeps
  // its own flag. The package-level classification (render/markdown.ts
  // isDevelopmentOnly: production iff ANY occurrence is non-dev) therefore
  // reads production. This is the conscious, locked consequence: a package
  // shipped in a distributed image carries production distribution
  // obligations even when the app lockfile marks it dev.
  test("a dev-only app package that also ships in the image classifies as production (annotate decision)", () => {
    const devAppDoc = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        {
          type: "library",
          name: "shared",
          group: "@scope",
          version: "1.0.0",
          purl: SHARED_NPM,
          properties: [{ name: "cdx:npm:package:development", value: "true" }],
        },
      ],
    };
    const model = mergeSboms([
      { sbom: devAppDoc, targetIdentity: "backend" },
      { sbom: imageDoc, targetIdentity: "docker:os-packages", scope: "os" },
    ]);
    const shared = model.packages.find((p) => p.purl === SHARED_NPM);

    // Occurrence-level flags per target — the shape that drives the
    // package-level classification (isDevelopmentOnly requires EVERY
    // occurrence dev; here one is not, so the package is production).
    expect(shared?.occurrences).toEqual([
      { target: "backend", isDevDependency: true },
      { target: "docker:os-packages", isDevDependency: false },
    ]);
    expect(shared?.occurrences.every((o) => o.isDevDependency)).toBe(false);
  });

  test("an image-only package keeps scope os", () => {
    const osOnlyDoc = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        {
          type: "library",
          name: "libc6",
          version: "2.36-9",
          purl: "pkg:deb/debian/libc6@2.36-9",
        },
      ],
    };
    const model = mergeSboms([
      { sbom: osOnlyDoc, targetIdentity: "docker:os-packages", scope: "os" },
    ]);
    const os = model.packages.find(
      (p) => p.purl === "pkg:deb/debian/libc6@2.36-9",
    );

    expect(os?.scope).toBe("os");
  });

  // Documented limitation of the generated-image model: a component whose
  // name/purl matches the scanning repo's own package, arriving ONLY via the
  // image input, has no rootPurl to exclude it against (the docker OS-SBOM
  // input carries no metadata.component — rootPurlOf reads undefined for it),
  // so the self-reference is retained as a normal os-scope row rather than
  // filtered as first-party. A built image containing the app itself lists it
  // under the image scope.
  test("a component named like the scanning repo arriving only via the image input is retained as an os row (documented limitation)", () => {
    const selfInImageDoc = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        {
          type: "library",
          name: "sbomlet",
          version: "1.0.0",
          purl: "pkg:npm/sbomlet@1.0.0",
        },
      ],
    };
    const model = mergeSboms([
      {
        sbom: selfInImageDoc,
        targetIdentity: "docker:os-packages",
        scope: "os",
      },
    ]);
    const self = model.packages.find((p) => p.purl === "pkg:npm/sbomlet@1.0.0");

    expect(self).toBeDefined();
    expect(self?.scope).toBe("os");
  });
});

describe("mergeSboms — plugin dual-run prod diff", () => {
  // The plugin emits NO properties and NO scope on any component (verified
  // live); dev/prod is derived exclusively from the dual-run set diff:
  // dev = full-run purls ∖ production-run purls.
  function pluginModel(
    prodPurlSet: ReadonlySet<string>,
  ): Map<string, PackageEntry> {
    const model = mergeSboms([
      { sbom: pluginFullDoc, targetIdentity: TARGET, prodPurlSet },
    ]);
    return new Map(model.packages.map((p) => [p.purl, p]));
  }

  test("purls absent from the prod run are dev; purls present in the prod run are prod", () => {
    const byPurl = pluginModel(purlSetOf(pluginProdDoc));

    // full-only → dev
    expect(byPurl.get("pkg:npm/%40eslint/eslintrc@3.3.3")?.occurrences).toEqual(
      [{ target: TARGET, isDevDependency: true }],
    );
    expect(byPurl.get("pkg:npm/type-fest@4.26.1")?.occurrences).toEqual([
      { target: TARGET, isDevDependency: true },
    ]);
    // present in prod → prod
    expect(byPurl.get("pkg:npm/semver@7.7.1")?.occurrences).toEqual([
      { target: TARGET, isDevDependency: false },
    ]);
    expect(byPurl.get("pkg:npm/argparse@2.0.1")?.occurrences).toEqual([
      { target: TARGET, isDevDependency: false },
    ]);
  });

  test("an EMPTY prod purl set marks every occurrence dev (verified devDeps-only case)", () => {
    // Mirrors the verified iframe-rpc run: --production on a devDeps-only
    // project yields exactly 0 components, so everything in full is dev.
    const byPurl = pluginModel(new Set());

    for (const pkg of byPurl.values()) {
      expect(pkg.occurrences).toEqual([
        { target: TARGET, isDevDependency: true },
      ]);
    }
    expect(byPurl.size).toBeGreaterThan(0);
  });

  test("prodPurlSet is authoritative over the cdxgen dev property when both are present", () => {
    // RESEARCH Open Question 7: each generator's own semantics apply per
    // target — when the dual-run diff exists, property markers are ignored.
    const doc = {
      components: [
        {
          name: "marked-dev-pkg",
          version: "1.0.0",
          purl: "pkg:npm/marked-dev-pkg@1.0.0",
          properties: [{ name: "cdx:npm:package:development", value: "true" }],
        },
      ],
    };
    const model = mergeSboms([
      {
        sbom: doc,
        targetIdentity: SYNTHETIC_TARGET,
        prodPurlSet: new Set(["pkg:npm/marked-dev-pkg@1.0.0"]),
      },
    ]);

    expect(model.packages[0]?.occurrences).toEqual([
      { target: SYNTHETIC_TARGET, isDevDependency: false },
    ]);
  });

  test("the CycloneDX-1.6 acknowledgement field parses through unchanged as a normal spdx-id claim", () => {
    const byPurl = pluginModel(purlSetOf(pluginProdDoc));

    expect(
      byPurl.get("pkg:npm/%40eslint/eslintrc@3.3.3")?.licenseClaims,
    ).toEqual([{ raw: "MIT", kind: "spdx-id", source: "generator" }]);
    expect(byPurl.get("pkg:npm/semver@7.7.1")?.licenseClaims).toEqual([
      { raw: "ISC", kind: "spdx-id", source: "generator" },
    ]);
  });

  test("the plugin's exact-duplicate purl pair folds to one entry with one occurrence", () => {
    // The verified virtual-instance artifact: 21 exact-duplicate purl pairs
    // on iframe-rpc. plugin-full.json carries one such pair (type-fest).
    const model = mergeSboms([
      {
        sbom: pluginFullDoc,
        targetIdentity: TARGET,
        prodPurlSet: purlSetOf(pluginProdDoc),
      },
    ]);
    const dups = model.packages.filter(
      (p) => p.purl === "pkg:npm/type-fest@4.26.1",
    );

    expect(dups.length).toBe(1);
    expect(dups[0]?.occurrences).toEqual([
      { target: TARGET, isDevDependency: true },
    ]);
    expect(dups[0]?.licenseClaims).toEqual([
      { raw: "(MIT OR CC0-1.0)", kind: "expression", source: "generator" },
    ]);
  });
});

describe("mergeSboms — python dev-group marker", () => {
  const PY_TARGET = "apps/jupyter";

  test("cdx:pyproject:group 'dev' is dev; custom group and group-less stay prod; purls are pkg:pypi", () => {
    const model = mergeSboms([
      { sbom: poetryGroupsDoc, targetIdentity: PY_TARGET },
    ]);
    const byPurl = new Map(model.packages.map((p) => [p.purl, p]));

    expect(byPurl.get("pkg:pypi/pytest@8.3.4")?.occurrences).toEqual([
      { target: PY_TARGET, isDevDependency: true },
    ]);
    // custom group "docs" stays prod (conservative semantics)
    expect(byPurl.get("pkg:pypi/sphinx@8.1.3")?.occurrences).toEqual([
      { target: PY_TARGET, isDevDependency: false },
    ]);
    // no group property at all stays prod
    expect(byPurl.get("pkg:pypi/anyio@4.8.0")?.occurrences).toEqual([
      { target: PY_TARGET, isDevDependency: false },
    ]);
    expect(model.packages.every((p) => p.purl.startsWith("pkg:pypi/"))).toBe(
      true,
    );
  });
});

describe("mergeSboms — npm optional guard on the dev property", () => {
  // npm-scope-properties.json carries the verified cdxgen 12.5.1 component
  // shapes: optional-prod platform binaries (the @next/swc-* class) carry both
  // cdx:npm:package:development=true and cdx:npm:package:optional=true. The
  // rule: isDev = development && !optional — without the guard those binaries
  // vanish into the dev column and their prod license obligations are silently
  // understated.
  const scopePropsDoc = loadFixture("npm-scope-properties.json");
  const NPM_TARGET = "fixture/npm-app";

  function scopeByPurl(): Map<string, PackageEntry> {
    const model = mergeSboms([
      { sbom: scopePropsDoc, targetIdentity: NPM_TARGET },
    ]);
    return new Map(model.packages.map((p) => [p.purl, p]));
  }

  test("development=true alone still maps to a dev occurrence", () => {
    expect(
      scopeByPurl().get("pkg:npm/dev-only-pkg@1.0.0")?.occurrences,
    ).toEqual([{ target: NPM_TARGET, isDevDependency: true }]);
  });

  test("development=true AND optional=true merges as PROD (the @next/swc-* platform-binary class)", () => {
    const swc = scopeByPurl().get("pkg:npm/%40next/swc-win32-x64-msvc@16.0.10");

    expect(swc?.occurrences).toEqual([
      { target: NPM_TARGET, isDevDependency: false },
    ]);
    // The fixture's scope: "excluded" field is recorded raw but NEVER drives
    // the dev decision — properties only (Phase-1/2 rule re-confirmed on npm).
    expect(swc?.rawScope).toBe("excluded");
  });

  test("optional=true alone is prod (cdxgen never emits this, but the guard is independent of the dev property)", () => {
    expect(
      scopeByPurl().get("pkg:npm/optional-only-pkg@2.0.0")?.occurrences,
    ).toEqual([{ target: NPM_TARGET, isDevDependency: false }]);
  });

  test("the guard is order-independent: optional listed BEFORE development still merges prod", () => {
    expect(
      scopeByPurl().get("pkg:npm/optional-first-pkg@3.0.0")?.occurrences,
    ).toEqual([{ target: NPM_TARGET, isDevDependency: false }]);
  });

  test("cdx:pyproject:group=dev stays dev — the python branch is independent of the guard", () => {
    expect(scopeByPurl().get("pkg:pypi/pydev-pkg@1.0.0")?.occurrences).toEqual([
      { target: NPM_TARGET, isDevDependency: true },
    ]);
  });

  test("a target with prodPurlSet never consults properties — the guard cannot leak into plugin targets", () => {
    // The dev+optional component's purl is ABSENT from the prod set, so the
    // dual-run diff says dev — even though the guard would say prod. The
    // prodPurlSet branch stays authoritative and property-free.
    const model = mergeSboms([
      {
        sbom: scopePropsDoc,
        targetIdentity: NPM_TARGET,
        prodPurlSet: new Set(["pkg:npm/dev-only-pkg@1.0.0"]),
      },
    ]);
    const byPurl = new Map(model.packages.map((p) => [p.purl, p]));

    expect(
      byPurl.get("pkg:npm/%40next/swc-win32-x64-msvc@16.0.10")?.occurrences,
    ).toEqual([{ target: NPM_TARGET, isDevDependency: true }]);
    expect(byPurl.get("pkg:npm/dev-only-pkg@1.0.0")?.occurrences).toEqual([
      { target: NPM_TARGET, isDevDependency: false },
    ]);
  });
});

describe("mergeSboms — first-party exclusion (belt-and-braces)", () => {
  test("a workspace/portal member (name in set AND version 0.0.0-use.local) never reaches the inventory", () => {
    const model = mergeSboms([
      {
        sbom: pluginFullDoc,
        targetIdentity: TARGET,
        prodPurlSet: purlSetOf(pluginProdDoc),
        firstPartyNames: new Set(["iframe-rpc-react"]),
      },
    ]);

    expect(model.packages.some((p) => p.name === "iframe-rpc-react")).toBe(
      false,
    );
    // The rest of the document is untouched by the skip.
    expect(model.packages.some((p) => p.purl === "pkg:npm/semver@7.7.1")).toBe(
      true,
    );
  });

  test("name-only or version-only matches are NOT excluded — BOTH conditions required", () => {
    // A crafted SBOM cannot hide a real package behind the local version
    // marker, and a name collision alone cannot drop a third-party package.
    const doc = {
      components: [
        {
          // Same name as a first-party member, but a REAL published version:
          // name matches, version does not → KEPT.
          name: "iframe-rpc-react",
          version: "9.9.9",
          purl: "pkg:npm/iframe-rpc-react@9.9.9",
          licenses: [{ license: { id: "MIT" } }],
        },
        {
          // Local version marker, but the name is NOT in the target's own
          // lockfile member set → KEPT.
          name: "not-a-member",
          version: "0.0.0-use.local",
          purl: "pkg:npm/not-a-member@0.0.0-use.local",
          licenses: [],
        },
      ],
    };
    const model = mergeSboms([
      {
        sbom: doc,
        targetIdentity: SYNTHETIC_TARGET,
        firstPartyNames: new Set(["iframe-rpc-react"]),
      },
    ]);
    const purls = model.packages.map((p) => p.purl);

    expect(purls).toContain("pkg:npm/iframe-rpc-react@9.9.9");
    expect(purls).toContain("pkg:npm/not-a-member@0.0.0-use.local");
  });

  test("python inputs without firstPartyNames behave identically to before", () => {
    // poetry.lock does not list the root project (verified); the
    // metadata.component root-purl skip already covers it — no exclusion
    // set is built for python targets.
    const withUndefined = mergeSboms([
      { sbom: poetryGroupsDoc, targetIdentity: "apps/jupyter" },
    ]);
    const explicit = mergeSboms([
      {
        sbom: poetryGroupsDoc,
        targetIdentity: "apps/jupyter",
        firstPartyNames: undefined,
      },
    ]);

    expect(toSortedDependenciesJson(withUndefined)).toBe(
      toSortedDependenciesJson(explicit),
    );
    expect(withUndefined.packages.length).toBe(3);
  });
});

describe("mergeSboms — npm first-party double signal", () => {
  // npm-workspace-member.json carries the verified cdxgen 12.5.1
  // workspace-member shape: the member is emitted at its real version
  // (liba@0.1.0 — never 0.0.0-use.local) with cdx:npm:isWorkspace=true. The
  // rule: skip iff the name is in the target's own lockfile-derived set and
  // (yarn local-version marker or the isWorkspace property). Either signal
  // alone keeps the package — a crafted isWorkspace property can never drop a
  // third-party package, and a name collision alone never drops one either.
  const workspaceMemberDoc = loadFixture("npm-workspace-member.json");
  const WS_TARGET = "fixture/npm-ws";

  function wsModel(
    firstPartyNames?: ReadonlySet<string>,
  ): CanonicalDependencies {
    return mergeSboms([
      { sbom: workspaceMemberDoc, targetIdentity: WS_TARGET, firstPartyNames },
    ]);
  }

  test("a member at its REAL version with isWorkspace=true AND its name in firstPartyNames is excluded", () => {
    const model = wsModel(new Set(["liba"]));
    const purls = model.packages.map((p) => p.purl);

    expect(purls).not.toContain("pkg:npm/liba@0.1.0");
    // The rest of the document is untouched by the skip.
    expect(purls).toContain("pkg:npm/ordinary-pkg@2.0.0");
  });

  test("isWorkspace=true alone (name NOT in the set) keeps the package — a generator marker never drops", () => {
    const model = wsModel(new Set(["liba"]));

    expect(model.packages.map((p) => p.purl)).toContain(
      "pkg:npm/generator-marker-pkg@1.0.0",
    );
  });

  test("a name collision WITHOUT any marker keeps the package", () => {
    // Same name as the member, real version, NO isWorkspace property and
    // NOT the yarn local-version marker → KEPT.
    const model = wsModel(new Set(["liba"]));

    expect(model.packages.map((p) => p.purl)).toContain("pkg:npm/liba@9.9.9");
  });

  test("without firstPartyNames every component including the member is kept", () => {
    const model = wsModel(undefined);

    expect(model.packages.map((p) => p.purl)).toContain("pkg:npm/liba@0.1.0");
    expect(model.packages.length).toBe(4);
  });

  test("the yarn local-version signal still excludes through the extended branch", () => {
    // Yarn first-party (name in set AND version 0.0.0-use.local) is
    // unchanged — the isWorkspace signal is an OR alongside it, never a
    // replacement (npm members carry real versions; yarn members carry the
    // local marker).
    const doc = {
      components: [
        {
          name: "yarn-member",
          version: "0.0.0-use.local",
          purl: "pkg:npm/yarn-member@0.0.0-use.local",
        },
        {
          name: "kept-pkg",
          version: "1.0.0",
          purl: "pkg:npm/kept-pkg@1.0.0",
        },
      ],
    };
    const model = mergeSboms([
      {
        sbom: doc,
        targetIdentity: SYNTHETIC_TARGET,
        firstPartyNames: new Set(["yarn-member"]),
      },
    ]);
    const purls = model.packages.map((p) => p.purl);

    expect(purls).not.toContain("pkg:npm/yarn-member@0.0.0-use.local");
    expect(purls).toContain("pkg:npm/kept-pkg@1.0.0");
  });
});

describe("mergeSboms — multi-PM shared-purl merge proof", () => {
  // A yarn target (plugin shape, dual-run prodPurlSet authority) and an npm
  // target (cdxgen shape, property markers) sharing pkg:npm/shared-lib@1.0.0
  // merge to a single row whose occurrences carry both targets with their
  // per-target dev flags — prod in yarn (purl present in the prod run), dev in
  // npm (cdx:npm:package:development=true).
  const yarnDoc = loadFixture("multi-pm-yarn.json");
  const npmDoc = loadFixture("multi-pm-npm.json");

  test("one shared purl across a yarn and an npm target yields ONE row with both targets in occurrences", () => {
    const model = mergeSboms([
      {
        sbom: yarnDoc,
        targetIdentity: "fixture/yarn-app",
        // Full run == prod run for this fixture: everything yarn sees is prod.
        prodPurlSet: purlSetOf(yarnDoc),
      },
      { sbom: npmDoc, targetIdentity: "fixture/npm-app" },
    ]);
    const byPurl = new Map(model.packages.map((p) => [p.purl, p]));
    const shared = byPurl.get("pkg:npm/shared-lib@1.0.0");

    // Exactly one PackageEntry for the shared purl (purl-keyed merge) with
    // deterministic compareCodeUnits occurrence order.
    expect(
      model.packages.filter((p) => p.purl === "pkg:npm/shared-lib@1.0.0")
        .length,
    ).toBe(1);
    expect(shared?.occurrences).toEqual([
      { target: "fixture/npm-app", isDevDependency: true },
      { target: "fixture/yarn-app", isDevDependency: false },
    ]);
    // Each input's unique packages are present exactly once, single-target.
    expect(byPurl.get("pkg:npm/yarn-only-pkg@1.1.0")?.occurrences).toEqual([
      { target: "fixture/yarn-app", isDevDependency: false },
    ]);
    expect(byPurl.get("pkg:npm/npm-only-pkg@2.2.0")?.occurrences).toEqual([
      { target: "fixture/npm-app", isDevDependency: false },
    ]);
    expect(model.packages.length).toBe(3);
  });
});

describe("mergeSboms — evidence parsing into attribution", () => {
  // plugin-evidence.json follows the 04-RESEARCH verified shape:
  // component.evidence.licenses[].license = { name: "file: <basename>",
  // text: { content: <base64>, contentType, encoding: "base64" } }.
  const evidenceDoc = loadFixture("plugin-evidence.json");
  const EV_TARGET = "libraries/evidence-target";

  function evidenceByPurl(): Map<string, PackageEntry> {
    const model = mergeSboms([
      { sbom: evidenceDoc, targetIdentity: EV_TARGET },
    ]);
    return new Map(model.packages.map((p) => [p.purl, p]));
  }

  test("Test 1: evidence-bearing components keep licenseClaims byte-identical to a claims-only parse", () => {
    // Strip every evidence key from a fresh parse of the same fixture and
    // compare the claims pipeline output — evidence must be a SEPARATE walk.
    const stripped = loadFixture("plugin-evidence.json") as {
      components: Array<Record<string, unknown>>;
    };
    for (const component of stripped.components) {
      delete component["evidence"];
    }
    const withEvidence = mergeSboms([
      { sbom: evidenceDoc, targetIdentity: EV_TARGET },
    ]);
    const claimsOnly = mergeSboms([
      { sbom: stripped, targetIdentity: EV_TARGET },
    ]);
    const claimsOf = (
      m: typeof withEvidence,
    ): { purl: string; claims: PackageEntry["licenseClaims"] }[] =>
      m.packages.map((p) => ({ purl: p.purl, claims: p.licenseClaims }));

    expect(JSON.stringify(claimsOf(withEvidence))).toBe(
      JSON.stringify(claimsOf(claimsOnly)),
    );
    // No "file: <basename>" name ever appears in any claim.
    for (const pkg of withEvidence.packages) {
      for (const claim of pkg.licenseClaims) {
        expect(claim.raw.startsWith("file:")).toBe(false);
      }
    }
  });

  test("Test 2: decode + extraction — concrete line extracted; template case honestly empty", () => {
    const byPurl = evidenceByPurl();
    const alpha = byPurl.get("pkg:npm/alpha-license-pkg@1.0.0");
    const template = byPurl.get("pkg:npm/template-pkg@3.0.0");

    expect(alpha?.attribution?.hasVerbatimText).toBe(true);
    expect(alpha?.attribution?.copyrightLines).toEqual([
      "Copyright (c) 2015 Jane Doe",
    ]);
    expect(alpha?.attribution?.author).toBe("Jane Doe");

    // The bare Apache template carries NO concrete copyright line — the
    // honest 46/601 template-only case renders empty, never fabricated.
    expect(template?.attribution?.hasVerbatimText).toBe(true);
    expect(template?.attribution?.copyrightLines).toEqual([]);

    // (d) two evidence files: copyright lines union across files.
    const dual = byPurl.get("pkg:npm/dual-file-pkg@4.0.0");
    expect(dual?.attribution?.copyrightLines).toEqual([
      "Copyright (c) 2018 Dual Author",
      "Copyright 2019 Dual Author Apache",
    ]);

    // (e) author but no evidence → attribution key entirely absent.
    const authorOnly = byPurl.get("pkg:npm/author-only-pkg@5.0.0");
    expect(authorOnly?.attribution).toBeUndefined();
  });

  test("Test 3: NOTICE detection by stem match on the stripped basename", () => {
    const notice = evidenceByPurl().get("pkg:npm/notice-pkg@2.0.0");

    expect(notice?.attribution?.noticeTexts).toEqual([
      "Notice Product\nCopyright 2014-2024 Notice Foundation\n\nThis product includes software developed at\nThe Notice Foundation (http://example.org/).\n",
    ]);
    // NOTICE alone is not a verbatim LICENSE text.
    expect(notice?.attribution?.hasVerbatimText).toBe(false);
  });

  test("Test 3b (CR-02): NOTICE.txt with a parseable MIT claim still surfaces the NOTICE body", () => {
    // Pre-fix, the exact-match /^notice$/i classifier sent NOTICE.txt into
    // the license-text branch, where the parseable claim gated it out of
    // verbatimTexts — the NOTICE body was dropped from the legal document
    // entirely (the Apache-2.0 §4(d) silent-omission failure mode).
    const noticeTxt = evidenceByPurl().get("pkg:npm/notice-txt-pkg@9.0.0");

    expect(noticeTxt?.licenseClaims).toEqual([
      { raw: "MIT", kind: "spdx-id", source: "generator" },
    ]);
    expect(noticeTxt?.attribution?.noticeTexts).toEqual([
      "Notice Txt Product\nCopyright 2020-2025 Notice Txt Foundation\n\nThis product includes software developed at\nThe Notice Txt Foundation (http://example.org/).\n",
    ]);
    // A NOTICE variant is never a verbatim LICENSE text...
    expect(noticeTxt?.attribution?.hasVerbatimText).toBe(false);
    expect(noticeTxt?.attribution?.verbatimTexts).toBeUndefined();
    // ...but its copyright line is still extracted.
    expect(noticeTxt?.attribution?.copyrightLines).toEqual([
      "Copyright 2020-2025 Notice Txt Foundation",
    ]);
  });

  test("Test 4a: an oversize entry is skipped entirely — nothing stored from it", () => {
    const byPurl = evidenceByPurl();
    const oversize = byPurl.get("pkg:npm/oversize-pkg@7.0.0");

    // Its ONLY evidence entry exceeds the 1 MB decoded cap → no attribution.
    expect(oversize?.attribution).toBeUndefined();
    // The crafted blob's head line must not leak anywhere into the model.
    const dump = toSortedDependenciesJson(
      mergeSboms([{ sbom: evidenceDoc, targetIdentity: EV_TARGET }]),
    );
    expect(dump.includes("Oversize Hacker")).toBe(false);
  });

  test("Test 4b: C0 control chars (minus \\n/\\t), DEL, and C1 are replaced with spaces at intake", () => {
    const ctrl = evidenceByPurl().get("pkg:npm/control-char-pkg@8.0.0");

    // ESC, NUL, DEL, NEL (U+0085), BEL all become spaces; \n and \t survive.
    expect(ctrl?.attribution?.verbatimTexts).toEqual([
      "Evil [2K Text  here  end\nCopyright (c) 2021 Ctrl  Author\tTabbed\nPlain last line\n",
    ]);
    expect(ctrl?.attribution?.copyrightLines).toEqual([
      "Copyright (c) 2021 Ctrl  Author\tTabbed",
    ]);
    // Defense in depth: nothing stored for this package carries any control
    // character other than \n and \t (raw strings, not JSON-escaped).
    const stored = [
      ...(ctrl?.attribution?.copyrightLines ?? []),
      ...(ctrl?.attribution?.noticeTexts ?? []),
      ...(ctrl?.attribution?.verbatimTexts ?? []),
    ].join("");
    // eslint-disable-next-line no-control-regex -- deliberate control-character class: sanitizer boundary assert
    expect(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(stored)).toBe(
      false,
    );
  });

  test("Test 4c: at most 8 evidence entries are folded per package", () => {
    const entries = [];
    for (let i = 1; i <= 10; i++) {
      entries.push({
        license: {
          name: `file: LICENSE-${i}`,
          text: {
            content: Buffer.from(
              `Copyright (c) ${2000 + i} Holder ${i}\n`,
              "utf8",
            ).toString("base64"),
            contentType: "text/plain",
            encoding: "base64",
          },
        },
      });
    }
    const doc = {
      components: [
        {
          name: "many-files-pkg",
          version: "1.0.0",
          purl: "pkg:npm/many-files-pkg@1.0.0",
          licenses: [{ license: { id: "MIT" } }],
          evidence: { licenses: entries },
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: EV_TARGET }]);
    const lines = model.packages[0]?.attribution?.copyrightLines ?? [];

    expect(lines).toContain("Copyright (c) 2001 Holder 1");
    expect(lines).toContain("Copyright (c) 2008 Holder 8");
    expect(lines).not.toContain("Copyright (c) 2009 Holder 9");
    expect(lines).not.toContain("Copyright (c) 2010 Holder 10");
  });

  test("Test 4d: CRLF evidence intake yields LF-only text with no trailing spaces", () => {
    // Pre-fix, \r (0x0D) sat inside the control-character class and became
    // a SPACE: every CRLF-origin "verbatim" text gained a trailing space on
    // every line — a quiet mutation of text the document presents as
    // verbatim. The contract is byte-faithful MODULO line endings (LF).
    const crlfBody =
      "CRLF License\r\nCopyright (c) 2022 Crlf Author\r\nlast\rline\r\n";
    const doc = {
      components: [
        {
          name: "crlf-pkg",
          version: "1.0.0",
          purl: "pkg:npm/crlf-pkg@1.0.0",
          // name-kind claim only → the verbatim text is retained (Pitfall 4
          // path), so the stored bytes are directly observable.
          licenses: [{ license: { name: "custom crlf license" } }],
          evidence: {
            licenses: [
              {
                license: {
                  name: "file: LICENSE",
                  text: {
                    content: Buffer.from(crlfBody, "utf8").toString("base64"),
                    contentType: "text/plain",
                    encoding: "base64",
                  },
                },
              },
            ],
          },
        },
      ],
    };
    const model = mergeSboms([{ sbom: doc, targetIdentity: EV_TARGET }]);
    const attribution = model.packages[0]?.attribution;

    // CRLF and bare CR both normalize to LF — no \r, no trailing spaces.
    expect(attribution?.verbatimTexts).toEqual([
      "CRLF License\nCopyright (c) 2022 Crlf Author\nlast\nline\n",
    ]);
    expect(attribution?.copyrightLines).toEqual([
      "Copyright (c) 2022 Crlf Author",
    ]);
  });

  test("Test 5 (Pitfall 4): verbatim texts retained ONLY for packages with no spdx-id/expression claim", () => {
    const byPurl = evidenceByPurl();
    const named = byPurl.get("pkg:npm/named-claim-pkg@6.0.0");
    const alpha = byPurl.get("pkg:npm/alpha-license-pkg@1.0.0");

    // (f) only a "name"-kind claim → full text retained.
    expect(named?.attribution?.verbatimTexts?.length).toBe(1);
    expect(
      named?.attribution?.verbatimTexts?.[0]?.includes("public domain"),
    ).toBe(true);
    expect(named?.attribution?.copyrightLines).toEqual([
      "Copyright (c) 2017 Named Claim Author",
    ]);
    // (a) has an spdx-id claim → raw text never enters the model.
    expect(alpha?.attribution?.verbatimTexts).toBeUndefined();
  });

  test("Test 6: the same purl from two CollectedSboms carries attribution once, first-seen", () => {
    const model = mergeSboms([
      { sbom: evidenceDoc, targetIdentity: "apps/a" },
      { sbom: loadFixture("plugin-evidence.json"), targetIdentity: "apps/b" },
    ]);
    const byPurl = new Map(model.packages.map((p) => [p.purl, p]));
    const alpha = byPurl.get("pkg:npm/alpha-license-pkg@1.0.0");
    const notice = byPurl.get("pkg:npm/notice-pkg@2.0.0");

    // Two targets, ONE attribution — no duplicated lines or NOTICE texts.
    expect(alpha?.occurrences.map((o) => o.target)).toEqual([
      "apps/a",
      "apps/b",
    ]);
    expect(alpha?.attribution?.copyrightLines).toEqual([
      "Copyright (c) 2015 Jane Doe",
    ]);
    expect(notice?.attribution?.noticeTexts?.length).toBe(1);
  });

  test("Test 7: evidence-less fixtures keep the committed dump-model golden byte-identical", () => {
    // attribution is ABSENT, not empty, when no evidence exists — the model
    // change is invisible to every existing golden.
    const golden = readFileSync(
      join(import.meta.dir, "golden", "license-shapes.model.json"),
      "utf-8",
    );

    expect(
      toSortedDependenciesJson(
        mergeSboms([{ sbom: shapesDoc, targetIdentity: SYNTHETIC_TARGET }]),
      ),
    ).toBe(golden);
  });
});

describe("purlSetOf — tolerant purl extraction", () => {
  test("collects every string purl from components[]", () => {
    expect(purlSetOf(pluginProdDoc)).toEqual(
      new Set([
        "pkg:npm/semver@7.7.1",
        "pkg:npm/argparse@2.0.1",
        "pkg:npm/iframe-rpc-react@0.0.0-use.local",
      ]),
    );
  });

  test("malformed documents and entries yield an empty or partial set, never a throw", () => {
    expect(purlSetOf(undefined)).toEqual(new Set());
    expect(purlSetOf("not an object")).toEqual(new Set());
    expect(purlSetOf({ components: "nope" })).toEqual(new Set());
    expect(
      purlSetOf({
        components: [
          null,
          42,
          { name: "no-purl" },
          { purl: 7 },
          { purl: "pkg:npm/ok@1.0.0" },
        ],
      }),
    ).toEqual(new Set(["pkg:npm/ok@1.0.0"]));
  });
});

describe("mergeSboms — dependency provenance threading (07-13)", () => {
  const PROV_DOC = {
    components: [
      { name: "a", version: "1.0.0", purl: "pkg:npm/a@1.0.0" },
      { name: "b", version: "2.0.0", purl: "pkg:npm/b@2.0.0" },
    ],
  };

  test("introduction from the per-target map rides onto the matching occurrence", () => {
    const introductions = new Map([
      ["pkg:npm/a@1.0.0", { direct: true, introducedBy: [] }],
      [
        "pkg:npm/b@2.0.0",
        {
          direct: false,
          introducedBy: ["pkg:npm/a@1.0.0"],
          path: ["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"],
        },
      ],
    ]);
    const model = mergeSboms([
      { sbom: PROV_DOC, targetIdentity: "apps/x", introductions },
    ]);
    const a = model.packages.find((p) => p.purl === "pkg:npm/a@1.0.0");
    const b = model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0");
    expect(a?.occurrences[0]?.introduction).toEqual({
      direct: true,
      introducedBy: [],
    });
    expect(b?.occurrences[0]?.introduction).toEqual({
      direct: false,
      introducedBy: ["pkg:npm/a@1.0.0"],
      path: ["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"],
    });
  });

  test("a purl absent from the introductions map gets no introduction (honest residual)", () => {
    const model = mergeSboms([
      {
        sbom: PROV_DOC,
        targetIdentity: "apps/x",
        introductions: new Map([
          ["pkg:npm/a@1.0.0", { direct: true, introducedBy: [] }],
        ]),
      },
    ]);
    const b = model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0");
    expect(b?.occurrences[0]?.introduction).toBeUndefined();
  });

  test("no introductions map at all → no occurrence carries introduction (byte-identical residual)", () => {
    const model = mergeSboms([{ sbom: PROV_DOC, targetIdentity: "apps/x" }]);
    for (const pkg of model.packages) {
      for (const occurrence of pkg.occurrences) {
        expect(occurrence.introduction).toBeUndefined();
      }
    }
  });

  test("introduction is PER-TARGET — direct in one workspace, transitive in another, preserved through merge", () => {
    const model = mergeSboms([
      {
        sbom: PROV_DOC,
        targetIdentity: "apps/x",
        introductions: new Map([
          ["pkg:npm/b@2.0.0", { direct: true, introducedBy: [] }],
        ]),
      },
      {
        sbom: PROV_DOC,
        targetIdentity: "apps/y",
        introductions: new Map([
          [
            "pkg:npm/b@2.0.0",
            { direct: false, introducedBy: ["pkg:npm/a@1.0.0"] },
          ],
        ]),
      },
    ]);
    const b = model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0");
    // Two occurrences, sorted by target; each keeps its own introduction
    // unchanged through the merge (no cross-target reconciliation).
    expect(b?.occurrences).toEqual([
      {
        target: "apps/x",
        isDevDependency: false,
        introduction: { direct: true, introducedBy: [] },
      },
      {
        target: "apps/y",
        isDevDependency: false,
        introduction: { direct: false, introducedBy: ["pkg:npm/a@1.0.0"] },
      },
    ]);
  });

  test("same-target fold reconciles introduction deterministically, order-independent (#7)", () => {
    // The SAME target identity contributes the SAME purl twice with DIFFERENT
    // introductions. The fold must reconcile (union introducedBy, OR direct,
    // pick the lexicographically-smallest path) rather than first-wins. 07-19:
    // optionality is descoped — there is no `optional` field to reconcile.
    const introA = new Map([
      [
        "pkg:npm/b@2.0.0",
        {
          direct: false,
          introducedBy: ["pkg:npm/p2@1.0.0"],
          path: ["pkg:npm/p2@1.0.0", "pkg:npm/b@2.0.0"],
        },
      ],
    ]);
    const introB = new Map([
      [
        "pkg:npm/b@2.0.0",
        {
          direct: false,
          introducedBy: ["pkg:npm/p1@1.0.0"],
          path: ["pkg:npm/p1@1.0.0", "pkg:npm/b@2.0.0"],
        },
      ],
    ]);
    const reconcile = (
      first: ReadonlyMap<string, DependencyIntroduction>,
      second: ReadonlyMap<string, DependencyIntroduction>,
    ): unknown => {
      const model = mergeSboms([
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: first },
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: second },
      ]);
      const b = model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0");
      return b?.occurrences[0]?.introduction;
    };
    const expected = {
      direct: false,
      // union of introducedBy, sorted
      introducedBy: ["pkg:npm/p1@1.0.0", "pkg:npm/p2@1.0.0"],
      // smallest path by compareCodeUnits: p1 < p2
      path: ["pkg:npm/p1@1.0.0", "pkg:npm/b@2.0.0"],
    };
    expect(reconcile(introA, introB)).toEqual(expected);
    // BOTH input orders → identical reconciled result.
    expect(reconcile(introB, introA)).toEqual(expected);
  });

  test("same-target fold ORs direct — a direct contributor wins (#7)", () => {
    const introTransitive = new Map([
      ["pkg:npm/b@2.0.0", { direct: false, introducedBy: ["pkg:npm/p@1.0.0"] }],
    ]);
    const introDirect = new Map([
      ["pkg:npm/b@2.0.0", { direct: true, introducedBy: [] }],
    ]);
    const fold = (
      first: ReadonlyMap<string, DependencyIntroduction>,
      second: ReadonlyMap<string, DependencyIntroduction>,
    ): unknown => {
      const model = mergeSboms([
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: first },
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: second },
      ]);
      return model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0")
        ?.occurrences[0]?.introduction;
    };
    const direct = fold(introTransitive, introDirect) as { direct: boolean };
    expect(direct.direct).toBe(true);
    expect(
      (fold(introDirect, introTransitive) as { direct: boolean }).direct,
    ).toBe(true);
  });

  test("reconciling a DIRECT with a TRANSITIVE clears introducedBy + drops path (direct-consistency, Fix 2, 07-21)", () => {
    // INFO (07-21): the same-target fold ORs `direct` but UNIONS introducedBy and
    // keeps a path. Reconciling a direct intro with a transitive one yielded the
    // contradictory {direct:true, introducedBy:[mid], path:[mid,leaf]}; whyCellOf
    // then rendered bare "direct" and HID the (now meaningless) introducer — a
    // direct dependency has no introducer chain. FIX: when the reconciled result
    // is direct, clear introducedBy to [] and drop path.
    const introDirect = new Map([
      ["pkg:npm/b@2.0.0", { direct: true, introducedBy: [] }],
    ]);
    const introTransitive = new Map([
      [
        "pkg:npm/b@2.0.0",
        {
          direct: false,
          introducedBy: ["pkg:npm/mid@2"],
          path: ["pkg:npm/mid@2", "pkg:npm/b@2.0.0"],
        },
      ],
    ]);
    const fold = (
      first: ReadonlyMap<string, DependencyIntroduction>,
      second: ReadonlyMap<string, DependencyIntroduction>,
    ): unknown => {
      const model = mergeSboms([
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: first },
        { sbom: PROV_DOC, targetIdentity: "apps/x", introductions: second },
      ]);
      return model.packages.find((p) => p.purl === "pkg:npm/b@2.0.0")
        ?.occurrences[0]?.introduction;
    };
    const expected = { direct: true, introducedBy: [] };
    // No `path` key, no introducer — a direct dep has no parent chain.
    expect(fold(introDirect, introTransitive)).toEqual(expected);
    // Order-independent.
    expect(fold(introTransitive, introDirect)).toEqual(expected);
  });
});
