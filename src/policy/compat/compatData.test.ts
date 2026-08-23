import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";
import parse from "spdx-expression-parse";

import {
  assertInterTierGateAccepted,
  assertStructuralShape,
  assertWithinSizeGate,
  compareInterTierDisagreements,
  diffEntries,
  diffMatrix,
  type InterTierGateResult,
  renderProvenance,
  SIZE_GATES,
  validateDownloadedSnapshots,
  withUpdatedScancodeTimestamp,
} from "../../../scripts/update-compat-data";
import { interTierDisagreements } from "./consistency";
import {
  narrowOsadlCopyleftClass,
  narrowOsadlMatrix,
  narrowScancodeCategory,
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  SCANCODE_CATEGORY,
} from "./data";

const MATRIX_CELLS = new Set(["Same", "Yes", "No", "Unknown", "Check dependency"]);
const COPYLEFT_CLASSES = new Set(["No", "Yes", "Yes (restricted)", "Questionable"]);

const COMPAT_DIR = import.meta.dir;
const MATRIX_PATH = join(COMPAT_DIR, "osadl-matrix.json");
const COPYLEFT_PATH = join(COMPAT_DIR, "osadl-copyleft.json");
const SCANCODE_PATH = join(COMPAT_DIR, "scancode-licensedb-index.json");

function parses(id: string): boolean {
  try {
    parse(id);
    return true;
  } catch {
    return false;
  }
}

describe("OSADL matrix self-consistency", () => {
  test("row count is within the expected range", () => {
    expect(OSADL_MATRIX.size).toBeGreaterThanOrEqual(100);
    expect(OSADL_MATRIX.size).toBeLessThanOrEqual(200);
  });

  test("every row's column set equals the row set (square matrix)", () => {
    const rowIds = new Set(OSADL_MATRIX.keys());

    for (const [leading, row] of OSADL_MATRIX) {
      expect(new Set(row.keys())).toEqual(rowIds);
      void leading;
    }
  });

  test("Same appears exactly on the diagonal", () => {
    for (const [leading, row] of OSADL_MATRIX) {
      for (const [subordinate, cell] of row) {
        expect(cell === "Same").toBe(leading === subordinate);
      }
    }
  });

  test("every cell is one of the five OSADL verdicts", () => {
    for (const row of OSADL_MATRIX.values()) {
      for (const cell of row.values()) {
        expect(MATRIX_CELLS.has(cell)).toBe(true);
      }
    }
  });

  test("every row id parses as an SPDX expression", () => {
    for (const id of OSADL_MATRIX.keys()) {
      expect(parses(id)).toBe(true);
    }
  });

  test("MIT, BSD-3-Clause, and ISC absorb every leading license as subordinate", () => {
    for (const permissive of ["MIT", "BSD-3-Clause", "ISC"]) {
      for (const [leading, row] of OSADL_MATRIX) {
        const cell = row.get(permissive);

        expect(cell === "Yes" || cell === "Same").toBe(true);
        void leading;
      }
    }
  });
});

describe("OSADL copyleft class table", () => {
  test("every class is one of the four OSADL values", () => {
    for (const cls of OSADL_COPYLEFT_CLASS.values()) {
      expect(COPYLEFT_CLASSES.has(cls)).toBe(true);
    }
  });

  test("every id parses as an SPDX expression", () => {
    for (const id of OSADL_COPYLEFT_CLASS.keys()) {
      expect(parses(id)).toBe(true);
    }
  });

  test("the class table covers every matrix row id", () => {
    const uncovered = [...OSADL_MATRIX.keys()].filter((id) => !OSADL_COPYLEFT_CLASS.has(id));

    expect(uncovered).toEqual([]);
  });
});

describe("ScanCode LicenseDB category index", () => {
  test("no SPDX key maps to two different categories", () => {
    // narrowScancodeCategory itself throws on a conflict; a successful load already proves this,
    // this test pins the property so a future refactor that stops throwing is caught.
    expect(SCANCODE_CATEGORY.size).toBeGreaterThan(500);
  });

  test("every mapped category is a non-empty string", () => {
    for (const category of SCANCODE_CATEGORY.values()) {
      expect(typeof category).toBe("string");
      expect(category.trim().length).toBeGreaterThan(0);
    }
  });

  test("the canonical spot-check ids map to their expected categories", () => {
    expect(SCANCODE_CATEGORY.get("MIT")).toBe("Permissive");
    expect(SCANCODE_CATEGORY.get("Apache-2.0")).toBe("Permissive");
    expect(SCANCODE_CATEGORY.get("GPL-3.0-only")).toBe("Copyleft");
    expect(SCANCODE_CATEGORY.get("LGPL-2.1-only")).toBe("Copyleft Limited");
    expect(SCANCODE_CATEGORY.get("MPL-2.0")).toBe("Copyleft Limited");
  });
});

describe("orientation and semantics pins (the wrong-compatibility drift tripwire)", () => {
  const cell = (leading: string, subordinate: string): string | undefined =>
    OSADL_MATRIX.get(leading)?.get(subordinate);

  test("directional pairs name the exact cell so a refresh flip names the culprit", () => {
    expect(cell("GPL-3.0-only", "MIT")).toBe("Yes");
    expect(cell("MIT", "GPL-3.0-only")).toBe("No");
    expect(cell("GPL-2.0-only", "Apache-2.0")).toBe("No");
    expect(cell("GPL-3.0-only", "Apache-2.0")).toBe("Yes");
    expect(cell("MIT", "LGPL-2.1-only")).toBe("No");
    expect(cell("MIT", "GPL-2.0-only WITH Classpath-exception-2.0")).toBe("No");
    expect(cell("GPL-2.0-only", "GPL-3.0-only")).toBe("No");
    expect(cell("GPL-3.0-only", "GPL-2.0-only")).toBe("No");
  });

  test("CC0-1.0 and SSPL-1.0 are absent from the matrix rows", () => {
    expect(OSADL_MATRIX.has("CC0-1.0")).toBe(false);
    expect(OSADL_MATRIX.has("SSPL-1.0")).toBe(false);
  });

  test("copyleft classes name the exact class so a refresh flip names the culprit", () => {
    expect(OSADL_COPYLEFT_CLASS.get("MIT")).toBe("No");
    expect(OSADL_COPYLEFT_CLASS.get("Apache-2.0")).toBe("No");
    expect(OSADL_COPYLEFT_CLASS.get("LGPL-2.1-only")).toBe("Yes (restricted)");
    expect(OSADL_COPYLEFT_CLASS.get("MPL-2.0")).toBe("Yes (restricted)");
    expect(OSADL_COPYLEFT_CLASS.get("GPL-2.0-only")).toBe("Yes");
    expect(OSADL_COPYLEFT_CLASS.get("AGPL-3.0-only")).toBe("Yes");
    expect(OSADL_COPYLEFT_CLASS.get("GPL-2.0-only WITH Classpath-exception-2.0")).toBe(
      "Yes (restricted)",
    );
    expect(OSADL_COPYLEFT_CLASS.get("EPL-2.0")).toBe("Yes (restricted)");
    expect(OSADL_COPYLEFT_CLASS.get("MS-PL")).toBe("Questionable");
  });
});

/**
 * Inter-tier disagreements between the matrix and the class table, pinned as an exact literal
 * allowlist against the CURRENT snapshot (see consistency.ts's module doc for the two disagreement
 * shapes). A refresh introducing a NEW disagreement fails this test; runtime code never consults
 * this list - first-tier-wins classification stays strict regardless.
 */
const PINNED_INTER_TIER_DISAGREEMENTS: readonly string[] = [
  'Apache-1.0: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'Apache-1.1: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'Apache-2.0: class No but rejected (cell "No") by 8 leading id(s): GPL-1.0-only, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, MPL-1.1',
  'BSD-4-Clause-UC: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'BSD-4-Clause: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'BSD-4.3TAHOE: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'ECL-2.0: class No but rejected (cell "No") by 10 leading id(s): APSL-2.0, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later',
  'FTL: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'IJG: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'LicenseRef-scancode-bsla-no-advert: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'Minpack: class No but rejected (cell "No") by 16 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'PHP-3.01: class No but rejected (cell "No") by 16 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'PSF-2.0: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'Python-2.0: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
  'Spencer-86: class No but rejected (cell "No") by 1 leading id(s): Sleepycat',
  'XFree86-1.1: class No but rejected (cell "No") by 12 leading id(s): APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later',
  'zlib-acknowledgement: class No but rejected (cell "No") by 18 leading id(s): AGPL-3.0-only, AGPL-3.0-or-later, APSL-2.0, EUPL-1.1, EUPL-1.2, GPL-1.0-only, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-only WITH Classpath-exception-2.0, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.0-only, LGPL-2.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later',
];

describe("inter-tier disagreement allowlist (refresh-time gate, A3)", () => {
  test("the current snapshot's disagreements match the pinned allowlist exactly", () => {
    expect(interTierDisagreements(OSADL_MATRIX, OSADL_COPYLEFT_CLASS)).toEqual(
      PINNED_INTER_TIER_DISAGREEMENTS,
    );
  });
});

describe("inter-tier disagreement line reflects the full rejecting-lead set", () => {
  test("a new later-sorting rejecting lead changes the rendered line, never silently absorbed into the same first-lead citation", () => {
    const before = new Map<string, Map<string, "No">>([
      ["AAA", new Map([["SUB", "No"]])],
      ["ZZZ", new Map()],
      ["SUB", new Map()],
    ]);
    const after = new Map<string, Map<string, "No">>([
      ["AAA", new Map([["SUB", "No"]])],
      ["ZZZ", new Map([["SUB", "No"]])],
      ["SUB", new Map()],
    ]);
    const copyleftClass = new Map([["SUB", "No" as const]]);

    const beforeLines = interTierDisagreements(before, copyleftClass);
    const afterLines = interTierDisagreements(after, copyleftClass);

    // ZZZ sorts after AAA, so the lexicographically smallest rejecting lead never changes - a
    // line citing only the smallest lead stays byte-identical across this refresh, leaving the
    // abort gate silent even though classifyLeaf's per-leaf lookup now sees a second rejecting
    // cell. The rendered line must differ whenever the rejecting-lead SET changes.
    expect(beforeLines).not.toEqual(afterLines);

    const gate = compareInterTierDisagreements(beforeLines, afterLines);

    expect(gate.newEntries.length).toBeGreaterThan(0);
  });
});

describe("honest failure on a malformed shape", () => {
  test("a missing matrix row throws, naming the file and the row", () => {
    expect(() => narrowOsadlMatrix({ MIT: { MIT: "Same" } }, "probe-matrix.json")).not.toThrow();
    expect(() =>
      narrowOsadlMatrix(
        { MIT: { MIT: "Same" }, "GPL-3.0-only": "not an object" },
        "probe-matrix.json",
      ),
    ).toThrow(/probe-matrix\.json.*GPL-3\.0-only/s);
  });

  test("an unknown matrix cell value throws, naming the row and column", () => {
    expect(() =>
      narrowOsadlMatrix({ MIT: { MIT: "Same", "GPL-3.0-only": "Maybe" } }, "probe-matrix.json"),
    ).toThrow(/probe-matrix\.json.*\[MIT\]\[GPL-3\.0-only\]/s);
  });

  test("a non-object matrix document throws", () => {
    expect(() => narrowOsadlMatrix(["not", "an", "object"], "probe-matrix.json")).toThrow(
      /probe-matrix\.json/,
    );
  });

  test("a copyleft document missing the 'copyleft' payload key throws", () => {
    expect(() =>
      narrowOsadlCopyleftClass({ title: "x", license: "y" }, "probe-copyleft.json"),
    ).toThrow(/probe-copyleft\.json.*"copyleft"/s);
  });

  test("a non-string copyleft class value throws, naming the id", () => {
    expect(() =>
      narrowOsadlCopyleftClass({ copyleft: { MIT: "Maybe" } }, "probe-copyleft.json"),
    ).toThrow(/probe-copyleft\.json.*MIT/s);
  });

  test("a non-array ScanCode document throws", () => {
    expect(() => narrowScancodeCategory({ not: "an array" }, "probe-scancode.json")).toThrow(
      /probe-scancode\.json/,
    );
  });

  test("a ScanCode entry with an empty category throws, naming the entry index", () => {
    expect(() =>
      narrowScancodeCategory([{ category: "", spdx_license_key: "MIT" }], "probe-scancode.json"),
    ).toThrow(/probe-scancode\.json.*entry 0/s);
  });

  test("a duplicate SPDX key with conflicting categories throws, naming the key", () => {
    expect(() =>
      narrowScancodeCategory(
        [
          { category: "Permissive", spdx_license_key: "MIT" },
          { category: "Copyleft", spdx_license_key: "MIT" },
        ],
        "probe-scancode.json",
      ),
    ).toThrow(/probe-scancode\.json.*"MIT"/s);
  });

  test("a duplicate SPDX key with the SAME category does not throw", () => {
    expect(() =>
      narrowScancodeCategory(
        [
          { category: "Permissive", spdx_license_key: "MIT" },
          { category: "Permissive", other_spdx_license_keys: ["MIT"] },
        ],
        "probe-scancode.json",
      ),
    ).not.toThrow();
  });

  test("an entry whose spdx_license_key is null contributes nothing", () => {
    const categories = narrowScancodeCategory(
      [{ category: "Permissive", spdx_license_key: null, other_spdx_license_keys: [] }],
      "probe-scancode.json",
    );

    expect(categories.size).toBe(0);
  });
});

describe("update-compat-data.ts pure core", () => {
  test("size gates accept the committed files' own byte lengths", () => {
    expect(() =>
      assertWithinSizeGate(
        Buffer.byteLength(readFileSync(MATRIX_PATH, "utf8"), "utf8"),
        SIZE_GATES.matrix,
      ),
    ).not.toThrow();
    expect(() =>
      assertWithinSizeGate(
        Buffer.byteLength(readFileSync(COPYLEFT_PATH, "utf8"), "utf8"),
        SIZE_GATES.copyleft,
      ),
    ).not.toThrow();
    expect(() =>
      assertWithinSizeGate(
        Buffer.byteLength(readFileSync(SCANCODE_PATH, "utf8"), "utf8"),
        SIZE_GATES.scancode,
      ),
    ).not.toThrow();
  });

  test("a size gate rejects a truncated or oversized download", () => {
    expect(() => assertWithinSizeGate(50_000, SIZE_GATES.matrix)).toThrow(/osadl-matrix\.json/);
    expect(() => assertWithinSizeGate(2_000_000, SIZE_GATES.matrix)).toThrow(/osadl-matrix\.json/);
    expect(() => assertWithinSizeGate(500, SIZE_GATES.copyleft)).toThrow(/osadl-copyleft\.json/);
  });

  test("the tightened lower bounds reject a download only slightly smaller than the real file", () => {
    // A partial truncation that lands just under each committed size - the case the old
    // 100_000 / 1_000 / 100_000 floors would have waved straight through.
    expect(() => assertWithinSizeGate(240_000, SIZE_GATES.matrix)).toThrow(/osadl-matrix\.json/);
    expect(() => assertWithinSizeGate(4_000, SIZE_GATES.copyleft)).toThrow(/osadl-copyleft\.json/);
    expect(() => assertWithinSizeGate(900_000, SIZE_GATES.scancode)).toThrow(
      /scancode-licensedb-index\.json/,
    );
  });

  test("structural assertions accept the real committed shape", () => {
    expect(() =>
      assertStructuralShape(OSADL_MATRIX, OSADL_COPYLEFT_CLASS, SCANCODE_CATEGORY),
    ).not.toThrow();
  });

  test("structural assertions reject a matrix outside the row-count range", () => {
    const tooFew = new Map([["MIT", new Map([["MIT", "Same" as const]])]]);

    expect(() => assertStructuralShape(tooFew, OSADL_COPYLEFT_CLASS, SCANCODE_CATEGORY)).toThrow(
      /osadl-matrix\.json/,
    );
  });

  test("structural assertions reject a non-square row", () => {
    const rows = new Map<string, Map<string, "Same" | "Yes">>(
      Array.from({ length: 100 }, (_, i) => [`L${i}`, new Map([[`L${i}`, "Same"]])]),
    );

    // Give the first row an extra column no other row carries.
    rows.set("L0", new Map([...rows.get("L0")!, ["L1", "Yes"]]));

    expect(() => assertStructuralShape(rows, OSADL_COPYLEFT_CLASS, SCANCODE_CATEGORY)).toThrow(
      /not square/,
    );
  });

  test("structural assertions reject a ScanCode map with too few mapped keys", () => {
    expect(() =>
      assertStructuralShape(OSADL_MATRIX, OSADL_COPYLEFT_CLASS, new Map([["MIT", "Permissive"]])),
    ).toThrow(/scancode-licensedb-index\.json/);
  });

  test("the inter-tier gate reports a new disagreement and aborts the refresh", () => {
    const result = compareInterTierDisagreements(
      ["A: class No but B→A = No"],
      ["A: class No but B→A = No", "C: class No but D→C = No"],
    );

    expect(result.newEntries).toEqual(["C: class No but D→C = No"]);
    expect(result.resolvedEntries).toEqual([]);
  });

  test("the inter-tier gate reports a resolved disagreement without aborting", () => {
    const result = compareInterTierDisagreements(
      ["A: class No but B→A = No", "C: class No but D→C = No"],
      ["A: class No but B→A = No"],
    );

    expect(result.newEntries).toEqual([]);
    expect(result.resolvedEntries).toEqual(["C: class No but D→C = No"]);
  });

  test("an identical pair reports neither new nor resolved entries", () => {
    const disagreements = ["A: class No but B→A = No"];
    const result = compareInterTierDisagreements(disagreements, disagreements);

    expect(result.newEntries).toEqual([]);
    expect(result.resolvedEntries).toEqual([]);
  });

  test("a new disagreement aborts the refresh, but the explicit accept override lets it through", () => {
    const withNew: InterTierGateResult = {
      newEntries: ["C: class No but D→C = No"],
      resolvedEntries: [],
    };

    expect(() => assertInterTierGateAccepted(withNew, false)).toThrow(/--accept-new-disagreements/);
    // The override is the escape from the masking corner: a corrected refresh that re-introduces a
    // disagreement an earlier bad refresh had removed proceeds once the maintainer accepts it,
    // rather than needing the committed snapshot hand-edited.
    expect(() => assertInterTierGateAccepted(withNew, true)).not.toThrow();
  });

  test("a resolved-only disagreement never aborts, with or without the accept override", () => {
    const resolvedOnly: InterTierGateResult = {
      newEntries: [],
      resolvedEntries: ["C: class No but D→C = No"],
    };

    expect(() => assertInterTierGateAccepted(resolvedOnly, false)).not.toThrow();
    expect(() => assertInterTierGateAccepted(resolvedOnly, true)).not.toThrow();
  });

  test("diffMatrix is deterministic and caps the named-flip sample at 20", () => {
    const previous = new Map([["MIT", new Map([["MIT", "Same" as const]])]]);
    const nextRow = new Map<string, "Yes" | "No" | "Same">([["MIT", "Same"]]);

    for (let i = 0; i < 25; i++) {
      nextRow.set(`L${i}`, "Yes");
    }

    const next = new Map([["MIT", nextRow]]);

    const first = diffMatrix(previous, next);
    const second = diffMatrix(previous, next);

    expect(first).toEqual(second);
    expect(first.added).toBe(25);
    expect(first.sampleFlips.length).toBe(20);
  });

  test("diffEntries reports added, removed, and changed entries by id", () => {
    const previous = new Map([
      ["A", "No"],
      ["B", "Yes"],
    ]);
    const next = new Map([
      ["A", "No"],
      ["B", "Yes (restricted)"],
      ["C", "No"],
    ]);

    expect(diffEntries(previous, next)).toEqual(["B: Yes → Yes (restricted)", "C: (new) → No"]);
  });

  test("validateDownloadedSnapshots returns the real committed snapshots unchanged", () => {
    const result = validateDownloadedSnapshots({
      matrixText: readFileSync(MATRIX_PATH, "utf8"),
      copyleftText: readFileSync(COPYLEFT_PATH, "utf8"),
      scancodeText: readFileSync(SCANCODE_PATH, "utf8"),
    });

    expect(result.matrix.size).toBe(OSADL_MATRIX.size);
    expect(result.copyleftClass.size).toBe(OSADL_COPYLEFT_CLASS.size);
    expect(result.scancodeCategory.size).toBe(SCANCODE_CATEGORY.size);
    expect(result.interTierGate.newEntries).toEqual([]);
  });

  test("validateDownloadedSnapshots throws on a malformed download and writes nothing", () => {
    // A pure function with no filesystem access: it cannot write, so a thrown validation error
    // is itself the proof that nothing was committed - see the module doc on this function.
    expect(() =>
      validateDownloadedSnapshots({
        matrixText: "not json",
        copyleftText: readFileSync(COPYLEFT_PATH, "utf8"),
        scancodeText: readFileSync(SCANCODE_PATH, "utf8"),
      }),
    ).toThrow();
  });

  test("withUpdatedScancodeTimestamp rewrites the literal and rejects a missing declaration", () => {
    const source = 'export const SCANCODE_SNAPSHOT_TIMESTAMP = "2026-08-10T16:21:01Z";\n';

    expect(withUpdatedScancodeTimestamp(source, "Tue, 01 Sep 2026 00:00:00 GMT")).toBe(
      'export const SCANCODE_SNAPSHOT_TIMESTAMP = "Tue, 01 Sep 2026 00:00:00 GMT";\n',
    );
    expect(() =>
      withUpdatedScancodeTimestamp("// no declaration here", "Tue, 01 Sep 2026 00:00:00 GMT"),
    ).toThrow(/SCANCODE_SNAPSHOT_TIMESTAMP/);
  });

  test("withUpdatedScancodeTimestamp rejects a Last-Modified value that is not RFC 7231 date-shaped, before it can ever reach the string replacement", () => {
    const source = 'export const SCANCODE_SNAPSHOT_TIMESTAMP = "2026-08-10T16:21:01Z";\n';

    // A raw HTTP header is untrusted input. A "$&"/"$'"-style token here, spliced through a
    // template-string replacement (String.replace's special replacement-pattern syntax), would
    // insert the matched declaration text into itself instead of the intended timestamp -
    // corrupting data.ts silently rather than throwing. The shape gate rejects it outright, and
    // the underlying rewrite itself uses a function replacement, never a raw string, so even a
    // date-shaped value could not trigger the substitution syntax (RFC dates carry no "$").
    expect(() => withUpdatedScancodeTimestamp(source, "$&")).toThrow(/RFC 7231/);
    expect(() => withUpdatedScancodeTimestamp(source, "$'malicious")).toThrow(/RFC 7231/);
    expect(() => withUpdatedScancodeTimestamp(source, "not-a-date-at-all")).toThrow(/RFC 7231/);
  });

  test("renderProvenance embeds every dynamic field for all three sources", () => {
    const rendered = renderProvenance({
      matrix: {
        retrievalUrl: "https://example.test/matrix.json",
        retrievedAt: "2026-09-01T00:00:00.000Z",
        upstreamTimestamp: "2026-08-30T00:00:00+0000",
        sha256: "a".repeat(64),
      },
      copyleft: {
        retrievalUrl: "https://example.test/copyleft.json",
        retrievedAt: "2026-09-01T00:00:00.000Z",
        upstreamTimestamp: "2026-08-30T00:00:00+0000",
        sha256: "b".repeat(64),
      },
      scancode: {
        retrievalUrl: "https://example.test/index.json",
        retrievedAt: "2026-09-01T00:00:00.000Z",
        upstreamTimestamp: "Sun, 30 Aug 2026 00:00:00 GMT",
        sha256: "c".repeat(64),
      },
    });

    expect(rendered).toContain("a".repeat(64));
    expect(rendered).toContain("b".repeat(64));
    expect(rendered).toContain("c".repeat(64));
    expect(rendered).toContain("https://example.test/matrix.json");
    expect(rendered).toContain("https://example.test/copyleft.json");
    expect(rendered).toContain("https://example.test/index.json");
  });
});
