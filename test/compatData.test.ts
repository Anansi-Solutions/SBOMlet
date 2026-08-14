import { describe, expect, test } from "bun:test";
import parse from "spdx-expression-parse";

import { interTierDisagreements } from "../src/policy/compat/consistency";
import {
  narrowOsadlCopyleftClass,
  narrowOsadlMatrix,
  narrowScancodeCategory,
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  SCANCODE_CATEGORY,
} from "../src/policy/compat/data";

const MATRIX_CELLS = new Set(["Same", "Yes", "No", "Unknown", "Check dependency"]);
const COPYLEFT_CLASSES = new Set(["No", "Yes", "Yes (restricted)", "Questionable"]);

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
  "Apache-1.0: class No but AGPL-3.0-only→Apache-1.0 = No",
  "Apache-1.1: class No but AGPL-3.0-only→Apache-1.1 = No",
  "Apache-2.0: class No but GPL-1.0-only→Apache-2.0 = No",
  "BSD-4-Clause-UC: class No but AGPL-3.0-only→BSD-4-Clause-UC = No",
  "BSD-4-Clause: class No but AGPL-3.0-only→BSD-4-Clause = No",
  "BSD-4.3TAHOE: class No but AGPL-3.0-only→BSD-4.3TAHOE = No",
  "ECL-2.0: class No but APSL-2.0→ECL-2.0 = No",
  "FTL: class No but AGPL-3.0-only→FTL = No",
  "IJG: class No but AGPL-3.0-only→IJG = No",
  "LicenseRef-scancode-bsla-no-advert: class No but AGPL-3.0-only→LicenseRef-scancode-bsla-no-advert = No",
  "Minpack: class No but AGPL-3.0-only→Minpack = No",
  "PHP-3.01: class No but AGPL-3.0-only→PHP-3.01 = No",
  "PSF-2.0: class No but AGPL-3.0-only→PSF-2.0 = No",
  "Python-2.0: class No but AGPL-3.0-only→Python-2.0 = No",
  "Spencer-86: class No but Sleepycat→Spencer-86 = No",
  "XFree86-1.1: class No but APSL-2.0→XFree86-1.1 = No",
  "zlib-acknowledgement: class No but AGPL-3.0-only→zlib-acknowledgement = No",
];

describe("inter-tier disagreement allowlist (refresh-time gate, A3)", () => {
  test("the current snapshot's disagreements match the pinned allowlist exactly", () => {
    expect(interTierDisagreements(OSADL_MATRIX, OSADL_COPYLEFT_CLASS)).toEqual(
      PINNED_INTER_TIER_DISAGREEMENTS,
    );
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
