import { describe, expect, test } from "bun:test";

import { classifyLeaf } from "./classify";
import { OSADL_MATRIX, type OsadlMatrixCell } from "./data";
import type { AxisClass, TargetLicense } from "./classification";

const oss = (id: string): TargetLicense => ({ kind: "oss", id });
const proprietary: TargetLicense = { kind: "proprietary" };

/**
 * The matrix-cell contract, transcribed from classify.ts's `classifyMatrixCell` switch and its
 * module doc (not read back through the function under test): a `Same`/`Yes` cell is a pass, a `No`
 * cell is a hard fail, and both open-ended verdicts are an honest residual. This is the single
 * oracle the whole-matrix sweep below asserts `classifyLeaf` against for every populated cell.
 */
function expectedCellClass(cell: OsadlMatrixCell): AxisClass {
  switch (cell) {
    case "Same":
    case "Yes":
      return "compatible";
    case "No":
      return "incompatible";
    case "Unknown":
    case "Check dependency":
      return "residual";
  }
}

/** One flat (leading target, subordinate leaf, cell) view of the matrix - the sweep's row set. */
interface MatrixEntry {
  readonly leading: string;
  readonly subordinate: string;
  readonly cell: OsadlMatrixCell;
}

const ALL_CELLS: readonly MatrixEntry[] = [...OSADL_MATRIX].flatMap(([leading, row]) =>
  [...row].map(([subordinate, cell]) => ({ leading, subordinate, cell })),
);

describe("classifyLeaf - whole-matrix consistency sweep (matrix as oracle)", () => {
  test(`every populated OSADL cell maps to its matrixTier class and cites the cell verbatim`, () => {
    // The core "many combinations" pass: the OSS matrix is square (~119 rows), so this exercises
    // every leading-target x subordinate-leaf pair the vetted data models - on the order of 14k
    // combinations. Violations accumulate so a failure prints one readable diff of the offending
    // (leading, subordinate) pairs, not thousands of separate assertion frames.
    const mismatches = ALL_CELLS.flatMap(({ leading, subordinate, cell }) => {
      const result = classifyLeaf(oss(leading), subordinate);
      const expected = { class: expectedCellClass(cell), source: `OSADL: ${cell}` };
      const actual = { class: result.class, source: result.source };

      return JSON.stringify(actual) === JSON.stringify(expected)
        ? []
        : [{ leading, subordinate, cell, expected, actual }];
    });

    expect(mismatches).toEqual([]);
  });

  test("the sweep covers the full square matrix, not a degenerate subset", () => {
    const rows = OSADL_MATRIX.size;

    expect(rows).toBeGreaterThanOrEqual(100);
    expect(ALL_CELLS.length).toBe(rows * rows);
  });
});

describe("classifyLeaf - matrix invariants partitioned by cell value", () => {
  const cellsWhere = (predicate: (cell: OsadlMatrixCell) => boolean): readonly MatrixEntry[] =>
    ALL_CELLS.filter(({ cell }) => predicate(cell));

  test("reflexivity: every diagonal (a license against itself) is compatible, never incompatible", () => {
    const offenders = [...OSADL_MATRIX.keys()].filter(
      (id) => classifyLeaf(oss(id), id).class !== "compatible",
    );

    expect(offenders).toEqual([]);
  });

  test("every Same/Yes cell is compatible - a pass is only ever a vetted pass", () => {
    const offenders = cellsWhere((cell) => cell === "Same" || cell === "Yes").filter(
      ({ leading, subordinate }) => classifyLeaf(oss(leading), subordinate).class !== "compatible",
    );

    expect(offenders).toEqual([]);
  });

  test("no No cell is ever a passing class - a hard fail never softens to compatible/boundary/held", () => {
    const passing: readonly AxisClass[] = ["compatible", "boundary"];
    const offenders = cellsWhere((cell) => cell === "No").filter(({ leading, subordinate }) =>
      passing.includes(classifyLeaf(oss(leading), subordinate).class),
    );

    expect(offenders).toEqual([]);
  });

  test("every Unknown/Check-dependency cell is residual - an open verdict never silently passes or fails", () => {
    const offenders = cellsWhere(
      (cell) => cell === "Unknown" || cell === "Check dependency",
    ).filter(
      ({ leading, subordinate }) => classifyLeaf(oss(leading), subordinate).class !== "residual",
    );

    expect(offenders).toEqual([]);
  });
});

describe("classifyLeaf - LicenseRef/DocumentRef universality across many targets", () => {
  const SYNTHETIC_REFS: readonly string[] = [
    "LicenseRef-vendor-custom-eula",
    "LicenseRef-not-in-any-dataset",
    "DocumentRef-spdx-tool-1:LicenseRef-internal",
    "LicenseRef-scancode-this-row-does-not-exist",
  ];
  const TARGETS: readonly TargetLicense[] = [
    oss("MIT"),
    oss("GPL-3.0-only"),
    oss("AGPL-3.0-only"),
    oss("Apache-2.0"),
    proprietary,
  ];

  test("a ref leaf absent from the matrix is always unassessed-ref / unknown, for every target", () => {
    for (const ref of SYNTHETIC_REFS) {
      // A synthetic ref must never coincide with a real matrix column, or matrix-tier would
      // (correctly) intercept it - this guards the premise of the invariant below.
      expect([...OSADL_MATRIX.values()].some((row) => row.has(ref))).toBe(false);
    }

    for (const target of TARGETS) {
      for (const ref of SYNTHETIC_REFS) {
        const result = classifyLeaf(target, ref);

        expect(result.class).toBe("unassessed-ref");
        expect(result.obligation).toBe("unknown");
      }
    }
  });
});
