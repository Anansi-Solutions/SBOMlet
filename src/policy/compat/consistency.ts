/**
 * Cross-tier disagreement enumeration between the OSADL matrix and the OSADL copyleft-class table.
 *
 * The two tables are independently curated and occasionally disagree in ways that would flip a
 * verdict depending on which tier answers first: a license classed "not copyleft" that some leading
 * license still refuses as a subordinate (the class table under-reports an incompatibility the
 * matrix carries), or a copyleft-classed license that a permissive-led row nonetheless absorbs (the
 * matrix under-reports the obligation the class table carries). Runtime classification stays strict
 * first-tier-wins regardless - this enumerator exists purely to surface disagreements when the data
 * is reviewed: the test suite pins the CURRENT snapshot's list as an exact allowlist, and the
 * refresh task (scripts/refresh-compat-data.ts) runs this same function against a freshly
 * downloaded pair and aborts on any entry the allowlist does not already name.
 */
import type { OsadlCopyleftClass, OsadlMatrixCell } from "./data";

/** Leading licenses whose absorption of a copyleft-classed dependency is checked for tier (b). */
const PERMISSIVE_LEADS: readonly string[] = ["MIT", "BSD-3-Clause", "ISC"];

const compareCodeUnits = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Enumerate every inter-tier disagreement on the given matrix/class-table pair, as a sorted,
 * rendered list of one line per disagreement. Two disagreement shapes, per the data-review
 * definition above:
 *
 * (a) a license classed "No" (not copyleft) that some OTHER leading license's row still rejects it
 *     as subordinate (cell "No") - reported against the lexicographically smallest such leading
 *     license, so the rendered line is deterministic regardless of the maps' iteration order.
 * (b) a license classed "Yes" or "Yes (restricted)" that a permissive leading license (MIT,
 *     BSD-3-Clause, ISC) accepts as subordinate (cell "Yes") - one line per matching leading
 *     license, since each is independently informative.
 */
export function interTierDisagreements(
  matrix: ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>>,
  copyleftClass: ReadonlyMap<string, OsadlCopyleftClass>,
): readonly string[] {
  const ids = [...matrix.keys()].sort(compareCodeUnits);
  const lines: string[] = [];

  for (const subordinate of ids) {
    if (copyleftClass.get(subordinate) !== "No") {
      continue;
    }

    const rejectingLeads = ids
      .filter(
        (leading) => leading !== subordinate && matrix.get(leading)?.get(subordinate) === "No",
      )
      .sort(compareCodeUnits);

    if (rejectingLeads.length > 0) {
      lines.push(`${subordinate}: class No but ${rejectingLeads[0]}→${subordinate} = No`);
    }
  }

  for (const subordinate of ids) {
    const subClass = copyleftClass.get(subordinate);

    if (subClass !== "Yes" && subClass !== "Yes (restricted)") {
      continue;
    }

    for (const leading of PERMISSIVE_LEADS) {
      if (matrix.get(leading)?.get(subordinate) === "Yes") {
        lines.push(`${subordinate}: class ${subClass} but ${leading}→${subordinate} = Yes`);
      }
    }
  }

  return lines.sort(compareCodeUnits);
}
