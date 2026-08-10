/**
 * Unknown-license predicate shared by both rendered documents —
 * THIRD_PARTY_LICENSES.md's counts block and THIRD_PARTY_NOTICES.md's
 * unknown-packages section — so the two can never disagree on which
 * packages count as unknown.
 */

import parseSpdx from "spdx-expression-parse";

import { allLeavesAreRefs, type ExpressionNode } from "../normalize/expression";
import type { PackageEntry } from "../model/dependencies";

/**
 * Unknown-license predicate: a finding with a null expression, an elected
 * branch composed entirely of LicenseRef-/DocumentRef- leaves, or —
 * pre-annotation — no finding and zero claims. An imprecise finding is
 * present, not unknown, so it is excluded.
 */
export function isUnknownLicense(pkg: PackageEntry): boolean {
  const finding = pkg.finding;
  if (finding !== undefined) {
    if (finding.confidence === "imprecise") return false;
    if (finding.expression === null) return true;
    return electedIsRefOnly(finding.elected);
  }
  return pkg.licenseClaims.length === 0;
}

/**
 * True when a finding's elected branch is composed ENTIRELY of
 * LicenseRef-/DocumentRef- leaves. Defensive: elected was rendered by
 * renderNode(elect(...)) so it parses by construction; the catch mirrors
 * the policy engine's never-throws posture rather than crashing report
 * generation.
 */
function electedIsRefOnly(elected: string | null): boolean {
  if (elected === null) return false;
  try {
    // The narrower allLeavesAreRefs, not hasRefLeaf: an AND that keeps a
    // known conjunct alongside a ref carries real content and must not
    // count as unknown here.
    return allLeavesAreRefs(parseSpdx(elected) as ExpressionNode);
  } catch {
    return false;
  }
}
