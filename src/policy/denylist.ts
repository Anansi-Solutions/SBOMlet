/**
 * POL-09 terminal deny-list matcher.
 *
 * A [[deny]] entry FORCE-FAILS a matching package at the very top of verdictFor
 * — above stale, compatible, workspace suppression, and the dev-scope
 * downgrade. A use-restricted ("source-available") license (BUSL/SSPL/Elastic/
 * RSAL) or a use-restriction rider (Commons-Clause) legally cannot be
 * redistributed in client-shipped artifacts, so no other policy lever may
 * license it back in. Deny is the mirror of compatible: where compatible elects
 * a package IN, deny elects it OUT.
 *
 * Two match modes (exactly one per entry, mirroring the [[compatible]] shape):
 *
 *   match = "license": `pattern` is an SPDX id or an OR of ids, pre-decomposed
 *     at VALIDATION time (orLeaves) into a spdx-satisfies allowlist — identical
 *     to the compatible license path. The matcher walks the finding's parsed
 *     expression and asks, per node, "is this branch unavoidably denied?".
 *     Never substring, never re-parsed at evaluate time. RSAL has NO registered
 *     SPDX id, so it ships in name-mode, not here.
 *
 *   match = "name": `pattern` is a VERBATIM (exact, case-sensitive) package-NAME
 *     compare. This is the escape hatch for non-SPDX use-restriction riders like
 *     Commons-Clause, which is NOT a registered SPDX license and rides alongside
 *     another license (e.g. "MIT AND Commons-Clause" — not SPDX-parseable). The
 *     SPDX-satisfies path therefore cannot catch it; an exact name compare can.
 *     Name-mode deliberately does NOT require a parseable license expression —
 *     a package with an unknown (null) finding can still be name-denied. It is
 *     an EXACT compare, never a broad regex/substring, so a typo'd or unrelated
 *     name can never be denied.
 *
 * OR-FINDING-vs-DENY ELECTION SEMANTICS (plan-check W1 — load-bearing):
 * spdx-satisfies(finding, allowlist) is the WRONG primitive for deny because it
 * treats the allowlist as "available licenses" and an OR finding as satisfied
 * when ANY branch is available — so satisfies("MIT OR BUSL-1.1", ["BUSL-1.1"])
 * is TRUE, which would WRONGLY deny a dep that can elect MIT. The correct,
 * OR-election-consistent rule is the DUAL of isCopyleft's recursion: a finding
 * is denied only when it cannot elect OUT of the deny set —
 *   - leaf       → denied iff the leaf satisfies the deny allowlist;
 *   - OR (l, r)  → denied iff BOTH sides are denied (an electable acceptable
 *                  branch defeats the denial);
 *   - AND (l, r) → denied iff EITHER side is denied (an AND conjunct cannot be
 *                  elected away — every obligation applies).
 * Concretely, with [[deny]] match="license" pattern covering BUSL-1.1:
 *   - "MIT OR BUSL-1.1"      → NOT denied (MIT is an electable acceptable
 *                              branch — mirrors compatible OR-election).
 *   - "GPL-3.0 OR BUSL-1.1"  → denied ONLY when the deny set covers BOTH
 *                              branches, i.e. no branch is electable out.
 * This keeps deny exactly consistent with the compatible OR-election path while
 * preventing over-denial of a finding that has an acceptable branch (T-06-16).
 *
 * UNION-ELECTION ACROSS SEPARATE LICENSE RULES (C#6 — load-bearing):
 * The election above must run against the UNION of EVERY match="license" deny
 * allowlist, not each rule's allowlist in isolation. The shipped policy lists
 * BUSL-1.1, SSPL-1.0, Elastic-2.0 as THREE separate match="license" entries, so
 * an isolated per-rule election sees only ONE branch of "BUSL-1.1 OR SSPL-1.0"
 * and never denies it (each rule finds the other branch "electable"). The
 * correct decision builds the combined allowlist once and asks nodeDenied
 * against it; "BUSL-1.1 OR SSPL-1.0" then has NO electable branch and is denied,
 * while "MIT OR BUSL-1.1" stays electable (MIT is in neither allowlist). When
 * the union denies, the verdict is attributed to the FIRST license rule that
 * contributes a denied LEAF (for the rule-id/reason). Name-mode rules stay
 * per-rule (an exact name compare has no election).
 *
 * Pure functions, no I/O, no logging; the satisfies calls are wrapped in a
 * defensive catch to preserve the engine's never-throws posture.
 */
import satisfies from "spdx-satisfies";

import parseSpdx from "spdx-expression-parse";

import { type ExpressionNode } from "../normalize/expression";
import type { Policy } from "./schema";

/**
 * A validated deny entry. License mode carries the pre-decomposed allowlist
 * (orLeaves), name mode carries only the verbatim package name to compare.
 */
export type DenyRule =
  | {
      match: "license";
      /** The pattern exactly as written in the policy file. */
      pattern: string;
      /** Pre-decomposed satisfies allowlist (OR-leaves), computed at validation. */
      allowlist: ReadonlyArray<string>;
      reason: string;
    }
  | { match: "name"; pattern: string; reason: string };

/** A matched deny rule plus its index, for the `denied[i]` rule id. */
export interface IndexedDenyRule {
  index: number;
  rule: DenyRule;
}

/** True iff a single leaf id satisfies the deny allowlist (defensive catch). */
function leafDenied(leaf: string, allowlist: ReadonlyArray<string>): boolean {
  try {
    return satisfies(leaf, [...allowlist]);
  } catch {
    return false;
  }
}

/**
 * Dual of isCopyleft over the parsed finding AST: OR is denied only when BOTH
 * branches are denied (an electable branch defeats the denial — W1); AND is
 * denied when EITHER conjunct is denied (no conjunct can be elected away).
 */
function nodeDenied(
  node: ExpressionNode,
  allowlist: ReadonlyArray<string>,
): boolean {
  if ("license" in node) return leafDenied(renderLeaf(node), allowlist);
  if (node.conjunction === "and") {
    return (
      nodeDenied(node.left, allowlist) || nodeDenied(node.right, allowlist)
    );
  }
  return nodeDenied(node.left, allowlist) && nodeDenied(node.right, allowlist);
}

/** Leaf rendering for the satisfies call (id[+][ WITH exception]). */
function renderLeaf(node: {
  license: string;
  plus?: true;
  exception?: string;
}): string {
  const plus = node.plus === true ? "+" : "";
  const withPart =
    node.exception !== undefined ? ` WITH ${node.exception}` : "";
  return `${node.license}${plus}${withPart}`;
}

/** True when ANY leaf of the parsed expression satisfies the allowlist. */
function anyLeafDenied(
  node: ExpressionNode,
  allowlist: ReadonlyArray<string>,
): boolean {
  if ("license" in node) return leafDenied(renderLeaf(node), allowlist);
  return (
    anyLeafDenied(node.left, allowlist) || anyLeafDenied(node.right, allowlist)
  );
}

/**
 * License-mode union election (C#6): build the combined allowlist of EVERY
 * match="license" deny rule once and ask nodeDenied against it. When denied,
 * attribute to the FIRST license rule that contributes a denied leaf (so the
 * rule-id/reason names a real rule). A null/unparseable expression can never be
 * license-denied. Returns undefined when no license rule (or no electable-out
 * branch) applies.
 */
function unionLicenseDeny(
  policy: Policy,
  expression: string,
): IndexedDenyRule | undefined {
  const licenseRules: IndexedDenyRule[] = [];
  const union: string[] = [];
  for (const [index, rule] of policy.deny.entries()) {
    if (rule.match !== "license") continue;
    licenseRules.push({ index, rule });
    union.push(...rule.allowlist);
  }
  if (union.length === 0) return undefined;
  let node: ExpressionNode;
  try {
    node = parseSpdx(expression) as ExpressionNode;
  } catch {
    return undefined;
  }
  if (!nodeDenied(node, union)) return undefined;
  // Attribute to the first license rule that contributes a denied leaf.
  for (const candidate of licenseRules) {
    if (
      candidate.rule.match === "license" &&
      anyLeafDenied(node, candidate.rule.allowlist)
    ) {
      return candidate;
    }
  }
  return licenseRules[0]; // defensive: denied by the union, attribute to first
}

/**
 * First deny rule that matches, or undefined. Name-mode matches the exact
 * package `name` per-rule (no election) and does NOT need a parseable
 * expression. License-mode matches against the finding's (already-normalized)
 * `expression` with OR-election semantics over the UNION of all license deny
 * allowlists (C#6); a null expression (unknown/imprecise) can never be
 * license-denied.
 *
 * Name-mode and license-mode are checked in rule order so the lowest-index
 * matching rule wins — a name rule before a contributing license rule is cited
 * first, matching the documented "first deny rule" precedence.
 */
export function denyRuleFor(
  policy: Policy,
  expression: string | null,
  name: string,
): IndexedDenyRule | undefined {
  let nameMatch: IndexedDenyRule | undefined;
  for (const [index, rule] of policy.deny.entries()) {
    if (rule.match === "name" && rule.pattern === name) {
      nameMatch = { index, rule };
      break;
    }
  }
  const licenseMatch =
    expression === null ? undefined : unionLicenseDeny(policy, expression);
  if (nameMatch === undefined) return licenseMatch;
  if (licenseMatch === undefined) return nameMatch;
  // Both matched: the lower index (earlier rule) wins.
  return nameMatch.index <= licenseMatch.index ? nameMatch : licenseMatch;
}
