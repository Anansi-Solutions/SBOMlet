/**
 * Terminal deny-list matcher.
 *
 * A deny entry force-fails a matching package at the very top of verdictFor, above stale,
 * compatible, workspace suppression, and the dev-scope downgrade. A use-restricted
 * ("source-available") license (BUSL/SSPL/Elastic/RSAL) or a use-restriction rider (Commons-Clause)
 * legally cannot be redistributed in client-shipped artifacts, so no other policy lever can license
 * it back in. Deny mirrors compatible: compatible elects a package in, deny elects it out (see
 * docs/glossary.md#election for what "elect" means here).
 *
 * The effective deny set has two sources but one precedence lane: the consumer's policy `[[deny]]`
 * entries, plus the shipped source-available defaults (builtinDenylist.ts). A source-available
 * license fails out of the box with no policy authored, exactly like the shipped copyleft families
 * and clarify defaults. effectiveDenyRules orders policy entries first, so a license a consumer
 * also lists wins attribution to their explicit `denied[i]`; a license only the defaults catch is
 * cited `default:source-available`. The deny election spans both sets, so the two compose
 * correctly.
 *
 * Two match modes, exactly one per entry, mirroring the `[[compatible]]` shape:
 *
 *   match = "license": `pattern` is an SPDX id or an OR of ids, pre-decomposed
 *     at validation time (orLeaves) into a spdx-satisfies allowlist - identical to the compatible
 *     license path. The matcher walks the finding's parsed expression and asks, per node, "is this
 *     branch unavoidably denied?" Never substring, never re-parsed at evaluate time. RSAL has no
 *     registered SPDX id, so it ships in name-mode, not here.
 *
 *   match = "name": `pattern` is a verbatim, case-sensitive package-name
 *     compare. This is the escape hatch for non-SPDX use-restriction riders like Commons-Clause,
 *     which is not a registered SPDX license and rides alongside another license (e.g. "MIT AND
 *     Commons-Clause" - not SPDX-parseable). The spdx-satisfies path cannot catch it; an exact name
 *     compare can. Name-mode deliberately does not require a parseable license expression - a
 *     package with an unknown (null) finding can still be name-denied. The compare is exact, never
 *     a broad regex or substring, so a typo'd or unrelated name can never be denied. The shipped
 *     defaults are license-mode only - a name-mode default would have to guess encumbered package
 *     names.
 *
 * Election applies to deny too, not just to compatible (load-bearing): spdx-satisfies(finding,
 * allowlist) is the wrong primitive for deny - it treats the allowlist as "available licenses" and
 * calls an OR finding satisfied when any branch is available, so satisfies("MIT OR BUSL-1.1",
 * ["BUSL-1.1"]) is true. That would wrongly deny a dependency that can elect MIT instead. The
 * correct rule is the dual of isCopyleft's recursion: a finding is denied only when it has no
 * branch left to elect out of the deny set.
 *   - leaf       → denied iff the leaf satisfies the deny allowlist;
 *   - OR (l, r) → denied iff both sides are denied (one electable branch
 *                  defeats the denial);
 *   - AND (l, r) → denied iff either side is denied (an AND conjunct cannot be elected away - every
 *     obligation applies).
 * Concretely, with BUSL-1.1 in the deny set:
 *   - "MIT OR BUSL-1.1"      → not denied (MIT is an electable branch - the
 *                              same election compatible relies on).
 *   - "GPL-3.0 OR BUSL-1.1" → denied only when the deny set covers both branches, i.e. no branch is
 *     electable out.
 * This keeps deny exactly consistent with the compatible election path while preventing over-denial
 * of a finding that has an acceptable branch.
 *
 * One election runs across every license rule, not one per rule (load-bearing): it must run against
 * the union of every match="license" deny allowlist, not each rule's allowlist in isolation. The
 * shipped defaults provide BUSL-1.1, SSPL-1.0, and Elastic-2.0 as separate match="license" rules,
 * so an isolated per-rule election sees only one branch of "BUSL-1.1 OR SSPL-1.0" and never denies
 * it - each rule finds the other branch electable on its own. The correct decision builds the
 * combined allowlist once and asks nodeDenied against it: "BUSL-1.1 OR SSPL-1.0" then has no
 * electable branch and is denied, while "MIT OR BUSL-1.1" stays electable (MIT is in neither
 * allowlist). When the union denies, the verdict is attributed to the first license rule that
 * contributes a denied leaf, for the rule-id/reason. Name-mode rules stay per-rule - an exact name
 * compare has nothing to elect.
 *
 * Pure functions, no I/O, no logging; the satisfies calls are wrapped in a defensive catch to
 * preserve the engine's never-throws posture.
 */
import satisfies from "spdx-satisfies";

import parseSpdx from "spdx-expression-parse";

import { asSpdxLicenseLeaf, type SpdxLicenseLeaf } from "../../model/dependencies";
import { type ExpressionNode } from "../../normalize/expression";
import { BUILTIN_DENY_RULES, BUILTIN_DENY_RULE_ID } from "./builtinDenylist";
import type { DenyRule } from "../schema/deny";
import type { Policy } from "../schema";

/**
 * A matched deny rule plus the rule id it is cited under: `denied[i]` for a consumer policy rule,
 * `default:source-available` for a shipped default.
 */
export interface IndexedDenyRule {
  ruleId: string;
  rule: DenyRule;
}

/**
 * The effective deny rules in precedence order: the consumer's policy denies first (cited
 * `denied[i]`), then the shipped source-available defaults (cited `default:source-available`).
 * Policy-first ordering means a license a consumer also lists wins attribution to their explicit
 * rule; the deny election (unionLicenseDeny) spans both sets regardless of order, so the two
 * compose.
 */
function effectiveDenyRules(policy: Policy): IndexedDenyRule[] {
  const rules: IndexedDenyRule[] = [];

  policy.deny.forEach((rule, index) => rules.push({ ruleId: `denied[${index}]`, rule }));
  for (const rule of BUILTIN_DENY_RULES) {
    rules.push({ ruleId: BUILTIN_DENY_RULE_ID, rule });
  }

  return rules;
}

/** True iff a single leaf id satisfies the deny allowlist (defensive catch). */
function leafDenied(leaf: SpdxLicenseLeaf, allowlist: readonly SpdxLicenseLeaf[]): boolean {
  try {
    return satisfies(leaf, [...allowlist]);
  } catch {
    return false;
  }
}

/**
 * Dual of isCopyleft over the parsed finding AST: OR is denied only when both branches are denied
 * (an electable branch defeats the denial); AND is denied when either conjunct is denied (no
 * conjunct can be elected away).
 */
function nodeDenied(node: ExpressionNode, allowlist: readonly SpdxLicenseLeaf[]): boolean {
  if ("license" in node) {
    return leafDenied(asSpdxLicenseLeaf(renderLeaf(node)), allowlist);
  }

  if (node.conjunction === "and") {
    return nodeDenied(node.left, allowlist) || nodeDenied(node.right, allowlist);
  }

  return nodeDenied(node.left, allowlist) && nodeDenied(node.right, allowlist);
}

/** Leaf rendering for the satisfies call (id[+][ WITH exception]). */
function renderLeaf(node: { license: string; plus?: true; exception?: string }): string {
  const plus = node.plus === true ? "+" : "";
  const withPart = node.exception !== undefined ? ` WITH ${node.exception}` : "";

  return `${node.license}${plus}${withPart}`;
}

/** True when any leaf of the parsed expression satisfies the allowlist. */
function anyLeafDenied(node: ExpressionNode, allowlist: readonly SpdxLicenseLeaf[]): boolean {
  if ("license" in node) {
    return leafDenied(asSpdxLicenseLeaf(renderLeaf(node)), allowlist);
  }

  return anyLeafDenied(node.left, allowlist) || anyLeafDenied(node.right, allowlist);
}

/**
 * License-mode union election: build the combined allowlist of every match="license" rule (policy +
 * shipped defaults) once and ask nodeDenied against it. When denied, attribute to the first license
 * rule that contributes a denied leaf, so the rule-id/reason names a real rule - policy first per
 * effectiveDenyRules order. A null/unparseable expression can never be license-denied. Returns
 * undefined when no license rule, or no electable-out branch, applies.
 */
function unionLicenseDeny(
  rules: ReadonlyArray<IndexedDenyRule>,
  expression: string,
): IndexedDenyRule | undefined {
  const licenseRules = rules.filter((r) => r.rule.match === "license");

  if (licenseRules.length === 0) {
    return undefined;
  }

  const union: SpdxLicenseLeaf[] = [];

  for (const r of licenseRules) {
    if (r.rule.match === "license") {
      union.push(...r.rule.allowlist);
    }
  }

  let node: ExpressionNode;

  try {
    node = parseSpdx(expression) as ExpressionNode;
  } catch {
    return undefined;
  }

  if (!nodeDenied(node, union)) {
    return undefined;
  }

  // Attribute to the first license rule that contributes a denied leaf.
  for (const candidate of licenseRules) {
    if (candidate.rule.match === "license" && anyLeafDenied(node, candidate.rule.allowlist)) {
      return candidate;
    }
  }

  return licenseRules[0]; // defensive: denied by the union, attribute to first
}

/**
 * First deny rule that matches, or undefined, over the effective deny set (policy denies, then
 * shipped source-available defaults). Name-mode matches the exact package `name` per-rule (nothing
 * to elect) and does not need a parseable expression. License-mode matches against the finding's
 * already-normalized `expression`, electing over the union of all license deny allowlists; a null
 * expression (unknown/imprecise) can never be license-denied.
 *
 * Name-mode and license-mode are reconciled by effective order, so the earliest-listed matching
 * rule wins - a name rule before a contributing license rule is cited first, matching the
 * documented "first deny rule" precedence.
 */
export function denyRuleFor(
  policy: Policy,
  expression: string | null,
  name: string,
): IndexedDenyRule | undefined {
  const rules = effectiveDenyRules(policy);
  let nameMatch: IndexedDenyRule | undefined;
  let namePosition = -1;

  for (const [position, r] of rules.entries()) {
    if (r.rule.match === "name" && r.rule.pattern === name) {
      nameMatch = r;
      namePosition = position;
      break;
    }
  }

  const licenseMatch = expression === null ? undefined : unionLicenseDeny(rules, expression);

  if (nameMatch === undefined) {
    return licenseMatch;
  }

  if (licenseMatch === undefined) {
    return nameMatch;
  }

  // Both matched: the earlier rule in effective order wins (mirrors the prior lowest-index
  // precedence). licenseMatch is a reference into `rules`.
  const licensePosition = rules.indexOf(licenseMatch);

  return namePosition <= licensePosition ? nameMatch : licenseMatch;
}
