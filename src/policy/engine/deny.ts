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
 *   - leaf       → denied iff the leaf, or its id without a WITH exception, satisfies the deny
 *                  allowlist;
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
 * of a finding that has an acceptable branch. The other lanes then judge the finding without its
 * denied branches (withoutDeniedBranches), so "GPL-3.0 OR BUSL-1.1" is judged as GPL.
 *
 * One election runs across every license rule, not one per rule (load-bearing): it must run against
 * the union of every match="license" deny allowlist, not each rule's allowlist in isolation. The
 * shipped defaults provide BUSL-1.1, SSPL-1.0, and Elastic-2.0 as separate match="license" rules,
 * so an isolated per-rule election sees only one branch of "BUSL-1.1 OR SSPL-1.0" and never denies
 * it - each rule finds the other branch electable on its own. The correct decision builds the
 * combined allowlist once and asks nodeDenied against it: "BUSL-1.1 OR SSPL-1.0" then has no
 * electable branch and is denied, while "MIT OR BUSL-1.1" stays electable (MIT is in neither
 * allowlist). When the union denies, the verdict is attributed to the first license rule that
 * contributes a denied leaf, and the reason names every other contributing rule. Name-mode rules
 * stay per-rule - an exact name compare has nothing to elect.
 *
 * Pure functions, no I/O, no logging; the satisfies calls are wrapped in a defensive catch to
 * preserve the engine's never-throws posture.
 */
import satisfies from "spdx-satisfies";

import parseSpdx from "spdx-expression-parse";

import { asSpdxLicenseLeaf, type SpdxLicenseLeaf } from "../../model/dependencies";
import { type ExpressionNode } from "../../normalize/expression";
import { baseLeafId } from "../compat/classify";
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

/** The effective deny rules, split by what `[[allow_source_available]]` lifts. */
export interface ExemptionAwareDenyRules {
  /** The rules no exemption lifts, in precedence order. */
  readonly inForce: ReadonlyArray<IndexedDenyRule>;
  /** Every rule, the exempted shipped defaults first, so attribution names one when it can. */
  readonly exemptedFirst: ReadonlyArray<IndexedDenyRule>;
}

/** The effective deny rules split into those in force and those an exemption lifts. */
export function exemptionAwareDenyRules(policy: Policy): ExemptionAwareDenyRules {
  const exemptedLicenses = new Set<string>(
    policy.allowSourceAvailable.map((entry) => entry.license),
  );
  const isExempted = (r: IndexedDenyRule): boolean =>
    r.ruleId === BUILTIN_DENY_RULE_ID &&
    r.rule.match === "license" &&
    exemptedLicenses.has(r.rule.pattern);
  const rules = effectiveDenyRules(policy);

  return {
    inForce: rules.filter((r) => !isExempted(r)),
    exemptedFirst: [...rules.filter(isExempted), ...rules.filter((r) => !isExempted(r))],
  };
}

/** True iff one leaf form satisfies the deny allowlist (defensive catch). */
function satisfiesDenyAllowlist(
  form: SpdxLicenseLeaf,
  allowlist: readonly SpdxLicenseLeaf[],
): boolean {
  try {
    return satisfies(form, [...allowlist]);
  } catch {
    return false;
  }
}

/**
 * True iff a single leaf, or its base id without the exception and `+`, is denied. An exception
 * only narrows obligations, so `BUSL-1.1 WITH x` stays denied.
 */
function leafDenied(leaf: SpdxLicenseLeaf, allowlist: readonly SpdxLicenseLeaf[]): boolean {
  return [leaf, asSpdxLicenseLeaf(baseLeafId(leaf))].some((form) =>
    satisfiesDenyAllowlist(form, allowlist),
  );
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

/** The combined allowlist of every match="license" rule among `rules`. */
function unionAllowlist(rules: ReadonlyArray<IndexedDenyRule>): SpdxLicenseLeaf[] {
  return rules.flatMap((r) => (r.rule.match === "license" ? r.rule.allowlist : []));
}

/** The combined allowlist of every license-mode deny rule, policy entries and shipped defaults. */
export function licenseDenyUnion(policy: Policy): SpdxLicenseLeaf[] {
  return unionAllowlist(effectiveDenyRules(policy));
}

/** {@link licenseDenyUnion} without the shipped defaults `[[allow_source_available]]` lifts. */
export function inForceLicenseDenyUnion(policy: Policy): SpdxLicenseLeaf[] {
  return unionAllowlist(exemptionAwareDenyRules(policy).inForce);
}

/**
 * The expression with every OR branch the deny union covers dropped while a sibling branch is not
 * covered, so election ranks a denied branch below every other, copyleft included. An OR whose
 * branches are all denied is kept whole: the deny lane fails it.
 */
export function withoutDeniedBranches(
  node: ExpressionNode,
  union: readonly SpdxLicenseLeaf[],
): ExpressionNode {
  if ("license" in node) {
    return node;
  }

  if (node.conjunction === "or") {
    const leftDenied = nodeDenied(node.left, union);

    if (leftDenied !== nodeDenied(node.right, union)) {
      return withoutDeniedBranches(leftDenied ? node.right : node.left, union);
    }
  }

  return {
    left: withoutDeniedBranches(node.left, union),
    conjunction: node.conjunction,
    right: withoutDeniedBranches(node.right, union),
  };
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
 * shipped defaults) once and ask nodeDenied against it. When denied, returns every license rule
 * that contributes a denied leaf, in effective order, so the citation names real rules - policy
 * first. A null/unparseable expression can never be license-denied. Returns an empty list when no
 * license rule, or no electable-out branch, applies.
 */
function unionLicenseDeny(
  rules: ReadonlyArray<IndexedDenyRule>,
  expression: string,
): IndexedDenyRule[] {
  const licenseRules = rules.filter((r) => r.rule.match === "license");
  let node: ExpressionNode;

  try {
    node = parseSpdx(expression) as ExpressionNode;
  } catch {
    return [];
  }

  if (licenseRules.length === 0 || !nodeDenied(node, unionAllowlist(licenseRules))) {
    return [];
  }

  const contributing = licenseRules.filter(
    (r) => r.rule.match === "license" && anyLeafDenied(node, r.rule.allowlist),
  );

  // defensive: denied by the union, attribute to the first rule
  return contributing.length > 0 ? contributing : licenseRules.slice(0, 1);
}

/** A matched deny rule plus every rule the denial rests on. */
export interface DenyMatch extends IndexedDenyRule {
  /** Every matching rule with a distinct pattern, this one first, in effective order. */
  readonly contributing: ReadonlyArray<IndexedDenyRule>;
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
): DenyMatch | undefined {
  return denyRuleAmong(effectiveDenyRules(policy), expression, name);
}

/** {@link denyRuleFor} over an explicit rule list, in that list's precedence order. */
export function denyRuleAmong(
  rules: ReadonlyArray<IndexedDenyRule>,
  expression: string | null,
  name: string,
): DenyMatch | undefined {
  const nameMatches = rules.filter((r) => r.rule.match === "name" && r.rule.pattern === name);
  const licenseMatches = expression === null ? [] : unionLicenseDeny(rules, expression);
  const matches = [...nameMatches, ...licenseMatches].sort(
    (a, b) => rules.indexOf(a) - rules.indexOf(b),
  );
  const first = matches[0];

  if (first === undefined) {
    return undefined;
  }

  const seen = new Set<string>();
  const contributing = matches.filter((r) => {
    const key = `${r.rule.match}\u0000${r.rule.pattern}`;
    const fresh = !seen.has(key);

    seen.add(key);
    return fresh;
  });

  return { ...first, contributing };
}
