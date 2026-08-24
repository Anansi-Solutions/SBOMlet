/**
 * Per-value justification predicates: whether a `[[clarify]]` entry's stated reason still holds
 * against what the sources report now.
 *
 * Each value of the closed justification set asserts something specific about the two lanes - the
 * declared/registry claim and the in-depth scan - and most of those assertions are checkable. One
 * the evidence disproves fails the gate. One whose subject has simply gone away leaves the entry
 * unnecessary rather than wrong: that is a signal for the maintainer, never a failure.
 *
 * Every predicate reads the licences a lane's members resolve to, so a member carrying only a
 * family label ("BSD", "Dual License") weighs on nothing. A lane that stopped reporting what the
 * entry recorded is the staleness precondition's business, decided before any of this runs.
 */

import parseSpdx from "spdx-expression-parse";

import { type NormalizedLicense, type SpdxExpression } from "../../model/dependencies";
import { leafIds, orLeaves, type ExpressionNode } from "../../normalize/expression";
import { accountsFor, type ObservedSignal } from "../../normalize/normalize";
import { statedLicense } from "../statedLicense";
import { type Justification } from "../schema/clarify";

/** What a validity check reads off an entry: its stated reason and the expression it records. */
export interface JustifiedExpression {
  readonly justification: Justification;
  readonly expression: SpdxExpression;
}

/**
 * The verdict on one entry's justification.
 *
 * `invalid` is a gate failure - the reason names the divergence and the sanctioned refile.
 * `unnecessary` is the maintainer signal: the justification was true and the thing it corrected is
 * gone, so the entry can be dropped.
 */
export type JustificationValidity =
  | { readonly outcome: "ok" }
  | { readonly outcome: "invalid"; readonly reason: string }
  | { readonly outcome: "unnecessary"; readonly reason: string };

const OK: JustificationValidity = { outcome: "ok" };

/** The values an entry the evidence disproves can legally move to, named in every reason. */
const REFILE =
  "file the entry under the justification the evidence now supports, under " +
  '"contradictory-claims-recorded" when the sources genuinely disagree, or accept the licence ' +
  'outright with a [[compatible]] entry whose rationale is "license-reviewed"';

function invalid(detail: string, justification: Justification): JustificationValidity {
  return {
    outcome: "invalid",
    reason: `"${justification}" no longer holds: ${detail} — ${REFILE}.`,
  };
}

function unnecessary(detail: string, justification: Justification): JustificationValidity {
  return {
    outcome: "unnecessary",
    reason: `"${justification}" has nothing left to correct: ${detail}.`,
  };
}

/** Every lane member the normalizer reads as a precise expression, in lane order. */
function preciseMembers(lane: ReadonlyArray<string>): NormalizedLicense[] {
  return lane
    .map((member) => statedLicense(member))
    .filter((expression): expression is NormalizedLicense => expression !== null);
}

/** The SPDX leaf ids across some expressions; an unparseable one contributes none. */
function leavesOf(expressions: ReadonlyArray<string>): Set<string> {
  const ids = new Set<string>();

  for (const expression of expressions) {
    try {
      for (const id of leafIds(parseSpdx(expression) as ExpressionNode).ids) {
        ids.add(id);
      }
    } catch {
      /* nothing to compare */
    }
  }

  return ids;
}

/** The parsed expression, or null when it is not SPDX at all - defensive, never thrown. */
function parseNode(expression: string): ExpressionNode | null {
  try {
    return parseSpdx(expression) as ExpressionNode;
  } catch {
    return null;
  }
}

function sameLeaves(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  return a.size === b.size && [...a].every((id) => b.has(id));
}

/**
 * The entry records a choice the package offers, which the scan then joined with AND. It is
 * disproved when the scan's leaves are not the recorded choice - nothing was joined, so there was
 * no choice to record - or when the declared side has stopped offering any of the recorded
 * licences.
 */
function dualLicenseChoice(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  const node = parseNode(rule.expression);
  const choice = node === null ? null : orLeaves(node);

  if (choice === null) {
    return invalid(`the recorded "${rule.expression}" is not a choice`, rule.justification);
  }

  const chosen = leavesOf(choice);
  const scanned = leavesOf(preciseMembers(signal.intensive));

  if (scanned.size > 0 && !sameLeaves(chosen, scanned)) {
    return invalid(
      `the in-depth scan reads "${signal.intensive.join(", ")}", not the recorded choice`,
      rule.justification,
    );
  }

  const declared = leavesOf(preciseMembers(signal.registry));

  if (declared.size > 0 && ![...chosen].some((id) => declared.has(id))) {
    return invalid(
      `the declared claim "${signal.registry.join(", ")}" offers none of the recorded licences`,
      rule.justification,
    );
  }

  return OK;
}

/**
 * The entry drops leaves the scan reported from files that do not govern the package. Once the scan
 * reports nothing outside the recorded expression there is nothing left to drop.
 */
function scanOverdetection(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  const scanned = leavesOf(preciseMembers(signal.intensive));

  if (scanned.size === 0) {
    return OK;
  }

  const recorded = leavesOf([rule.expression]);

  return [...scanned].some((id) => !recorded.has(id))
    ? OK
    : unnecessary(
        "the in-depth scan reports no licence outside the recorded expression",
        rule.justification,
      );
}

/**
 * The entry adopts the scan's reading, so the recorded expression has to account for every licence
 * the scan reads. One it does not cover disproves the adoption.
 */
function adoptsScanReading(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  const unaccounted = preciseMembers(signal.intensive).filter(
    (member) => !accountsFor(rule.expression, member),
  );

  return unaccounted.length === 0
    ? OK
    : invalid(
        `the recorded expression does not account for the in-depth scan's "${unaccounted.join(", ")}"`,
        rule.justification,
      );
}

/** The entry adopts the declared claim, which therefore has to still name every leaf it took. */
function declaredMoreComplete(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  const declared = leavesOf(preciseMembers(signal.registry));

  if (declared.size === 0) {
    return OK;
  }

  const dropped = [...leavesOf([rule.expression])].filter((id) => !declared.has(id));

  return dropped.length === 0
    ? OK
    : invalid(
        `the declared claim "${signal.registry.join(", ")}" no longer names ${dropped.join(", ")}`,
        rule.justification,
      );
}

/**
 * The entry records both sides of an irreconcilable disagreement. Once the two sides read the same
 * licences there is no disagreement left to record - re-spelling is not disagreement, so the
 * comparison is on the leaves each side resolves to.
 */
function contradictoryClaims(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  const declared = leavesOf(preciseMembers(signal.registry));
  const scanned = leavesOf(preciseMembers(signal.intensive));

  if (declared.size === 0 || scanned.size === 0) {
    return OK;
  }

  return sameLeaves(declared, scanned)
    ? unnecessary(
        "the declared claim and the in-depth scan now agree on the same licences",
        rule.justification,
      )
    : OK;
}

/**
 * The entry supplies an expression no source stated. A source that now states one is evidence a
 * person has to read, whether or not it agrees with what was researched.
 */
function licenseNotFound(rule: JustifiedExpression, signal: ObservedSignal): JustificationValidity {
  const stated = [...preciseMembers(signal.registry), ...preciseMembers(signal.intensive)];

  return stated.length === 0
    ? OK
    : invalid(`detection now states "${stated.join(", ")}"`, rule.justification);
}

/**
 * Whether an entry's stated justification still holds against the partitioned signal.
 *
 * Pure, and the single authority on what each justification value asserts: the gate reads it for
 * the failing outcome, maintainer tooling for the unnecessary one.
 */
export function justificationValidity(
  rule: JustifiedExpression,
  signal: ObservedSignal,
): JustificationValidity {
  switch (rule.justification) {
    case "contradictory-claims-recorded":
      return contradictoryClaims(rule, signal);
    case "declared-more-complete":
      return declaredMoreComplete(rule, signal);
    case "dual-license-choice":
      return dualLicenseChoice(rule, signal);
    case "license-not-found":
      return licenseNotFound(rule, signal);
    case "scan-found-additional-content":
    case "scan-more-precise":
      return adoptsScanReading(rule, signal);
    case "scan-overdetection":
      return scanOverdetection(rule, signal);
  }
}
