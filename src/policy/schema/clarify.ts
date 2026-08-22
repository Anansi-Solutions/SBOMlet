import { recordOf, stringOf } from "../../validate/record";
import { statedLicense } from "../justificationValidity";

import {
  checkKeys,
  optionalText,
  parseSpdxChecked,
  requireText,
  validateClosedSet,
} from "./diagnostics";
import { validateNameOrPattern, validateVersionPin } from "./package";
import { validatePath } from "./scope";

import type { DetectedSignal } from "../../normalize/normalize";

/**
 * Why a recorded license expression is preferred over what detection reports.
 *
 * - `contradictory-claims-recorded`: the sources disagree irreconcilably and the recorded
 *   expression is the reading the maintainer stands behind. The sanctioned fallback.
 * - `declared-more-complete`: the package's own metadata names licenses the scan cannot see.
 * - `dual-license-choice`: the package offers a choice of licenses that the intensive scan read as
 *   one joined license, and the expression restores the choice it offers - not the branch taken.
 * - `license-not-found`: no source states a license; the expression comes from evidence outside
 *   detection.
 * - `scan-found-additional-content`: the intensive scan sees further licenses that do govern
 *   content the package ships.
 * - `scan-more-precise`: the intensive scan resolves an under-specified declared label to the exact
 *   license.
 * - `scan-overdetection`: the intensive scan reports licenses from files that do not govern the
 *   package.
 */
export const JUSTIFICATION_VALUES = [
  "contradictory-claims-recorded",
  "declared-more-complete",
  "dual-license-choice",
  "license-not-found",
  "scan-found-additional-content",
  "scan-more-precise",
  "scan-overdetection",
] as const;

/** The reason an entry gives for its recorded license expression. */
export type Justification = (typeof JUSTIFICATION_VALUES)[number];

/**
 * Where a clarify entry was written, which is the id space every citation of it is spelled in:
 * `clarify[i]` for the policy's own entries, `clarifications[j]` for those imported from the
 * separate file. An imported entry is numbered within THAT file, so a reader given a citation knows
 * both which file to open and which table in it.
 */
export interface ClarifyIdentity {
  space: "clarify" | "clarifications";
  index: number;
}

/** The citation every surface spells for one entry. */
export function clarifyCitation(rule: ClarifyRule): string {
  return `${rule.identity.space}[${rule.identity.index}]`;
}

/** The rule id of a fail on an entry whose stated justification the signal disproved. */
export function clarifyInvalidRuleId(rule: ClarifyRule): string {
  return `${rule.identity.space}:invalid[${rule.identity.index}]`;
}

export interface ClarifyRule {
  /** Which file wrote this entry, and its position there - see {@link clarifyCitation}. */
  identity: ClarifyIdentity;
  /** Exact display name; exactly one of `name` and `pattern` is present. */
  name?: string;
  /** Display-name pattern, in the dialect of {@link compileNamePattern}. */
  pattern?: string;
  /** The exact version, or exact versions, covered - required on every clarify entry. */
  version?: string | ReadonlyArray<string>;
  /**
   * The staleness precondition: what each producing lane reported when the entry was written. The
   * engine applies the `expression` only while every recorded lane still reports what is written
   * here - a divergence is a STALE entry that fails the gate loudly, so a relicense can never be
   * silently masked.
   */
  detected: DetectedSignal;
  /** Why the recorded expression is preferred over what detection reports. */
  justification: Justification;
  /** A valid SPDX expression - parsed eagerly here. */
  expression: string;
  /** Files or URLs a reader can check; recorded verbatim, never fetched or verified. */
  evidence?: ReadonlyArray<string>;
  /** Free prose, for what the justification alone cannot carry. */
  comment?: string;
}

/**
 * The optional top-level `clarifications` key: where the imported `[[clarify]]` entries live.
 * Validated exactly like `cache.dir` - repo-root-relative, forward slashes, no ".." segments - so a
 * policy can never point the loader outside the scanned repository. Absent yields undefined; a
 * malformed value yields undefined after recording the problem.
 */
export function validateClarificationsPath(
  root: Record<string, unknown>,
  problems: string[],
): string | undefined {
  if (!("clarifications" in root)) {
    return undefined;
  }

  const value = stringOf(root["clarifications"]);

  if (value === undefined || value.trim() === "") {
    problems.push("clarifications: must be a non-empty path string");
    return undefined;
  }

  const before = problems.length;

  validatePath(value, "clarifications", problems);
  return problems.length === before ? value : undefined;
}

/** The lanes `detected` may record, in the order the documented table and the checks use. */
const DETECTED_SOURCES = ["registry", "intensive"] as const;

/** One producing lane a `detected` table may record. */
type DetectedSource = (typeof DETECTED_SOURCES)[number];

/** The parsed `detected` table - see {@link validateDetected}. */
interface DetectedFields {
  detected?: DetectedSignal;
  valid: boolean;
}

/**
 * The mandatory `detected` table: what each producing lane reported when the entry was written. At
 * least one lane must be recorded. A lane's value is the raw value that lane produces, which is
 * often not SPDX - a registry classifier like "BSD" or "Dual License" is exactly what an entry
 * exists to disambiguate - or `false`, which records that the lane reports nothing at all.
 */
function validateDetected(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): DetectedFields {
  if (!("detected" in entry)) {
    problems.push(
      `${where}: missing required key "detected" (an inline table of ${DETECTED_SOURCES.join(" and ")} detections)`,
    );
    return { valid: false };
  }

  const table = recordOf(entry["detected"]);

  if (table === undefined) {
    problems.push(
      `${where}: key "detected" must be an inline table { registry = ..., intensive = ... }`,
    );
    return { valid: false };
  }

  const before = problems.length;

  checkKeys(table, DETECTED_SOURCES, `${where}: detected`, problems);

  const detected: DetectedSignal = {};

  for (const source of DETECTED_SOURCES) {
    if (!(source in table)) {
      continue;
    }

    const value = table[source];

    if (value === false) {
      detected[source] = false;
      continue;
    }

    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(
        `${where}: detected.${source} must be that source's detected value as a non-empty string, or false when it detects nothing`,
      );
      continue;
    }

    detected[source] = text;
  }

  if (problems.length === before && Object.keys(detected).length === 0) {
    problems.push(
      `${where}: key "detected" must record at least one of ${DETECTED_SOURCES.join(", ")}`,
    );
  }

  return problems.length === before ? { detected, valid: true } : { valid: false };
}

/** The parsed `evidence` list - see {@link validateEvidence}. */
interface EvidenceFields {
  evidence?: ReadonlyArray<string>;
  valid: boolean;
}

/**
 * The optional `evidence` list: files or URLs a reader can check for themselves. Recorded verbatim
 * and never fetched or verified, so the only rules are that the list is non-empty and every element
 * carries text.
 */
function validateEvidence(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): EvidenceFields {
  if (!("evidence" in entry)) {
    return { valid: true };
  }

  const raw = entry["evidence"];

  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(`${where}: key "evidence" must be a non-empty array of file paths or URLs`);
    return { valid: false };
  }

  const evidence: string[] = [];
  const before = problems.length;

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(`${where}: evidence[${index}] must be a non-empty string`);
      return;
    }

    evidence.push(text);
  });
  return problems.length === before ? { evidence, valid: true } : { valid: false };
}

/**
 * The lanes each justification makes a claim ABOUT. None of them may be recorded as `false`, which
 * says that source reported nothing - the opposite of a claim about what it reported. A lane left
 * out is not constrained: `detected` records what was checked, and an entry that never mentions a
 * lane asserts nothing about it either way. `dual-license-choice` and `license-not-found` speak for
 * no lane - each is about the licence text rather than about one source - and `license-not-found`
 * carries its own rule below.
 */
const JUSTIFICATION_LANES: Readonly<Record<Justification, ReadonlyArray<DetectedSource>>> = {
  "contradictory-claims-recorded": ["registry", "intensive"],
  "declared-more-complete": ["registry"],
  "dual-license-choice": [],
  "license-not-found": [],
  "scan-found-additional-content": ["intensive"],
  "scan-more-precise": ["intensive"],
  "scan-overdetection": ["intensive"],
};

/**
 * The stated justification against the entry's own `detected`.
 *
 * An entry claiming the two sources disagree while recording one of them as silent contradicts
 * itself, and the invalidity lane can never say so: it runs only while `detected` still holds, and
 * a lane recorded as silent holds by staying silent. The check belongs here, where the entry is
 * read, and the error names the lane to record.
 */
function validateJustificationDetection(
  justification: Justification,
  detected: DetectedSignal,
  where: string,
  problems: string[],
): void {
  for (const source of JUSTIFICATION_LANES[justification]) {
    if (detected[source] === false) {
      problems.push(
        `${where}: justification "${justification}" is a claim about what the ${source} source reported, but detected.${source} records that it reports nothing. Record what it reported, or choose the justification that fits.`,
      );
    }
  }

  if (justification !== "license-not-found") {
    return;
  }

  for (const source of DETECTED_SOURCES) {
    const value = detected[source];
    const stated = typeof value === "string" ? statedLicense(value) : null;

    if (stated !== null) {
      problems.push(
        `${where}: justification "license-not-found" says no source states a licence, but detected.${source} records "${value}", which states ${stated}. Record the reason the stated licence is wrong instead, or choose the justification that fits.`,
      );
    }
  }
}

const CLARIFY_KEYS = [
  "name",
  "pattern",
  "version",
  "detected",
  "justification",
  "expression",
  "evidence",
  "comment",
] as const;

/** Keys an earlier [[clarify]] schema used, each naming what replaced it. */
const CLARIFY_REPLACED_KEYS: ReadonlyMap<string, string> = new Map([
  [
    "package",
    'the "package" inline table was flattened - write "name" (or "pattern") and "version" directly on the entry',
  ],
  ["expects", 'key "expects" was replaced by detected = { registry = ..., intensive = ... }'],
  [
    "reason",
    'key "reason" was replaced by "justification" (a closed set) plus an optional "comment"',
  ],
]);

/** One [[clarify]] entry -> rule, or undefined when any field is invalid. */
function validateClarifyEntry(
  entry: Record<string, unknown>,
  where: string,
  identity: ClarifyIdentity,
  problems: string[],
): ClarifyRule | undefined {
  const before = problems.length;

  checkKeys(entry, CLARIFY_KEYS, where, problems, CLARIFY_REPLACED_KEYS);

  const selector = validateNameOrPattern(entry, where, problems);
  const pin = validateVersionPin(entry, where, problems, {
    required: true,
    osScopeExemptible: false,
  });
  const detection = validateDetected(entry, where, problems);
  const justification = validateClosedSet(
    entry,
    "justification",
    JUSTIFICATION_VALUES,
    where,
    problems,
  );
  const expression = requireText(entry, "expression", where, problems);

  if (expression !== undefined) {
    parseSpdxChecked(expression, `${where}: expression`, problems);
  }

  const evidence = validateEvidence(entry, where, problems);
  const comment = optionalText(entry, "comment", where, problems);

  if (justification !== undefined && detection.detected !== undefined) {
    validateJustificationDetection(justification, detection.detected, where, problems);
  }

  if (
    problems.length !== before ||
    expression === undefined ||
    justification === undefined ||
    detection.detected === undefined
  ) {
    return undefined;
  }

  return {
    identity,
    ...(selector.name !== undefined ? { name: selector.name } : {}),
    ...(selector.pattern !== undefined ? { pattern: selector.pattern } : {}),
    ...(pin.version !== undefined ? { version: pin.version } : {}),
    detected: detection.detected,
    justification,
    expression,
    ...(evidence.evidence !== undefined ? { evidence: evidence.evidence } : {}),
    ...(comment !== undefined ? { comment } : {}),
  };
}

/**
 * The `[[clarify]]` array of ONE file, validated into entries citable in `space`. Shared by the
 * policy proper and the separate clarifications file so both mean exactly the same thing by an
 * entry; problem paths name the TOML position (`clarify[i]`) and the imported file's reader
 * prefixes them with its own path.
 */
export function validateClarifyTables(
  raw: unknown,
  space: ClarifyIdentity["space"],
  problems: string[],
): ClarifyRule[] {
  const clarify: ClarifyRule[] = [];

  if (raw === undefined) {
    return clarify;
  }

  if (!Array.isArray(raw)) {
    problems.push("clarify: must be an array of tables ([[clarify]])");
    return clarify;
  }

  raw.forEach((rawEntry, index) => {
    const where = `clarify[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const rule = validateClarifyEntry(entry, where, { space, index }, problems);

    if (rule !== undefined) {
      clarify.push(rule);
    }
  });
  return clarify;
}
