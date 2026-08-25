import { type } from "arktype";

import { asRawLicense, type CanonicalLicense } from "../../model/dependencies";
import { recordOf } from "../../validate/record";
import { statedLicense } from "../statedLicense";

import {
  collectArkProblems,
  formatProblems,
  nonBlankString,
  toDomainProblems,
  type DomainProblem,
} from "./arkAdapter";
import { checkKeys, unknownKeyProblems } from "./diagnostics";
import { nameOrPatternProblems, versionPinProblems } from "./package";
import { repoRelativePath } from "./scope";
import { spdxExpression } from "./spdx";

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
  /** A valid SPDX expression, canonicalized at validation - see {@link spdxExpression}. */
  expression: CanonicalLicense;
  /** Files or URLs a reader can check; recorded verbatim, never fetched or verified. */
  evidence?: ReadonlyArray<string>;
  /** Free prose, for what the justification alone cannot carry. */
  comment?: string;
}

/**
 * The optional top-level `clarifications` key: where the imported `[[clarify]]` entries live. A
 * non-empty repo-root-relative forward-slash path (no "..", no leading/trailing slash), so a policy
 * can never point the loader outside the scanned repository - the same posture as `cache.dir`. A
 * non-string reads as a string fault and an empty value as a non-empty-string fault; the segment
 * rules ride the shared {@link repoRelativePath} morph.
 */
const clarificationsPathType = nonBlankString.to(repoRelativePath);

export function validateClarificationsPath(
  root: Record<string, unknown>,
  problems: string[],
): string | undefined {
  if (!("clarifications" in root)) {
    return undefined;
  }

  const result = clarificationsPathType(root["clarifications"]);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, "clarifications"));
    return undefined;
  }

  return result;
}

/** The lanes `detected` may record, in the order the documented table and the checks use. */
const DETECTED_SOURCES = ["registry", "intensive"] as const;

/** One producing lane a `detected` table may record. */
type DetectedSource = (typeof DETECTED_SOURCES)[number];

/**
 * One lane's recorded detection: the raw value that lane produced as a non-empty string (trimmed)
 * - often not SPDX, since a registry label like "BSD" or "Dual License" is exactly what an entry
 * exists to disambiguate - or the literal `false`, which records that the lane reports nothing.
 */
const detectedValue = type("false").or(nonBlankString);

/**
 * The mandatory `detected` table: what each producing lane reported when the entry was written. At
 * least one lane must be recorded. A lane's value is the raw value that lane produces, which is
 * often not SPDX - a registry classifier like "BSD" or "Dual License" is exactly what an entry
 * exists to disambiguate - or `false`, which records that the lane reports nothing at all. Faults
 * are entry-relative for the caller to place under the entry.
 */
function detectedProblems(entry: Record<string, unknown>): {
  detected?: DetectedSignal;
  problems: DomainProblem[];
} {
  if (!("detected" in entry)) {
    return {
      problems: [
        {
          message: `missing required key "detected" (an inline table of ${DETECTED_SOURCES.join(" and ")} detections)`,
        },
      ],
    };
  }

  const table = recordOf(entry["detected"]);

  if (table === undefined) {
    return {
      problems: [
        { message: `key "detected" must be an inline table { registry = ..., intensive = ... }` },
      ],
    };
  }

  const problems: DomainProblem[] = unknownKeyProblems(table, DETECTED_SOURCES).map((problem) => ({
    message: `detected: ${problem.message}`,
  }));

  const detected: DetectedSignal = {};

  for (const source of DETECTED_SOURCES) {
    if (!(source in table)) {
      continue;
    }

    const value = detectedValue(table[source]);

    if (value instanceof type.errors) {
      problems.push({
        message: `detected.${source} must be that source's detected value as a non-empty string, or false when it detects nothing`,
      });
      continue;
    }

    detected[source] = value;
  }

  if (problems.length === 0 && Object.keys(detected).length === 0) {
    problems.push({
      message: `key "detected" must record at least one of ${DETECTED_SOURCES.join(", ")}`,
    });
  }

  return problems.length === 0 ? { detected, problems } : { problems };
}

/**
 * The optional `evidence` list: files or URLs a reader can check for themselves. Recorded verbatim
 * and never fetched or verified, so the only rules are that the list is non-empty and every element
 * carries text. Faults are entry-relative.
 */
const evidenceList = nonBlankString.array().atLeastLength(1);

function evidenceProblems(entry: Record<string, unknown>): {
  evidence?: ReadonlyArray<string>;
  problems: DomainProblem[];
} {
  if (!("evidence" in entry)) {
    return { problems: [] };
  }

  const result = evidenceList(entry["evidence"]);

  if (result instanceof type.errors) {
    return { problems: toDomainProblems(result, ["evidence"]) };
  }

  return { evidence: result, problems: [] };
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
 * The stated justification against the entry's own `detected` - the self-contained cross-field
 * residue, reported as one accumulated set of entry-relative faults.
 *
 * An entry claiming the two sources disagree while recording one of them as silent contradicts
 * itself, and the invalidity lane can never say so: it runs only while `detected` still holds, and
 * a lane recorded as silent holds by staying silent. The check belongs here, where the entry is
 * read, and the fault names the lane to record.
 */
function justificationDetectionProblems(
  justification: Justification,
  detected: DetectedSignal,
): DomainProblem[] {
  const problems: DomainProblem[] = [];

  for (const source of JUSTIFICATION_LANES[justification]) {
    if (detected[source] === false) {
      problems.push({
        message: `justification "${justification}" is a claim about what the ${source} source reported, but detected.${source} records that it reports nothing. Record what it reported, or choose the justification that fits.`,
      });
    }
  }

  if (justification !== "license-not-found") {
    return problems;
  }

  for (const source of DETECTED_SOURCES) {
    const value = detected[source];
    const stated = typeof value === "string" ? statedLicense(asRawLicense(value)) : null;

    if (stated !== null) {
      problems.push({
        message: `justification "license-not-found" says no source states a licence, but detected.${source} records "${value}", which states ${stated}. Record the reason the stated licence is wrong instead, or choose the justification that fits.`,
      });
    }
  }

  return problems;
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

/** The closed `justification` and the SPDX `expression`, plus the optional prose `comment`. */
const clarifyEnvelope = type({
  justification: type.enumerated(...JUSTIFICATION_VALUES),
  expression: spdxExpression,
  "comment?": nonBlankString,
});

/** One [[clarify]] entry -> rule, or undefined when any field is invalid. */
function validateClarifyEntry(
  entry: Record<string, unknown>,
  where: string,
  identity: ClarifyIdentity,
  problems: string[],
): ClarifyRule | undefined {
  const before = problems.length;

  checkKeys(entry, CLARIFY_KEYS, where, problems, CLARIFY_REPLACED_KEYS);

  const envelope = clarifyEnvelope(entry);

  if (envelope instanceof type.errors) {
    problems.push(...collectArkProblems(envelope, where));
  }

  const selector = nameOrPatternProblems(entry);

  problems.push(...formatProblems(where, selector.problems));

  const pin = versionPinProblems(entry, { required: true, osScopeExemptible: false });

  problems.push(...formatProblems(where, pin.problems));

  const detection = detectedProblems(entry);

  problems.push(...formatProblems(where, detection.problems));

  const evidence = evidenceProblems(entry);

  problems.push(...formatProblems(where, evidence.problems));

  if (!(envelope instanceof type.errors) && detection.detected !== undefined) {
    problems.push(
      ...formatProblems(
        where,
        justificationDetectionProblems(envelope.justification, detection.detected),
      ),
    );
  }

  if (
    envelope instanceof type.errors ||
    detection.detected === undefined ||
    problems.length !== before
  ) {
    return undefined;
  }

  return {
    identity,
    ...selector.selector,
    ...(pin.version !== undefined ? { version: pin.version } : {}),
    detected: detection.detected,
    justification: envelope.justification,
    expression: envelope.expression,
    ...(evidence.evidence !== undefined ? { evidence: evidence.evidence } : {}),
    ...(envelope.comment !== undefined ? { comment: envelope.comment } : {}),
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
