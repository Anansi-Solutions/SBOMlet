import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems, formatProblems, type DomainProblem } from "./arkAdapter";
import { SOURCE_AVAILABLE_LICENSE_IDS } from "./deny";
import { checkKeys } from "./diagnostics";
import { nonEmptyString } from "./scalars";
import { pathProblems } from "./scope";
import { parseSpdxNode } from "./spdx";

export interface SuppressedWorkspace {
  /** Repo-relative target-identity prefix, e.g. "apps/studio". */
  path: string;
  /**
   * SPDX ID the workspace itself is distributed under. Validated to be a single license id (leaf,
   * optionally WITH/+) - never a compound expression: this field is verdict-affecting (the
   * family-aware suppression check compares it to the finding's copyleft obligations).
   */
  license: string;
  /** Mandatory documentation: why suppression is justified. */
  description: string;
}

/** The three required fields of a `[[workspace.copyleft_suppressed]]` entry. */
const suppressionEnvelope = type({
  path: nonEmptyString,
  license: nonEmptyString,
  description: nonEmptyString,
});

/**
 * A suppression path's faults: the shared segment rules, plus the suppression-only fence against a
 * "docker:" prefix (a container image is not a workspace; a container's copyleft is accepted with a
 * scoped [[compatible]] rule instead).
 */
function suppressionPathProblems(path: string): DomainProblem[] {
  const problems: DomainProblem[] = pathProblems(path).map((message) => ({ message }));

  if (path.startsWith("docker:")) {
    problems.push({
      message: `path "${path}" must not start with "docker:" (a container image is not a workspace; accept a container's copyleft package with a scoped [[compatible]] rule instead)`,
    });
  }

  return problems;
}

/**
 * A suppression license's fault: it must be a single SPDX license id (a leaf, optionally WITH/+),
 * never a compound expression, since a compound has no single family/identity to verify the
 * suppression against.
 */
function suppressionLicenseProblems(license: string): DomainProblem[] {
  const node = parseSpdxNode(license);

  if (node === undefined) {
    return [{ message: `license "${license}" is not a valid SPDX expression` }];
  }

  if (!("license" in node)) {
    return [
      {
        message: `license "${license}" must be a single SPDX license ID (the workspace's own distribution license), not a compound expression`,
      },
    ];
  }

  return [];
}

export function validateSuppressions(
  root: Record<string, unknown>,
  problems: string[],
): SuppressedWorkspace[] {
  const suppressed: SuppressedWorkspace[] = [];

  if (!("workspace" in root)) {
    return suppressed;
  }

  const workspace = recordOf(root["workspace"]);

  if (workspace === undefined) {
    problems.push(
      "workspace: must be a table containing [[workspace.copyleft_suppressed]] entries",
    );
    return suppressed;
  }

  checkKeys(workspace, ["copyleft_suppressed"], "workspace", problems);
  const entries = workspace["copyleft_suppressed"];

  if (entries === undefined) {
    return suppressed;
  }

  if (!Array.isArray(entries)) {
    problems.push(
      "workspace.copyleft_suppressed: must be an array of tables ([[workspace.copyleft_suppressed]])",
    );
    return suppressed;
  }

  entries.forEach((raw, index) => {
    const where = `workspace.copyleft_suppressed[${index}]`;
    const entry = recordOf(raw);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const before = problems.length;

    checkKeys(entry, ["path", "license", "description"], where, problems);

    const envelope = suppressionEnvelope(entry);

    if (envelope instanceof type.errors) {
      problems.push(...collectArkProblems(envelope, where));
    } else {
      problems.push(...formatProblems(where, suppressionPathProblems(envelope.path)));
      problems.push(...formatProblems(where, suppressionLicenseProblems(envelope.license)));
    }

    if (!(envelope instanceof type.errors) && problems.length === before) {
      suppressed.push({
        path: envelope.path,
        license: envelope.license,
        description: envelope.description,
      });
    }
  });
  return suppressed;
}

/**
 * One [[allow_source_available]] exemption (ADR-0013): a built-in source-available licence the
 * consumer has explicitly, auditably accepted, so it surfaces as a warn instead of failing the gate
 * by default.
 */
export interface AllowSourceAvailable {
  /** A built-in source-available SPDX id (BUSL-1.1, SSPL-1.0, Elastic-2.0). */
  license: string;
  /** Mandatory documentation: why this source-available licence is accepted. */
  reason: string;
}

/** The two required fields of an `[[allow_source_available]]` entry. */
const exemptionEnvelope = type({ license: nonEmptyString, reason: nonEmptyString });

/**
 * Parse [[allow_source_available]] (ADR-0013 opt-out): each entry exempts ONE built-in
 * source-available licence from the shipped deny default. `license` must be one of the shipped
 * patterns (a consumer's own [[deny]] is absolute and not exempted here); `reason` is mandatory
 * documentation. An absent table yields [].
 */
export function validateAllowSourceAvailable(
  root: Record<string, unknown>,
  problems: string[],
): AllowSourceAvailable[] {
  const exemptions: AllowSourceAvailable[] = [];
  const raw = root["allow_source_available"];

  if (raw === undefined) {
    return exemptions;
  }

  if (!Array.isArray(raw)) {
    problems.push(
      "allow_source_available: must be an array of tables ([[allow_source_available]])",
    );
    return exemptions;
  }

  raw.forEach((rawEntry, index) => {
    const where = `allow_source_available[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    checkKeys(entry, ["license", "reason"], where, problems);

    const envelope = exemptionEnvelope(entry);

    if (envelope instanceof type.errors) {
      problems.push(...collectArkProblems(envelope, where));
      return;
    }

    if (!SOURCE_AVAILABLE_LICENSE_IDS.includes(envelope.license as never)) {
      problems.push(
        `${where}: license "${envelope.license}" is not a built-in source-available default — only ${SOURCE_AVAILABLE_LICENSE_IDS.join(", ")} can be exempted (a consumer's own [[deny]] is absolute and not exempted here)`,
      );
      return;
    }

    exemptions.push({ license: envelope.license, reason: envelope.reason });
  });
  return exemptions;
}
