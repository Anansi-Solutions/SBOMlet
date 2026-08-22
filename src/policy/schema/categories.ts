import { recordOf, stringOf } from "../../validate/record";

import { checkKeys } from "./diagnostics";

/**
 * How a would-be default-FAIL verdict is treated on a DEV-only occurrence. Per-occurrence, never
 * package-level - a package that is dev in one workspace and prod in another still FAILS on the
 * prod occurrence.
 *   "warn"   - a dev would-be-fail downgrades to warn (the default).
 *   "fail"   - NO downgrade; dev gates exactly like prod (strict).
 *   "ignore" - a dev would-be-fail becomes ok (an EXPLICIT, documented opt-out).
 * A PRODUCTION occurrence ALWAYS fails under "warn"/"ignore" - a shipped copyleft can never be
 * dev-downgraded.
 */
export type DevDependencyHandling = "warn" | "fail" | "ignore";

/**
 * The [os_dependencies] knob, mirroring DevDependencyHandling. It governs a would-be-FAIL on a
 * PACKAGE-level os-scope dependency (a pkg:deb / pkg:apk row from the Docker base image):
 *   "warn"   - an os would-be-fail downgrades to warn (the default): expected
 *              base-image copyleft (glibc/bash GPL/LGPL, satisfied by shipping the image) LISTS,
 *              not fails.
 *   "fail"   - NO downgrade; an os-scope copyleft gates exactly like an app one.
 *   "ignore" - an os would-be-fail becomes ok (an EXPLICIT, documented opt-out).
 * A DENIED (source-available) license in an OS package STILL FAILS regardless - deny is terminal-0
 * above the os downgrade.
 */
export type OsDependencyHandling = "warn" | "fail" | "ignore";

export function validateUnknown(
  root: Record<string, unknown>,
  problems: string[],
): "warn" | "fail" {
  const raw = root["unknown"];

  if (raw === undefined) {
    return "warn";
  } // absent table defaults to warn

  const table = recordOf(raw);

  if (table === undefined) {
    problems.push("unknown: must be a table ([unknown])");
    return "warn";
  }

  checkKeys(table, ["handling"], "unknown", problems);
  if (!("handling" in table)) {
    problems.push('unknown: missing required key "handling"');
    return "warn";
  }

  const handling = stringOf(table["handling"]);

  if (handling === "warn" || handling === "fail") {
    return handling;
  }

  problems.push('unknown.handling: must be "warn" or "fail"');
  return "warn";
}

/**
 * Parse the [dev_dependencies] knob, mirroring validateUnknown EXACTLY: an absent table defaults to
 * "warn"; a non-table, missing handling, unknown key, or invalid handling value each push the
 * existing aggregated PolicyError message naming the table path. The three valid values are
 * warn|fail|ignore.
 */
export function validateDevDependencies(
  root: Record<string, unknown>,
  problems: string[],
): DevDependencyHandling {
  const raw = root["dev_dependencies"];

  if (raw === undefined) {
    return "warn";
  } // absent table defaults to warn

  const table = recordOf(raw);

  if (table === undefined) {
    problems.push("dev_dependencies: must be a table ([dev_dependencies])");
    return "warn";
  }

  checkKeys(table, ["handling"], "dev_dependencies", problems);
  if (!("handling" in table)) {
    problems.push('dev_dependencies: missing required key "handling"');
    return "warn";
  }

  const handling = stringOf(table["handling"]);

  if (handling === "warn" || handling === "fail" || handling === "ignore") {
    return handling;
  }

  problems.push('dev_dependencies.handling: must be "warn", "fail", or "ignore"');
  return "warn";
}

/**
 * Parse the [os_dependencies] knob, an EXACT mirror of validateDevDependencies: an absent table
 * defaults to "warn"; a non-table, missing handling, unknown key, or invalid handling value each
 * push the aggregated PolicyError message naming the os_dependencies table path. The three valid
 * values are warn|fail|ignore.
 */
export function validateOsDependencies(
  root: Record<string, unknown>,
  problems: string[],
): OsDependencyHandling {
  const raw = root["os_dependencies"];

  if (raw === undefined) {
    return "warn";
  } // absent table defaults to warn

  const table = recordOf(raw);

  if (table === undefined) {
    problems.push("os_dependencies: must be a table ([os_dependencies])");
    return "warn";
  }

  checkKeys(table, ["handling"], "os_dependencies", problems);
  if (!("handling" in table)) {
    problems.push('os_dependencies: missing required key "handling"');
    return "warn";
  }

  const handling = stringOf(table["handling"]);

  if (handling === "warn" || handling === "fail" || handling === "ignore") {
    return handling;
  }

  problems.push('os_dependencies.handling: must be "warn", "fail", or "ignore"');
  return "warn";
}
