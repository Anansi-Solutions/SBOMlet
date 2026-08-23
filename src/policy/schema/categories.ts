import { type } from "arktype";

import { recordOf } from "../../validate/record";

import { collectArkProblems } from "./arkAdapter";
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

/**
 * Parse a `[<table>]` knob whose sole key is `handling`, one of `values`. An absent table defaults
 * to "warn"; a non-table, an unknown key, a missing `handling`, or a value outside `values` each
 * push the aggregated PolicyError message naming the table path. Shared by [unknown] (warn|fail)
 * and the [dev_dependencies]/[os_dependencies] knobs (warn|fail|ignore).
 */
function handling<T extends string>(
  root: Record<string, unknown>,
  key: string,
  values: ReadonlyArray<T>,
  problems: string[],
): "warn" | T {
  const raw = root[key];

  if (raw === undefined) {
    return "warn";
  }

  const table = recordOf(raw);

  if (table === undefined) {
    problems.push(`${key}: must be a table ([${key}])`);
    return "warn";
  }

  checkKeys(table, ["handling"], key, problems);

  const result = type({ handling: type.enumerated(...values) })(table);

  if (result instanceof type.errors) {
    problems.push(...collectArkProblems(result, key));
    return "warn";
  }

  return (result as { handling: T }).handling;
}

export function validateUnknown(
  root: Record<string, unknown>,
  problems: string[],
): "warn" | "fail" {
  return handling(root, "unknown", ["warn", "fail"] as const, problems);
}

export function validateDevDependencies(
  root: Record<string, unknown>,
  problems: string[],
): DevDependencyHandling {
  return handling(root, "dev_dependencies", ["warn", "fail", "ignore"] as const, problems);
}

export function validateOsDependencies(
  root: Record<string, unknown>,
  problems: string[],
): OsDependencyHandling {
  return handling(root, "os_dependencies", ["warn", "fail", "ignore"] as const, problems);
}
