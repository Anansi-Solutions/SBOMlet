import { type } from "arktype";

import { recordOf, stringOf } from "../../validate/record";
import { OSADL_MATRIX, type TargetLicense, type TargetProfile } from "../compat";

import { collectArkProblems } from "./arkAdapter";
import { checkKeys, requireText } from "./diagnostics";
import { validatePath } from "./scope";
import { parseSpdxNode } from "./spdx";

export interface TargetWorkspaceEntry {
  /** Repo-relative target-identity prefix this override governs, e.g. "apps/studio". */
  path: string;
  /** This workspace's own declared target license - overrides the project license when present. */
  license: TargetLicense;
  /** Mandatory documentation: why this workspace diverges from the project profile. */
  reason: string;
  /** Overrides the project profile's network flag; inherited when absent. */
  network?: boolean;
  /** Overrides the project profile's distribution; inherited when absent. */
  distribution?: "external" | "internal";
}

/**
 * The parsed [target] table: the declared usage profile that activates the compatibility lane
 * (policy/target.ts resolves it per occurrence; policy/evaluate.ts wires the lane). Absent
 * `profile` with a non-empty `workspaces` is the workspaces-only shape (every entry then
 * self-complete, per {@link TargetWorkspaceEntry}'s doc) - schema.ts's validator rejects the table
 * entirely when it would resolve to neither (a dead activation switch).
 */
export interface TargetConfig {
  /** The complete project-level usage profile; undefined for a workspaces-only [target] table. */
  profile?: TargetProfile;
  /** Default "warn" - the D4 residual knob for a matrix-uncovered pair under the target lane. */
  unknownPair: "warn" | "fail";
  /** Per-workspace overrides; resolution takes the most-specific covering path. */
  workspaces: ReadonlyArray<TargetWorkspaceEntry>;
}

/** The [target] table's own top-level keys, and one [[target.workspace]] entry's keys. */
const TARGET_KEYS = ["license", "network", "distribution", "unknown_pair", "workspace"] as const;
const TARGET_WORKSPACE_KEYS = ["path", "license", "reason", "network", "distribution"] as const;

/**
 * A target license value: the literal "proprietary" keyword, or a single FOSS SPDX id covered by
 * the OSADL compatibility matrix's own row keys (a compound expression, or a LicenseRef-/
 * DocumentRef- reference, is rejected loudly naming the table path: neither can anchor a
 * compatibility matrix row). Coverage is required, not just SPDX validity: an OSS target id absent
 * from the matrix's 119 rows would make classifyLeaf's tier 1 - the only tier that may ever decide
 * "incompatible" for an OSS target - unreachable, silently degrading every genuinely-incompatible
 * dependency to the residual target:unknown-pair warn instead of a fail. `proprietary` is exempt
 * - tiers 2 and 3 already serve it a real incompatible verdict without needing a matrix row.
 */
function validateTargetLicense(
  raw: unknown,
  where: string,
  problems: string[],
): TargetLicense | undefined {
  const value = stringOf(raw);

  if (value === undefined) {
    problems.push(`${where}: key "license" must be a string`);
    return undefined;
  }

  if (value === "proprietary") {
    return { kind: "proprietary" };
  }

  const node = parseSpdxNode(value);

  if (node === undefined) {
    problems.push(`${where}: license "${value}" is not a valid SPDX expression`);
    return undefined;
  }

  if (!("license" in node)) {
    problems.push(
      `${where}: license "${value}" must be a single SPDX license id or the literal "proprietary", not a compound expression (dual-licensed targets are not supported in v1)`,
    );
    return undefined;
  }

  if (node.license.startsWith("LicenseRef-") || node.license.startsWith("DocumentRef-")) {
    problems.push(
      `${where}: license "${value}" must be a real SPDX license id or the literal "proprietary" - a LicenseRef-/DocumentRef- reference cannot anchor a compatibility target`,
    );
    return undefined;
  }

  if (!OSADL_MATRIX.has(node.license)) {
    problems.push(
      `${where}: license "${value}" is not covered by the compatibility matrix as a TARGET - the vetted OSADL data has no row for it, so the target lane could never classify a dependency against it; choose a target id the matrix covers, or govern the affected packages with per-package [[compatible]] rules instead`,
    );
    return undefined;
  }

  return { kind: "oss", id: node.license };
}

/**
 * The project-level [target] profile, all-or-nothing: zero of license/network/distribution present
 * yields undefined (the workspaces-only shape, or the caller's dead-activation rejection when there
 * are no workspaces either); one or two present is a loud rejection naming every missing key
 * ("declaring a target requires the full usage profile" - no partial defaults, forcing the
 * conscious choice); all three present parses each field.
 */
function validateTargetProjectProfile(
  table: Record<string, unknown>,
  where: string,
  problems: string[],
): TargetProfile | undefined {
  const profileKeys = ["license", "network", "distribution"] as const;
  const present = profileKeys.filter((key) => key in table);

  if (present.length === 0) {
    return undefined;
  }

  if (present.length < profileKeys.length) {
    const missing = profileKeys.filter((key) => !present.includes(key));

    problems.push(
      `${where}: declaring a target requires the full usage profile - missing ${missing.map((key) => `"${key}"`).join(", ")}`,
    );
    return undefined;
  }

  const license = validateTargetLicense(table["license"], where, problems);
  const flags = profileFlags({ network: table["network"], distribution: table["distribution"] });

  if (flags instanceof type.errors) {
    problems.push(...collectArkProblems(flags, where));
  }

  if (license === undefined || flags instanceof type.errors) {
    return undefined;
  }

  return { license, network: flags.network, distribution: flags.distribution };
}

/** The two non-license usage-profile flags, once the all-or-nothing gate has confirmed presence. */
const profileFlags = type({ network: "boolean", distribution: "'external' | 'internal'" });

/** [target] unknown_pair: the D4 residual knob, mirroring [unknown].handling. Absent -> "warn". */
function validateTargetUnknownPair(
  table: Record<string, unknown>,
  where: string,
  problems: string[],
): "warn" | "fail" {
  if (!("unknown_pair" in table)) {
    return "warn";
  }

  const value = stringOf(table["unknown_pair"]);

  if (value === "warn" || value === "fail") {
    return value;
  }

  problems.push(`${where}: key "unknown_pair" must be "warn" or "fail"`);
  return "warn";
}

/**
 * One [[target.workspace]] entry: `path`/`license`/`reason` mandatory; `network`/`distribution`
 * optional and inherited from a complete project profile - but MANDATORY here too when no complete
 * project profile is declared (nothing to inherit from). `path` reuses validatePath, rejects a
 * "docker:" prefix (a container is never governed by a workspace override - the project profile
 * alone governs docker occurrences), and rejects a duplicate against `seen` (the first match would
 * always win at resolution time, making a repeat dead).
 */
/**
 * network/distribution parse result for one [[target.workspace]] entry - see {@link
 * validateTargetWorkspaceFlagsOf}.
 */
interface TargetWorkspaceFlags {
  network?: boolean;
  distribution?: "external" | "internal";
  /** True when the key was PRESENT but malformed - distinct from simply absent (inheritable). */
  networkTypeError: boolean;
  distributionTypeError: boolean;
}

/**
 * The two optional per-field overrides of one [[target.workspace]] entry: absent is inheritable
 * (the project profile's own value), present-and-malformed is a type-error problem naming `where`.
 */
function validateTargetWorkspaceFlagsOf(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): TargetWorkspaceFlags {
  let network: boolean | undefined;
  let networkTypeError = false;

  if ("network" in entry) {
    if (typeof entry["network"] !== "boolean") {
      problems.push(`${where}: key "network" must be a boolean`);
      networkTypeError = true;
    } else {
      network = entry["network"];
    }
  }

  let distribution: "external" | "internal" | undefined;
  let distributionTypeError = false;

  if ("distribution" in entry) {
    const value = stringOf(entry["distribution"]);

    if (value === "external" || value === "internal") {
      distribution = value;
    } else {
      problems.push(`${where}: key "distribution" must be "external" or "internal"`);
      distributionTypeError = true;
    }
  }

  return { network, distribution, networkTypeError, distributionTypeError };
}

/**
 * `path`'s three rejection rules for one [[target.workspace]] entry: validatePath's shared segment
 * rules, a "docker:" prefix (a container is never governed by a workspace override), and a
 * duplicate against `seen` (the first match always wins at resolution, so a repeat would be dead).
 * No-op when `path` is undefined (an earlier problem already covers a missing/malformed path).
 */
function validateTargetWorkspacePathOf(
  path: string | undefined,
  where: string,
  seen: Set<string>,
  problems: string[],
): void {
  if (path === undefined) {
    return;
  }

  validatePath(path, where, problems);
  if (path.startsWith("docker:")) {
    problems.push(
      `${where}: path "${path}" must not start with "docker:" (a container image is never governed by a [[target.workspace]] override; the project profile alone governs docker occurrences)`,
    );
  }

  if (seen.has(path)) {
    problems.push(
      `${where}: path "${path}" duplicates an earlier [[target.workspace]] entry (the first match wins at resolution; the duplicate would be dead)`,
    );
  }
}

function validateTargetWorkspaceEntry(
  rawEntry: unknown,
  where: string,
  seen: Set<string>,
  hasProjectProfile: boolean,
  problems: string[],
): TargetWorkspaceEntry | undefined {
  const entry = recordOf(rawEntry);

  if (entry === undefined) {
    problems.push(`${where}: must be a table`);
    return undefined;
  }

  const before = problems.length;

  checkKeys(entry, [...TARGET_WORKSPACE_KEYS], where, problems);

  let license: TargetLicense | undefined;

  if (!("license" in entry)) {
    problems.push(`${where}: missing required key "license"`);
  } else {
    license = validateTargetLicense(entry["license"], where, problems);
  }

  const path = requireText(entry, "path", where, problems);
  const reason = requireText(entry, "reason", where, problems);
  const flags = validateTargetWorkspaceFlagsOf(entry, where, problems);

  validateTargetWorkspacePathOf(path, where, seen, problems);

  if (
    !hasProjectProfile &&
    !flags.networkTypeError &&
    !flags.distributionTypeError &&
    (flags.network === undefined || flags.distribution === undefined)
  ) {
    problems.push(
      `${where}: no complete project [target] profile is declared, so this entry must carry its own "network" and "distribution" (nothing to inherit from)`,
    );
  }

  if (
    problems.length !== before ||
    path === undefined ||
    license === undefined ||
    reason === undefined
  ) {
    return undefined;
  }

  seen.add(path);
  return {
    path,
    license,
    reason,
    ...(flags.network !== undefined ? { network: flags.network } : {}),
    ...(flags.distribution !== undefined ? { distribution: flags.distribution } : {}),
  };
}

/**
 * Parse the optional [target] table: absent -> undefined (today's walk, byte-identical). A present
 * table validates its project-level profile fields (all-or-nothing), its `unknown_pair` knob, and
 * every [[target.workspace]] override; a table resolving to neither a project profile nor any
 * workspace override is a dead activation switch and is rejected.
 */
export function validateTarget(
  root: Record<string, unknown>,
  problems: string[],
): TargetConfig | undefined {
  if (!("target" in root)) {
    return undefined;
  }

  const table = recordOf(root["target"]);

  if (table === undefined) {
    problems.push("target: must be a table ([target])");
    return undefined;
  }

  checkKeys(table, [...TARGET_KEYS], "target", problems);

  const profile = validateTargetProjectProfile(table, "target", problems);
  const unknownPair = validateTargetUnknownPair(table, "target", problems);

  const workspaces: TargetWorkspaceEntry[] = [];

  if ("workspace" in table) {
    const raw = table["workspace"];

    if (!Array.isArray(raw)) {
      problems.push("target.workspace: must be an array of tables ([[target.workspace]])");
    } else {
      const seen = new Set<string>();

      raw.forEach((rawEntry, index) => {
        const entry = validateTargetWorkspaceEntry(
          rawEntry,
          `target.workspace[${index}]`,
          seen,
          profile !== undefined,
          problems,
        );

        if (entry !== undefined) {
          workspaces.push(entry);
        }
      });
    }
  }

  const profileAttempted = ["license", "network", "distribution"].some((key) => key in table);

  if (profile === undefined && !profileAttempted && workspaces.length === 0) {
    problems.push(
      "target: an empty [target] table declares nothing to govern - add a complete usage profile (license/network/distribution) or at least one [[target.workspace]] entry",
    );
    return undefined;
  }

  return { ...(profile !== undefined ? { profile } : {}), unknownPair, workspaces };
}
