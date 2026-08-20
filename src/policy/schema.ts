/**
 * TOML policy text → validated Policy.
 *
 * Validation rejects - never skips - with every semantic problem collected into one PolicyError,
 * each problem naming its table path and key (the opposite tolerance posture from merge.ts, which
 * skips malformed SBOM entries). TOML syntax errors propagate smol-toml's TomlError untouched: its
 * message already embeds line, column, and a caret-annotated source line.
 *
 * Every SPDX pattern, clarify expression, and workspace license is parsed eagerly here so
 * evaluate() never sees an unparseable rule. Compatible license patterns are pre-decomposed into
 * spdx-satisfies-safe OR-leaf allowlists via orLeaves; AND-containing patterns are rejected
 * up-front because satisfies throws on AND allowlist entries. No substring matching on license
 * values anywhere - patterns flow through spdx-expression-parse + orLeaves only.
 *
 * Policy text is untrusted config (repo-tampered or user-authored). Suppression paths are validated
 * - non-empty, forward slashes only, no ".." segments, no leading/trailing slash, no drive
 * specifier - so a crafted path can never suppress everything, escape the target namespace, or name
 * a file outside the repository; compatible `where` scopes reuse the same validation, so a crafted
 * scope cannot escape the identity namespace either. smol-toml is a spec-compliant TOML 1.0 parser
 * with no eval; duplicate tables throw per spec.
 *
 * Pure function: no I/O, no logging - the CLI reads the file and owns stderr.
 */
import { win32 } from "node:path";

import { type } from "arktype";
import { parse as parseToml } from "smol-toml";
import parseSpdx from "spdx-expression-parse";

import { orLeaves, type ExpressionNode } from "../normalize/expression";
import { PolicyRoot, TOP_LEVEL_KEYS } from "../validate/policy";
import { recordOf, stringOf } from "../validate/record";
import { BUILTIN_DENY_RULES } from "./builtinDenylist";
import { OSADL_MATRIX, type TargetLicense, type TargetProfile } from "./compat";
import {
  JUSTIFICATION_VALUES,
  RATIONALE_VALUES,
  type Justification,
  type Rationale,
} from "./enums";
import { compileNamePattern, isGlobPattern } from "./namePattern";

import type { DetectedSignal } from "../normalize/normalize";
import type { DenyRule } from "./denylist";

export type { DenyRule } from "./denylist";

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

export interface CompatibleLicenseRule {
  match: "license";
  /** The SPDX pattern exactly as written in the policy file. */
  pattern: string;
  /**
   * Pre-decomposed satisfies allowlist: rendered OR-leaves of the pattern (single ID, optionally
   * WITH ⇒ one entry). Computed at validation time, never at evaluate time.
   */
  allowlist: ReadonlyArray<string>;
  /** Why this licence is accepted where the scope below covers it. */
  rationale: Rationale;
  /**
   * The occurrence scope: identity prefixes the rule is limited to, matched with the same
   * segment-aware prefix comparison as suppression paths, or the everywhere token {@link
   * EVERYWHERE_SCOPE} for a deliberately repository-wide acceptance.
   */
  where: ReadonlyArray<string>;
  /** Free prose, for what the rationale alone cannot carry. */
  comment?: string;
}

export interface CompatiblePackageRule {
  match: "package";
  /** Exact display name; exactly one of `name` and `pattern` is present. */
  name?: string;
  /**
   * Display-name pattern, in the dialect of {@link compileNamePattern}. The license form reads the
   * same key as an SPDX expression instead - `match` decides which, as it does on the deny lane.
   */
  pattern?: string;
  /** The exact version, or exact versions, covered. Absent covers every version. */
  version?: string | ReadonlyArray<string>;
  /**
   * The packages whose use of this one the acceptance was judged under, by display name, or the
   * reserved {@link SELF_PARENT} token. Parsed and carried here; which introduction paths a listed
   * parent covers is not decided in this file.
   */
  asDependencyOf: ReadonlyArray<string>;
  /** Why this package is accepted where the scope below covers it. */
  rationale: Rationale;
  /** The occurrence scope - see CompatibleLicenseRule.where. */
  where: ReadonlyArray<string>;
  /** Free prose, for what the rationale alone cannot carry. */
  comment?: string;
}

export type CompatibleRule = CompatibleLicenseRule | CompatiblePackageRule;

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
  /** The exact version, or exact versions, covered. Absent covers every version. */
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
 * The optional [document] table: author-supplied presentation prose for the LICENSES document only
 * (never the notices companion). Both keys are OPTIONAL; when present each must be a non-empty
 * string. The render layer treats `title` as a heading and `preamble` as verbatim author markdown
 * - both at the policy-file trust boundary, so neither is escapeCell'd.
 */
export interface DocumentConfig {
  /** Replaces the default "Third-Party Licenses" H1 when present. */
  title?: string;
  /** Verbatim markdown block rendered below the auto-generated header. */
  preamble?: string;
}

/**
 * One [[docker.development]] entry: marks every container whose Dockerfile identity matches
 * `source` as development-only (never shipped).
 */
export interface DockerDevelopmentEntry {
  /**
   * Repo-relative glob over Dockerfile identities, in the EXACT same dialect as `[docker].ignore`
   * (globToRegExp in targets/discover.ts: `*` within a segment, `**` across segments,
   * case-insensitive, anchored - a literal path is a valid glob). Here the pattern is only
   * validated and stored verbatim; matching against discovered containers happens where the report
   * is rendered. A matching container's packages are listed under Development-only in the report
   * - placement only, it never affects a verdict.
   */
  source: string;
  /** Mandatory documentation: why this container never ships. */
  reason: string;
}

/**
 * The optional [docker] table: Dockerfile-discovery exclusion globs plus per-container development
 * marking. When `generate-docker-sbom --repo-root` discovers Dockerfiles, every Dockerfile whose
 * repo-relative forward-slash identity matches an `ignore` glob is EXCLUDED ENTIRELY - its base
 * image is never derived, never scanned. `ignore` defaults to [] when the [docker] table is present
 * without the key, and the whole table is undefined when absent. Each glob is validated with the
 * SAME posture as suppression paths (forward slashes only, no ".." segments, no leading/trailing
 * slash) so a crafted glob can never escape the repo namespace. `development` defaults to [] the
 * same way; every analyzed container is production unless a `[[docker.development]]` entry's
 * `source` glob matches it - the conservative default.
 */
export interface DockerConfig {
  /** Repo-relative forward-slash globs; a matching Dockerfile is excluded. */
  ignore: ReadonlyArray<string>;
  /** Per-container development marking; absent key defaults to []. */
  development: ReadonlyArray<DockerDevelopmentEntry>;
}

/**
 * The optional [cache] table: the directory holding all tool-generated committed artifacts (the
 * enrichment cache, the Docker OS SBOM, and any added later), so they live in one place instead of
 * scattering across the repo root. `dir` is a repo-root-relative forward-slash path, validated like
 * a suppression path (no "..", no leading/trailing slash) so a committed artifact directory can
 * never escape the repo: a project that keeps its root clean can point it at e.g.
 * "eng/.sbomlet.cache". An absent table, or an absent `dir`, falls back to the DEFAULT_CACHE_DIR
 * default at resolution time.
 */
export interface CacheConfig {
  /** Repo-root-relative dir for committed artifacts; default applies when absent. */
  dir?: string;
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

/**
 * One [[target.workspace]] override: PER-FIELD inheritance from a complete project [target] profile
 * - `path`/`license`/`reason` are always mandatory here; `network`/`distribution` are optional and
 * inherit the project profile's own values when a complete one is declared. When no complete
 * project profile exists, schema.ts's validator requires every entry to carry BOTH itself
 * - there is nothing to inherit from.
 */
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

export interface Policy {
  /** Default "warn" when the [unknown] table is absent. */
  unknownHandling: "warn" | "fail";
  /** Default "warn" when the [dev_dependencies] table is absent. */
  devDependencies: DevDependencyHandling;
  /** Default "warn" when the [os_dependencies] table is absent. */
  osDependencies: OsDependencyHandling;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  compatible: ReadonlyArray<CompatibleRule>;
  clarify: ReadonlyArray<ClarifyRule>;
  /**
   * The declared path of a file holding further `[[clarify]]` entries, repo-root-relative. Absent
   * when the policy declares none; the entries themselves arrive appended to `clarify`.
   */
  clarifications?: string;
  /**
   * Terminal deny-list: the HIGHEST-precedence lane. A matching package FORCE-FAILS regardless of
   * compatible/suppression/dev-scope. Absent [[deny]] table yields [].
   */
  deny: ReadonlyArray<DenyRule>;
  /**
   * Per-licence exemptions from the shipped source-available deny defaults (ADR-0013). A listed
   * licence is no longer force-failed by the default - the package surfaces as a WARN citing the
   * exemption, never silently. Does NOT affect a consumer's own [[deny]] (an explicit deny still
   * wins). Absent → [].
   */
  allowSourceAvailable: ReadonlyArray<AllowSourceAvailable>;
  /**
   * Author-supplied document presentation. Absent [document] table yields undefined; an empty
   * [document] yields {} (both keys optional).
   */
  document?: DocumentConfig;
  /**
   * Dockerfile-discovery exclusion globs. Absent [docker] table yields undefined; a present
   * [docker] (with or without `ignore`) yields a DockerConfig whose `ignore` defaults to [].
   */
  docker?: DockerConfig;
  /**
   * Where tool-generated committed artifacts live (the enrichment cache, the Docker OS SBOM, and
   * any added later). Absent maps to DEFAULT_CACHE_DIR.
   */
  cache?: CacheConfig;
  /**
   * The declared target usage profile that activates the compatibility lane. Absent [target] table
   * yields undefined - today's walk stays byte-identical.
   */
  target?: TargetConfig;
}

/**
 * The reason an entry surfaces wherever a verdict cites it: the closed-set value it chose, and the
 * comment appended after an em-dash when it carries one. One derivation for every entry kind, so a
 * rendered reason reads the same whatever cited it.
 */
export function ruleReason(value: string, comment: string | undefined): string {
  return comment === undefined ? value : `${value} — ${comment}`;
}

/** All semantic problems aggregated; message = problems joined with "\n". */
export class PolicyError extends Error {
  readonly problems: ReadonlyArray<string>;

  constructor(problems: ReadonlyArray<string>) {
    super(problems.join("\n"));
    this.name = "PolicyError";
    this.problems = problems;
  }
}

/**
 * Reject every key outside `allowed`. A key an earlier schema used is reported with the replacement
 * `replaced` names, so a file written against that schema is told what to write instead of only
 * that something is wrong.
 */
function checkKeys(
  entry: Record<string, unknown>,
  allowed: ReadonlyArray<string>,
  where: string,
  problems: string[],
  replaced: ReadonlyMap<string, string> = new Map(),
): void {
  for (const key of Object.keys(entry)) {
    if (allowed.includes(key)) {
      continue;
    }

    const replacement = replaced.get(key);

    problems.push(
      replacement === undefined
        ? `${where}: unknown key "${key}"`
        : `${where}: ${replacement} (see docs/reference/policy.md)`,
    );
  }
}

/**
 * Mandatory non-empty string field. Reasons and descriptions are documentation - an empty or
 * whitespace-only value does not count.
 */
function requireText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  if (!(key in entry)) {
    problems.push(`${where}: missing required key "${key}"`);
    return undefined;
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    problems.push(`${where}: key "${key}" must be a string`);
    return undefined;
  }

  if (value.trim() === "") {
    problems.push(`${where}: key "${key}" must be a non-empty string`);
    return undefined;
  }

  return value;
}

/**
 * OPTIONAL non-empty string field of [document]. Absent → undefined, no problem. Present but
 * non-string or empty/whitespace-only → undefined + a problem (mirroring requireText's posture for
 * the present-and-invalid case).
 */
function optionalText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  if (!(key in entry)) {
    return undefined;
  }

  const value = stringOf(entry[key]);

  if (value === undefined) {
    problems.push(`${where}: key "${key}" must be a string`);
    return undefined;
  }

  if (value.trim() === "") {
    problems.push(`${where}: key "${key}" must be a non-empty string`);
    return undefined;
  }

  return value;
}

/**
 * Parse the optional [document] table: an absent table yields undefined;
 * a non-table value rejects; an empty table yields {}; title/preamble are each OPTIONAL but, when
 * present, must be a non-empty string (optionalText). Unknown keys reject via checkKeys. Only
 * present-and-valid keys are materialized so the "absent key" state stays observable.
 */
function validateDocument(
  root: Record<string, unknown>,
  problems: string[],
): DocumentConfig | undefined {
  if (!("document" in root)) {
    return undefined;
  }

  const table = recordOf(root["document"]);

  if (table === undefined) {
    problems.push("document: must be a table ([document])");
    return undefined;
  }

  checkKeys(table, ["title", "preamble"], "document", problems);
  const title = optionalText(table, "title", "document", problems);
  const preamble = optionalText(table, "preamble", "document", problems);

  return {
    ...(title !== undefined ? { title } : {}),
    ...(preamble !== undefined ? { preamble } : {}),
  };
}

/**
 * Parse the optional [docker] table: an absent table yields undefined;
 * a non-table value rejects; a present table (with or without `ignore`) yields a DockerConfig whose
 * `ignore` defaults to []. Each ignore entry must be a non-empty string and a repo-relative
 * forward-slash glob - reusing validatePath EXACTLY (no backslashes, no ".." segments, no
 * leading/trailing slash, no empty/"."/whitespace-padded segments) so a crafted glob can never
 * escape the repo namespace. Unknown keys reject via checkKeys. A malformed entry pushes the
 * aggregated PolicyError message naming docker.ignore[i]; only a fully-valid table materializes
 * (matching the present-key idiom elsewhere).
 */
/**
 * Parse one [[docker.development]] entry: `source` must be a valid glob (validatePath - the same
 * posture as a docker.ignore entry) that does not
 * start with "docker:" (the table already scopes the Dockerfile identity;
 * the prefix would double up and could never match); `reason` is mandatory documentation. `seen`
 * collects already-accepted source strings so a duplicate pattern - silently dead, since only the
 * first entry could ever decide anything - is rejected too.
 */
function validateDockerDevelopmentEntry(
  rawEntry: unknown,
  where: string,
  seen: Set<string>,
  problems: string[],
): DockerDevelopmentEntry | undefined {
  const entry = recordOf(rawEntry);

  if (entry === undefined) {
    problems.push(`${where}: must be a table`);
    return undefined;
  }

  checkKeys(entry, ["source", "reason"], where, problems);
  const source = requireText(entry, "source", where, problems);
  const reason = requireText(entry, "reason", where, problems);

  if (source === undefined || reason === undefined) {
    return undefined;
  }

  const before = problems.length;

  validatePath(source, where, problems);
  if (source.startsWith("docker:")) {
    problems.push(
      `${where}: source "${source}" must not start with "docker:" (the table already scopes the Dockerfile identity; the prefix would double up and could never match)`,
    );
  }

  if (seen.has(source)) {
    problems.push(
      `${where}: source "${source}" duplicates an earlier [[docker.development]] entry (the first match wins; the duplicate would be dead)`,
    );
  }

  if (problems.length !== before) {
    return undefined;
  }

  seen.add(source);
  return { source, reason };
}

/**
 * Parse the optional `development` array inside [docker]: each entry marks a glob-matched container
 * as development-only. Absent → []. Every malformed
 * entry pushes the aggregated PolicyError message naming docker.development[i];
 * only fully-valid entries materialize.
 */
function validateDockerDevelopment(
  table: Record<string, unknown>,
  problems: string[],
): DockerDevelopmentEntry[] {
  if (!("development" in table)) {
    return [];
  }

  const raw = table["development"];

  if (!Array.isArray(raw)) {
    problems.push("docker.development: must be an array of tables ([[docker.development]])");
    return [];
  }

  const development: DockerDevelopmentEntry[] = [];
  const seen = new Set<string>();

  raw.forEach((rawEntry, index) => {
    const entry = validateDockerDevelopmentEntry(
      rawEntry,
      `docker.development[${index}]`,
      seen,
      problems,
    );

    if (entry !== undefined) {
      development.push(entry);
    }
  });
  return development;
}

function validateDocker(
  root: Record<string, unknown>,
  problems: string[],
): DockerConfig | undefined {
  if (!("docker" in root)) {
    return undefined;
  }

  const table = recordOf(root["docker"]);

  if (table === undefined) {
    problems.push("docker: must be a table ([docker])");
    return undefined;
  }

  checkKeys(table, ["ignore", "development"], "docker", problems);
  const development = validateDockerDevelopment(table, problems);

  if (!("ignore" in table)) {
    return { ignore: [], development };
  }

  const raw = table["ignore"];

  if (!Array.isArray(raw)) {
    problems.push("docker.ignore: must be an array of strings");
    return { ignore: [], development };
  }

  const ignore: string[] = [];

  raw.forEach((rawEntry, index) => {
    const where = `docker.ignore[${index}]`;
    const value = stringOf(rawEntry);

    if (value === undefined) {
      problems.push(`${where}: must be a string`);
      return;
    }

    if (value.trim() === "") {
      problems.push(`${where}: must be a non-empty string`);
      return;
    }

    const before = problems.length;

    validatePath(value, where, problems);
    if (problems.length === before) {
      ignore.push(value);
    }
  });
  return { ignore, development };
}

/**
 * Parse the optional [cache] table: an absent table yields undefined; a non-table rejects; a
 * present table with no `dir` yields {} (the default applies later). `dir`, when present, must be a
 * non-empty repo-root-relative forward-slash path (validatePath: no "..", no leading/trailing
 * slash), so a committed artifact directory can never escape the repo. A malformed `dir` drops to
 * {} after recording the aggregated PolicyError naming cache.dir.
 */
function validateCache(root: Record<string, unknown>, problems: string[]): CacheConfig | undefined {
  if (!("cache" in root)) {
    return undefined;
  }

  const table = recordOf(root["cache"]);

  if (table === undefined) {
    problems.push("cache: must be a table ([cache])");
    return undefined;
  }

  checkKeys(table, ["dir"], "cache", problems);
  if (!("dir" in table)) {
    return {};
  }

  const dir = requireText(table, "dir", "cache", problems);

  if (dir === undefined) {
    return {};
  }

  const before = problems.length;

  validatePath(dir, "cache.dir", problems);
  if (problems.length !== before) {
    return {};
  }

  return { dir };
}

/**
 * The optional top-level `clarifications` key: where the imported `[[clarify]]` entries live.
 * Validated exactly like `cache.dir` - repo-root-relative, forward slashes, no ".." segments - so a
 * policy can never point the loader outside the scanned repository. Absent yields undefined; a
 * malformed value yields undefined after recording the problem.
 */
function validateClarificationsPath(
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

/** Eager SPDX parse; a problem is recorded on failure. */
function parseSpdxChecked(
  value: string,
  where: string,
  problems: string[],
): ExpressionNode | undefined {
  try {
    return parseSpdx(value) as ExpressionNode;
  } catch {
    problems.push(`${where} "${value}" is not a valid SPDX expression`);
    return undefined;
  }
}

/** A leading Windows drive specifier: `C:/x`, `C:\\x`, and the drive-relative `C:x` alike. */
const DRIVE_SPECIFIER = /^[A-Za-z]:/;

/**
 * Suppression path rules: forward-slash repo-relative identity prefix. Empty paths are rejected by
 * requireText (an empty prefix would suppress everything); ".." segments, backslashes, and
 * leading/trailing slashes can never appear in target identities, so a path carrying them is a
 * policy bug, not a match candidate. The same goes for empty ("a//b"), "." ("a/./b"), and
 * whitespace-padded ("a /b") segments: target identities are normalized segment text, so such a
 * path can never match - and because suppression entries are excluded from unused-rule reporting, a
 * typo here would otherwise be silently dead forever.
 *
 * A leading drive specifier is rejected outright. `C:/elsewhere/x.toml` is a legal chain of
 * segments and passes every check below, but the fields sharing this validator name files the tool
 * reads and, for `clarifications` under refresh-clarifications --write, rewrites: one would reach
 * outside the scanned repository entirely. `C:x` - drive-relative, resolved against that drive's
 * own working directory - is refused for the same reason. The test is a single letter followed by a
 * colon, so the multi-letter "docker:" prefix a `where` scope carries is untouched.
 *
 * Shared by every path-shaped policy field - a "docker:"-prefixed path is fine here (a
 * [[compatible]] `where` scope deliberately targets a container occurrence). The suppression-only
 * "docker:" fence lives in validateSuppressions instead, since only a workspace suppression must
 * never absorb a container.
 */
function validatePath(path: string, where: string, problems: string[]): void {
  if (DRIVE_SPECIFIER.test(path) || win32.isAbsolute(path)) {
    problems.push(
      `${where}: path "${path}" must be repository-relative (an absolute or drive-lettered path names a file outside the repository)`,
    );
  }

  if (path.includes("\\")) {
    problems.push(
      `${where}: path "${path}" must use forward slashes only (target identities are forward-slash)`,
    );
  }

  if (path.startsWith("/") || path.endsWith("/")) {
    problems.push(`${where}: path "${path}" must not have a leading or trailing slash`);
  }

  const segments = path.split("/");

  if (segments.includes("..")) {
    problems.push(`${where}: path "${path}" must not contain ".." segments`);
  }

  if (segments.some((s) => s === "" || s === "." || s !== s.trim())) {
    problems.push(
      `${where}: path "${path}" contains an empty, ".", or whitespace-padded segment (it could never match a target identity)`,
    );
  }
}

function validateSuppressions(
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

    checkKeys(entry, ["path", "license", "description"], where, problems);
    const path = requireText(entry, "path", where, problems);
    const license = requireText(entry, "license", where, problems);
    const description = requireText(entry, "description", where, problems);

    if (path !== undefined) {
      validatePath(path, where, problems);
      if (path.startsWith("docker:")) {
        problems.push(
          `${where}: path "${path}" must not start with "docker:" (a container image is not a workspace; accept a container's copyleft package with a scoped [[compatible]] rule instead)`,
        );
      }
    }

    let licenseValid = false;

    if (license !== undefined) {
      const node = parseSpdxChecked(license, `${where}: license`, problems);

      if (node !== undefined) {
        if ("license" in node) {
          licenseValid = true;
        } else {
          // Verdict-affecting - a compound expression has no single family/identity to verify
          // suppression against.
          problems.push(
            `${where}: license "${license}" must be a single SPDX license ID (the workspace's own distribution license), not a compound expression`,
          );
        }
      }
    }

    if (path !== undefined && license !== undefined && licenseValid && description !== undefined) {
      suppressed.push({ path, license, description });
    }
  });
  return suppressed;
}

/**
 * The reserved `where` element that scopes an entry to every occurrence. No target identity can be
 * "/" - a leading or trailing slash is rejected wherever a path is validated - so the token is
 * unambiguous, and a deliberately repository-wide entry stays expressible without dropping the
 * scope key.
 */
export const EVERYWHERE_SCOPE = "/";

/**
 * The required `where` scope on a [[compatible]] entry: a non-empty array of occurrence-identity
 * prefixes, each validated exactly like a suppression path (the evaluator applies the same
 * segment-aware prefix comparison to both). An EMPTY array is rejected - a rule that could never
 * match anywhere is a dead rule by construction, the same posture as validatePath's
 * could-never-match segments. An element may be the everywhere token {@link EVERYWHERE_SCOPE} in
 * place of a path, so a deliberately repository-wide acceptance stays expressible while stating a
 * scope stays a conscious choice. `context` is the error-context string (conventionally named
 * `where` elsewhere in this file - renamed here because `where` is the TOML key under validation).
 */
function validateWhere(
  entry: Record<string, unknown>,
  context: string,
  problems: string[],
): { where?: ReadonlyArray<string>; valid: boolean } {
  if (!("where" in entry)) {
    problems.push(
      `${context}: missing required key "where" (the occurrence-identity prefixes this acceptance covers, or ["${EVERYWHERE_SCOPE}"] for every occurrence)`,
    );
    return { valid: false };
  }

  const raw = entry["where"];

  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(
      `${context}: key "where" must be a non-empty array of occurrence-identity prefixes`,
    );
    return { valid: false };
  }

  const before = problems.length;
  const scope: string[] = [];

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined) {
      problems.push(`${context}: where[${index}] must be a string`);
      return;
    }

    if (text !== EVERYWHERE_SCOPE) {
      validatePath(text, `${context}.where[${index}]`, problems);
    }

    scope.push(text);
  });
  if (problems.length !== before) {
    return { valid: false };
  }

  return { where: scope, valid: true };
}

/**
 * The reserved `as-dependency-of` element naming the project itself. On a target with a dependency
 * graph it is the direct edge from the project; on a target without one every package is a direct
 * dependency of the project, so it is the honest value there.
 */
export const SELF_PARENT = "self";

/**
 * The required `as-dependency-of` list on a package-form entry: the packages whose use of this one
 * the acceptance was judged against, by display name, or {@link SELF_PARENT}. Parsed as text here
 * and nothing more - which introduction paths a listed parent covers is decided against the model,
 * not against the file.
 */
function validateAsDependencyOf(
  entry: Record<string, unknown>,
  context: string,
  problems: string[],
): { asDependencyOf?: ReadonlyArray<string>; valid: boolean } {
  const key = "as-dependency-of";

  if (!(key in entry)) {
    problems.push(
      `${context}: missing required key "${key}" (the package names this acceptance was judged under, or ["${SELF_PARENT}"] for the project itself)`,
    );
    return { valid: false };
  }

  const raw = entry[key];

  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(
      `${context}: key "${key}" must be a non-empty array of package names, or ["${SELF_PARENT}"]`,
    );
    return { valid: false };
  }

  const parents: string[] = [];
  const before = problems.length;

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(`${context}: ${key}[${index}] must be a non-empty package name`);
      return;
    }

    parents.push(text);
  });
  return problems.length === before ? { asDependencyOf: parents, valid: true } : { valid: false };
}

/** Keys an earlier [[compatible]] schema used, each naming what replaced it. */
const COMPATIBLE_REPLACED_KEYS: ReadonlyMap<string, string> = new Map([
  ["reason", 'key "reason" was replaced by "rationale" (a closed set) plus an optional "comment"'],
]);

/** {@link COMPATIBLE_REPLACED_KEYS} plus the license form's own inapplicable key. */
const COMPATIBLE_LICENSE_REPLACED_KEYS: ReadonlyMap<string, string> = new Map([
  ...COMPATIBLE_REPLACED_KEYS,
  [
    "as-dependency-of",
    'key "as-dependency-of" is not applicable at license level - a licence is accepted wherever "where" covers it, not through one package\'s use of another',
  ],
]);

function validateCompatible(root: Record<string, unknown>, problems: string[]): CompatibleRule[] {
  const compatible: CompatibleRule[] = [];
  const raw = root["compatible"];

  if (raw === undefined) {
    return compatible;
  }

  if (!Array.isArray(raw)) {
    problems.push("compatible: must be an array of tables ([[compatible]])");
    return compatible;
  }

  raw.forEach((rawEntry, index) => {
    const where = `compatible[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const match = stringOf(entry["match"]);

    if (match === "license") {
      const rule = validateCompatibleLicense(entry, where, problems);

      if (rule !== undefined) {
        compatible.push(rule);
      }
    } else if (match === "package") {
      const rule = validateCompatiblePackage(entry, where, problems);

      if (rule !== undefined) {
        compatible.push(rule);
      }
    } else {
      problems.push(`${where}: key "match" must be "license" or "package"`);
    }
  });
  return compatible;
}

/**
 * License-form [[compatible]] entry -> rule, or undefined when invalid. Here `pattern` is the SPDX
 * expression the acceptance covers; the package form reads the same key as a name glob instead, the
 * split the deny lane already makes on its own `match` discriminator.
 */
function validateCompatibleLicense(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatibleLicenseRule | undefined {
  const before = problems.length;

  checkKeys(
    entry,
    ["match", "pattern", "rationale", "where", "comment"],
    where,
    problems,
    COMPATIBLE_LICENSE_REPLACED_KEYS,
  );
  const pattern = requireText(entry, "pattern", where, problems);
  const rationale = validateClosedSet(entry, "rationale", RATIONALE_VALUES, where, problems);
  const scope = validateWhere(entry, where, problems);
  const comment = optionalText(entry, "comment", where, problems);

  if (pattern === undefined) {
    return undefined;
  }

  const node = parseSpdxChecked(pattern, `${where}: pattern`, problems);

  if (node === undefined) {
    return undefined;
  }

  const allowlist = orLeaves(node);

  if (allowlist === null) {
    problems.push(
      `${where}: pattern "${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
    );
    return undefined;
  }

  if (problems.length !== before || rationale === undefined || scope.where === undefined) {
    return undefined;
  }

  return {
    match: "license",
    pattern,
    allowlist,
    rationale,
    where: scope.where,
    ...(comment !== undefined ? { comment } : {}),
  };
}

/** Package-form [[compatible]] entry -> rule, or undefined when invalid. */
function validateCompatiblePackage(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatiblePackageRule | undefined {
  const before = problems.length;

  checkKeys(
    entry,
    ["match", "name", "pattern", "version", "as-dependency-of", "rationale", "where", "comment"],
    where,
    problems,
    COMPATIBLE_REPLACED_KEYS,
  );
  const selector = validateNameOrPattern(entry, where, problems);
  const pin = validateVersionPin(entry, where, problems);
  const parents = validateAsDependencyOf(entry, where, problems);
  const rationale = validateClosedSet(entry, "rationale", RATIONALE_VALUES, where, problems);
  const scope = validateWhere(entry, where, problems);
  const comment = optionalText(entry, "comment", where, problems);

  if (
    problems.length !== before ||
    parents.asDependencyOf === undefined ||
    rationale === undefined ||
    scope.where === undefined
  ) {
    return undefined;
  }

  return {
    match: "package",
    ...(selector.name !== undefined ? { name: selector.name } : {}),
    ...(selector.pattern !== undefined ? { pattern: selector.pattern } : {}),
    ...(pin.version !== undefined ? { version: pin.version } : {}),
    asDependencyOf: parents.asDependencyOf,
    rationale,
    where: scope.where,
    ...(comment !== undefined ? { comment } : {}),
  };
}

/** Package selector fields shared by every entry that names the packages it governs. */
interface SelectorFields {
  name?: string;
  pattern?: string;
  valid: boolean;
}

/**
 * The `name`/`pattern` pair: exactly one is required. `name` is compared verbatim; `pattern` must
 * use the glob dialect - a glob-free pattern names one package and belongs under `name` - and must
 * compile, which refuses a pattern with no literal character to anchor it.
 */
function validateNameOrPattern(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): SelectorFields {
  const hasName = "name" in entry;
  const hasPattern = "pattern" in entry;

  if (hasName === hasPattern) {
    problems.push(
      `${where}: exactly one of "name" and "pattern" is required (${hasName ? "both are present" : "neither is present"})`,
    );
    return { valid: false };
  }

  if (hasName) {
    const name = requireText(entry, "name", where, problems);

    return name === undefined ? { valid: false } : { name, valid: true };
  }

  const pattern = requireText(entry, "pattern", where, problems);

  if (pattern === undefined) {
    return { valid: false };
  }

  if (!isGlobPattern(pattern)) {
    problems.push(
      `${where}: pattern "${pattern}" carries no wildcard - use "name" to select a single package`,
    );
    return { valid: false };
  }

  try {
    compileNamePattern(pattern);
  } catch (error) {
    problems.push(`${where}: ${(error as Error).message}`);
    return { valid: false };
  }

  return { pattern, valid: true };
}

/** The parsed `version` pin - see {@link validateVersionPin}. */
interface VersionPin {
  version?: string | ReadonlyArray<string>;
  valid: boolean;
}

/**
 * The optional `version` pin: one exact version, or a non-empty list of them. Absent covers every
 * version. The schema has no wildcard version anywhere - version churn is a maintenance task, not a
 * matching rule - so every element is compared literally.
 */
function validateVersionPin(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): VersionPin {
  if (!("version" in entry)) {
    return { valid: true };
  }

  const raw = entry["version"];

  if (!Array.isArray(raw)) {
    const version = stringOf(raw);

    if (version === undefined || version.trim() === "") {
      problems.push(
        `${where}: key "version" must be an exact version string, or a non-empty array of them`,
      );
      return { valid: false };
    }

    return { version, valid: true };
  }

  if (raw.length === 0) {
    problems.push(`${where}: key "version" must be a non-empty array of exact versions`);
    return { valid: false };
  }

  const versions: string[] = [];
  const before = problems.length;

  raw.forEach((value, index) => {
    const text = stringOf(value);

    if (text === undefined || text.trim() === "") {
      problems.push(`${where}: version[${index}] must be a non-empty string`);
      return;
    }

    versions.push(text);
  });
  return problems.length === before ? { version: versions, valid: true } : { valid: false };
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

/**
 * A closed-set key: required, a string, and one of `values`. The error names the whole set, so a
 * mistyped or invented value is told what may be written instead.
 */
function validateClosedSet<T extends string>(
  entry: Record<string, unknown>,
  key: string,
  values: ReadonlyArray<T>,
  where: string,
  problems: string[],
): T | undefined {
  const value = requireText(entry, key, where, problems);

  if (value === undefined) {
    return undefined;
  }

  if (!(values as ReadonlyArray<string>).includes(value)) {
    problems.push(`${where}: key "${key}" must be one of ${values.join(", ")} (got "${value}")`);
    return undefined;
  }

  return value as T;
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

/** Does this recorded value read as SPDX - a licence, rather than a label about one? */
function isSpdxExpression(value: string): boolean {
  try {
    parseSpdx(value);
    return true;
  } catch {
    return false;
  }
}

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

    if (typeof value === "string" && isSpdxExpression(value)) {
      problems.push(
        `${where}: justification "license-not-found" says no source states a licence, but detected.${source} records "${value}", which is one. Record the reason the stated licence is wrong instead, or choose the justification that fits.`,
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
  const pin = validateVersionPin(entry, where, problems);
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

/**
 * One [[deny]] entry → a DenyRule, mirroring validateCompatible EXACTLY. A license-mode entry
 * pre-decomposes its pattern via orLeaves into a satisfies allowlist (AND patterns rejected up
 * front, same as compatible - satisfies cannot hold AND allowlist entries); a name-mode entry
 * stores the verbatim pattern. Every malformed field pushes the aggregated PolicyError message
 * naming `deny[i]`.
 */
function validateDenyEntry(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): DenyRule | undefined {
  const match = stringOf(entry["match"]);

  if (match === "license") {
    checkKeys(entry, ["match", "pattern", "reason"], where, problems);
    const pattern = requireText(entry, "pattern", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (pattern === undefined) {
      return undefined;
    }

    const node = parseSpdxChecked(pattern, `${where}: pattern`, problems);

    if (node === undefined) {
      return undefined;
    }

    const allowlist = orLeaves(node);

    if (allowlist === null) {
      problems.push(
        `${where}: pattern "${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
      );
      return undefined;
    }

    if (reason === undefined) {
      return undefined;
    }

    return { match: "license", pattern, allowlist, reason };
  }

  if (match === "name") {
    checkKeys(entry, ["match", "pattern", "reason"], where, problems);
    const pattern = requireText(entry, "pattern", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (pattern === undefined || reason === undefined) {
      return undefined;
    }

    return { match: "name", pattern, reason };
  }

  problems.push(`${where}: key "match" must be "license" or "name"`);
  return undefined;
}

function validateDeny(root: Record<string, unknown>, problems: string[]): DenyRule[] {
  const deny: DenyRule[] = [];
  const raw = root["deny"];

  if (raw === undefined) {
    return deny;
  }

  if (!Array.isArray(raw)) {
    problems.push("deny: must be an array of tables ([[deny]])");
    return deny;
  }

  raw.forEach((rawEntry, index) => {
    const where = `deny[${index}]`;
    const entry = recordOf(rawEntry);

    if (entry === undefined) {
      problems.push(`${where}: must be a table`);
      return;
    }

    const rule = validateDenyEntry(entry, where, problems);

    if (rule !== undefined) {
      deny.push(rule);
    }
  });
  return deny;
}

/** The shipped source-available licence ids - the only ones an exemption may name. */
const BUILTIN_DENY_PATTERNS: ReadonlyArray<string> = BUILTIN_DENY_RULES.filter(
  (rule) => rule.match === "license",
).map((rule) => rule.pattern);

/**
 * Parse [[allow_source_available]] (ADR-0013 opt-out): each entry exempts ONE built-in
 * source-available licence from the shipped deny default. `license` must be one of the shipped
 * patterns (a consumer's own [[deny]] is absolute and not exempted here); `reason` is mandatory
 * documentation. An absent table yields [].
 */
function validateAllowSourceAvailable(
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
    const license = requireText(entry, "license", where, problems);
    const reason = requireText(entry, "reason", where, problems);

    if (license !== undefined && !BUILTIN_DENY_PATTERNS.includes(license)) {
      problems.push(
        `${where}: license "${license}" is not a built-in source-available default — only ${BUILTIN_DENY_PATTERNS.join(", ")} can be exempted (a consumer's own [[deny]] is absolute and not exempted here)`,
      );
      return;
    }

    if (license !== undefined && reason !== undefined) {
      exemptions.push({ license, reason });
    }
  });
  return exemptions;
}

function validateUnknown(root: Record<string, unknown>, problems: string[]): "warn" | "fail" {
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
function validateDevDependencies(
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
function validateOsDependencies(
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

  const node = parseSpdxChecked(value, `${where}: license`, problems);

  if (node === undefined) {
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

  if (!("network" in table) || typeof table["network"] !== "boolean") {
    problems.push(`${where}: key "network" must be a boolean`);
  }

  const network = typeof table["network"] === "boolean" ? table["network"] : undefined;
  const distributionRaw = stringOf(table["distribution"]);
  const distribution =
    distributionRaw === "external" || distributionRaw === "internal" ? distributionRaw : undefined;

  if (distribution === undefined) {
    problems.push(`${where}: key "distribution" must be "external" or "internal"`);
  }

  if (license === undefined || network === undefined || distribution === undefined) {
    return undefined;
  }

  return { license, network, distribution };
}

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
function validateTarget(
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

/**
 * Parse and validate TOML policy text. smol-toml's TomlError propagates untouched (its message
 * embeds line/column/caret context); every semantic problem is collected and thrown as ONE
 * PolicyError naming table paths.
 *
 * PolicyRoot ("+": "reject") narrows the root shape; the unknown-top-level-key message stays
 * hand-written (arktype's text differs from the PolicyError contract).
 */
export function parsePolicy(text: string): Policy {
  const root = recordOf(parseToml(text)) ?? {};
  const problems: string[] = [];

  const narrowed = PolicyRoot(root);

  if (narrowed instanceof type.errors) {
    const accepted: readonly string[] = TOP_LEVEL_KEYS;

    for (const key of Object.keys(root)) {
      if (!accepted.includes(key)) {
        problems.push(`unknown top-level key "${key}"`);
      }
    }
  }

  const suppressedWorkspaces = validateSuppressions(root, problems);
  const compatible = validateCompatible(root, problems);
  const clarify = validateClarifyTables(root["clarify"], "clarify", problems);
  const clarifications = validateClarificationsPath(root, problems);
  const deny = validateDeny(root, problems);
  const unknownHandling = validateUnknown(root, problems);
  const devDependencies = validateDevDependencies(root, problems);
  const osDependencies = validateOsDependencies(root, problems);
  const document = validateDocument(root, problems);
  const docker = validateDocker(root, problems);
  const cache = validateCache(root, problems);
  const allowSourceAvailable = validateAllowSourceAvailable(root, problems);
  const target = validateTarget(root, problems);

  if (problems.length > 0) {
    throw new PolicyError(problems);
  }

  return {
    unknownHandling,
    devDependencies,
    osDependencies,
    suppressedWorkspaces,
    compatible,
    clarify,
    deny,
    allowSourceAvailable,
    ...(clarifications !== undefined ? { clarifications } : {}),
    ...(document !== undefined ? { document } : {}),
    ...(docker !== undefined ? { docker } : {}),
    ...(cache !== undefined ? { cache } : {}),
    ...(target !== undefined ? { target } : {}),
  };
}
