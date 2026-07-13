/**
 * TOML policy text → validated Policy.
 *
 * Validation rejects — never skips — with every semantic problem collected
 * into one PolicyError, each problem naming its table path and key (the
 * opposite tolerance posture from merge.ts, which skips malformed SBOM
 * entries). TOML syntax errors propagate smol-toml's TomlError untouched: its
 * message already embeds line, column, and a caret-annotated source line.
 *
 * Every SPDX pattern, clarify expression, and workspace license is parsed
 * eagerly here so evaluate() never sees an unparseable rule. Compatible license
 * patterns are pre-decomposed into spdx-satisfies-safe OR-leaf allowlists via
 * orLeaves; AND-containing patterns are rejected up-front because satisfies
 * throws on AND allowlist entries. No substring matching on license values
 * anywhere — patterns flow through spdx-expression-parse + orLeaves only.
 *
 * Policy text is untrusted config (repo-tampered or user-authored).
 * Suppression paths are validated — non-empty, forward slashes only, no ".."
 * segments, no leading/trailing slash — so a crafted path can never suppress
 * everything or escape the target namespace; compatible `where` scopes reuse
 * the same validation, so a crafted scope cannot escape the identity
 * namespace either. smol-toml is a spec-compliant TOML 1.0 parser with no
 * eval; duplicate tables throw per spec.
 *
 * Pure function: no I/O, no logging — the CLI reads the file and owns stderr.
 */
import { type } from "arktype";
import { parse as parseToml } from "smol-toml";
import parseSpdx from "spdx-expression-parse";

import { orLeaves, type ExpressionNode } from "../normalize/expression";
import { PolicyRoot, TOP_LEVEL_KEYS } from "../validate/policy";
import { recordOf, stringOf } from "../validate/record";
import { BUILTIN_DENY_RULES } from "./builtinDenylist";
import type { DenyRule } from "./denylist";

export type { DenyRule } from "./denylist";

export interface SuppressedWorkspace {
  /** Repo-relative target-identity prefix, e.g. "apps/scratch". */
  path: string;
  /**
   * SPDX ID the workspace itself is distributed under. Validated to be a single
   * license id (leaf, optionally WITH/+) — never a compound expression: this
   * field is verdict-affecting (the family-aware suppression check compares it
   * to the finding's copyleft obligations).
   */
  license: string;
  /** Mandatory documentation: why suppression is justified. */
  description: string;
}

export interface CompatibleLicenseRule {
  match: "license";
  /** The pattern exactly as written in the policy file. */
  pattern: string;
  /**
   * Pre-decomposed satisfies allowlist: rendered OR-leaves of the pattern
   * (single ID, optionally WITH ⇒ one entry). Computed at validation time,
   * never at evaluate time.
   */
  allowlist: ReadonlyArray<string>;
  reason: string;
  /**
   * Optional occurrence scope: identity prefixes the rule is limited
   * to, matched with the same segment-aware prefix comparison as suppression
   * paths. Materialized present-only — an absent key means the rule applies
   * at every occurrence (the pre-scoping behavior).
   */
  where?: ReadonlyArray<string>;
}

export interface CompatiblePackageRule {
  match: "package";
  name: string;
  version?: string;
  reason: string;
  /** Optional occurrence scope — see CompatibleLicenseRule.where. */
  where?: ReadonlyArray<string>;
}

export type CompatibleRule = CompatibleLicenseRule | CompatiblePackageRule;

export interface ClarifyRule {
  name: string;
  version?: string;
  /**
   * Optional staleness precondition: the pre-override observed license
   * value this clarify disambiguates FROM. When present, the engine applies the
   * `expression` ONLY if the dependency's currently-observed signal still
   * matches `expects` — a mismatch is a STALE override that fails the gate
   * loudly (it must never silently mask a relicense). OPTIONAL for backward
   * compatibility: the existing Phase-3 misdetection-correction clarify (e.g.
   * jsonify → Unlicense) keeps working WITHOUT it, applying blindly as before;
   * `expects` is the precondition for the new staleness-guarded disambiguation.
   */
  expects?: string;
  /** A valid SPDX expression — parsed eagerly here. */
  expression: string;
  reason: string;
}

/**
 * How a would-be default-FAIL verdict is treated on a DEV-only occurrence
 * (POL-08, D-POL-08). Per-occurrence, never package-level — a package that is
 * dev in one workspace and prod in another still FAILS on the prod occurrence.
 *   "warn"   — a dev would-be-fail downgrades to warn (the default).
 *   "fail"   — NO downgrade; dev gates exactly like prod (pre-POL-08, strict).
 *   "ignore" — a dev would-be-fail becomes ok (an EXPLICIT, documented opt-out).
 * A PRODUCTION occurrence ALWAYS fails under "warn"/"ignore" — a shipped
 * copyleft can never be dev-downgraded.
 */
export type DevDependencyHandling = "warn" | "fail" | "ignore";

/**
 * The [os_dependencies] knob, mirroring DevDependencyHandling. It
 * governs a would-be-FAIL on a PACKAGE-level os-scope dependency (a pkg:deb /
 * pkg:apk row from the Docker base image):
 *   "warn"   — an os would-be-fail downgrades to warn (the default): expected
 *              base-image copyleft (glibc/bash GPL/LGPL, satisfied by shipping
 *              the image) LISTS, not fails.
 *   "fail"   — NO downgrade; an os-scope copyleft gates exactly like an app one.
 *   "ignore" — an os would-be-fail becomes ok (an EXPLICIT, documented opt-out).
 * A DENIED (source-available) license in an OS package STILL FAILS regardless —
 * deny is terminal-0 above the os downgrade.
 */
export type OsDependencyHandling = "warn" | "fail" | "ignore";

/**
 * The optional [document] table: author-supplied presentation prose for
 * the LICENSES document only (never the notices companion). Both keys are
 * OPTIONAL; when present each must be a non-empty string. The render layer
 * treats `title` as a heading and `preamble` as verbatim author markdown — both
 * at the policy-file trust boundary, so neither is escapeCell'd.
 */
export interface DocumentConfig {
  /** Replaces the default "Third-Party Licenses" H1 when present. */
  title?: string;
  /** Verbatim markdown block rendered below the auto-generated header. */
  preamble?: string;
}

/**
 * The optional [docker] table (07-23): Dockerfile-discovery exclusion globs.
 * When `generate-docker-sbom --repo-root` discovers Dockerfiles, every
 * Dockerfile whose repo-relative forward-slash identity matches an `ignore`
 * glob is EXCLUDED ENTIRELY — its base image is never derived, never scanned.
 * `ignore` defaults to [] when the [docker] table is present without the key,
 * and the whole table is undefined when absent. Each glob is validated with the
 * SAME posture as suppression paths (forward slashes only, no ".." segments, no
 * leading/trailing slash) so a crafted glob can never escape the repo namespace.
 */
export interface DockerConfig {
  /** Repo-relative forward-slash globs; a matching Dockerfile is excluded. */
  ignore: ReadonlyArray<string>;
}

/**
 * The optional [cache] table: the directory holding all tool-generated committed
 * artifacts (the enrichment cache, the Docker OS SBOM, and any added later), so
 * they live in one place instead of scattering across the repo root. `dir` is a
 * repo-root-relative forward-slash path, validated like a suppression path (no
 * "..", no leading/trailing slash) so a committed artifact directory can never
 * escape the repo: a project that keeps its root clean can point it at e.g.
 * "eng/.sbomlet.cache". An absent table, or an absent `dir`, falls back to the
 * DEFAULT_CACHE_DIR default at resolution time.
 */
export interface CacheConfig {
  /** Repo-root-relative dir for committed artifacts; default applies when absent. */
  dir?: string;
}

/**
 * One [[allow_source_available]] exemption (ADR-0013): a built-in
 * source-available licence the consumer has explicitly, auditably accepted, so it
 * surfaces as a warn instead of failing the gate by default.
 */
export interface AllowSourceAvailable {
  /** A built-in source-available SPDX id (BUSL-1.1, SSPL-1.0, Elastic-2.0). */
  license: string;
  /** Mandatory documentation: why this source-available licence is accepted. */
  reason: string;
}

export interface Policy {
  /** Default "warn" when the [unknown] table is absent. */
  unknownHandling: "warn" | "fail";
  /** Default "warn" when the [dev_dependencies] table is absent (POL-08). */
  devDependencies: DevDependencyHandling;
  /** Default "warn" when the [os_dependencies] table is absent. */
  osDependencies: OsDependencyHandling;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  compatible: ReadonlyArray<CompatibleRule>;
  clarify: ReadonlyArray<ClarifyRule>;
  /**
   * Terminal deny-list (POL-09): the HIGHEST-precedence lane. A matching
   * package FORCE-FAILS regardless of compatible/suppression/dev-scope. Absent
   * [[deny]] table yields [].
   */
  deny: ReadonlyArray<DenyRule>;
  /**
   * Per-licence exemptions from the shipped source-available deny defaults
   * (ADR-0013). A listed licence is no longer force-failed by the default — the
   * package surfaces as a WARN citing the exemption, never silently. Does NOT
   * affect a consumer's own [[deny]] (an explicit deny still wins). Absent → [].
   */
  allowSourceAvailable: ReadonlyArray<AllowSourceAvailable>;
  /**
   * Author-supplied document presentation. Absent [document] table
   * yields undefined; an empty [document] yields {} (both keys optional).
   */
  document?: DocumentConfig;
  /**
   * Dockerfile-discovery exclusion globs (07-23). Absent [docker] table yields
   * undefined; a present [docker] (with or without `ignore`) yields a
   * DockerConfig whose `ignore` defaults to [].
   */
  docker?: DockerConfig;
  /**
   * Where tool-generated committed artifacts live (the enrichment cache, the
   * Docker OS SBOM, and any added later). Absent maps to DEFAULT_CACHE_DIR.
   */
  cache?: CacheConfig;
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

function checkKeys(
  entry: Record<string, unknown>,
  allowed: ReadonlyArray<string>,
  where: string,
  problems: string[],
): void {
  for (const key of Object.keys(entry)) {
    if (!allowed.includes(key)) {
      problems.push(`${where}: unknown key "${key}"`);
    }
  }
}

/**
 * Mandatory non-empty string field. Reasons and descriptions are
 * documentation — an empty or whitespace-only value does not count.
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
 * OPTIONAL non-empty string field of [document]. Absent → undefined, no
 * problem. Present but non-string or empty/whitespace-only → undefined + a
 * problem (mirroring requireText's posture for the present-and-invalid case).
 */
function optionalText(
  entry: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | undefined {
  if (!(key in entry)) return undefined;
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
 * a non-table value rejects; an empty table yields {}; title/preamble are each
 * OPTIONAL but, when present, must be a non-empty string (optionalText). Unknown
 * keys reject via checkKeys. Only present-and-valid keys are materialized so the
 * "absent key" state stays observable.
 */
function validateDocument(
  root: Record<string, unknown>,
  problems: string[],
): DocumentConfig | undefined {
  if (!("document" in root)) return undefined;
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
 * Parse the optional [docker] table (07-23): an absent table yields undefined;
 * a non-table value rejects; a present table (with or without `ignore`) yields
 * a DockerConfig whose `ignore` defaults to []. Each ignore entry must be a
 * non-empty string and a repo-relative forward-slash glob — reusing validatePath
 * EXACTLY (no backslashes, no ".." segments, no leading/trailing slash, no
 * empty/"."/whitespace-padded segments) so a crafted glob can never escape the
 * repo namespace. Unknown keys reject via checkKeys. A malformed entry pushes
 * the aggregated PolicyError message naming docker.ignore[i]; only a fully-valid
 * table materializes (matching the present-key idiom elsewhere).
 */
function validateDocker(
  root: Record<string, unknown>,
  problems: string[],
): DockerConfig | undefined {
  if (!("docker" in root)) return undefined;
  const table = recordOf(root["docker"]);
  if (table === undefined) {
    problems.push("docker: must be a table ([docker])");
    return undefined;
  }
  checkKeys(table, ["ignore"], "docker", problems);
  if (!("ignore" in table)) return { ignore: [] };
  const raw = table["ignore"];
  if (!Array.isArray(raw)) {
    problems.push("docker.ignore: must be an array of strings");
    return { ignore: [] };
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
    if (problems.length === before) ignore.push(value);
  });
  return { ignore };
}

/**
 * Parse the optional [cache] table: an absent table yields undefined; a non-table
 * rejects; a present table with no `dir` yields {} (the default applies later).
 * `dir`, when present, must be a non-empty repo-root-relative forward-slash path
 * (validatePath: no "..", no leading/trailing slash), so a committed artifact
 * directory can never escape the repo. A malformed `dir` drops to {} after
 * recording the aggregated PolicyError naming cache.dir.
 */
function validateCache(
  root: Record<string, unknown>,
  problems: string[],
): CacheConfig | undefined {
  if (!("cache" in root)) return undefined;
  const table = recordOf(root["cache"]);
  if (table === undefined) {
    problems.push("cache: must be a table ([cache])");
    return undefined;
  }
  checkKeys(table, ["dir"], "cache", problems);
  if (!("dir" in table)) return {};
  const dir = requireText(table, "dir", "cache", problems);
  if (dir === undefined) return {};
  const before = problems.length;
  validatePath(dir, "cache.dir", problems);
  if (problems.length !== before) return {};
  return { dir };
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

/**
 * Suppression path rules: forward-slash repo-relative identity prefix. Empty
 * paths are rejected by requireText (an empty prefix would suppress
 * everything); ".." segments, backslashes, and leading/trailing slashes can
 * never appear in target identities, so a path carrying them is a policy bug,
 * not a match candidate. The same goes for empty ("a//b"), "." ("a/./b"), and
 * whitespace-padded ("a /b") segments: target identities are normalized
 * segment text, so such a path can never match — and because suppression
 * entries are excluded from unused-rule reporting, a typo here would otherwise
 * be silently dead forever.
 */
function validatePath(path: string, where: string, problems: string[]): void {
  if (path.includes("\\")) {
    problems.push(
      `${where}: path "${path}" must use forward slashes only (target identities are forward-slash)`,
    );
  }
  if (path.startsWith("/") || path.endsWith("/")) {
    problems.push(
      `${where}: path "${path}" must not have a leading or trailing slash`,
    );
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
  if (!("workspace" in root)) return suppressed;
  const workspace = recordOf(root["workspace"]);
  if (workspace === undefined) {
    problems.push(
      "workspace: must be a table containing [[workspace.copyleft_suppressed]] entries",
    );
    return suppressed;
  }
  checkKeys(workspace, ["copyleft_suppressed"], "workspace", problems);
  const entries = workspace["copyleft_suppressed"];
  if (entries === undefined) return suppressed;
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
    if (path !== undefined) validatePath(path, where, problems);
    let licenseValid = false;
    if (license !== undefined) {
      const node = parseSpdxChecked(license, `${where}: license`, problems);
      if (node !== undefined) {
        if ("license" in node) {
          licenseValid = true;
        } else {
          // Verdict-affecting — a compound expression has no single
          // family/identity to verify suppression against.
          problems.push(
            `${where}: license "${license}" must be a single SPDX license ID (the workspace's own distribution license), not a compound expression`,
          );
        }
      }
    }
    if (
      path !== undefined &&
      license !== undefined &&
      licenseValid &&
      description !== undefined
    ) {
      suppressed.push({ path, license, description });
    }
  });
  return suppressed;
}

/**
 * Optional `where` scope on a [[compatible]] entry: a non-empty array of
 * occurrence-identity prefixes, each validated exactly like a suppression path
 * (the evaluator applies the same segment-aware prefix comparison to both). An
 * EMPTY array is rejected — a rule that could never match anywhere is a dead
 * rule by construction, the same posture as validatePath's could-never-match
 * segments. `context` is the error-context string (conventionally named
 * `where` elsewhere in this file — renamed here because `where` is the TOML
 * key under validation).
 */
function validateWhere(
  entry: Record<string, unknown>,
  context: string,
  problems: string[],
): { where?: ReadonlyArray<string>; valid: boolean } {
  if (!("where" in entry)) return { valid: true };
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
    validatePath(text, `${context}.where[${index}]`, problems);
    scope.push(text);
  });
  if (problems.length !== before) return { valid: false };
  return { where: scope, valid: true };
}

function validateCompatible(
  root: Record<string, unknown>,
  problems: string[],
): CompatibleRule[] {
  const compatible: CompatibleRule[] = [];
  const raw = root["compatible"];
  if (raw === undefined) return compatible;
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
      if (rule !== undefined) compatible.push(rule);
    } else if (match === "package") {
      const rule = validateCompatiblePackage(entry, where, problems);
      if (rule !== undefined) compatible.push(rule);
    } else {
      problems.push(`${where}: key "match" must be "license" or "package"`);
    }
  });
  return compatible;
}

/** License-form [[compatible]] entry → rule, or undefined when invalid. */
function validateCompatibleLicense(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatibleLicenseRule | undefined {
  checkKeys(entry, ["match", "pattern", "reason", "where"], where, problems);
  const pattern = requireText(entry, "pattern", where, problems);
  const reason = requireText(entry, "reason", where, problems);
  const scope = validateWhere(entry, where, problems);
  if (pattern === undefined) return undefined;
  const node = parseSpdxChecked(pattern, `${where}: pattern`, problems);
  if (node === undefined) return undefined;
  const allowlist = orLeaves(node);
  if (allowlist === null) {
    problems.push(
      `${where}: pattern "${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
    );
    return undefined;
  }
  if (reason === undefined || !scope.valid) return undefined;
  return {
    match: "license",
    pattern,
    allowlist,
    reason,
    ...(scope.where !== undefined ? { where: scope.where } : {}),
  };
}

/** Package-form [[compatible]] entry → rule, or undefined when invalid. */
function validateCompatiblePackage(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): CompatiblePackageRule | undefined {
  checkKeys(
    entry,
    ["match", "name", "version", "reason", "where"],
    where,
    problems,
  );
  const name = requireText(entry, "name", where, problems);
  const reason = requireText(entry, "reason", where, problems);
  const scope = validateWhere(entry, where, problems);
  let version: string | undefined;
  if ("version" in entry) {
    version = stringOf(entry["version"]);
    if (version === undefined) {
      problems.push(`${where}: key "version" must be a string`);
      return undefined;
    }
  }
  if (name === undefined || reason === undefined || !scope.valid) {
    return undefined;
  }
  return {
    match: "package",
    name,
    ...(version !== undefined ? { version } : {}),
    reason,
    ...(scope.where !== undefined ? { where: scope.where } : {}),
  };
}

interface ClarifyPackage {
  name?: string;
  version?: string;
  versionValid: boolean;
}

/**
 * Inline-table { name, version? } extraction for a clarify entry. Extracted
 * to keep validateClarify's loop body within the max-depth bar; messages and
 * push order are unchanged from the inline form.
 */
function validateClarifyPackage(
  entry: Record<string, unknown>,
  where: string,
  problems: string[],
): ClarifyPackage {
  if (!("package" in entry)) {
    problems.push(`${where}: missing required key "package"`);
    return { versionValid: true };
  }
  const pkg = recordOf(entry["package"]);
  if (pkg === undefined) {
    problems.push(
      `${where}: key "package" must be an inline table { name, version? }`,
    );
    return { versionValid: true };
  }
  checkKeys(pkg, ["name", "version"], `${where}: package`, problems);
  const name = requireText(pkg, "name", `${where}: package`, problems);
  if (!("version" in pkg)) return { name, versionValid: true };
  const version = stringOf(pkg["version"]);
  if (version === undefined) {
    problems.push(`${where}: package key "version" must be a string`);
    return { name, versionValid: false };
  }
  return { name, version, versionValid: true };
}

/**
 * Build a ClarifyRule with only the present optional keys materialized
 * (version, expects). Keeping the absent keys OFF the object — rather than
 * `undefined`-but-present — keeps "no precondition" observable and the parsed
 * shape minimal, matching the compatible-package-rule idiom above.
 */
function makeClarifyRule(
  name: string,
  version: string | undefined,
  expects: string | undefined,
  expression: string,
  reason: string,
): ClarifyRule {
  return {
    name,
    ...(version !== undefined ? { version } : {}),
    ...(expects !== undefined ? { expects } : {}),
    expression,
    reason,
  };
}

function validateClarify(
  root: Record<string, unknown>,
  problems: string[],
): ClarifyRule[] {
  const clarify: ClarifyRule[] = [];
  const raw = root["clarify"];
  if (raw === undefined) return clarify;
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
    checkKeys(
      entry,
      ["package", "expects", "expression", "reason"],
      where,
      problems,
    );
    const { name, version, versionValid } = validateClarifyPackage(
      entry,
      where,
      problems,
    );
    // `expects` is OPTIONAL (backward-compat) but, when present, must be a
    // non-empty string — a blank precondition could never match an observed
    // signal and would be silently dead. requireText records the existing
    // aggregated-PolicyError messages naming clarify[i].
    let expects: string | undefined;
    let expectsValid = true;
    if ("expects" in entry) {
      expects = requireText(entry, "expects", `${where}: expects`, problems);
      expectsValid = expects !== undefined;
    }
    const expression = requireText(entry, "expression", where, problems);
    let expressionValid = false;
    if (expression !== undefined) {
      expressionValid =
        parseSpdxChecked(expression, `${where}: expression`, problems) !==
        undefined;
    }
    const reason = requireText(entry, "reason", where, problems);
    if (
      name !== undefined &&
      versionValid &&
      expectsValid &&
      expressionValid &&
      expression !== undefined &&
      reason !== undefined
    ) {
      clarify.push(makeClarifyRule(name, version, expects, expression, reason));
    }
  });
  return clarify;
}

/**
 * One [[deny]] entry → a DenyRule, mirroring validateCompatible EXACTLY. A
 * license-mode entry pre-decomposes its pattern via orLeaves into a satisfies
 * allowlist (AND patterns rejected up front, same as compatible — satisfies
 * cannot hold AND allowlist entries); a name-mode entry stores the verbatim
 * pattern. Every malformed field pushes the aggregated PolicyError message
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
    if (pattern === undefined) return undefined;
    const node = parseSpdxChecked(pattern, `${where}: pattern`, problems);
    if (node === undefined) return undefined;
    const allowlist = orLeaves(node);
    if (allowlist === null) {
      problems.push(
        `${where}: pattern "${pattern}" must be a license ID or an OR of license IDs (AND is not allowed — satisfies allowlists cannot hold AND expressions)`,
      );
      return undefined;
    }
    if (reason === undefined) return undefined;
    return { match: "license", pattern, allowlist, reason };
  }
  if (match === "name") {
    checkKeys(entry, ["match", "pattern", "reason"], where, problems);
    const pattern = requireText(entry, "pattern", where, problems);
    const reason = requireText(entry, "reason", where, problems);
    if (pattern === undefined || reason === undefined) return undefined;
    return { match: "name", pattern, reason };
  }
  problems.push(`${where}: key "match" must be "license" or "name"`);
  return undefined;
}

function validateDeny(
  root: Record<string, unknown>,
  problems: string[],
): DenyRule[] {
  const deny: DenyRule[] = [];
  const raw = root["deny"];
  if (raw === undefined) return deny;
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
    if (rule !== undefined) deny.push(rule);
  });
  return deny;
}

/** The shipped source-available licence ids — the only ones an exemption may name. */
const BUILTIN_DENY_PATTERNS: ReadonlyArray<string> = BUILTIN_DENY_RULES.filter(
  (rule) => rule.match === "license",
).map((rule) => rule.pattern);

/**
 * Parse [[allow_source_available]] (ADR-0013 opt-out): each entry exempts ONE
 * built-in source-available licence from the shipped deny default. `license` must
 * be one of the shipped patterns (a consumer's own [[deny]] is absolute and not
 * exempted here); `reason` is mandatory documentation. An absent table yields [].
 */
function validateAllowSourceAvailable(
  root: Record<string, unknown>,
  problems: string[],
): AllowSourceAvailable[] {
  const exemptions: AllowSourceAvailable[] = [];
  const raw = root["allow_source_available"];
  if (raw === undefined) return exemptions;
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

function validateUnknown(
  root: Record<string, unknown>,
  problems: string[],
): "warn" | "fail" {
  const raw = root["unknown"];
  if (raw === undefined) return "warn"; // absent table defaults to warn
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
  if (handling === "warn" || handling === "fail") return handling;
  problems.push('unknown.handling: must be "warn" or "fail"');
  return "warn";
}

/**
 * Parse the [dev_dependencies] knob (POL-08), mirroring validateUnknown EXACTLY:
 * an absent table defaults to "warn"; a non-table, missing handling, unknown
 * key, or invalid handling value each push the existing aggregated PolicyError
 * message naming the table path. The three valid values are warn|fail|ignore.
 */
function validateDevDependencies(
  root: Record<string, unknown>,
  problems: string[],
): DevDependencyHandling {
  const raw = root["dev_dependencies"];
  if (raw === undefined) return "warn"; // absent table defaults to warn
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
  problems.push(
    'dev_dependencies.handling: must be "warn", "fail", or "ignore"',
  );
  return "warn";
}

/**
 * Parse the [os_dependencies] knob, an EXACT mirror of
 * validateDevDependencies: an absent table defaults to "warn"; a non-table,
 * missing handling, unknown key, or invalid handling value each push the
 * aggregated PolicyError message naming the os_dependencies table path. The
 * three valid values are warn|fail|ignore.
 */
function validateOsDependencies(
  root: Record<string, unknown>,
  problems: string[],
): OsDependencyHandling {
  const raw = root["os_dependencies"];
  if (raw === undefined) return "warn"; // absent table defaults to warn
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
  problems.push(
    'os_dependencies.handling: must be "warn", "fail", or "ignore"',
  );
  return "warn";
}

/**
 * Parse and validate TOML policy text. smol-toml's TomlError propagates
 * untouched (its message embeds line/column/caret context); every semantic
 * problem is collected and thrown as ONE PolicyError naming table paths.
 *
 * PolicyRoot ("+": "reject") narrows the root shape; the unknown-top-level-key
 * message stays hand-written (arktype's text differs from the PolicyError
 * contract).
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
  const clarify = validateClarify(root, problems);
  const deny = validateDeny(root, problems);
  const unknownHandling = validateUnknown(root, problems);
  const devDependencies = validateDevDependencies(root, problems);
  const osDependencies = validateOsDependencies(root, problems);
  const document = validateDocument(root, problems);
  const docker = validateDocker(root, problems);
  const cache = validateCache(root, problems);
  const allowSourceAvailable = validateAllowSourceAvailable(root, problems);

  if (problems.length > 0) throw new PolicyError(problems);
  return {
    unknownHandling,
    devDependencies,
    osDependencies,
    suppressedWorkspaces,
    compatible,
    clarify,
    deny,
    allowSourceAvailable,
    ...(document !== undefined ? { document } : {}),
    ...(docker !== undefined ? { docker } : {}),
    ...(cache !== undefined ? { cache } : {}),
  };
}
