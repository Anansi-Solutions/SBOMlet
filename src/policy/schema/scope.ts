import { win32 } from "node:path";

import { stringOf } from "../../validate/record";

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
export function validatePath(path: string, where: string, problems: string[]): void {
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
export function validateWhere(
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
 * True when every `where` element targets a container os-scope. That is the one shape a
 * package-form entry may omit `version` on: a base image's OS-package versions are not
 * author-controlled and change on every rebuild, so pinning them would be churn rather than a
 * guarantee.
 */
export function whereIsEntirelyContainerScope(where: ReadonlyArray<string> | undefined): boolean {
  return (
    where !== undefined && where.length > 0 && where.every((scope) => scope.startsWith("docker:"))
  );
}
