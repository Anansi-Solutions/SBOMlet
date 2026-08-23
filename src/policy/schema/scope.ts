import { win32 } from "node:path";

import { type } from "arktype";

import { DISAMBIGUATOR } from "./arkAdapter";

/** A leading Windows drive specifier: `C:/x`, `C:\\x`, and the drive-relative `C:x` alike. */
const DRIVE_SPECIFIER = /^[A-Za-z]:/;

/**
 * Suppression path rules: forward-slash repo-relative identity prefix. Empty paths are rejected
 * here as an empty segment (an empty prefix would suppress everything); ".." segments, backslashes,
 * and leading/trailing slashes can never appear in target identities, so a path carrying them is a
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
export function pathProblems(path: string): string[] {
  const problems: string[] = [];

  if (DRIVE_SPECIFIER.test(path) || win32.isAbsolute(path)) {
    problems.push(
      `path "${path}" must be repository-relative (an absolute or drive-lettered path names a file outside the repository)`,
    );
  }

  if (path.includes("\\")) {
    problems.push(
      `path "${path}" must use forward slashes only (target identities are forward-slash)`,
    );
  }

  if (path.startsWith("/") || path.endsWith("/")) {
    problems.push(`path "${path}" must not have a leading or trailing slash`);
  }

  const segments = path.split("/");

  if (segments.includes("..")) {
    problems.push(`path "${path}" must not contain ".." segments`);
  }

  if (segments.some((s) => s === "" || s === "." || s !== s.trim())) {
    problems.push(
      `path "${path}" contains an empty, ".", or whitespace-padded segment (it could never match a target identity)`,
    );
  }

  return problems;
}

/**
 * A repo-relative-path field, declaratively. The verbatim text flows through unchanged; each fault
 * {@link pathProblems} finds is rejected on its own disambiguated sub-path so several diagnostics
 * accumulate for the one scalar, exactly as arktype cannot express through chained scalar
 * refinements (which short-circuit at the first failure). Reused by every single-field path/glob
 * the schema carries - the committed-artifact `cache.dir`, a `[docker].ignore` glob, a
 * `[[docker.development]]` source, the `clarifications` file - so the shared segment rules live in
 * ONE construct the field types reference.
 */
export const repoRelativePath = type("string").pipe((value, ctx): string => {
  pathProblems(value).forEach((message, index) =>
    ctx.reject({ relativePath: [`${DISAMBIGUATOR}${index}`], message }),
  );
  return value;
});

/**
 * {@link repoRelativePath} that additionally forbids a leading `docker:` occurrence prefix - the
 * path fields a container occurrence must never name (a workspace suppression, a
 * `[[target.workspace]]` override, a `[[docker.development]]` source). The `docker:` rejection
 * reads in the caller's own terms, so `dockerRejection` supplies the message for the offending
 * value.
 */
export function repoRelativePathRejectingDocker(
  dockerRejection: (path: string) => string,
): typeof repoRelativePath {
  return type("string").pipe((value, ctx): string => {
    pathProblems(value).forEach((message, index) =>
      ctx.reject({ relativePath: [`${DISAMBIGUATOR}${index}`], message }),
    );
    if (value.startsWith("docker:")) {
      ctx.reject({ relativePath: [`${DISAMBIGUATOR}docker`], message: dockerRejection(value) });
    }

    return value;
  });
}

/**
 * The reserved `where` element that scopes an entry to every occurrence. No target identity can be
 * "/" - a leading or trailing slash is rejected wherever a path is validated - so the token is
 * unambiguous, and a deliberately repository-wide entry stays expressible without dropping the
 * scope key.
 */
export const EVERYWHERE_SCOPE = "/";

/**
 * One `where` scope element: the everywhere token {@link EVERYWHERE_SCOPE}, which stands for a
 * deliberately repository-wide acceptance in place of a path, or an occurrence-identity prefix
 * validated exactly like a suppression path (the evaluator applies the same segment-aware prefix
 * comparison to both). A "docker:"-prefixed prefix is legal here - a [[compatible]] `where` scope
 * deliberately targets a container occurrence.
 */
const whereElement = type("string").pipe((value, ctx): string => {
  if (value === EVERYWHERE_SCOPE) {
    return value;
  }

  pathProblems(value).forEach((message, index) =>
    ctx.reject({ relativePath: [`${DISAMBIGUATOR}${index}`], message }),
  );
  return value;
});

/**
 * A `[[compatible]]` entry's `where` scope: a non-empty array of {@link whereElement} prefixes. The
 * emptiness rule is declarative - a rule that could never match anywhere is a dead rule by
 * construction, the same posture as {@link pathProblems}'s could-never-match segments.
 */
export const whereScope = whereElement.array().atLeastLength(1);

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
