/**
 * Single-sourced path resolution: cli, pipeline, and gate all anchor
 * user-supplied relative paths here so the resolution rule can never drift.
 */

import { dirname, join, resolve } from "node:path";

/**
 * Resolve one user-supplied path against the invocation base directory: an
 * absolute path passes through unchanged; a relative path anchors to baseDir
 * (itself resolved against cwd when relative); an absent baseDir degrades to
 * plain cwd resolution. Exported for direct unit testing.
 */
export function resolveFrom(baseDir: string | undefined, path: string): string {
  return resolve(process.cwd(), baseDir ?? ".", path);
}

/**
 * --notices defaults to THIRD_PARTY_NOTICES.md in the same directory as the
 * output path. Exported for direct unit testing.
 */
export function defaultNoticesPath(outputPath: string): string {
  return join(dirname(outputPath), "THIRD_PARTY_NOTICES.md");
}
