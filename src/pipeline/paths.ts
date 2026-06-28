/**
 * Single-sourced path resolution: cli, pipeline, and gate all anchor
 * user-supplied relative paths here so the resolution rule can never drift.
 */

import { mkdirSync, writeFileSync } from "node:fs";
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

/**
 * Write a committed artifact, creating its parent directory first. The cache dir
 * (e.g. `.sbomlet.cache/`) need not exist on the first generate, and writeFileSync
 * does not create parents, so every committed-artifact write (the enrichment
 * cache, the Docker OS SBOM) routes through here. Idempotent: a recursive mkdir is
 * a no-op when the directory already exists.
 */
export function writeArtifact(path: string, data: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
}
