/**
 * Single-sourced path resolution: cli, pipeline, and gate all anchor user-supplied relative paths
 * here so the resolution rule can never drift.
 */

import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";

import { asAbsolutePath, type AbsolutePath } from "../model/dependencies";

/**
 * Resolve one user-supplied path against the invocation base directory: an absolute path passes
 * through unchanged; a relative path anchors to baseDir (itself resolved against cwd when
 * relative); an absent baseDir degrades to plain cwd resolution. Exported for direct unit testing.
 */
export function resolveFrom(baseDir: string | undefined, path: string): AbsolutePath {
  return asAbsolutePath(resolve(process.cwd(), baseDir ?? ".", path));
}

/**
 * The path every symbolic link along it leads to. A path that does not exist yet resolves as far as
 * its deepest existing ancestor, with the segments below it appended: only a segment that exists
 * can lead anywhere. An ancestor that cannot be read leaves the path as it was written.
 */
function linksLeadTo(path: string): string {
  const below: string[] = [];
  let candidate = path;

  for (;;) {
    try {
      return join(realpathSync(candidate), ...below);
    } catch {
      const parent = dirname(candidate);

      if (parent === candidate) {
        return path;
      }

      below.unshift(basename(candidate));
      candidate = parent;
    }
  }
}

/** Whether `path` is `anchor` itself or under it, compared on whole segments. */
function isUnder(anchor: string, path: string): boolean {
  return path === anchor || path.startsWith(anchor + sep);
}

/**
 * {@link resolveFrom}, with the result asserted to be inside `anchor`.
 *
 * @returns the resolved path as written, links and all - never the path they lead to.
 *
 * @throws Error naming `what`, the written path, and where it resolved to, when the resolved path
 * is neither the anchor itself nor under it. Containment is compared on whole path segments, so a
 * sibling directory whose name merely starts with the anchor's is outside it, and on the paths
 * links actually lead to, so a link inside the repository pointing out of it is outside as well.
 *
 * @privateRemarks
 * The policy schema already refuses absolute and drive-lettered paths, so nothing a valid policy
 * can say reaches this. It is the last stop before a read or a write leaves the repository, which
 * is worth a second check that does not depend on the first one staying correct.
 */
export function resolveContained(
  anchor: string | undefined,
  path: string,
  what: string,
): AbsolutePath {
  const base = resolve(process.cwd(), anchor ?? ".");
  const resolved = resolveFrom(anchor, path);
  const target = linksLeadTo(resolved);

  if (!isUnder(linksLeadTo(base), target)) {
    // A path lexically inside its anchor got out through a link: name where it leads.
    const via = isUnder(base, resolved) ? `, a link to ${target}` : "";

    throw new Error(
      `${what}: "${path}" resolves to ${resolved}${via}, outside ${base} - a policy path may never leave the repository`,
    );
  }

  return resolved;
}

/**
 * --notices defaults to THIRD_PARTY_NOTICES.md in the same directory as the output path. Exported
 * for direct unit testing.
 */
export function defaultNoticesPath(outputPath: string): AbsolutePath {
  return asAbsolutePath(join(dirname(outputPath), "THIRD_PARTY_NOTICES.md"));
}

/**
 * Write a committed artifact, creating its parent directory first. The cache dir (e.g.
 * `.sbomlet.cache/`) need not exist on the first generate, and writeFileSync does not create
 * parents, so every committed-artifact write (the enrichment cache, the Docker OS SBOM) routes
 * through here. Idempotent: a recursive mkdir is a no-op when the directory already exists.
 */
export function writeArtifact(path: string, data: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
}
