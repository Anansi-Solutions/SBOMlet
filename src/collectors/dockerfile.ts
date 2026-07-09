/**
 * Dockerfile discovery — a listing-only repo walk.
 *
 * This module answers one narrow question: which Dockerfiles live in a repo
 * tree? It walks the repo root, matches Dockerfile basenames, applies the shared
 * lockfile-discovery exclusion set (node_modules, .git, every dotfile dir incl.
 * .terraform), then the CLI `--exclude` globs, then the `[docker] ignore` globs,
 * and returns the surviving identities deterministically sorted by repo-relative
 * forward-slash path. It reads NO file contents: a Dockerfile is a BUILD INPUT,
 * never an object of analysis — the build-and-analyze lanes hand each discovered
 * identity to the in-tool build step and scan the built image. Zero new
 * dependencies: pure node:fs + the shared glob/exclusion helpers.
 *
 * NAME-PATTERN ONLY: there is no extension blocklist. A blocklist silently DROPS
 * real variants (`Dockerfile.go`/`.py`/`.rs`/`.sh`/`.bak`) — an under-coverage
 * bug — while inconsistently admitting others. EVERY name-pattern match is
 * LISTED: a genuine Dockerfile builds; a stray non-Dockerfile (the tool's own
 * `dockerfile.ts`, a consumer's `dockerfile.md`) is never silently dropped — it
 * either fails the build loudly or is `[docker]`-ignored by policy. The tool's
 * OWN directory is kept out of the walk by the toolDir descent prune
 * (shouldDescendDir), not by a name rule.
 *
 * KNOWN LIMITATIONS (DELIBERATE tradeoffs, documented not changed). The walk
 * does NOT auto-exclude the generic build-output dir names
 * `build`/`out`/`target`/`vendor` (too generic — re-adding them recreates a
 * prior under-coverage finding where real source Dockerfiles were dropped); it
 * does NOT prune nested INDEPENDENT git repos whose `.git` is a DIRECTORY (only
 * the gitlink-FILE submodule case is pruned); and it SKIPS symlinked Dockerfiles
 * (anti-cycle / no escape from repoRoot). A consumer that vends non-submodule
 * third-party trees under such dirs excludes them explicitly via the `[docker]
 * ignore` policy globs or the CLI `--exclude` flag.
 */

import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { compareCodeUnits } from "../model/dependencies";
import {
  DOCKERFILE_DOT_DIR_ALLOWLIST,
  globToRegExp,
  isExcluded,
  shouldDescendDir,
} from "../targets/discover";

/** A discovered Dockerfile: its repo-relative identity and absolute path. */
export interface DiscoveredDockerfile {
  /** Repo-relative forward-slash path, e.g. "backend/Dockerfile". */
  identity: string;
  /** Absolute filesystem path. */
  path: string;
}

export interface DiscoverDockerfilesOptions {
  /** Absolute path of this tool's own directory (excluded from the walk). */
  toolDir?: string;
  /** Repeatable --exclude globs, matched against the identity. */
  excludes?: readonly string[];
  /** `[docker] ignore` globs, matched against the identity. */
  dockerIgnore?: readonly string[];
}

export interface DiscoverDockerfilesResult {
  dockerfiles: DiscoveredDockerfile[];
  /**
   * Repo-relative identities of Dockerfiles EXCLUDED by a `[docker] ignore`
   * glob — deterministically sorted. (Files excluded by the shared descent
   * predicate or by `--exclude` are NOT listed here; only the policy-driven
   * ignores, which are the user-meaningful "I deliberately excluded this"
   * signal the summary surfaces.)
   */
  ignored: string[];
}

/**
 * True iff `name` is a Dockerfile basename. Accepts (case-insensitive on the
 * `Dockerfile`/`dockerfile` stem):
 *   - exactly `Dockerfile`
 *   - `<prefix>.Dockerfile`  (e.g. nginx.Dockerfile)
 *   - `Dockerfile.<suffix>`  (e.g. Dockerfile.prod, Dockerfile.go) — ANY suffix
 *   - `<prefix>.dockerfile`  (e.g. build.dockerfile)
 * A file merely CONTAINING "dockerfile" (e.g. notADockerfile.txt) is NOT matched.
 *
 * NAME-PATTERN ONLY: there is no extension blocklist. A blocklist silently DROPS
 * real variants (`Dockerfile.go`/`.py`/`.rs`/`.sh`/`.bak`) while inconsistently
 * admitting others. Instead, EVERY name-pattern match is LISTED and handed to
 * the build lane; a stray non-Dockerfile fails the build loudly or is
 * `[docker]`-ignored, never silently dropped. The tool's OWN directory is kept
 * out of the walk by the toolDir descent prune, not by a name rule.
 */
export function isDockerfileName(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "dockerfile") return true;
  if (lower.endsWith(".dockerfile")) return true;
  if (lower.startsWith("dockerfile.")) return true;
  return false;
}

/**
 * Walk `repoRoot` and return every non-excluded Dockerfile, deterministically
 * sorted by repo-relative forward-slash identity. NO file contents are read.
 *
 * Exclusion order (each step strictly narrows): the SHARED descent predicate
 * (shouldDescendDir — node_modules/.git/dotfile dirs incl. .terraform/the tool
 * dir) prunes whole subtrees during the walk; then the CLI `--exclude` globs;
 * then the `[docker] ignore` globs. A Dockerfile under any excluded path is
 * never listed.
 */
export function discoverDockerfiles(
  repoRoot: string,
  opts?: DiscoverDockerfilesOptions,
): DiscoverDockerfilesResult {
  const toolDir = opts?.toolDir;
  const excludeMatchers = (opts?.excludes ?? []).map(globToRegExp);
  const ignoreMatchers = (opts?.dockerIgnore ?? []).map(globToRegExp);

  const identityOf = (path: string): string =>
    relative(repoRoot, path).split(sep).join("/");

  const found: DiscoveredDockerfile[] = [];
  const ignored: string[] = [];

  const walk = (dir: string): void => {
    // Symlinks report isDirectory()/isFile() === false on Dirent entries, so
    // they are never followed/read — no cycle traversal, no escape from repoRoot.
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const sub = join(dir, entry.name);
      if (entry.isDirectory()) {
        // Dockerfile lane: pass the dot-dir allowlist so .docker/.devcontainer
        // (conventional Dockerfile homes) are descended while .git/.terraform and
        // every other dot-dir stay pruned.
        if (
          shouldDescendDir(
            sub,
            entry.name,
            toolDir,
            DOCKERFILE_DOT_DIR_ALLOWLIST,
          )
        ) {
          walk(sub);
        }
        continue;
      }
      if (!entry.isFile() || !isDockerfileName(entry.name)) continue;
      const identity = identityOf(sub);
      // --exclude prunes silently (a generic walk filter); a [docker] ignore is
      // a deliberate user exclusion the summary surfaces by name.
      if (isExcluded(identity, excludeMatchers)) continue;
      if (isExcluded(identity, ignoreMatchers)) {
        ignored.push(identity);
        continue;
      }
      found.push({ identity, path: sub });
    }
  };

  walk(repoRoot);
  found.sort((a, b) => compareCodeUnits(a.identity, b.identity));
  ignored.sort(compareCodeUnits);
  return { dockerfiles: found, ignored };
}
