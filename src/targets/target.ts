/**
 * Target resolution: an explicit `--target <path>` argument becomes a
 * validated Target with a deterministic, forward-slash identity string.
 *
 * The identity contract ("libraries/iframe-rpc" shape) is fixed because it
 * surfaces in rendered output.
 */

import { existsSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

export interface Target {
  /** Resolved absolute path of the target directory. */
  dir: string;
  /**
   * Forward-slash path of the target relative to the enclosing repository
   * root (e.g. "libraries/iframe-rpc"); basename of the directory when no
   * `.git` ancestor exists. NEVER contains backslashes, even on Windows.
   */
  identity: string;
  /**
   * Present ONLY on a yarn workspace scan unit (a collect-loop expansion):
   * the absolute directory holding the governing root yarn.lock
   * and root package.json. Absent means the target itself governs both — every
   * non-yarn-workspace target and every existing constructor leaves this
   * unset, so the cache-key and collector paths they exercise stay
   * byte-unchanged.
   */
  lockfileDir?: string;
  /**
   * Present ONLY on a yarn workspace scan unit: the lock-relative,
   * forward-slash workspace path exactly as `@workspace:` resolved it (e.g.
   * "backend", "libs/a"). Feeds the cache-key discriminator so two
   * workspaces sharing byte-identical manifests never collide.
   */
  workspacePath?: string;
}

/**
 * Walk parent directories looking for a `.git` entry. `existsSync` matches
 * both a `.git` directory and a `.git` file (git worktrees use a file).
 */
function findRepoRoot(startDir: string): string | undefined {
  let current = startDir;
  for (;;) {
    if (existsSync(join(current, ".git"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

export function resolveTarget(targetArg: string, cwd?: string): Target {
  const dir = resolve(cwd ?? process.cwd(), targetArg);

  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    throw new Error(
      `--target "${targetArg}" does not resolve to a directory: ${dir}`,
    );
  }

  // Single-target mode is yarn-only debug mode: a poetry/uv project must fail
  // fast here with the expectation named — not with a misleading
  // missing-manifest message or a downstream ENOENT. Discovery mode
  // (--repo-root) handles poetry/uv targets.
  if (!existsSync(join(dir, "yarn.lock"))) {
    throw new Error(
      `--target only supports yarn projects: "${targetArg}" has no yarn.lock ` +
        `(expected ${join(dir, "yarn.lock")}) — use --repo-root for poetry/uv targets`,
    );
  }
  // The cache key reads both manifest files, so package.json presence is
  // validated up front too.
  if (!existsSync(join(dir, "package.json"))) {
    throw new Error(
      `--target "${targetArg}" is missing package.json: expected ${join(dir, "package.json")}`,
    );
  }

  const repoRoot = findRepoRoot(dir);
  // Identity must be forward-slash on every platform — raw path.relative
  // output contains backslashes on Windows.
  const identity =
    repoRoot === undefined || repoRoot === dir
      ? basename(dir)
      : relative(repoRoot, dir).split(sep).join("/");

  return { dir, identity };
}
