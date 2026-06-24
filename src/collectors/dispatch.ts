/**
 * Pure generator dispatch + empty-lockfile classification.
 *
 * Decides which JS generator scans a yarn target from the lockfile content
 * alone — never from the package-manager pin field in package.json:
 * `__metadata.version >= 8` (Yarn 4+ lockfiles) routes to the yarn-plugin
 * adapter; version 6 (Yarn 3 — the plugin hard-fails: "expected yarn version
 * >= 4"), empty, or unparseable lockfiles route to cdxgen. Dispatch never
 * throws.
 *
 * poetry.lock and uv.lock both map to the python cdxgen path.
 *
 * npm/pnpm/bun all map to the js ecosystem. npm and pnpm route through the
 * cdxgen adapter; bun targets are collected by the custom bun.lock collector
 * but reuse the same manifest list for cache-key framing.
 *
 * Pure functions, no I/O: the caller reads the lockfile text once and passes
 * it in. Parsing is regex over text lines — no YAML parser, no eval — so
 * malicious lockfile content can at worst select the wrong (still
 * sandbox-equivalent) generator, never execute.
 */

import type { LockfileKind } from "../targets/discover";

export type JsGenerator = "yarn-plugin" | "cdxgen";

/** Only the head of the lockfile is consulted; `__metadata` is always first. */
const HEAD_LINES = 20;

/**
 * Select the JS generator from raw yarn.lock text.
 *
 * Scans only the first ~20 lines for a top-level `__metadata:` line
 * (optionally quoted), then reads `version: <int>` inside its indented block.
 * Only the `__metadata` block is consulted — an indented `version: 8` line
 * inside a package entry can never trigger plugin dispatch. Anything
 * unparseable degrades to "cdxgen".
 */
export function selectJsGenerator(lockfileText: string): JsGenerator {
  const lines = lockfileText.split(/\r?\n/, HEAD_LINES);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] as string;
    if (!/^"?__metadata"?:\s*$/.test(line)) {
      continue;
    }
    // Inside the __metadata block: indented lines only; the block ends at
    // the first non-indented line (the next top-level entry).
    for (let j = i + 1; j < lines.length; j += 1) {
      const inner = lines[j] as string;
      if (!/^[ \t]/.test(inner)) {
        break;
      }
      const match = /^[ \t]+version:[ \t]*(\d+)[ \t]*$/.exec(inner);
      if (match !== null) {
        return Number(match[1]) >= 8 ? "yarn-plugin" : "cdxgen";
      }
    }
    return "cdxgen"; // __metadata block without a parseable version
  }
  return "cdxgen"; // no __metadata block (empty, garbage, Yarn 1, ...)
}

/**
 * A lockfile is "empty" when it contains no non-whitespace bytes (e.g. a
 * 0-byte yarn.lock placeholder). Empty lockfiles are the warn+skip case
 * (wired by the CLI). A non-empty lockfile whose scan yields zero components
 * is instead the hard-error case — that distinction is decided by the CLI,
 * not here.
 */
export function isLockfileEmpty(lockfileText: string): boolean {
  return lockfileText.trim().length === 0;
}

/**
 * Lockfile kind → ecosystem. The Ecosystem RETURN type stays inline on
 * purpose — this module must not import it from cdxgen.ts; TypeScript
 * structural typing connects them at the CLI. The parameter, however, is
 * exactly LockfileKind, so it is imported rather than re-spelled.
 */
export function ecosystemFor(kind: LockfileKind): "js" | "python" {
  switch (kind) {
    case "yarn":
    case "npm":
    case "pnpm":
    case "bun":
      return "js";
    case "poetry":
    case "uv":
      return "python";
    case "terraform":
      // Terraform targets never route through the cdxgen ecosystem dispatch —
      // the in-process terraform collector computes its own cache key directly
      // (the bun.lock precedent). ecosystemFor stays js|python; reaching here
      // is a wiring bug, not a normal path.
      throw new Error(
        "terraform targets are collected in-process and have no cdxgen ecosystem",
      );
  }
}

/**
 * Lockfile kind → manifest files hashed into the scan cache key. uv takes the
 * same adapter path and cache-key shape as poetry.
 */
export function manifestFilesFor(kind: LockfileKind): readonly string[] {
  switch (kind) {
    case "yarn":
      return ["yarn.lock", "package.json"];
    case "npm":
      return ["package-lock.json", "package.json"];
    case "pnpm":
      // pnpm-workspace.yaml is deliberately not hashed into the cache key —
      // the file is optional in pnpm projects and computeCacheKey throws on
      // missing manifests. Components are lockfile-determined; only
      // workspace-attribution properties could shift, and a
      // pnpm-workspace.yaml edit without a lockfile change cannot alter the
      // emitted component set.
      return ["pnpm-lock.yaml", "package.json"];
    case "bun":
      return ["bun.lock", "package.json"];
    case "poetry":
      return ["poetry.lock", "pyproject.toml"];
    case "uv":
      return ["uv.lock", "pyproject.toml"];
    case "terraform":
      // Only the lock is hashed into the cache key. modules.json is gitignored
      // and absent until init runs (its presence is the loud-fail gate, not a
      // cache input); a re-init that changes resolved module versions also
      // rewrites the lock, so the lock byte-hash is a sufficient cache framing.
      return [".terraform.lock.hcl"];
  }
}
