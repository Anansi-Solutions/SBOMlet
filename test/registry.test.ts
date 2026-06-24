/**
 * Dispatch-table tests for the collector registry — the one genuinely new
 * seam of the collectors refactor. Locks three properties:
 *
 * - exhaustiveness: every LockfileKind has a registration, so a discovered
 *   target can never fall through the dispatch;
 * - tool identity: the name@version each registration reports is exactly
 *   what the CLI's loop-owned "collecting <id> via <tool>" stderr line
 *   prints today (the locked stderr contract);
 * - yarn routing: the yarn collector selects plugin-vs-cdxgen from the
 *   LOCKFILE CONTENT (Yarn 4+ `__metadata.version >= 8` routes to the
 *   plugin; pre-4, empty, or unparseable text routes to cdxgen).
 */

import { describe, expect, test } from "bun:test";

import { BUN_COLLECTOR_TOOL } from "../src/collectors/bunLock";
import { CDXGEN_TOOL } from "../src/collectors/cdxgen";
import { collectors } from "../src/collectors/registry";
import { TERRAFORM_COLLECTOR_TOOL } from "../src/collectors/terraform";
import { YARN_PLUGIN_TOOL } from "../src/collectors/yarnPlugin";
import type { LockfileKind } from "../src/targets/discover";

/**
 * Every LockfileKind value. The explicit type annotation keeps this list
 * honest: a new union member makes the exhaustiveness test the place where
 * a missing registration surfaces.
 */
const ALL_KINDS: readonly LockfileKind[] = [
  "yarn",
  "npm",
  "pnpm",
  "bun",
  "poetry",
  "uv",
  "terraform",
];

/** Minimal Yarn 4+ lockfile head: `__metadata.version: 8` → plugin. */
const YARN_V8_LOCKFILE = [
  "__metadata:",
  "  version: 8",
  "  cacheKey: 10c0",
  "",
].join("\n");

/** Minimal Yarn 3 lockfile head: `__metadata.version: 6` → cdxgen. */
const YARN_V6_LOCKFILE = [
  "__metadata:",
  "  version: 6",
  "  cacheKey: 8",
  "",
].join("\n");

describe("collector registry", () => {
  test("registers a collector for every LockfileKind (exhaustive)", () => {
    for (const kind of ALL_KINDS) {
      expect(collectors.get(kind)).toBeDefined();
    }
    expect(collectors.size).toBe(ALL_KINDS.length);
  });

  test("npm, pnpm, poetry, and uv report the cdxgen tool identity", () => {
    for (const kind of ["npm", "pnpm", "poetry", "uv"] as const) {
      expect(collectors.get(kind)?.tool("")).toEqual(CDXGEN_TOOL);
    }
  });

  test("bun reports the in-process bun.lock collector identity", () => {
    expect(collectors.get("bun")?.tool("")).toEqual(BUN_COLLECTOR_TOOL);
  });

  test("terraform reports the in-process terraform collector identity", () => {
    expect(collectors.get("terraform")?.tool("")).toEqual(
      TERRAFORM_COLLECTOR_TOOL,
    );
  });

  test("yarn routes a Yarn 4+ lockfile to the plugin tool identity", () => {
    expect(collectors.get("yarn")?.tool(YARN_V8_LOCKFILE)).toEqual(
      YARN_PLUGIN_TOOL,
    );
  });

  test("yarn routes a pre-4 or unparseable lockfile to the cdxgen identity", () => {
    expect(collectors.get("yarn")?.tool(YARN_V6_LOCKFILE)).toEqual(CDXGEN_TOOL);
    expect(collectors.get("yarn")?.tool("")).toEqual(CDXGEN_TOOL);
    expect(collectors.get("yarn")?.tool("not a lockfile }{ :::")).toEqual(
      CDXGEN_TOOL,
    );
  });
});
