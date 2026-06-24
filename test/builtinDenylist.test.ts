import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import {
  BUILTIN_DENY_RULES,
  BUILTIN_DENY_RULE_ID,
} from "../src/policy/builtinDenylist";
import { denyRuleFor } from "../src/policy/denylist";
import type { Policy } from "../src/policy/schema";

// A minimal policy with no consumer rules — proves the defaults fire on their own.
const EMPTY_POLICY: Policy = {
  unknownHandling: "warn",
  devDependencies: "warn",
  osDependencies: "warn",
  suppressedWorkspaces: [],
  compatible: [],
  clarify: [],
  deny: [],
};

// The same spdx-license-ids data spdx-expression-parse matches against — a typo
// in a shipped deny pattern would never match a parsed leaf and would silently
// ship a default that denies nothing.
const spdxDataDir = join(
  import.meta.dir,
  "..",
  "node_modules",
  "spdx-license-ids",
);
const spdxIds = new Set<string>([
  ...(JSON.parse(
    readFileSync(join(spdxDataDir, "index.json"), "utf8"),
  ) as string[]),
  ...(JSON.parse(
    readFileSync(join(spdxDataDir, "deprecated.json"), "utf8"),
  ) as string[]),
]);

describe("builtin source-available deny defaults", () => {
  test("every shipped pattern is a registered SPDX id", () => {
    for (const rule of BUILTIN_DENY_RULES) {
      expect(rule.match).toBe("license");
      expect(spdxIds.has(rule.pattern)).toBe(true);
    }
  });

  test("a source-available license is denied with NO policy authored", () => {
    for (const rule of BUILTIN_DENY_RULES) {
      const hit = denyRuleFor(EMPTY_POLICY, rule.pattern, "some-pkg");
      expect(hit).toBeDefined();
      expect(hit?.ruleId).toBe(BUILTIN_DENY_RULE_ID);
    }
  });

  test("a permissive license is never denied by the defaults", () => {
    for (const expr of ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]) {
      expect(denyRuleFor(EMPTY_POLICY, expr, "some-pkg")).toBeUndefined();
    }
  });

  test("an OR finding with a permissive electable branch is NOT denied", () => {
    expect(
      denyRuleFor(EMPTY_POLICY, "MIT OR BUSL-1.1", "some-pkg"),
    ).toBeUndefined();
  });

  test("an OR finding denied on every branch IS denied (union across builtins)", () => {
    const hit = denyRuleFor(EMPTY_POLICY, "BUSL-1.1 OR SSPL-1.0", "some-pkg");
    expect(hit).toBeDefined();
    expect(hit?.ruleId).toBe(BUILTIN_DENY_RULE_ID);
  });

  test("a consumer [[deny]] for the same license wins attribution (denied[i])", () => {
    const policy: Policy = {
      ...EMPTY_POLICY,
      deny: [
        {
          match: "license",
          pattern: "BUSL-1.1",
          allowlist: ["BUSL-1.1"],
          reason: "consumer-authored",
        },
      ],
    };
    const hit = denyRuleFor(policy, "BUSL-1.1", "some-pkg");
    expect(hit?.ruleId).toBe("denied[0]");
  });
});
