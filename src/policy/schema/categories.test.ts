import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import { expectPolicyError, licenseRuleFixture } from "../../../test/policyTestSupport";

describe("parsePolicy — [unknown] handling knob", () => {
  test('handling = "ignore" is rejected naming unknown.handling', () => {
    const error = expectPolicyError('[unknown]\nhandling = "ignore"');

    expect(error.message).toContain("unknown.handling");
  });

  test('absent [unknown] table defaults to "warn"', () => {
    const policy = parsePolicy(licenseRuleFixture("MIT"));

    expect(policy.unknownHandling).toBe("warn");
  });
});

describe("dev_dependencies knob — parsing (mirrors unknown.handling)", () => {
  test('absent [dev_dependencies] table defaults to "warn"', () => {
    expect(parsePolicy("").devDependencies).toBe("warn");
  });

  test('handling = "warn" | "fail" | "ignore" parse to themselves', () => {
    for (const value of ["warn", "fail", "ignore"] as const) {
      expect(parsePolicy(`[dev_dependencies]\nhandling = "${value}"`).devDependencies).toBe(value);
    }
  });

  test("an invalid handling value rejects naming dev_dependencies.handling", () => {
    const error = expectPolicyError('[dev_dependencies]\nhandling = "skip"');

    expect(
      error.problems.some(
        (p) =>
          p.includes("dev_dependencies.handling") &&
          ["warn", "fail", "ignore"].every((value) => p.includes(value)),
      ),
    ).toBe(true);
  });

  test("a non-table [dev_dependencies] value rejects", () => {
    const error = expectPolicyError('dev_dependencies = "warn"');

    expect(error.problems.some((p) => p.includes("dev_dependencies: must be a table"))).toBe(true);
  });

  test("a missing handling key rejects", () => {
    const error = expectPolicyError("[dev_dependencies]\nother = 1");

    expect(
      error.problems.some((p) => p.includes('dev_dependencies: missing required key "handling"')),
    ).toBe(true);
  });

  test("an unknown key inside [dev_dependencies] rejects", () => {
    const error = expectPolicyError('[dev_dependencies]\nhandling = "warn"\nbogus = 1');

    expect(error.problems.some((p) => p.includes('dev_dependencies: unknown key "bogus"'))).toBe(
      true,
    );
  });

  test("dev_dependencies is an accepted top-level key (no unknown-key error)", () => {
    expect(() => parsePolicy('[dev_dependencies]\nhandling = "warn"')).not.toThrow();
  });

  test("a genuinely unknown top-level key still rejects", () => {
    const error = expectPolicyError("[bogus_table]\nx = 1");

    expect(error.problems).toContain('unknown top-level key "bogus_table"');
  });
});

describe("os_dependencies knob — parsing (mirrors dev_dependencies EXACTLY)", () => {
  test('absent [os_dependencies] table defaults to "warn"', () => {
    expect(parsePolicy("").osDependencies).toBe("warn");
  });

  test('handling = "warn" | "fail" | "ignore" parse to themselves', () => {
    for (const value of ["warn", "fail", "ignore"] as const) {
      expect(parsePolicy(`[os_dependencies]\nhandling = "${value}"`).osDependencies).toBe(value);
    }
  });

  test("an invalid handling value rejects naming os_dependencies.handling", () => {
    const error = expectPolicyError('[os_dependencies]\nhandling = "skip"');

    expect(
      error.problems.some(
        (p) =>
          p.includes("os_dependencies.handling") &&
          ["warn", "fail", "ignore"].every((value) => p.includes(value)),
      ),
    ).toBe(true);
  });

  test("a non-table [os_dependencies] value rejects", () => {
    const error = expectPolicyError('os_dependencies = "warn"');

    expect(error.problems.some((p) => p.includes("os_dependencies: must be a table"))).toBe(true);
  });

  test("a missing handling key rejects", () => {
    const error = expectPolicyError("[os_dependencies]\nother = 1");

    expect(
      error.problems.some((p) => p.includes('os_dependencies: missing required key "handling"')),
    ).toBe(true);
  });

  test("an unknown key inside [os_dependencies] rejects", () => {
    const error = expectPolicyError('[os_dependencies]\nhandling = "warn"\nbogus = 1');

    expect(error.problems.some((p) => p.includes('os_dependencies: unknown key "bogus"'))).toBe(
      true,
    );
  });

  test("os_dependencies is an accepted top-level key (no unknown-key error)", () => {
    expect(() => parsePolicy('[os_dependencies]\nhandling = "warn"')).not.toThrow();
  });
});
