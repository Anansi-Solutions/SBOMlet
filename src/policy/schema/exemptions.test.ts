import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import { expectPolicyError, suppressionFixture } from "../../../test/policyTestSupport";

describe("parsePolicy — suppression path validation", () => {
  test('empty path is rejected (path = "" would suppress everything)', () => {
    const error = expectPolicyError(suppressionFixture(""));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
  });

  test('".." segments are rejected', () => {
    const error = expectPolicyError(suppressionFixture("apps/../backend"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
  });

  test("backslashes are rejected (forward-slash identities only)", () => {
    const error = expectPolicyError(suppressionFixture("apps\\scratch"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
  });

  test("leading slash is rejected", () => {
    const error = expectPolicyError(suppressionFixture("/apps/scratch"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
  });

  test("trailing slash is rejected", () => {
    const error = expectPolicyError(suppressionFixture("apps/scratch/"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
  });

  test('"." segments are rejected — "apps/./scratch" could never match', () => {
    const error = expectPolicyError(suppressionFixture("apps/./scratch"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain("could never match");
  });

  test('empty segments are rejected — "apps//scratch" could never match', () => {
    const error = expectPolicyError(suppressionFixture("apps//scratch"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain("could never match");
  });

  test('whitespace-padded segments are rejected — "apps /scratch" could never match', () => {
    const error = expectPolicyError(suppressionFixture("apps /scratch"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain("could never match");
  });

  test('a bare "." path is rejected', () => {
    const error = expectPolicyError(suppressionFixture("."));

    expect(error.message).toContain("could never match");
  });

  test('a "docker:"-prefixed path is rejected — a container image is not a workspace', () => {
    const error = expectPolicyError(suppressionFixture("docker:api/Dockerfile"));

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain('"docker:"');
    expect(error.message).toContain("not a workspace");
  });
});

describe("parsePolicy — suppression license must be a single ID (IN-04)", () => {
  test("a compound expression in the license field is rejected with a table path", () => {
    const fixture = [
      "[[workspace.copyleft_suppressed]]",
      'path = "apps/scratch"',
      'license = "MIT OR Apache-2.0"',
      'description = "d"',
    ].join("\n");
    const error = expectPolicyError(fixture);

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain("single SPDX license ID");
  });
});

describe("policy — [[allow_source_available]] validation", () => {
  test("rejects a licence that is not a built-in source-available default", () => {
    const error = expectPolicyError(
      ["[[allow_source_available]]", 'license = "MIT"', 'reason = "x"'].join("\n"),
    );

    expect(error.message).toContain('"BUSL-1.1"');
  });

  test("rejects a missing reason", () => {
    const error = expectPolicyError(
      ["[[allow_source_available]]", 'license = "BUSL-1.1"'].join("\n"),
    );

    expect(error.message).toContain('missing required key "reason"');
  });

  test("accepts a valid exemption", () => {
    expect(() =>
      parsePolicy(
        [
          "[[allow_source_available]]",
          'license = "BUSL-1.1"',
          'reason = "internal-only tool"',
        ].join("\n"),
      ),
    ).not.toThrow();
  });
});
