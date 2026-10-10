import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import { expectPolicyError, licenseRuleFixture } from "../../../test/policyTestSupport";

describe("parsePolicy — mandatory documentation text", () => {
  test('suppression entry missing "description" is rejected', () => {
    const fixture = [
      "[[workspace.copyleft_suppressed]]",
      'path = "apps/scratch"',
      'license = "AGPL-3.0-only"',
    ].join("\n");
    const error = expectPolicyError(fixture);

    expect(error.message).toContain("workspace.copyleft_suppressed[0]");
    expect(error.message).toContain('"description"');
  });

  test("an empty-string rationale does not count as documentation", () => {
    const fixture = [
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = ""',
      'where = ["/"]',
    ].join("\n");
    const error = expectPolicyError(fixture);

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("rationale");
  });
});

// ===========================================================================
// The optional [document] table — author-supplied title +
// preamble for the LICENSES document only. Both keys are OPTIONAL; when present
// each must be a non-empty string. Unknown keys under [document] reject.
// ===========================================================================
describe("parsePolicy — [document] title + preamble", () => {
  test("title + preamble both parse into policy.document", () => {
    const policy = parsePolicy(
      [
        "[document]",
        'title = "Example — Third-Party Licenses"',
        'preamble = "Auto-generated across npm/Python/Terraform/Docker-OS."',
      ].join("\n"),
    );

    expect(policy.document).toEqual({
      title: "Example — Third-Party Licenses",
      preamble: "Auto-generated across npm/Python/Terraform/Docker-OS.",
    });
  });

  test("title-only is valid (preamble absent)", () => {
    const policy = parsePolicy(["[document]", 'title = "Just A Title"'].join("\n"));

    expect(policy.document).toEqual({ title: "Just A Title" });
  });

  test("preamble-only is valid (title absent)", () => {
    const policy = parsePolicy(["[document]", 'preamble = "Just a preamble."'].join("\n"));

    expect(policy.document).toEqual({ preamble: "Just a preamble." });
  });

  test("absent [document] yields undefined", () => {
    const policy = parsePolicy(licenseRuleFixture("MIT"));

    expect(policy.document).toBeUndefined();
  });

  test("an empty [document] table parses to an empty object (both keys optional)", () => {
    const policy = parsePolicy("[document]");

    expect(policy.document).toEqual({});
  });

  test("empty-string title is rejected (must be non-empty when present)", () => {
    const error = expectPolicyError(["[document]", 'title = ""'].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain("title");
  });

  test("non-string title is rejected", () => {
    const error = expectPolicyError(["[document]", "title = 42"].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain("title");
  });

  test("empty-string preamble is rejected", () => {
    const error = expectPolicyError(["[document]", 'preamble = "   "'].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain("preamble");
  });

  test("unknown key under [document] is rejected", () => {
    const error = expectPolicyError(["[document]", 'title = "T"', 'footer = "nope"'].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain('"footer"');
  });

  test("a non-table [document] value is rejected", () => {
    const error = expectPolicyError('document = "not a table"');

    expect(error.message).toContain("document");
  });
});
