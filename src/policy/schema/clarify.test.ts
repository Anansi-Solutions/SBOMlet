import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import {
  expectPolicyError,
  clarifyFixture,
  DEMO_CLARIFY,
  clarifyWithout,
} from "../../../test/policyTestSupport";
import { canon } from "../../../test/brandTestSupport";
import { JUSTIFICATION_VALUES } from "./clarify";

describe("parsePolicy — the [[clarify]] package selector", () => {
  test("an exact name parses, and no absent optional key materializes", () => {
    const policy = parsePolicy(clarifyFixture(DEMO_CLARIFY));

    expect(policy.clarify).toEqual([
      {
        identity: { space: "clarify", index: 0 },
        name: "demo-pkg",
        version: "1.0.0",
        detected: { registry: "BSD" },
        justification: "scan-more-precise",
        expression: canon("BSD-3-Clause"),
      },
    ]);
  });

  test("a name pattern parses and is kept verbatim for the shared matcher", () => {
    const policy = parsePolicy(
      clarifyFixture(['pattern = "@cspell/dict-*"', ...clarifyWithout("name")]),
    );

    expect(policy.clarify[0]?.pattern).toBe("@cspell/dict-*");
    expect("name" in (policy.clarify[0] ?? {})).toBe(false);
  });

  test("name AND pattern together is rejected — the selector must be unambiguous", () => {
    const error = expectPolicyError(clarifyFixture(['pattern = "demo-*"', ...DEMO_CLARIFY]));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("must be removed");
  });

  test("neither name nor pattern is rejected", () => {
    const error = expectPolicyError(clarifyFixture(clarifyWithout("name")));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("was missing");
  });

  test("a glob-free pattern is rejected, naming the key to use instead", () => {
    const error = expectPolicyError(
      clarifyFixture(['pattern = "demo-pkg"', ...clarifyWithout("name")]),
    );

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('use "name"');
  });

  test("an anchor-less pattern is rejected — it would cover every package in the model", () => {
    const error = expectPolicyError(clarifyFixture(['pattern = "**"', ...clarifyWithout("name")]));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("at least one literal character");
  });

  test("a version list parses; an empty list is rejected", () => {
    const policy = parsePolicy(
      clarifyFixture([...clarifyWithout("version"), 'version = ["1.0.0", "1.0.1"]']),
    );

    expect(policy.clarify[0]?.version).toEqual(["1.0.0", "1.0.1"]);

    const error = expectPolicyError(clarifyFixture([...clarifyWithout("version"), "version = []"]));

    expect(error.message).toContain("clarify[0].version");
    expect(error.message).toContain("must be a non-empty array of version strings");
  });

  test("a clarify entry omitting version is rejected — there is no os-scope exemption here", () => {
    const error = expectPolicyError(clarifyFixture(clarifyWithout("version")));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('missing required key "version"');
    expect(error.message).not.toContain("container os-scope");
  });
});

describe("parsePolicy — the [[clarify]] `detected` precondition", () => {
  test("both lanes parse, and `false` records that a lane detects nothing", () => {
    const policy = parsePolicy(
      clarifyFixture([
        'name = "demo-pkg"',
        'version = "1.0.0"',
        'detected = { registry = "BSD", intensive = false }',
        'justification = "declared-more-complete"',
        'expression = "BSD-3-Clause"',
      ]),
    );

    expect(policy.clarify[0]?.detected).toEqual({
      registry: "BSD",
      intensive: false,
    });
  });

  test("a missing detected is rejected — every entry states what it was written against", () => {
    const error = expectPolicyError(clarifyFixture(clarifyWithout("detected")));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('missing required key "detected"');
  });

  test("an empty detected table is rejected — at least one lane must be recorded", () => {
    const error = expectPolicyError(
      clarifyFixture(["detected = {}", ...clarifyWithout("detected")]),
    );

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("at least one of registry, intensive");
  });

  test("an unknown detected key is rejected naming the inline table", () => {
    const error = expectPolicyError(
      clarifyFixture(['detected = { guessed = "MIT" }', ...clarifyWithout("detected")]),
    );

    expect(error.message).toContain("clarify[0]: detected");
    expect(error.message).toContain('"guessed"');
  });

  test("`true` is not a detection — only a reported value or `false` is legal", () => {
    const error = expectPolicyError(
      clarifyFixture(["detected = { registry = true }", ...clarifyWithout("detected")]),
    );

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("detected.registry");
  });
});

describe("parsePolicy — the [[clarify]] closed justification set", () => {
  test("an invented value is rejected and the error names the whole set", () => {
    const error = expectPolicyError(
      clarifyFixture(['justification = "because-i-said-so"', ...clarifyWithout("justification")]),
    );

    expect(error.message).toContain("clarify[0]");
    for (const value of JUSTIFICATION_VALUES) {
      expect(error.message).toContain(value);
    }
  });

  test("a missing justification is rejected", () => {
    const error = expectPolicyError(clarifyFixture(clarifyWithout("justification")));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('"justification"');
  });
});

describe("parsePolicy — [[clarify]] evidence and comment", () => {
  test("evidence is recorded verbatim, and a comment parses beside it", () => {
    const policy = parsePolicy(
      clarifyFixture([
        ...DEMO_CLARIFY,
        'evidence = ["node_modules/demo-pkg/LICENSE", "https://example.invalid/license"]',
        'comment = "the file carries the three-clause text"',
      ]),
    );

    expect(policy.clarify[0]?.evidence).toEqual([
      "node_modules/demo-pkg/LICENSE",
      "https://example.invalid/license",
    ]);
    expect(policy.clarify[0]?.comment).toBe("the file carries the three-clause text");
  });

  test("an empty evidence list is rejected — an empty list records nothing", () => {
    const error = expectPolicyError(clarifyFixture([...DEMO_CLARIFY, "evidence = []"]));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("evidence");
  });
});

describe("parsePolicy — a [[clarify]] entry written against the previous schema", () => {
  const REPLACED: ReadonlyArray<[string, string, string]> = [
    ["package", 'package = { name = "demo-pkg" }', '"name"'],
    ["expects", 'expects = "BSD"', "detected"],
    ["reason", 'reason = "confirmed in the LICENSE file"', '"justification"'],
  ];

  for (const [key, line, replacement] of REPLACED) {
    test(`"${key}" is rejected naming its replacement, not as a bare unknown key`, () => {
      const error = expectPolicyError(clarifyFixture([...DEMO_CLARIFY, line]));

      expect(error.message).toContain("clarify[0]");
      expect(error.message).toContain(replacement);
      expect(error.message).toContain("docs/reference/policy.md");
      expect(error.message).not.toContain(`unknown key "${key}"`);
    });
  }

  test("a complete old-shape entry names every replacement in one aggregated error", () => {
    const error = expectPolicyError(
      clarifyFixture([
        'package = { name = "demo-pkg", version = "1.0.0" }',
        'expects = "BSD"',
        'expression = "BSD-3-Clause"',
        'reason = "confirmed in the LICENSE file"',
      ]),
    );

    expect(error.message).toContain('"name"');
    expect(error.message).toContain("detected");
    expect(error.message).toContain('"justification"');
  });
});

// ===========================================================================
// A justification is a claim about what a source reported, so an entry may not
// pair one with a `detected` lane recorded as silent. The invalidity lane
// cannot catch this: it runs only while `detected` still holds, and a lane
// recorded as silent holds by staying silent.
// ===========================================================================

describe("a justification and the detections it speaks for", () => {
  const clarifyWith = (detected: string, justification: string): string =>
    [
      "[[clarify]]",
      'name = "spoken-for"',
      'version = "1.0.0"',
      `detected = ${detected}`,
      `justification = "${justification}"`,
      'expression = "MIT"',
      "",
    ].join("\n");

  test("contradictory-claims-recorded with a silent intensive lane rejects", () => {
    expect(
      expectPolicyError(
        clarifyWith(
          '{ registry = "Dual License", intensive = false }',
          "contradictory-claims-recorded",
        ),
      ).message,
    ).toContain("detected.intensive records that it reports nothing");
  });

  test("contradictory-claims-recorded with a silent registry lane rejects", () => {
    expect(
      expectPolicyError(
        clarifyWith(
          '{ registry = false, intensive = "Apache-2.0" }',
          "contradictory-claims-recorded",
        ),
      ).message,
    ).toContain("detected.registry records that it reports nothing");
  });

  test("declared-more-complete with a silent registry lane rejects", () => {
    expect(
      expectPolicyError(
        clarifyWith('{ registry = false, intensive = "MIT" }', "declared-more-complete"),
      ).message,
    ).toContain("detected.registry records that it reports nothing");
  });

  test("each scan- justification with a silent intensive lane rejects", () => {
    for (const justification of [
      "scan-found-additional-content",
      "scan-more-precise",
      "scan-overdetection",
    ]) {
      expect(
        expectPolicyError(clarifyWith('{ registry = "BSD", intensive = false }', justification))
          .message,
      ).toContain("detected.intensive records that it reports nothing");
    }
  });

  test("license-not-found rejects a recorded value that is itself a licence", () => {
    expect(
      expectPolicyError(clarifyWith('{ registry = "MIT" }', "license-not-found")).message,
    ).toContain('records "MIT", which states MIT');
  });

  test("license-not-found rejects a label the tool reads as a licence", () => {
    expect(
      expectPolicyError(clarifyWith('{ registry = "MIT License" }', "license-not-found")).message,
    ).toContain('records "MIT License", which states MIT');
  });

  test("license-not-found accepts a recorded label that states no licence", () => {
    const policy = parsePolicy(
      clarifyWith('{ registry = "Public Domain", intensive = false }', "license-not-found"),
    );

    expect(policy.clarify[0]?.detected).toEqual({ registry: "Public Domain", intensive: false });
  });

  test("dual-license-choice speaks for no lane, so a silent one is fine", () => {
    const policy = parsePolicy(
      clarifyWith('{ registry = "MIT OR Apache-2.0", intensive = false }', "dual-license-choice"),
    );

    expect(policy.clarify[0]?.justification).toBe("dual-license-choice");
  });

  test("a lane simply left out is not a claim that it is silent", () => {
    expect(() =>
      parsePolicy(clarifyWith('{ registry = "BSD" }', "scan-more-precise")),
    ).not.toThrow();
  });
});
