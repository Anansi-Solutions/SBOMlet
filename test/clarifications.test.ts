/**
 * The separate clarifications file: the top-level `clarifications` key, the loader that accepts
 * nothing but `[[clarify]]` tables, and the combination that appends imported entries after the
 * policy's own.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { annotateFindings } from "../src/normalize/normalize";
import { writePolicySummary } from "../src/pipeline/summary";
import { buildOutputs, resolveCacheDir } from "../src/pipeline/pipeline";
import {
  parseClarifications,
  parseClarificationsAt,
  shadowedClarifications,
  withImportedClarifications,
} from "../src/policy/clarifications";
import { renderMarkdown, type PolicyView } from "../src/render/markdown";
import { parsePolicy, PolicyError } from "../src/policy/schema";
import { claim, modelOf, pkg } from "./normalizeTestSupport";

/** One `[[clarify]]` table naming `name`, recording the registry lane, electing `expression`. */
const clarifyTable = (name: string, expression: string): string =>
  [
    "[[clarify]]",
    `name = ${JSON.stringify(name)}`,
    'detected = { registry = "Public Domain" }',
    'justification = "license-not-found"',
    `expression = ${JSON.stringify(expression)}`,
  ].join("\n");

function expectClarificationsError(text: string): PolicyError {
  let thrown: unknown;

  try {
    parseClarifications(text);
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(PolicyError);
  return thrown as PolicyError;
}

/** The PolicyError parsePolicy raises for `text`. */
function expectPolicyError(text: string): PolicyError {
  let thrown: unknown;

  try {
    parsePolicy(text);
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(PolicyError);
  return thrown as PolicyError;
}

describe("the clarifications key", () => {
  test("a repo-relative path is accepted at top level", () => {
    expect(parsePolicy('clarifications = ".sbomlet.clarifications.toml"').clarifications).toBe(
      ".sbomlet.clarifications.toml",
    );
  });

  test("a policy that declares none carries no path", () => {
    expect(parsePolicy("").clarifications).toBeUndefined();
  });

  test("a nested repo-relative path is accepted", () => {
    expect(parsePolicy('clarifications = "policy/clarifications.toml"').clarifications).toBe(
      "policy/clarifications.toml",
    );
  });

  test("a path escaping the repository rejects", () => {
    expect(
      expectPolicyError('clarifications = "../elsewhere/clarifications.toml"').problems,
    ).toContain(
      'clarifications: path "../elsewhere/clarifications.toml" must not contain ".." segments',
    );
  });

  test("a backslash path rejects", () => {
    expect(expectPolicyError('clarifications = "policy\\\\clarifications.toml"').message).toContain(
      "must use forward slashes only",
    );
  });

  test("an absolute path rejects", () => {
    expect(expectPolicyError('clarifications = "/etc/clarifications.toml"').message).toContain(
      "must not have a leading or trailing slash",
    );
  });

  test("a non-string value rejects", () => {
    expect(expectPolicyError("clarifications = 7").problems).toContain(
      "clarifications: must be a non-empty path string",
    );
  });
});

describe("parseClarifications", () => {
  test("a file of only [[clarify]] tables parses, numbered in its own citation space", () => {
    const rules = parseClarifications(
      [clarifyTable("jsonify", "Unlicense"), clarifyTable("other-pkg", "MIT")].join("\n\n"),
    );

    expect(rules.map((rule) => rule.name)).toEqual(["jsonify", "other-pkg"]);
    expect(rules.map((rule) => rule.identity)).toEqual([
      { space: "clarifications", index: 0 },
      { space: "clarifications", index: 1 },
    ]);
  });

  test("an empty file yields no entries", () => {
    expect(parseClarifications("")).toEqual([]);
  });

  test("a [[compatible]] table rejects, naming the key", () => {
    const error = expectClarificationsError(
      [
        clarifyTable("jsonify", "Unlicense"),
        "",
        "[[compatible]]",
        'match = "license"',
        'pattern = "MIT"',
        'rationale = "license-reviewed"',
        'where = ["/"]',
      ].join("\n"),
    );

    expect(error.problems).toEqual([
      'unknown top-level key "compatible": a clarifications file holds [[clarify]] tables and nothing else',
    ]);
  });

  test("a scalar key rejects, naming the key", () => {
    expect(expectClarificationsError('title = "my clarifications"').problems[0]).toContain(
      'unknown top-level key "title"',
    );
  });

  test("a [unknown] table rejects even beside valid entries", () => {
    const error = expectClarificationsError(
      [clarifyTable("jsonify", "Unlicense"), "", "[unknown]", 'handling = "fail"'].join("\n"),
    );

    expect(error.problems[0]).toContain('unknown top-level key "unknown"');
  });

  test("a malformed entry's problem names its position in this file", () => {
    const error = expectClarificationsError(
      [
        clarifyTable("jsonify", "Unlicense"),
        "",
        "[[clarify]]",
        'name = "broken-pkg"',
        'detected = { registry = "MIT" }',
        'justification = "not-a-justification"',
        'expression = "MIT"',
      ].join("\n"),
    );

    expect(error.problems.some((problem) => problem.startsWith("clarify[1]: "))).toBe(true);
  });

  test("the same validator runs: an entry with no detected record rejects", () => {
    const error = expectClarificationsError(
      [
        "[[clarify]]",
        'name = "jsonify"',
        'justification = "license-not-found"',
        'expression = "Unlicense"',
      ].join("\n"),
    );

    expect(error.problems[0]).toContain("clarify[0]");
  });
});

describe("parseClarificationsAt", () => {
  test("every semantic problem names the file to open", () => {
    let thrown: unknown;

    try {
      parseClarificationsAt("repo/.sbomlet.clarifications.toml", 'title = "nope"');
    } catch (error) {
      thrown = error;
    }

    expect((thrown as PolicyError).problems[0]).toStartWith(
      'repo/.sbomlet.clarifications.toml: unknown top-level key "title"',
    );
  });

  test("a syntax error names the file too", () => {
    let thrown: unknown;

    try {
      parseClarificationsAt("repo/.sbomlet.clarifications.toml", "[[clarify]\n");
    } catch (error) {
      thrown = error;
    }

    expect((thrown as Error).message).toContain("repo/.sbomlet.clarifications.toml");
  });

  test("a valid file passes its entries through unchanged", () => {
    expect(
      parseClarificationsAt("c.toml", clarifyTable("jsonify", "Unlicense")).map(
        (rule) => rule.expression,
      ),
    ).toEqual(["Unlicense"]);
  });
});

describe("combining the two files", () => {
  test("imported entries append after the policy's own, each keeping its own index space", () => {
    const combined = withImportedClarifications(
      parsePolicy(clarifyTable("policy-pkg", "MIT")),
      parseClarifications(
        [clarifyTable("imported-pkg", "Unlicense"), clarifyTable("other-pkg", "0BSD")].join("\n\n"),
      ),
    );

    expect(combined.clarify.map((rule) => rule.name)).toEqual([
      "policy-pkg",
      "imported-pkg",
      "other-pkg",
    ]);
    expect(combined.clarify.map((rule) => rule.identity)).toEqual([
      { space: "clarify", index: 0 },
      { space: "clarifications", index: 0 },
      { space: "clarifications", index: 1 },
    ]);
  });

  test("a name collision resolves to the POLICY entry — first match wins", () => {
    const combined = withImportedClarifications(
      parsePolicy(clarifyTable("jsonify", "Unlicense")),
      parseClarifications(clarifyTable("jsonify", "0BSD")),
    );
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(pkg("jsonify", "0.0.1", [claim("Public Domain", "name")])),
      combined.clarify,
    );

    expect(model.packages[0]!.finding!.expression).toBe("Unlicense");
    expect([...usedClarifyIndices]).toEqual([0]);
  });

  test("an imported entry decides a package the policy says nothing about", () => {
    const combined = withImportedClarifications(
      parsePolicy(clarifyTable("policy-pkg", "MIT")),
      parseClarifications(clarifyTable("jsonify", "0BSD")),
    );
    const { model } = annotateFindings(
      modelOf(pkg("jsonify", "0.0.1", [claim("Public Domain", "name")])),
      combined.clarify,
    );

    expect(model.packages[0]!.finding!.expression).toBe("0BSD");
  });
});

describe("shadowed imported entries", () => {
  const shadowingCase = (): ReturnType<typeof withImportedClarifications> =>
    withImportedClarifications(
      parsePolicy(clarifyTable("jsonify", "Unlicense")),
      parseClarifications(
        [clarifyTable("jsonify", "0BSD"), clarifyTable("elsewhere", "MIT")].join("\n\n"),
      ),
    );

  test("the entry the policy decides ahead of is reported, naming both citations", () => {
    expect(
      shadowedClarifications(
        modelOf(pkg("jsonify", "0.0.1", [claim("Public Domain", "name")])),
        shadowingCase(),
      ),
    ).toEqual([{ shadowing: "clarify[0]", shadowed: "clarifications[0]" }]);
  });

  test("an imported entry no policy entry stands ahead of is not reported", () => {
    expect(
      shadowedClarifications(
        modelOf(pkg("elsewhere", "1.0.0", [claim("Public Domain", "name")])),
        shadowingCase(),
      ),
    ).toEqual([]);
  });
});

describe("an imported entry on the reader-facing surfaces", () => {
  test("the unused-entry warning carries the imported entry's own reason, not an empty one", () => {
    const policy = withImportedClarifications(
      parsePolicy(""),
      parseClarifications(clarifyTable("never-scanned", "Unlicense")),
    );
    const original = process.stderr.write.bind(process.stderr);
    let captured = "";

    process.stderr.write = ((chunk: unknown): boolean => {
      captured += String(chunk);
      return true;
    }) as typeof process.stderr.write;
    try {
      writePolicySummary(policy, [], new Set());
    } finally {
      process.stderr.write = original;
    }

    expect(captured).toContain(
      "policy warning: unused entry clarifications[0] — license-not-found\n",
    );
  });

  test("a fail on an imported entry rows in the Problematic roll-up like any other", () => {
    const { model } = annotateFindings(
      modelOf(pkg("choice-lib", "1.0.0", [claim("MIT", "spdx-id")])),
      [],
    );
    const view: PolicyView = {
      policyPath: "policy.toml",
      suppressedWorkspaces: [],
      verdicts: [
        {
          purl: "pkg:npm/choice-lib@1.0.0",
          occurrenceTarget: "frontend",
          status: "fail",
          rule: "clarifications:invalid[0]",
          reason: 'INVALID justification on "choice-lib@1.0.0"',
        },
      ],
    };
    const markdown = renderMarkdown(model, view);

    expect(markdown).toContain("## Problematic licenses");
    // The Rule cell escapes brackets, as it does for every other id shape.
    expect(markdown.slice(markdown.indexOf("## Problematic licenses"))).toContain(
      "| fail | clarifications:invalid\\[0\\] | choice-lib |",
    );
  });
});

describe("the pipeline's clarifications read", () => {
  test("a policy naming a file that is not there fails, naming both files", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-clarifications-"));
    const policyPath = join(root, ".sbomlet.policy.toml");

    writeFileSync(policyPath, 'clarifications = "clarifications.toml"\n');

    let thrown: unknown;

    try {
      await buildOutputs({
        repoRoot: root,
        baseDir: root,
        policyPath,
        outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
        noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
        verbose: false,
      });
    } catch (error) {
      thrown = error;
    }

    const message = (thrown as Error).message;

    expect(message).toContain(policyPath);
    expect(message).toContain(join(root, "clarifications.toml"));
  });

  test("the docker SBOM pre-read still reads only [cache] dir, never the new key", () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-clarifications-"));
    const policyPath = join(root, ".sbomlet.policy.toml");

    writeFileSync(policyPath, 'clarifications = "not-there.toml"\n[cache]\ndir = "artifacts"\n');

    expect(resolveCacheDir({ baseDir: root, repoRoot: root, policyPath })).toBe(
      join(root, "artifacts"),
    );
  });

  test("a malformed clarifications file fails before any scan, naming that file", async () => {
    const root = mkdtempSync(join(tmpdir(), "licenses-clarifications-"));
    const policyPath = join(root, ".sbomlet.policy.toml");
    const clarificationsPath = join(root, "clarifications.toml");

    writeFileSync(policyPath, 'clarifications = "clarifications.toml"\n');
    writeFileSync(clarificationsPath, '[unknown]\nhandling = "fail"\n');

    let thrown: unknown;

    try {
      await buildOutputs({
        repoRoot: root,
        baseDir: root,
        policyPath,
        outputPath: join(root, "THIRD_PARTY_LICENSES.md"),
        noticesPath: join(root, "THIRD_PARTY_NOTICES.md"),
        verbose: false,
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(PolicyError);
    expect((thrown as PolicyError).problems[0]).toStartWith(`${clarificationsPath}: `);
  });
});
