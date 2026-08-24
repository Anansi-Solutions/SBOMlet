import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import {
  expectPolicyError,
  licenseRuleFixture,
  DOCKER_ID,
  scopedLicenseFixture,
  scopedPackageFixture,
  compatiblePackageFixture,
  DEMO_COMPATIBLE,
  compatibleWithout,
} from "../../../test/policyTestSupport";
import { RATIONALE_VALUES } from "./compatible";

describe("parsePolicy — compatible pattern decomposition", () => {
  test("OR expression decomposes to sorted leaf allowlist", () => {
    const policy = parsePolicy(licenseRuleFixture("(MIT OR Apache-2.0)"));
    const rule = policy.compatible[0];

    if (rule === undefined || rule.match !== "license") {
      throw new Error("expected a compatible license rule");
    }

    expect(rule.allowlist).toEqual(["Apache-2.0", "MIT"]);
  });

  test("WITH leaf is preserved as a single allowlist entry", () => {
    const policy = parsePolicy(licenseRuleFixture("GPL-2.0-only WITH Classpath-exception-2.0"));
    const rule = policy.compatible[0];

    if (rule === undefined || rule.match !== "license") {
      throw new Error("expected a compatible license rule");
    }

    expect(rule.allowlist).toEqual(["GPL-2.0-only WITH Classpath-exception-2.0"]);
  });

  test("AND pattern is rejected at validation time (satisfies throws on AND allowlists)", () => {
    const error = expectPolicyError(licenseRuleFixture("MIT AND Apache-2.0"));

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("OR of license IDs");
  });
});

describe("parsePolicy — compatible `where` scope", () => {
  test("license form parses with where; the rule carries the array", () => {
    const policy = parsePolicy(scopedLicenseFixture(JSON.stringify([DOCKER_ID])));

    expect(policy.compatible).toEqual([
      {
        match: "license",
        pattern: "MPL-2.0",
        allowlist: ["MPL-2.0"],
        rationale: "license-reviewed",
        where: [DOCKER_ID],
      },
    ]);
  });

  test("package form parses with where (multi-entry) and version pins still work", () => {
    const policy = parsePolicy(
      [
        "[[compatible]]",
        'match = "package"',
        'name = "busybox"',
        'version = "1.37.0"',
        'as-dependency-of = ["self"]',
        'rationale = "license-reviewed"',
        `where = ${JSON.stringify([DOCKER_ID, "docker:other/Dockerfile"])}`,
      ].join("\n"),
    );

    expect(policy.compatible).toEqual([
      {
        match: "package",
        name: "busybox",
        version: "1.37.0",
        asDependencyOf: ["self"],
        rationale: "license-reviewed",
        where: [DOCKER_ID, "docker:other/Dockerfile"],
      },
    ]);
  });

  test("an absent where is rejected on both forms — stating a scope is a decision, not a default", () => {
    for (const form of [
      [
        "[[compatible]]",
        'match = "license"',
        'pattern = "MPL-2.0"',
        'rationale = "license-reviewed"',
      ],
      [
        "[[compatible]]",
        'match = "package"',
        'name = "busybox"',
        'as-dependency-of = ["self"]',
        'rationale = "os-package-unmodified"',
      ],
    ]) {
      const error = expectPolicyError(form.join("\n"));

      expect(error.message).toContain("compatible[0]");
      expect(error.message).toContain('missing required key "where"');
    }
  });

  test("the everywhere token covers every occurrence without dropping the scope key", () => {
    const policy = parsePolicy(scopedLicenseFixture('["/"]'));

    expect(policy.compatible[0]?.where).toEqual(["/"]);
  });

  test("colons in entries pass validation (image refs are legal identities)", () => {
    const policy = parsePolicy(scopedPackageFixture('["docker:node:24-alpine"]'));

    expect(policy.compatible[0]).toMatchObject({
      where: ["docker:node:24-alpine"],
    });
  });

  test("a backslash entry rejects naming compatible[0].where", () => {
    const error = expectPolicyError(scopedLicenseFixture(JSON.stringify(["docker:img\\bad"])));

    expect(error.message).toContain("compatible[0].where[0]");
    expect(error.message).toContain("forward slashes");
  });

  test('a ".." segment rejects naming compatible[0].where', () => {
    const error = expectPolicyError(scopedPackageFixture('["docker:img/../etc"]'));

    expect(error.message).toContain("compatible[0].where[0]");
    expect(error.message).toContain('".." segments');
  });

  test("leading and trailing slashes reject naming compatible[0].where", () => {
    for (const bad of ["/docker:img", "docker:img/"]) {
      const error = expectPolicyError(scopedLicenseFixture(JSON.stringify([bad])));

      expect(error.message).toContain("compatible[0].where[0]");
      expect(error.message).toContain("leading or trailing slash");
    }
  });

  test("an empty segment rejects naming compatible[0].where", () => {
    const error = expectPolicyError(scopedPackageFixture('["docker:img//x"]'));

    expect(error.message).toContain("compatible[0].where[0]");
    expect(error.message).toContain("could never match");
  });

  test("a non-array where rejects naming compatible[0] (both forms)", () => {
    for (const fixture of [scopedLicenseFixture, scopedPackageFixture]) {
      const error = expectPolicyError(fixture('"docker:img"'));

      expect(error.message).toContain("compatible[0]");
      expect(error.message).toContain("where");
    }
  });

  test("a non-string entry rejects naming compatible[0]", () => {
    const error = expectPolicyError(scopedLicenseFixture("[42]"));

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("where[0]");
  });

  test("an EMPTY where array rejects on both forms (a dead rule by construction)", () => {
    for (const fixture of [scopedLicenseFixture, scopedPackageFixture]) {
      const error = expectPolicyError(fixture("[]"));

      expect(error.message).toContain("compatible[0]");
      expect(error.message).toContain("where");
    }
  });

  test('the everywhere token "/" parses on both forms', () => {
    for (const fixture of [scopedLicenseFixture, scopedPackageFixture]) {
      const policy = parsePolicy(fixture('["/"]'));

      expect(policy.compatible[0]).toMatchObject({ where: ["/"] });
    }
  });

  test("the everywhere token is legal alongside ordinary prefixes", () => {
    const policy = parsePolicy(scopedPackageFixture(JSON.stringify(["/", "src"])));

    expect(policy.compatible[0]).toMatchObject({ where: ["/", "src"] });
  });

  test('only the exact string "/" is special: other slash forms still reject', () => {
    for (const bad of ["/src", "src/", "//"]) {
      const error = expectPolicyError(scopedPackageFixture(JSON.stringify([bad])));

      expect(error.message).toContain("compatible[0].where[0]");
      expect(error.message).toContain("leading or trailing slash");
    }
  });

  test("an unknown key alongside where still rejects naming the key", () => {
    const error = expectPolicyError(
      scopedLicenseFixture(JSON.stringify([DOCKER_ID])) + '\nbogus = "x"',
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('"bogus"');
  });
});

describe("parsePolicy — the [[compatible]] closed rationale set", () => {
  test("an invented value is rejected and the error names the whole set", () => {
    const error = expectPolicyError(
      compatiblePackageFixture([
        'rationale = "seems-fine-to-me"',
        ...compatibleWithout("rationale"),
      ]),
    );

    expect(error.message).toContain("compatible[0]");
    for (const value of RATIONALE_VALUES) {
      expect(error.message).toContain(value);
    }
  });

  test("a missing rationale is rejected on both forms", () => {
    const packageForm = expectPolicyError(compatiblePackageFixture(compatibleWithout("rationale")));
    const licenseForm = expectPolicyError(
      ["[[compatible]]", 'match = "license"', 'pattern = "MPL-2.0"', 'where = ["/"]'].join("\n"),
    );

    for (const error of [packageForm, licenseForm]) {
      expect(error.message).toContain("compatible[0]");
      expect(error.message).toContain('"rationale"');
    }
  });
});

describe("parsePolicy — a [[compatible]] entry written against the previous schema", () => {
  test('"reason" is rejected naming its replacement, not as a bare unknown key', () => {
    const error = expectPolicyError(
      compatiblePackageFixture([...DEMO_COMPATIBLE, 'reason = "reviewed and accepted"']),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('"rationale"');
    expect(error.message).toContain("docs/reference/policy.md");
    expect(error.message).not.toContain('unknown key "reason"');
  });

  test("a complete old-shape policy names every migration hint in one aggregated error", () => {
    // Both forms exactly as the previous schema spelled them: a free-text
    // reason, no scope, no parents. Every replacement must be named at once, so
    // one run migrates the whole file.
    const error = expectPolicyError(
      [
        "[[compatible]]",
        'match = "license"',
        'pattern = "MPL-2.0"',
        'reason = "weak copyleft, reviewed"',
        "",
        "[[compatible]]",
        'match = "package"',
        'name = "busybox"',
        'reason = "unmodified base-image package"',
      ].join("\n"),
    );
    const message = error.message;

    expect(message).toContain('compatible[0]: key "reason" was replaced by "rationale"');
    expect(message).toContain('compatible[0]: missing required key "where"');
    expect(message).toContain('compatible[1]: key "reason" was replaced by "rationale"');
    expect(message).toContain('compatible[1]: missing required key "as-dependency-of"');
    expect(message).toContain('compatible[1]: missing required key "where"');
    expect(message).toContain("docs/reference/policy.md");
  });
});
