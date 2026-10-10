import { describe, expect, test } from "bun:test";
import { parsePolicy } from "../parse/parse";
import {
  expectPolicyError,
  compatiblePackageFixture,
  DEMO_COMPATIBLE,
  compatibleWithout,
} from "../../../test/policyTestSupport";

describe("parsePolicy — the [[compatible]] package selector", () => {
  test("an exact name parses into the full rule shape", () => {
    const policy = parsePolicy(compatiblePackageFixture(DEMO_COMPATIBLE));

    expect(policy.compatible).toEqual([
      {
        match: "package",
        name: "demo-pkg",
        version: "1.0.0",
        asDependencyOf: ["self"],
        rationale: "build-time-only",
        where: ["/"],
      },
    ]);
  });

  test("a name pattern covers a family, and is kept verbatim for the shared matcher", () => {
    const policy = parsePolicy(
      compatiblePackageFixture(['pattern = "@img/sharp-*"', ...compatibleWithout("name")]),
    );

    expect(policy.compatible[0]).toMatchObject({ pattern: "@img/sharp-*" });
    expect("name" in (policy.compatible[0] ?? {})).toBe(false);
  });

  test("name AND pattern together, and neither, are both rejected", () => {
    const both = expectPolicyError(
      compatiblePackageFixture(['pattern = "demo-*"', ...DEMO_COMPATIBLE]),
    );
    const neither = expectPolicyError(compatiblePackageFixture(compatibleWithout("name")));

    for (const error of [both, neither]) {
      expect(error.message).toContain("compatible[0]");
      expect(error.message).toContain("exactly one selector");
    }
  });

  test("a glob-free pattern names the key to use instead; an anchor-less one is refused outright", () => {
    const globFree = expectPolicyError(
      compatiblePackageFixture(['pattern = "demo-pkg"', ...compatibleWithout("name")]),
    );
    const anchorLess = expectPolicyError(
      compatiblePackageFixture(['pattern = "**"', ...compatibleWithout("name")]),
    );

    expect(globFree.message).toContain('use "name"');
    expect(anchorLess.message).toContain("at least one literal character");
  });

  test("a version list parses; an empty list is rejected", () => {
    const policy = parsePolicy(
      compatiblePackageFixture([...compatibleWithout("version"), 'version = ["1.0.0", "2.0.0"]']),
    );

    expect(policy.compatible[0]).toMatchObject({ version: ["1.0.0", "2.0.0"] });

    const error = expectPolicyError(
      compatiblePackageFixture([...compatibleWithout("version"), "version = []"]),
    );

    expect(error.message).toContain("compatible[0].version");
    expect(error.message).toContain("must be a non-empty array of version strings");
  });

  test("a name/pattern entry outside container scope must pin a version", () => {
    const error = expectPolicyError(compatiblePackageFixture(compatibleWithout("version")));

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('missing required key "version"');
    expect(error.message).toContain("container os-scope");
  });

  test('a version-less entry scoped entirely to a "docker:" os-scope is accepted (the exemption)', () => {
    const policy = parsePolicy(
      compatiblePackageFixture([
        ...compatibleWithout("version").filter((line) => !line.startsWith("where =")),
        'where = ["docker:examples/docker-scan/Dockerfile"]',
      ]),
    );

    expect(policy.compatible[0]).toMatchObject({ name: "demo-pkg" });
    expect("version" in (policy.compatible[0] ?? {})).toBe(false);
  });

  test('a version-less entry with a MIXED "where" (one non-docker element) is still rejected', () => {
    const error = expectPolicyError(
      compatiblePackageFixture([
        ...compatibleWithout("version").filter((line) => !line.startsWith("where =")),
        'where = ["docker:examples/docker-scan/Dockerfile", "apps/web"]',
      ]),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('missing required key "version"');
  });
});

describe("parsePolicy — the [[compatible]] `packages` list", () => {
  /** A package-form entry carrying the given `packages` array TOML plus the shared fields. */
  const packagesFixture = (packagesToml: string): string =>
    compatiblePackageFixture([
      ...compatibleWithout("name").filter((line) => !line.startsWith("version =")),
      `packages = ${packagesToml}`,
    ]);

  test("a bundle of disparate packages parses, each member pinning its own version", () => {
    const policy = parsePolicy(
      packagesFixture(
        '[{ name = "left-pad", version = "1.3.0" }, { name = "ms", version = ["2.1.3", "2.1.2"] }]',
      ),
    );

    expect(policy.compatible[0]).toMatchObject({
      match: "package",
      packages: [
        { name: "left-pad", version: "1.3.0" },
        { name: "ms", version: ["2.1.3", "2.1.2"] },
      ],
      asDependencyOf: ["self"],
    });
    expect("name" in (policy.compatible[0] ?? {})).toBe(false);
  });

  test("a member missing its version is rejected, naming the member", () => {
    const error = expectPolicyError(packagesFixture('[{ name = "left-pad" }]'));

    expect(error.message).toContain("compatible[0].packages[0]");
    expect(error.message).toContain('missing required key "version"');
  });

  test('"packages" alongside "name" is rejected — exactly one selector mode per entry', () => {
    const error = expectPolicyError(
      compatiblePackageFixture([
        ...compatibleWithout("version"),
        'packages = [{ name = "left-pad", version = "1.3.0" }]',
      ]),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("exactly one selector");
  });

  test("an empty packages list is rejected", () => {
    const error = expectPolicyError(packagesFixture("[]"));

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('"packages"');
  });

  test("a glob name inside a member is rejected, pointing at the pattern selector", () => {
    const error = expectPolicyError(
      packagesFixture('[{ name = "@img/sharp-*", version = "1.0.0" }]'),
    );

    expect(error.message).toContain("compatible[0].packages[0]");
    expect(error.message).toContain("pattern");
  });
});

describe("parsePolicy — the [[compatible]] `as-dependency-of` list", () => {
  test("package names and the reserved self token both parse, in order", () => {
    const policy = parsePolicy(
      compatiblePackageFixture([
        'as-dependency-of = ["build-tool", "self"]',
        ...compatibleWithout("as-dependency-of"),
      ]),
    );

    expect(policy.compatible[0]).toMatchObject({
      asDependencyOf: ["build-tool", "self"],
    });
  });

  test("it is required — an acceptance always states whose use of the package it judged", () => {
    const error = expectPolicyError(
      compatiblePackageFixture(compatibleWithout("as-dependency-of")),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('missing required key "as-dependency-of"');
  });

  test("an empty list is rejected — it would state nothing at all", () => {
    const error = expectPolicyError(
      compatiblePackageFixture(["as-dependency-of = []", ...compatibleWithout("as-dependency-of")]),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("as-dependency-of");
  });

  test("it is not applicable at license level and is rejected there, naming why", () => {
    const error = expectPolicyError(
      [
        "[[compatible]]",
        'match = "license"',
        'pattern = "MPL-2.0"',
        'as-dependency-of = ["self"]',
        'rationale = "license-reviewed"',
        'where = ["/"]',
      ].join("\n"),
    );

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("not applicable at license level");
  });
});
