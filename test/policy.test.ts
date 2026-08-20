import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { TomlError } from "smol-toml";
import parseSpdxId from "spdx-expression-parse";

import {
  annotateFindings,
  normalizeRaw,
  type BuiltinOverrideInput,
} from "../src/normalize/normalize";
import {
  acceptedContainerNotices,
  evaluate,
  unnecessaryClarifyEntries,
  unusedRuleIds,
} from "../src/policy/evaluate";
import { parseClarifications, withImportedClarifications } from "../src/policy/clarifications";
import { BUILTIN_DENY_RULES } from "../src/policy/builtinDenylist";
import { denyRuleFor } from "../src/policy/denylist";
import { AGPL_IDS, COPYLEFT_IDS } from "../src/policy/copyleft";
import { COULD_BE_COPYLEFT_FAMILIES, WORKSPACE_ABSORBS } from "../src/policy/copyleftFamily";
import { BUILTIN_OVERRIDES } from "../src/policy/builtinOverrides";
import { JUSTIFICATION_VALUES, RATIONALE_VALUES } from "../src/policy/enums";
import { parsePolicy, PolicyError, type Policy } from "../src/policy/schema";
import type {
  CanonicalDependencies,
  DependencyIntroduction,
  LicenseClaimKind,
  LicenseFinding,
  Verdict,
} from "../src/model/dependencies";

/** No scanned target in these scenarios is collected by a lane that derives a dependency graph. */
const WITHOUT_DEPENDENCY_GRAPHS: ReadonlySet<string> = new Set();

// Inline TOML fixtures (dispatch.test.ts idiom) — each one is commented with
// the trap it encodes. Policy text is untrusted config: schema validation
// must reject loudly with table-path errors, never skip.

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

/** Minimal policy with a single compatible license rule for `pattern`. */
const licenseRuleFixture = (pattern: string): string =>
  [
    "[[compatible]]",
    'match = "license"',
    `pattern = ${JSON.stringify(pattern)}`,
    'rationale = "license-reviewed"',
    'where = ["/"]',
  ].join("\n");

/** Minimal policy with a single suppression entry for `path`. */
const suppressionFixture = (path: string): string =>
  [
    "[[workspace.copyleft_suppressed]]",
    `path = ${JSON.stringify(path)}`,
    'license = "AGPL-3.0-only"',
    'description = "test description"',
  ].join("\n");

const SUPPRESSION_DESCRIPTION =
  "Workspace is itself distributed under AGPL-3.0; in-family copyleft is fine.";
const MPL_COMMENT = "Weak copyleft; compatible under AGPL-3.0 and Apache License v2.0";
const SHARP_COMMENT = "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; LGPL obligations accepted.";
const CLARIFY_COMMENT = "Upstream declares Public Domain; mapped to Unlicense deliberately.";

// Happy path: every table class present, exercising the full locked TOML
// surface.
const VALID_POLICY = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  `description = ${JSON.stringify(SUPPRESSION_DESCRIPTION)}`,
  "",
  "[[compatible]]",
  'match = "license"',
  'pattern = "MPL-2.0"',
  'rationale = "license-reviewed"',
  'where = ["/"]',
  `comment = ${JSON.stringify(MPL_COMMENT)}`,
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "@img/sharp-win32-x64"',
  'version = "0.34.5"',
  'as-dependency-of = ["self"]',
  'rationale = "license-reviewed"',
  'where = ["/"]',
  `comment = ${JSON.stringify(SHARP_COMMENT)}`,
  "",
  "[[clarify]]",
  'name = "jsonify"',
  'version = "0.0.1"',
  'detected = { registry = "Public Domain", intensive = false }',
  'justification = "license-not-found"',
  'expression = "Unlicense"',
  `comment = ${JSON.stringify(CLARIFY_COMMENT)}`,
  "",
  "[unknown]",
  'handling = "fail"',
].join("\n");

describe("parsePolicy — happy path", () => {
  test("full fixture parses into the exact Policy shape", () => {
    const policy = parsePolicy(VALID_POLICY);

    expect(policy.unknownHandling).toBe("fail");
    expect(policy.suppressedWorkspaces).toEqual([
      {
        path: "apps/scratch",
        license: "AGPL-3.0-only",
        description: SUPPRESSION_DESCRIPTION,
      },
    ]);
    expect(policy.compatible).toEqual([
      {
        match: "license",
        pattern: "MPL-2.0",
        allowlist: ["MPL-2.0"],
        rationale: "license-reviewed",
        where: ["/"],
        comment: MPL_COMMENT,
      },
      {
        match: "package",
        name: "@img/sharp-win32-x64",
        version: "0.34.5",
        asDependencyOf: ["self"],
        rationale: "license-reviewed",
        where: ["/"],
        comment: SHARP_COMMENT,
      },
    ]);
    expect(policy.clarify).toEqual([
      {
        identity: { space: "clarify", index: 0 },
        name: "jsonify",
        version: "0.0.1",
        detected: { registry: "Public Domain", intensive: false },
        justification: "license-not-found",
        expression: "Unlicense",
        comment: CLARIFY_COMMENT,
      },
    ]);
  });
});

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

// ===========================================================================
// The REQUIRED `where` scope on BOTH [[compatible]] forms — an array of
// occurrence-identity prefixes, each validated like a suppression path, or the
// reserved everywhere token. Empty arrays reject (a rule that can never match
// anywhere is a dead rule by construction).
// ===========================================================================

const DOCKER_ID = "docker:examples/docker-scan/Dockerfile";

/** License-form compatible rule with a raw TOML `where` clause. */
const scopedLicenseFixture = (whereToml: string): string =>
  [
    "[[compatible]]",
    'match = "license"',
    'pattern = "MPL-2.0"',
    'rationale = "license-reviewed"',
    `where = ${whereToml}`,
  ].join("\n");

/** Package-form compatible rule with a raw TOML `where` clause. */
const scopedPackageFixture = (whereToml: string): string =>
  [
    "[[compatible]]",
    'match = "package"',
    'name = "busybox"',
    'version = "1.37.0"',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    `where = ${whereToml}`,
  ].join("\n");

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
      expect(error.message).toContain('"where"');
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
      expect(error.message).toContain('"where"');
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

// ===========================================================================
// The [[compatible]] schema: the package selector, the required
// `as-dependency-of` list, the closed rationale set, and the pointed errors an
// entry written against the previous schema gets.
// ===========================================================================

/** A package-form [[compatible]] entry built from the given key lines. */
const compatiblePackageFixture = (lines: ReadonlyArray<string>): string =>
  ["[[compatible]]", 'match = "package"', ...lines].join("\n");

/** A minimal valid package-form entry. */
const DEMO_COMPATIBLE = [
  'name = "demo-pkg"',
  'version = "1.0.0"',
  'as-dependency-of = ["self"]',
  'rationale = "build-time-only"',
  'where = ["/"]',
];

/** DEMO_COMPATIBLE without the line starting with `key`. */
const compatibleWithout = (key: string): string[] =>
  DEMO_COMPATIBLE.filter((line) => !line.startsWith(`${key} =`));

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

    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('"version"');
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

describe("evaluate — a [[compatible]] entry covering a family of packages", () => {
  test("HEADLINE: one pattern entry accepts every matching package, each citing the same entry", () => {
    const policyText = compatiblePackageFixture([
      'pattern = "@img/sharp-*"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const { verdicts } = runEngine(
      [
        pkgSpec("@img/sharp-win32-x64", "LGPL-3.0-or-later", ["backend"]),
        pkgSpec("@img/sharp-linux-arm64", "LGPL-3.0-or-later", ["backend"]),
      ],
      policyText,
    );

    for (const verdict of verdicts) {
      expect(verdict.status).toBe("ok");
      expect(verdict.rule).toBe("compatible[0]");
    }

    expect(verdicts[0].reason).toContain('package "@img/sharp-*@1.0.0, 2.0.0"');
    expect(verdicts[0].reason).toContain("license-reviewed");
  });

  test("a package outside the pattern still fails — the entry covers the family, not the model", () => {
    const policyText = compatiblePackageFixture([
      'pattern = "@img/sharp-*"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const { verdicts } = runEngine(
      [pkgSpec("@other/lib", "LGPL-3.0-or-later", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("a version list accepts exactly the versions it names, and nothing else", () => {
    const policyText = compatiblePackageFixture([
      'name = "pinned-copyleft"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const covered = runEngine(
      [pkgSpec("pinned-copyleft", "LGPL-3.0-or-later", ["backend"], "2.0.0")],
      policyText,
    ).verdicts;
    const uncovered = runEngine(
      [pkgSpec("pinned-copyleft", "LGPL-3.0-or-later", ["backend"], "3.0.0")],
      policyText,
    ).verdicts;

    expect(covered[0].rule).toBe("compatible[0]");
    expect(covered[0].reason).toContain('"pinned-copyleft@1.0.0, 2.0.0"');
    expect(uncovered[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — `as-dependency-of` is recorded, not yet enforced", () => {
  // The list is parsed, validated, and carried onto the rule, and it does not
  // narrow which occurrences the entry decides: the introduction-path walk that
  // reads it lands separately. This test states that gap explicitly so the walk
  // has a place to change when it arrives.
  test("a parent that governs nothing in the model still accepts the package", () => {
    const policyText = compatiblePackageFixture([
      'name = "governed-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["a-package-nothing-depends-on"]',
      'rationale = "unused-transitive"',
      'where = ["/"]',
    ]);
    const { verdicts, policy } = runEngine(
      [pkgSpec("governed-pkg", "LGPL-3.0-or-later", ["backend"])],
      policyText,
    );

    expect(policy.compatible[0]).toMatchObject({
      asDependencyOf: ["a-package-nothing-depends-on"],
    });
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });
});

describe("evaluate — a [[compatible]] `packages` list bundling disparate packages", () => {
  const bundlePolicy = compatiblePackageFixture([
    'packages = [{ name = "alpha-lib", version = "1.0.0" }, { name = "omega-lib", version = "2.5.0" }]',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    'where = ["/"]',
  ]);

  test("an occurrence matching a NON-first member is accepted, citing the one entry", () => {
    const { verdicts } = runEngine(
      [pkgSpec("omega-lib", "LGPL-3.0-or-later", ["backend"], "2.5.0")],
      bundlePolicy,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(verdicts[0].reason).toContain('"omega-lib@2.5.0"');
  });

  test("a member matches only at its pinned version — a version it does not name still fails", () => {
    const { verdicts } = runEngine(
      [pkgSpec("omega-lib", "LGPL-3.0-or-later", ["backend"], "9.9.9")],
      bundlePolicy,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

// ===========================================================================
// The [[clarify]] schema: the package selector, the mandatory `detected`
// precondition, the closed justification set, evidence, and the pointed
// errors an entry written against the previous schema gets.
// ===========================================================================

/** A [[clarify]] entry built from the given key lines. */
const clarifyFixture = (lines: ReadonlyArray<string>): string =>
  ["[[clarify]]", ...lines].join("\n");

/** A minimal valid entry: name, version, one recorded lane, justification, expression. */
const DEMO_CLARIFY = [
  'name = "demo-pkg"',
  'version = "1.0.0"',
  'detected = { registry = "BSD" }',
  'justification = "scan-more-precise"',
  'expression = "BSD-3-Clause"',
];

/** DEMO_CLARIFY without the line starting with `key`, for missing-key cases. */
const clarifyWithout = (key: string): string[] =>
  DEMO_CLARIFY.filter((line) => !line.startsWith(`${key} `) && !line.startsWith(`${key} =`));

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
        expression: "BSD-3-Clause",
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
    expect(error.message).toContain('exactly one of "name" and "pattern"');
  });

  test("neither name nor pattern is rejected", () => {
    const error = expectPolicyError(clarifyFixture(clarifyWithout("name")));

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('exactly one of "name" and "pattern"');
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

    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain('"version"');
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
    expect(error.message).toContain('"evidence"');
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

describe("BUILTIN_OVERRIDES — the shipped tool-level set", () => {
  test("is a non-empty literal array; every entry has name, detected, expression, reason", () => {
    expect(BUILTIN_OVERRIDES.length).toBeGreaterThan(0);
    for (const o of BUILTIN_OVERRIDES) {
      expect(typeof o.name).toBe("string");
      expect(o.name.trim().length).toBeGreaterThan(0);
      expect(Object.keys(o.detected).length).toBeGreaterThan(0);
      expect(typeof o.expression).toBe("string");
      expect(typeof o.reason).toBe("string");
      expect(o.reason.trim().length).toBeGreaterThan(0);
    }
  });

  test("every expression is a valid SPDX expression (typo-proof)", () => {
    for (const o of BUILTIN_OVERRIDES) {
      expect(() => parseSpdxId(o.expression)).not.toThrow();
    }
  });

  test("every expression's leaf ids are real SPDX ids", () => {
    const dataDir = join(import.meta.dir, "..", "node_modules", "spdx-license-ids");
    const current = JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const leafIds: string[] = [];
    const walk = (node: unknown): void => {
      if (typeof node !== "object" || node === null) {
        return;
      }

      const n = node as Record<string, unknown>;

      if (typeof n.license === "string") {
        leafIds.push(n.license);
      }

      walk(n.left);
      walk(n.right);
    };

    for (const o of BUILTIN_OVERRIDES) {
      walk(parseSpdxId(o.expression));
    }

    expect(leafIds.filter((id) => !known.has(id))).toEqual([]);
  });

  test("ships python-dateutil's dual license as a REAL default (BLOCKER-1)", () => {
    const entry = BUILTIN_OVERRIDES.find((o) => o.name === "python-dateutil");

    expect(entry).toBeDefined();
    expect(entry?.detected).toEqual({ registry: "Dual License" });
    expect(entry?.expression).toBe("Apache-2.0 OR BSD-3-Clause");
    // The exact value from CONTEXT.md parses as a valid OR expression.
    const node = parseSpdxId(entry?.expression ?? "") as {
      conjunction?: string;
    };

    expect(node.conjunction).toBe("or");
  });

  test("ships the Jupyter/IPython BSD stack disambiguating the imprecise BSD value (BLOCKER-1)", () => {
    const canonical = [
      "ipython",
      "ipykernel",
      "jupyter-core",
      "jupyter-client",
      "nbformat",
      "traitlets",
    ];

    for (const name of canonical) {
      const entry = BUILTIN_OVERRIDES.find((o) => o.name === name);

      expect(entry).toBeDefined();
      // Records the imprecise BSD value the registry lane produces.
      expect(entry?.detected).toEqual({ registry: "BSD" });
      expect(entry?.expression).toBe("BSD-3-Clause");
    }
  });

  test("does NOT ship copier or jinja2-ansible-filters (Phase-6 project judgment)", () => {
    expect(BUILTIN_OVERRIDES.some((o) => o.name === "copier")).toBe(false);
    expect(BUILTIN_OVERRIDES.some((o) => o.name === "jinja2-ansible-filters")).toBe(false);
  });

  test("keys by package NAME (version optional) so an override survives version bumps", () => {
    // No entry pins a version: a name-only override matches every version of
    // the package as long as upstream keeps reporting the ambiguous value.
    for (const o of BUILTIN_OVERRIDES) {
      expect(o.version).toBeUndefined();
    }
  });
});

describe("parsePolicy — error aggregation", () => {
  test("three independent problems surface in ONE PolicyError, each table-path named", () => {
    // Trap fixture: a typo'd top-level table, a compatible entry missing its
    // mandatory reason, and a clarify expression that is not SPDX.
    const fixture = [
      "[[compatibel]]",
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MIT"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "Apache-2.0"',
      'where = ["/"]',
      "",
      "[[clarify]]",
      'name = "x"',
      'version = "1.0.0"',
      'detected = { registry = "MIT" }',
      'justification = "scan-more-precise"',
      'expression = "not a license"',
    ].join("\n");
    const error = expectPolicyError(fixture);

    expect(error.problems).toHaveLength(3);
    expect(error.message).toContain('"compatibel"');
    expect(error.message).toContain("compatible[1]");
    expect(error.message).toContain('"rationale"');
    expect(error.message).toContain("clarify[0]");
  });
});

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

describe("parsePolicy — TOML syntax errors pass through", () => {
  test("malformed TOML throws smol-toml TomlError with caret context, unwrapped", () => {
    let thrown: unknown;

    try {
      parsePolicy("[unknown");
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(TomlError);
    expect((thrown as TomlError).message).toContain("^");
  });
});

describe("policy.example.toml — the shipped starter contract", () => {
  test("the real file round-trips through parsePolicy with all four rule classes", () => {
    // Read the REAL shipped file from disk — no inline copy. This test locks
    // the example template: it must always parse and validate cleanly.
    const text = readFileSync(join(import.meta.dir, "..", "policy.example.toml"), "utf8");
    const policy = parsePolicy(text);

    expect(policy.suppressedWorkspaces.some((w) => w.path === "apps/scratch")).toBe(true);
    expect(policy.compatible.some((r) => r.match === "license" && r.pattern === "MPL-2.0")).toBe(
      true,
    );
    expect(policy.compatible.some((r) => r.match === "package")).toBe(true);
    expect(policy.clarify.length).toBeGreaterThanOrEqual(1);
    // The example must carry an EXPLICIT [unknown] table (the knob is part
    // of the starter contract, not just the default).
    expect(text).toContain("[unknown]");
    expect(policy.unknownHandling).toBe("warn");
    // The example must carry an EXPLICIT [dev_dependencies] table too.
    expect(text).toContain("[dev_dependencies]");
    expect(policy.devDependencies).toBe("warn");
  });
});

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
    expect(error.message).toContain('"rationale"');
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
    expect(error.message).toContain('"title"');
  });

  test("non-string title is rejected", () => {
    const error = expectPolicyError(["[document]", "title = 42"].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain('"title"');
  });

  test("empty-string preamble is rejected", () => {
    const error = expectPolicyError(["[document]", 'preamble = "   "'].join("\n"));

    expect(error.message).toContain("document");
    expect(error.message).toContain('"preamble"');
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

// ===========================================================================
// Policy engine: evaluate() + unusedRuleIds(). All inputs are hand-built
// CanonicalDependencies literals run through annotateFindings — evaluate is
// pure over the model, no SBOM JSON anywhere.
// ===========================================================================

/** Occurrence spec: a bare string is a prod occurrence in that target. */
type OccurrenceSpec = string | { target: string; dev: boolean };

interface PackageSpec {
  purl: string;
  name: string;
  version: string;
  /** Raw license claim strings; [] = the zero-claim (unknown) population. */
  claims: ReadonlyArray<string>;
  occurrences: ReadonlyArray<OccurrenceSpec>;
  /** Package-level taxonomy; defaults to "app" ("os" routes applyOsScope). */
  scope?: "app" | "os";
  /**
   * A ScanCode-sourced claim raw: appended as a { source: "scancode" }
   * claim so annotateFindings runs applyScancodeAssessment and can attach a
   * conflict marker. Absent = the common quick-check-only case.
   */
  scancode?: string;
  /**
   * A merge-time cross-image claim divergence (mergeSboms' dockerClaimDivergence carrier) —
   * threaded straight onto the built PackageEntry so annotateFindings overlays it exactly as the
   * live pipeline does. Absent = the common no-docker-divergence case.
   */
  dockerClaimDivergence?: {
    target: string;
    claims: readonly string[];
  }[];
}

/**
 * Hand-built CanonicalDependencies literal (merge.test.ts idiom). The claim `kind`
 * is inert in normalization — only `raw` flows through normalizeRaw — so a
 * cosmetic heuristic is enough here.
 */
function makeModel(specs: ReadonlyArray<PackageSpec>): CanonicalDependencies {
  return {
    packages: specs.map((spec) => ({
      purl: spec.purl,
      name: spec.name,
      version: spec.version,
      occurrences: spec.occurrences.map((o) =>
        typeof o === "string"
          ? { target: o, isDevDependency: false }
          : { target: o.target, isDevDependency: o.dev },
      ),
      licenseClaims: [
        ...spec.claims.map((raw) => {
          const kind: LicenseClaimKind =
            raw.includes(" ") || raw.includes("(") ? "expression" : "spdx-id";

          return { raw, kind, source: "generator" as const };
        }),
        ...(spec.scancode !== undefined
          ? [
              {
                raw: spec.scancode,
                kind: "expression" as const,
                source: "scancode" as const,
              },
            ]
          : []),
      ],
      scope: spec.scope ?? "app",
      ...(spec.dockerClaimDivergence !== undefined
        ? {
            dockerClaimDivergence: {
              kind: "cross-image-claims" as const,
              byTarget: spec.dockerClaimDivergence,
            },
          }
        : {}),
    })),
  };
}

/** Shorthand for an OS-scope package (pkg:deb/pkg:apk). */
function osPkgSpec(
  purl: string,
  name: string,
  claim: string | null,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
    scope: "os",
  };
}

/** Shorthand for the common one-package case. */
function pkgSpec(
  name: string,
  claim: string | null,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
  };
}

/**
 * Shorthand for a package carrying a quick-check claim PLUS a scancode claim —
 * the assessment/conflict trigger. `claim === null` means the scancode
 * claim is the only license evidence (the vacuous-agreement case).
 */
function scanPkgSpec(
  name: string,
  claim: string | null,
  scancode: string,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
    scancode,
  };
}

/** parse policy → annotateFindings (clarify + optional builtins) → evaluate. */
function runEngineWith(
  policy: Policy,
  specs: ReadonlyArray<PackageSpec>,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): {
  verdicts: Verdict[];
  usedClarifyIndices: ReadonlySet<number>;
  policy: Policy;
  model: CanonicalDependencies;
} {
  const { model, usedClarifyIndices } = annotateFindings(
    makeModel(specs),
    policy.clarify,
    builtins,
  );

  return {
    verdicts: evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS),
    usedClarifyIndices,
    policy,
    model,
  };
}

function runEngine(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): ReturnType<typeof runEngineWith> {
  return runEngineWith(parsePolicy(policyText), specs, builtins);
}

/** {@link runEngine} over both files, combined exactly as the pipeline combines them. */
function runEngineWithImports(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
  clarificationsText: string,
): ReturnType<typeof runEngineWith> {
  return runEngineWith(
    withImportedClarifications(parsePolicy(policyText), parseClarifications(clarificationsText)),
    specs,
  );
}

/** Suppression-only fixture policy: apps/scratch absorbs copyleft. */
const SUPPRESS_SCRATCH = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  'description = "scratch workspace is itself distributed under AGPL-3.0"',
].join("\n");

describe("evaluate — precedence chain", () => {
  test("compatible(package) beats compatible(license) beats suppression on one package", () => {
    // One MPL-2.0 package matched SIMULTANEOUSLY by compatible[0]
    // (match="package") and compatible[1] (match="license"), occurring in a
    // suppressed workspace: the package rule decides.
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "mpl-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])], policyText);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });
});

describe("evaluate — satisfies-based compatible(license) matching", () => {
  test("exact ID: finding MPL-2.0 vs allowlist [MPL-2.0] is ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["backend"])],
      licenseRuleFixture("MPL-2.0"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("range semantics: GPL-3.0-only satisfies allowlist [GPL-2.0-or-later]", () => {
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["backend"])],
      licenseRuleFixture("GPL-2.0-or-later"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("AND needs all: Apache-2.0 AND LGPL-3.0-or-later vs [Apache-2.0] falls to default:copyleft", () => {
    const { verdicts } = runEngine(
      [pkgSpec("sharp-ish", "Apache-2.0 AND LGPL-3.0-or-later", ["backend"])],
      licenseRuleFixture("Apache-2.0"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — segment-aware suppression", () => {
  test("apps/scratch and apps/scratch/sub suppress; apps/scratch-helper FAILS", () => {
    // Substring matching would wrongly suppress apps/scratch-helper.
    const { verdicts } = runEngine(
      [
        pkgSpec("agpl-pkg", "AGPL-3.0-only", [
          "apps/scratch-helper",
          "apps/scratch/sub",
          "apps/scratch",
        ]),
      ],
      SUPPRESS_SCRATCH,
    );

    // compareCodeUnits order on occurrenceTarget: "-" (0x2D) sorts before "/" (0x2F).
    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "suppressed", "workspace.copyleft_suppressed[0]"],
      ["apps/scratch-helper", "fail", "default:copyleft"],
      ["apps/scratch/sub", "suppressed", "workspace.copyleft_suppressed[0]"],
    ]);
  });
});

describe("evaluate — family-aware suppression", () => {
  test("same-license dep is suppressed; the reason states the satisfies relationship", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
    expect(verdicts[0].reason).toContain(
      'elected "AGPL-3.0-only" satisfies the workspace license AGPL-3.0-only',
    );
  });

  test("GPL and LGPL deps are suppressed under an AGPL workspace (GNU family)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("gpl-pkg", "GPL-2.0-only", ["apps/scratch"]),
        pkgSpec("lgpl-pkg", "LGPL-3.0-or-later", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => v.status)).toEqual(["suppressed", "suppressed"]);
    // The audit-trail reason states the VERIFIED relationship, never an
    // unverified in-family assertion.
    expect(verdicts[0].reason).toContain("same GNU family as the workspace license AGPL-3.0-only");
  });

  test("AND expressions suppress when every copyleft leaf is in-family", () => {
    // The sharp-win32 shape: Apache-2.0 AND LGPL-3.0-or-later — the only
    // copyleft obligation (LGPL) is GNU-family under the AGPL workspace.
    const { verdicts } = runEngine(
      [pkgSpec("sharp-ish", "Apache-2.0 AND LGPL-3.0-or-later", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
  });

  test("out-of-family copyleft under the suppressed path falls through to default:copyleft", () => {
    // CC-BY-SA is out-of-family copyleft; SSPL is now a source-available deny default: a path match alone must
    // never suppress them — that would assert a legally false in-family
    // justification.
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["apps/scratch"]),
        pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:source-available"],
    ]);
  });

  test("mixed AND with an out-of-family copyleft leaf is NOT suppressed", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mixed-pkg", "LGPL-3.0-or-later AND CC-BY-SA-4.0", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

// ===========================================================================
// Revision F: apps/scratch absorbs ALL bundled strong copyleft — an AGPL-3.0
// (GNU-family) workspace absorbs inbound-compatible weaker copyleft (MPL) in
// ADDITION to its own family (GNU). The safety floor (SSPL/CC-BY-SA), the deny
// terminal, directionality, and the GPL-prod-outside-suppression scope are all
// regression-guarded here.
// ===========================================================================

describe("WORKSPACE_ABSORBS — literal absorption relation", () => {
  test("the GNU family absorbs exactly GNU and MPL (the bundled inbound set)", () => {
    const gnu = WORKSPACE_ABSORBS.get("GNU");

    expect(gnu).toBeDefined();
    expect([...(gnu ?? [])].sort()).toEqual(["GNU", "MPL"]);
  });

  test("the GNU absorbed set NEVER includes the safety-floor families (SSPL/CC-BY-SA)", () => {
    const gnu = WORKSPACE_ABSORBS.get("GNU");

    expect(gnu?.has("SSPL")).toBe(false);
    expect(gnu?.has("CC-BY-SA")).toBe(false);
  });

  test("no non-GNU workspace family declares an absorption set (directional, scoped)", () => {
    expect([...WORKSPACE_ABSORBS.keys()]).toEqual(["GNU"]);
  });
});

describe("evaluate — absorb-all-copyleft suppression", () => {
  test("an AGPL workspace now SUPPRESSES an MPL-2.0 finding (was: fell through to fail)", () => {
    // Without absorption this fell through to default:copyleft (MPL is a
    // different family from GNU). apps/scratch re-releases bundled MPL files
    // under AGPL, so it absorbs them.
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
    // The audit-trail reason names the absorption, not an in-family assertion.
    expect(verdicts[0].reason).toContain("absorbed by the GNU workspace license");
  });

  test("it STILL suppresses GPL-3.0 and LGPL (exact-family regression intact)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("gpl-pkg", "GPL-3.0-only", ["apps/scratch"]),
        pkgSpec("lgpl-pkg", "LGPL-3.0-or-later", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => v.status)).toEqual(["suppressed", "suppressed"]);
    // The same-family path keeps its "same GNU family" wording.
    expect(verdicts[0].reason).toContain("same GNU family as the workspace license AGPL-3.0-only");
  });

  test("it STILL does NOT suppress SSPL-1.0 or CC-BY-SA (the safety floor)", () => {
    // CC-BY-SA falls to copyleft (out-of-family); SSPL-1.0 is now a source-available deny default — both prove the floor (neither is suppressed).
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["apps/scratch"]),
        pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:source-available"],
    ]);
  });

  test("a DENIED license under the scratch path still FAILS (deny terminal beats suppression)", () => {
    // SSPL-1.0 is both copyleft AND on the deny list: the deny terminal sits
    // ABOVE suppression, so even if it were in the absorbed set it would fail.
    const policyText = [
      "[[deny]]",
      'match = "license"',
      'pattern = "SSPL-1.0"',
      'reason = "source-available; cannot ship"',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("absorption is DIRECTIONAL: a non-AGPL (MPL) workspace does NOT absorb GNU-family GPL", () => {
    // WORKSPACE_ABSORBS declares no MPL key, so an MPL-distributed workspace
    // absorbs only its own license via branch (a) (satisfies), never GNU.
    const mplWorkspace = [
      "[[workspace.copyleft_suppressed]]",
      'path = "apps/scratch"',
      'license = "MPL-2.0"',
      'description = "hypothetical MPL-distributed workspace"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["apps/scratch"])],
      mplWorkspace,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("W2 GUARD: a GPL-3.0 PRODUCTION occurrence under a NON-suppressed workspace still FAILS default:copyleft", () => {
    // The absorb-all widening must NOT leak outside the declared suppressed
    // path. A GPL-3.0 prod dep under backend/ (not suppressed) stays a hard
    // fail — assert the EXACT verdict so the scope is proven.
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["backend"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].occurrenceTarget).toBe("backend");
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
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

describe("evaluate — election gates the copyleft flag", () => {
  test("(MIT OR GPL-3.0-or-later) elects MIT → default:ok with ZERO policy rules", () => {
    const { verdicts } = runEngine(
      [pkgSpec("or-pkg", "(MIT OR GPL-3.0-or-later)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("(GPL-2.0-only OR GPL-3.0-only) cannot avoid copyleft → fail without a rule", () => {
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "(GPL-2.0-only OR GPL-3.0-only)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — CR-01 copyleft families reach default:copyleft", () => {
  test("CC-BY-SA-4.0, Sleepycat, and GFDL-1.3-only packages fail (no more silent default:ok)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["backend"]),
        pkgSpec("gfdl-pkg", "GFDL-1.3-only", ["backend"]),
        pkgSpec("sleepycat-pkg", "Sleepycat", ["backend"]),
      ],
      "",
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
    ]);
  });

  test("OR-with-permissive still elects the permissive branch for the new ids", () => {
    const { verdicts } = runEngine([pkgSpec("dual-pkg", "(CC-BY-SA-4.0 OR MIT)", ["backend"])], "");

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });
});

describe("evaluate — copyleft dominates a permissive sibling end-to-end (C2/W2)", () => {
  const multi = (name: string, claims: ReadonlyArray<string>): PackageSpec => ({
    purl: `pkg:npm/${name}@1.0.0`,
    name,
    version: "1.0.0",
    claims,
    occurrences: ["backend"],
  });

  test("C2: imprecise permissive + precise copyleft → default:copyleft fail (not a non-gating warn)", () => {
    const { verdicts } = runEngine(
      [
        multi("apache-plus-agpl", ["Apache", "AGPL-3.0-only"]),
        multi("bsd-plus-gpl", ["BSD", "GPL-3.0-only"]),
      ],
      "",
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
    ]);
  });

  test("W2: two conflicting imprecise families route to default:imprecise-copyleft order-independently", () => {
    const { verdicts } = runEngine(
      [
        multi("bsd-then-gpl", ["BSD License", "GPL"]),
        multi("gpl-then-bsd", ["GPL", "BSD License"]),
      ],
      "",
    );

    // Both packages, regardless of claim order, reach the could-be-copyleft
    // review lane — never the non-gating default:imprecise.
    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["warn", "default:imprecise-copyleft"],
      ["warn", "default:imprecise-copyleft"],
    ]);
  });
});

// ===========================================================================
// Imprecise findings + the could-be-copyleft literal token set.
// ===========================================================================

describe("COULD_BE_COPYLEFT_FAMILIES — literal token set", () => {
  test("contains the bare GNU-family copyleft tokens", () => {
    expect(COULD_BE_COPYLEFT_FAMILIES.has("GPL")).toBe(true);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("AGPL")).toBe(true);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("LGPL")).toBe(true);
  });

  test("does NOT contain permissive family tokens (BSD/Apache/MIT)", () => {
    expect(COULD_BE_COPYLEFT_FAMILIES.has("BSD")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("Apache")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("MIT")).toBe(false);
  });

  test("deliberately excludes the weak-copyleft family tokens (MPL/EPL/CDDL)", () => {
    // These are gated on the EXPRESSION path via COPYLEFT_FAMILY; an imprecise
    // finding never reaches it, and no producing path emits a bare MPL/EPL/CDDL
    // family token, so adding them would be untested dead data.
    expect(COULD_BE_COPYLEFT_FAMILIES.has("MPL")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("EPL")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("CDDL")).toBe(false);
  });

  test("contains EUPL — the copyleft family correct() cross-maps to permissive (W1)", () => {
    // "EUPL" → spdx-correct → UPL-1.0 (permissive). Intercepting it as the
    // imprecise copyleft family routes it to the could-be-copyleft review lane
    // instead of a silent default:ok.
    expect(COULD_BE_COPYLEFT_FAMILIES.has("EUPL")).toBe(true);
  });

  test("is exactly the four-token set", () => {
    expect([...COULD_BE_COPYLEFT_FAMILIES].sort()).toEqual(["AGPL", "EUPL", "GPL", "LGPL"]);
  });
});

describe("evaluate — imprecise findings route to a safe lane", () => {
  test("a permissive imprecise family (BSD) gets a non-gating default:imprecise status", () => {
    const { verdicts } = runEngine([pkgSpec("jinja2-ish", "BSD License", ["frontend"])], "");

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).toBe("default:imprecise");
    // The signal must be visible — not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("an imprecise BSD family is NOT copyleft-flagged and NOT a hard fail in a non-suppressed workspace", () => {
    const { verdicts } = runEngine([pkgSpec("bsd-pkg", "BSD", ["backend"])], "");

    expect(verdicts[0].rule).not.toBe("default:copyleft");
    expect(verdicts[0].status).not.toBe("fail");
  });

  test("a could-be-copyleft imprecise family (GPL) is flagged for review, never silently passed", () => {
    const { verdicts } = runEngine([pkgSpec("gpl-ish", "GPL", ["backend"])], "");

    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // Not the permissive lane and not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:imprecise");
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare EUPL routes to default:imprecise-copyleft, never a silent default:ok (W1)", () => {
    const { verdicts } = runEngine([pkgSpec("eupl-pkg", "EUPL", ["backend"])], "");

    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // The masking this kills: EUPL → UPL-1.0 (permissive) → default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare imprecise AGPL and LGPL are likewise flagged for review (the WARNING-2 regression)", () => {
    for (const token of ["AGPL", "LGPL"]) {
      const { verdicts } = runEngine([pkgSpec(`${token}-ish`, token, ["backend"])], "");

      expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
      expect(verdicts[0].status).not.toBe("ok");
      // The regression this kills: a COPYLEFT_FAMILY.get("GPL") lookup returns
      // undefined and would mis-route it to the permissive lane.
      expect(verdicts[0].rule).not.toBe("default:imprecise");
    }
  });

  test("the engine never throws on an imprecise finding (no spdx-satisfies on a null expression)", () => {
    const impreciseFinding: LicenseFinding = {
      expression: null,
      elected: null,
      source: "registry",
      confidence: "imprecise",
      impreciseFamily: "GPL",
    };
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:pypi/imp@1.0.0",
          name: "imp",
          version: "1.0.0",
          occurrences: [{ target: "backend", isDevDependency: false }],
          licenseClaims: [],
          scope: "app",
          finding: impreciseFinding,
        },
      ],
    };

    expect(() => evaluate(model, parsePolicy(""), WITHOUT_DEPENDENCY_GRAPHS)).not.toThrow();
    const verdicts = evaluate(model, parsePolicy(""), WITHOUT_DEPENDENCY_GRAPHS);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });

  test("an imprecise finding is NOT governed by the unknown knob (it is present, not unknown)", () => {
    // Under handling="fail", a genuinely unknown package fails; an imprecise
    // permissive family must NOT — it is present-but-needs-clarify.
    const { verdicts } = runEngine(
      [pkgSpec("bsd-pkg", "BSD", ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).toBe("default:imprecise");
  });
});

describe("evaluate — unknown handling knob", () => {
  test('zero-claim package warns under handling "warn" (the absent-table default)', () => {
    const { verdicts } = runEngine([pkgSpec("no-claims", null, ["backend"])], "");

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test('zero-claim package fails under handling "fail"', () => {
    const { verdicts } = runEngine(
      [pkgSpec("no-claims", null, ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });
});

describe("evaluate — per-occurrence verdicts", () => {
  test("copyleft package in a suppressed AND a non-suppressed target yields TWO verdicts", () => {
    const { verdicts } = runEngine(
      // Occurrence input order deliberately unsorted: output order must come
      // from the compareCodeUnits sort on (purl, occurrenceTarget).
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["backend", "apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts).toHaveLength(2);
    expect(verdicts.map((v) => v.occurrenceTarget)).toEqual(["apps/scratch", "backend"]);
    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[1].status).toBe("fail");
    // Fail reasons MUST name the occurrence target AND the elected
    // expression — Phase-4 violation messages build on this.
    expect(verdicts[1].reason).toContain("backend");
    expect(verdicts[1].reason).toContain("AGPL-3.0-only");
    for (const v of verdicts) {
      expect(v.rule.length).toBeGreaterThan(0);
      expect(v.reason.length).toBeGreaterThan(0);
    }
  });
});

describe("evaluate — clarify usage visibility", () => {
  test("a clarified package falling through to ok cites clarify[0]", () => {
    const policyText = [
      "[[clarify]]",
      'name = "weird-pkg"',
      'version = "1.0.0"',
      'detected = { registry = "Public Domain" }',
      'justification = "license-not-found"',
      'expression = "MIT"',
      'comment = "upstream metadata is garbage; MIT confirmed in the repository"',
    ].join("\n");
    const { verdicts, usedClarifyIndices } = runEngine(
      [pkgSpec("weird-pkg", "Public Domain", ["backend"])],
      policyText,
    );

    expect(usedClarifyIndices.has(0)).toBe(true);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });
});

describe("evaluate — LicenseRef acceptance for commercial clarifies (A4/P-05)", () => {
  test("a [[clarify]] with a LicenseRef- expression on an honest-unknown pkg:maven component VALIDATES and the verdict cites clarify[0] with the LicenseRef expression", () => {
    const policyText = [
      "[[clarify]]",
      'name = "proprietary-reporting-engine"',
      'version = "9.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "LicenseRef-commercial-vendor-agreement"',
      'comment = "system-scoped commercial jar; the vendor agreement governs, not a public license"',
    ].join("\n");
    const spec: PackageSpec = {
      purl: "pkg:maven/com.example.vendor/proprietary-reporting-engine@9.0.0",
      name: "proprietary-reporting-engine",
      version: "9.0.0",
      claims: [], // the honest unknown: no registry presence, no POM license
      occurrences: ["backend"],
    };
    const { verdicts, usedClarifyIndices, policy } = runEngine([spec], policyText);

    expect(policy.clarify[0]?.expression).toBe("LicenseRef-commercial-vendor-agreement");
    expect(usedClarifyIndices.has(0)).toBe(true);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].reason).toContain("LicenseRef-commercial-vendor-agreement");
  });

  test("a LicenseRef- expression inside a compound (LicenseRef-x OR MIT) is LOCKED to whatever the in-tree machinery already does — no compound handling is extended here", () => {
    const policyText = [
      "[[clarify]]",
      'name = "dual-ref-pkg"',
      'version = "1.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "LicenseRef-x OR MIT"',
      'comment = "dual: a proprietary ref or MIT, whichever the consumer prefers"',
    ].join("\n");
    const spec: PackageSpec = {
      purl: "pkg:maven/com.example/dual-ref-pkg@1.0.0",
      name: "dual-ref-pkg",
      version: "1.0.0",
      claims: [],
      occurrences: ["backend"],
    };
    const { verdicts } = runEngine([spec], policyText);

    // LOCKED: the OR election prefers the non-copyleft, non-ref branch
    // (normalize/expression.ts elect's LicenseRef/DocumentRef tie-break) —
    // MIT wins over the opaque LicenseRef- atom.
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("normalizeRaw NEVER mints a LicenseRef from free text — a commercial-sounding raw name stays an honest unknown, not a guessed LicenseRef", () => {
    const result = normalizeRaw("Commercial License Agreement");

    expect(result.expression).toBeNull();
  });
});

describe("evaluate — an unassessed LicenseRef never reaches default:ok (silent-pass fix)", () => {
  test("a bare LicenseRef-AGPL-3.0-only expression is NOT ok — it routes to the unknown lane, not default:ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-named-ref-pkg", "LicenseRef-AGPL-3.0-only", ["backend"])],
      "",
    );

    expect(verdicts[0].status).not.toBe("ok");
    expect(verdicts[0].rule).toBe("default:unknown");
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test('the bare-ref package fails under [unknown] handling = "fail", exactly like a genuine unknown', () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-named-ref-pkg", "LicenseRef-AGPL-3.0-only", ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test("(MIT OR LicenseRef-x) still elects MIT and stays default:ok — the OR election is not regressed", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-or-ref-pkg", "(MIT OR LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("(MIT AND LicenseRef-x) carries unassessed ref content alongside a known conjunct — NOT a silent default:ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-and-ref-pkg", "(MIT AND LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).not.toBe("ok");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test("a copyleft leaf ANDed with a ref still fails default:copyleft — copyleft is a stronger signal than the ref-unknown lane", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-and-ref-pkg", "(AGPL-3.0-only AND LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — staleness-guarded overrides", () => {
  test("a tool-level override that decides a verdict cites override:builtin[i], not default:ok", () => {
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD", ["backend"])], "", builtins);

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
    expect(verdicts[0].rule).not.toBe("default:ok");
    expect(verdicts[0].reason).toContain("BSD-3-Clause");
  });

  test("HEADLINE: a stale BSD→BSD-3-Clause override on a now-GPL-3.0 dep FAILS naming pkg/expected/observed", () => {
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", ["backend"])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain("relicensed");
    expect(verdicts[0].reason).toContain("BSD"); // expected
    expect(verdicts[0].reason).toContain("GPL-3.0-only"); // now-observed
  });

  test("a stale project clarify also fails (level surfaced in the message)", () => {
    const policyText = [
      "[[clarify]]",
      'name = "relicensed"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("project clarify WINS over tool-level on conflict, end-to-end", () => {
    const policyText = [
      "[[clarify]]",
      'name = "ipython"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "project says MIT"',
    ].join("\n");
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD", ["backend"])], policyText, builtins);

    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].reason).toContain("project says MIT");
  });

  test("an imprecise finding with NO matching override stays imprecise+surfaced", () => {
    const { verdicts } = runEngine([pkgSpec("orphan-bsd", "BSD", ["backend"])], "", []);

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise");
  });

  test("REDUNDANT override (metadata caught up to a precise satisfying license) does NOT fail — observed finding stands ok (gap fix)", () => {
    // The live false-positive: PyPI now reports ipython precisely as
    // "BSD-3-Clause" (no bare "BSD"). The recorded "BSD" is absent from the
    // signal, but the observed precise license already satisfies the asserted
    // BSD-3-Clause — nothing is masked, so the gate must NOT fire override:stale.
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD-3-Clause", ["backend"])], "", builtins);

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toContain("override:stale");
  });

  test("a genuine relicense to a NON-satisfying license still FAILS override:stale (gap fix is fail-safe)", () => {
    // The recorded "BSD" is absent AND the observed precise license (MIT) does
    // not satisfy the asserted BSD-3-Clause → genuine drift → must fail closed.
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine([pkgSpec("relicensed", "MIT", ["backend"])], "", builtins);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("an OR-only expression applies while the recorded detection still holds", () => {
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "or-expression-pkg",
        detected: { registry: "MIT" },
        expression: "MIT OR Apache-2.0",
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("or-expression-pkg", "MIT", ["backend"])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
    expect(verdicts[0].reason).toContain("MIT OR Apache-2.0");
  });
});

// ===========================================================================
// The per-source `detected` precondition at verdict level: which lane a
// recorded value is checked against, what `false` asserts, what a lane that
// has gone quiet does, and how the reason names each.
// ===========================================================================

describe("evaluate — per-source detected preconditions", () => {
  /** A [[clarify]] on `detected-pkg` recording exactly the given inline table. */
  const detectedClarify = (table: string, justification = "scan-more-precise"): string =>
    [
      "[[clarify]]",
      'name = "detected-pkg"',
      'version = "1.0.0"',
      `detected = ${table}`,
      `justification = "${justification}"`,
      'expression = "BSD-3-Clause"',
    ].join("\n");

  test("HEADLINE: a value is checked against ITS OWN lane — a registry value the intensive lane happens to report does not satisfy it", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", null, "BSD", ["backend"])],
      detectedClarify('{ registry = "BSD" }'),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("no current registry detection");
  });

  test("the same value recorded against the lane that reports it APPLIES", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", null, "BSD", ["backend"])],
      detectedClarify('{ intensive = "BSD" }'),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("`false` records that a lane reports nothing, and holds while it stays quiet", () => {
    const { verdicts } = runEngine(
      [pkgSpec("detected-pkg", "BSD", ["backend"])],
      detectedClarify('{ registry = "BSD", intensive = false }', "declared-more-complete"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a `false` record is PROVEN WRONG once that lane starts reporting, even when the new report AGREES — a source that has started speaking is evidence to read", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", "BSD", "BSD-3-Clause", ["backend"])],
      detectedClarify('{ registry = "BSD", intensive = false }', "declared-more-complete"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("recorded no intensive detection");
    expect(verdicts[0].reason).toContain("BSD-3-Clause");
  });
});

// ===========================================================================
// Selecting a FAMILY of packages: one entry covers every name a pattern
// matches, and one entry covers several pinned versions. Both go through the
// shared matcher, so annotate and evaluate agree on which packages an entry
// governs.
// ===========================================================================

describe("evaluate — a [[clarify]] covering a family of packages", () => {
  const patternClarify = [
    "[[clarify]]",
    'pattern = "@dicts/*"',
    'version = "1.0.0"',
    'detected = { registry = "BSD" }',
    'justification = "scan-more-precise"',
    'expression = "BSD-3-Clause"',
  ].join("\n");

  test("HEADLINE: one pattern entry clarifies every matching package, each citing the same entry", () => {
    const { verdicts, usedClarifyIndices } = runEngine(
      [pkgSpec("@dicts/en", "BSD", ["backend"]), pkgSpec("@dicts/fr", "BSD", ["backend"])],
      patternClarify,
    );

    expect(usedClarifyIndices.has(0)).toBe(true);
    for (const verdict of verdicts) {
      expect(verdict.status).toBe("ok");
      expect(verdict.rule).toBe("clarify[0]");
      expect(verdict.reason).toContain("BSD-3-Clause");
    }
  });

  test("a package outside the pattern is untouched — the entry governs the family, not the model", () => {
    const { verdicts } = runEngine([pkgSpec("@other/en", "BSD", ["backend"])], patternClarify);

    expect(verdicts[0].rule).toBe("default:imprecise");
  });

  test("a version list covers exactly the versions it names, and nothing else", () => {
    const policyText = [
      "[[clarify]]",
      'name = "pinned-pkg"',
      'version = ["1.0.0", "2.0.0"]',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
    ].join("\n");
    const covered = runEngine(
      [pkgSpec("pinned-pkg", "BSD", ["backend"], "2.0.0")],
      policyText,
    ).verdicts;
    const uncovered = runEngine(
      [pkgSpec("pinned-pkg", "BSD", ["backend"], "3.0.0")],
      policyText,
    ).verdicts;

    expect(covered[0].rule).toBe("clarify[0]");
    expect(uncovered[0].rule).toBe("default:imprecise");
  });
});

// ===========================================================================
// The reason a cited entry surfaces: the closed-set value, and the comment
// after an em-dash when the entry carries one.
// ===========================================================================

describe("evaluate — the reason a cited [[clarify]] surfaces", () => {
  const citingClarify = (extra: ReadonlyArray<string>): string =>
    [
      "[[clarify]]",
      'name = "cited-pkg"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
      ...extra,
    ].join("\n");

  test("without a comment the reason is the justification value alone", () => {
    const { verdicts } = runEngine([pkgSpec("cited-pkg", "BSD", ["backend"])], citingClarify([]));

    expect(verdicts[0].reason).toContain("scan-more-precise");
    expect(verdicts[0].reason).not.toContain("—");
  });

  test("with a comment the reason is the value, an em-dash, then the comment", () => {
    const { verdicts } = runEngine(
      [pkgSpec("cited-pkg", "BSD", ["backend"])],
      citingClarify(['comment = "the LICENSE file carries the three-clause text"']),
    );

    expect(verdicts[0].reason).toContain(
      "scan-more-precise — the LICENSE file carries the three-clause text",
    );
  });
});

// ===========================================================================
// A COMPOUND recorded detection: an entry written against a multi-license
// (AND/OR) registry claim. Both sides of the lane comparison run through
// canonicalizeExpression (flatten, dedupe, absorb, sort) before the
// case-insensitive, trimmed comparison, so a registry re-spelling of the same
// license set - reordered operands, a duplicated conjunct, an absorbable
// branch - never reopens the entry. Only a genuine change to the license SET
// does. Modeled on the real spdx-ranges dogfood case: npm declares
// "(MIT AND CC-BY-3.0)", the in-depth scan reads only the root LICENSE and
// sees "MIT" - two lanes, one of which reports the compound the entry names.
// ===========================================================================

describe("evaluate — a compound recorded detection", () => {
  const compoundClaim = "(MIT AND CC-BY-3.0)";

  /** A [[clarify]] whose recorded registry value AND expression are the same compound claim. */
  const compoundClarify = [
    "[[clarify]]",
    'name = "compound-pkg"',
    'version = "1.0.0"',
    `detected = { registry = ${JSON.stringify(compoundClaim)}, intensive = "MIT" }`,
    'justification = "declared-more-complete"',
    `expression = ${JSON.stringify(compoundClaim)}`,
  ].join("\n");

  test("HEADLINE: a compound record APPLIES while the registry claim still matches, alongside a co-present in-depth claim", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("compound-pkg", compoundClaim, "MIT", ["backend"])],
      compoundClarify,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a genuine change to the license SET goes stale (fail closed), naming expected and now-observed — not merely a re-spelling", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("compound-pkg", "(MIT AND CC0-1.0)", "MIT", ["backend"])],
      compoundClarify,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain(compoundClaim); // expected
    expect(verdicts[0].reason).toContain("(MIT AND CC0-1.0)"); // now-observed
  });

  test("a re-spelling of the SAME license set — a parenthesized recorded value (the dogfood shape) against an unparenthesized, reordered claim — stays APPLIED — canonical comparison, not a stale trigger", () => {
    const respellClaim = "(MIT AND CC0-1.0)";
    const policyText = [
      "[[clarify]]",
      'name = "respelled-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(respellClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(respellClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("respelled-pkg", "CC0-1.0 AND MIT", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a genuine set change (MIT AND CC0-1.0 -> MIT AND Apache-2.0) still flags override:stale under canonical comparison", () => {
    const baseClaim = "MIT AND CC0-1.0";
    const policyText = [
      "[[clarify]]",
      'name = "set-changed-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(baseClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(baseClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("set-changed-pkg", "MIT AND Apache-2.0", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain(baseClaim); // expected
    expect(verdicts[0].reason).toContain("MIT AND Apache-2.0"); // now-observed
  });

  test("a noisy-but-equal compound claim (duplicated conjunct, an absorbable OR branch) canonicalizes to the same set and stays APPLIED", () => {
    const baseClaim = "MIT AND CC0-1.0";
    const policyText = [
      "[[clarify]]",
      'name = "noisy-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(baseClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(baseClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("noisy-pkg", "MIT AND CC0-1.0 AND (MIT OR Apache-2.0)", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("an OR-compound expression also takes the literal-equality path (either half compound trips it)", () => {
    const orClaim = "(MIT OR Apache-2.0)";
    const policyText = [
      "[[clarify]]",
      'name = "or-compound-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(orClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(orClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("or-compound-pkg", orClaim, "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("parsePolicy ACCEPTS a compound recorded detection — validation never restricts its shape", () => {
    const policy = parsePolicy(compoundClarify);

    expect(policy.clarify[0]?.detected.registry).toBe(compoundClaim);
  });
});

// ===========================================================================
// The conflict:scancode fail verdict. A ScanCode-vs-quick-check
// disagreement (marker set by applyScancodeAssessment) becomes a
// distinct fail in verdictFor, slotted directly below stale and ABOVE
// compatible. Fail-not-warn (human involvement is NECESSARY; a warn is
// ignorable). Exit 1 is automatic — a "fail" verdict is a violation in
// exitCodeFor's mapping (check.ts), no new machinery.
// ===========================================================================

describe("evaluate — conflict:scancode fail verdict", () => {
  test("HEADLINE: a scancode assessment disagreeing with a precise declared claim FAILS conflict:scancode, naming both sides and the clarify remedy", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "Apache-2.0", "MIT", ["backend"])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail"); // → exitCodeFor violation → exit 1
    expect(verdicts[0].rule).toBe("conflict:scancode");
    expect(verdicts[0].reason).toContain("disputed-pkg");
    expect(verdicts[0].reason).toContain("MIT"); // the in-depth assessment
    expect(verdicts[0].reason).toContain("Apache-2.0"); // the quick-check answer
    expect(verdicts[0].reason).toContain("[[clarify]]"); // the remedy
  });

  test("chain order: an entry with BOTH a stale override and a conflict fires override:stale FIRST (a stale override is strictly more urgent)", () => {
    const policyText = [
      "[[clarify]]",
      'name = "stale-and-conflicted"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("stale-and-conflicted", "Apache-2.0", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("chain order: a denied observed member AND a conflict fires deny FIRST (deny is terminal above every lane incl. conflict)", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("denied-and-conflicted", "BUSL-1.1", "MIT", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("chain order (inverse): a denied license the ScanCode assessment ITSELF surfaces, over a permissive declared answer, fires deny FIRST — the senior assessment can never license a denied member in, and a disagreement never downgrades a deny to a mere conflict", () => {
    // The mirror of the sibling above: here the DENIED license is the in-depth
    // ScanCode answer and the declared quick-check answer is permissive. The
    // assessment disagrees with the declared claim (a conflict marker is set),
    // but the denied member still reaches the deny terminal through
    // observedExpressions (every per-claim precise expression, the scancode
    // claim included), so deny fires above the conflict lane. A denied license
    // that only the deep scan detected can never be masked by the disagreement
    // being surfaced as a conflict rather than a deny.
    const { verdicts } = runEngine(
      [scanPkgSpec("scancode-denied", "MIT", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
    expect(verdicts[0].reason).toContain("BUSL-1.1");
  });

  test("placement ABOVE compatible: a conflict on a package whose base a compatible license rule would accept still FAILS conflict:scancode", () => {
    // base = "Apache-2.0 AND MIT" (the AND-combine of the declared claim and the
    // scancode claim); the compatible allowlist [Apache-2.0, MIT] satisfies it,
    // so WITHOUT the conflict slot this would pass compatible[0]. A disputed
    // answer must never be auto-absorbed by a compatible rule.
    const { verdicts } = runEngine(
      [scanPkgSpec("compat-but-disputed", "Apache-2.0", "MIT", ["backend"])],
      licenseRuleFixture("(Apache-2.0 OR MIT)"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("conflict:scancode");
  });

  test("no warn-bucket regression: a conflict is a fail, never a warn — and an AGREEING scancode assessment yields no conflict verdict at all", () => {
    const conflicted = runEngine(
      [scanPkgSpec("c-pkg", "Apache-2.0", "MIT", ["backend"])],
      "",
    ).verdicts;

    expect(conflicted.every((v) => v.status !== "warn")).toBe(true);

    // Agreement: scancode MIT corroborates declared MIT → scancode-sourced ok,
    // no conflict verdict, no warn.
    const agreed = runEngine([scanPkgSpec("agree-pkg", "MIT", "MIT", ["backend"])], "").verdicts;

    expect(agreed.every((v) => v.rule !== "conflict:scancode")).toBe(true);
    expect(agreed[0].status).toBe("ok");
  });
});

// ===========================================================================
// The conflict:cross-image-claims fail verdict. Two or more docker
// occurrences of the SAME purl declaring different licenses (marker set at
// merge time, threaded via PackageSpec.dockerClaimDivergence) share the
// conflict:scancode lane (verdictFor) — a fail, not a warn, for the same
// reason: human involvement is necessary. Exit 1 is automatic, no new
// machinery in exitCodeFor.
// ===========================================================================

/** Shorthand for a docker-vs-docker cross-image claim divergence spec. */
function crossImagePkgSpec(
  name: string,
  byTarget: ReadonlyArray<{ target: string; claims: readonly string[] }>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:apk/alpine/${name}@${version}`,
    name,
    version,
    claims: [],
    occurrences: byTarget.map((t) => t.target),
    scope: "os",
    dockerClaimDivergence: [...byTarget],
  };
}

describe("evaluate — conflict:cross-image-claims fail verdict", () => {
  test("HEADLINE: two docker occurrences declaring different licenses FAILS conflict:cross-image-claims, naming every image and the clarify remedy", () => {
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("busybox", [
          { target: "docker:image-a", claims: ["MIT"] },
          { target: "docker:image-b", claims: ["Apache-2.0"] },
        ]),
      ],
      "",
    );

    expect(verdicts).toHaveLength(2); // one verdict per occurrence
    for (const v of verdicts) {
      expect(v.status).toBe("fail"); // → exitCodeFor violation → exit 1
      expect(v.rule).toBe("conflict:cross-image-claims");
      expect(v.reason).toContain("busybox");
      expect(v.reason).toContain("docker:image-a: MIT");
      expect(v.reason).toContain("docker:image-b: Apache-2.0");
      expect(v.reason).toContain("[[clarify]]"); // the remedy
    }
  });

  test("an image with no declared claim renders '(no declared license)' in the reason, never a blank", () => {
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("partial-claim-pkg", [
          { target: "docker:image-a", claims: [] },
          { target: "docker:image-b", claims: ["MIT"] },
        ]),
      ],
      "",
    );

    expect(verdicts[0].reason).toContain("docker:image-a: (no declared license)");
  });

  test("resolution: a [[clarify]] override APPLIES, clears the conflict, and the verdict is clarify[0] ok (exit 0) — the same remedy path as a ScanCode conflict", () => {
    const policyText = [
      "[[clarify]]",
      'name = "busybox"',
      'version = "1.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "MIT"',
      'comment = "reviewed: image-a is correct"',
    ].join("\n");
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("busybox", [
          { target: "docker:image-a", claims: ["MIT"] },
          { target: "docker:image-b", claims: ["Apache-2.0"] },
        ]),
      ],
      policyText,
    );

    for (const v of verdicts) {
      expect(v.status).toBe("ok");
      expect(v.rule).toBe("clarify[0]");
      expect(v.rule).not.toBe("conflict:cross-image-claims");
    }
  });

  test("without a clarify, the divergence stays a fail deterministically across repeated runs (no flapping)", () => {
    const spec = [
      crossImagePkgSpec("busybox", [
        { target: "docker:image-a", claims: ["MIT"] },
        { target: "docker:image-b", claims: ["Apache-2.0"] },
      ]),
    ];
    const a = runEngine(spec, "").verdicts;
    const b = runEngine(spec, "").verdicts;

    expect(a).toEqual(b);
    expect(a.every((v) => v.rule === "conflict:cross-image-claims")).toBe(true);
  });
});

// ===========================================================================
// The [[clarify]] resolution path, end to end. The
// conflict machinery (the marker and verdict above) is cleared by a
// human decision recorded as a clarify override — the "documented
// resolution path" the docs describe. Worked example:
// the declared/registry quick check reads MIT; the in-depth ScanCode assessment
// reads BSD-3-Clause. These are verdict-level proofs; the annotate-level marker
// semantics are locked in normalize.test.ts.
// ===========================================================================

describe("evaluate — conflict:scancode resolution via [[clarify]]", () => {
  // The human's recorded call: "the quick check reads MIT, the in-depth scan
  // reads BSD-3-Clause, and I decide the scan is right." Both sources still
  // report what the entry recorded, and recording the intensive source is what
  // settles the disagreement, so the override APPLIES and the conflict is gone.
  const clarifyResolvesToScancode = [
    "[[clarify]]",
    'name = "disputed-pkg"',
    'version = "1.0.0"',
    'detected = { registry = "MIT", intensive = "BSD-3-Clause" }',
    'justification = "scan-more-precise"',
    'expression = "BSD-3-Clause"',
  ].join("\n");

  test("HEADLINE: a [[clarify]] recording the decision APPLIES, clears the conflict, and the verdict is clarify[0] ok (exit 0) — never a lingering conflict:scancode", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "MIT", "BSD-3-Clause", ["backend"])],
      clarifyResolvesToScancode,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok"); // → exit 0
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("an APPLIED override never lets a conflict marker survive into a fail — the resolved package yields no conflict verdict, deterministically across repeated runs (no permanent, un-clearable fail)", () => {
    const run = (): Verdict[] =>
      runEngine(
        [scanPkgSpec("disputed-pkg", "MIT", "BSD-3-Clause", ["backend"])],
        clarifyResolvesToScancode,
      ).verdicts;
    const a = run();
    const b = run();

    expect(a).toEqual(b);
    expect(a.every((v) => v.rule !== "conflict:scancode")).toBe(true);
    expect(a[0].status).toBe("ok");
  });

  test("the stale guard reopens it: after the registry relicenses away from the recorded expectation, the SAME clarify FAILS override:stale (the guard works both ways with zero new machinery)", () => {
    // The registry answer has moved from MIT to GPL-3.0-only, so the recorded
    // registry detection no longer holds, and the standing base (GPL-3.0-only)
    // does not satisfy the asserted BSD-3-Clause → the override is stale, fail
    // closed, and fires above the co-present conflict.
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "GPL-3.0-only", "BSD-3-Clause", ["backend"])],
      clarifyResolvesToScancode,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("determinism: a conflict with NO clarify stays a conflict:scancode fail across repeated runs — same rule, byte-identical reason (no flapping)", () => {
    const run = (): Verdict[] =>
      runEngine([scanPkgSpec("unresolved-pkg", "Apache-2.0", "MIT", ["backend"])], "").verdicts;
    const a = run();
    const b = run();

    expect(a).toEqual(b); // byte-identical verdict incl. reason
    expect(a[0].status).toBe("fail");
    expect(a[0].rule).toBe("conflict:scancode");
  });
});

describe("unusedRuleIds — stale-policy hygiene", () => {
  test("unused compatible and clarify entries are reported; suppressions never are", () => {
    const policyText = [
      // Unused suppression entry — must NOT be reported (only compatible and
      // clarify entries participate in stale-policy detection).
      SUPPRESS_SCRATCH,
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "never-matches"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[clarify]]",
      'name = "never-clarified"',
      'version = "1.0.0"',
      'detected = { registry = "MIT" }',
      'justification = "scan-overdetection"',
      'expression = "MIT"',
      'comment = "no package by this name exists"',
    ].join("\n");
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["backend"])],
      policyText,
    );

    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([
      "compatible[1]",
      "clarify[0]",
    ]);
  });
});

// ===========================================================================
// Per-occurrence compatible matching. A `where`-scoped rule
// decides at each occurrence via the SAME segment-aware prefix comparison
// suppression paths use; an unscoped rule keeps pre-scoping behavior
// byte-identically. Targets here are synthetic — per-image docker identities
// do not exist yet; the engine must not care.
// ===========================================================================

const TARGET_A = "docker:a/Dockerfile";
const TARGET_B = "docker:b/Dockerfile";
const TARGET_A_EXTRA = "docker:a/Dockerfile-extra";
const TARGET_A_PREFIX = "docker:a";

/** Package-form busybox acceptance scoped to the given identity prefixes. */
const scopedBusyboxPolicy = (where: ReadonlyArray<string>): string =>
  [
    "[[compatible]]",
    'match = "package"',
    'name = "busybox"',
    'version = "1.37.0"',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    `where = ${JSON.stringify(where)}`,
  ].join("\n");

/** License-form GPL acceptance scoped to the given identity prefixes. */
const scopedGplPolicy = (where: ReadonlyArray<string>): string =>
  [
    "[[compatible]]",
    'match = "license"',
    'pattern = "GPL-2.0-only"',
    'rationale = "license-reviewed"',
    `where = ${JSON.stringify(where)}`,
  ].join("\n");

/** An os-scope GPL busybox occurring at the given targets. */
const busyboxAt = (targets: ReadonlyArray<string>): PackageSpec =>
  osPkgSpec("pkg:apk/alpine/busybox@1.37.0", "busybox", "GPL-2.0-only", targets, "1.37.0");

describe("evaluate — where-scoped compatible matching", () => {
  test("package form: scoped rule cited ONLY at its target; segment-aware; other occurrences fall to default:copyleft", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B, TARGET_A_EXTRA])],
      scopedBusyboxPolicy([TARGET_A]),
    );

    // compareCodeUnits order: .../a/Dockerfile, .../a/Dockerfile-extra,
    // .../b/Dockerfile. Out-of-scope occurrences fall to default:copyleft,
    // os-downgraded to warn ([os_dependencies] defaults to "warn").
    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_A_EXTRA, "warn", "default:copyleft"],
      [TARGET_B, "warn", "default:copyleft"],
    ]);
  });

  test("license form: same matrix", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B, TARGET_A_EXTRA])],
      scopedGplPolicy([TARGET_A]),
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_A_EXTRA, "warn", "default:copyleft"],
      [TARGET_B, "warn", "default:copyleft"],
    ]);
  });

  test("a prefix scope matches every target under it as a whole segment and the prefix itself (both forms)", () => {
    for (const policyText of [
      scopedBusyboxPolicy([TARGET_A_PREFIX]),
      scopedGplPolicy([TARGET_A_PREFIX]),
    ]) {
      const { verdicts } = runEngine(
        [busyboxAt([TARGET_A, TARGET_A_EXTRA, TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
      ]);
    }
  });

  test("FAIL-SAFE direction: a scope never matches a SHORTER target above it (both forms)", () => {
    // The reverse comparison: the scope docker:a/Dockerfile is LONGER than the
    // target docker:a — a broader occurrence must never satisfy a narrower
    // scope, or an acceptance reviewed for one image would leak upward.
    for (const policyText of [scopedBusyboxPolicy([TARGET_A]), scopedGplPolicy([TARGET_A])]) {
      const { verdicts, usedClarifyIndices, policy } = runEngine(
        [busyboxAt([TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([["warn", "default:copyleft"]]);
      // ...and the rule that decided nothing surfaces as unused.
      expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual(["compatible[0]"]);
    }
  });

  test("first-match order per occurrence: scoped rule[0] wins at its target, unscoped rule[1] elsewhere", () => {
    const policyText = [
      scopedBusyboxPolicy([TARGET_A]),
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "busybox"',
      'version = "1.37.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts } = runEngine([busyboxAt([TARGET_A, TARGET_B])], policyText);

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_B, "ok", "compatible[1]"],
    ]);
  });

  test("byte-identity: an unscoped policy over a multi-occurrence model is unchanged — rule ids and statuses per occurrence", () => {
    // The pre-scoping contract: without `where`, a
    // compatible rule accepts the package at EVERY occurrence, package form
    // beating license form, first match in TOML order.
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "mpl-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine(
      [
        pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch", "backend", "proj"]),
        pkgSpec("other-mpl", "MPL-2.0", ["backend", "proj"]),
      ],
      policyText,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "ok", "compatible[0]"],
      ["backend", "ok", "compatible[0]"],
      ["proj", "ok", "compatible[0]"],
      ["backend", "ok", "compatible[1]"],
      ["proj", "ok", "compatible[1]"],
    ]);
  });

  test('the everywhere token "/" decides at every occurrence identity (both forms)', () => {
    for (const policyText of [scopedBusyboxPolicy(["/"]), scopedGplPolicy(["/"])]) {
      const { verdicts } = runEngine(
        [busyboxAt([TARGET_A, TARGET_B, TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
      ]);
    }
  });

  test("the everywhere token beside a narrower prefix still covers every occurrence", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B])],
      scopedBusyboxPolicy([TARGET_A, "/"]),
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_B, "ok", "compatible[0]"],
    ]);
  });

  test("dead scoped rule: a where that matches no occurrence lands in unusedRuleIds", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [busyboxAt([TARGET_A])],
      scopedBusyboxPolicy([TARGET_B]),
    );

    expect(verdicts.map((v) => v.rule)).toEqual(["default:copyleft"]);
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual(["compatible[0]"]);
  });
});

describe("evaluate — purity and determinism", () => {
  test("identical inputs evaluate to deeply equal arrays; occurrence input order is irrelevant", () => {
    const forward = pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch", "backend"]);
    const reversed = pkgSpec("agpl-pkg", "AGPL-3.0-only", ["backend", "apps/scratch"]);
    const first = runEngine([forward], SUPPRESS_SCRATCH).verdicts;
    const second = runEngine([forward], SUPPRESS_SCRATCH).verdicts;
    const shuffled = runEngine([reversed], SUPPRESS_SCRATCH).verdicts;

    expect(second).toEqual(first);
    expect(shuffled).toEqual(first);
  });
});

// ===========================================================================
// AGPL acceptance corpus — every fixture mirrors a real row of the live
// discovery run (3616 packages). These are real purls, names, versions,
// expressions, and occurrence shapes — not inventions — so future updates can
// re-verify them against the live model.
// ===========================================================================

/**
 * The fixture policy from the plan: apps/scratch suppressed as AGPL-3.0-only,
 * NO LGPL compatible rule, unknown = warn.
 */
const ACCEPTANCE_POLICY = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  'description = "apps/scratch ships the AGPL-3.0 scratch-editor derivative; copyleft distribution is the workspace model."',
  "",
  "[unknown]",
  'handling = "warn"',
].join("\n");

describe("AGPL acceptance corpus", () => {
  // Corpus row: @scratch/scratch-vm @11.6.0-react-18 — AGPL-3.0-only,
  // occurrences apps/scratch (prod) ONLY. Expected: suppressed.
  test("scratch-vm shape: AGPL occurring only under apps/scratch is suppressed", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40scratch/scratch-vm@11.6.0-react-18",
          name: "@scratch/scratch-vm",
          version: "11.6.0-react-18",
          claims: ["AGPL-3.0-only"],
          occurrences: ["apps/scratch"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
  });

  // Corpus row: same purl with a hypothetical added backend occurrence — THE
  // The failure must name the non-suppressed workspace.
  test("scratch-vm shape + backend occurrence: fail verdict names backend", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40scratch/scratch-vm@11.6.0-react-18",
          name: "@scratch/scratch-vm",
          version: "11.6.0-react-18",
          claims: ["AGPL-3.0-only"],
          occurrences: ["apps/scratch", "backend"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["backend", "fail"],
    ]);
    expect(verdicts[1].occurrenceTarget).toBe("backend");
    expect(verdicts[1].reason).toContain("backend");
  });

  // Corpus row: @img/sharp-libvips-* (10 platform pkgs @1.2.4) —
  // LGPL-3.0-or-later, occurrences apps/scratch (prod) AND frontend (prod).
  // This is the REAL live-data leakage shape.
  test("sharp-libvips shape: LGPL leaking into frontend fails naming frontend", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40img/sharp-libvips-linux-x64@1.2.4",
          name: "@img/sharp-libvips-linux-x64",
          version: "1.2.4",
          claims: ["LGPL-3.0-or-later"],
          occurrences: ["apps/scratch", "frontend"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["frontend", "fail"],
    ]);
    expect(verdicts[1].reason).toContain("frontend");
  });

  // Corpus row: @img/sharp-win32-* @0.34.5 — "Apache-2.0 AND
  // LGPL-3.0-or-later": AND cannot avoid the LGPL branch. The user's example
  // compatible(package) rule flips ALL occurrences to ok.
  test("sharp-win32-x64 shape: AND cannot avoid copyleft; a package rule flips all occurrences ok", () => {
    const spec: PackageSpec = {
      purl: "pkg:npm/%40img/sharp-win32-x64@0.34.5",
      name: "@img/sharp-win32-x64",
      version: "0.34.5",
      claims: ["Apache-2.0 AND LGPL-3.0-or-later"],
      occurrences: ["apps/scratch", "frontend"],
    };
    const without = runEngine([spec], ACCEPTANCE_POLICY).verdicts;

    expect(without.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["frontend", "fail"],
    ]);
    expect(without[1].reason).toContain("frontend");

    const withRule = [
      ACCEPTANCE_POLICY,
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "@img/sharp-win32-x64"',
      'version = "0.34.5"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const accepted = runEngine([spec], withRule).verdicts;

    expect(accepted.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "ok", "compatible[0]"],
      ["frontend", "ok", "compatible[0]"],
    ]);
  });

  // Corpus row: dompurify @3.1.6/@3.3.1 — "(MPL-2.0 OR Apache-2.0)",
  // occurrence apps/scratch (prod). Elects Apache-2.0 → must NOT flag even
  // though MPL-2.0 is in COPYLEFT_IDS and the policy has no MPL rule.
  test("dompurify shape: OR-with-permissive elects Apache-2.0 → default:ok", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/dompurify@3.1.6",
          name: "dompurify",
          version: "3.1.6",
          claims: ["(MPL-2.0 OR Apache-2.0)"],
          occurrences: ["apps/scratch"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  // Corpus row: jsonify @0.0.1 — garbage claim "Public Domain" (frontend dev
  // dep), the live corpus's only non-normalizable value. Normalizes to
  // unknown; the [unknown].handling knob governs it . NOTE: this
  // occurrence is dev-only, so under [unknown] handling="fail" the would-be FAIL
  // is dev-downgraded to warn by default (dev_dependencies=warn). A PROD
  // occurrence of the same would still fail — covered by the dev-scope suite above.
  test("jsonify shape: garbage claim is governed by the unknown knob (dev-downgraded under fail)", () => {
    const spec: PackageSpec = {
      purl: "pkg:npm/jsonify@0.0.1",
      name: "jsonify",
      version: "0.0.1",
      claims: ["Public Domain"],
      occurrences: [{ target: "frontend", dev: true }],
    };
    const warned = runEngine([spec], ACCEPTANCE_POLICY).verdicts;

    expect(warned[0].status).toBe("warn");
    expect(warned[0].rule).toBe("default:unknown");

    const failPolicy = ACCEPTANCE_POLICY.replace('handling = "warn"', 'handling = "fail"');
    // A dev-only unknown-fail downgrades to warn by default.
    const failed = runEngine([spec], failPolicy).verdicts;

    expect(failed[0].status).toBe("warn");
    expect(failed[0].rule).toBe("default:unknown");
    expect(failed[0].reason).toContain("dev-only occurrence");

    // Strict projects can restore the fail with dev_dependencies=fail.
    const strictPolicy = `${failPolicy}\n\n[dev_dependencies]\nhandling = "fail"`;
    const strict = runEngine([spec], strictPolicy).verdicts;

    expect(strict[0].status).toBe("fail");
    expect(strict[0].rule).toBe("default:unknown");
  });
});

// ===========================================================================
// Dev/prod gate downgrade — the `dev_dependencies` knob + the
// per-occurrence dev-scope downgrade at the would-be default-FAIL terminals.
// ===========================================================================

/** A copyleft package with one DEV occurrence (A) and one PROD occurrence (B). */
const DEV_PROD_COPYLEFT = pkgSpec("agpl-pkg", "AGPL-3.0-only", [
  { target: "apps/a", dev: true },
  { target: "apps/b", dev: false },
]);

/** An UNKNOWN-license package with one DEV occurrence (A) and one PROD (B). */
const DEV_PROD_UNKNOWN = pkgSpec("no-claims", null, [
  { target: "apps/a", dev: true },
  { target: "apps/b", dev: false },
]);

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

    expect(error.problems).toContain(
      'dev_dependencies.handling: must be "warn", "fail", or "ignore"',
    );
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

describe("evaluate — dev-scope downgrade (default warn)", () => {
  test("HEADLINE: one copyleft package, dev occurrence WARNS + prod occurrence FAILS", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], "");

    expect(verdicts).toHaveLength(2);
    // sorted compareCodeUnits on (purl, target): apps/a before apps/b
    const [a, b] = verdicts;

    expect(a.occurrenceTarget).toBe("apps/a");
    expect(a.status).toBe("warn");
    expect(a.rule).toBe("default:copyleft");
    expect(b.occurrenceTarget).toBe("apps/b");
    expect(b.status).toBe("fail");
    expect(b.rule).toBe("default:copyleft");
  });

  test("the dev-downgraded reason names the cause and the knob value", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], "");
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");

    expect(dev?.reason).toContain("dev-only occurrence");
    expect(dev?.reason).toContain("dev_dependencies=warn");
    // the prod fail reason is a genuine default:copyleft fail, not a downgrade
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(prod?.reason).not.toContain("dev-only occurrence");
  });

  test("unknown-fail downgrade is covered too (general, both default-FAIL terminals)", () => {
    const { verdicts } = runEngine([DEV_PROD_UNKNOWN], '[unknown]\nhandling = "fail"');
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("warn");
    expect(dev?.rule).toBe("default:unknown");
    expect(dev?.reason).toContain("dev-only occurrence");
    expect(prod?.status).toBe("fail");
    expect(prod?.rule).toBe("default:unknown");
  });

  test('a default:unknown that is already "warn" is never downgraded (it is no fail)', () => {
    // unknownHandling="warn" → the dev occurrence is a plain default:unknown
    // warn, NOT a dev-downgrade; its reason carries no dev-only marker.
    const { verdicts } = runEngine([DEV_PROD_UNKNOWN], "");
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");

    expect(dev?.status).toBe("warn");
    expect(dev?.rule).toBe("default:unknown");
    expect(dev?.reason).not.toContain("dev-only occurrence");
  });
});

describe("evaluate — workspace-shape production occurrences", () => {
  // Pins the applyDevScope production terminal (evaluate.ts ~411:
  // "if (!occurrence.isDevDependency) return failVerdict;") on the EXACT
  // per-workspace repo shape the collect-loop expansion now produces —
  // {target: "frontend" | "backend", isDevDependency: false} — so the fix
  // can never silently regress under the real workspace target identities
  // instead of the older synthetic apps/a / apps/b names.

  test("HEADLINE: a production copyleft occurrence on {target:'frontend', isDevDependency:false} FAILS under dev_dependencies=warn — never downgraded", () => {
    const { verdicts } = runEngine(
      [pkgSpec("imaging-native", "LGPL-3.0-or-later", [{ target: "frontend", dev: false }])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].occurrenceTarget).toBe("frontend");
  });

  test("contrast arm: the SAME package as a dev occurrence on the workspace shape WARNS — proving the terminal, not the shape, does the work", () => {
    const { verdicts } = runEngine(
      [pkgSpec("imaging-native", "LGPL-3.0-or-later", [{ target: "frontend", dev: true }])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].occurrenceTarget).toBe("frontend");
    expect(verdicts[0].reason).toContain("dev-only occurrence");
  });

  test("deny, production: a [[deny]]-listed license on {target:'backend', isDevDependency:false} FAILS (terminal)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "backend", dev: false }])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].occurrenceTarget).toBe("backend");
  });

  test("deny, dev: the SAME deny shape with isDevDependency:true STILL FAILS — deny sits above the dev downgrade on this scan shape too", () => {
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "backend", dev: true }])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].occurrenceTarget).toBe("backend");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });
});

describe('evaluate — dev_dependencies = "fail" (the pre-knob behavior)', () => {
  test("BOTH copyleft occurrences fail (no downgrade)", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], '[dev_dependencies]\nhandling = "fail"');

    expect(verdicts.map((v) => v.status)).toEqual(["fail", "fail"]);
    expect(verdicts.every((v) => v.rule === "default:copyleft")).toBe(true);
    expect(verdicts.every((v) => !v.reason.includes("dev-only"))).toBe(true);
  });

  test("BOTH unknown-fail occurrences fail (gate dev like prod)", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_UNKNOWN],
      '[dev_dependencies]\nhandling = "fail"\n\n[unknown]\nhandling = "fail"',
    );

    expect(verdicts.map((v) => v.status)).toEqual(["fail", "fail"]);
  });
});

describe('evaluate — dev_dependencies = "ignore"', () => {
  test("dev copyleft occurrence is ok; prod copyleft occurrence still FAILS", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], '[dev_dependencies]\nhandling = "ignore"');
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("ok");
    expect(dev?.rule).toBe("default:copyleft");
    expect(dev?.reason).toContain("dev_dependencies=ignore");
    expect(prod?.status).toBe("fail");
  });

  test("dev unknown-fail occurrence is ok; prod still fails", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_UNKNOWN],
      '[dev_dependencies]\nhandling = "ignore"\n\n[unknown]\nhandling = "fail"',
    );
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("ok");
    expect(prod?.status).toBe("fail");
  });
});

describe("evaluate — precedence is preserved (downgrade is last)", () => {
  test("a suppressed dev copyleft occurrence stays suppressed (not warn)", () => {
    // apps/scratch is family-suppressed AND the occurrence is dev: suppression
    // wins, the dev-scope downgrade never touches it.
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", [{ target: "apps/scratch", dev: true }])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
  });

  test("a compatible-matched dev copyleft occurrence stays ok via compatible[i]", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", [{ target: "backend", dev: true }])],
      licenseRuleFixture("MPL-2.0"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("a stale-override dev occurrence still FAILS (a stale override is no default FAIL)", () => {
    // The load-bearing precedence guard: a stale override is a compliance gate
    // failure that must NEVER be dev-downgraded.
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", [{ target: "apps/a", dev: true }])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });
});

// ===========================================================================
// Terminal deny-list (highest precedence). denyRuleFor is the pure
// matcher (Task 1); the verdictFor terminal-0 wiring + the "deny beats X"
// precedence proofs live in the dedicated describe blocks (Task 2).
// ===========================================================================

/** A minimal [[deny]] license-mode policy for `pattern`. */
const denyLicenseFixture = (pattern: string): string =>
  [
    "[[deny]]",
    'match = "license"',
    `pattern = ${JSON.stringify(pattern)}`,
    'reason = "source-available; cannot ship"',
  ].join("\n");

/** A minimal [[deny]] name-mode policy for `pattern`. */
const denyNameFixture = (pattern: string): string =>
  [
    "[[deny]]",
    'match = "name"',
    `pattern = ${JSON.stringify(pattern)}`,
    'reason = "use-restriction rider; cannot ship"',
  ].join("\n");

describe("parsePolicy — [[deny]] parsing (mirrors compatible two-mode)", () => {
  test("a license-mode entry stores the pre-decomposed allowlist", () => {
    const policy = parsePolicy(denyLicenseFixture("BUSL-1.1"));

    expect(policy.deny).toEqual([
      {
        match: "license",
        pattern: "BUSL-1.1",
        allowlist: ["BUSL-1.1"],
        reason: "source-available; cannot ship",
      },
    ]);
  });

  test("an OR license pattern decomposes to a multi-entry allowlist", () => {
    const policy = parsePolicy(denyLicenseFixture("(SSPL-1.0 OR Elastic-2.0)"));

    expect(policy.deny[0]).toMatchObject({
      match: "license",
      allowlist: ["Elastic-2.0", "SSPL-1.0"],
    });
  });

  test("a name-mode entry stores the verbatim pattern (no allowlist)", () => {
    const policy = parsePolicy(denyNameFixture("Commons-Clause"));

    expect(policy.deny).toEqual([
      {
        match: "name",
        pattern: "Commons-Clause",
        reason: "use-restriction rider; cannot ship",
      },
    ]);
  });

  test("an absent [[deny]] table yields []", () => {
    expect(parsePolicy("").deny).toEqual([]);
  });

  test("an AND license pattern is rejected naming deny[i]", () => {
    const error = expectPolicyError(denyLicenseFixture("BUSL-1.1 AND MIT"));

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain("AND is not allowed");
  });

  test("an invalid SPDX license pattern is rejected naming deny[i]", () => {
    const error = expectPolicyError(denyLicenseFixture("not a license"));

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain("not a valid SPDX expression");
  });

  test("a missing reason is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      ["[[deny]]", 'match = "license"', 'pattern = "BUSL-1.1"'].join("\n"),
    );

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('"reason"');
  });

  test("a blank pattern is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      ["[[deny]]", 'match = "name"', 'pattern = "   "', 'reason = "r"'].join("\n"),
    );

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('"pattern"');
  });

  test("an unknown key inside a deny entry is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      ["[[deny]]", 'match = "license"', 'pattern = "BUSL-1.1"', 'reason = "r"', "bogus = 1"].join(
        "\n",
      ),
    );

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('unknown key "bogus"');
  });

  test("an invalid match value is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      ["[[deny]]", 'match = "spdx"', 'pattern = "BUSL-1.1"', 'reason = "r"'].join("\n"),
    );

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('"match"');
  });

  test("a non-array deny is rejected", () => {
    const error = expectPolicyError('deny = "BUSL-1.1"');

    expect(error.problems.some((p) => p.includes("deny: must be an array of tables"))).toBe(true);
  });

  test("a non-table deny entry is rejected naming deny[i]", () => {
    const error = expectPolicyError('deny = ["BUSL-1.1"]');

    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain("must be a table");
  });

  test("deny is an accepted top-level key (no unknown-key error)", () => {
    expect(() => parsePolicy(denyLicenseFixture("BUSL-1.1"))).not.toThrow();
  });

  test("a [[deny]]-bearing file still rejects an unknown top-level key", () => {
    const error = expectPolicyError(
      [denyLicenseFixture("BUSL-1.1"), "", "[bogus_top]", "x = 1"].join("\n"),
    );

    expect(error.message).toContain('unknown top-level key "bogus_top"');
  });
});

describe("denyRuleFor — pure matcher (SPDX + name + OR-election)", () => {
  const denyBusl = parsePolicy(denyLicenseFixture("BUSL-1.1"));

  test("license-mode matches an exact denied finding", () => {
    const hit = denyRuleFor(denyBusl, "BUSL-1.1", "anything");

    expect(hit?.ruleId).toBe("denied[0]");
  });

  test("license-mode does NOT match a non-denied finding", () => {
    expect(denyRuleFor(denyBusl, "MIT", "anything")).toBeUndefined();
  });

  test("an OR pattern matches either denied branch", () => {
    const policy = parsePolicy(denyLicenseFixture("(SSPL-1.0 OR Elastic-2.0)"));

    expect(denyRuleFor(policy, "SSPL-1.0", "x")?.ruleId).toBe("denied[0]");
    expect(denyRuleFor(policy, "Elastic-2.0", "x")?.ruleId).toBe("denied[0]");
  });

  test("W1: an OR finding with an electable acceptable branch is NOT denied", () => {
    // "MIT OR BUSL-1.1" elects MIT — an acceptable branch exists, so deny must
    // not fire (consistent with compatible OR-election).
    expect(denyRuleFor(denyBusl, "MIT OR BUSL-1.1", "x")).toBeUndefined();
  });

  test("W1: an OR finding with NO acceptable branch IS denied", () => {
    // Deny set covers BOTH branches → the dep cannot elect out → denied.
    const policy = parsePolicy(denyLicenseFixture("(GPL-3.0 OR BUSL-1.1)"));

    expect(denyRuleFor(policy, "GPL-3.0 OR BUSL-1.1", "x")?.ruleId).toBe("denied[0]");
  });

  test("name-mode matches the target package name (verbatim, non-SPDX rider)", () => {
    const policy = parsePolicy(denyNameFixture("commons-clause-pkg"));

    // name-mode matches on the PACKAGE NAME and does not require a parseable
    // license expression (the Commons-Clause rider rides a non-SPDX value).
    expect(denyRuleFor(policy, null, "commons-clause-pkg")?.ruleId).toBe("denied[0]");
    expect(denyRuleFor(policy, null, "unrelated-pkg")).toBeUndefined();
  });

  test("name-mode does not deny an unrelated license/package", () => {
    const policy = parsePolicy(denyNameFixture("commons-clause-pkg"));

    expect(denyRuleFor(policy, "MIT", "some-mit-pkg")).toBeUndefined();
  });
});

describe("evaluate — deny is terminal-0 (beats every accept lever)", () => {
  test("deny BEATS compatible: same license denied AND compatible → fail/denied[i]", () => {
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "BUSL-1.1"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).toContain("BUSL-1.1");
  });

  test("deny BEATS suppression: a denied in-family copyleft under a suppressed path still fails", () => {
    // AGPL-3.0-only under apps/scratch would normally be family-suppressed; the
    // deny terminal sits above suppression, so it still fails.
    const policyText = [denyLicenseFixture("AGPL-3.0-only"), "", SUPPRESS_SCRATCH].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("deny BEATS dev-downgrade: a denied license on a dev occurrence still fails", () => {
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[dev_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "apps/a", dev: true }])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });

  test("deny BEATS a would-be stale override: deny is terminal-0", () => {
    // The package carries a stale builtin override (recorded BSD, observes
    // BUSL-1.1) AND the observed license is denied → deny wins over stale.
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).not.toContain("STALE");
  });

  test("name-mode deny fails a package with an UNKNOWN finding (the rider case)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("commons-clause-pkg", null, ["backend"])],
      denyNameFixture("commons-clause-pkg"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("W1 through the verdict: 'MIT OR BUSL-1.1' is NOT a deny verdict", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-pkg", "MIT OR BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("W1 through the verdict: a no-acceptable-branch OR IS a deny verdict", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-pkg", "GPL-3.0 OR BUSL-1.1", ["backend"])],
      denyLicenseFixture("(GPL-3.0 OR BUSL-1.1)"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a non-denied package is unaffected (no regression)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-pkg", "MIT", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });
});

describe("evaluate — deny is terminal OVER OVERRIDES (C#1: deny reads the pre-override observed license)", () => {
  test("a blind clarify rewriting a DENIED observed license to MIT still FAILS (deny terminal)", () => {
    // Observed BUSL-1.1; a [[clarify]] rewrites it to MIT. Pre-fix the override
    // ran before evaluate, so deny saw MIT and passed it back in. Deny must
    // consult the PRE-OVERRIDE observed BUSL-1.1 and fail.
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[clarify]]",
      'name = "evil"',
      'version = "1.0.0"',
      'detected = { registry = "BUSL-1.1" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "claims MIT but the observed signal is BUSL-1.1"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("evil", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a SUCCESSFULLY-APPLIED builtin over a denied observed license still FAILS", () => {
    // The recorded BUSL-1.1 still holds → the builtin applies and rewrites the
    // finding to Apache-2.0. Deny must still fire on the observed BUSL-1.1 (a
    // denied OBSERVED license can never be licensed back in).
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed-evil",
        detected: { registry: "BUSL-1.1" },
        expression: "Apache-2.0",
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed-evil", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a legit clarify over a NON-denied observed license still applies normally", () => {
    // Observed "Apache" (imprecise); a clarify disambiguates to Apache-2.0.
    // The observed license is NOT denied, so the override applies as usual.
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[clarify]]",
      'name = "legit"',
      'version = "1.0.0"',
      'detected = { registry = "Apache" }',
      'justification = "scan-more-precise"',
      'expression = "Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("legit", "Apache", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a denied observed license is denied even when the override REWRITES it (project clarify)", () => {
    // Mirror of the builtin case for a project clarify whose record still holds.
    const policyText = [
      denyLicenseFixture("SSPL-1.0"),
      "",
      "[[clarify]]",
      'name = "sspl-evil"',
      'version = "1.0.0"',
      'detected = { registry = "SSPL-1.0" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "rewrites a denied observed license"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("sspl-evil", "SSPL-1.0", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — deny election across SEPARATE [[deny]] entries (C#6: union allowlist)", () => {
  // The shipped policy ships BUSL-1.1, SSPL-1.0, Elastic-2.0 as THREE separate
  // match="license" entries. An OR across two of them must be denied: neither
  // branch is electable out of the UNION of all license deny allowlists.
  const THREE_SEPARATE_DENIES = [
    denyLicenseFixture("BUSL-1.1"),
    "",
    denyLicenseFixture("SSPL-1.0"),
    "",
    denyLicenseFixture("Elastic-2.0"),
  ].join("\n");

  test("'BUSL-1.1 OR SSPL-1.0' across separate deny entries IS denied", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-evil", "BUSL-1.1 OR SSPL-1.0", ["backend"])],
      THREE_SEPARATE_DENIES,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]"); // first contributing license rule
  });

  test("'MIT OR BUSL-1.1' (one branch denied, one not) stays electable / NOT denied", () => {
    const { verdicts } = runEngine(
      [pkgSpec("electable", "MIT OR BUSL-1.1", ["backend"])],
      THREE_SEPARATE_DENIES,
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("denyRuleFor: 'SSPL-1.0 OR Elastic-2.0' across separate entries is denied, attributed to the first contributing rule", () => {
    const policy = parsePolicy(THREE_SEPARATE_DENIES);
    const hit = denyRuleFor(policy, "SSPL-1.0 OR Elastic-2.0", "x");

    // Both branches denied via the union; attribute to the FIRST license rule
    // that contributes a denied leaf (SSPL-1.0 at index 1 here).
    expect(hit?.ruleId).toBe("denied[1]");
  });
});

// ===========================================================================
// FINDINGS #1 + #5 + #11 (same root cause): deny must see EVERY observed
// per-claim license, not just the lossy COMBINED finding expression.
//
// combineKnown (normalize.ts) elects an imprecise family BEFORE the precise
// members when hasPreciseCopyleft is false, SILENTLY DROPPING a precise
// non-copyleft DENIED member (BUSL-1.1, Elastic-2.0 — source-available,
// NOT in COPYLEFT_IDS) when an imprecise family token ("GPL") co-exists:
//   [BUSL-1.1, GPL] → combine elects family "GPL" → expression null →
//   deny terminal (which reads the COMBINED expression) never sees BUSL-1.1
//   → bypassed (warn, not fail).
// Same gap via the all-or-nothing UNKNOWN collapse in gating (app) scope
// (#11): [BUSL-1.1, <custom>] → unknown → deny can't match a null expression.
//
// FIX: the deny terminal evaluates against the SET of all observed per-claim
// normalized precise licenses (finding.observedExpressions), not just the
// single combined assessment.expression — so a denied member is seen
// regardless of whether the combine renders precise/imprecise/unknown.
// ===========================================================================

/** A multi-claim spec (pkgSpec only takes one claim). */
function multiClaimSpec(
  name: string,
  claims: ReadonlyArray<string>,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  scope: "app" | "os" = "app",
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims,
    occurrences,
    scope,
  };
}

describe("evaluate — deny sees EVERY observed claim (#1/#5/#11: lossy combine must not hide a denied member)", () => {
  const denyBusl = denyLicenseFixture("BUSL-1.1");
  const denyElastic = denyLicenseFixture("Elastic-2.0");

  // The load-bearing regressions, in BOTH app and os scope: a denied precise
  // member co-present with an imprecise family / custom token must still FAIL
  // denied[i], even though combineKnown renders the finding imprecise/unknown.
  for (const scope of ["app", "os"] as const) {
    test(`[BUSL-1.1, GPL] in ${scope} scope → fail denied[0] (imprecise-family combine hides BUSL)`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("busl-gpl", ["BUSL-1.1", "GPL"], ["backend"], scope)],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
      expect(verdicts[0].reason).toContain("BUSL-1.1");
    });

    test(`[Elastic-2.0, GPL] in ${scope} scope → fail denied[0]`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("elastic-gpl", ["Elastic-2.0", "GPL"], ["backend"], scope)],
        denyElastic,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });

    test(`[BUSL-1.1, public-domain] in ${scope} scope → fail denied[0] (unknown token co-present)`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("busl-pd", ["BUSL-1.1", "public-domain"], ["backend"], scope)],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });

    test(`[BUSL-1.1, <custom>] in ${scope} scope → fail denied[0] (#11 unknown collapse)`, () => {
      const { verdicts } = runEngine(
        [
          multiClaimSpec(
            "busl-custom",
            ["BUSL-1.1", "some-bespoke-corp-license"],
            ["backend"],
            scope,
          ),
        ],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });
  }

  test("control: [BUSL-1.1, MIT] still fails denied[0] (combine renders precise, deny already saw it)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("busl-mit", ["BUSL-1.1", "MIT"], ["backend"])],
      denyBusl,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a non-denied [MIT, GPL] is UNAFFECTED (no over-denial regression)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("mit-gpl", ["MIT", "GPL"], ["backend"])],
      denyBusl,
    );

    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("[SSPL-1.0, GPL] still fails denied (the original copyleft+source-available case)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("sspl-gpl", ["SSPL-1.0", "GPL"], ["backend"])],
      denyLicenseFixture("SSPL-1.0"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a single denied claim still fails (no observedExpressions regression for the single-claim path)", () => {
    const { verdicts } = runEngine([pkgSpec("busl-only", "BUSL-1.1", ["backend"])], denyBusl);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("policy.example.toml — the shipped [[deny]] block", () => {
  const exampleText = readFileSync(join(import.meta.dir, "..", "policy.example.toml"), "utf8");
  const examplePolicy = parsePolicy(exampleText);

  test("ships the source-available set BUSL-1.1, SSPL-1.0, Elastic-2.0 as built-in defaults", () => {
    const licensePatterns = BUILTIN_DENY_RULES.filter((r) => r.match === "license").map(
      (r) => r.pattern,
    );

    for (const id of ["BUSL-1.1", "SSPL-1.0", "Elastic-2.0"]) {
      expect(licensePatterns.some((p) => p.includes(id))).toBe(true);
    }
  });

  test("ships an RSAL deny entry (name-mode, no SPDX id) and a Commons-Clause rider", () => {
    // RSAL has no registered SPDX id, so it is name-mode and its rationale
    // lives in the reason (audit trail), not the SPDX-less pattern.
    expect(
      examplePolicy.deny.some((r) => r.match === "name" && r.reason.toLowerCase().includes("rsal")),
    ).toBe(true);
    expect(
      examplePolicy.deny.some(
        (r) =>
          r.match === "name" &&
          (r.pattern.toLowerCase().includes("commons-clause") ||
            r.reason.toLowerCase().includes("commons-clause")),
      ),
    ).toBe(true);
  });

  test("every license-mode deny SPDX id is a real spdx-license-id (typo-proof)", () => {
    const dataDir = join(import.meta.dir, "..", "node_modules", "spdx-license-ids");
    const current = JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const leafIds: string[] = [];
    const walk = (node: unknown): void => {
      if (typeof node !== "object" || node === null) {
        return;
      }

      const n = node as Record<string, unknown>;

      if (typeof n.license === "string") {
        leafIds.push(n.license);
      }

      walk(n.left);
      walk(n.right);
    };

    for (const rule of examplePolicy.deny) {
      if (rule.match === "license") {
        walk(parseSpdxId(rule.pattern));
      }
    }

    expect(leafIds.filter((id) => !known.has(id))).toEqual([]);
  });
});

// ===========================================================================
// The `[os_dependencies]` knob + the package-level os-scope downgrade
// at the would-be default-FAIL terminals. Mirrors the dev_dependencies
// suite EXACTLY, but routes on entry.scope === "os" (package-level), not the
// occurrence-level dev marker. Deny stays terminal-0 above the os downgrade.
// ===========================================================================

/** An OS-scope copyleft package (a pkg:deb glibc-style LGPL row). */
const OS_COPYLEFT = osPkgSpec("pkg:deb/debian/libc6@2.36-9", "libc6", "LGPL-2.1-or-later", [
  "docker:img/Dockerfile",
]);

/** An OS-scope UNKNOWN-license package (zero claims). */
const OS_UNKNOWN = osPkgSpec("pkg:apk/alpine/mystery@1.0.0", "mystery", null, [
  "docker:img/Dockerfile",
]);

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

    expect(error.problems).toContain(
      'os_dependencies.handling: must be "warn", "fail", or "ignore"',
    );
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

describe("evaluate — os-scope downgrade (default warn)", () => {
  test("HEADLINE: an os-scope copyleft WARNS under default os_dependencies=warn", () => {
    const { verdicts } = runEngine([OS_COPYLEFT], "");

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test('os_dependencies="fail" gates an os-scope copyleft exactly like an app one', () => {
    const { verdicts } = runEngine([OS_COPYLEFT], '[os_dependencies]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test('os_dependencies="ignore" makes an os-scope copyleft ok (rule id preserved)', () => {
    const { verdicts } = runEngine([OS_COPYLEFT], '[os_dependencies]\nhandling = "ignore"');

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=ignore");
  });

  test("the os-scope downgrade applies at the unknown-fail terminal too", () => {
    const { verdicts } = runEngine([OS_UNKNOWN], '[unknown]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:unknown");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an APP-scope copyleft is UNAFFECTED by os_dependencies (only scope===os routes through applyOsScope)", () => {
    // Same license, app scope, prod occurrence: os_dependencies must not touch
    // it — it fails on the genuine default:copyleft terminal.
    const { verdicts } = runEngine(
      [pkgSpec("agpl-app", "AGPL-3.0-only", ["apps/b"])],
      '[os_dependencies]\nhandling = "ignore"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).not.toContain("os_dependencies");
  });
});

describe("evaluate — deny STAYS TERMINAL over the os knob", () => {
  test("an os-scope package matching a [[deny]] license still FAILS regardless of os_dependencies", () => {
    // A source-available license in an OS package is denied: the os knob never
    // licenses it back in (denyVerdict returns first in verdictFor).
    for (const handling of ["warn", "fail", "ignore"] as const) {
      const policyText = [
        denyLicenseFixture("BUSL-1.1"),
        "",
        "[os_dependencies]",
        `handling = "${handling}"`,
      ].join("\n");
      const { verdicts } = runEngine(
        [
          osPkgSpec("pkg:deb/debian/evil-os@1.0.0", "evil-os", "BUSL-1.1", [
            "docker:img/Dockerfile",
          ]),
        ],
        policyText,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
      expect(verdicts[0].reason).not.toContain("os_dependencies");
    }
  });

  test("name-mode deny on an os-scope package with UNKNOWN finding still fails", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/rider-os@1.0.0", "rider-os", null, ["docker:img/Dockerfile"])],
      denyNameFixture("rider-os"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — os-scope and dev-scope downgraders compose without interaction", () => {
  test("an os-scope copyleft WARNS under dev_dependencies=fail AND os_dependencies=warn (dev lane never clobbers it)", () => {
    // The package is os-scope with a NON-dev (prod) occurrence: it is not a dev
    // occurrence, so the dev lane (set to fail) must not touch it. The os lane
    // (warn) downgrades the would-be FAIL. The two downgraders compose: an
    // os-scope package is not a dev occurrence, so dev_dependencies=fail is
    // inert on it and the os warn stands.
    const policyText = [
      "[dev_dependencies]",
      'handling = "fail"',
      "",
      "[os_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine([OS_COPYLEFT], policyText);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an os-scope copyleft on a DEV occurrence under os=warn + dev=fail still warns (os downgrade owns the os package)", () => {
    // Locks the composition ORDER: even when the single occurrence is dev-marked
    // AND dev_dependencies=fail, the os-scope warn downgrade is applied so the
    // verdict is warn, not fail. The os lane is not clobbered by the dev lane.
    const policyText = [
      "[dev_dependencies]",
      'handling = "fail"',
      "",
      "[os_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/libc6@2.36-9", "libc6", "LGPL-2.1-or-later", [
          { target: "docker:img/Dockerfile", dev: true },
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an APP-scope dev copyleft still downgrades via the dev lane while os=ignore is inert on it", () => {
    // The reverse non-interaction: an app-scope dev copyleft under
    // dev=warn + os=ignore warns through the DEV lane (os lane inert on app).
    const policyText = [
      "[dev_dependencies]",
      'handling = "warn"',
      "",
      "[os_dependencies]",
      'handling = "ignore"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("agpl-app", "AGPL-3.0-only", [{ target: "apps/a", dev: true }])],
      policyText,
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].reason).toContain("dev-only occurrence");
    expect(verdicts[0].reason).not.toContain("os_dependencies");
  });
});

// ===========================================================================
// The os-scope PARTIAL finding evaluates on its KNOWN-member expression.
// A known copyleft member → applyOsScope → warn (non-gating); a known denied
// member STAYS terminal (deny is checked before applyOsScope). The
// unrecognizedTokens themselves never gate (os non-gating). No change to
// app-scope verdicts (the all-or-nothing → unknown invariant holds there).
// ===========================================================================

/** A multi-claim os-scope spec (the partial-finding shape). */
const osMultiSpec = (
  name: string,
  claims: ReadonlyArray<string>,
  occurrences: ReadonlyArray<OccurrenceSpec> = ["docker:img/Dockerfile"],
): PackageSpec => ({
  purl: `pkg:deb/debian/${name}@1.0.0`,
  name,
  version: "1.0.0",
  claims,
  occurrences,
  scope: "os",
});

describe("evaluate — os-scope partial finding", () => {
  test("os [GPL-2.0-only, BSD-3-Clause, public-domain] → known copyleft WARNS (os non-gating)", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-partial", ["GPL-2.0-only", "BSD-3-Clause", "public-domain"])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("a known permissive os-partial member → ok (default:ok), tokens do not gate", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-perm", ["MIT", "public-domain", "Artistic"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("DENY STAYS TERMINAL over an os-partial: a denied KNOWN member still FAILS", () => {
    // BUSL-1.1 is a known normalizable member; public-domain is the surfaced
    // remainder. Deny is checked before applyOsScope, so the os knob never
    // licenses the denied known member back in.
    for (const handling of ["warn", "fail", "ignore"] as const) {
      const policyText = [
        denyLicenseFixture("BUSL-1.1"),
        "",
        "[os_dependencies]",
        `handling = "${handling}"`,
      ].join("\n");
      const { verdicts } = runEngine(
        [osMultiSpec("os-denied", ["BUSL-1.1", "public-domain"])],
        policyText,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    }
  });

  test("os_dependencies=fail gates an os-partial copyleft member exactly like an app one", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-partial-fail", ["GPL-2.0-only", "public-domain"])],
      '[os_dependencies]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("INVARIANT: app-scope [GPL-2.0-only, custom] stays UNKNOWN (no partial, no gate weakening)", () => {
    // The same mixed claim set in app scope: still unknown. Under unknown=fail it
    // FAILS as unknown — a partial finding never licenses an app row to a clean
    // expression.
    const appMixed: PackageSpec = {
      purl: "pkg:npm/app-mixed@1.0.0",
      name: "app-mixed",
      version: "1.0.0",
      claims: ["GPL-2.0-only", "custom"],
      occurrences: ["apps/a"],
    };
    const { verdicts } = runEngine([appMixed], '[unknown]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });
});

// ===========================================================================
// AGPL in a container system package escalates to a REAL fail
// (default:agpl-container), never the routine os-scope downgrade —
// network copyleft (AGPL section 13) applies to server-side container use.
// ===========================================================================

describe("AGPL_IDS — literal set (copyleft.ts)", () => {
  test("is exactly the six AGPL ids", () => {
    expect([...AGPL_IDS].sort()).toEqual([
      "AGPL-1.0",
      "AGPL-1.0-only",
      "AGPL-1.0-or-later",
      "AGPL-3.0",
      "AGPL-3.0-only",
      "AGPL-3.0-or-later",
    ]);
  });

  test("every member is in COPYLEFT_IDS", () => {
    for (const id of AGPL_IDS) {
      expect(COPYLEFT_IDS.has(id)).toBe(true);
    }
  });

  test('drift tripwire: every COPYLEFT_IDS id with the "AGPL-" prefix is in AGPL_IDS', () => {
    // TEST-only prefix scan — a future FAMILY_MEMBERS addition can never
    // silently miss the escalation set. Runtime matching stays exact-ID
    // (AGPL_IDS.has), never a prefix check.
    for (const id of COPYLEFT_IDS) {
      if (id.startsWith("AGPL-")) {
        expect(AGPL_IDS.has(id)).toBe(true);
      }
    }
  });
});

describe("evaluate — os-scope AGPL container escalation", () => {
  const AGPL_TARGET = "docker:img/Dockerfile";

  test("HEADLINE: os-scope AGPL-3.0-only under os_dependencies=warn escalates to a REAL fail, not the routine warn", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("os_dependencies=ignore does not license the AGPL container package back in (the loudest current escape)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      '[os_dependencies]\nhandling = "ignore"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("os_dependencies=fail also fails with the SAME distinct rule id (deterministic across every handling)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      '[os_dependencies]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("OR-election: AGPL-3.0-only OR MIT elects MIT and stays default:ok (election semantics preserved)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-or-mit@1.0.0", "agpl-or-mit", "AGPL-3.0-only OR MIT", [
          AGPL_TARGET,
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("AND-taint: GPL-2.0-only AND AGPL-3.0-or-later escalates (copyleftLeafIds sees both conjuncts)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec(
          "pkg:deb/debian/gpl-and-agpl@1.0.0",
          "gpl-and-agpl",
          "GPL-2.0-only AND AGPL-3.0-or-later",
          [AGPL_TARGET],
        ),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("app-scope precise AGPL stays default:copyleft UNCHANGED — the new rule id is container-only", () => {
    const { verdicts } = runEngine([pkgSpec("agpl-app", "AGPL-3.0-only", ["apps/a"])], "");

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("defensive: an os-scope AGPL occurrence marked isDevDependency=true still fails (no dev softening)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [
          { target: AGPL_TARGET, dev: true },
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("a where-scoped [[compatible]] package rule still accepts an os AGPL package (the explicit escape hatch)", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-os-accepted"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([AGPL_TARGET])}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-accepted@1.0.0", "agpl-os-accepted", "AGPL-3.0-only", [
          AGPL_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("a [[deny]] license match still yields denied[..] (deny is terminal above the AGPL escalation too)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-denied@1.0.0", "agpl-os-denied", "AGPL-3.0-only", [
          AGPL_TARGET,
        ]),
      ],
      denyLicenseFixture("AGPL-3.0-only"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("regression: a docker:-prefixed suppression can no longer absorb the os-scope AGPL escalation — parsePolicy rejects the policy outright, so evaluate never even runs against it", () => {
    const policyText = [
      "[[workspace.copyleft_suppressed]]",
      `path = ${JSON.stringify(AGPL_TARGET)}`,
      'license = "AGPL-3.0-only"',
      'description = "attempted absorption of the container image"',
    ].join("\n");

    expect(() => parsePolicy(policyText)).toThrow(PolicyError);

    // With that suppression impossible to construct, the same os-scope AGPL
    // package at the same target has only one reachable outcome: the
    // container escalation fail — never suppressed.
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });
});

describe("evaluate — imprecise AGPL container escalation (imprecise variant)", () => {
  test("os-scope imprecise AGPL fails default:agpl-container (the imprecise escape lane is closed too, not just the precise-expression one)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:apk/alpine/agpl-ish@1.0.0", "agpl-ish", "AGPL", ["docker:img/Dockerfile"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("app-scope imprecise AGPL stays warn default:imprecise-copyleft UNCHANGED", () => {
    const { verdicts } = runEngine([pkgSpec("agpl-ish-app", "AGPL", ["apps/a"])], "");

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });

  test("os-scope imprecise GPL (not AGPL) stays warn default:imprecise-copyleft UNCHANGED — only the literal AGPL token escalates", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/gpl-ish-os@1.0.0", "gpl-ish-os", "GPL", [
          "docker:img/Dockerfile",
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });
});

// ---------------------------------------------------------------------------
// Accepted-AGPL container notices (evaluate.ts#acceptedContainerNotices): an
// os-scope AGPL obligation that was ACCEPTED (status "ok" via a
// `[[compatible]]` rule) rather than failing must still surface, as a
// non-blocking notice, distinct from the Verdict[] the CycloneDX/summary
// consumers read.
// ---------------------------------------------------------------------------

describe("evaluate — accepted-AGPL container notices (acceptedContainerNotices)", () => {
  const NOTICE_TARGET = "docker:img/Dockerfile";

  test("a precise AGPL system package accepted via a scoped [[compatible]] package rule surfaces as an accepted-container notice", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-os-notice"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([NOTICE_TARGET])}`,
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-notice@1.0.0", "agpl-os-notice", "AGPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");

    const notices = acceptedContainerNotices(model, verdicts);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({
      purl: "pkg:deb/debian/agpl-os-notice@1.0.0",
      name: "agpl-os-notice",
      version: "1.0.0",
      license: "AGPL-3.0-only",
      targets: [NOTICE_TARGET],
      rule: "compatible[0]",
    });
  });

  test('the imprecise "AGPL" family accepted via a scoped [[compatible]] package rule also surfaces as a notice', () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-ish-notice"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([NOTICE_TARGET])}`,
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:apk/alpine/agpl-ish-notice@1.0.0", "agpl-ish-notice", "AGPL", [
          NOTICE_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");

    const notices = acceptedContainerNotices(model, verdicts);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({
      purl: "pkg:apk/alpine/agpl-ish-notice@1.0.0",
      license: "AGPL",
      targets: [NOTICE_TARGET],
      rule: "compatible[0]",
    });
  });

  test("regression: a routine GPL/LGPL system package (accepted or os-downgraded) is never an accepted-container notice — the fix does not widen the net", () => {
    const acceptPolicy = [
      "[[compatible]]",
      'match = "package"',
      'name = "gpl-os-accepted"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts: acceptedVerdicts, model: acceptedModel } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/gpl-os-accepted@1.0.0", "gpl-os-accepted", "GPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      acceptPolicy,
    );

    expect(acceptedVerdicts[0].status).toBe("ok");
    expect(acceptedContainerNotices(acceptedModel, acceptedVerdicts)).toHaveLength(0);

    const { verdicts: warnVerdicts, model: warnModel } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/lgpl-os-warn@1.0.0", "lgpl-os-warn", "LGPL-2.1-or-later", [
          NOTICE_TARGET,
        ]),
      ],
      "",
    );

    expect(warnVerdicts[0].status).toBe("warn");
    expect(acceptedContainerNotices(warnModel, warnVerdicts)).toHaveLength(0);
  });

  test("a FAILING AGPL system package (not accepted) is not an accepted-container notice — Problematic only, never duplicated", () => {
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-failing@1.0.0", "agpl-os-failing", "AGPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
    expect(acceptedContainerNotices(model, verdicts)).toHaveLength(0);
  });

  test("determinism: notices sort by purl (compareCodeUnits), target lists dedupe+sort, and repeated calls are byte-identical", () => {
    const TARGET_A = "docker:a/Dockerfile";
    const TARGET_B = "docker:b/Dockerfile";
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "zeta-agpl"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "alpha-agpl"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/zeta-agpl@1.0.0", "zeta-agpl", "AGPL-3.0-only", [
          TARGET_B,
          TARGET_A,
        ]),
        osPkgSpec("pkg:deb/debian/alpha-agpl@1.0.0", "alpha-agpl", "AGPL-3.0-only", [TARGET_A]),
      ],
      policyText,
    );
    const notices1 = acceptedContainerNotices(model, verdicts);
    const notices2 = acceptedContainerNotices(model, verdicts);

    expect(notices1).toEqual(notices2);
    expect(notices1.map((n) => n.purl)).toEqual([
      "pkg:deb/debian/alpha-agpl@1.0.0",
      "pkg:deb/debian/zeta-agpl@1.0.0",
    ]);
    expect(notices1[1]!.targets).toEqual([TARGET_A, TARGET_B]);
  });
});

// ---------------------------------------------------------------------------
// [docker] ignore — Dockerfile-discovery exclusion globs.
// ---------------------------------------------------------------------------

describe("[docker] ignore parsing", () => {
  test("absent [docker] table → docker is undefined", () => {
    const policy = parsePolicy("");

    expect(policy.docker).toBeUndefined();
  });

  test("valid ignore globs parse into a readonly array", () => {
    const policy = parsePolicy('[docker]\nignore = ["docker/dev/**", "legacy/Dockerfile"]\n');

    expect(policy.docker).toEqual({
      ignore: ["docker/dev/**", "legacy/Dockerfile"],
      development: [],
    });
  });

  test("[docker] with no ignore key → ignore defaults to empty array", () => {
    const policy = parsePolicy("[docker]\n");

    expect(policy.docker).toEqual({ ignore: [], development: [] });
  });

  test("a non-table [docker] value is rejected", () => {
    const err = expectPolicyError('docker = "nope"\n');

    expect(err.problems.some((p) => p.includes("docker"))).toBe(true);
  });

  test("a non-array ignore is rejected", () => {
    const err = expectPolicyError('[docker]\nignore = "docker/dev"\n');

    expect(err.problems.some((p) => p.includes("ignore"))).toBe(true);
  });

  test("an empty-string ignore entry is rejected", () => {
    const err = expectPolicyError('[docker]\nignore = [""]\n');

    expect(err.problems.length).toBeGreaterThan(0);
  });

  test("a backslash ignore entry is rejected (forward-slash posture)", () => {
    const err = expectPolicyError('[docker]\nignore = ["docker\\\\dev"]\n');

    expect(err.problems.some((p) => p.includes("forward slashes"))).toBe(true);
  });

  test("a `..`-segment ignore entry is rejected", () => {
    const err = expectPolicyError('[docker]\nignore = ["../escape/**"]\n');

    expect(err.problems.some((p) => p.includes(".."))).toBe(true);
  });

  test("a non-string ignore entry is rejected", () => {
    const err = expectPolicyError("[docker]\nignore = [42]\n");

    expect(err.problems.length).toBeGreaterThan(0);
  });

  test("an unknown key under [docker] is rejected", () => {
    const err = expectPolicyError('[docker]\nbogus = "x"\n');

    expect(err.problems.some((p) => p.includes("bogus"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// [[docker.development]] — per-container development marking (glob source).
// ---------------------------------------------------------------------------

/** Minimal [docker] table with one [[docker.development]] entry. */
const developmentFixture = (source: string, reason = "test reason"): string =>
  [
    "[docker]",
    "",
    "[[docker.development]]",
    `source = ${JSON.stringify(source)}`,
    `reason = ${JSON.stringify(reason)}`,
  ].join("\n");

describe("[[docker.development]] schema parsing", () => {
  test("a literal path source parses; policy.docker.development carries it verbatim", () => {
    const policy = parsePolicy(
      developmentFixture(
        "examples/docker-scan/Dockerfile",
        "spun up only for local scan smoke-tests, never shipped",
      ),
    );

    expect(policy.docker).toEqual({
      ignore: [],
      development: [
        {
          source: "examples/docker-scan/Dockerfile",
          reason: "spun up only for local scan smoke-tests, never shipped",
        },
      ],
    });
  });

  test("a `**` glob source parses and is stored verbatim", () => {
    const policy = parsePolicy(developmentFixture("tools/**"));

    expect(policy.docker?.development).toEqual([{ source: "tools/**", reason: "test reason" }]);
  });

  test("a `*` glob source parses and is stored verbatim", () => {
    const policy = parsePolicy(developmentFixture("examples/*/Dockerfile"));

    expect(policy.docker?.development).toEqual([
      { source: "examples/*/Dockerfile", reason: "test reason" },
    ]);
  });

  test("[docker] present without the development key → development defaults to []", () => {
    const policy = parsePolicy("[docker]\nignore = []\n");

    expect(policy.docker).toEqual({ ignore: [], development: [] });
  });

  test("no [docker] table at all → docker stays undefined (unchanged)", () => {
    const policy = parsePolicy("");

    expect(policy.docker).toBeUndefined();
  });

  test("missing reason rejects naming docker.development[0]", () => {
    const err = expectPolicyError(
      ["[docker]", "", "[[docker.development]]", 'source = "tools/**"'].join("\n"),
    );

    expect(
      err.problems.some(
        (p) => p.includes("docker.development[0]") && p.includes('missing required key "reason"'),
      ),
    ).toBe(true);
  });

  test("an empty-string source rejects naming docker.development[0]", () => {
    const err = expectPolicyError(developmentFixture(""));

    expect(err.problems.some((p) => p.includes("docker.development[0]"))).toBe(true);
  });

  test("a backslash source rejects (forward-slash posture, byte-identical to docker.ignore)", () => {
    const err = expectPolicyError(developmentFixture("tools\\dev"));

    expect(err.problems.some((p) => p.includes("forward slashes"))).toBe(true);
  });

  test('a ".." segment source rejects', () => {
    const err = expectPolicyError(developmentFixture("../escape/**"));

    expect(err.problems.some((p) => p.includes(".."))).toBe(true);
  });

  test("a leading-slash source rejects", () => {
    const err = expectPolicyError(developmentFixture("/tools/**"));

    expect(err.problems.some((p) => p.includes("leading or trailing slash"))).toBe(true);
  });

  test('a "docker:"-prefixed source rejects with a pointed double-prefix message', () => {
    const err = expectPolicyError(developmentFixture("docker:tools/Dockerfile"));

    expect(
      err.problems.some((p) => p.includes("docker.development[0]") && p.includes('"docker:"')),
    ).toBe(true);
  });

  test("two entries with the SAME pattern string reject as a dead duplicate", () => {
    const policyText = [
      "[docker]",
      "",
      "[[docker.development]]",
      'source = "tools/**"',
      'reason = "first"',
      "",
      "[[docker.development]]",
      'source = "tools/**"',
      'reason = "second, duplicate pattern"',
    ].join("\n");
    const err = expectPolicyError(policyText);

    expect(
      err.problems.some((p) => p.includes("docker.development[1]") && p.includes("duplicate")),
    ).toBe(true);
  });

  test("two DIFFERENT patterns that could match the same container are legal", () => {
    const policyText = [
      "[docker]",
      "",
      "[[docker.development]]",
      'source = "tools/**"',
      'reason = "first"',
      "",
      "[[docker.development]]",
      'source = "tools/nested/**"',
      'reason = "second, different pattern"',
    ].join("\n");
    const policy = parsePolicy(policyText);

    expect(policy.docker?.development).toEqual([
      { source: "tools/**", reason: "first" },
      { source: "tools/nested/**", reason: "second, different pattern" },
    ]);
  });

  test("an unknown key inside a [[docker.development]] entry rejects via checkKeys", () => {
    const policyText = [
      "[docker]",
      "",
      "[[docker.development]]",
      'source = "tools/**"',
      'reason = "test reason"',
      "bogus = 1",
    ].join("\n");
    const err = expectPolicyError(policyText);

    expect(
      err.problems.some((p) => p.includes("docker.development[0]") && p.includes("bogus")),
    ).toBe(true);
  });

  test("[docker] ignore and [[docker.development]] compose in one policy", () => {
    const policyText = [
      "[docker]",
      'ignore = ["legacy/**"]',
      "",
      "[[docker.development]]",
      'source = "tools/Dockerfile"',
      'reason = "internal tooling image, never shipped"',
    ].join("\n");
    const policy = parsePolicy(policyText);

    expect(policy.docker).toEqual({
      ignore: ["legacy/**"],
      development: [
        {
          source: "tools/Dockerfile",
          reason: "internal tooling image, never shipped",
        },
      ],
    });
  });
});

describe("evaluate — [[allow_source_available]] exemption (ADR-0013 opt-out)", () => {
  const exemptBusl = [
    "[[allow_source_available]]",
    'license = "BUSL-1.1"',
    'reason = "internal-only build tool, never redistributed; counsel-approved"',
  ].join("\n");

  test("an exempted source-available license WARNS (allowed), not fail", () => {
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], exemptBusl);

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("allow_source_available[0]");
  });

  test("a non-exempted source-available license still FAILS by default", () => {
    const { verdicts } = runEngine([pkgSpec("sspl-pkg", "SSPL-1.0", ["backend"])], exemptBusl);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:source-available");
  });

  test("an explicit [[deny]] wins over an exemption (the consumer's own choice)", () => {
    const policyText = [
      "[[deny]]",
      'match = "license"',
      'pattern = "BUSL-1.1"',
      'reason = "we deny it regardless of the default"',
      "",
      exemptBusl,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("policy — [[allow_source_available]] validation", () => {
  test("rejects a licence that is not a built-in source-available default", () => {
    const error = expectPolicyError(
      ["[[allow_source_available]]", 'license = "MIT"', 'reason = "x"'].join("\n"),
    );

    expect(error.message).toContain("not a built-in source-available default");
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

describe("parsePolicy — [cache] table", () => {
  test("dir is captured", () => {
    const policy = parsePolicy('[cache]\ndir = "eng/.sbomlet.cache"\n');

    expect(policy.cache).toEqual({ dir: "eng/.sbomlet.cache" });
  });

  test("an empty [cache] table yields {} (the default applies at resolution)", () => {
    expect(parsePolicy("[cache]\n").cache).toEqual({});
  });

  test("an absent [cache] table yields undefined", () => {
    expect(parsePolicy('[unknown]\nhandling = "warn"\n').cache).toBeUndefined();
  });

  test('a ".." segment is rejected (a committed dir cannot escape the repo)', () => {
    expect(expectPolicyError('[cache]\ndir = "../outside"\n').message).toContain("cache.dir");
  });

  test("a leading slash is rejected", () => {
    expect(expectPolicyError('[cache]\ndir = "/abs"\n').message).toContain("cache.dir");
  });

  test("an unknown key is rejected", () => {
    expect(expectPolicyError('[cache]\nfolder = "x"\n').message).toContain('unknown key "folder"');
  });

  test("an empty dir is rejected", () => {
    expect(expectPolicyError('[cache]\ndir = ""\n').message).toContain("cache");
  });
});

describe("parsePolicy — [target] table", () => {
  test("policy.target is undefined when absent", () => {
    expect(parsePolicy('[unknown]\nhandling = "warn"\n').target).toBeUndefined();
  });

  test("a complete project profile without unknown_pair parses, defaulting unknown_pair to warn", () => {
    const policy = parsePolicy(
      ["[target]", 'license = "MIT"', "network = false", 'distribution = "external"', ""].join(
        "\n",
      ),
    );

    expect(policy.target).toEqual({
      profile: { license: { kind: "oss", id: "MIT" }, network: false, distribution: "external" },
      unknownPair: "warn",
      workspaces: [],
    });
  });

  test("a proprietary target with unknown_pair captures both", () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "proprietary"',
        "network = true",
        'distribution = "internal"',
        'unknown_pair = "fail"',
        "",
      ].join("\n"),
    );

    expect(policy.target).toEqual({
      profile: { license: { kind: "proprietary" }, network: true, distribution: "internal" },
      unknownPair: "fail",
      workspaces: [],
    });
  });

  test("a workspaces-only [target] whose every entry is complete parses with no project profile", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "public API service"',
        "",
      ].join("\n"),
    );

    expect(policy.target?.profile).toBeUndefined();
    expect(policy.target?.workspaces).toEqual([
      {
        path: "apps/api",
        license: { kind: "oss", id: "MIT" },
        reason: "public API service",
        network: false,
        distribution: "external",
      },
    ]);
  });

  test("per-field inheritance: a workspace entry may carry only path/license/reason under a complete project profile", () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "GPL-3.0-only"',
        'reason = "diverging outbound license for this workspace"',
        "",
      ].join("\n"),
    );

    expect(policy.target?.workspaces).toEqual([
      {
        path: "apps/api",
        license: { kind: "oss", id: "GPL-3.0-only" },
        reason: "diverging outbound license for this workspace",
      },
    ]);
  });

  test("TOP_LEVEL_KEYS accepts clarifications (no unknown-top-level-key rejection)", () => {
    expect(() => parsePolicy('clarifications = "clarifications.toml"')).not.toThrow();
  });

  test("TOP_LEVEL_KEYS accepts target (no unknown-top-level-key rejection)", () => {
    expect(() =>
      parsePolicy(
        ["[target]", 'license = "MIT"', "network = false", 'distribution = "external"', ""].join(
          "\n",
        ),
      ),
    ).not.toThrow();
  });

  test("rejects missing network, naming the table path and the missing key", () => {
    const error = expectPolicyError(
      ["[target]", 'license = "MIT"', 'distribution = "external"', ""].join("\n"),
    );

    expect(error.message).toContain("target:");
    expect(error.message).toContain("declaring a target requires the full usage profile");
    expect(error.message).toContain('"network"');
  });

  test("rejects missing distribution, naming the missing key", () => {
    const error = expectPolicyError(
      ["[target]", 'license = "MIT"', "network = false", ""].join("\n"),
    );

    expect(error.message).toContain('"distribution"');
  });

  test("rejects missing license, naming the missing key", () => {
    const error = expectPolicyError(
      ["[target]", "network = false", 'distribution = "external"', ""].join("\n"),
    );

    expect(error.message).toContain('"license"');
  });

  test("rejects a compound license expression", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT OR Apache-2.0"',
        "network = false",
        'distribution = "external"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain("compound expression");
  });

  test("rejects a LicenseRef- target license", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "LicenseRef-proprietary-eula"',
        "network = false",
        'distribution = "external"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain("LicenseRef-/DocumentRef-");
  });

  test("rejects an unknown SPDX id (parse failure, house idiom)", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "Not-A-Real-License-XYZ"',
        "network = false",
        'distribution = "external"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain("not a valid SPDX expression");
  });

  test("rejects a project-level OSS target license that parses as SPDX but is absent from the compatibility matrix's rows", () => {
    const error = expectPolicyError(`[target]
license = "CC0-1.0"
network = false
distribution = "external"
`);

    expect(error.message).toContain("target:");
    expect(error.message).toContain('license "CC0-1.0"');
    expect(error.message).toContain("not covered by the compatibility matrix");
  });

  test("accepts a project-level OSS target license that is a matrix row (MIT)", () => {
    expect(() =>
      parsePolicy(`[target]
license = "MIT"
network = false
distribution = "external"
`),
    ).not.toThrow();
  });

  test("accepts the literal proprietary target license regardless of matrix coverage", () => {
    expect(() =>
      parsePolicy(`[target]
license = "proprietary"
network = false
distribution = "external"
`),
    ).not.toThrow();
  });

  test("rejects a [[target.workspace]] override license absent from the matrix, even when the project license is covered", () => {
    const error = expectPolicyError(`[target]
license = "MIT"
network = false
distribution = "external"

[[target.workspace]]
path = "apps/api"
license = "CC0-1.0"
reason = "diverging outbound license for this workspace"
`);

    expect(error.message).toContain("target.workspace[0]:");
    expect(error.message).toContain('license "CC0-1.0"');
    expect(error.message).toContain("not covered by the compatibility matrix");
  });

  test("rejects a non-boolean network", () => {
    const error = expectPolicyError(
      ["[target]", 'license = "MIT"', 'network = "false"', 'distribution = "external"', ""].join(
        "\n",
      ),
    );

    expect(error.message).toContain('key "network" must be a boolean');
  });

  test("rejects a distribution outside external|internal", () => {
    const error = expectPolicyError(
      ["[target]", 'license = "MIT"', "network = false", 'distribution = "worldwide"', ""].join(
        "\n",
      ),
    );

    expect(error.message).toContain('"external" or "internal"');
  });

  test("rejects unknown_pair outside warn|fail", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'unknown_pair = "ignore"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain('unknown_pair" must be "warn" or "fail"');
  });

  test("rejects an unknown key on the [target] table", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'strict = "true"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain('unknown key "strict"');
  });

  test("rejects an empty [target] table (a dead activation switch)", () => {
    const error = expectPolicyError("[target]\n");

    expect(error.message).toContain("declares nothing to govern");
  });

  test("rejects a docker:-prefixed [[target.workspace]] path", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "docker:services/app/Dockerfile"',
        'license = "MIT"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain('must not start with "docker:"');
  });

  test("rejects a duplicate [[target.workspace]] path", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        'reason = "first"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "GPL-3.0-only"',
        'reason = "second, duplicate path"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain("duplicates an earlier [[target.workspace]] entry");
  });

  test("rejects a [[target.workspace]] entry missing reason", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain('missing required key "reason"');
  });

  test("rejects a partial [[target.workspace]] profile when no complete project profile exists", () => {
    const error = expectPolicyError(
      [
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "network = false",
        'reason = "n/a"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain("must carry its own");
  });

  test("rejects an unknown key on a [[target.workspace]] entry", () => {
    const error = expectPolicyError(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        'reason = "n/a"',
        'weird = "x"',
        "",
      ].join("\n"),
    );

    expect(error.message).toContain('unknown key "weird"');
  });
});

// ---------------------------------------------------------------------------
// A [[compatible]] package entry states whose use of a package was judged. On
// a target with a dependency graph, a package it accepts that also arrives
// around every introducer it names contradicts that statement, and the entry
// accepts nothing there.
// ---------------------------------------------------------------------------

describe("evaluate — an entry the introduction chains contradict", () => {
  const GRAPH_TARGET = "apps/web";
  const WITH_A_DEPENDENCY_GRAPH: ReadonlySet<string> = new Set([GRAPH_TARGET]);
  const JUDGED = "pkg:npm/judged@1.0.0";
  const OTHER = "pkg:npm/other@1.0.0";
  const GPL_LIB = "pkg:npm/gpl-lib@1.0.0";
  const MPL_LIB = "pkg:npm/mpl-lib@1.0.0";

  /** The judged entry: both -lib packages, accepted as dependencies of "judged" alone. */
  const LIB_FAMILY_POLICY = [
    "[[compatible]]",
    'match = "package"',
    'pattern = "*-lib"',
    'version = "1.0.0"',
    'as-dependency-of = ["judged"]',
    'rationale = "license-reviewed"',
    `where = ["${GRAPH_TARGET}"]`,
  ].join("\n");

  /** Attach the provenance a lane deriving a dependency graph would have recorded. */
  function withIntroductions(
    model: CanonicalDependencies,
    byPurl: Readonly<Record<string, DependencyIntroduction>>,
  ): CanonicalDependencies {
    for (const entry of model.packages) {
      const introduction = byPurl[entry.purl];

      for (const occurrence of entry.occurrences) {
        if (introduction !== undefined) {
          occurrence.introduction = introduction;
        }
      }
    }

    return model;
  }

  /**
   * The workspace the entry is scoped to: "judged" and "other" are declared directly, both pull in
   * gpl-lib, and only "judged" pulls in mpl-lib.
   */
  const SCANNED_INTRODUCTIONS: Readonly<Record<string, DependencyIntroduction>> = {
    [JUDGED]: { direct: true, introducedBy: [] },
    [OTHER]: { direct: true, introducedBy: [] },
    [GPL_LIB]: { direct: false, introducedBy: [JUDGED, OTHER] },
    [MPL_LIB]: { direct: false, introducedBy: [JUDGED] },
  };

  function runChainEngine(
    policyText: string,
    introductions: Readonly<Record<string, DependencyIntroduction>> = SCANNED_INTRODUCTIONS,
  ): {
    verdicts: Verdict[];
    usedClarifyIndices: ReadonlySet<number>;
    policy: Policy;
    model: CanonicalDependencies;
  } {
    const policy = parsePolicy(policyText);
    const specs = [
      pkgSpec("judged", "MIT", [GRAPH_TARGET]),
      pkgSpec("other", "MIT", [GRAPH_TARGET]),
      pkgSpec("gpl-lib", "GPL-3.0-only", [GRAPH_TARGET]),
      { ...pkgSpec("mpl-lib", "MPL-2.0", []), occurrences: [{ target: GRAPH_TARGET, dev: true }] },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      withIntroductions(makeModel(specs), introductions),
      policy.clarify,
      [],
    );

    return {
      verdicts: evaluate(model, policy, WITH_A_DEPENDENCY_GRAPH),
      usedClarifyIndices,
      policy,
      model,
    };
  }

  /** gpl-lib as the scan reports a component no chain from the project reaches. */
  const ORPHANED_GPL_LIB: Readonly<Record<string, DependencyIntroduction>> = {
    ...SCANNED_INTRODUCTIONS,
    [GPL_LIB]: { direct: false, introducedBy: [] },
  };

  test("every package the entry governs there fails, not only the one that arrives around it", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY);
    const decided = verdicts.filter((v) => v.purl === GPL_LIB || v.purl === MPL_LIB);

    expect(decided.map((v) => [v.purl, v.status, v.rule])).toEqual([
      [GPL_LIB, "fail", "compatible:voided[0]"],
      [MPL_LIB, "fail", "compatible:voided[0]"],
    ]);
  });

  test("the reason names the chain and the package that arrives through it first", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY);
    const reason = verdicts.find((v) => v.purl === MPL_LIB)?.reason ?? "";

    expect(reason).toStartWith('other → gpl-lib introduces "gpl-lib" in "apps/web"');
    expect(reason).toContain('"as-dependency-of" does not cover how it arrives');
    expect(reason).toContain("split the entry");
  });

  test("a dev-only occurrence fails with the rest - a contradicted entry is not an obligation to downgrade", () => {
    const { verdicts } = runChainEngine(
      [LIB_FAMILY_POLICY, "", "[dev_dependencies]", 'handling = "warn"'].join("\n"),
    );

    expect(verdicts.find((v) => v.purl === MPL_LIB)?.status).toBe("fail");
  });

  test("naming every introducer leaves the entry standing", () => {
    const { verdicts } = runChainEngine(
      LIB_FAMILY_POLICY.replace('["judged"]', '["judged", "other"]'),
    );

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("compatible[0]");
    expect(verdicts.find((v) => v.purl === MPL_LIB)?.rule).toBe("compatible[0]");
  });

  test("a contradicted entry is never reported unused - it decided every occurrence it governs", () => {
    const { verdicts, usedClarifyIndices, policy } = runChainEngine(LIB_FAMILY_POLICY);

    expect(verdicts.some((v) => v.rule === "compatible:voided[0]")).toBeTrue();
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("its id stays outside the compatible[ prefix, so no acceptance surface reads it as one", () => {
    const { verdicts, model } = runChainEngine(LIB_FAMILY_POLICY);
    const voided = verdicts.find((v) => v.rule.startsWith("compatible:voided")) as Verdict;

    expect(voided.rule.startsWith("compatible[")).toBeFalse();
    expect(acceptedContainerNotices(model, verdicts)).toEqual([]);
  });

  test("a package recorded as arriving from nothing reachable is not accepted by the entry", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY, ORPHANED_GPL_LIB);

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("default:copyleft");
  });

  test("it does not void the entry either - the packages that do arrive stay accepted", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY, ORPHANED_GPL_LIB);

    expect(verdicts.find((v) => v.purl === MPL_LIB)?.rule).toBe("compatible[0]");
  });

  test("an entry judged under the project itself is contradicted by any chain into the package", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY.replace('["judged"]', '["self"]'));

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("compatible:voided[0]");
  });

  test("a package the project declares directly is covered by the project itself", () => {
    const { verdicts } = runChainEngine(
      LIB_FAMILY_POLICY.replace('pattern = "*-lib"', 'name = "judged"').replace(
        '["judged"]',
        '["self"]',
      ),
    );

    expect(verdicts.find((v) => v.purl === JUDGED)?.rule).toBe("compatible[0]");
  });
});

describe("evaluate — a target without a dependency graph says so", () => {
  const FLAT_TARGET = "docker:img/Dockerfile";

  test("an entry judged under the project accepts, and no output implies a chain was checked", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "busybox"',
      'as-dependency-of = ["self"]',
      'rationale = "os-package-unmodified"',
      `where = ["${FLAT_TARGET}"]`,
    ].join("\n");
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:apk/alpine/busybox@1.0.0", "busybox", "GPL-2.0-only", [FLAT_TARGET])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(verdicts[0].reason).not.toContain("→");
    expect(verdicts[0].reason).not.toContain("as-dependency-of");
  });
});

// ===========================================================================
// The invalid-justification lane. An entry whose recorded detections still
// hold, but whose stated reason the current signal disproves, fails on its
// own rule id; an entry whose reason has nothing left to correct is reported
// to maintainer tooling and never reaches a verdict.
// ===========================================================================

describe("evaluate — a clarify entry the current signal disproves", () => {
  const DUAL_CHOICE = [
    "[[clarify]]",
    'name = "choice-lib"',
    'version = "1.0.0"',
    'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
    'justification = "dual-license-choice"',
    'expression = "MIT OR Apache-2.0"',
  ].join("\n");

  test("a disproved justification fails on its own rule id, naming the refile", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      DUAL_CHOICE,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("clarify:invalid[0]");
    expect(verdicts[0].reason).toContain("choice-lib@1.0.0");
    expect(verdicts[0].reason).toContain("contradictory-claims-recorded");
  });

  test("a justification the signal still supports decides nothing here", () => {
    const joined = [
      "[[clarify]]",
      'name = "choice-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT OR Apache-2.0", intensive = "Apache-2.0 AND MIT" }',
      'justification = "dual-license-choice"',
      'expression = "MIT OR Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "Apache-2.0 AND MIT", ["backend"])],
      joined,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a diverged detection is the more urgent answer and decides first", () => {
    const policyText = [
      "[[clarify]]",
      'name = "choice-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
      'justification = "dual-license-choice"',
      'expression = "MIT OR Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "GPL-3.0-only", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
  });

  test("the failing entry is never also reported as an unused entry", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      DUAL_CHOICE,
    );

    expect(verdicts[0].rule).toBe("clarify:invalid[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("a builtin override carries no justification and never enters this lane", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        {
          name: "choice-lib",
          detected: { registry: "MIT OR Apache-2.0", intensive: "MIT" },
          expression: "MIT OR Apache-2.0",
        },
      ],
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
  });
});

// ===========================================================================
// Entries imported from the clarifications file are cited in their OWN id
// space, indexed within that file. No combined-array position may reach a
// reader: a citation names the file to open and the table in it.
// ===========================================================================

describe("evaluate — the clarifications file's own citation space", () => {
  const importable = (name: string, expression: string): string =>
    [
      "[[clarify]]",
      `name = ${JSON.stringify(name)}`,
      'version = "1.0.0"',
      'detected = { registry = "Public Domain" }',
      'justification = "license-not-found"',
      `expression = ${JSON.stringify(expression)}`,
    ].join("\n");

  test("HEADLINE: an imported entry cites clarifications[j], never its combined position", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      importable("policy-only", "MIT"),
      importable("jsonify", "Unlicense"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarifications[0]");
    expect(verdicts[0].reason).toBe('clarified to "Unlicense": license-not-found');
  });

  test("the policy's own entry keeps clarify[i] with imported entries beside it", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      importable("jsonify", "Unlicense"),
      importable("imported-only", "MIT"),
    );

    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("the second imported entry is clarifications[1], with two policy entries ahead of it", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      [importable("policy-one", "MIT"), importable("policy-two", "MIT")].join("\n"),
      [importable("imported-one", "MIT"), importable("jsonify", "Unlicense")].join("\n"),
    );

    expect(verdicts[0].rule).toBe("clarifications[1]");
  });

  test("a stale imported entry names the entry to update", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "GPL-3.0-only", ["backend"])],
      "",
      importable("jsonify", "Unlicense"),
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("Update or remove clarifications[0].");
  });

  test("a stale policy entry names its own citation", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "GPL-3.0-only", ["backend"])],
      importable("jsonify", "Unlicense"),
      "",
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("Update or remove clarify[0].");
  });

  test("an imported entry the signal disproves fails on clarifications:invalid[j]", () => {
    const { verdicts } = runEngineWithImports(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "choice-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
        'justification = "dual-license-choice"',
        'expression = "MIT OR Apache-2.0"',
      ].join("\n"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("clarifications:invalid[0]");
  });

  test("unused accounting reports each file's own ids, policy file first", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngineWithImports(
      [pkgSpec("unrelated", "MIT", ["backend"])],
      importable("policy-only", "MIT"),
      importable("imported-only", "MIT"),
    );

    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([
      "clarify[0]",
      "clarifications[0]",
    ]);
  });

  test("a failing imported entry is never also reported as an unused entry", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngineWithImports(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "choice-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
        'justification = "dual-license-choice"',
        'expression = "MIT OR Apache-2.0"',
      ].join("\n"),
    );

    expect(verdicts[0].rule).toBe("clarifications:invalid[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("an imported entry with nothing left to correct is reported in the imported space", () => {
    const { model, policy } = runEngineWithImports(
      [scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "settled-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT", intensive = "MIT" }',
        'justification = "contradictory-claims-recorded"',
        'expression = "MIT"',
      ].join("\n"),
    );

    expect(unnecessaryClarifyEntries(model, policy).map((entry) => entry.rule)).toEqual([
      "clarifications[0]",
    ]);
  });

  test("an imported citation is not read as a [[compatible]] acceptance of an AGPL obligation", () => {
    const purl = "pkg:deb/debian/agpl-imported@1.0.0";
    const target = "docker:img/Dockerfile";
    const model = annotateFindings(
      makeModel([osPkgSpec(purl, "agpl-imported", "AGPL-3.0-only", [target])]),
      [],
    ).model;
    const base = {
      purl,
      occurrenceTarget: target,
      status: "ok" as const,
      reason: 'clarified to "AGPL-3.0-only": license-reviewed',
    };

    expect(acceptedContainerNotices(model, [{ ...base, rule: "clarifications[0]" }])).toEqual([]);
    expect(acceptedContainerNotices(model, [{ ...base, rule: "clarify[0]" }])).toEqual([]);
    expect(acceptedContainerNotices(model, [{ ...base, rule: "compatible[0]" }])).toHaveLength(1);
  });
});

describe("unnecessaryClarifyEntries — the entries a maintainer can drop", () => {
  const AGREED = [
    "[[clarify]]",
    'name = "settled-lib"',
    'version = "1.0.0"',
    'detected = { registry = "MIT", intensive = "MIT" }',
    'justification = "contradictory-claims-recorded"',
    'expression = "MIT"',
  ].join("\n");

  test("an entry whose sources now agree is reported, and fails nothing", () => {
    const { verdicts, model, policy } = runEngine(
      [scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"])],
      AGREED,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(unnecessaryClarifyEntries(model, policy)).toEqual([
      {
        rule: "clarify[0]",
        reason:
          '"contradictory-claims-recorded" has nothing left to correct: the declared claim and ' +
          "the in-depth scan now agree on the same licences.",
      },
    ]);
  });

  test("an entry still doing its job anywhere is not reported", () => {
    const { model, policy } = runEngine(
      [
        scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"]),
        scanPkgSpec("settled-lib", "MIT", "MIT AND BSD-3-Clause", ["frontend"], "2.0.0"),
      ],
      [
        "[[clarify]]",
        'pattern = "settled-*"',
        'version = ["1.0.0", "2.0.0"]',
        'detected = { registry = "MIT" }',
        'justification = "contradictory-claims-recorded"',
        'expression = "MIT AND BSD-3-Clause"',
      ].join("\n"),
    );

    expect(unnecessaryClarifyEntries(model, policy)).toEqual([]);
  });
});

// ===========================================================================
// Path-shaped policy fields are repository-relative, always. A drive specifier
// is a legal path segment, so a policy naming one used to read - and, through
// refresh-clarifications --write, rewrite - a file outside the repository the
// scan was pointed at.
// ===========================================================================

describe("path-shaped policy fields never leave the repository", () => {
  test("a drive-lettered cache dir rejects", () => {
    expect(expectPolicyError('[cache]\ndir = "C:/anywhere"\n').message).toContain(
      "must be repository-relative",
    );
  });

  test("a drive-relative cache dir rejects", () => {
    expect(expectPolicyError('[cache]\ndir = "C:anywhere"\n').message).toContain(
      "must be repository-relative",
    );
  });

  test("a drive-lettered docker ignore glob rejects", () => {
    expect(expectPolicyError('[docker]\nignore = ["C:/anywhere/**"]\n').message).toContain(
      "must be repository-relative",
    );
  });

  test("a drive-lettered where scope rejects", () => {
    expect(
      expectPolicyError(
        [
          "[[compatible]]",
          'match = "license"',
          'pattern = "MIT"',
          'rationale = "license-reviewed"',
          'where = ["C:/anywhere"]',
          "",
        ].join("\n"),
      ).message,
    ).toContain("must be repository-relative");
  });

  test("a docker: scope is not a drive specifier and still parses", () => {
    const policy = parsePolicy(
      [
        "[[compatible]]",
        'match = "license"',
        'pattern = "MIT"',
        'rationale = "license-reviewed"',
        'where = ["docker:img/Dockerfile", "docker:ghcr.io/acme/api:1.2.3"]',
        "",
      ].join("\n"),
    );

    expect(policy.compatible[0]?.where).toEqual([
      "docker:img/Dockerfile",
      "docker:ghcr.io/acme/api:1.2.3",
    ]);
  });

  test("a docker: ignore glob is not a drive specifier and still parses", () => {
    expect(parsePolicy('[docker]\nignore = ["docker/dev/**"]\n').docker?.ignore).toEqual([
      "docker/dev/**",
    ]);
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
