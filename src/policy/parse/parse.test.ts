import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { TomlError } from "smol-toml";
import parseSpdxId from "spdx-expression-parse";
import { BUILTIN_DENY_RULES } from "../engine/builtinDenylist";
import {
  expectPolicyError,
  SUPPRESSION_DESCRIPTION,
  MPL_COMMENT,
  SHARP_COMMENT,
  CLARIFY_COMMENT,
  VALID_POLICY,
  denyLicenseFixture,
  denyNameFixture,
  developmentFixture,
} from "../../../test/policyTestSupport";
import { parsePolicy } from "./parse";
import type { SpdxExpression } from "../../model/dependencies";

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
        expression: "Unlicense" as SpdxExpression,
        comment: CLARIFY_COMMENT,
      },
    ]);
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
    const text = readFileSync(
      join(import.meta.dir, "..", "..", "..", "policy.example.toml"),
      "utf8",
    );
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
    expect(error.message).toContain("pattern");
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

describe("policy.example.toml — the shipped [[deny]] block", () => {
  const exampleText = readFileSync(
    join(import.meta.dir, "..", "..", "..", "policy.example.toml"),
    "utf8",
  );
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
    const dataDir = join(import.meta.dir, "..", "..", "..", "node_modules", "spdx-license-ids");
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

    expect(error.message).toContain("network");
    expect(error.message).toContain("must be boolean");
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

    expect(error.message).toContain('must be "fail" or "warn"');
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
