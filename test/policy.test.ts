import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { TomlError } from "smol-toml";
import parseSpdxId from "spdx-expression-parse";

import {
  annotateFindings,
  type BuiltinOverrideInput,
} from "../src/normalize/normalize";
import { evaluate, unusedRuleIds } from "../src/policy/evaluate";
import { BUILTIN_DENY_RULES } from "../src/policy/builtinDenylist";
import { denyRuleFor } from "../src/policy/denylist";
import {
  COULD_BE_COPYLEFT_FAMILIES,
  WORKSPACE_ABSORBS,
} from "../src/policy/copyleftFamily";
import { BUILTIN_OVERRIDES } from "../src/policy/builtinOverrides";
import { parsePolicy, PolicyError, type Policy } from "../src/policy/schema";
import type {
  CanonicalDependencies,
  LicenseClaimKind,
  LicenseFinding,
  Verdict,
} from "../src/model/dependencies";

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
    'reason = "test reason"',
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
const MPL_REASON =
  "Weak copyleft; compatible under AGPL-3.0 and Apache License v2.0";
const SHARP_REASON =
  "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; LGPL obligations accepted.";
const CLARIFY_REASON =
  "Upstream declares Public Domain; mapped to Unlicense deliberately.";

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
  `reason = ${JSON.stringify(MPL_REASON)}`,
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "@img/sharp-win32-x64"',
  'version = "0.34.5"',
  `reason = ${JSON.stringify(SHARP_REASON)}`,
  "",
  "[[clarify]]",
  'package = { name = "jsonify", version = "0.0.1" }',
  'expression = "Unlicense"',
  `reason = ${JSON.stringify(CLARIFY_REASON)}`,
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
        reason: MPL_REASON,
      },
      {
        match: "package",
        name: "@img/sharp-win32-x64",
        version: "0.34.5",
        reason: SHARP_REASON,
      },
    ]);
    expect(policy.clarify).toEqual([
      {
        name: "jsonify",
        version: "0.0.1",
        expression: "Unlicense",
        reason: CLARIFY_REASON,
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
    const policy = parsePolicy(
      licenseRuleFixture("GPL-2.0-only WITH Classpath-exception-2.0"),
    );
    const rule = policy.compatible[0];
    if (rule === undefined || rule.match !== "license") {
      throw new Error("expected a compatible license rule");
    }
    expect(rule.allowlist).toEqual([
      "GPL-2.0-only WITH Classpath-exception-2.0",
    ]);
  });

  test("AND pattern is rejected at validation time (satisfies throws on AND allowlists)", () => {
    const error = expectPolicyError(licenseRuleFixture("MIT AND Apache-2.0"));
    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain("OR of license IDs");
  });
});

// ===========================================================================
// POL-07 Task 1: the optional `expects` precondition on [[clarify]] + the
// shipped tool-level BUILTIN_OVERRIDES set.
// ===========================================================================

/** A [[clarify]] entry carrying an `expects` precondition. */
const clarifyWithExpects = (expects: string): string =>
  [
    "[[clarify]]",
    'package = { name = "demo-pkg" }',
    `expects = ${JSON.stringify(expects)}`,
    'expression = "BSD-3-Clause"',
    'reason = "disambiguate the imprecise BSD label to BSD-3-Clause"',
  ].join("\n");

describe("parsePolicy — clarify `expects` precondition (POL-07)", () => {
  test("a [[clarify]] WITH expects parses and the ClarifyRule carries it", () => {
    const policy = parsePolicy(clarifyWithExpects("BSD"));
    expect(policy.clarify).toEqual([
      {
        name: "demo-pkg",
        expects: "BSD",
        expression: "BSD-3-Clause",
        reason: "disambiguate the imprecise BSD label to BSD-3-Clause",
      },
    ]);
  });

  test("a [[clarify]] WITHOUT expects still parses (optional-for-backward-compat)", () => {
    const policy = parsePolicy(
      [
        "[[clarify]]",
        'package = { name = "jsonify", version = "0.0.1" }',
        'expression = "Unlicense"',
        `reason = ${JSON.stringify(CLARIFY_REASON)}`,
      ].join("\n"),
    );
    expect(policy.clarify).toEqual([
      {
        name: "jsonify",
        version: "0.0.1",
        expression: "Unlicense",
        reason: CLARIFY_REASON,
      },
    ]);
    // No expects key materializes when absent.
    expect("expects" in (policy.clarify[0] ?? {})).toBe(false);
  });

  test("a malformed (non-string) expects is rejected naming clarify[i]", () => {
    const error = expectPolicyError(
      [
        "[[clarify]]",
        'package = { name = "demo-pkg" }',
        "expects = 42",
        'expression = "BSD-3-Clause"',
        'reason = "r"',
      ].join("\n"),
    );
    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("expects");
  });

  test("an empty-string expects is rejected (a precondition must carry a value)", () => {
    const error = expectPolicyError(
      [
        "[[clarify]]",
        'package = { name = "demo-pkg" }',
        'expects = "   "',
        'expression = "BSD-3-Clause"',
        'reason = "r"',
      ].join("\n"),
    );
    expect(error.message).toContain("clarify[0]");
    expect(error.message).toContain("expects");
  });
});

describe("BUILTIN_OVERRIDES — shipped tool-level set (POL-07)", () => {
  test("is a non-empty literal array; every entry has name, expects, expression, reason", () => {
    expect(BUILTIN_OVERRIDES.length).toBeGreaterThan(0);
    for (const o of BUILTIN_OVERRIDES) {
      expect(typeof o.name).toBe("string");
      expect(o.name.trim().length).toBeGreaterThan(0);
      expect(typeof o.expects).toBe("string");
      expect(o.expects.trim().length).toBeGreaterThan(0);
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
    const dataDir = join(
      import.meta.dir,
      "..",
      "node_modules",
      "spdx-license-ids",
    );
    const current = JSON.parse(
      readFileSync(join(dataDir, "index.json"), "utf8"),
    ) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const leafIds: string[] = [];
    const walk = (node: unknown): void => {
      if (typeof node !== "object" || node === null) return;
      const n = node as Record<string, unknown>;
      if (typeof n.license === "string") leafIds.push(n.license);
      walk(n.left);
      walk(n.right);
    };
    for (const o of BUILTIN_OVERRIDES) walk(parseSpdxId(o.expression));
    expect(leafIds.filter((id) => !known.has(id))).toEqual([]);
  });

  test("ships python-dateutil's dual license as a REAL default (BLOCKER-1)", () => {
    const entry = BUILTIN_OVERRIDES.find((o) => o.name === "python-dateutil");
    expect(entry).toBeDefined();
    expect(entry?.expects).toBe("Dual License");
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
      // expects the imprecise BSD value the 05-05 normalizer produces.
      expect(entry?.expects).toBe("BSD");
      expect(entry?.expression).toBe("BSD-3-Clause");
    }
  });

  test("does NOT ship copier or jinja2-ansible-filters (Phase-6 project judgment)", () => {
    expect(BUILTIN_OVERRIDES.some((o) => o.name === "copier")).toBe(false);
    expect(
      BUILTIN_OVERRIDES.some((o) => o.name === "jinja2-ansible-filters"),
    ).toBe(false);
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
      'reason = "ok"',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "Apache-2.0"',
      "",
      "[[clarify]]",
      'package = { name = "x" }',
      'expression = "not a license"',
      'reason = "r"',
    ].join("\n");
    const error = expectPolicyError(fixture);
    expect(error.problems).toHaveLength(3);
    expect(error.message).toContain('"compatibel"');
    expect(error.message).toContain("compatible[1]");
    expect(error.message).toContain('"reason"');
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
});

describe("parsePolicy — [unknown] handling knob (POL-04)", () => {
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
    const text = readFileSync(
      join(import.meta.dir, "..", "policy.example.toml"),
      "utf8",
    );
    const policy = parsePolicy(text);
    expect(
      policy.suppressedWorkspaces.some((w) => w.path === "apps/scratch"),
    ).toBe(true);
    expect(
      policy.compatible.some(
        (r) => r.match === "license" && r.pattern === "MPL-2.0",
      ),
    ).toBe(true);
    expect(policy.compatible.some((r) => r.match === "package")).toBe(true);
    expect(policy.clarify.length).toBeGreaterThanOrEqual(1);
    // The example must carry an EXPLICIT [unknown] table (the knob is part
    // of the starter contract, not just the default).
    expect(text).toContain("[unknown]");
    expect(policy.unknownHandling).toBe("warn");
    // POL-08: the example must carry an EXPLICIT [dev_dependencies] table too.
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

  test("empty-string reason does not count as documentation", () => {
    const fixture = [
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'reason = ""',
    ].join("\n");
    const error = expectPolicyError(fixture);
    expect(error.message).toContain("compatible[0]");
    expect(error.message).toContain('"reason"');
  });
});

// ===========================================================================
// 07-09 COMMIT 2: the optional [document] table — author-supplied title +
// preamble for the LICENSES document only. Both keys are OPTIONAL; when present
// each must be a non-empty string. Unknown keys under [document] reject.
// ===========================================================================
describe("parsePolicy — [document] title + preamble (07-09)", () => {
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
    const policy = parsePolicy(
      ["[document]", 'title = "Just A Title"'].join("\n"),
    );
    expect(policy.document).toEqual({ title: "Just A Title" });
  });

  test("preamble-only is valid (title absent)", () => {
    const policy = parsePolicy(
      ["[document]", 'preamble = "Just a preamble."'].join("\n"),
    );
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
    const error = expectPolicyError(
      ["[document]", 'preamble = "   "'].join("\n"),
    );
    expect(error.message).toContain("document");
    expect(error.message).toContain('"preamble"');
  });

  test("unknown key under [document] is rejected", () => {
    const error = expectPolicyError(
      ["[document]", 'title = "T"', 'footer = "nope"'].join("\n"),
    );
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
  /** Package-level taxonomy; defaults to "app" (COLL-04: "os" routes applyOsScope). */
  scope?: "app" | "os";
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
      licenseClaims: spec.claims.map((raw) => {
        const kind: LicenseClaimKind =
          raw.includes(" ") || raw.includes("(") ? "expression" : "spdx-id";
        return { raw, kind, source: "generator" as const };
      }),
      scope: spec.scope ?? "app",
    })),
  };
}

/** Shorthand for an OS-scope package (pkg:deb/pkg:apk in COLL-04 reality). */
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

/** parse policy → annotateFindings (clarify + optional builtins) → evaluate. */
function runEngine(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): {
  verdicts: Verdict[];
  usedClarifyIndices: ReadonlySet<number>;
  policy: Policy;
} {
  const policy = parsePolicy(policyText);
  const { model, usedClarifyIndices } = annotateFindings(
    makeModel(specs),
    policy.clarify,
    builtins,
  );
  return { verdicts: evaluate(model, policy), usedClarifyIndices, policy };
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
      'reason = "package-level acceptance"',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'reason = "license-level acceptance"',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])],
      policyText,
    );
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
    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual(
      [
        ["apps/scratch", "suppressed", "workspace.copyleft_suppressed[0]"],
        ["apps/scratch-helper", "fail", "default:copyleft"],
        ["apps/scratch/sub", "suppressed", "workspace.copyleft_suppressed[0]"],
      ],
    );
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
    expect(verdicts[0].reason).toContain(
      "same GNU family as the workspace license AGPL-3.0-only",
    );
  });

  test("AND expressions suppress when every copyleft leaf is in-family", () => {
    // The sharp-win32 shape: Apache-2.0 AND LGPL-3.0-or-later — the only
    // copyleft obligation (LGPL) is GNU-family under the AGPL workspace.
    const { verdicts } = runEngine(
      [
        pkgSpec("sharp-ish", "Apache-2.0 AND LGPL-3.0-or-later", [
          "apps/scratch",
        ]),
      ],
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
      [
        pkgSpec("mixed-pkg", "LGPL-3.0-or-later AND CC-BY-SA-4.0", [
          "apps/scratch",
        ]),
      ],
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

describe("WORKSPACE_ABSORBS — literal absorption relation (revision F)", () => {
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

describe("evaluate — absorb-all-copyleft suppression (revision F)", () => {
  test("an AGPL workspace now SUPPRESSES an MPL-2.0 finding (was: fell through to fail)", () => {
    // Before revision F this fell through to default:copyleft (MPL is a
    // different family from GNU). apps/scratch re-releases bundled MPL files
    // under AGPL, so it absorbs them.
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );
    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
    // The audit-trail reason names the absorption, not an in-family assertion.
    expect(verdicts[0].reason).toContain(
      "absorbed by the GNU workspace license",
    );
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
    expect(verdicts[0].reason).toContain(
      "same GNU family as the workspace license AGPL-3.0-only",
    );
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
    const { verdicts } = runEngine(
      [pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"])],
      policyText,
    );
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
    const { verdicts } = runEngine(
      [pkgSpec("dual-pkg", "(CC-BY-SA-4.0 OR MIT)", ["backend"])],
      "",
    );
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
// INV-04: imprecise findings + the could-be-copyleft literal token set (05-05).
// ===========================================================================

describe("COULD_BE_COPYLEFT_FAMILIES — literal token set (INV-04)", () => {
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
    expect([...COULD_BE_COPYLEFT_FAMILIES].sort()).toEqual([
      "AGPL",
      "EUPL",
      "GPL",
      "LGPL",
    ]);
  });
});

describe("evaluate — imprecise findings route to a safe lane (INV-04)", () => {
  test("a permissive imprecise family (BSD) gets a non-gating default:imprecise status", () => {
    const { verdicts } = runEngine(
      [pkgSpec("jinja2-ish", "BSD License", ["frontend"])],
      "",
    );
    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).toBe("default:imprecise");
    // The signal must be visible — not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("an imprecise BSD family is NOT copyleft-flagged and NOT a hard fail in a non-suppressed workspace", () => {
    const { verdicts } = runEngine(
      [pkgSpec("bsd-pkg", "BSD", ["backend"])],
      "",
    );
    expect(verdicts[0].rule).not.toBe("default:copyleft");
    expect(verdicts[0].status).not.toBe("fail");
  });

  test("a could-be-copyleft imprecise family (GPL) is flagged for review, never silently passed", () => {
    const { verdicts } = runEngine(
      [pkgSpec("gpl-ish", "GPL", ["backend"])],
      "",
    );
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // Not the permissive lane and not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:imprecise");
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare EUPL routes to default:imprecise-copyleft, never a silent default:ok (W1)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("eupl-pkg", "EUPL", ["backend"])],
      "",
    );
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // The masking this kills: EUPL → UPL-1.0 (permissive) → default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare imprecise AGPL and LGPL are likewise flagged for review (the WARNING-2 regression)", () => {
    for (const token of ["AGPL", "LGPL"]) {
      const { verdicts } = runEngine(
        [pkgSpec(`${token}-ish`, token, ["backend"])],
        "",
      );
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
    expect(() => evaluate(model, parsePolicy(""))).not.toThrow();
    const verdicts = evaluate(model, parsePolicy(""));
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

describe("evaluate — unknown handling knob (POL-04)", () => {
  test('zero-claim package warns under handling "warn" (the absent-table default)', () => {
    const { verdicts } = runEngine(
      [pkgSpec("no-claims", null, ["backend"])],
      "",
    );
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
    expect(verdicts.map((v) => v.occurrenceTarget)).toEqual([
      "apps/scratch",
      "backend",
    ]);
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
      'package = { name = "weird-pkg", version = "1.0.0" }',
      'expression = "MIT"',
      'reason = "upstream metadata is garbage; MIT confirmed in the repository"',
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

describe("evaluate — staleness-guarded overrides (POL-07)", () => {
  test("a tool-level override that decides a verdict cites override:builtin[i], not default:ok", () => {
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("ipython", "BSD", ["backend"])],
      "",
      builtins,
    );
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
    expect(verdicts[0].rule).not.toBe("default:ok");
    expect(verdicts[0].reason).toContain("BSD-3-Clause");
  });

  test("HEADLINE: a stale BSD→BSD-3-Clause override on a now-GPL-3.0 dep FAILS naming pkg/expected/observed", () => {
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", expects: "BSD", expression: "BSD-3-Clause" },
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
      'package = { name = "relicensed" }',
      'expects = "BSD"',
      'expression = "BSD-3-Clause"',
      'reason = "was BSD-3-Clause upstream"',
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
      'package = { name = "ipython" }',
      'expects = "BSD"',
      'expression = "MIT"',
      'reason = "project says MIT"',
    ].join("\n");
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("ipython", "BSD", ["backend"])],
      policyText,
      builtins,
    );
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].reason).toContain("project says MIT");
  });

  test("an imprecise finding with NO matching override stays imprecise+surfaced", () => {
    const { verdicts } = runEngine(
      [pkgSpec("orphan-bsd", "BSD", ["backend"])],
      "",
      [],
    );
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise");
  });

  test("REDUNDANT override (metadata caught up to a precise satisfying license) does NOT fail — observed finding stands ok (gap fix)", () => {
    // The live false-positive: PyPI now reports ipython precisely as
    // "BSD-3-Clause" (no bare "BSD"). expects "BSD" is absent from the signal,
    // but the observed precise license already satisfies the asserted
    // BSD-3-Clause — nothing is masked, so the gate must NOT fire override:stale.
    const builtins: BuiltinOverrideInput[] = [
      { name: "ipython", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("ipython", "BSD-3-Clause", ["backend"])],
      "",
      builtins,
    );
    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toContain("override:stale");
  });

  test("a genuine relicense to a NON-satisfying license still FAILS override:stale (gap fix is fail-safe)", () => {
    // expects "BSD" absent AND the observed precise license (MIT) does not
    // satisfy the asserted BSD-3-Clause → genuine drift → must fail closed.
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "MIT", ["backend"])],
      "",
      builtins,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
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
      'reason = "used by the MPL package below"',
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "never-matches"',
      'reason = "no package by this name exists"',
      "",
      "[[clarify]]",
      'package = { name = "never-clarified" }',
      'expression = "MIT"',
      'reason = "no package by this name exists"',
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

describe("evaluate — purity and determinism", () => {
  test("identical inputs evaluate to deeply equal arrays; occurrence input order is irrelevant", () => {
    const forward = pkgSpec("agpl-pkg", "AGPL-3.0-only", [
      "apps/scratch",
      "backend",
    ]);
    const reversed = pkgSpec("agpl-pkg", "AGPL-3.0-only", [
      "backend",
      "apps/scratch",
    ]);
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
// expressions, and occurrence shapes — not inventions — so future relocks can
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
  // roadmap success criterion 3: fail "naming the non-suppressed workspace".
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
  // This is the REAL live-data leakage shape (POL-03).
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
      'reason = "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; LGPL obligations accepted."',
    ].join("\n");
    const accepted = runEngine([spec], withRule).verdicts;
    expect(accepted.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual(
      [
        ["apps/scratch", "ok", "compatible[0]"],
        ["frontend", "ok", "compatible[0]"],
      ],
    );
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
  // unknown; the [unknown].handling knob governs it (POL-04). POL-08 NOTE: this
  // occurrence is dev-only, so under [unknown] handling="fail" the would-be FAIL
  // is dev-downgraded to warn by default (dev_dependencies=warn). A PROD
  // occurrence of the same would still fail — covered by the POL-08 suite above.
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

    const failPolicy = ACCEPTANCE_POLICY.replace(
      'handling = "warn"',
      'handling = "fail"',
    );
    // POL-08: a dev-only unknown-fail downgrades to warn by default.
    const failed = runEngine([spec], failPolicy).verdicts;
    expect(failed[0].status).toBe("warn");
    expect(failed[0].rule).toBe("default:unknown");
    expect(failed[0].reason).toContain("dev-only occurrence");

    // Strict projects can restore the pre-POL-08 fail with dev_dependencies=fail.
    const strictPolicy = `${failPolicy}\n\n[dev_dependencies]\nhandling = "fail"`;
    const strict = runEngine([spec], strictPolicy).verdicts;
    expect(strict[0].status).toBe("fail");
    expect(strict[0].rule).toBe("default:unknown");
  });
});

// ===========================================================================
// POL-08: dev/prod gate downgrade — the `dev_dependencies` knob + the
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
      expect(
        parsePolicy(`[dev_dependencies]\nhandling = "${value}"`)
          .devDependencies,
      ).toBe(value);
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
    expect(
      error.problems.some((p) =>
        p.includes("dev_dependencies: must be a table"),
      ),
    ).toBe(true);
  });

  test("a missing handling key rejects", () => {
    const error = expectPolicyError("[dev_dependencies]\nother = 1");
    expect(
      error.problems.some((p) =>
        p.includes('dev_dependencies: missing required key "handling"'),
      ),
    ).toBe(true);
  });

  test("an unknown key inside [dev_dependencies] rejects", () => {
    const error = expectPolicyError(
      '[dev_dependencies]\nhandling = "warn"\nbogus = 1',
    );
    expect(
      error.problems.some((p) =>
        p.includes('dev_dependencies: unknown key "bogus"'),
      ),
    ).toBe(true);
  });

  test("dev_dependencies is an accepted top-level key (no unknown-key error)", () => {
    expect(() =>
      parsePolicy('[dev_dependencies]\nhandling = "warn"'),
    ).not.toThrow();
  });

  test("a genuinely unknown top-level key still rejects", () => {
    const error = expectPolicyError("[bogus_table]\nx = 1");
    expect(error.problems).toContain('unknown top-level key "bogus_table"');
  });
});

describe("evaluate — POL-08 dev-scope downgrade (default warn)", () => {
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
    const { verdicts } = runEngine(
      [DEV_PROD_UNKNOWN],
      '[unknown]\nhandling = "fail"',
    );
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

describe('evaluate — POL-08 dev_dependencies = "fail" (pre-POL-08 behavior)', () => {
  test("BOTH copyleft occurrences fail (no downgrade)", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_COPYLEFT],
      '[dev_dependencies]\nhandling = "fail"',
    );
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

describe('evaluate — POL-08 dev_dependencies = "ignore"', () => {
  test("dev copyleft occurrence is ok; prod copyleft occurrence still FAILS", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_COPYLEFT],
      '[dev_dependencies]\nhandling = "ignore"',
    );
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

describe("evaluate — POL-08 precedence is preserved (downgrade is last)", () => {
  test("a suppressed dev copyleft occurrence stays suppressed (not warn)", () => {
    // apps/scratch is family-suppressed AND the occurrence is dev: suppression
    // wins, the dev-scope downgrade never touches it.
    const { verdicts } = runEngine(
      [
        pkgSpec("agpl-pkg", "AGPL-3.0-only", [
          { target: "apps/scratch", dev: true },
        ]),
      ],
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
      { name: "relicensed", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { verdicts } = runEngine(
      [
        pkgSpec("relicensed", "GPL-3.0-only", [
          { target: "apps/a", dev: true },
        ]),
      ],
      "",
      builtins,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });
});

// ===========================================================================
// POL-09: terminal deny-list (highest precedence). denyRuleFor is the pure
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
      ["[[deny]]", 'match = "name"', 'pattern = "   "', 'reason = "r"'].join(
        "\n",
      ),
    );
    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('"pattern"');
  });

  test("an unknown key inside a deny entry is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      [
        "[[deny]]",
        'match = "license"',
        'pattern = "BUSL-1.1"',
        'reason = "r"',
        "bogus = 1",
      ].join("\n"),
    );
    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('unknown key "bogus"');
  });

  test("an invalid match value is rejected naming deny[i]", () => {
    const error = expectPolicyError(
      [
        "[[deny]]",
        'match = "spdx"',
        'pattern = "BUSL-1.1"',
        'reason = "r"',
      ].join("\n"),
    );
    expect(error.message).toContain("deny[0]");
    expect(error.message).toContain('"match"');
  });

  test("a non-array deny is rejected", () => {
    const error = expectPolicyError('deny = "BUSL-1.1"');
    expect(
      error.problems.some((p) =>
        p.includes("deny: must be an array of tables"),
      ),
    ).toBe(true);
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
    expect(denyRuleFor(policy, "GPL-3.0 OR BUSL-1.1", "x")?.ruleId).toBe(
      "denied[0]",
    );
  });

  test("name-mode matches the target package name (verbatim, non-SPDX rider)", () => {
    const policy = parsePolicy(denyNameFixture("commons-clause-pkg"));
    // name-mode matches on the PACKAGE NAME and does not require a parseable
    // license expression (the Commons-Clause rider rides a non-SPDX value).
    expect(denyRuleFor(policy, null, "commons-clause-pkg")?.ruleId).toBe(
      "denied[0]",
    );
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
      'reason = "would-be accepted but deny wins"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])],
      policyText,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).toContain("BUSL-1.1");
  });

  test("deny BEATS suppression: a denied in-family copyleft under a suppressed path still fails", () => {
    // AGPL-3.0-only under apps/scratch would normally be family-suppressed; the
    // deny terminal sits above suppression, so it still fails.
    const policyText = [
      denyLicenseFixture("AGPL-3.0-only"),
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
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
    // The package carries a stale builtin override (expects BSD, observes
    // BUSL-1.1) AND the observed license is denied → deny wins over stale.
    const builtins: BuiltinOverrideInput[] = [
      { name: "relicensed", expects: "BSD", expression: "BSD-3-Clause" },
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
    // Observed BUSL-1.1; a blind [[clarify]] (no expects) rewrites it to MIT.
    // Pre-fix the override ran before evaluate, so deny saw MIT and passed it
    // back in. Deny must consult the PRE-OVERRIDE observed BUSL-1.1 and fail.
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[clarify]]",
      'package = { name = "evil" }',
      'expression = "MIT"',
      'reason = "claims MIT but observed signal is BUSL-1.1"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("evil", "BUSL-1.1", ["backend"])],
      policyText,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a SUCCESSFULLY-APPLIED matching-expects builtin over a denied observed license still FAILS", () => {
    // expects BUSL-1.1 MATCHES observed BUSL-1.1 → the builtin applies and
    // rewrites the finding to Apache-2.0. Deny must still fire on the observed
    // BUSL-1.1 (a denied OBSERVED license can never be licensed back in).
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed-evil",
        expects: "BUSL-1.1",
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
      'package = { name = "legit" }',
      'expression = "Apache-2.0"',
      'reason = "disambiguate the imprecise Apache family"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("legit", "Apache", ["backend"])],
      policyText,
    );
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a denied observed license is denied even when the override REWRITES it (project clarify)", () => {
    // Mirror of the builtin case for a project clarify with a matching expects.
    const policyText = [
      denyLicenseFixture("SSPL-1.0"),
      "",
      "[[clarify]]",
      'package = { name = "sspl-evil" }',
      'expects = "SSPL-1.0"',
      'expression = "MIT"',
      'reason = "rewrites a denied observed license"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("sspl-evil", "SSPL-1.0", ["backend"])],
      policyText,
    );
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
        [
          multiClaimSpec(
            "elastic-gpl",
            ["Elastic-2.0", "GPL"],
            ["backend"],
            scope,
          ),
        ],
        denyElastic,
      );
      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });

    test(`[BUSL-1.1, public-domain] in ${scope} scope → fail denied[0] (unknown token co-present)`, () => {
      const { verdicts } = runEngine(
        [
          multiClaimSpec(
            "busl-pd",
            ["BUSL-1.1", "public-domain"],
            ["backend"],
            scope,
          ),
        ],
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
    const { verdicts } = runEngine(
      [pkgSpec("busl-only", "BUSL-1.1", ["backend"])],
      denyBusl,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("policy.example.toml — the shipped [[deny]] block (POL-09)", () => {
  const exampleText = readFileSync(
    join(import.meta.dir, "..", "policy.example.toml"),
    "utf8",
  );
  const examplePolicy = parsePolicy(exampleText);

  test("ships the source-available set BUSL-1.1, SSPL-1.0, Elastic-2.0 as built-in defaults", () => {
    const licensePatterns = BUILTIN_DENY_RULES.filter(
      (r) => r.match === "license",
    ).map((r) => r.pattern);
    for (const id of ["BUSL-1.1", "SSPL-1.0", "Elastic-2.0"]) {
      expect(licensePatterns.some((p) => p.includes(id))).toBe(true);
    }
  });

  test("ships an RSAL deny entry (name-mode, no SPDX id) and a Commons-Clause rider", () => {
    // RSAL has no registered SPDX id, so it is name-mode and its rationale
    // lives in the reason (audit trail), not the SPDX-less pattern.
    expect(
      examplePolicy.deny.some(
        (r) => r.match === "name" && r.reason.toLowerCase().includes("rsal"),
      ),
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
    const dataDir = join(
      import.meta.dir,
      "..",
      "node_modules",
      "spdx-license-ids",
    );
    const current = JSON.parse(
      readFileSync(join(dataDir, "index.json"), "utf8"),
    ) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const leafIds: string[] = [];
    const walk = (node: unknown): void => {
      if (typeof node !== "object" || node === null) return;
      const n = node as Record<string, unknown>;
      if (typeof n.license === "string") leafIds.push(n.license);
      walk(n.left);
      walk(n.right);
    };
    for (const rule of examplePolicy.deny) {
      if (rule.match === "license") walk(parseSpdxId(rule.pattern));
    }
    expect(leafIds.filter((id) => !known.has(id))).toEqual([]);
  });
});

// ===========================================================================
// COLL-04: the `[os_dependencies]` knob + the package-level os-scope downgrade
// at the would-be default-FAIL terminals. Mirrors the POL-08 dev_dependencies
// suite EXACTLY, but routes on entry.scope === "os" (package-level), not the
// occurrence-level dev marker. Deny stays terminal-0 above the os downgrade.
// ===========================================================================

/** An OS-scope copyleft package (a pkg:deb glibc-style LGPL row). */
const OS_COPYLEFT = osPkgSpec(
  "pkg:deb/debian/libc6@2.36-9",
  "libc6",
  "LGPL-2.1-or-later",
  ["docker:os-packages"],
);

/** An OS-scope UNKNOWN-license package (zero claims). */
const OS_UNKNOWN = osPkgSpec("pkg:apk/alpine/mystery@1.0.0", "mystery", null, [
  "docker:os-packages",
]);

describe("os_dependencies knob — parsing (mirrors dev_dependencies EXACTLY)", () => {
  test('absent [os_dependencies] table defaults to "warn"', () => {
    expect(parsePolicy("").osDependencies).toBe("warn");
  });

  test('handling = "warn" | "fail" | "ignore" parse to themselves', () => {
    for (const value of ["warn", "fail", "ignore"] as const) {
      expect(
        parsePolicy(`[os_dependencies]\nhandling = "${value}"`).osDependencies,
      ).toBe(value);
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
    expect(
      error.problems.some((p) =>
        p.includes("os_dependencies: must be a table"),
      ),
    ).toBe(true);
  });

  test("a missing handling key rejects", () => {
    const error = expectPolicyError("[os_dependencies]\nother = 1");
    expect(
      error.problems.some((p) =>
        p.includes('os_dependencies: missing required key "handling"'),
      ),
    ).toBe(true);
  });

  test("an unknown key inside [os_dependencies] rejects", () => {
    const error = expectPolicyError(
      '[os_dependencies]\nhandling = "warn"\nbogus = 1',
    );
    expect(
      error.problems.some((p) =>
        p.includes('os_dependencies: unknown key "bogus"'),
      ),
    ).toBe(true);
  });

  test("os_dependencies is an accepted top-level key (no unknown-key error)", () => {
    expect(() =>
      parsePolicy('[os_dependencies]\nhandling = "warn"'),
    ).not.toThrow();
  });
});

describe("evaluate — COLL-04 os-scope downgrade (default warn)", () => {
  test("HEADLINE: an os-scope copyleft WARNS under default os_dependencies=warn", () => {
    const { verdicts } = runEngine([OS_COPYLEFT], "");
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test('os_dependencies="fail" gates an os-scope copyleft exactly like an app one', () => {
    const { verdicts } = runEngine(
      [OS_COPYLEFT],
      '[os_dependencies]\nhandling = "fail"',
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test('os_dependencies="ignore" makes an os-scope copyleft ok (rule id preserved)', () => {
    const { verdicts } = runEngine(
      [OS_COPYLEFT],
      '[os_dependencies]\nhandling = "ignore"',
    );
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=ignore");
  });

  test("the os-scope downgrade applies at the unknown-fail terminal too", () => {
    const { verdicts } = runEngine(
      [OS_UNKNOWN],
      '[unknown]\nhandling = "fail"',
    );
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

describe("evaluate — COLL-04 deny STAYS TERMINAL over the os knob", () => {
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
            "docker:os-packages",
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
      [
        osPkgSpec("pkg:deb/debian/rider-os@1.0.0", "rider-os", null, [
          "docker:os-packages",
        ]),
      ],
      denyNameFixture("rider-os"),
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — COLL-04 W1: os-scope and dev-scope downgraders compose without interaction", () => {
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
          { target: "docker:os-packages", dev: true },
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
// 07-06: the os-scope PARTIAL finding evaluates on its KNOWN-member expression.
// A known copyleft member → applyOsScope → warn (non-gating); a known denied
// member STAYS terminal (deny is checked before applyOsScope). The
// unrecognizedTokens themselves never gate (os non-gating). No change to
// app-scope verdicts (the all-or-nothing → unknown invariant holds there).
// ===========================================================================

/** A multi-claim os-scope spec (the partial-finding shape). */
const osMultiSpec = (
  name: string,
  claims: ReadonlyArray<string>,
  occurrences: ReadonlyArray<OccurrenceSpec> = ["docker:os-packages"],
): PackageSpec => ({
  purl: `pkg:deb/debian/${name}@1.0.0`,
  name,
  version: "1.0.0",
  claims,
  occurrences,
  scope: "os",
});

describe("evaluate — 07-06 os-scope partial finding", () => {
  test("os [GPL-2.0-only, BSD-3-Clause, public-domain] → known copyleft WARNS (os non-gating)", () => {
    const { verdicts } = runEngine(
      [
        osMultiSpec("os-partial", [
          "GPL-2.0-only",
          "BSD-3-Clause",
          "public-domain",
        ]),
      ],
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

// ---------------------------------------------------------------------------
// [docker] ignore — Dockerfile-discovery exclusion globs (07-23).
// ---------------------------------------------------------------------------

describe("[docker] ignore parsing", () => {
  test("absent [docker] table → docker is undefined", () => {
    const policy = parsePolicy("");
    expect(policy.docker).toBeUndefined();
  });

  test("valid ignore globs parse into a readonly array", () => {
    const policy = parsePolicy(
      '[docker]\nignore = ["docker/dev/**", "legacy/Dockerfile"]\n',
    );
    expect(policy.docker).toEqual({
      ignore: ["docker/dev/**", "legacy/Dockerfile"],
    });
  });

  test("[docker] with no ignore key → ignore defaults to empty array", () => {
    const policy = parsePolicy("[docker]\n");
    expect(policy.docker).toEqual({ ignore: [] });
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

describe("evaluate — [[allow_source_available]] exemption (ADR-0015 opt-out)", () => {
  const exemptBusl = [
    "[[allow_source_available]]",
    'license = "BUSL-1.1"',
    'reason = "internal-only build tool, never redistributed; counsel-approved"',
  ].join("\n");

  test("an exempted source-available license WARNS (allowed), not fail", () => {
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])],
      exemptBusl,
    );
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("allow_source_available[0]");
  });

  test("a non-exempted source-available license still FAILS by default", () => {
    const { verdicts } = runEngine(
      [pkgSpec("sspl-pkg", "SSPL-1.0", ["backend"])],
      exemptBusl,
    );
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
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])],
      policyText,
    );
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("policy — [[allow_source_available]] validation", () => {
  test("rejects a licence that is not a built-in source-available default", () => {
    const error = expectPolicyError(
      ["[[allow_source_available]]", 'license = "MIT"', 'reason = "x"'].join(
        "\n",
      ),
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
    expect(
      expectPolicyError('[cache]\ndir = "../outside"\n').message,
    ).toContain("cache.dir");
  });

  test("a leading slash is rejected", () => {
    expect(expectPolicyError('[cache]\ndir = "/abs"\n').message).toContain(
      "cache.dir",
    );
  });

  test("an unknown key is rejected", () => {
    expect(expectPolicyError('[cache]\nfolder = "x"\n').message).toContain(
      'unknown key "folder"',
    );
  });

  test("an empty dir is rejected", () => {
    expect(expectPolicyError('[cache]\ndir = ""\n').message).toContain("cache");
  });
});
