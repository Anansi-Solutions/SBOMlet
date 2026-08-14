/**
 * Unit-level engine locks for the target-compatibility lane: precedence (deny/stale/conflict/
 * compatible decide above the lane), overrideCitation preserved on the compatible outcome, the
 * ref-carrying-elected-branch fallthrough, imprecise/null findings keeping their existing lanes, the
 * residual-fail dev-downgrade composition, and determinism. Driven directly against evaluate() with
 * hand-built models (policy.test.ts's makeModel/runEngine idiom, kept local and minimal here).
 */
import { describe, expect, test } from "bun:test";

import { annotateFindings } from "../src/normalize/normalize";
import { evaluate } from "../src/policy/evaluate";
import { parsePolicy, type Policy } from "../src/policy/schema";
import type { CanonicalDependencies, Verdict } from "../src/model/dependencies";

interface OccurrenceSpec {
  target: string;
  dev?: boolean;
}

interface PackageSpec {
  purl: string;
  name: string;
  version?: string;
  /** Raw license claim strings; [] = the zero-claim (unknown) population. */
  claims: ReadonlyArray<string>;
  occurrences: ReadonlyArray<OccurrenceSpec>;
  scope?: "app" | "os";
  /** A free-text imprecise family label, set on the claim's `kind: "name"` shape. */
  impreciseLabel?: string;
}

function makeModel(specs: ReadonlyArray<PackageSpec>): CanonicalDependencies {
  return {
    packages: specs.map((spec) => ({
      purl: spec.purl,
      name: spec.name,
      version: spec.version ?? "1.0.0",
      occurrences: spec.occurrences.map((o) => ({
        target: o.target,
        isDevDependency: o.dev ?? false,
      })),
      licenseClaims:
        spec.impreciseLabel !== undefined
          ? [{ raw: spec.impreciseLabel, kind: "name" as const, source: "generator" as const }]
          : spec.claims.map((raw) => ({
              raw,
              kind: (raw.includes(" ") ? "expression" : "spdx-id") as "expression" | "spdx-id",
              source: "generator" as const,
            })),
      scope: spec.scope ?? "app",
    })),
  };
}

/** parse policy -> annotateFindings (clarify only) -> evaluate. */
function runEngine(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
): { verdicts: Verdict[]; policy: Policy; model: CanonicalDependencies } {
  const policy = parsePolicy(policyText);
  const { model } = annotateFindings(makeModel(specs), policy.clarify, []);

  return { verdicts: evaluate(model, policy), policy, model };
}

function findVerdict(
  verdicts: ReadonlyArray<Verdict>,
  purl: string,
  target: string,
): Verdict | undefined {
  return verdicts.find((v) => v.purl === purl && v.occurrenceTarget === target);
}

const TARGET = "apps/api";
const MIT_TARGET_EXTERNAL = [
  "[target]",
  'license = "MIT"',
  "network = false",
  'distribution = "external"',
  "",
].join("\n");
const GPL2_TARGET_EXTERNAL = [
  "[target]",
  'license = "GPL-2.0-only"',
  "network = false",
  'distribution = "external"',
  "",
].join("\n");

describe("target lane — precedence (deny/stale/conflict/compatible decide above the lane)", () => {
  test("a denied license under a compatible target still fails denied[i]", () => {
    const purl = "pkg:npm/denied-under-target@1.0.0";
    const policy = [
      MIT_TARGET_EXTERNAL,
      "[[deny]]",
      'match = "license"',
      'pattern = "MIT"',
      'reason = "denied for this test"',
      "",
    ].join("\n");
    const { verdicts } = runEngine(
      [{ purl, name: "denied-under-target", claims: ["MIT"], occurrences: [{ target: TARGET }] }],
      policy,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.status).toBe("fail");
    expect(verdict.rule).toBe("denied[0]");
  });

  test("a [[compatible]] rule still cites compatible[i] over an incompatible target verdict", () => {
    const purl = "pkg:npm/compatible-over-target@1.0.0";
    const policy = [
      GPL2_TARGET_EXTERNAL,
      "[[compatible]]",
      'match = "license"',
      'pattern = "Apache-2.0"',
      'reason = "accepted regardless of the target"',
      "",
    ].join("\n");
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "compatible-over-target",
          claims: ["Apache-2.0"],
          occurrences: [{ target: TARGET }],
        },
      ],
      policy,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.status).toBe("ok");
    expect(verdict.rule).toBe("compatible[0]");
  });
});

describe("target lane — overrideCitation preserved on the compatible outcome", () => {
  test("a clarified package landing target:ok cites clarify[i], not a bare target:ok", () => {
    const purl = "pkg:npm/clarified-target-ok@1.0.0";
    const policy = [
      MIT_TARGET_EXTERNAL,
      "[[clarify]]",
      'package = { name = "clarified-target-ok" }',
      'expression = "MIT"',
      'reason = "misdetected upstream; corrected to MIT"',
      "",
    ].join("\n");
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "clarified-target-ok",
          claims: ["totally-not-a-license"],
          occurrences: [{ target: TARGET }],
        },
      ],
      policy,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.status).toBe("ok");
    expect(verdict.rule).toBe("clarify[0]");
  });
});

describe("target lane — a ref-carrying elected branch routes to default:unknown", () => {
  test("LicenseRef AND MIT under an active target still routes to default:unknown, never target:ok", () => {
    const purl = "pkg:npm/ref-carrying@1.0.0";
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "ref-carrying",
          claims: ["LicenseRef-custom-eula AND MIT"],
          occurrences: [{ target: TARGET }],
        },
      ],
      MIT_TARGET_EXTERNAL,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.rule).toBe("default:unknown");
    expect(verdict.status).toBe("warn");
  });
});

describe("target lane — imprecise and null findings keep their existing lanes", () => {
  test("an imprecise finding under an active target still routes through impreciseVerdict", () => {
    const purl = "pkg:npm/imprecise-under-target@1.0.0";
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "imprecise-under-target",
          claims: [],
          impreciseLabel: "BSD",
          occurrences: [{ target: TARGET }],
        },
      ],
      MIT_TARGET_EXTERNAL,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.rule).toBe("default:imprecise");
    expect(verdict.status).toBe("warn");
  });

  test("a null-expression (genuine unknown) finding under an active target still routes through unknownVerdict", () => {
    const purl = "pkg:npm/null-under-target@1.0.0";
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "null-under-target",
          claims: [],
          occurrences: [{ target: TARGET }],
        },
      ],
      MIT_TARGET_EXTERNAL,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.rule).toBe("default:unknown");
    expect(verdict.status).toBe("warn");
  });
});

describe("target lane — residual fail composes with applyDevScope, never applyOsScope", () => {
  test('unknown_pair = "fail" on a dev occurrence downgrades to warn via applyDevScope', () => {
    const purl = "pkg:npm/residual-dev-downgrade@1.0.0";
    const policy = [
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "external"',
      'unknown_pair = "fail"',
      "",
    ].join("\n");
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "residual-dev-downgrade",
          claims: ["QPL-1.0"],
          occurrences: [{ target: TARGET, dev: true }],
        },
      ],
      policy,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.status).toBe("warn");
    expect(verdict.rule).toBe("target:unknown-pair");
    expect(verdict.reason).toContain("downgraded to warn: dev-only occurrence");
    expect(verdict.reason).not.toContain("os-scope");
  });

  test('unknown_pair = "fail" on a production occurrence stays fail (no downgrade)', () => {
    const purl = "pkg:npm/residual-prod-stays-fail@1.0.0";
    const policy = [
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "external"',
      'unknown_pair = "fail"',
      "",
    ].join("\n");
    const { verdicts } = runEngine(
      [
        {
          purl,
          name: "residual-prod-stays-fail",
          claims: ["QPL-1.0"],
          occurrences: [{ target: TARGET }],
        },
      ],
      policy,
    );
    const verdict = findVerdict(verdicts, purl, TARGET)!;

    expect(verdict.status).toBe("fail");
    expect(verdict.rule).toBe("target:unknown-pair");
  });
});

describe("target lane — determinism", () => {
  test("evaluate twice over the same model + policy yields an identical Verdict[]", () => {
    const specs: PackageSpec[] = [
      { purl: "pkg:npm/a@1.0.0", name: "a", claims: ["MIT"], occurrences: [{ target: TARGET }] },
      {
        purl: "pkg:npm/b@1.0.0",
        name: "b",
        claims: ["GPL-3.0-only"],
        occurrences: [{ target: TARGET }],
      },
      {
        purl: "pkg:npm/c@1.0.0",
        name: "c",
        claims: ["LGPL-2.1-only"],
        occurrences: [{ target: TARGET, dev: true }],
      },
    ];
    const policy = parsePolicy(MIT_TARGET_EXTERNAL);
    const { model } = annotateFindings(makeModel(specs), policy.clarify, []);

    const first = evaluate(model, policy);
    const second = evaluate(model, policy);

    expect(second).toEqual(first);
  });
});
