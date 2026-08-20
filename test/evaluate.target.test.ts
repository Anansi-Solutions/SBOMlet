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
import { parsePolicy, PolicyError, type Policy } from "../src/policy/schema";
import { renderMarkdown } from "../src/render/markdown";
import type { CanonicalDependencies, Verdict } from "../src/model/dependencies";

/** No scanned target in these scenarios is collected by a lane that derives a dependency graph. */
const WITHOUT_DEPENDENCY_GRAPHS: ReadonlySet<string> = new Set();

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

  return { verdicts: evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS), policy, model };
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
      'rationale = "license-reviewed"',
      'where = ["/"]',
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
      'name = "clarified-target-ok"',
      'detected = { registry = "totally-not-a-license" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "misdetected upstream; corrected to MIT"',
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

    const first = evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS);
    const second = evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS);

    expect(second).toEqual(first);
  });
});

describe("target lane — election flip locks (both directions)", () => {
  test("Apache-2.0 OR GPL-2.0-only: no target elects Apache-2.0 (today's elect()); a GPL-2.0-only target's verdict cites the GPL branch instead; the License column stays byte-identical between the two runs", () => {
    const purl = "pkg:npm/election-flip@1.0.0";
    const specs: PackageSpec[] = [
      {
        purl,
        name: "election-flip",
        claims: ["Apache-2.0 OR GPL-2.0-only"],
        occurrences: [{ target: TARGET }],
      },
    ];

    const noTargetPolicy = parsePolicy('[unknown]\nhandling = "warn"\n');
    const { model: noTargetModel } = annotateFindings(makeModel(specs), noTargetPolicy.clarify, []);
    const noTargetVerdicts = evaluate(noTargetModel, noTargetPolicy, WITHOUT_DEPENDENCY_GRAPHS);
    const noTargetVerdict = findVerdict(noTargetVerdicts, purl, TARGET)!;

    // Today's non-target-aware elect() prefers the non-copyleft branch.
    expect(noTargetModel.packages[0]!.finding!.elected).toBe("Apache-2.0");
    expect(noTargetVerdict.rule).toBe("default:ok");
    expect(noTargetVerdict.reason).toContain("Apache-2.0");

    const targetPolicy = parsePolicy(GPL2_TARGET_EXTERNAL);
    const { model: targetModel } = annotateFindings(makeModel(specs), targetPolicy.clarify, []);
    const targetVerdicts = evaluate(targetModel, targetPolicy, WITHOUT_DEPENDENCY_GRAPHS);
    const targetVerdict = findVerdict(targetVerdicts, purl, TARGET)!;

    // The target-aware election picks the GPL-2.0-only branch instead (the matrix diagonal),
    // the exact opposite of elect()'s own preference.
    expect(targetVerdict.rule).toBe("target:ok");
    expect(targetVerdict.reason).toContain("GPL-2.0-only");

    // The two runs differ ONLY at the verdict-reason level. finding.expression/elected are
    // computed at normalize time, independent of any policy target, so the rendered License
    // column (which shows the full expression, never one elected branch) is byte-identical.
    const licenseLine = (model: CanonicalDependencies): string | undefined =>
      renderMarkdown(model)
        .split("\n")
        .find((line) => line.includes("election-flip"));

    expect(licenseLine(targetModel)).toBe(licenseLine(noTargetModel));
    expect(licenseLine(noTargetModel)).toContain("Apache-2.0 OR GPL-2.0-only");
  });
});

describe("target lane — profile flip re-fails (the held exposure is never sticky)", () => {
  test("flipping distribution internal -> external turns a held GPL dep into a fail", () => {
    const purl = "pkg:npm/profile-flip-distribution@1.0.0";
    const specs: PackageSpec[] = [
      {
        purl,
        name: "profile-flip-distribution",
        claims: ["GPL-3.0-only"],
        occurrences: [{ target: TARGET }],
      },
    ];
    const internalPolicy = [
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "internal"',
      "",
    ].join("\n");
    const { verdicts: heldVerdicts } = runEngine(specs, internalPolicy);
    const held = findVerdict(heldVerdicts, purl, TARGET)!;

    expect(held.status).toBe("ok");
    expect(held.rule).toBe("target:internal-use");

    const externalPolicy = [
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "external"',
      "",
    ].join("\n");
    const { verdicts: failedVerdicts } = runEngine(specs, externalPolicy);
    const failed = findVerdict(failedVerdicts, purl, TARGET)!;

    expect(failed.status).toBe("fail");
    expect(failed.rule).toBe("target:incompatible");
  });

  test("flipping network false -> true turns a held AGPL dep into a fail", () => {
    const purl = "pkg:npm/profile-flip-network@1.0.0";
    const specs: PackageSpec[] = [
      {
        purl,
        name: "profile-flip-network",
        claims: ["AGPL-3.0-only"],
        occurrences: [{ target: TARGET }],
      },
    ];
    const networkFalsePolicy = [
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "internal"',
      "",
    ].join("\n");
    const { verdicts: heldVerdicts } = runEngine(specs, networkFalsePolicy);
    const held = findVerdict(heldVerdicts, purl, TARGET)!;

    expect(held.status).toBe("ok");
    expect(held.rule).toBe("target:internal-use");

    const networkTruePolicy = [
      "[target]",
      'license = "MIT"',
      "network = true",
      'distribution = "internal"',
      "",
    ].join("\n");
    const { verdicts: failedVerdicts } = runEngine(specs, networkTruePolicy);
    const failed = findVerdict(failedVerdicts, purl, TARGET)!;

    expect(failed.status).toBe("fail");
    expect(failed.rule).toBe("target:incompatible");
  });

  test("absorption guard: the same flips over an AGPL dep under an AGPL-3.0-only target change nothing - target:ok throughout", () => {
    const purl = "pkg:npm/absorption-guard@1.0.0";
    const specs: PackageSpec[] = [
      {
        purl,
        name: "absorption-guard",
        claims: ["AGPL-3.0-only"],
        occurrences: [{ target: TARGET }],
      },
    ];
    const combos: ReadonlyArray<
      readonly [network: boolean, distribution: "external" | "internal"]
    > = [
      [false, "internal"],
      [false, "external"],
      [true, "internal"],
      [true, "external"],
    ];

    for (const [network, distribution] of combos) {
      const policy = [
        "[target]",
        'license = "AGPL-3.0-only"',
        `network = ${network}`,
        `distribution = "${distribution}"`,
        "",
      ].join("\n");
      const { verdicts } = runEngine(specs, policy);
      const verdict = findVerdict(verdicts, purl, TARGET)!;

      expect(verdict.status).toBe("ok");
      expect(verdict.rule).toBe("target:ok");
    }
  });
});

describe("target lane — an unlisted-OSS-target policy is rejected before it can ever reach evaluate", () => {
  test("the maintainer's repro: a CC0-1.0 target (valid SPDX, absent from the compatibility matrix's 119 rows) paired with a GPL-3.0-only dependency used to warn target:unknown-pair instead of failing target:incompatible - parsePolicy now rejects the target before evaluate ever sees it", () => {
    const policyText = `[target]
license = "CC0-1.0"
network = false
distribution = "external"
`;

    // Pre-fix, this policy parsed and the pair below landed here:
    //   { status: "warn", rule: "target:unknown-pair",
    //     reason: "... has no vetted compatibility data - OSADL copyleft class: Yes - not
    //     silently passed; accept explicitly via [[compatible]] or correct the finding via
    //     [[clarify]]" }
    // CC0-1.0 is not an OSADL matrix row, so classifyLeaf's tier 1 (the only tier that may ever
    // decide "incompatible" for an OSS target) never fires - every genuinely-incompatible
    // dependency under an unlisted target silently degrades to the residual warn above, exit 0.
    // The fix rejects the unlisted target at parse time instead, so the pair can never reach
    // evaluate() at all.
    let thrown: unknown;

    try {
      parsePolicy(policyText);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(PolicyError);
    expect((thrown as PolicyError).message).toContain('license "CC0-1.0"');
    expect((thrown as PolicyError).message).toContain("not covered by the compatibility matrix");
  });

  test("permanent lock: an unlisted-OSS-target policy never produces a Verdict[] - parsePolicy throws before runEngine's evaluate() call is reachable", () => {
    const purl = "pkg:npm/unlisted-target-lock@1.0.0";
    const policyText = `[target]
license = "CC0-1.0"
network = false
distribution = "external"
`;
    const specs: PackageSpec[] = [
      {
        purl,
        name: "unlisted-target-lock",
        claims: ["GPL-3.0-only"],
        occurrences: [{ target: TARGET }],
      },
    ];

    expect(() => runEngine(specs, policyText)).toThrow(PolicyError);
  });
});
