import { describe, expect, test } from "bun:test";
import parseSpdx from "spdx-expression-parse";

import { renderNode, type ExpressionNode } from "../../normalize/expression";
import { classifyExpression, classifyLeaf } from "./classify";
import {
  formatProfileLabel,
  targetBoundaryReason,
  targetIncompatibleReason,
  targetInternalUseReason,
  targetOkReason,
  targetUnknownPairReason,
  TARGET_RULE_BOUNDARY,
  TARGET_RULE_INCOMPATIBLE,
  TARGET_RULE_INTERNAL_USE,
  TARGET_RULE_OK,
  TARGET_RULE_UNKNOWN_PAIR,
} from "./reasons";
import type { TargetLicense } from "./classification";
import type { TargetProfile } from "./profile";

const oss = (id: string): TargetLicense => ({ kind: "oss", id });
const proprietary: TargetLicense = { kind: "proprietary" };

const p = (text: string): ExpressionNode => parseSpdx(text) as ExpressionNode;

const profile = (
  license: TargetLicense,
  network = false,
  distribution: TargetProfile["distribution"] = "external",
): TargetProfile => ({ license, network, distribution });

describe("classifyExpression - single-leaf identity", () => {
  test("a single leaf equals classifyLeaf modulated through the same profile", () => {
    const prof = profile(oss("GPL-3.0-only"), false, "external");
    const result = classifyExpression(prof, p("MIT"));

    expect(result.class).toBe(classifyLeaf(prof.license, "MIT").class);
    expect(renderNode(result.elected)).toBe("MIT");
    expect(result.sources).toEqual([classifyLeaf(prof.license, "MIT").source]);
  });
});

describe("classifyExpression - AND dominance, elected keeps both sides", () => {
  test("both compatible leaves stay compatible, elected keeps both", () => {
    const prof = profile(oss("GPL-3.0-only"), false, "external");
    const result = classifyExpression(prof, p("MIT AND GPL-3.0-only"));

    expect(result.class).toBe("compatible");
    expect(renderNode(result.elected)).toBe("MIT AND GPL-3.0-only");
  });

  test("one incompatible conjunct dominates", () => {
    const prof = profile(oss("GPL-2.0-only"), false, "external");
    const result = classifyExpression(prof, p("MIT AND Apache-2.0"));

    expect(result.class).toBe("incompatible");
  });
});

describe("classifyExpression - OR election, the target-aware preference", () => {
  test("the counterexample, both operand orders, under an active GPL-2.0-only target: elects GPL, compatible", () => {
    const prof = profile(oss("GPL-2.0-only"), false, "external");
    const forward = classifyExpression(prof, p("Apache-2.0 OR GPL-2.0-only"));
    const reverse = classifyExpression(prof, p("GPL-2.0-only OR Apache-2.0"));

    expect(forward.class).toBe("compatible");
    expect(renderNode(forward.elected)).toBe("GPL-2.0-only");
    expect(reverse.class).toBe("compatible");
    expect(renderNode(reverse.elected)).toBe("GPL-2.0-only");
  });

  test("the same finding under an MIT target elects Apache-2.0 instead - the flip is target-driven, not order-driven", () => {
    const prof = profile(oss("MIT"), false, "external");
    const result = classifyExpression(prof, p("Apache-2.0 OR GPL-2.0-only"));

    expect(result.class).toBe("compatible");
    expect(renderNode(result.elected)).toBe("Apache-2.0");
  });

  test("MIT OR LicenseRef-internal elects MIT, compatible, under any profile", () => {
    const profiles: readonly TargetProfile[] = [
      profile(oss("GPL-3.0-only"), false, "external"),
      profile(proprietary, true, "internal"),
    ];

    for (const prof of profiles) {
      const result = classifyExpression(prof, p("MIT OR LicenseRef-internal"));

      expect(result.class).toBe("compatible");
      expect(renderNode(result.elected)).toBe("MIT");
    }
  });
});

describe("classifyExpression - AGPL absorption end-to-end (the case a hardcoded network rule would break)", () => {
  test("an AGPL-3.0-only leaf under an AGPL-3.0-only, network-deployed, external target is compatible, target-absorbed", () => {
    const prof = profile(oss("AGPL-3.0-only"), true, "external");
    const result = classifyExpression(prof, p("AGPL-3.0-only"));

    expect(result.class).toBe("compatible");
  });
});

describe("classifyExpression - profile-modulated election", () => {
  test("Apache-2.0 OR GPL-3.0-only under a GPL-2.0-only INTERNAL target elects the GPL branch as held-internal, never the incompatible Apache-2.0 branch", () => {
    const prof = profile(oss("GPL-2.0-only"), false, "internal");
    const result = classifyExpression(prof, p("Apache-2.0 OR GPL-3.0-only"));

    expect(result.class).toBe("held-internal");
    expect(renderNode(result.elected)).toBe("GPL-3.0-only");
  });
});

describe("classifyExpression - WITH never stripped", () => {
  test("whenever the WITH branch wins the election, its rendered text keeps the WITH clause", () => {
    const result = classifyExpression(
      profile(proprietary),
      p("GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-2.0-only"),
    );

    expect(result.class).toBe("boundary");
    expect(renderNode(result.elected)).toBe("GPL-2.0-only WITH Classpath-exception-2.0");
  });
});

describe("classifyExpression - nested shapes", () => {
  test("(MIT AND Apache-2.0) OR GPL-3.0-only under an MIT target elects the AND branch, compatible", () => {
    const result = classifyExpression(
      profile(oss("MIT")),
      p("(MIT AND Apache-2.0) OR GPL-3.0-only"),
    );

    expect(result.class).toBe("compatible");
    expect(renderNode(result.elected)).toBe("MIT AND Apache-2.0");
  });

  test("(MIT AND Apache-2.0) OR GPL-3.0-only under a GPL-3.0-only target elects GPL-3.0-only, compatible", () => {
    const result = classifyExpression(
      profile(oss("GPL-3.0-only")),
      p("(MIT AND Apache-2.0) OR GPL-3.0-only"),
    );

    expect(result.class).toBe("compatible");
    expect(renderNode(result.elected)).toBe("GPL-3.0-only");
  });

  test("adversarial gate: a fresh (A OR B) AND C shape is operand-order independent under both an MIT and a GPL-2.0-only target", () => {
    for (const target of [oss("MIT"), oss("GPL-2.0-only")]) {
      const prof = profile(target, false, "external");
      const forward = classifyExpression(prof, p("(Apache-2.0 OR GPL-2.0-only) AND MIT"));
      const reverse = classifyExpression(prof, p("MIT AND (GPL-2.0-only OR Apache-2.0)"));

      expect(forward.class).toBe(reverse.class);
      expect(forward.class).toBe("compatible");
    }
  });
});

describe("classifyExpression - properties (sampled over real matrix ids x both flags)", () => {
  const SAMPLE_IDS: readonly string[] = [
    "MIT",
    "Apache-2.0",
    "GPL-2.0-only",
    "GPL-3.0-only",
    "AGPL-3.0-only",
    "LGPL-2.1-only",
    "BSD-3-Clause",
    "MPL-2.0",
  ];
  const TARGETS: readonly TargetLicense[] = [oss("MIT"), oss("GPL-3.0-only"), proprietary];
  const NETWORK_VALUES: readonly boolean[] = [false, true];

  test("single-leaf classifyExpression equals modulated classifyLeaf for every sampled (target, leaf, network) combination", () => {
    for (const target of TARGETS) {
      for (const leaf of SAMPLE_IDS) {
        for (const network of NETWORK_VALUES) {
          const prof = profile(target, network, "external");
          const expressionResult = classifyExpression(prof, p(leaf));
          const leafResult = classifyLeaf(target, leaf);

          expect(expressionResult.class).toBe(leafResult.class);
          expect(renderNode(expressionResult.elected)).toBe(leaf);
        }
      }
    }
  });

  test("OR of a leaf with itself equals the leaf, for every sampled (target, leaf, network) combination", () => {
    for (const target of TARGETS) {
      for (const leaf of SAMPLE_IDS) {
        for (const network of NETWORK_VALUES) {
          const prof = profile(target, network, "external");
          const self = classifyExpression(prof, p(`${leaf} OR ${leaf}`));
          const single = classifyExpression(prof, p(leaf));

          expect(self.class).toBe(single.class);
          expect(renderNode(self.elected)).toBe(renderNode(single.elected));
        }
      }
    }
  });

  test("operand order never changes class or elected rendering, for every sampled AND/OR pair", () => {
    const pairs = TARGETS.flatMap((target) =>
      SAMPLE_IDS.flatMap((a) => SAMPLE_IDS.filter((b) => b !== a).map((b) => ({ target, a, b }))),
    );

    for (const { target, a, b } of pairs) {
      const prof = profile(target, false, "external");
      const orForward = classifyExpression(prof, p(`${a} OR ${b}`));
      const orReverse = classifyExpression(prof, p(`${b} OR ${a}`));
      const andForward = classifyExpression(prof, p(`${a} AND ${b}`));
      const andReverse = classifyExpression(prof, p(`${b} AND ${a}`));

      expect(orForward.class).toBe(orReverse.class);
      expect(renderNode(orForward.elected)).toBe(renderNode(orReverse.elected));
      expect(andForward.class).toBe(andReverse.class);
    }
  });

  test("external results never contain held-internal, for every sampled (target, leaf, network) combination", () => {
    for (const target of TARGETS) {
      for (const leaf of SAMPLE_IDS) {
        for (const network of NETWORK_VALUES) {
          const result = classifyExpression(profile(target, network, "external"), p(leaf));

          expect(result.class).not.toBe("held-internal");
        }
      }
    }
  });
});

describe("reasons.ts - rule ids and reason builders", () => {
  const ctx = {
    elected: "GPL-3.0-only",
    occurrenceTarget: "apps/api",
    profileLabel: "proprietary, network-deployed, distributed externally",
    source: "OSADL: No",
  };

  test("the five rule ids are the target: namespace, each distinct", () => {
    const ids = new Set([
      TARGET_RULE_OK,
      TARGET_RULE_INCOMPATIBLE,
      TARGET_RULE_BOUNDARY,
      TARGET_RULE_UNKNOWN_PAIR,
      TARGET_RULE_INTERNAL_USE,
    ]);

    expect(ids.size).toBe(5);
    for (const id of ids) {
      expect(id.startsWith("target:")).toBe(true);
    }
  });

  test("each builder names the elected rendering, the occurrence target, and the profile", () => {
    const builders = [
      targetOkReason,
      targetIncompatibleReason,
      targetBoundaryReason,
      targetUnknownPairReason,
      targetInternalUseReason,
    ];

    for (const builder of builders) {
      const reason = builder(ctx);

      expect(reason).toContain('"GPL-3.0-only"');
      expect(reason).toContain('"apps/api"');
      expect(reason).toContain("proprietary, network-deployed, distributed externally");
      expect(reason).toContain("OSADL: No");
    }
  });

  test("the incompatible/boundary/unknown-pair builders carry a [[compatible]] or [[clarify]] remedy", () => {
    expect(targetIncompatibleReason(ctx)).toMatch(/\[\[compatible\]\]|\[\[clarify\]\]/);
    expect(targetBoundaryReason(ctx)).toContain("[[compatible]]");
    expect(targetUnknownPairReason(ctx)).toMatch(/\[\[compatible\]\]|\[\[clarify\]\]/);
  });

  test("no reason string ever carries retrieval metadata (a URL or an ISO timestamp)", () => {
    const builders = [
      targetOkReason,
      targetIncompatibleReason,
      targetBoundaryReason,
      targetUnknownPairReason,
      targetInternalUseReason,
    ];

    for (const builder of builders) {
      const reason = builder(ctx);

      expect(reason.toLowerCase()).not.toContain("http");
      expect(reason).not.toMatch(/\d{4}-\d{2}-\d{2}/);
    }
  });

  test("formatProfileLabel renders license/network/distribution in reader's words", () => {
    expect(
      formatProfileLabel({ license: proprietary, network: true, distribution: "external" }),
    ).toBe("proprietary, network-deployed, distributed externally");
    expect(
      formatProfileLabel({ license: oss("MIT"), network: false, distribution: "internal" }),
    ).toBe("MIT, not network-deployed, internal use only");
  });
});
