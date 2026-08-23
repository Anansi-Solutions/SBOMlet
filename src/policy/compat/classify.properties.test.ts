import { describe, expect, test } from "bun:test";
import parseSpdx from "spdx-expression-parse";

import { renderNode, type ExpressionNode } from "../../normalize/expression";
import { classifyExpression, classifyLeaf } from "./classify";
import { applyUsageProfile, type ModulatedClass, type TargetProfile } from "./profile";
import type { AxisClass, ObligationClass, TargetLicense } from "./classification";

const oss = (id: string): TargetLicense => ({ kind: "oss", id });
const proprietary: TargetLicense = { kind: "proprietary" };

const p = (text: string): ExpressionNode => parseSpdx(text) as ExpressionNode;

const profile = (
  license: TargetLicense,
  network = false,
  distribution: TargetProfile["distribution"] = "external",
): TargetProfile => ({ license, network, distribution });

// ===========================================================================
// Layer 2: an independently hand-authored table of well-established compatibility facts. These are
// drawn from license law and common practice, NOT read from the vendored json - so a matrix that
// silently regressed to the wrong verdict fails here even while it stays internally self-consistent.
// ===========================================================================

interface LicenseFact {
  readonly target: TargetLicense;
  readonly leaf: string;
  readonly class: AxisClass;
  readonly obligation?: ObligationClass;
  readonly why: string;
}

const FAMOUS_FACTS: readonly LicenseFact[] = [
  // A copyleft project can absorb inbound permissive code.
  { target: oss("GPL-3.0-only"), leaf: "MIT", class: "compatible", why: "GPLv3 absorbs MIT" },
  {
    target: oss("GPL-3.0-only"),
    leaf: "BSD-2-Clause",
    class: "compatible",
    why: "GPLv3 absorbs BSD-2-Clause",
  },
  { target: oss("GPL-3.0-only"), leaf: "ISC", class: "compatible", why: "GPLv3 absorbs ISC" },
  {
    target: oss("GPL-3.0-only"),
    leaf: "Apache-2.0",
    class: "compatible",
    why: "GPLv3 is Apache-2.0 compatible",
  },
  // The classic incompatibility: Apache-2.0's patent terms clash with GPLv2-only.
  {
    target: oss("GPL-2.0-only"),
    leaf: "Apache-2.0",
    class: "incompatible",
    obligation: "none",
    why: "the classic Apache-2.0 / GPLv2-only clash",
  },
  // A permissive project cannot silently take in reciprocal code.
  {
    target: oss("MIT"),
    leaf: "GPL-3.0-only",
    class: "incompatible",
    obligation: "copyleft",
    why: "MIT cannot absorb GPLv3",
  },
  {
    target: oss("MIT"),
    leaf: "AGPL-3.0-only",
    class: "incompatible",
    obligation: "agpl",
    why: "MIT cannot absorb AGPLv3",
  },
  {
    target: oss("MIT"),
    leaf: "LGPL-2.1-only",
    class: "incompatible",
    obligation: "copyleft",
    why: "MIT cannot absorb LGPLv2.1 obligations",
  },
  // GPL cross-version incompatibility, both directions.
  {
    target: oss("GPL-2.0-only"),
    leaf: "GPL-3.0-only",
    class: "incompatible",
    why: "GPLv2-only and GPLv3 are mutually incompatible",
  },
  {
    target: oss("GPL-3.0-only"),
    leaf: "GPL-2.0-only",
    class: "incompatible",
    why: "GPLv3 cannot absorb GPLv2-only",
  },
  // Identity (matrix diagonal) always passes.
  { target: oss("MIT"), leaf: "MIT", class: "compatible", why: "identical license" },
  {
    target: oss("GPL-3.0-only"),
    leaf: "GPL-3.0-only",
    class: "compatible",
    why: "identical license",
  },
  {
    target: oss("AGPL-3.0-only"),
    leaf: "AGPL-3.0-only",
    class: "compatible",
    obligation: "agpl",
    why: "identical license, AGPL absorbs AGPL",
  },
  // Permissive under permissive.
  {
    target: oss("MIT"),
    leaf: "BSD-3-Clause",
    class: "compatible",
    why: "permissive under permissive",
  },
  // Proprietary boundary tier - the shipping-a-closed-product view.
  {
    target: proprietary,
    leaf: "MIT",
    class: "compatible",
    obligation: "none",
    why: "permissive is safe in a proprietary product",
  },
  {
    target: proprietary,
    leaf: "Apache-2.0",
    class: "compatible",
    obligation: "none",
    why: "permissive is safe in a proprietary product",
  },
  {
    target: proprietary,
    leaf: "GPL-2.0-only",
    class: "incompatible",
    obligation: "copyleft",
    why: "strong copyleft in a proprietary product",
  },
  {
    target: proprietary,
    leaf: "AGPL-3.0-only",
    class: "incompatible",
    obligation: "agpl",
    why: "network copyleft in a proprietary product",
  },
  {
    target: proprietary,
    leaf: "LGPL-2.1-only",
    class: "boundary",
    why: "weak copyleft is a boundary case in a proprietary product",
  },
  {
    target: proprietary,
    leaf: "MPL-2.0",
    class: "boundary",
    why: "weak copyleft is a boundary case in a proprietary product",
  },
];

describe("classifyLeaf - hand-authored famous-fact table (independent of the vendored json)", () => {
  test("every well-established license-compatibility fact holds against the current engine", () => {
    const violations = FAMOUS_FACTS.flatMap((fact) => {
      const result = classifyLeaf(fact.target, fact.leaf);
      const classOk = result.class === fact.class;
      const obligationOk = fact.obligation === undefined || result.obligation === fact.obligation;

      return classOk && obligationOk
        ? []
        : [
            {
              pair: `${fact.target.kind === "oss" ? fact.target.id : "proprietary"} <- ${fact.leaf}`,
              why: fact.why,
              expected: { class: fact.class, obligation: fact.obligation },
              actual: { class: result.class, obligation: result.obligation },
            },
          ];
    });

    expect(violations).toEqual([]);
  });
});

// ===========================================================================
// Layer 3: structural laws that must hold for ALL composed inputs, driven over a curated cartesian
// of real licenses x targets (hand-rolled property testing - no library). The dominance order below
// is the documented worst-to-best contract from classify.ts, transcribed here as the independent
// oracle for AND/OR composition, the same way profile.test transcribes the scope-gating rule.
// ===========================================================================

const DOMINANCE_ORDER: readonly ModulatedClass[] = [
  "incompatible",
  "unassessed-ref",
  "residual",
  "boundary",
  "held-internal",
  "compatible",
];
const rank = (cls: ModulatedClass): number => DOMINANCE_ORDER.indexOf(cls);

const LICENSES: readonly string[] = [
  "MIT",
  "Apache-2.0",
  "BSD-3-Clause",
  "ISC",
  "GPL-2.0-only",
  "GPL-3.0-only",
  "AGPL-3.0-only",
  "LGPL-2.1-only",
  "MPL-2.0",
  "EPL-2.0",
];
const TARGETS: readonly TargetLicense[] = [
  oss("MIT"),
  oss("GPL-2.0-only"),
  oss("GPL-3.0-only"),
  oss("AGPL-3.0-only"),
  proprietary,
];

/** One leaf's modulated class through the real production path, the composition laws' per-leaf input. */
const modClass = (prof: TargetProfile, leaf: string): ModulatedClass =>
  applyUsageProfile(classifyLeaf(prof.license, leaf), prof).class;

const ORDERED_PAIRS = TARGETS.flatMap((target) =>
  LICENSES.flatMap((a) => LICENSES.map((b) => ({ target, a, b }))),
);

describe("classifyExpression - AND dominance law over the curated cartesian", () => {
  test("an AND is exactly the worst (lowest-ranked) of its two modulated conjuncts, both sides kept", () => {
    const violations = ORDERED_PAIRS.flatMap(({ target, a, b }) => {
      const prof = profile(target, false, "external");
      const result = classifyExpression(prof, p(`${a} AND ${b}`));
      const worst = Math.min(rank(modClass(prof, a)), rank(modClass(prof, b)));
      const electedOk = renderNode(result.elected) === `${a} AND ${b}`;

      return rank(result.class) === worst && electedOk
        ? []
        : [{ target, a, b, class: result.class, elected: renderNode(result.elected) }];
    });

    expect(violations).toEqual([]);
  });
});

describe("classifyExpression - OR preference law over the curated cartesian", () => {
  test("an OR is exactly the best (highest-ranked) of its two modulated branches", () => {
    const violations = ORDERED_PAIRS.flatMap(({ target, a, b }) => {
      const prof = profile(target, false, "external");
      const result = classifyExpression(prof, p(`${a} OR ${b}`));
      const best = Math.max(rank(modClass(prof, a)), rank(modClass(prof, b)));

      return rank(result.class) === best ? [] : [{ target, a, b, class: result.class }];
    });

    expect(violations).toEqual([]);
  });

  test("when the two OR branches differ in rank, the strictly-better branch is the elected one", () => {
    const violations = ORDERED_PAIRS.flatMap(({ target, a, b }) => {
      const prof = profile(target, false, "external");
      const rankA = rank(modClass(prof, a));
      const rankB = rank(modClass(prof, b));

      if (rankA === rankB) {
        return [];
      }

      const winner = rankA > rankB ? a : b;
      const elected = renderNode(classifyExpression(prof, p(`${a} OR ${b}`)).elected);

      return elected === winner ? [] : [{ target, a, b, winner, elected }];
    });

    expect(violations).toEqual([]);
  });
});

describe("classifyExpression - operand-order independence over the curated cartesian", () => {
  test("AND and OR class, and OR elected rendering, are invariant under swapping the two operands", () => {
    const distinct = ORDERED_PAIRS.filter(({ a, b }) => a !== b);
    const violations = distinct.flatMap(({ target, a, b }) => {
      const prof = profile(target, false, "external");
      const andFwd = classifyExpression(prof, p(`${a} AND ${b}`)).class;
      const andRev = classifyExpression(prof, p(`${b} AND ${a}`)).class;
      const orFwd = classifyExpression(prof, p(`${a} OR ${b}`));
      const orRev = classifyExpression(prof, p(`${b} OR ${a}`));
      const ok =
        andFwd === andRev &&
        orFwd.class === orRev.class &&
        renderNode(orFwd.elected) === renderNode(orRev.elected);

      return ok ? [] : [{ target, a, b, andFwd, andRev, orFwd: orFwd.class, orRev: orRev.class }];
    });

    expect(violations).toEqual([]);
  });
});

describe("classifyExpression - reflexive-composition and floor laws over the curated cartesian", () => {
  test("a OR a and a AND a both collapse to the single-leaf verdict, for every (target, leaf)", () => {
    const singles = TARGETS.flatMap((target) => LICENSES.map((leaf) => ({ target, leaf })));
    const violations = singles.flatMap(({ target, leaf }) => {
      const prof = profile(target, false, "external");
      const single = classifyExpression(prof, p(leaf));
      const orSelf = classifyExpression(prof, p(`${leaf} OR ${leaf}`));
      const andSelf = classifyExpression(prof, p(`${leaf} AND ${leaf}`));

      return single.class === orSelf.class && single.class === andSelf.class
        ? []
        : [{ target, leaf, single: single.class, orSelf: orSelf.class, andSelf: andSelf.class }];
    });

    expect(violations).toEqual([]);
  });

  test("external distribution never yields a held-internal outcome for any single leaf or pair", () => {
    const singles = TARGETS.flatMap((target) =>
      LICENSES.map((leaf) => classifyExpression(profile(target, false, "external"), p(leaf)).class),
    );
    const pairs = ORDERED_PAIRS.flatMap(({ target, a, b }) => {
      const prof = profile(target, false, "external");

      return [
        classifyExpression(prof, p(`${a} AND ${b}`)).class,
        classifyExpression(prof, p(`${a} OR ${b}`)).class,
      ];
    });

    expect([...singles, ...pairs].filter((cls) => cls === "held-internal")).toEqual([]);
  });
});

describe("classifyExpression - the {compatible, incompatible} composition endpoints", () => {
  test("AND selects the conflict and OR selects the pass, both operand orders, under an active target", () => {
    // GPL-2.0-only absorbs MIT (compatible) but rejects Apache-2.0 (incompatible), so a single
    // expression exercises both endpoints of the dominance order at once.
    const prof = profile(oss("GPL-2.0-only"), false, "external");

    expect(classifyExpression(prof, p("MIT AND Apache-2.0")).class).toBe("incompatible");
    expect(classifyExpression(prof, p("Apache-2.0 AND MIT")).class).toBe("incompatible");
    expect(classifyExpression(prof, p("MIT OR Apache-2.0")).class).toBe("compatible");
    expect(classifyExpression(prof, p("Apache-2.0 OR MIT")).class).toBe("compatible");
  });

  test("internal distribution can rescue an out-of-scope copyleft conflict to held-internal, network held apart", () => {
    // The same Apache-2.0-under-GPL-2.0-only conflict is obligation none, so internal use never
    // rescues it; a genuine copyleft leaf under an internal proprietary target does hold.
    const internal = profile(proprietary, false, "internal");

    expect(classifyExpression(internal, p("GPL-2.0-only")).class).toBe("held-internal");
    expect(
      classifyExpression(profile(proprietary, false, "external"), p("GPL-2.0-only")).class,
    ).toBe("incompatible");
    // An AGPL obligation stays in scope under network deployment even when internal-only.
    expect(
      classifyExpression(profile(proprietary, true, "internal"), p("AGPL-3.0-only")).class,
    ).toBe("incompatible");
    expect(
      classifyExpression(profile(proprietary, false, "internal"), p("AGPL-3.0-only")).class,
    ).toBe("held-internal");
  });
});
