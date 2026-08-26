import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import parse from "spdx-expression-parse";
import satisfies from "spdx-satisfies";

import { COPYLEFT_IDS } from "../policy/engine/copyleft";
import { denyRuleFor } from "../policy/engine/deny";
import { asRawLicense, leaf, widen } from "../../test/brandTestSupport";
import {
  canonicalizeExpression,
  elect,
  isCopyleft,
  orLeaves,
  renderNode,
  type ExpressionNode,
} from "./expression";
import type { Policy } from "../policy/schema";

// parse() output is structurally compatible with ExpressionNode (inline-union
// purity pattern: we never import the lib's internal types).
const p = (expr: string): ExpressionNode => parse(expr) as ExpressionNode;

describe("COPYLEFT_IDS membership", () => {
  test("contains current, deprecated, and family ids", () => {
    expect(COPYLEFT_IDS.has(leaf("AGPL-3.0-only"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("AGPL-3.0"))).toBe(true); // deprecated form
    expect(COPYLEFT_IDS.has(leaf("GPL-2.0"))).toBe(true); // deprecated form
    expect(COPYLEFT_IDS.has(leaf("MPL-2.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("SSPL-1.0"))).toBe(true);
  });

  test("contains the CR-01 reciprocal families (CC-BY-SA, Sleepycat, CPAL, MS-RL, RPL, QPL, APSL, GFDL)", () => {
    // CC ShareAlike IS copyleft — the CC family demonstrably reaches this
    // tool's input (CC-BY-3.0/4.0 are in the live corpus below).
    expect(COPYLEFT_IDS.has(leaf("CC-BY-SA-4.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("CC-BY-SA-1.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("CC-BY-SA-3.0-DE"))).toBe(true); // jurisdiction port
    expect(COPYLEFT_IDS.has(leaf("Sleepycat"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("CPAL-1.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("MS-RL"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("RPL-1.1"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("RPL-1.5"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("QPL-1.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("APSL-1.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("APSL-2.0"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("GFDL-1.3"))).toBe(true); // deprecated base
    expect(COPYLEFT_IDS.has(leaf("GFDL-1.3-only"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("GFDL-1.3-or-later"))).toBe(true);
    expect(COPYLEFT_IDS.has(leaf("GFDL-1.1-invariants-only"))).toBe(true);
    // Plain CC attribution (no ShareAlike) is NOT copyleft.
    expect(COPYLEFT_IDS.has(leaf("CC-BY-4.0"))).toBe(false);
    expect(COPYLEFT_IDS.has(leaf("CC-BY-3.0"))).toBe(false);
    // Microsoft PUBLIC license (permissive sibling of MS-RL) stays out.
    expect(COPYLEFT_IDS.has(leaf("MS-PL"))).toBe(false);
  });

  test("is the verbatim 94-id literal (54 from research + 40 CR-01 additions)", () => {
    expect(COPYLEFT_IDS.size).toBe(94);
  });

  test("every member is a real SPDX id — current or deprecated (typo-proof)", () => {
    // Validate the literal against the spdx-license-ids data shipped in
    // node_modules (the same data spdx-expression-parse matches against):
    // a typo'd id here would never match a parsed leaf and would silently
    // recreate the CR-01 default:ok gap.
    const dataDir = join(import.meta.dir, "..", "..", "node_modules", "spdx-license-ids");
    const current = JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const typos = [...COPYLEFT_IDS].filter((id) => !known.has(id));

    expect(typos).toEqual([]);
  });

  test("GPL-2.0+ leaf is copyleft via base-id membership", () => {
    expect(isCopyleft({ license: "GPL-2.0", plus: true })).toBe(true);
  });
});

describe("COPYLEFT_IDS collision exclusions (never substring)", () => {
  test("GPL-substring ids that are NOT copyleft are excluded", () => {
    expect(COPYLEFT_IDS.has(leaf("LGPLLR"))).toBe(false);
    expect(COPYLEFT_IDS.has(leaf("NGPL"))).toBe(false);
    expect(COPYLEFT_IDS.has(leaf("SMAIL-GPL"))).toBe(false);
    expect(COPYLEFT_IDS.has(leaf("CNRI-Python-GPL-Compatible"))).toBe(false);
  });
});

describe("isCopyleft tree semantics", () => {
  test("OR is copyleft only if BOTH branches are", () => {
    expect(isCopyleft(p("MIT OR GPL-3.0-only"))).toBe(false);
    expect(isCopyleft(p("GPL-2.0-only OR GPL-3.0-only"))).toBe(true);
  });

  test("AND is tainted by ANY copyleft conjunct", () => {
    expect(isCopyleft(p("Apache-2.0 AND LGPL-3.0-or-later"))).toBe(true);
  });

  test("WITH exception does not clear copyleft", () => {
    expect(isCopyleft(p("GPL-2.0-only WITH Classpath-exception-2.0"))).toBe(true);
  });
});

describe("elect — deterministic OR-branch election", () => {
  test("prefers the non-copyleft branch, order-independent", () => {
    expect(renderNode(elect(p("(MIT OR GPL-3.0-only)")))).toBe("MIT");
    expect(renderNode(elect(p("(GPL-3.0-only OR MIT)")))).toBe("MIT");
  });

  test("tie-break 2c: codepoint-lexicographic on rendered branch", () => {
    // Both permissive: C < M, so CC0-1.0 wins deterministically.
    expect(renderNode(elect(p("(MIT OR CC0-1.0)")))).toBe("CC0-1.0");
  });

  test("tie-break 2b: prefers a branch with no LicenseRef/DocumentRef leaves", () => {
    // Pure lexicographic would elect LicenseRef-internal-foo (L < M).
    expect(renderNode(elect(p("(LicenseRef-internal-foo OR MIT)")))).toBe("MIT");
  });

  test("AND composes elected sub-expressions (rule 1)", () => {
    expect(renderNode(elect(p("(MIT OR GPL-2.0-only) AND Apache-2.0")))).toBe("MIT AND Apache-2.0");
  });

  test("(MPL-2.0 OR Apache-2.0) elects Apache-2.0 and avoids copyleft", () => {
    const elected = elect(p("(MPL-2.0 OR Apache-2.0)"));

    expect(renderNode(elected)).toBe("Apache-2.0");
    expect(isCopyleft(elected)).toBe(false);
  });

  test("WITH leaves are elected as a unit — exception never stripped (rule 3)", () => {
    expect(renderNode(elect(p("GPL-2.0-only WITH Classpath-exception-2.0")))).toBe(
      "GPL-2.0-only WITH Classpath-exception-2.0",
    );
  });
});

describe("orLeaves — satisfies-allowlist decomposition primitive", () => {
  test("pure OR tree yields compareCodeUnits-sorted rendered leaves", () => {
    expect(widen(orLeaves(p("(MIT OR Apache-2.0)")))).toEqual(["Apache-2.0", "MIT"]);
  });

  test("single leaf yields a one-element list", () => {
    expect(widen(orLeaves(p("MIT")))).toEqual(["MIT"]);
  });

  test("WITH leaf is preserved as a unit", () => {
    expect(widen(orLeaves(p("GPL-2.0-only WITH Classpath-exception-2.0")))).toEqual([
      "GPL-2.0-only WITH Classpath-exception-2.0",
    ]);
  });

  test("any AND anywhere yields null", () => {
    expect(orLeaves(p("MIT AND Apache-2.0"))).toBeNull();
    expect(orLeaves(p("(MIT OR Apache-2.0) AND BSD-2-Clause"))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// spdx-satisfies allowlist-entry behavior lock. The scancode agreement test
// (applyScancodeAssessment) calls satisfies(P, [S]) with the in-depth
// expression S as a one-entry allowlist, inside try/catch where ANY throw =
// disagree (fail closed). That posture must be grounded in the library's REAL
// behavior, not the schema.ts comment: this suite records it. Observed at
// spdx-satisfies 6.0.0: a compound allowlist entry — AND *or* OR — throws
// ("Approved licenses cannot be AND or OR expressions"), so a compound
// scancode expression can only agree via the exact-equality pre-check; a WITH
// entry is a valid single unit; the first argument may be compound freely.
// ---------------------------------------------------------------------------

describe("spdx-satisfies allowlist-entry edge (agreement-test substrate)", () => {
  test("an AND-bearing allowlist entry throws — never returns a verdict", () => {
    expect(() => satisfies("MIT", ["MIT AND Apache-2.0"])).toThrow();
    // Even the byte-identical expression cannot satisfy itself through the
    // allowlist — the exact-equality pre-check is the ONLY agreement path
    // for compound in-depth expressions.
    expect(() => satisfies("MIT AND Apache-2.0", ["MIT AND Apache-2.0"])).toThrow();
  });

  test("an OR-bearing allowlist entry throws too (stricter than the AND-only schema.ts comment)", () => {
    expect(() => satisfies("MIT", ["MIT OR Apache-2.0"])).toThrow();
  });

  test("a simple allowlist entry returns a boolean; WITH is a valid unit; a compound FIRST argument is fine", () => {
    expect(satisfies("MIT", ["MIT"])).toBe(true);
    expect(satisfies("Apache-2.0", ["MIT"])).toBe(false);
    expect(satisfies("MIT AND Apache-2.0", ["MIT"])).toBe(false);
    expect(
      satisfies("GPL-2.0-only WITH Classpath-exception-2.0", [
        "GPL-2.0-only WITH Classpath-exception-2.0",
      ]),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// canonicalizeExpression — conservative boolean-algebra simplification for a
// noisy SPDX expression (ScanCode's motivating case: same-operator nesting,
// duplicate conjuncts, absorbable OR/AND branches). FLATTEN, IDEMPOTENCE,
// ABSORPTION, COMMUTATIVITY only — never distribution, never any other
// cross-operator rewrite. Every fixture is also checked for round-trip
// (the output always reparses) and idempotence (canonicalizing it again is a
// no-op).
// ---------------------------------------------------------------------------

/** Reparses cleanly, and canonicalizing the output again changes nothing. */
function assertRoundTripAndIdempotent(output: string): void {
  expect(() => parse(output)).not.toThrow();
  expect(widen(canonicalizeExpression(asRawLicense(output)))).toBe(output);
}

describe("canonicalizeExpression — conservative boolean-algebra simplification", () => {
  test("the maintainer's live noisy example reduces to its three-conjunct canonical form", () => {
    const noisy =
      "(MIT AND OFL-1.1 AND CC-BY-4.0) AND (CC-BY-4.0 OR CC-BY-3.0) AND " +
      "(OFL-1.1 AND (CC-BY-4.0 AND OFL-1.1 AND MIT) AND MIT AND (MIT AND OFL-1.1 AND CC-BY-4.0))";
    const canonical = canonicalizeExpression(asRawLicense(noisy));

    expect(widen(canonical)).toBe("CC-BY-4.0 AND MIT AND OFL-1.1");
    assertRoundTripAndIdempotent(canonical);
  });

  test("ABSORPTION (AND-set absorbs an OR-sibling): A AND (A OR B) -> A", () => {
    const canonical = canonicalizeExpression(asRawLicense("MIT AND (MIT OR Apache-2.0)"));

    expect(widen(canonical)).toBe("MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("ABSORPTION (OR-set absorbs an AND-sibling): A OR (A AND B) -> A", () => {
    const canonical = canonicalizeExpression(asRawLicense("MIT OR (MIT AND Apache-2.0)"));

    expect(widen(canonical)).toBe("MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("FLATTEN only: same-operator nesting collapses before sorting", () => {
    const canonical = canonicalizeExpression(asRawLicense("MIT AND (Apache-2.0 AND BSD-2-Clause)"));

    expect(widen(canonical)).toBe("Apache-2.0 AND BSD-2-Clause AND MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("IDEMPOTENCE only: a duplicate AND conjunct dedupes", () => {
    expect(widen(canonicalizeExpression(asRawLicense("MIT AND MIT")))).toBe("MIT");
  });

  test("(MIT OR MIT) dedupes to MIT", () => {
    expect(widen(canonicalizeExpression(asRawLicense("(MIT OR MIT)")))).toBe("MIT");
  });

  test("A AND (B OR C) is UNCHANGED except child-sort — no distribution", () => {
    const canonical = canonicalizeExpression(asRawLicense("Apache-2.0 AND (MIT OR BSD-2-Clause)"));

    // No distribution into (Apache-2.0 AND MIT) OR (Apache-2.0 AND BSD-2-Clause) —
    // the OR branch stays intact; only its own two children get reordered.
    expect(widen(canonical)).toBe("Apache-2.0 AND (BSD-2-Clause OR MIT)");
    assertRoundTripAndIdempotent(canonical);
  });

  test("a WITH-exception leaf is never decomposed, even duplicated across a compound", () => {
    const canonical = canonicalizeExpression(
      asRawLicense(
        "(GPL-2.0-only WITH Classpath-exception-2.0) AND (GPL-2.0-only WITH Classpath-exception-2.0)",
      ),
    );

    expect(widen(canonical)).toBe("GPL-2.0-only WITH Classpath-exception-2.0");
    assertRoundTripAndIdempotent(canonical);
  });

  test("deep mixed nesting: both absorption directions fire inside a shared AND", () => {
    const canonical = canonicalizeExpression(
      asRawLicense("(MIT OR (MIT AND Apache-2.0)) AND (BSD-2-Clause OR BSD-2-Clause)"),
    );

    expect(widen(canonical)).toBe("BSD-2-Clause AND MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("a single-leaf result serializes bare — no residual parens", () => {
    const canonical = canonicalizeExpression(
      asRawLicense("Apache-2.0 AND (Apache-2.0 OR GPL-2.0-only)"),
    );

    expect(widen(canonical)).toBe("Apache-2.0");
    assertRoundTripAndIdempotent(canonical);
  });

  test("unparseable input passes through UNCHANGED — never throws, never guesses", () => {
    const garbage = "Not a real (((expression";

    expect(widen(canonicalizeExpression(asRawLicense(garbage)))).toBe(garbage);
    expect(widen(canonicalizeExpression(asRawLicense("MIT AND")))).toBe("MIT AND");
  });
});

// ---------------------------------------------------------------------------
// Adversarial property suite. canonicalizeExpression is now load-bearing for
// the policy gate (agreement, staleness, and cross-image divergence all
// compare canonically), so this section holds it to a stronger bar than the
// hand fixtures above: a tiny reference boolean evaluator treats an
// expression as a Boolean formula over its leaves (a leaf = a license id
// INCLUDING any WITH-exception suffix, treated atomically) and checks
// canonicalization never changes the formula it computes. Everything below
// is driven by a seeded LCG, never Math.random, so a failure reproduces
// byte-for-byte.
//
// The documented boundary (a maintainer decision — a Blake-style canonical
// form was explicitly rejected): comparisons here are spelling-blind under
// reordering, duplication, and absorption noise, but deliberately NOT under
// re-factoring — `(A OR B) AND (A OR C)` and `A OR (B AND C)` stay distinct
// even though a full Boolean-algebra normal form would equate them. That
// direction fails safe as a visible conflict rather than a silent one.
// ---------------------------------------------------------------------------

/**
 * Minimal Numerical-Recipes LCG (state_{n+1} = 1664525*state_n + 1013904223 mod 2^32) — the
 * property suite's only source of randomness, seeded once for byte-determinism.
 */
class Lcg {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  private next(): number {
    this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0;

    return this.state;
  }

  /** A float in [0, 1). */
  float(): number {
    return this.next() / 4294967296;
  }

  /** An integer in [0, bound). */
  int(bound: number): number {
    return Math.floor(this.float() * bound);
  }
}

const PROPERTY_SEED = 0xc0ffee;

/**
 * Nine real SPDX ids: three near-miss pairs (MIT/MIT-0, CC-BY-4.0/CC-BY-SA-4.0,
 * GPL-2.0-only/GPL-2.0-or-later), one leaf carrying a WITH exception, and BUSL-1.1 — the only
 * pool member the shipped source-available defaults (builtinDenylist.ts) deny, so the
 * deny-election gate predicate below is actually exercised rather than vacuously undefined.
 */
const LEAF_POOL: ReadonlyArray<string> = [
  "MIT",
  "MIT-0",
  "CC-BY-4.0",
  "CC-BY-SA-4.0",
  "GPL-2.0-only",
  "GPL-2.0-or-later",
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BUSL-1.1",
];

/** Random AND/OR expression text, depth-bounded; duplicate leaves are deliberate, not avoided. */
function randomExpressionText(rng: Lcg, depth: number): string {
  if (depth <= 0 || rng.float() < 0.35) {
    return LEAF_POOL[rng.int(LEAF_POOL.length)]!;
  }

  const left = randomExpressionText(rng, depth - 1);
  const right = randomExpressionText(rng, depth - 1);
  const conjunction = rng.float() < 0.5 ? "AND" : "OR";

  return `(${left} ${conjunction} ${right})`;
}

/** Every distinct rendered leaf in a parsed tree, insertion-ordered and deduped. */
function collectLeaves(node: ExpressionNode, into: Set<string>): void {
  if ("license" in node) {
    into.add(renderNode(node));

    return;
  }

  collectLeaves(node.left, into);
  collectLeaves(node.right, into);
}

/** Evaluates a parsed tree against one leaf-to-truth assignment (an absent leaf reads false). */
function evaluateNode(node: ExpressionNode, assignment: ReadonlyMap<string, boolean>): boolean {
  if ("license" in node) {
    return assignment.get(renderNode(node)) ?? false;
  }

  const left = evaluateNode(node.left, assignment);
  const right = evaluateNode(node.right, assignment);

  return node.conjunction === "and" ? left && right : left || right;
}

/** The full truth table of a parsed tree over every 2^n assignment of `leaves` (fixed order). */
function truthTable(node: ExpressionNode, leaves: ReadonlyArray<string>): boolean[] {
  const rows: boolean[] = [];

  for (let mask = 0; mask < 2 ** leaves.length; mask++) {
    const assignment = new Map(leaves.map((leaf, i) => [leaf, (mask & (1 << i)) !== 0]));

    rows.push(evaluateNode(node, assignment));
  }

  return rows;
}

/**
 * Truth-table equality of two SPDX expression texts over the union of their leaves — bounded
 * ≤ 10 by construction (LEAF_POOL has 9 members; the hand fixtures below stay well under it too).
 */
function semanticallyEqual(a: string, b: string): boolean {
  const nodeA = p(a);
  const nodeB = p(b);
  const leaves = new Set<string>();

  collectLeaves(nodeA, leaves);
  collectLeaves(nodeB, leaves);

  const order = [...leaves];

  return JSON.stringify(truthTable(nodeA, order)) === JSON.stringify(truthTable(nodeB, order));
}

/**
 * The minimal real Policy relying only on the shipped BUSL/SSPL/Elastic defaults — an empty
 * `deny` means denyRuleFor here is the real deny-election predicate over BUILTIN_DENY_RULES, not
 * a stub with hand-authored rules.
 */
const DENY_ONLY_DEFAULTS_POLICY: Policy = {
  unknownHandling: "warn",
  devDependencies: "warn",
  osDependencies: "warn",
  suppressedWorkspaces: [],
  compatible: [],
  clarify: [],
  deny: [],
  allowSourceAvailable: [],
};

// Every hand fixture from the describe above, re-checked against the oracle: the noisy
// motivating example, both absorption directions, flatten-only, both idempotence shapes,
// no-distribution, the WITH-exception leaf, deep mixed nesting, and the single-leaf collapse.
const HAND_FIXTURES: ReadonlyArray<string> = [
  "(MIT AND OFL-1.1 AND CC-BY-4.0) AND (CC-BY-4.0 OR CC-BY-3.0) AND " +
    "(OFL-1.1 AND (CC-BY-4.0 AND OFL-1.1 AND MIT) AND MIT AND (MIT AND OFL-1.1 AND CC-BY-4.0))",
  "MIT AND (MIT OR Apache-2.0)",
  "MIT OR (MIT AND Apache-2.0)",
  "MIT AND (Apache-2.0 AND BSD-2-Clause)",
  "MIT AND MIT",
  "(MIT OR MIT)",
  "Apache-2.0 AND (MIT OR BSD-2-Clause)",
  "(GPL-2.0-only WITH Classpath-exception-2.0) AND (GPL-2.0-only WITH Classpath-exception-2.0)",
  "(MIT OR (MIT AND Apache-2.0)) AND (BSD-2-Clause OR BSD-2-Clause)",
  "Apache-2.0 AND (Apache-2.0 OR GPL-2.0-only)",
];

const RANDOM_CASE_COUNT = 3000;
const RANDOM_PAIR_COUNT = 1500;
const MAX_DEPTH = 5;

/**
 * RANDOM_CASE_COUNT deterministic expressions from the seeded LCG, generated once so every
 * property test below shares the identical corpus.
 */
const RANDOM_CASES: ReadonlyArray<string> = ((): ReadonlyArray<string> => {
  const rng = new Lcg(PROPERTY_SEED);

  return Array.from({ length: RANDOM_CASE_COUNT }, () => randomExpressionText(rng, MAX_DEPTH));
})();

describe("canonicalizeExpression — adversarial property suite (truth-table oracle)", () => {
  test(`truth-table oracle: every hand fixture (${HAND_FIXTURES.length}) canonicalizes to a semantically identical formula`, () => {
    for (const fixture of HAND_FIXTURES) {
      expect(semanticallyEqual(fixture, canonicalizeExpression(asRawLicense(fixture)))).toBe(true);
    }
  });

  test(`truth-table oracle: ${RANDOM_CASE_COUNT} seeded-random expressions canonicalize to a semantically identical formula`, () => {
    for (const original of RANDOM_CASES) {
      expect(semanticallyEqual(original, canonicalizeExpression(asRawLicense(original)))).toBe(
        true,
      );
    }
  });

  test("leaf containment: every canonical leaf already appeared in the original (absorption may drop, nothing may appear)", () => {
    for (const original of RANDOM_CASES) {
      const originalLeaves = new Set<string>();
      const canonicalLeaves = new Set<string>();

      collectLeaves(p(original), originalLeaves);
      collectLeaves(p(canonicalizeExpression(asRawLicense(original))), canonicalLeaves);

      for (const leaf of canonicalLeaves) {
        expect(originalLeaves.has(leaf)).toBe(true);
      }
    }
  });

  test("idempotence + round-trip parse hold on every seeded-random case", () => {
    for (const original of RANDOM_CASES) {
      assertRoundTripAndIdempotent(canonicalizeExpression(asRawLicense(original)));
    }
  });

  test("gate-predicate preservation: isCopyleft and the deny election agree on original vs. canonical", () => {
    for (const original of RANDOM_CASES) {
      const canonical = canonicalizeExpression(asRawLicense(original));

      expect(isCopyleft(p(canonical))).toBe(isCopyleft(p(original)));
      expect(denyRuleFor(DENY_ONLY_DEFAULTS_POLICY, canonical, "property-suite-pkg")).toEqual(
        denyRuleFor(DENY_ONLY_DEFAULTS_POLICY, original, "property-suite-pkg"),
      );
    }
  });

  test(`false-agreement kill-test: ${RANDOM_PAIR_COUNT} seeded-random pairs never canonical-equate two semantically different expressions`, () => {
    // The catastrophic direction only: canonical-equality must always imply semantic equality.
    // The converse — semantic equality implying canonical-equality — is never asserted here or
    // anywhere else; re-factoring noise (see the module doc boundary above) deliberately stays a
    // visible conflict rather than a silent agreement.
    const rng = new Lcg(PROPERTY_SEED ^ 0x5eed);
    let agreementsChecked = 0;

    for (let i = 0; i < RANDOM_PAIR_COUNT; i++) {
      const a = RANDOM_CASES[rng.int(RANDOM_CASES.length)]!;
      const b = RANDOM_CASES[rng.int(RANDOM_CASES.length)]!;

      if (canonicalizeExpression(asRawLicense(a)) === canonicalizeExpression(asRawLicense(b))) {
        agreementsChecked++;
        expect(semanticallyEqual(a, b)).toBe(true);
      }
    }

    // A sanity floor: the seeded pairs must exercise the agreement branch at least once, or the
    // kill-test above is vacuous.
    expect(agreementsChecked).toBeGreaterThan(0);
  });
});
