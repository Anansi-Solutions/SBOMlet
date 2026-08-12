import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import parse from "spdx-expression-parse";
import satisfies from "spdx-satisfies";

import { COPYLEFT_IDS } from "../src/policy/copyleft";
import {
  canonicalizeExpression,
  elect,
  isCopyleft,
  orLeaves,
  renderNode,
  type ExpressionNode,
} from "../src/normalize/expression";

// parse() output is structurally compatible with ExpressionNode (inline-union
// purity pattern: we never import the lib's internal types).
const p = (expr: string): ExpressionNode => parse(expr) as ExpressionNode;

describe("COPYLEFT_IDS membership", () => {
  test("contains current, deprecated, and family ids", () => {
    expect(COPYLEFT_IDS.has("AGPL-3.0-only")).toBe(true);
    expect(COPYLEFT_IDS.has("AGPL-3.0")).toBe(true); // deprecated form
    expect(COPYLEFT_IDS.has("GPL-2.0")).toBe(true); // deprecated form
    expect(COPYLEFT_IDS.has("MPL-2.0")).toBe(true);
    expect(COPYLEFT_IDS.has("SSPL-1.0")).toBe(true);
  });

  test("contains the CR-01 reciprocal families (CC-BY-SA, Sleepycat, CPAL, MS-RL, RPL, QPL, APSL, GFDL)", () => {
    // CC ShareAlike IS copyleft — the CC family demonstrably reaches this
    // tool's input (CC-BY-3.0/4.0 are in the live corpus below).
    expect(COPYLEFT_IDS.has("CC-BY-SA-4.0")).toBe(true);
    expect(COPYLEFT_IDS.has("CC-BY-SA-1.0")).toBe(true);
    expect(COPYLEFT_IDS.has("CC-BY-SA-3.0-DE")).toBe(true); // jurisdiction port
    expect(COPYLEFT_IDS.has("Sleepycat")).toBe(true);
    expect(COPYLEFT_IDS.has("CPAL-1.0")).toBe(true);
    expect(COPYLEFT_IDS.has("MS-RL")).toBe(true);
    expect(COPYLEFT_IDS.has("RPL-1.1")).toBe(true);
    expect(COPYLEFT_IDS.has("RPL-1.5")).toBe(true);
    expect(COPYLEFT_IDS.has("QPL-1.0")).toBe(true);
    expect(COPYLEFT_IDS.has("APSL-1.0")).toBe(true);
    expect(COPYLEFT_IDS.has("APSL-2.0")).toBe(true);
    expect(COPYLEFT_IDS.has("GFDL-1.3")).toBe(true); // deprecated base
    expect(COPYLEFT_IDS.has("GFDL-1.3-only")).toBe(true);
    expect(COPYLEFT_IDS.has("GFDL-1.3-or-later")).toBe(true);
    expect(COPYLEFT_IDS.has("GFDL-1.1-invariants-only")).toBe(true);
    // Plain CC attribution (no ShareAlike) is NOT copyleft.
    expect(COPYLEFT_IDS.has("CC-BY-4.0")).toBe(false);
    expect(COPYLEFT_IDS.has("CC-BY-3.0")).toBe(false);
    // Microsoft PUBLIC license (permissive sibling of MS-RL) stays out.
    expect(COPYLEFT_IDS.has("MS-PL")).toBe(false);
  });

  test("is the verbatim 94-id literal (54 from research + 40 CR-01 additions)", () => {
    expect(COPYLEFT_IDS.size).toBe(94);
  });

  test("every member is a real SPDX id — current or deprecated (typo-proof)", () => {
    // Validate the literal against the spdx-license-ids data shipped in
    // node_modules (the same data spdx-expression-parse matches against):
    // a typo'd id here would never match a parsed leaf and would silently
    // recreate the CR-01 default:ok gap.
    const dataDir = join(import.meta.dir, "..", "node_modules", "spdx-license-ids");
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
    expect(COPYLEFT_IDS.has("LGPLLR")).toBe(false);
    expect(COPYLEFT_IDS.has("NGPL")).toBe(false);
    expect(COPYLEFT_IDS.has("SMAIL-GPL")).toBe(false);
    expect(COPYLEFT_IDS.has("CNRI-Python-GPL-Compatible")).toBe(false);
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
    expect(orLeaves(p("(MIT OR Apache-2.0)"))).toEqual(["Apache-2.0", "MIT"]);
  });

  test("single leaf yields a one-element list", () => {
    expect(orLeaves(p("MIT"))).toEqual(["MIT"]);
  });

  test("WITH leaf is preserved as a unit", () => {
    expect(orLeaves(p("GPL-2.0-only WITH Classpath-exception-2.0"))).toEqual([
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
  expect(canonicalizeExpression(output)).toBe(output);
}

describe("canonicalizeExpression — conservative boolean-algebra simplification", () => {
  test("the maintainer's live noisy example reduces to its three-conjunct canonical form", () => {
    const noisy =
      "(MIT AND OFL-1.1 AND CC-BY-4.0) AND (CC-BY-4.0 OR CC-BY-3.0) AND " +
      "(OFL-1.1 AND (CC-BY-4.0 AND OFL-1.1 AND MIT) AND MIT AND (MIT AND OFL-1.1 AND CC-BY-4.0))";
    const canonical = canonicalizeExpression(noisy);

    expect(canonical).toBe("CC-BY-4.0 AND MIT AND OFL-1.1");
    assertRoundTripAndIdempotent(canonical);
  });

  test("ABSORPTION (AND-set absorbs an OR-sibling): A AND (A OR B) -> A", () => {
    const canonical = canonicalizeExpression("MIT AND (MIT OR Apache-2.0)");

    expect(canonical).toBe("MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("ABSORPTION (OR-set absorbs an AND-sibling): A OR (A AND B) -> A", () => {
    const canonical = canonicalizeExpression("MIT OR (MIT AND Apache-2.0)");

    expect(canonical).toBe("MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("FLATTEN only: same-operator nesting collapses before sorting", () => {
    const canonical = canonicalizeExpression("MIT AND (Apache-2.0 AND BSD-2-Clause)");

    expect(canonical).toBe("Apache-2.0 AND BSD-2-Clause AND MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("IDEMPOTENCE only: a duplicate AND conjunct dedupes", () => {
    expect(canonicalizeExpression("MIT AND MIT")).toBe("MIT");
  });

  test("(MIT OR MIT) dedupes to MIT", () => {
    expect(canonicalizeExpression("(MIT OR MIT)")).toBe("MIT");
  });

  test("A AND (B OR C) is UNCHANGED except child-sort — no distribution", () => {
    const canonical = canonicalizeExpression("Apache-2.0 AND (MIT OR BSD-2-Clause)");

    // No distribution into (Apache-2.0 AND MIT) OR (Apache-2.0 AND BSD-2-Clause) —
    // the OR branch stays intact; only its own two children get reordered.
    expect(canonical).toBe("Apache-2.0 AND (BSD-2-Clause OR MIT)");
    assertRoundTripAndIdempotent(canonical);
  });

  test("a WITH-exception leaf is never decomposed, even duplicated across a compound", () => {
    const canonical = canonicalizeExpression(
      "(GPL-2.0-only WITH Classpath-exception-2.0) AND (GPL-2.0-only WITH Classpath-exception-2.0)",
    );

    expect(canonical).toBe("GPL-2.0-only WITH Classpath-exception-2.0");
    assertRoundTripAndIdempotent(canonical);
  });

  test("deep mixed nesting: both absorption directions fire inside a shared AND", () => {
    const canonical = canonicalizeExpression(
      "(MIT OR (MIT AND Apache-2.0)) AND (BSD-2-Clause OR BSD-2-Clause)",
    );

    expect(canonical).toBe("BSD-2-Clause AND MIT");
    assertRoundTripAndIdempotent(canonical);
  });

  test("a single-leaf result serializes bare — no residual parens", () => {
    const canonical = canonicalizeExpression("Apache-2.0 AND (Apache-2.0 OR GPL-2.0-only)");

    expect(canonical).toBe("Apache-2.0");
    assertRoundTripAndIdempotent(canonical);
  });

  test("unparseable input passes through UNCHANGED — never throws, never guesses", () => {
    const garbage = "Not a real (((expression";

    expect(canonicalizeExpression(garbage)).toBe(garbage);
    expect(canonicalizeExpression("MIT AND")).toBe("MIT AND");
  });
});
