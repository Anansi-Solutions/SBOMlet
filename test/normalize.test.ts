import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import parse from "spdx-expression-parse";
import satisfies from "spdx-satisfies";

import { COPYLEFT_IDS } from "../src/policy/copyleft";
import {
  elect,
  isCopyleft,
  orLeaves,
  renderNode,
  type ExpressionNode,
} from "../src/normalize/expression";
import {
  annotateFindings,
  applyScancodeAssessment,
  normalizeRaw,
  type ClarifyInput,
  type BuiltinOverrideInput,
} from "../src/normalize/normalize";
import { BUILTIN_OVERRIDES } from "../src/policy/builtinOverrides";
import type {
  CanonicalDependencies,
  LicenseClaim,
  LicenseClaimKind,
  LicenseFinding,
  PackageEntry,
} from "../src/model/dependencies";

// parse() output is structurally compatible with ExpressionNode (inline-union
// purity pattern: we never import the lib's internal types).
const p = (expr: string): ExpressionNode => parse(expr) as ExpressionNode;

describe("COPYLEFT_IDS membership", () => {
  test("contains current, deprecated, and family ids", () => {
    expect(COPYLEFT_IDS.has("AGPL-3.0-only")).toBe(true);
    expect(COPYLEFT_IDS.has("AGPL-3.0")).toBe(true); // deprecated form (Pitfall 5)
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
    const typos = [...COPYLEFT_IDS].filter((id) => !known.has(id));
    expect(typos).toEqual([]);
  });

  test("GPL-2.0+ leaf is copyleft via base-id membership (Pitfall 5)", () => {
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
    expect(isCopyleft(p("GPL-2.0-only WITH Classpath-exception-2.0"))).toBe(
      true,
    );
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
    expect(renderNode(elect(p("(LicenseRef-internal-foo OR MIT)")))).toBe(
      "MIT",
    );
  });

  test("AND composes elected sub-expressions (rule 1)", () => {
    expect(renderNode(elect(p("(MIT OR GPL-2.0-only) AND Apache-2.0")))).toBe(
      "MIT AND Apache-2.0",
    );
  });

  test("(MPL-2.0 OR Apache-2.0) elects Apache-2.0 and avoids copyleft", () => {
    const elected = elect(p("(MPL-2.0 OR Apache-2.0)"));
    expect(renderNode(elected)).toBe("Apache-2.0");
    expect(isCopyleft(elected)).toBe(false);
  });

  test("WITH leaves are elected as a unit — exception never stripped (rule 3)", () => {
    expect(
      renderNode(elect(p("GPL-2.0-only WITH Classpath-exception-2.0"))),
    ).toBe("GPL-2.0-only WITH Classpath-exception-2.0");
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
    expect(() =>
      satisfies("MIT AND Apache-2.0", ["MIT AND Apache-2.0"]),
    ).toThrow();
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
// normalizeRaw + annotateFindings (Task 3)
// ---------------------------------------------------------------------------

const claim = (
  raw: string,
  kind: LicenseClaimKind = "spdx-id",
): LicenseClaim => ({ raw, kind, source: "generator" });

const pkg = (
  name: string,
  version: string,
  claims: LicenseClaim[],
): PackageEntry => ({
  purl: `pkg:npm/${name}@${version}`,
  name,
  version,
  occurrences: [{ target: "frontend", isDevDependency: false }],
  licenseClaims: claims,
  scope: "app",
});

/** OS-scope variant of {@link pkg} (a pkg:deb row): scope "os", os target. */
const osPkg = (
  name: string,
  version: string,
  claims: LicenseClaim[],
): PackageEntry => ({
  purl: `pkg:deb/debian/${name}@${version}`,
  name,
  version,
  occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
  licenseClaims: claims,
  scope: "os",
});

const modelOf = (...entries: PackageEntry[]): CanonicalDependencies => ({
  packages: entries,
});

type CorpusClass = "exact" | "corrected" | "none" | "imprecise";

// The full 33-row live corpus from 03-RESEARCH (3616 packages, 2026-06-11):
// every distinct (kind, raw) value the real repo produces, with the expected
// Normalized column. [raw, kind, expectedExpression, class]
const CORPUS: ReadonlyArray<
  [
    raw: string,
    kind: LicenseClaimKind,
    expected: string | null,
    klass: CorpusClass,
  ]
> = [
  ["MIT", "spdx-id", "MIT", "exact"],
  ["Apache-2.0", "spdx-id", "Apache-2.0", "exact"],
  ["ISC", "spdx-id", "ISC", "exact"],
  ["BSD-3-Clause", "spdx-id", "BSD-3-Clause", "exact"],
  ["MIT-0", "spdx-id", "MIT-0", "exact"],
  ["BSD-2-Clause", "spdx-id", "BSD-2-Clause", "exact"],
  ["FSL-1.1-MIT", "spdx-id", "FSL-1.1-MIT", "exact"],
  ["BlueOak-1.0.0", "spdx-id", "BlueOak-1.0.0", "exact"],
  ["LGPL-3.0-or-later", "spdx-id", "LGPL-3.0-or-later", "exact"],
  ["AGPL-3.0-only", "spdx-id", "AGPL-3.0-only", "exact"],
  ["(MIT OR CC0-1.0)", "expression", "(MIT OR CC0-1.0)", "exact"],
  ["CC-BY-4.0", "spdx-id", "CC-BY-4.0", "exact"],
  // INV-04 (05-05): the bare family label "BSD" is no longer guessed to
  // BSD-2-Clause (the conscious change documented in the plan). It is
  // present-but-imprecise: expression null, confidence "imprecise". The 23
  // Jupyter BSD rows ride this change; 05-06's tool-level override will later
  // disambiguate them to BSD-3-Clause.
  ["BSD", "name", null, "imprecise"],
  ["CC0-1.0", "spdx-id", "CC0-1.0", "exact"],
  [
    "Apache-2.0 AND LGPL-3.0-or-later",
    "expression",
    "Apache-2.0 AND LGPL-3.0-or-later",
    "exact",
  ],
  ["Unlicense", "spdx-id", "Unlicense", "exact"],
  ["0BSD", "spdx-id", "0BSD", "exact"],
  ["(CC-BY-4.0 AND MIT)", "expression", "(CC-BY-4.0 AND MIT)", "exact"],
  ["(MIT OR Apache-2.0)", "expression", "(MIT OR Apache-2.0)", "exact"],
  ["MPL-2.0", "spdx-id", "MPL-2.0", "exact"],
  ["(MPL-2.0 OR Apache-2.0)", "expression", "(MPL-2.0 OR Apache-2.0)", "exact"],
  [
    "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
    "expression",
    "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
    "exact",
  ],
  ["BSD-3-Clause OR MIT", "expression", "BSD-3-Clause OR MIT", "exact"],
  ["Python-2.0", "spdx-id", "Python-2.0", "exact"],
  ["Apache License, Version 2.0", "name", "Apache-2.0", "corrected"],
  [
    "(AFL-2.1 OR BSD-3-Clause)",
    "expression",
    "(AFL-2.1 OR BSD-3-Clause)",
    "exact",
  ],
  ["Public Domain", "name", null, "none"],
  [
    "(MIT OR GPL-3.0-or-later)",
    "expression",
    "(MIT OR GPL-3.0-or-later)",
    "exact",
  ],
  ["(WTFPL OR MIT)", "expression", "(WTFPL OR MIT)", "exact"],
  ["(MIT AND Zlib)", "expression", "(MIT AND Zlib)", "exact"],
  [
    "(BSD-2-Clause OR MIT OR Apache-2.0)",
    "expression",
    "(BSD-2-Clause OR MIT OR Apache-2.0)",
    "exact",
  ],
  ["CC-BY-3.0", "spdx-id", "CC-BY-3.0", "exact"],
  [
    "(Unlicense OR Apache-2.0)",
    "expression",
    "(Unlicense OR Apache-2.0)",
    "exact",
  ],
];

describe("normalizeRaw — live 33-value corpus", () => {
  test("corpus covers all 33 distinct live (kind, raw) values", () => {
    expect(CORPUS.length).toBe(33);
    expect(new Set(CORPUS.map(([raw, kind]) => `${kind}\0${raw}`)).size).toBe(
      33,
    );
  });

  for (const [raw, , expected, klass] of CORPUS) {
    test(`"${raw}" → ${expected === null ? "unknown" : `"${expected}"`}`, () => {
      const result = normalizeRaw(raw);
      expect(result.expression).toBe(expected);
      expect(result.source).toBe(
        klass === "corrected" ? "corrected" : "generator",
      );
    });
  }

  test("findings over the corpus carry the expected confidence", () => {
    const entries = CORPUS.map(([raw, kind], i) =>
      pkg(`corpus-${i}`, "1.0.0", [claim(raw, kind)]),
    );
    const { model } = annotateFindings(modelOf(...entries), []);
    for (const [i, [raw, , expected, klass]] of CORPUS.entries()) {
      const finding = model.packages[i]!.finding;
      expect(finding).toBeDefined();
      expect(finding!.expression).toBe(expected);
      expect(finding!.confidence).toBe(klass);
      if (expected === null) {
        expect(finding!.elected).toBeNull();
      } else {
        expect(finding!.elected).not.toBeNull();
      }
      void raw;
    }
  });
});

// ---------------------------------------------------------------------------
// 17-04: the six real-world free-text Maven license raws from research §4 —
// verified byte-for-byte against the real public repo1.maven.org POMs this
// session (mysql-connector-j 9.5.0, jasperreports/-fonts 6.21.0, jcommon/
// jfreechart 1.0.23/1.0.19, juniversalchardet 2.5.0 — P-08, the one
// sanctioned use of real GAVs). Each raw's ACTUAL normalizeRaw outcome is
// locked as a decided fact, whatever it is — some are GUESS-SHAPED surprises
// (a version-specific id from an unversioned label, or a wrong SPDX family
// entirely) that this task does NOT soften or fix; they are flagged in
// AFK-CHECKLIST.md and handed to the 17-06 adversarial review lens list.
// ---------------------------------------------------------------------------
describe("normalizeRaw — six real-world Maven free-text raws (17-RESEARCH §4, locked)", () => {
  test("mysql-connector-j's FOSS-exception GPLv2 label GUESSES to GPL-3.0-or-later — a confidently WRONG major-version+scope id (flagged, not fixed here)", () => {
    const result = normalizeRaw(
      "The GNU General Public License, v2 with Universal FOSS Exception, v1.0",
    );
    // LOCKED as-observed: correct()'s fuzzy matcher resolves this to
    // GPL-3.0-or-later, silently dropping BOTH the v2 pin and the FOSS
    // exception clause. The real license is GPL-2 plus a MySQL-specific
    // exception, never GPL-3-or-later — a guess-shaped surprise (17-06).
    expect(result).toEqual({
      expression: "GPL-3.0-or-later",
      source: "corrected",
    });
  });

  test('bare "GNU Lesser General Public License" (jasperreports, jasperreports-fonts) is NOT in AMBIGUOUS_FAMILY and GUESSES to a specific version id, LGPL-2.1-only', () => {
    const result = normalizeRaw("GNU Lesser General Public License");
    // LOCKED as-observed: the AMBIGUOUS_FAMILY intercept only keys on the
    // short "lgpl"/"lgpl license" tokens, not this full-text label, so it
    // falls through to correct()'s fuzzy match — a version-specific guess
    // from an unversioned source label (the plan's own flagged example).
    expect(result).toEqual({
      expression: "LGPL-2.1-only",
      source: "corrected",
    });
  });

  test('the British-spelling "GNU Lesser General Public Licence" (jcommon, jfreechart) GUESSES to GPL-3.0-or-later, dropping "Lesser" entirely', () => {
    const result = normalizeRaw("GNU Lesser General Public Licence");
    // LOCKED as-observed: the spelling variant sends correct()'s fuzzy
    // matcher to the GPL family instead of LGPL — a severe misclassification
    // (a weak-copyleft label resolving to a strong-copyleft id), flagged.
    expect(result).toEqual({
      expression: "GPL-3.0-or-later",
      source: "corrected",
    });
  });

  test('juniversalchardet\'s "Mozilla Public License Version 1.1" resolves PRECISELY to MPL-1.1', () => {
    const result = normalizeRaw("Mozilla Public License Version 1.1");
    expect(result).toEqual({ expression: "MPL-1.1", source: "corrected" });
  });

  test('juniversalchardet\'s "GENERAL PUBLIC LICENSE, version 3 (GPL-3.0)" resolves to GPL-3.0-or-later (the bare-GPL correct() convention)', () => {
    const result = normalizeRaw("GENERAL PUBLIC LICENSE, version 3 (GPL-3.0)");
    expect(result).toEqual({
      expression: "GPL-3.0-or-later",
      source: "corrected",
    });
  });

  test('juniversalchardet\'s PARALLEL "GNU LESSER GENERAL PUBLIC LICENSE, version 3 (LGPL-3.0)" stays an honest UNKNOWN — an asymmetry with its GPL sibling above, locked as-observed', () => {
    const result = normalizeRaw(
      "GNU LESSER GENERAL PUBLIC LICENSE, version 3 (LGPL-3.0)",
    );
    // LOCKED: despite the identical structure and an explicit "(LGPL-3.0)"
    // hint, correct() fails to resolve this one while its GPL sibling (same
    // POM, same author, same wording pattern) DOES resolve — an inconsistent
    // guess/no-guess split, flagged to 17-06.
    expect(result.expression).toBeNull();
    expect(result.source).toBe("generator");
  });

  test("the juniversalchardet triple claim: each of the three raws normalizes SEPARATELY, and the genuinely-unknown LGPL member collapses the WHOLE app-scope finding to unknown (app-scope all-or-nothing, INV-04's conservative posture)", () => {
    const claims: LicenseClaim[] = [
      claim("Mozilla Public License Version 1.1", "name"),
      claim("GENERAL PUBLIC LICENSE, version 3 (GPL-3.0)", "name"),
      claim("GNU LESSER GENERAL PUBLIC LICENSE, version 3 (LGPL-3.0)", "name"),
    ];
    // Each claim's OWN normalizeRaw outcome is exactly the three locks above
    // — never joined, never guessed at the claim level.
    const perClaim = claims.map((c) => normalizeRaw(c.raw).expression);
    expect(perClaim).toEqual(["MPL-1.1", "GPL-3.0-or-later", null]);

    const { model } = annotateFindings(
      modelOf(pkg("juniversalchardet", "2.5.0", claims)),
      [],
    );
    const finding = model.packages[0]!.finding;
    // LOCKED: two of three sub-licenses resolve, but the third's genuine
    // unknown forces the combined app-scope finding to unknown — partial
    // knowledge never hides a potential obligation (findingFromClaims).
    expect(finding).toEqual({
      expression: null,
      elected: null,
      source: "generator",
      confidence: "none",
      observedExpressions: ["GPL-3.0-or-later", "MPL-1.1"],
    });
  });
});

describe("normalizeRaw — guards", () => {
  test("UNLICENSED is unknown and NEVER Unlicense", () => {
    const result = normalizeRaw("UNLICENSED");
    expect(result.expression).toBeNull();
    expect(result.expression).not.toBe("Unlicense");
  });

  test("SEE LICENSE IN … is unknown (never corrected)", () => {
    expect(normalizeRaw("SEE LICENSE IN LICENSE.md").expression).toBeNull();
  });

  test("empty and whitespace input degrade to unknown without throwing", () => {
    expect(normalizeRaw("").expression).toBeNull();
    expect(normalizeRaw("   ").expression).toBeNull();
  });

  test("comma lists are not correctable — correct() would drop MIT", () => {
    expect(normalizeRaw("MIT,Apache-2.0").expression).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INV-04: imprecise family labels (05-05). An ambiguous family label is
// represented faithfully as the imprecise family — never guessed to a precise
// SPDX id and never silently dropped to unknown.
// ---------------------------------------------------------------------------

describe("normalizeRaw — imprecise family labels (INV-04)", () => {
  test('"BSD" is imprecise family "BSD" — never the BSD-2-Clause guess', () => {
    const result = normalizeRaw("BSD");
    expect(result.expression).toBeNull();
    expect(result.expression).not.toBe("BSD-2-Clause");
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("BSD");
  });

  test('"BSD License" is imprecise family "BSD" — never BSD-2-Clause, never null-unknown', () => {
    const result = normalizeRaw("BSD License");
    expect(result.expression).toBeNull();
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("BSD");
  });

  test('"Apache Software License" (no version) is imprecise family "Apache", not a guessed Apache-2.0', () => {
    const result = normalizeRaw("Apache Software License");
    expect(result.expression).toBeNull();
    expect(result.expression).not.toBe("Apache-2.0");
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("Apache");
  });

  test('bare "Apache" (no version) is imprecise family "Apache"', () => {
    const result = normalizeRaw("Apache");
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("Apache");
  });

  test('a precise corrected value is NOT imprecise — "Apache License, Version 2.0" still corrects to Apache-2.0', () => {
    const result = normalizeRaw("Apache License, Version 2.0");
    expect(result.expression).toBe("Apache-2.0");
    expect(result.source).toBe("corrected");
    expect(result.imprecise).toBeUndefined();
    expect(result.impreciseFamily).toBeUndefined();
  });

  test("an exact id stays exact and never imprecise (MIT, Apache-2.0, BSD-2-Clause)", () => {
    for (const id of ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]) {
      const result = normalizeRaw(id);
      expect(result.expression).toBe(id);
      expect(result.imprecise).toBeUndefined();
    }
  });

  test("imprecise is distinct from unknown — garbage stays unknown (no impreciseFamily)", () => {
    for (const garbage of ["", "   ", "total garbage xyz", "MIT,Apache-2.0"]) {
      const result = normalizeRaw(garbage);
      expect(result.expression).toBeNull();
      expect(result.imprecise).toBeUndefined();
      expect(result.impreciseFamily).toBeUndefined();
    }
  });

  // W1 (corrections): a bare copyleft family that spdx-correct cross-maps to a
  // PERMISSIVE id ("EUPL" → UPL-1.0) must be intercepted as the imprecise
  // copyleft family, never silently rewritten to a permissive (non-copyleft) id.
  test('"EUPL" is imprecise family "EUPL" — never the permissive UPL-1.0 guess', () => {
    const result = normalizeRaw("EUPL");
    expect(result.expression).toBeNull();
    expect(result.expression).not.toBe("UPL-1.0");
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("EUPL");
  });

  test('"EUPL License" is also intercepted as imprecise family "EUPL"', () => {
    const result = normalizeRaw("EUPL License");
    expect(result.expression).toBeNull();
    expect(result.imprecise).toBe(true);
    expect(result.impreciseFamily).toBe("EUPL");
  });

  test('a precise "EUPL-1.2" is NOT imprecise — stays the exact copyleft id', () => {
    const result = normalizeRaw("EUPL-1.2");
    expect(result.expression).toBe("EUPL-1.2");
    expect(result.imprecise).toBeUndefined();
  });

  test("weak-copyleft families correct() KEEPS copyleft stay on the precise path (MPL/CDDL)", () => {
    expect(normalizeRaw("MPL").expression).toBe("MPL-2.0");
    expect(normalizeRaw("MPL").imprecise).toBeUndefined();
    expect(normalizeRaw("CDDL").expression).toBe("CDDL-1.1");
    expect(normalizeRaw("CDDL").imprecise).toBeUndefined();
  });
});

describe("normalizeRaw — ISC-license suffix fix (INV-04)", () => {
  test('"ISC license" resolves to ISC (the suffix false-negative)', () => {
    expect(normalizeRaw("ISC license").expression).toBe("ISC");
  });

  test('"ISC License" (capitalized) also resolves to ISC', () => {
    expect(normalizeRaw("ISC License").expression).toBe("ISC");
  });

  test('bare "ISC" still resolves to ISC', () => {
    expect(normalizeRaw("ISC").expression).toBe("ISC");
  });
});

describe("annotateFindings — imprecise findings (INV-04)", () => {
  test("a single imprecise claim yields confidence imprecise + impreciseFamily, expression null", () => {
    const entry = pkg("jinja2-ish", "1.0.0", [claim("BSD License", "name")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.expression).toBeNull();
    expect(finding.elected).toBeNull();
  });

  test("an imprecise finding is distinct from an unknown finding", () => {
    const impreciseEntry = pkg("imp", "1.0.0", [claim("BSD", "name")]);
    const unknownEntry = pkg("unk", "1.0.0", [claim("Public Domain", "name")]);
    const { model } = annotateFindings(
      modelOf(impreciseEntry, unknownEntry),
      [],
    );
    expect(model.packages[0]!.finding!.confidence).toBe("imprecise");
    expect(model.packages[0]!.finding!.impreciseFamily).toBe("BSD");
    expect(model.packages[1]!.finding!.confidence).toBe("none");
    expect(model.packages[1]!.finding!.impreciseFamily).toBeUndefined();
  });

  test("one precise + one imprecise claim degrades conservatively (never AND-ed into a fake expression)", () => {
    const entry = pkg("mixed", "1.0.0", [
      claim("MIT"),
      claim("BSD License", "name"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    // Conservative: the combined finding is at most as confident as its
    // weakest claim — imprecise, never "MIT AND BSD-2-Clause".
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
  });

  test("a clarify override on an imprecise package wins (precise expression, source override)", () => {
    const entry = pkg("jupyter-thing", "1.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jupyter-thing", expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.confidence).toBe("exact");
    expect(finding.impreciseFamily).toBeUndefined();
  });
});

describe("annotateFindings — claim combination (Pitfalls 7-8)", () => {
  test("duplicate identical claims collapse — never MIT AND MIT (Pitfall 7)", () => {
    // buffer-crc32@0.2.13 live shape: two identical claims in one component.
    const entry = pkg("buffer-crc32", "0.2.13", [claim("MIT"), claim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);
    expect(model.packages[0]!.finding!.expression).toBe("MIT");
  });

  test("distinct claims AND-combine conservatively and re-parse (Pitfall 8/A1)", () => {
    const entry = pkg("two-claims", "1.0.0", [
      claim("MIT"),
      claim("Apache-2.0"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const expression = model.packages[0]!.finding!.expression;
    expect(expression).toBe("MIT AND Apache-2.0");
    expect(() => parse(expression!)).not.toThrow();
  });

  test("one normalizable + one garbage claim → whole finding unknown", () => {
    // Partial knowledge must not hide an obligation.
    const entry = pkg("mixed", "1.0.0", [
      claim("MIT"),
      claim("total garbage xyz", "name"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBeNull();
    expect(finding.elected).toBeNull();
    expect(finding.confidence).toBe("none");
  });
});

// ===========================================================================
// C2 + W2 (corrections): a copyleft signal — precise OR imprecise — must
// DOMINATE a permissive sibling in findingFromClaims. The old "first imprecise
// wins" short-circuit let an imprecise-permissive label discard a precise
// copyleft id (C2) and let claim order between two imprecise families decide the
// lane (W2). One corrected combine rule closes both.
// ===========================================================================

describe("findingFromClaims — copyleft dominates a permissive sibling (C2/W2)", () => {
  test("C2: imprecise Apache + precise AGPL-3.0-only → AGPL preserved (copyleft, not imprecise)", () => {
    const entry = pkg("mixed", "1.0.0", [
      claim("Apache", "name"),
      claim("AGPL-3.0-only", "spdx-id"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    // The precise copyleft must survive — not be discarded by the imprecise
    // short-circuit and downgraded to a non-gating warn.
    expect(finding.expression).toBe("AGPL-3.0-only");
    expect(finding.confidence).not.toBe("imprecise");
  });

  test("C2: imprecise BSD + precise GPL-3.0-only → GPL preserved (copyleft)", () => {
    const entry = pkg("mixed", "1.0.0", [
      claim("BSD", "name"),
      claim("GPL-3.0-only", "spdx-id"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.confidence).not.toBe("imprecise");
  });

  test("W2: two imprecise families, copyleft wins regardless of order — [BSD, GPL]", () => {
    const entry = pkg("two-imprecise", "1.0.0", [
      claim("BSD License", "name"),
      claim("GPL", "name"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
  });

  test("W2: two imprecise families, copyleft wins regardless of order — [GPL, BSD] (order-flipped)", () => {
    const entry = pkg("two-imprecise", "1.0.0", [
      claim("GPL", "name"),
      claim("BSD License", "name"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
  });

  test("regression: precise permissive + imprecise permissive still degrades to imprecise (line 449 intact)", () => {
    const entry = pkg("mixed", "1.0.0", [
      claim("MIT"),
      claim("BSD License", "name"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
  });
});

describe("annotateFindings — coverage, immutability, election", () => {
  test("every package gets a finding, including zero-claim packages", () => {
    const entry = pkg("no-claims", "1.0.0", []);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding;
    expect(finding).toBeDefined();
    expect(finding!.expression).toBeNull();
    expect(finding!.confidence).toBe("none");
  });

  test("input model is never mutated — entries are cloned", () => {
    const entry = pkg("immutable", "1.0.0", [claim("MIT")]);
    const input = modelOf(entry);
    const { model } = annotateFindings(input, []);
    expect("finding" in entry).toBe(false);
    expect(model.packages[0]).not.toBe(entry);
    expect(model.packages[0]!.finding).toBeDefined();
  });

  test("elected branch is recorded — raw expression preserved", () => {
    const entry = pkg("dompurify", "3.1.6", [
      claim("(MPL-2.0 OR Apache-2.0)", "expression"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("(MPL-2.0 OR Apache-2.0)");
    expect(finding.elected).toBe("Apache-2.0");
  });
});

describe("annotateFindings — clarify overrides", () => {
  test("matching name+version replaces the finding with source override", () => {
    const entry = pkg("@img/sharp-win32-x64", "0.34.5", [
      claim("Apache-2.0 AND LGPL-3.0-or-later", "expression"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "@img/sharp-win32-x64",
        version: "0.34.5",
        expression: "Apache-2.0",
      },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(entry),
      clarify,
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.confidence).toBe("exact");
    expect(finding.expression).toBe("Apache-2.0");
    expect(finding.elected).toBe("Apache-2.0");
    expect(usedClarifyIndices.has(0)).toBe(true);
  });

  test("non-matching version does not override", () => {
    const entry = pkg("@img/sharp-win32-x64", "0.34.5", [
      claim("Apache-2.0 AND LGPL-3.0-or-later", "expression"),
    ]);
    const clarify: ClarifyInput[] = [
      { name: "@img/sharp-win32-x64", version: "9.9.9", expression: "MIT" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(entry),
      clarify,
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("generator");
    expect(finding.expression).toBe("Apache-2.0 AND LGPL-3.0-or-later");
    expect(usedClarifyIndices.size).toBe(0);
  });

  test("version-less clarify matches any version of the named package", () => {
    const entry = pkg("jsonify", "0.0.1", [claim("Public Domain", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jsonify", expression: "Unlicense" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(entry),
      clarify,
    );
    expect(model.packages[0]!.finding!.expression).toBe("Unlicense");
    expect(model.packages[0]!.finding!.source).toBe("override");
    expect(usedClarifyIndices.has(0)).toBe(true);
  });
});

// ===========================================================================
// Staleness-guarded two-level override chain in annotateFindings.
// ===========================================================================

describe("annotateFindings — staleness-guarded clarify", () => {
  test("expects matching the imprecise-BSD signal APPLIES the disambiguation", () => {
    const entry = pkg("jupyter-thing", "1.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jupyter-thing", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(entry),
      clarify,
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
    expect(usedClarifyIndices.has(0)).toBe(true);
  });

  test("expects matching a raw claim string APPLIES (raw-string signal member)", () => {
    const entry = pkg("dateutil-ish", "1.0.0", [claim("Dual License", "name")]);
    const clarify: ClarifyInput[] = [
      {
        name: "dateutil-ish",
        expects: "Dual License",
        expression: "Apache-2.0 OR BSD-3-Clause",
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("Apache-2.0 OR BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });

  test("STALE: expects BSD but the package now reports GPL-3.0 → not applied, staleOverride recorded", () => {
    const entry = pkg("relicensed", "2.0.0", [claim("GPL-3.0-only")]);
    const clarify: ClarifyInput[] = [
      { name: "relicensed", expects: "BSD", expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    // The stale BSD-3-Clause assertion is NOT applied — the real finding stands.
    expect(finding.source).not.toBe("override");
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("clarify");
    expect(finding.staleOverride!.expected).toBe("BSD");
    expect(finding.staleOverride!.observed).toContain("GPL-3.0-only");
  });

  test("expects is matched case-insensitively and trimmed", () => {
    const entry = pkg("ci-pkg", "1.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "ci-pkg", expects: "  bsd  ", expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    expect(model.packages[0]!.finding!.expression).toBe("BSD-3-Clause");
  });

  test("no-expects clarify still applies blindly (backward-compat)", () => {
    const entry = pkg("jsonify", "0.0.1", [claim("Public Domain", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jsonify", expression: "Unlicense" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("Unlicense");
    expect(finding.staleOverride).toBeUndefined();
  });
});

describe("annotateFindings — tool-level BUILTIN overrides", () => {
  const jupyterBuiltin: BuiltinOverrideInput[] = [
    { name: "ipython", expects: "BSD", expression: "BSD-3-Clause" },
  ];

  test("a tool-level override applies when no project clarify matches and is cited override:builtin[i]", () => {
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name")]);
    const { model } = annotateFindings(modelOf(entry), [], jupyterBuiltin);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.overrideRule).toBe("override:builtin[0]");
  });

  test("tool-level override is version-agnostic (survives version bumps)", () => {
    const v1 = pkg("ipython", "7.0.0", [claim("BSD", "name")]);
    const v2 = pkg("ipython", "8.31.0", [claim("BSD", "name")]);
    const { model } = annotateFindings(modelOf(v1, v2), [], jupyterBuiltin);
    expect(model.packages[0]!.finding!.expression).toBe("BSD-3-Clause");
    expect(model.packages[1]!.finding!.expression).toBe("BSD-3-Clause");
  });

  test("project clarify WINS over a tool-level override on conflict (project-wins)", () => {
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "ipython", expects: "BSD", expression: "MIT" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      modelOf(entry),
      clarify,
      jupyterBuiltin,
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.overrideRule).toBeUndefined(); // project clarify, not builtin
    expect(usedClarifyIndices.has(0)).toBe(true);
  });

  test("STALE tool-level override → not applied, staleOverride level builtin", () => {
    const entry = pkg("ipython", "8.0.0", [claim("GPL-3.0-only")]);
    const { model } = annotateFindings(modelOf(entry), [], jupyterBuiltin);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.staleOverride!.level).toBe("builtin");
    expect(finding.staleOverride!.expected).toBe("BSD");
  });

  test("the chain performs no I/O and never throws on a stale override", () => {
    const entry = pkg("ipython", "8.0.0", [claim("GPL-3.0-only")]);
    expect(() =>
      annotateFindings(modelOf(entry), [], jupyterBuiltin),
    ).not.toThrow();
  });
});

// ===========================================================================
// C1 (corrections): the staleness guard must FAIL CLOSED when an obsolete
// signal member (matching `expects`) coexists with a NEW precise claim that
// contradicts the asserted expression. A lingering label must never license-out
// a co-present precise copyleft claim. The any-member `.some()` match on
// `expects` alone is fail-OPEN.
// ===========================================================================

describe("annotateFindings — staleness fails CLOSED on a contradicting co-claim (C1)", () => {
  test("stale BSD label + new precise GPL claim → fail closed, NOT applied (shipped ipython builtin)", () => {
    // The canonical relicense-metadata-lag case: PyPI still carries the old
    // "BSD" classifier while a new precise "GPL-3.0-only" id has appeared. The
    // shipped ipython BUILTIN_OVERRIDES entry must NOT mask the GPL.
    const entry = pkg("ipython", "8.0.0", [
      claim("BSD", "name"),
      claim("GPL-3.0-only", "spdx-id"),
    ]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("builtin");
    expect(finding.staleOverride!.expected.toLowerCase()).toBe("bsd");
  });

  test("clean case: BSD alone still applies BSD-3-Clause (shipped ipython builtin)", () => {
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name")]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });

  test("GPL alone (no lingering BSD) still fails closed (control)", () => {
    const entry = pkg("ipython", "8.0.0", [claim("GPL-3.0-only", "spdx-id")]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("builtin");
  });

  test("stale BSD label + a co-present permissive MIT claim still APPLIES (no copyleft contradiction)", () => {
    // A co-present PERMISSIVE precise claim that the asserted BSD-3-Clause does
    // not literally satisfy must not block the disambiguation when there is no
    // contradicting copyleft — the guard fails closed only on a precise member
    // that the asserted expression cannot account for as copyleft.
    const entry = pkg("ipython", "8.0.0", [
      claim("BSD", "name"),
      claim("BSD-3-Clause", "spdx-id"),
    ]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
  });
});

// ===========================================================================
// GAP FIX: when the registry UPGRADES the imprecise label
// to the EXACT precise license the override asserts, the override is REDUNDANT
// — NOT stale. expects "BSD" is no longer present in the signal (the dep now
// reports precise "BSD-3-Clause"), but the observed precise finding already
// SATISFIES the asserted expression, so nothing is masked: the observed finding
// must stand unchanged and the gate must NOT fail. A relicense to a license that
// does NOT satisfy the assertion still fails closed.
// ===========================================================================

describe("annotateFindings — redundant override when metadata catches up (gap fix)", () => {
  test("REDUNDANT: precise BSD-3-Clause observed, expects BSD asserts BSD-3-Clause → finding stays, NOT stale (live ipython false-positive)", () => {
    // The exact live case: modern PyPI reports ipython with the PRECISE
    // license_expression "BSD-3-Clause" — no bare "BSD" classifier — so the
    // shipped "expects: BSD" override no longer matches the signal. But the
    // observed precise license is IDENTICAL to what the override asserts.
    const entry = pkg("ipython", "9.10.0", [claim("BSD-3-Clause", "spdx-id")]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.source).not.toBe("override"); // observed finding stands
    expect(finding.staleOverride).toBeUndefined(); // NOT a false-positive stale
  });

  test("REDUNDANT covers the whole now-precise Jupyter stack (ipykernel, jupyter-core)", () => {
    const ipykernel = pkg("ipykernel", "7.2.0", [
      claim("BSD-3-Clause", "spdx-id"),
    ]);
    const jupyterCore = pkg("jupyter-core", "5.9.1", [
      claim("BSD-3-Clause", "spdx-id"),
    ]);
    const { model } = annotateFindings(
      modelOf(ipykernel, jupyterCore),
      [],
      [...BUILTIN_OVERRIDES],
    );
    for (const p of model.packages) {
      expect(p.finding!.expression).toBe("BSD-3-Clause");
      expect(p.finding!.staleOverride).toBeUndefined();
    }
  });

  test("STALE: precise MIT observed, expects BSD asserts BSD-3-Clause → fail (MIT does not satisfy BSD-3-Clause)", () => {
    const entry = pkg("relicensed-permissive", "2.0.0", [
      claim("MIT", "spdx-id"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "relicensed-permissive",
        expects: "BSD",
        expression: "BSD-3-Clause",
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.expression).toBe("MIT"); // observed finding stands
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.expected).toBe("BSD");
    expect(finding.staleOverride!.observed).toContain("MIT");
  });

  test("STALE: precise GPL-3.0-only observed, expects BSD asserts BSD-3-Clause → fail (relicense to copyleft)", () => {
    const entry = pkg("relicensed-copyleft", "2.0.0", [
      claim("GPL-3.0-only", "spdx-id"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "relicensed-copyleft",
        expects: "BSD",
        expression: "BSD-3-Clause",
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("clarify");
  });

  test("the C1 masking case STILL fails closed (expects BSD present + co-present GPL contradicts)", () => {
    // Regression guard: the gap fix must not reopen C1. Here expects IS in the
    // signal, so the redundant path is never consulted; signalContradicts fires.
    const entry = pkg("ipython", "8.0.0", [
      claim("BSD", "name"),
      claim("GPL-3.0-only", "spdx-id"),
    ]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("builtin");
  });

  test("the normal disambiguation case STILL applies (observed imprecise BSD, expects BSD)", () => {
    // Regression guard: the gap fix must not break the imprecise→precise path.
    const entry = pkg("traitlets", "5.0.0", [claim("BSD License", "name")]);
    const { model } = annotateFindings(
      modelOf(entry),
      [],
      [...BUILTIN_OVERRIDES],
    );
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Debian/DEP-5 copyright short-name → canonical SPDX normalization.
//
// syft fills ~98% of OS-package licenses, but Debian's machine-readable copyright
// (DEP-5) uses copyright shorthands ("Expat", "GPL-2+", "BSD-3-clause") that are
// NOT valid SPDX ids, so they render `unknown` after normalization. The vendored
// DEBIAN_SHORTHAND map (the copyleftFamily.ts literal-data idiom) maps the
// well-known unambiguous shorthands to canonical SPDX ids, applied within
// normalizeRaw BEFORE the spdx-correct path. Case-insensitive on the EXACT
// shorthand token only — never substring, never broadened.
// ---------------------------------------------------------------------------

// [shorthand, expected SPDX id]. Every TARGET is validated against
// spdx-license-ids below — a typo'd target would silently re-create the unknown.
// [shorthand, expectedExpression, source]. The "+" forms with a NON-SPDX base
// ("GPL-2+", "LGPL-2+", "LGPL-3+", "GPL-3+") are mapped to the precise -or-later
// id; "LGPL-2.1+" is ALREADY valid SPDX (LGPL-2.1 is a real base id) so it is
// preserved verbatim by the exact-parse path (source "generator") — rewriting an
// already-valid SPDX id would violate the verbatim-preservation invariant. Both
// forms mean GPL/LGPL "or-later", so the OS section renders a real license.
const DEBIAN_SHORTHAND_CASES: ReadonlyArray<
  [shorthand: string, expected: string, source: "corrected" | "generator"]
> = [
  ["Expat", "MIT", "corrected"],
  ["GPL-2", "GPL-2.0-only", "corrected"],
  ["GPL-2+", "GPL-2.0-or-later", "corrected"],
  ["GPL-3", "GPL-3.0-only", "corrected"],
  ["GPL-3+", "GPL-3.0-or-later", "corrected"],
  ["LGPL-2", "LGPL-2.0-only", "corrected"],
  ["LGPL-2+", "LGPL-2.0-or-later", "corrected"],
  ["LGPL-2.1", "LGPL-2.1", "generator"], // deprecated-but-valid SPDX id — preserved verbatim
  ["LGPL-2.1+", "LGPL-2.1+", "generator"], // already valid SPDX — preserved verbatim
  ["LGPL-3", "LGPL-3.0-only", "corrected"],
  ["LGPL-3+", "LGPL-3.0-or-later", "corrected"],
  ["BSD-2-clause", "BSD-2-Clause", "corrected"],
  ["BSD-3-clause", "BSD-3-Clause", "corrected"],
  // Observed in the committed docker.sbom.json: ncurses' "MIT/X11" Debian-ism.
  ["MIT/X11", "MIT", "corrected"],
];

describe("normalizeRaw — Debian/DEP-5 shorthand map", () => {
  for (const [shorthand, expected, source] of DEBIAN_SHORTHAND_CASES) {
    test(`"${shorthand}" → "${expected}"`, () => {
      const result = normalizeRaw(shorthand);
      expect(result.expression).toBe(expected);
      expect(result.source).toBe(source);
      expect(result.imprecise).toBeUndefined();
    });
  }

  test("every Debian-shorthand TARGET is a real SPDX id (typo-proof)", () => {
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
    // Strip a trailing "+" (the SPDX or-later operator) to recover the base id
    // that must exist in spdx-license-ids — "LGPL-2.1+" is a valid expression
    // whose base "LGPL-2.1" is the listed id.
    const targets = DEBIAN_SHORTHAND_CASES.map(([, t]) => t.replace(/\+$/, ""));
    expect(targets.filter((t) => !known.has(t))).toEqual([]);
  });

  test("matching is case-insensitive on the exact token (Debian is inconsistent)", () => {
    // BSD-3-clause vs BSD-3-Clause: Debian uses lowercase-clause.
    expect(normalizeRaw("bsd-3-clause").expression).toBe("BSD-3-Clause");
    expect(normalizeRaw("EXPAT").expression).toBe("MIT");
    expect(normalizeRaw("gpl-2+").expression).toBe("GPL-2.0-or-later");
  });

  test("the DEBIAN_SHORTHAND map itself never broadens to substring — a custom name that merely CONTAINS a shorthand is not mapped BY THE MAP", () => {
    // These tokens are NOT in DEBIAN_SHORTHAND. Whatever they resolve to must
    // come from the pre-existing spdx-correct path, never from the new map: the
    // map's source attribution is the proof. "Expat-ISC"/"Expat-UNM" are the
    // sharpest probe — bare "Expat" maps via the new map, but the hyphenated
    // custom names must NOT, and correct() returns null for them, so they stay
    // genuinely unknown.
    expect(normalizeRaw("Expat-ISC").expression).toBeNull();
    expect(normalizeRaw("Expat-UNM").expression).toBeNull();
    expect(normalizeRaw("Expat-ISC").imprecise).toBeUndefined();
  });

  test("bare GPL/LGPL/AGPL stay IMPRECISE — the shorthand map never collides with the family lane", () => {
    // The shorthand keys are all VERSIONED; bare family labels must still route
    // to the could-be-copyleft imprecise lane (INV-04), never a guessed id.
    for (const fam of ["GPL", "LGPL", "AGPL"]) {
      const result = normalizeRaw(fam);
      expect(result.expression).toBeNull();
      expect(result.imprecise).toBe(true);
      expect(result.impreciseFamily).toBe(fam);
    }
  });

  test("genuinely-unknown / non-SPDX Debian tokens the plan names STAY unknown (never guessed)", () => {
    // The plan's explicit stay-unknown set: custom, public-domain (no SPDX id),
    // sha256-hash fallbacks, and the bare connector token. These are NOT added
    // to DEBIAN_SHORTHAND and correct() already returns null for them.
    for (const token of [
      "custom",
      "public-domain",
      "Public Domain",
      "AND",
      "sha256:fd7e4aae7e7b05f217bcf2d02322825c360e66c52c4c2f1b28d784d6297a1c23",
    ]) {
      const result = normalizeRaw(token);
      expect(result.expression).toBeNull();
    }
  });

  test("existing valid SPDX ids are unchanged — no shorthand collision regression", () => {
    // The shorthands must not shadow any valid SPDX id the corpus already emits.
    for (const [raw, , expected, klass] of CORPUS) {
      const result = normalizeRaw(raw);
      expect(result.expression).toBe(expected);
      expect(result.source).toBe(
        klass === "corrected" ? "corrected" : "generator",
      );
    }
    // And the canonical TARGETs themselves still parse as exact (not re-corrected).
    expect(normalizeRaw("GPL-2.0-only").source).toBe("generator");
    expect(normalizeRaw("MIT").source).toBe("generator");
    expect(normalizeRaw("BSD-3-Clause").source).toBe("generator");
  });
});

describe("annotateFindings — OS packages render real licenses for mapped shorthands", () => {
  test("an Expat-sole OS package lifts from unknown to MIT", () => {
    // Mirrors apt / libz3-4 in the committed docker.sbom.json.
    const entry = pkg("apt", "2.6.1", [claim("Expat", "name")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.elected).toBe("MIT");
    expect(finding.confidence).toBe("corrected");
  });

  test("a MIT/X11 OS package (ncurses) lifts from unknown to MIT", () => {
    const entry = pkg("libtinfo6", "6.4-4", [claim("MIT/X11", "name")]);
    const { model } = annotateFindings(modelOf(entry), []);
    expect(model.packages[0]!.finding!.expression).toBe("MIT");
  });

  test("a real coreutils-style GPL OS package renders a real copyleft license", () => {
    // Debian DEP-5 "GPL-3+" shorthand → the precise GPL-3.0-or-later copyleft id.
    const entry = pkg("coreutils", "9.1-1", [claim("GPL-3+", "name")]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("GPL-3.0-or-later");
  });

  test("a BSD OS package renders a real permissive license", () => {
    const entry = pkg("libbsd0", "0.11", [claim("BSD-3-clause", "name")]);
    expect(
      annotateFindings(modelOf(entry), []).model.packages[0]!.finding!
        .expression,
    ).toBe("BSD-3-Clause");
  });

  test("all-or-nothing unknown invariant intact: an Expat sibling next to a genuinely-unknown token stays unknown", () => {
    // libmd-style: BSD ids + a bare "AND"/"Public Domain" split keeps it unknown.
    const entry = pkg("aom-libs", "3.13.1", [
      claim("BSD-2-Clause", "spdx-id"),
      claim("AND", "name"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    // "custom" is genuinely unknown → the whole row is correctly unknown.
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
  });

  test("a proper CycloneDX expression claim is ingested whole, not split (multi-token finding)", () => {
    // syft emits real multi-license deb packages as a single `expression` claim
    // (SbomExpressionClaim, tried first in licenseClaimsOf). It must normalize as
    // one expression — never split into name tokens that force the row unknown.
    const entry = pkg("font-pkg", "1.0", [
      claim("FTL OR GPL-2.0-or-later", "expression"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("FTL OR GPL-2.0-or-later");
    expect(finding.elected).not.toBeNull();
  });
});

// ===========================================================================
// The os-partial finding: for the NON-GATING os scope ONLY, a claim set that
// mixes normalizable SPDX members with genuinely-unknown (none) tokens renders
// the KNOWN licenses AND surfaces the unrecognized remainder, instead of the
// all-or-nothing unknown. App-scope (gating) keeps the strict invariant: a
// genuinely-unknown sibling forces the whole row unknown.
//
// SAFETY:
//  - partial finding applies ONLY to scope === "os".
//  - app/dev/prod (gating) scopes are COMPLETELY UNCHANGED.
//  - an imprecise sibling (not a "none" token) is NOT an unrecognized token —
//    it routes through the existing imprecise lane, never the os-partial lane.
//  - a partial finding NEVER turns an app-scope would-be-unknown into a clean
//    license (no gate weakening).
// ===========================================================================

describe("findingFromClaims — os-scope partial finding", () => {
  test("HEADLINE: os [GPL-2.0-only, BSD-3-Clause, public-domain] → expression of the known two + unrecognizedTokens", () => {
    const entry = osPkg("os-partial", "1.0", [
      claim("GPL-2.0-only", "spdx-id"),
      claim("BSD-3-Clause", "spdx-id"),
      claim("public-domain", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("GPL-2.0-only AND BSD-3-Clause");
    expect(finding.elected).not.toBeNull();
    expect(finding.unrecognizedTokens).toEqual(["public-domain"]);
    // The known copyleft member survives — the finding is NOT unknown.
    expect(finding.confidence).not.toBe("none");
  });

  test("unrecognizedTokens are sorted + deduped (deterministic)", () => {
    // "custom" and "public-domain" are genuinely non-SPDX (normalizeRaw → null,
    // not imprecise); "MIT" is the known member. The dup "public-domain"
    // collapses; the surfaced set sorts by compareCodeUnits ("c" < "p").
    const entry = osPkg("os-many", "1.0", [
      claim("MIT", "spdx-id"),
      claim("public-domain", "name"),
      claim("custom", "name"),
      claim("public-domain", "name"), // dup
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.unrecognizedTokens).toEqual(["custom", "public-domain"]);
  });

  test("os ZERO-normalizable (only public-domain) stays unknown (expression null)", () => {
    const entry = osPkg("os-none", "1.0", [
      claim("public-domain", "name"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
  });

  test("INVARIANT: app-scope [GPL-2.0-only, custom] still yields unknown (all-or-nothing intact)", () => {
    const entry = pkg("app-mixed", "1.0", [
      claim("GPL-2.0-only", "spdx-id"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("INVARIANT: app-scope [MIT, custom] still yields unknown (no gate weakening)", () => {
    const entry = pkg("app-mit-custom", "1.0", [
      claim("MIT", "spdx-id"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("os all-normalizable (no unknown token) → no unrecognizedTokens field", () => {
    const entry = osPkg("os-clean", "1.0", [
      claim("MIT", "spdx-id"),
      claim("BSD-3-Clause", "spdx-id"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("MIT AND BSD-3-Clause");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("os [MIT, BSD-License-imprecise] is NOT os-partial — imprecise lane unchanged (no unrecognizedTokens)", () => {
    // An imprecise family is not a "none" token: it keeps the existing imprecise
    // behavior even in os scope, never the os-partial surfacing.
    const entry = osPkg("os-imprecise", "1.0", [
      claim("MIT", "spdx-id"),
      claim("BSD License", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("os partial preserves the RAW unknown token verbatim (not a normalized form)", () => {
    const entry = osPkg("os-raw", "1.0", [
      claim("MIT", "spdx-id"),
      claim("  Weird Custom Name  ", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("MIT");
    // trimmed but otherwise verbatim.
    expect(finding.unrecognizedTokens).toEqual(["Weird Custom Name"]);
  });

  // #3 + #10: syft tokenizes a compound license ("GPL-2.0-only AND MIT") into
  // SEPARATE entries INCLUDING the bare connective tokens "AND"/"OR"/"WITH".
  // Those are SYNTAX artifacts, not licenses — they must be filtered out of
  // unrecognizedTokens (case-insensitive) and must never count as a claim.
  test("#3/#10: a bare 'AND' connective token is filtered from unrecognizedTokens (os scope)", () => {
    const entry = osPkg("os-connective", "1.0", [
      claim("GPL-2.0-only", "spdx-id"),
      claim("AND", "name"),
      claim("MIT", "spdx-id"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    // The two real licenses combine; "AND" is NOT surfaced as an unknown token.
    expect(finding.unrecognizedTokens ?? []).not.toContain("AND");
    expect(finding.expression).toBe("GPL-2.0-only AND MIT");
  });

  test("#3/#10: bare OR/WITH/and (any case) are all filtered, a real custom token survives", () => {
    const entry = osPkg("os-connectives", "1.0", [
      claim("MIT", "spdx-id"),
      claim("OR", "name"),
      claim("with", "name"),
      claim("And", "name"),
      claim("public-domain", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    const tokens = finding.unrecognizedTokens ?? [];
    for (const connective of ["OR", "with", "And", "AND", "WITH"]) {
      expect(tokens).not.toContain(connective);
    }
    // The genuinely-unknown token still surfaces.
    expect(tokens).toContain("public-domain");
  });

  test("#3/#10: a connective token does NOT trigger the all-or-nothing unknown collapse (it is not a claim)", () => {
    // [MIT, AND] in OS scope: "AND" is a syntax artifact, not an unknown claim,
    // so the finding is the clean MIT — NOT unknown, NOT os-partial.
    const entry = osPkg("os-mit-and", "1.0", [
      claim("MIT", "spdx-id"),
      claim("AND", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("#3/#10: a connective token in APP scope does not force unknown either", () => {
    const entry = pkg("app-mit-and", "1.0", [
      claim("MIT", "spdx-id"),
      claim("AND", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.confidence).not.toBe("none");
  });

  // #2: an os claim set of [imprecise-copyleft-family, genuinely-unknown] with
  // NO precise member must carry the impreciseFamily onto the finding so the
  // could-be-copyleft review hint survives (not silently flattened to plain
  // unknown). It is an imprecise os-partial: family carried + token surfaced.
  test("#2: os [GPL-family-imprecise, custom] carries impreciseFamily + surfaces the unknown token", () => {
    const entry = osPkg("os-imprecise-partial", "1.0", [
      claim("GPL", "name"), // imprecise copyleft family
      claim("some-custom-token", "name"), // genuinely unknown
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!
      .finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
    expect(finding.unrecognizedTokens).toEqual(["some-custom-token"]);
  });
});

// ---------------------------------------------------------------------------
// ScanCode senior assessment. applyScancodeAssessment
// replaces the earlier family-consistency refinement gate at the same seam: the
// in-depth scancode answer OUTRANKS the quick check (declared metadata and
// registry answers) when they agree — the finding becomes the assessed
// expression, source "scancode", confidence "exact" — and ANY disagreement
// becomes a first-class conflict marker on the UNCHANGED base finding, never
// absorbed in either direction (the marked finding flows to the policy
// engine; surfacing is its concern). Overrides (clarify/builtin) still decide
// last; an APPLIED override never carries the marker. An imprecise scancode
// answer never upgrades anything. Every changed expectation below is
// a conscious re-pin of an earlier fill-matrix row to the new semantics.
// ---------------------------------------------------------------------------

/** A claim with an explicit source — the scancode-assessment fixture idiom. */
const sourcedClaim = (
  raw: string,
  source: LicenseClaim["source"],
  kind: LicenseClaimKind = "name",
): LicenseClaim => ({ raw, kind, source });

/** A scancode-sourced claim (the assessment trigger). */
const scancodeClaim = (raw: string): LicenseClaim =>
  sourcedClaim(raw, "scancode", "expression");

describe("annotateFindings — scancode senior assessment (the re-pinned fill matrix)", () => {
  test("row 1 (vacuous agreement): zero-claim package + a precise scancode claim — the assessment IS the finding, source scancode", () => {
    const entry = pkg("zero-claim-pkg", "1.0.0", [scancodeClaim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.confidence).toBe("exact");
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("row 2 (re-pinned): garbage-claim package + precise scancode claim — the unknown base STANDS and carries a conflict marker, never silently decided either way", () => {
    const entry = pkg("garbage-claim-pkg", "1.0.0", [
      claim("total garbage xyz", "name"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("none");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toEqual({
      assessed: "MIT",
      disagreeing: ["total garbage xyz"],
    });
  });

  test("row 3 (agreement): imprecise BSD family + scancode BSD-3-Clause — the in-family assessment becomes the finding, source scancode, confidence exact", () => {
    const entry = pkg("imprecise-bsd-pkg", "1.0.0", [
      claim("BSD", "name"),
      scancodeClaim("BSD-3-Clause"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.confidence).toBe("exact");
    expect(finding.impreciseFamily).toBeUndefined();
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("row 4 (re-pinned, the flagship conflict): imprecise GPL family + scancode MIT — the copyleft signal STANDS and the disagreement is surfaced as a conflict", () => {
    const entry = pkg("imprecise-gpl-pkg", "1.0.0", [
      claim("GPL", "name"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toEqual({
      assessed: "MIT",
      disagreeing: ["GPL"],
    });
  });

  test("row 5 (INV-04): a scancode claim that itself normalizes imprecise (bare family raw) leaves the same-family imprecise base unchanged, no conflict", () => {
    const entry = pkg("imprecise-apache-pkg", "1.0.0", [
      claim("Apache", "name"),
      scancodeClaim("Apache"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("Apache");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toBeUndefined();
  });

  test("an imprecise assessment never conflicts with an imprecise base, even out-of-family — nothing precise on either side to weigh (INV-04)", () => {
    const entry = pkg("imprecise-both-pkg", "1.0.0", [
      claim("BSD", "name"),
      scancodeClaim("Apache"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.conflict).toBeUndefined();
  });

  test('family edge (re-pinned): imprecise BSD family + scancode 0BSD — prefix discipline (0BSD does not start with "BSD-") makes it a conflict, the imprecise base stands', () => {
    const entry = pkg("imprecise-bsd-0bsd-pkg", "1.0.0", [
      claim("BSD", "name"),
      scancodeClaim("0BSD"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toEqual({
      assessed: "0BSD",
      disagreeing: ["BSD"],
    });
  });

  test("family edge (re-pinned, copyleft prefix guard): imprecise GPL family + scancode LGPL-2.1-only — C2 copyleft dominance still elects the precise LGPL base, AND the out-of-family disagreement is surfaced (LGPL vs GPL is a human question)", () => {
    const entry = pkg("imprecise-gpl-lgpl-pkg", "1.0.0", [
      claim("GPL", "name"),
      scancodeClaim("LGPL-2.1-only"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    // C2 (combineKnown, untouched): a PRECISE copyleft claim dominates an
    // imprecise sibling family regardless of source — the base finding is the
    // genuinely-observed LGPL-2.1-only, never a fabricated bare-GPL guess.
    // NEW under the assessment model: the GPL family member is out-of-family
    // for the LGPL leaf (prefix boundary), so the disagreement is surfaced.
    expect(finding.expression).toBe("LGPL-2.1-only");
    expect(finding.confidence).toBe("exact");
    expect(finding.conflict).toEqual({
      assessed: "LGPL-2.1-only",
      disagreeing: ["GPL"],
    });
  });

  test("fail-closed (re-pinned): a compound scancode expression mixing an in-family leaf with an out-of-family leaf conflicts with the imprecise family, no throw", () => {
    const entry = pkg("imprecise-mixed-compound-pkg", "1.0.0", [
      claim("BSD", "name"),
      scancodeClaim("BSD-3-Clause AND MIT"),
    ]);
    expect(() => annotateFindings(modelOf(entry), [])).not.toThrow();
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toEqual({
      assessed: "BSD-3-Clause AND MIT",
      disagreeing: ["BSD"],
    });
  });

  test("precedence: a clarify override on the same package still decides the final finding over the assessment (clarify on top)", () => {
    const entry = pkg("imprecise-clarified-pkg", "1.0.0", [
      claim("BSD", "name"),
      scancodeClaim("BSD-3-Clause"),
    ]);
    const clarify: ClarifyInput[] = [
      { name: "imprecise-clarified-pkg", expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("MIT");
  });

  test("seniority (formerly never-override): a PRECISE declared claim agreeing with the assessment yields the scancode-sourced finding — the in-depth assessment outranks the quick check", () => {
    const entry = pkg("agreeing-precise-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.confidence).toBe("exact");
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("seniority (formerly never-override): a PRECISE declared claim contradicted by the assessment STANDS in full and carries a conflict marker — never silently overridden in either direction", () => {
    const entry = pkg("disagreeing-precise-pkg", "1.0.0", [
      claim("Apache-2.0"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    // The base finding — the quick-check AND-combine of every precise claim —
    // stands untouched; the marker names both sides for a human.
    expect(finding.expression).toBe("Apache-2.0 AND MIT");
    expect(finding.source).not.toBe("scancode");
    expect(finding.conflict).toEqual({
      assessed: "MIT",
      disagreeing: ["Apache-2.0"],
    });
  });

  test("agreement via satisfies: a precise OR-bearing declared claim whose elected branch matches the assessment agrees — satisfies(P, [S])", () => {
    const entry = pkg("or-agreeing-pkg", "1.0.0", [
      claim("Apache-2.0 OR MIT", "expression"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("fail closed on the satisfies throw: a compound assessment agrees only via exact equality — any other precise claim is a conflict", () => {
    // Compound S: satisfies(P, [S]) throws (locked above), so agreement falls
    // back to the exact-equality pre-check alone.
    const equal = pkg("compound-equal-pkg", "1.0.0", [
      claim("MIT AND Apache-2.0", "expression"),
      scancodeClaim("MIT AND Apache-2.0"),
    ]);
    const equalFinding = annotateFindings(modelOf(equal), []).model.packages[0]!
      .finding!;
    expect(equalFinding.expression).toBe("MIT AND Apache-2.0");
    expect(equalFinding.source).toBe("scancode");
    expect(equalFinding.conflict).toBeUndefined();

    const differing = pkg("compound-differing-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("MIT AND Apache-2.0"),
    ]);
    const differingFinding = annotateFindings(modelOf(differing), []).model
      .packages[0]!.finding!;
    expect(differingFinding.source).not.toBe("scancode");
    expect(differingFinding.conflict).toEqual({
      assessed: "MIT AND Apache-2.0",
      disagreeing: ["MIT"],
    });
  });

  test("imprecise assessment vs an out-of-family PRECISE base (C2 copyleft): the base stands and the disagreement is a conflict — an imprecise answer never upgrades or absorbs", () => {
    const entry = pkg("imprecise-scan-vs-copyleft-pkg", "1.0.0", [
      claim("GPL-3.0-only"),
      scancodeClaim("Apache"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.confidence).toBe("exact");
    expect(finding.conflict).toEqual({
      assessed: "Apache",
      disagreeing: ["GPL-3.0-only"],
    });
  });

  test("imprecise assessment vs an in-family PRECISE base: unchanged, no conflict — the assessment corroborates without upgrading", () => {
    const entry = pkg("imprecise-scan-in-family-pkg", "1.0.0", [
      claim("GPL-3.0-only"),
      scancodeClaim("GPL"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.confidence).toBe("exact");
    expect(finding.conflict).toBeUndefined();
  });

  test("a bare connective artifact is tokenization noise, never a disagreeing member (#3/#10 discipline carries over)", () => {
    const entry = pkg("connective-noise-pkg", "1.0.0", [
      claim("AND", "name"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.expression).toBe("MIT");
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("multiple disagreeing members are collected, deduped, and sorted deterministically", () => {
    const entry = pkg("multi-disagree-pkg", "1.0.0", [
      claim("Apache-2.0"),
      claim("BSD", "name"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    // W2 stickiness (untouched): the imprecise BSD member keeps the base
    // imprecise; the conflict names BOTH disagreeing quick-check members —
    // the precise one normalized, the imprecise one as its family token.
    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.conflict).toEqual({
      assessed: "MIT",
      disagreeing: ["Apache-2.0", "BSD"],
    });
  });

  test("resolution: an APPLIED clarify override decides the conflict and the marker is dropped — the marker lives on the un-overridden base only", () => {
    const entry = pkg("conflicted-clarified-pkg", "1.0.0", [
      claim("Apache-2.0"),
      scancodeClaim("MIT"),
    ]);
    const clarify: ClarifyInput[] = [
      { name: "conflicted-clarified-pkg", expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("MIT");
    expect(finding.conflict).toBeUndefined();
    expect(finding.staleOverride).toBeUndefined();
  });

  test("a STALE clarify override keeps the base finding, which carries BOTH markers — stale + conflict coexist (chain ordering is the policy engine's concern)", () => {
    const entry = pkg("stale-conflicted-pkg", "1.0.0", [
      claim("Apache-2.0"),
      scancodeClaim("MIT"),
    ]);
    const clarify: ClarifyInput[] = [
      { name: "stale-conflicted-pkg", expects: "BSD", expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.staleOverride).toBeDefined();
    expect(finding.conflict).toEqual({
      assessed: "MIT",
      disagreeing: ["Apache-2.0"],
    });
  });

  test("resolution (guarded): a staleness-GUARDED clarify (expects present and matched) that applies STILL clears the conflict marker — the guarded-apply path, not only the blind path, drops it (worked example: registry MIT vs scancode BSD-3-Clause)", () => {
    const entry = pkg("guarded-clarified-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("BSD-3-Clause"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "guarded-clarified-pkg",
        expects: "MIT",
        expression: "BSD-3-Clause",
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.conflict).toBeUndefined();
    expect(finding.staleOverride).toBeUndefined();
  });

  test("deny visibility: a scancode win never drops the quick-check members from observedExpressions — a denied license present only in a non-scancode claim stays visible to the deny terminal", () => {
    const entry = pkg("deny-visible-pkg", "1.0.0", [
      claim("BUSL-1.1 OR MIT", "expression"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;
    expect(finding.source).toBe("scancode");
    expect(finding.expression).toBe("MIT");
    expect(finding.observedExpressions).toContain("BUSL-1.1 OR MIT");
  });
});

describe("applyScancodeAssessment — unit surface", () => {
  const impreciseBsdBase: LicenseFinding = {
    expression: null,
    elected: null,
    source: "generator",
    confidence: "imprecise",
    impreciseFamily: "BSD",
  };

  test("purity: exported, a function of (claims, base finding) only — identical inputs reproduce identical findings (no options, no mode, no clock)", () => {
    const claims = [claim("BSD", "name"), scancodeClaim("BSD-3-Clause")];
    const a = applyScancodeAssessment(claims, impreciseBsdBase);
    const b = applyScancodeAssessment(claims, impreciseBsdBase);
    expect(a).toEqual(b);
    expect(a.expression).toBe("BSD-3-Clause");
    expect(a.source).toBe("scancode");
  });

  test("no scancode claim: the base finding is returned unchanged — the identical reference, not a copy (byte-identity for scancode-free inputs)", () => {
    const claims = [claim("MIT"), claim("Apache-2.0")];
    expect(applyScancodeAssessment(claims, impreciseBsdBase)).toBe(
      impreciseBsdBase,
    );
  });

  test("a genuinely-unknown scancode raw assesses nothing — base returned unchanged, defensively (the election rejects these upstream)", () => {
    const claims = [claim("MIT"), scancodeClaim("who knows")];
    expect(applyScancodeAssessment(claims, impreciseBsdBase)).toBe(
      impreciseBsdBase,
    );
  });
});
