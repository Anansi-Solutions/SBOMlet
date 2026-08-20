import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import parse from "spdx-expression-parse";

import { annotateFindings, normalizeRaw, type ClarifyInput } from "../src/normalize/normalize";
import { claim, pkg, osPkg, modelOf } from "./normalizeTestSupport";
import type { LicenseClaim, LicenseClaimKind } from "../src/model/dependencies";

// ---------------------------------------------------------------------------
// normalizeRaw + annotateFindings (Task 3)
// ---------------------------------------------------------------------------

type CorpusClass = "exact" | "corrected" | "none" | "imprecise";

// The full 33-row live corpus (3616 packages, captured 2026-06-11):
// every distinct (kind, raw) value the real repo produces, with the expected
// Normalized column. [raw, kind, expectedExpression, class]
const CORPUS: ReadonlyArray<
  [raw: string, kind: LicenseClaimKind, expected: string | null, klass: CorpusClass]
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
  // The bare family label "BSD" is no longer guessed to
  // BSD-2-Clause (the conscious change documented in the plan). It is
  // present-but-imprecise: expression null, confidence "imprecise". The 23
  // Jupyter BSD rows ride this change; the tool-level override will later
  // disambiguate them to BSD-3-Clause.
  ["BSD", "name", null, "imprecise"],
  ["CC0-1.0", "spdx-id", "CC0-1.0", "exact"],
  ["Apache-2.0 AND LGPL-3.0-or-later", "expression", "Apache-2.0 AND LGPL-3.0-or-later", "exact"],
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
  ["(AFL-2.1 OR BSD-3-Clause)", "expression", "(AFL-2.1 OR BSD-3-Clause)", "exact"],
  ["Public Domain", "name", null, "none"],
  ["(MIT OR GPL-3.0-or-later)", "expression", "(MIT OR GPL-3.0-or-later)", "exact"],
  ["(WTFPL OR MIT)", "expression", "(WTFPL OR MIT)", "exact"],
  ["(MIT AND Zlib)", "expression", "(MIT AND Zlib)", "exact"],
  [
    "(BSD-2-Clause OR MIT OR Apache-2.0)",
    "expression",
    "(BSD-2-Clause OR MIT OR Apache-2.0)",
    "exact",
  ],
  ["CC-BY-3.0", "spdx-id", "CC-BY-3.0", "exact"],
  ["(Unlicense OR Apache-2.0)", "expression", "(Unlicense OR Apache-2.0)", "exact"],
];

describe("normalizeRaw — live 33-value corpus", () => {
  test("corpus covers all 33 distinct live (kind, raw) values", () => {
    expect(CORPUS.length).toBe(33);
    expect(new Set(CORPUS.map(([raw, kind]) => `${kind}\0${raw}`)).size).toBe(33);
  });

  for (const [raw, , expected, klass] of CORPUS) {
    test(`"${raw}" → ${expected === null ? "unknown" : `"${expected}"`}`, () => {
      const result = normalizeRaw(raw);

      expect(result.expression).toBe(expected);
      expect(result.source).toBe(klass === "corrected" ? "corrected" : "generator");
    });
  }

  test("findings over the corpus carry the expected confidence", () => {
    const entries = CORPUS.map(([raw, kind], i) => pkg(`corpus-${i}`, "1.0.0", [claim(raw, kind)]));
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
// Real-world free-text Maven license raws, verified byte-for-byte against the
// real public repo1.maven.org POMs (mysql-connector-j 9.5.0,
// jasperreports/-fonts 6.21.0, jcommon/jfreechart 1.0.23/1.0.19,
// juniversalchardet 2.5.0 — real public GAVs, sanctioned for this one use).
// Three of these labels originally surfaced guess-shaped correct() outcomes
// (a version-specific id from an unversioned label, a family flip, a
// version-contradicting id); the review fixed them via the ambiguous-family
// intercept and the precise-label fixup, and these tests lock the honest
// outcomes.
// ---------------------------------------------------------------------------
describe("normalizeRaw — real-world Maven free-text raws (locked)", () => {
  test("mysql-connector-j's FOSS-exception GPLv2 label resolves to the PRECISE GPL-2.0-only WITH Universal-FOSS-exception-1.0 — never the GPL-3.0-or-later fuzzy guess that contradicted the stated v2", () => {
    const result = normalizeRaw(
      "The GNU General Public License, v2 with Universal FOSS Exception, v1.0",
    );

    // The label states BOTH a version (v2) and an exception (Universal FOSS
    // Exception v1.0), and each has an exact SPDX spelling — the fixup maps
    // the whole label to it. correct() used to resolve this to
    // GPL-3.0-or-later, contradicting the stated version and dropping the
    // exception clause entirely.
    expect(result).toEqual({
      expression: "GPL-2.0-only WITH Universal-FOSS-exception-1.0",
      source: "corrected",
    });
  });

  test('bare "GNU Lesser General Public License" (jasperreports, jasperreports-fonts) is an IMPRECISE LGPL family — never a guessed version id', () => {
    const result = normalizeRaw("GNU Lesser General Public License");

    // The spelled-out family name carries no version; correct() used to
    // guess LGPL-2.1-only from it. It now routes to the same imprecise
    // could-be-copyleft lane as the short "lgpl" label.
    expect(result).toEqual({
      expression: null,
      source: "generator",
      imprecise: true,
      impreciseFamily: "LGPL",
    });
  });

  test('the British-spelling "GNU Lesser General Public Licence" (jcommon, jfreechart) is the SAME imprecise LGPL family — never the GPL-3.0-or-later family flip', () => {
    const result = normalizeRaw("GNU Lesser General Public Licence");

    // correct() used to send the spelling variant to the GPL family,
    // resolving a weak-copyleft label to a strong-copyleft id.
    expect(result).toEqual({
      expression: null,
      source: "generator",
      imprecise: true,
      impreciseFamily: "LGPL",
    });
  });

  test("the spelled-out GPL and AGPL family names (both spellings) are imprecise families too — correct() guessed a precise or-later id from every one of them", () => {
    for (const [raw, family] of [
      ["GNU General Public License", "GPL"],
      ["GNU General Public Licence", "GPL"],
      ["GNU Affero General Public License", "AGPL"],
      ["GNU Affero General Public Licence", "AGPL"],
    ] as const) {
      expect(normalizeRaw(raw)).toEqual({
        expression: null,
        source: "generator",
        imprecise: true,
        impreciseFamily: family,
      });
    }
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
    const result = normalizeRaw("GNU LESSER GENERAL PUBLIC LICENSE, version 3 (LGPL-3.0)");

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

    const { model } = annotateFindings(modelOf(pkg("juniversalchardet", "2.5.0", claims)), []);
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
// Imprecise family labels. An ambiguous family label is
// represented faithfully as the imprecise family — never guessed to a precise
// SPDX id and never silently dropped to unknown.
// ---------------------------------------------------------------------------

describe("normalizeRaw — imprecise family labels", () => {
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

describe("normalizeRaw — ISC-license suffix fix", () => {
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

describe("annotateFindings — imprecise findings", () => {
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
    const { model } = annotateFindings(modelOf(impreciseEntry, unknownEntry), []);

    expect(model.packages[0]!.finding!.confidence).toBe("imprecise");
    expect(model.packages[0]!.finding!.impreciseFamily).toBe("BSD");
    expect(model.packages[1]!.finding!.confidence).toBe("none");
    expect(model.packages[1]!.finding!.impreciseFamily).toBeUndefined();
  });

  test("one precise + one imprecise claim degrades conservatively (never AND-ed into a fake expression)", () => {
    const entry = pkg("mixed", "1.0.0", [claim("MIT"), claim("BSD License", "name")]);
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
      { name: "jupyter-thing", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
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
  test("duplicate identical claims collapse — never MIT AND MIT", () => {
    // buffer-crc32@0.2.13 live shape: two identical claims in one component.
    const entry = pkg("buffer-crc32", "0.2.13", [claim("MIT"), claim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);

    expect(model.packages[0]!.finding!.expression).toBe("MIT");
  });

  test("distinct claims AND-combine conservatively and re-parse", () => {
    const entry = pkg("two-claims", "1.0.0", [claim("MIT"), claim("Apache-2.0")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const expression = model.packages[0]!.finding!.expression;

    expect(expression).toBe("MIT AND Apache-2.0");
    expect(() => parse(expression!)).not.toThrow();
  });

  test("one normalizable + one garbage claim → whole finding unknown", () => {
    // Partial knowledge must not hide an obligation.
    const entry = pkg("mixed", "1.0.0", [claim("MIT"), claim("total garbage xyz", "name")]);
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
    const entry = pkg("mixed", "1.0.0", [claim("BSD", "name"), claim("GPL-3.0-only", "spdx-id")]);
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
    const entry = pkg("mixed", "1.0.0", [claim("MIT"), claim("BSD License", "name")]);
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
    const entry = pkg("dompurify", "3.1.6", [claim("(MPL-2.0 OR Apache-2.0)", "expression")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(finding.expression).toBe("(MPL-2.0 OR Apache-2.0)");
    expect(finding.elected).toBe("Apache-2.0");
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
    const dataDir = join(import.meta.dir, "..", "node_modules", "spdx-license-ids");
    const current = JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as string[];
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
    // to the could-be-copyleft imprecise lane, never a guessed id.
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
      expect(result.source).toBe(klass === "corrected" ? "corrected" : "generator");
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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBe("GPL-3.0-or-later");
  });

  test("a BSD OS package renders a real permissive license", () => {
    const entry = pkg("libbsd0", "0.11", [claim("BSD-3-clause", "name")]);

    expect(annotateFindings(modelOf(entry), []).model.packages[0]!.finding!.expression).toBe(
      "BSD-3-Clause",
    );
  });

  test("all-or-nothing unknown invariant intact: an Expat sibling next to a genuinely-unknown token stays unknown", () => {
    // libmd-style: BSD ids + a bare "AND"/"Public Domain" split keeps it unknown.
    const entry = pkg("aom-libs", "3.13.1", [
      claim("BSD-2-Clause", "spdx-id"),
      claim("AND", "name"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    // "custom" is genuinely unknown → the whole row is correctly unknown.
    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
  });

  test("a proper CycloneDX expression claim is ingested whole, not split (multi-token finding)", () => {
    // syft emits real multi-license deb packages as a single `expression` claim
    // (SbomExpressionClaim, tried first in licenseClaimsOf). It must normalize as
    // one expression — never split into name tokens that force the row unknown.
    const entry = pkg("font-pkg", "1.0", [claim("FTL OR GPL-2.0-or-later", "expression")]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBe("MIT");
    expect(finding.unrecognizedTokens).toEqual(["custom", "public-domain"]);
  });

  test("os ZERO-normalizable (only public-domain) stays unknown (expression null)", () => {
    const entry = osPkg("os-none", "1.0", [
      claim("public-domain", "name"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
  });

  test("INVARIANT: app-scope [GPL-2.0-only, custom] still yields unknown (all-or-nothing intact)", () => {
    const entry = pkg("app-mixed", "1.0", [
      claim("GPL-2.0-only", "spdx-id"),
      claim("custom", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("INVARIANT: app-scope [MIT, custom] still yields unknown (no gate weakening)", () => {
    const entry = pkg("app-mit-custom", "1.0", [claim("MIT", "spdx-id"), claim("custom", "name")]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBeNull();
    expect(finding.confidence).toBe("none");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("os all-normalizable (no unknown token) → no unrecognizedTokens field", () => {
    const entry = osPkg("os-clean", "1.0", [
      claim("MIT", "spdx-id"),
      claim("BSD-3-Clause", "spdx-id"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("BSD");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("os partial preserves the RAW unknown token verbatim (not a normalized form)", () => {
    const entry = osPkg("os-raw", "1.0", [
      claim("MIT", "spdx-id"),
      claim("  Weird Custom Name  ", "name"),
    ]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;
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
    const entry = osPkg("os-mit-and", "1.0", [claim("MIT", "spdx-id"), claim("AND", "name")]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.expression).toBe("MIT");
    expect(finding.unrecognizedTokens).toBeUndefined();
  });

  test("#3/#10: a connective token in APP scope does not force unknown either", () => {
    const entry = pkg("app-mit-and", "1.0", [claim("MIT", "spdx-id"), claim("AND", "name")]);
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

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
    const finding = annotateFindings(modelOf(entry), []).model.packages[0]!.finding!;

    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
    expect(finding.unrecognizedTokens).toEqual(["some-custom-token"]);
  });
});
