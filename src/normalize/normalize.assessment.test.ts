import { describe, expect, test } from "bun:test";

import { claim, pkg, osPkg, modelOf } from "../../test/normalizeTestSupport";
import { asRawLicense, canon, widen } from "../../test/brandTestSupport";
import { annotateFindings, applyScancodeAssessment, type ClarifyInput } from "./normalize";
import type {
  LicenseClaim,
  LicenseClaimKind,
  LicenseFinding,
  PackageEntry,
} from "../model/dependencies";

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
): LicenseClaim => ({ raw: asRawLicense(raw), kind, source });

/** A scancode-sourced claim (the assessment trigger). */
const scancodeClaim = (raw: string): LicenseClaim => sourcedClaim(raw, "scancode", "expression");

describe("annotateFindings — scancode senior assessment (the re-pinned fill matrix)", () => {
  test("row 1 (vacuous agreement): zero-claim package + a precise scancode claim — the assessment IS the finding, source scancode", () => {
    const entry = pkg("zero-claim-pkg", "1.0.0", [scancodeClaim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(widen(finding.expression)).toBe("MIT");
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
      kind: "scancode",
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

    expect(widen(finding.expression)).toBe("BSD-3-Clause");
    expect(finding.confidence).toBe("exact");
    expect(finding.impreciseFamily).toBeUndefined();
    expect(finding.source).toBe("scancode");
    expect(finding.conflict).toBeUndefined();
  });

  test("row 4 (re-pinned, the flagship conflict): imprecise GPL family + scancode MIT — the copyleft signal STANDS and the disagreement is surfaced as a conflict", () => {
    const entry = pkg("imprecise-gpl-pkg", "1.0.0", [claim("GPL", "name"), scancodeClaim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(finding.confidence).toBe("imprecise");
    expect(finding.impreciseFamily).toBe("GPL");
    expect(finding.expression).toBeNull();
    expect(finding.conflict).toEqual({
      kind: "scancode",
      assessed: "MIT",
      disagreeing: ["GPL"],
    });
  });

  test("row 5: a scancode claim that itself normalizes imprecise (bare family raw) leaves the same-family imprecise base unchanged, no conflict", () => {
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

  test("an imprecise assessment never conflicts with an imprecise base, even out-of-family — nothing precise on either side to weigh", () => {
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
      kind: "scancode",
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
    expect(widen(finding.expression)).toBe("LGPL-2.1-only");
    expect(finding.confidence).toBe("exact");
    expect(finding.conflict).toEqual({
      kind: "scancode",
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
      kind: "scancode",
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
      {
        name: "imprecise-clarified-pkg",
        detected: { registry: "BSD", intensive: "BSD-3-Clause" },
        expression: canon("MIT"),
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(widen(finding.expression)).toBe("MIT");
  });

  test("seniority (formerly never-override): a PRECISE declared claim agreeing with the assessment yields the scancode-sourced finding — the in-depth assessment outranks the quick check", () => {
    const entry = pkg("agreeing-precise-pkg", "1.0.0", [claim("MIT"), scancodeClaim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(widen(finding.expression)).toBe("MIT");
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
    expect(widen(finding.expression)).toBe("Apache-2.0 AND MIT");
    expect(finding.source).not.toBe("scancode");
    expect(finding.conflict).toEqual({
      kind: "scancode",
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

    expect(widen(finding.expression)).toBe("MIT");
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
    const equalFinding = annotateFindings(modelOf(equal), []).model.packages[0]!.finding!;

    // Canonical (compareCodeUnits-sorted) reading, not claim-as-written order.
    expect(widen(equalFinding.expression)).toBe("Apache-2.0 AND MIT");
    expect(equalFinding.source).toBe("scancode");
    expect(equalFinding.conflict).toBeUndefined();

    const differing = pkg("compound-differing-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("MIT AND Apache-2.0"),
    ]);
    const differingFinding = annotateFindings(modelOf(differing), []).model.packages[0]!.finding!;

    expect(differingFinding.source).not.toBe("scancode");
    expect(differingFinding.conflict).toEqual({
      kind: "scancode",
      assessed: "Apache-2.0 AND MIT",
      disagreeing: ["MIT"],
    });
  });

  test("canonical agreement: a declared compound claim spelled differently from the assessment still agrees — both sides canonicalize before the exact-equality check, so spelling alone never creates a conflict", () => {
    const agreeing = pkg("canonical-agree-pkg", "1.0.0", [
      claim("MIT AND CC0-1.0", "expression"),
      scancodeClaim("CC0-1.0 AND MIT"),
    ]);
    const agreeingFinding = annotateFindings(modelOf(agreeing), []).model.packages[0]!.finding!;

    expect(agreeingFinding.source).toBe("scancode");
    expect(widen(agreeingFinding.expression)).toBe("CC0-1.0 AND MIT");
    expect(agreeingFinding.conflict).toBeUndefined();

    const differing = pkg("canonical-disagree-pkg", "1.0.0", [
      claim("MIT AND ISC", "expression"),
      scancodeClaim("CC0-1.0 AND MIT"),
    ]);
    const differingFinding = annotateFindings(modelOf(differing), []).model.packages[0]!.finding!;

    expect(differingFinding.source).not.toBe("scancode");
    expect(differingFinding.conflict).toEqual({
      kind: "scancode",
      assessed: "CC0-1.0 AND MIT",
      disagreeing: ["ISC AND MIT"],
    });
  });

  test("imprecise assessment vs an out-of-family PRECISE base (C2 copyleft): the base stands and the disagreement is a conflict — an imprecise answer never upgrades or absorbs", () => {
    const entry = pkg("imprecise-scan-vs-copyleft-pkg", "1.0.0", [
      claim("GPL-3.0-only"),
      scancodeClaim("Apache"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(widen(finding.expression)).toBe("GPL-3.0-only");
    expect(finding.confidence).toBe("exact");
    expect(finding.conflict).toEqual({
      kind: "scancode",
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

    expect(widen(finding.expression)).toBe("GPL-3.0-only");
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

    expect(widen(finding.expression)).toBe("MIT");
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
      kind: "scancode",
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
      {
        name: "conflicted-clarified-pkg",
        detected: { registry: "Apache-2.0", intensive: "MIT" },
        expression: canon("MIT"),
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(widen(finding.expression)).toBe("MIT");
    expect(finding.conflict).toBeUndefined();
    expect(finding.staleOverride).toBeUndefined();
  });

  test("a STALE clarify override keeps the base finding, which carries BOTH markers — stale + conflict coexist (chain ordering is the policy engine's concern)", () => {
    const entry = pkg("stale-conflicted-pkg", "1.0.0", [claim("Apache-2.0"), scancodeClaim("MIT")]);
    const clarify: ClarifyInput[] = [
      { name: "stale-conflicted-pkg", detected: { registry: "BSD" }, expression: canon("MIT") },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.staleOverride).toBeDefined();
    expect(finding.conflict).toEqual({
      kind: "scancode",
      assessed: "MIT",
      disagreeing: ["Apache-2.0"],
    });
  });

  test("resolution: an entry recording BOTH lanes settles the disagreement and drops the marker (worked example: registry MIT vs an in-depth BSD-3-Clause)", () => {
    const entry = pkg("guarded-clarified-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("BSD-3-Clause"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "guarded-clarified-pkg",
        detected: { registry: "MIT", intensive: "BSD-3-Clause" },
        expression: canon("BSD-3-Clause"),
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(widen(finding.expression)).toBe("BSD-3-Clause");
    expect(finding.conflict).toBeUndefined();
    expect(finding.staleOverride).toBeUndefined();
  });

  test("a REGISTRY-ONLY entry applies but does NOT settle the disagreement — the marker survives, so the gate keeps asking", () => {
    // The entry says nothing about what the in-depth scan reports, so it is not
    // a decision between the two sources: recording one lane cannot silence a
    // disagreement between both.
    const entry = pkg("registry-only-clarified-pkg", "1.0.0", [
      claim("MIT"),
      scancodeClaim("BSD-3-Clause"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "registry-only-clarified-pkg",
        detected: { registry: "MIT" },
        expression: canon("MIT AND BSD-3-Clause"),
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(widen(finding.expression)).toBe("BSD-3-Clause AND MIT");
    expect(finding.conflict).toEqual({
      kind: "scancode",
      assessed: "BSD-3-Clause",
      disagreeing: ["MIT"],
    });
  });

  test("deny visibility: a scancode win never drops the quick-check members from observedExpressions — a denied license present only in a non-scancode claim stays visible to the deny terminal", () => {
    const entry = pkg("deny-visible-pkg", "1.0.0", [
      claim("BUSL-1.1 OR MIT", "expression"),
      scancodeClaim("MIT"),
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("scancode");
    expect(widen(finding.expression)).toBe("MIT");
    expect(widen(finding.observedExpressions!)).toContain("BUSL-1.1 OR MIT");
  });
});

/** A docker occurrence (see osPkg) carrying a merge-time cross-image claim divergence marker. */
const dockerPkgWithDivergence = (
  name: string,
  version: string,
  byTarget: ReadonlyArray<{ target: string; claims: readonly string[] }>,
): PackageEntry => ({
  ...osPkg(name, version, []),
  occurrences: byTarget.map((t) => ({
    target: t.target,
    isDevDependency: false,
  })),
  dockerClaimDivergence: { kind: "cross-image-claims", byTarget },
});

describe("annotateFindings — cross-image claim divergence overlay", () => {
  test("a package carrying dockerClaimDivergence and no scancode conflict surfaces it as finding.conflict, and the merge-only field is stripped from the entry", () => {
    const entry = dockerPkgWithDivergence("busybox", "1.37.0-r20", [
      { target: "docker:image-a", claims: ["MIT"] },
      { target: "docker:image-b", claims: ["Apache-2.0"] },
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const resultEntry = model.packages[0]!;

    expect(resultEntry.finding!.conflict).toEqual({
      kind: "cross-image-claims",
      byTarget: [
        { target: "docker:image-a", claims: ["MIT"] },
        { target: "docker:image-b", claims: ["Apache-2.0"] },
      ],
    });
    expect(resultEntry).not.toHaveProperty("dockerClaimDivergence");
  });

  test("no divergence recorded → finding.conflict stays undefined (a repo with no docker inputs is unaffected)", () => {
    const entry = pkg("no-divergence-pkg", "1.0.0", [claim("MIT")]);
    const { model } = annotateFindings(modelOf(entry), []);

    expect(model.packages[0]!.finding!.conflict).toBeUndefined();
  });

  test("a ScanCode assessment conflict takes the conflict slot over a co-present cross-image divergence — the in-depth ScanCode assessment wins the shared slot", () => {
    const entry: PackageEntry = {
      ...dockerPkgWithDivergence("both-conflicts-pkg", "1.0.0", [
        { target: "docker:image-a", claims: ["MIT"] },
        { target: "docker:image-b", claims: ["Apache-2.0"] },
      ]),
      licenseClaims: [claim("Apache-2.0"), scancodeClaim("MIT")],
    };
    const { model } = annotateFindings(modelOf(entry), []);
    const conflict = model.packages[0]!.finding!.conflict!;

    expect(conflict.kind).toBe("scancode");
  });

  test("resolution: a [[clarify]] override on a cross-image conflict decides the finding and clears the marker — same resolution path as a ScanCode conflict", () => {
    const entry = dockerPkgWithDivergence("clarified-divergent-pkg", "1.0.0", [
      { target: "docker:image-a", claims: ["MIT"] },
      { target: "docker:image-b", claims: ["Apache-2.0"] },
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "clarified-divergent-pkg",
        detected: { registry: false, intensive: false },
        expression: canon("MIT"),
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(widen(finding.expression)).toBe("MIT");
    expect(finding.conflict).toBeUndefined();
  });

  test("an image with no declared claim is carried losslessly in the marker as an empty claims array, never dropped", () => {
    const entry = dockerPkgWithDivergence("partial-claim-pkg", "1.0.0", [
      { target: "docker:image-a", claims: [] },
      { target: "docker:image-b", claims: ["MIT"] },
    ]);
    const { model } = annotateFindings(modelOf(entry), []);
    const conflict = model.packages[0]!.finding!.conflict!;

    expect(conflict.kind).toBe("cross-image-claims");
    if (conflict.kind === "cross-image-claims") {
      expect(conflict.byTarget).toEqual([
        { target: "docker:image-a", claims: [] },
        { target: "docker:image-b", claims: ["MIT"] },
      ]);
    }
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
    expect(widen(a.expression)).toBe("BSD-3-Clause");
    expect(a.source).toBe("scancode");
  });

  test("no scancode claim: the base finding is returned unchanged — the identical reference, not a copy (byte-identity for scancode-free inputs)", () => {
    const claims = [claim("MIT"), claim("Apache-2.0")];

    expect(applyScancodeAssessment(claims, impreciseBsdBase)).toBe(impreciseBsdBase);
  });

  test("a genuinely-unknown scancode raw assesses nothing — base returned unchanged, defensively (the election rejects these upstream)", () => {
    const claims = [claim("MIT"), scancodeClaim("who knows")];

    expect(applyScancodeAssessment(claims, impreciseBsdBase)).toBe(impreciseBsdBase);
  });
});
