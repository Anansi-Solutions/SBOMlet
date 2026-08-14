import { describe, expect, test } from "bun:test";

import { classifyLeaf, type TargetLicense } from "../src/policy/compat/classify";

const oss = (id: string): TargetLicense => ({ kind: "oss", id });
const proprietary: TargetLicense = { kind: "proprietary" };

describe("classifyLeaf - OSS target, matrix tier", () => {
  test("GPL-3.0-only target absorbs MIT (OSADL: Yes)", () => {
    const result = classifyLeaf(oss("GPL-3.0-only"), "MIT");

    expect(result).toEqual({ class: "compatible", source: "OSADL: Yes", obligation: "none" });
  });

  test("MIT target rejects GPL-3.0-only (OSADL: No)", () => {
    const result = classifyLeaf(oss("MIT"), "GPL-3.0-only");

    expect(result.class).toBe("incompatible");
    expect(result.source).toBe("OSADL: No");
    expect(result.obligation).toBe("copyleft");
  });

  test("target diagonal is compatible (OSADL: Same)", () => {
    const result = classifyLeaf(oss("GPL-3.0-only"), "GPL-3.0-only");

    expect(result.class).toBe("compatible");
    expect(result.source).toBe("OSADL: Same");
  });

  test("GPL-2.0-only x Apache-2.0 is incompatible with obligation none (the internal-hold floor case)", () => {
    const result = classifyLeaf(oss("GPL-2.0-only"), "Apache-2.0");

    expect(result).toEqual({ class: "incompatible", source: "OSADL: No", obligation: "none" });
  });

  test("Unknown cell (0BSD -> MS-PL) is residual naming OSADL: Unknown", () => {
    const result = classifyLeaf(oss("0BSD"), "MS-PL");

    expect(result.class).toBe("residual");
    expect(result.source).toBe("OSADL: Unknown");
  });

  test("Check dependency cell routes to residual naming the cell value verbatim (A4)", () => {
    const result = classifyLeaf(oss("GPL-3.0-only"), "AGPL-3.0-only");

    expect(result.class).toBe("residual");
    expect(result.source).toBe("OSADL: Check dependency");
  });
});

describe("classifyLeaf - AGPL absorption (the section-13 pairs the scope principle protects)", () => {
  test("AGPL-3.0-only target x AGPL-3.0-only leaf is compatible (Same)", () => {
    const result = classifyLeaf(oss("AGPL-3.0-only"), "AGPL-3.0-only");

    expect(result).toEqual({ class: "compatible", source: "OSADL: Same", obligation: "agpl" });
  });

  test("the GPL-3.0-only x AGPL-3.0-only mutual-clause pair pins the ACTUAL live matrix cells", () => {
    // Live data (verified at implementation time): both directions are "Check dependency", not a
    // clean "Yes" - the engine follows the vetted cell whatever it says, never assumes absorption.
    const gplTargetAgplLeaf = classifyLeaf(oss("GPL-3.0-only"), "AGPL-3.0-only");
    const agplTargetGplLeaf = classifyLeaf(oss("AGPL-3.0-only"), "GPL-3.0-only");

    expect(gplTargetAgplLeaf).toEqual({
      class: "residual",
      source: "OSADL: Check dependency",
      obligation: "agpl",
    });
    expect(agplTargetGplLeaf).toEqual({
      class: "residual",
      source: "OSADL: Check dependency",
      obligation: "copyleft",
    });
  });

  test("MIT target x AGPL-3.0-only leaf is incompatible, obligation agpl", () => {
    const result = classifyLeaf(oss("MIT"), "AGPL-3.0-only");

    expect(result).toEqual({ class: "incompatible", source: "OSADL: No", obligation: "agpl" });
  });
});

describe("classifyLeaf - orientation lock (the transposition tripwire on the ENGINE)", () => {
  test("GPL-3.0-only target x MIT leaf is compatible AND the reverse is incompatible", () => {
    expect(classifyLeaf(oss("GPL-3.0-only"), "MIT").class).toBe("compatible");
    expect(classifyLeaf(oss("MIT"), "GPL-3.0-only").class).toBe("incompatible");
  });
});

describe("classifyLeaf - OSS target, fallback tiers (leaf or target not a matrix row)", () => {
  test("OSADL class No is compatible when the target is not itself a matrix row", () => {
    const result = classifyLeaf(oss("CC0-1.0"), "MIT");

    expect(result.class).toBe("compatible");
    expect(result.source).toBe("OSADL copyleft class: No");
  });

  test("OSADL class Yes/Yes (restricted)/Questionable never fail for an OSS target - residual only", () => {
    expect(classifyLeaf(oss("CC0-1.0"), "GPL-2.0-only").class).toBe("residual");
    expect(classifyLeaf(oss("CC0-1.0"), "LGPL-2.1-only").class).toBe("residual");
    expect(classifyLeaf(oss("CC0-1.0"), "MS-PL").class).toBe("residual");
  });

  test("ScanCode Permissive/Public Domain is compatible - CC0-1.0 as a LEAF classifies compatible whichever tier catches it", () => {
    const result = classifyLeaf(oss("MIT"), "CC0-1.0");

    expect(result.class).toBe("compatible");
    expect(result.source).toBe("ScanCode LicenseDB: Public Domain");
  });

  test("ScanCode anything else is residual for an OSS target - SSPL-1.0 (Source-available)", () => {
    const result = classifyLeaf(oss("MIT"), "SSPL-1.0");

    expect(result.class).toBe("residual");
    expect(result.obligation).toBe("copyleft");
  });

  test("uncovered by every dataset: a COPYLEFT_IDS member is residual, a non-member is compatible", () => {
    const member = classifyLeaf(oss("MIT"), "GPL-2.0-with-bison-exception");
    const nonMember = classifyLeaf(oss("MIT"), "Made-Up-Fictional-License-1.0");

    expect(member).toEqual({
      class: "residual",
      source: "SBOMlet's literal copyleft set (no vetted compatibility data)",
      obligation: "copyleft",
    });
    expect(nonMember).toEqual({
      class: "compatible",
      source: "not a known copyleft license",
      obligation: "none",
    });
  });
});

describe("classifyLeaf - tier order observable", () => {
  test("MS-PL (OSADL Questionable) never falls through to ScanCode's permissive-looking category", () => {
    const result = classifyLeaf(oss("CC0-1.0"), "MS-PL");

    expect(result.class).toBe("residual");
    expect(result.source).toBe("OSADL copyleft class: Questionable");
  });
});

describe("classifyLeaf - proprietary target", () => {
  test("permissive is compatible", () => {
    const result = classifyLeaf(proprietary, "MIT");

    expect(result).toEqual({
      class: "compatible",
      source: "OSADL copyleft class: No",
      obligation: "none",
    });
  });

  test("weak copyleft (Yes (restricted)) is boundary - LGPL-2.1-only and MPL-2.0", () => {
    expect(classifyLeaf(proprietary, "LGPL-2.1-only").class).toBe("boundary");
    expect(classifyLeaf(proprietary, "MPL-2.0").class).toBe("boundary");
  });

  test("strong copyleft (Yes) is incompatible, obligation copyleft - GPL-2.0-only", () => {
    const result = classifyLeaf(proprietary, "GPL-2.0-only");

    expect(result.class).toBe("incompatible");
    expect(result.obligation).toBe("copyleft");
  });

  test("network copyleft (Yes) is incompatible, obligation agpl - AGPL-3.0-only", () => {
    const result = classifyLeaf(proprietary, "AGPL-3.0-only");

    expect(result.class).toBe("incompatible");
    expect(result.obligation).toBe("agpl");
  });

  test("Questionable is residual - MS-PL", () => {
    expect(classifyLeaf(proprietary, "MS-PL").class).toBe("residual");
  });

  test("a WITH exception changes the class - Classpath moves GPL-2.0-only from Yes to boundary", () => {
    const result = classifyLeaf(proprietary, "GPL-2.0-only WITH Classpath-exception-2.0");

    expect(result.class).toBe("boundary");
    expect(result.source).toBe("OSADL copyleft class: Yes (restricted)");
  });

  test("ScanCode tier: Copyleft Limited is boundary, Copyleft is incompatible, Permissive is compatible", () => {
    expect(classifyLeaf(proprietary, "CDL-1.0").class).toBe("boundary");
    expect(classifyLeaf(proprietary, "APL-1.0").class).toBe("incompatible");
    expect(classifyLeaf(proprietary, "MIT").class).toBe("compatible");
  });

  test("literal-set tier: a COPYLEFT_IDS member is residual, a non-member is compatible", () => {
    const member = classifyLeaf(proprietary, "GPL-2.0-with-bison-exception");
    const nonMember = classifyLeaf(proprietary, "Made-Up-Fictional-License-1.0");

    expect(member.class).toBe("residual");
    expect(nonMember.class).toBe("compatible");
  });
});

describe("classifyLeaf - WITH handling and deprecated plus forms", () => {
  test("exact rendered WITH key decides first (the matrix's one WITH row)", () => {
    const result = classifyLeaf(oss("MIT"), "GPL-2.0-only WITH Classpath-exception-2.0");

    expect(result.class).toBe("incompatible");
    expect(result.source).toBe("OSADL: No");
  });

  test("an unmatched WITH leaf falls back to the base id's class - never a throw", () => {
    expect(() => classifyLeaf(proprietary, "MIT WITH Some-Fictional-Exception")).not.toThrow();

    const result = classifyLeaf(proprietary, "MIT WITH Some-Fictional-Exception");

    expect(result.class).toBe("compatible");
  });

  test("a plus leaf (GPL-2.0+) falls back to the base id through the fallback tiers - never a throw", () => {
    expect(() => classifyLeaf(oss("GPL-2.0-or-later"), "GPL-2.0+")).not.toThrow();

    const result = classifyLeaf(oss("GPL-2.0-or-later"), "GPL-2.0+");

    expect(result).toEqual({
      class: "residual",
      source: "ScanCode LicenseDB: Copyleft",
      obligation: "copyleft",
    });
  });
});

describe("classifyLeaf - ref leaves", () => {
  test("a LicenseRef-scancode-* id present in the matrix uses its cell", () => {
    const result = classifyLeaf(oss("MIT"), "LicenseRef-scancode-bsla-no-advert");

    expect(result.class).toBe("compatible");
    expect(result.source).toBe("OSADL: Yes");
  });

  test("any other LicenseRef-/DocumentRef- leaf is unassessed-ref, obligation unknown", () => {
    expect(classifyLeaf(oss("MIT"), "LicenseRef-some-vendor-custom").class).toBe("unassessed-ref");
    expect(classifyLeaf(oss("MIT"), "LicenseRef-some-vendor-custom").obligation).toBe("unknown");
    expect(classifyLeaf(proprietary, "DocumentRef-spdx-tool-1:LicenseRef-foo").class).toBe(
      "unassessed-ref",
    );
  });

  test("unassessed-ref is never silently compatible via the literal-set tier", () => {
    const result = classifyLeaf(oss("MIT"), "LicenseRef-not-in-any-dataset");

    expect(result.class).not.toBe("compatible");
    expect(result.class).toBe("unassessed-ref");
  });
});

describe("classifyLeaf - purity and determinism", () => {
  test("identical inputs produce an identical result across repeated calls", () => {
    const first = classifyLeaf(oss("GPL-3.0-only"), "MIT");
    const second = classifyLeaf(oss("GPL-3.0-only"), "MIT");

    expect(first).toEqual(second);
  });
});
