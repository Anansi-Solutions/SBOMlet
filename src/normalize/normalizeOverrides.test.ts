import { describe, expect, test } from "bun:test";

import { BUILTIN_OVERRIDES } from "../policy/engine/builtinOverrides";
import { claim, pkg, modelOf } from "../../test/normalizeTestSupport";
import { annotateFindings, type ClarifyInput, type BuiltinOverrideInput } from "./normalize";

describe("annotateFindings — clarify overrides", () => {
  test("matching name+version replaces the finding with source override", () => {
    const entry = pkg("@img/sharp-win32-x64", "0.34.5", [
      claim("Apache-2.0 AND LGPL-3.0-or-later", "expression"),
    ]);
    const clarify: ClarifyInput[] = [
      {
        name: "@img/sharp-win32-x64",
        version: "0.34.5",
        detected: { registry: "Apache-2.0 AND LGPL-3.0-or-later" },
        expression: "Apache-2.0",
      },
    ];
    const { model, usedClarifyIndices } = annotateFindings(modelOf(entry), clarify);
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
      {
        name: "@img/sharp-win32-x64",
        version: "9.9.9",
        detected: { registry: "Apache-2.0 AND LGPL-3.0-or-later" },
        expression: "MIT",
      },
    ];
    const { model, usedClarifyIndices } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("generator");
    expect(finding.expression).toBe("Apache-2.0 AND LGPL-3.0-or-later");
    expect(usedClarifyIndices.size).toBe(0);
  });

  test("version-less clarify matches any version of the named package", () => {
    const entry = pkg("jsonify", "0.0.1", [claim("Public Domain", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jsonify", detected: { registry: "Public Domain" }, expression: "Unlicense" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(modelOf(entry), clarify);

    expect(model.packages[0]!.finding!.expression).toBe("Unlicense");
    expect(model.packages[0]!.finding!.source).toBe("override");
    expect(usedClarifyIndices.has(0)).toBe(true);
  });
});

// ===========================================================================
// Staleness-guarded two-level override chain in annotateFindings.
// ===========================================================================

describe("annotateFindings — staleness-guarded clarify", () => {
  test("a recorded registry detection matching the imprecise-BSD signal APPLIES the disambiguation", () => {
    const entry = pkg("jupyter-thing", "1.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jupyter-thing", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
    expect(usedClarifyIndices.has(0)).toBe(true);
  });

  test("a recorded detection matching a raw claim string APPLIES (raw-string signal member)", () => {
    const entry = pkg("dateutil-ish", "1.0.0", [claim("Dual License", "name")]);
    const clarify: ClarifyInput[] = [
      {
        name: "dateutil-ish",
        detected: { registry: "Dual License" },
        expression: "Apache-2.0 OR BSD-3-Clause",
      },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("Apache-2.0 OR BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });

  test("STALE: registry recorded BSD but the package now reports GPL-3.0 → not applied, staleOverride recorded", () => {
    const entry = pkg("relicensed", "2.0.0", [claim("GPL-3.0-only")]);
    const clarify: ClarifyInput[] = [
      { name: "relicensed", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    // The stale BSD-3-Clause assertion is NOT applied — the real finding stands.
    expect(finding.source).not.toBe("override");
    expect(finding.expression).toBe("GPL-3.0-only");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("clarify");
    expect(finding.staleOverride!.source).toBe("registry");
    expect(finding.staleOverride!.expected).toBe("BSD");
    expect(finding.staleOverride!.observed).toContain("GPL-3.0-only");
  });

  test("a recorded detection is matched case-insensitively and trimmed", () => {
    const entry = pkg("ci-pkg", "1.0.0", [claim("BSD", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "ci-pkg", detected: { registry: "  bsd  " }, expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);

    expect(model.packages[0]!.finding!.expression).toBe("BSD-3-Clause");
  });

  test("a non-SPDX registry value recorded verbatim still satisfies the precondition", () => {
    const entry = pkg("jsonify", "0.0.1", [claim("Public Domain", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "jsonify", detected: { registry: "Public Domain" }, expression: "Unlicense" },
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
    { name: "ipython", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
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
      { name: "ipython", detected: { registry: "BSD" }, expression: "MIT" },
    ];
    const { model, usedClarifyIndices } = annotateFindings(modelOf(entry), clarify, jupyterBuiltin);
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

    expect(() => annotateFindings(modelOf(entry), [], jupyterBuiltin)).not.toThrow();
  });
});

// ===========================================================================
// C1 (corrections): the staleness guard must FAIL CLOSED when an obsolete
// signal member (the one the entry recorded) coexists with a NEW precise claim
// that contradicts the asserted expression. A lingering label must never
// license-out a co-present precise copyleft claim: matching the recorded
// detections alone is fail-OPEN.
// ===========================================================================

describe("annotateFindings — staleness fails CLOSED on a contradicting co-claim (C1)", () => {
  test("stale BSD label + new precise GPL claim → fail closed, NOT applied (shipped ipython builtin)", () => {
    // The canonical relicense-metadata-lag case: PyPI still carries the old
    // "BSD" classifier while a new precise "GPL-3.0-only" id has appeared. The
    // shipped ipython BUILTIN_OVERRIDES entry must NOT mask the GPL.
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name"), claim("GPL-3.0-only", "spdx-id")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("builtin");
    expect(finding.staleOverride!.unaccounted).toBe("GPL-3.0-only");
  });

  test("clean case: BSD alone still applies BSD-3-Clause (shipped ipython builtin)", () => {
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });

  test("GPL alone (no lingering BSD) still fails closed (control)", () => {
    const entry = pkg("ipython", "8.0.0", [claim("GPL-3.0-only", "spdx-id")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
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
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name"), claim("BSD-3-Clause", "spdx-id")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
  });
});

// ===========================================================================
// GAP FIX: when the registry UPGRADES the imprecise label
// to the EXACT precise license the override asserts, the override is REDUNDANT
// — NOT stale. The recorded "BSD" is no longer in the signal (the dep now
// reports precise "BSD-3-Clause"), but the observed precise finding already
// SATISFIES the asserted expression, so nothing is masked: the observed finding
// must stand unchanged and the gate must NOT fail. A relicense to a license that
// does NOT satisfy the assertion still fails closed.
// ===========================================================================

describe("annotateFindings — redundant override when metadata catches up (gap fix)", () => {
  test("REDUNDANT: precise BSD-3-Clause observed, a recorded BSD asserts BSD-3-Clause → finding stays, NOT stale (live ipython false-positive)", () => {
    // The exact live case: modern PyPI reports ipython with the PRECISE
    // license_expression "BSD-3-Clause" — no bare "BSD" classifier — so the
    // shipped override recording "BSD" no longer matches the signal. But the
    // observed precise license is IDENTICAL to what the override asserts.
    const entry = pkg("ipython", "9.10.0", [claim("BSD-3-Clause", "spdx-id")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.source).not.toBe("override"); // observed finding stands
    expect(finding.staleOverride).toBeUndefined(); // NOT a false-positive stale
  });

  test("REDUNDANT covers the whole now-precise Jupyter stack (ipykernel, jupyter-core)", () => {
    const ipykernel = pkg("ipykernel", "7.2.0", [claim("BSD-3-Clause", "spdx-id")]);
    const jupyterCore = pkg("jupyter-core", "5.9.1", [claim("BSD-3-Clause", "spdx-id")]);
    const { model } = annotateFindings(modelOf(ipykernel, jupyterCore), [], [...BUILTIN_OVERRIDES]);

    for (const p of model.packages) {
      expect(p.finding!.expression).toBe("BSD-3-Clause");
      expect(p.finding!.staleOverride).toBeUndefined();
    }
  });

  test("STALE: precise MIT observed, a recorded BSD asserts BSD-3-Clause → fail (MIT does not satisfy BSD-3-Clause)", () => {
    const entry = pkg("relicensed-permissive", "2.0.0", [claim("MIT", "spdx-id")]);
    const clarify: ClarifyInput[] = [
      {
        name: "relicensed-permissive",
        detected: { registry: "BSD" },
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

  test("STALE: precise GPL-3.0-only observed, a recorded BSD asserts BSD-3-Clause → fail (relicense to copyleft)", () => {
    const entry = pkg("relicensed-copyleft", "2.0.0", [claim("GPL-3.0-only", "spdx-id")]);
    const clarify: ClarifyInput[] = [
      {
        name: "relicensed-copyleft",
        detected: { registry: "BSD" },
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

  test("the C1 masking case STILL fails closed (the recorded BSD is present + a co-present GPL contradicts)", () => {
    // Regression guard: the gap fix must not reopen C1. Here the recorded value
    // IS in the signal, so the redundant path is never consulted; the
    // unaccounted-license guard fires.
    const entry = pkg("ipython", "8.0.0", [claim("BSD", "name"), claim("GPL-3.0-only", "spdx-id")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("builtin");
  });

  test("the normal disambiguation case STILL applies (observed imprecise BSD, recorded BSD)", () => {
    // Regression guard: the gap fix must not break the imprecise→precise path.
    const entry = pkg("traitlets", "5.0.0", [claim("BSD License", "name")]);
    const { model } = annotateFindings(modelOf(entry), [], [...BUILTIN_OVERRIDES]);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });
});

// ===========================================================================
// The staleness sweep and the imprecise member. A bare family label appearing
// beside a still-matching recorded value carries a real license statement -
// "this is somewhere in the AGPL family" - even though it names no exact
// license. Skipping it let a clarify entry absorb an appended copyleft label
// and hand the package back as the permissive licence it used to be.
// ===========================================================================

describe("annotateFindings — an imprecise member the assertion cannot account for", () => {
  const OLD_SIGNAL_ONLY: ClarifyInput[] = [
    { name: "family-appended", detected: { registry: "MIT" }, expression: "MIT" },
  ];

  test("control: with no entry at all, the appended AGPL label reaches the finding", () => {
    const entry = pkg("family-appended", "1.0.0", [claim("MIT"), claim("AGPL", "name")]);
    const { model } = annotateFindings(modelOf(entry), []);
    const finding = model.packages[0]!.finding!;

    expect(finding.expression).not.toBe("MIT");
  });

  test("an entry recording only the old signal goes stale on the appended family label", () => {
    const entry = pkg("family-appended", "1.0.0", [claim("MIT"), claim("AGPL", "name")]);
    const { model } = annotateFindings(modelOf(entry), OLD_SIGNAL_ONLY);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("clarify");
    expect(finding.staleOverride!.unaccounted).toBe("AGPL");
  });

  test("control: the same label spelled precisely goes stale exactly as it always did", () => {
    const entry = pkg("family-appended", "1.0.0", [claim("MIT"), claim("AGPL-3.0-only")]);
    const { model } = annotateFindings(modelOf(entry), OLD_SIGNAL_ONLY);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride!.unaccounted).toBe("AGPL-3.0-only");
  });

  test("the disambiguation case is untouched: a recorded BSD label still upgrades to BSD-3-Clause", () => {
    const entry = pkg("disambiguated", "1.0.0", [claim("BSD License", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "disambiguated", detected: { registry: "BSD" }, expression: "BSD-3-Clause" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("BSD-3-Clause");
    expect(finding.staleOverride).toBeUndefined();
  });

  test("a member naming no family at all is now UNACCOUNTED - a proprietary claim contradicts a permissive assertion", () => {
    const entry = pkg("unreadable-label", "1.0.0", [
      claim("MIT"),
      claim("Some Proprietary Thing", "name"),
    ]);
    const clarify: ClarifyInput[] = [
      { name: "unreadable-label", detected: { registry: "MIT" }, expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.unaccounted).toBe("Some Proprietary Thing");
  });
});

// ===========================================================================
// H1: a null-expression member that names no family - a proprietary/UNLICENSED
// marker, or any other genuinely-unknown claim - is NOT recorded in the entry
// and contradicts a permissive assertion. Skipping it let a clarify hand a
// proprietary package back as the permissive licence it never was. The base
// combiner poisons the whole finding to unknown on such a claim; the override
// must fail closed the same way.
// ===========================================================================

describe("annotateFindings — a null-expression member naming no family (H1)", () => {
  test("a newly-appeared UNLICENSED claim beside MIT goes STALE, not licensed out as MIT", () => {
    const entry = pkg("proprietary-slipped-in", "1.0.0", [claim("MIT"), claim("UNLICENSED")]);
    const clarify: ClarifyInput[] = [
      { name: "proprietary-slipped-in", detected: { registry: "MIT" }, expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
    expect(finding.staleOverride!.level).toBe("clarify");
    expect(finding.staleOverride!.unaccounted).toBe("UNLICENSED");
  });

  test("a bare Proprietary marker beside MIT goes STALE the same way", () => {
    const entry = pkg("proprietary-marker", "1.0.0", [claim("MIT"), claim("Proprietary", "name")]);
    const clarify: ClarifyInput[] = [
      { name: "proprietary-marker", detected: { registry: "MIT" }, expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    expect(finding.source).not.toBe("override");
    expect(finding.staleOverride).toBeDefined();
  });

  test("a null-expression member the entry RECORDED is still accounted (no regression)", () => {
    const entry = pkg("recorded-unlicensed", "1.0.0", [claim("MIT"), claim("UNLICENSED")]);
    const clarify: ClarifyInput[] = [
      { name: "recorded-unlicensed", detected: { registry: "UNLICENSED" }, expression: "MIT" },
    ];
    const { model } = annotateFindings(modelOf(entry), clarify);
    const finding = model.packages[0]!.finding!;

    // A recorded UNLICENSED is not a NEW claim - the guard skips it, and the MIT the assertion
    // covers is accounted, so the override applies cleanly.
    expect(finding.source).toBe("override");
    expect(finding.expression).toBe("MIT");
    expect(finding.staleOverride).toBeUndefined();
  });
});
