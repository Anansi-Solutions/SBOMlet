import { describe, expect, test } from "bun:test";
import {
  annotateFindings,
  normalizeRaw,
  type BuiltinOverrideInput,
} from "../../normalize/normalize";
import { parsePolicy } from "../parse/parse";
import { PolicyError } from "../schema/diagnostics";
import {
  WITHOUT_DEPENDENCY_GRAPHS,
  licenseRuleFixture,
  compatiblePackageFixture,
  makeModel,
  osPkgSpec,
  pkgSpec,
  scanPkgSpec,
  runEngineWith,
  runEngine,
  runEngineWithImports,
  SUPPRESS_SCRATCH,
  crossImagePkgSpec,
  TARGET_A,
  TARGET_B,
  TARGET_A_EXTRA,
  TARGET_A_PREFIX,
  scopedBusyboxPolicy,
  scopedGplPolicy,
  busyboxAt,
  ACCEPTANCE_POLICY,
  DEV_PROD_COPYLEFT,
  DEV_PROD_UNKNOWN,
  denyLicenseFixture,
  denyNameFixture,
  multiClaimSpec,
  OS_COPYLEFT,
  OS_UNKNOWN,
  osMultiSpec,
  type PackageSpec,
} from "../../../test/policyTestSupport";
import { AGPL_IDS, COPYLEFT_IDS } from "./copyleft";
import { denyRuleFor } from "./deny";
import {
  acceptedContainerNotices,
  evaluate,
  unnecessaryClarifyEntries,
  unusedRuleIds,
} from "./evaluate";
import { COULD_BE_COPYLEFT_FAMILIES, WORKSPACE_ABSORBS } from "./copyleftFamily";
import type { Policy } from "../schema";
import type {
  CanonicalDependencies,
  DependencyIntroduction,
  LicenseFinding,
  SpdxExpression,
  Verdict,
} from "../../model/dependencies";

describe("evaluate — a [[compatible]] entry covering a family of packages", () => {
  test("HEADLINE: one pattern entry accepts every matching package, each citing the same entry", () => {
    const policyText = compatiblePackageFixture([
      'pattern = "@img/sharp-*"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const { verdicts } = runEngine(
      [
        pkgSpec("@img/sharp-win32-x64", "LGPL-3.0-or-later", ["backend"]),
        pkgSpec("@img/sharp-linux-arm64", "LGPL-3.0-or-later", ["backend"]),
      ],
      policyText,
    );

    for (const verdict of verdicts) {
      expect(verdict.status).toBe("ok");
      expect(verdict.rule).toBe("compatible[0]");
    }

    expect(verdicts[0].reason).toContain('package "@img/sharp-*@1.0.0, 2.0.0"');
    expect(verdicts[0].reason).toContain("license-reviewed");
  });

  test("a package outside the pattern still fails — the entry covers the family, not the model", () => {
    const policyText = compatiblePackageFixture([
      'pattern = "@img/sharp-*"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const { verdicts } = runEngine(
      [pkgSpec("@other/lib", "LGPL-3.0-or-later", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("a version list accepts exactly the versions it names, and nothing else", () => {
    const policyText = compatiblePackageFixture([
      'name = "pinned-copyleft"',
      'version = ["1.0.0", "2.0.0"]',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ]);
    const covered = runEngine(
      [pkgSpec("pinned-copyleft", "LGPL-3.0-or-later", ["backend"], "2.0.0")],
      policyText,
    ).verdicts;
    const uncovered = runEngine(
      [pkgSpec("pinned-copyleft", "LGPL-3.0-or-later", ["backend"], "3.0.0")],
      policyText,
    ).verdicts;

    expect(covered[0].rule).toBe("compatible[0]");
    expect(covered[0].reason).toContain('"pinned-copyleft@1.0.0, 2.0.0"');
    expect(uncovered[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — `as-dependency-of` is recorded, not yet enforced", () => {
  // The list is parsed, validated, and carried onto the rule, and it does not
  // narrow which occurrences the entry decides: the introduction-path walk that
  // reads it lands separately. This test states that gap explicitly so the walk
  // has a place to change when it arrives.
  test("a parent that governs nothing in the model still accepts the package", () => {
    const policyText = compatiblePackageFixture([
      'name = "governed-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["a-package-nothing-depends-on"]',
      'rationale = "unused-transitive"',
      'where = ["/"]',
    ]);
    const { verdicts, policy } = runEngine(
      [pkgSpec("governed-pkg", "LGPL-3.0-or-later", ["backend"])],
      policyText,
    );

    expect(policy.compatible[0]).toMatchObject({
      asDependencyOf: ["a-package-nothing-depends-on"],
    });
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });
});

describe("evaluate — a [[compatible]] `packages` list bundling disparate packages", () => {
  const bundlePolicy = compatiblePackageFixture([
    'packages = [{ name = "alpha-lib", version = "1.0.0" }, { name = "omega-lib", version = "2.5.0" }]',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    'where = ["/"]',
  ]);

  test("an occurrence matching a NON-first member is accepted, citing the one entry", () => {
    const { verdicts } = runEngine(
      [pkgSpec("omega-lib", "LGPL-3.0-or-later", ["backend"], "2.5.0")],
      bundlePolicy,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(verdicts[0].reason).toContain('"omega-lib@2.5.0"');
  });

  test("a member matches only at its pinned version — a version it does not name still fails", () => {
    const { verdicts } = runEngine(
      [pkgSpec("omega-lib", "LGPL-3.0-or-later", ["backend"], "9.9.9")],
      bundlePolicy,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — precedence chain", () => {
  test("compatible(package) beats compatible(license) beats suppression on one package", () => {
    // One MPL-2.0 package matched SIMULTANEOUSLY by compatible[0]
    // (match="package") and compatible[1] (match="license"), occurring in a
    // suppressed workspace: the package rule decides.
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "mpl-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])], policyText);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });
});

describe("evaluate — satisfies-based compatible(license) matching", () => {
  test("exact ID: finding MPL-2.0 vs allowlist [MPL-2.0] is ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["backend"])],
      licenseRuleFixture("MPL-2.0"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("range semantics: GPL-3.0-only satisfies allowlist [GPL-2.0-or-later]", () => {
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["backend"])],
      licenseRuleFixture("GPL-2.0-or-later"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("AND needs all: Apache-2.0 AND LGPL-3.0-or-later vs [Apache-2.0] falls to default:copyleft", () => {
    const { verdicts } = runEngine(
      [pkgSpec("sharp-ish", "Apache-2.0 AND LGPL-3.0-or-later", ["backend"])],
      licenseRuleFixture("Apache-2.0"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — segment-aware suppression", () => {
  test("apps/scratch and apps/scratch/sub suppress; apps/scratch-helper FAILS", () => {
    // Substring matching would wrongly suppress apps/scratch-helper.
    const { verdicts } = runEngine(
      [
        pkgSpec("agpl-pkg", "AGPL-3.0-only", [
          "apps/scratch-helper",
          "apps/scratch/sub",
          "apps/scratch",
        ]),
      ],
      SUPPRESS_SCRATCH,
    );

    // compareCodeUnits order on occurrenceTarget: "-" (0x2D) sorts before "/" (0x2F).
    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "suppressed", "workspace.copyleft_suppressed[0]"],
      ["apps/scratch-helper", "fail", "default:copyleft"],
      ["apps/scratch/sub", "suppressed", "workspace.copyleft_suppressed[0]"],
    ]);
  });
});

describe("evaluate — family-aware suppression", () => {
  test("same-license dep is suppressed; the reason states the satisfies relationship", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
    expect(verdicts[0].reason).toContain(
      'elected "AGPL-3.0-only" satisfies the workspace license AGPL-3.0-only',
    );
  });

  test("GPL and LGPL deps are suppressed under an AGPL workspace (GNU family)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("gpl-pkg", "GPL-2.0-only", ["apps/scratch"]),
        pkgSpec("lgpl-pkg", "LGPL-3.0-or-later", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => v.status)).toEqual(["suppressed", "suppressed"]);
    // The audit-trail reason states the VERIFIED relationship, never an
    // unverified in-family assertion.
    expect(verdicts[0].reason).toContain("same GNU family as the workspace license AGPL-3.0-only");
  });

  test("AND expressions suppress when every copyleft leaf is in-family", () => {
    // The sharp-win32 shape: Apache-2.0 AND LGPL-3.0-or-later — the only
    // copyleft obligation (LGPL) is GNU-family under the AGPL workspace.
    const { verdicts } = runEngine(
      [pkgSpec("sharp-ish", "Apache-2.0 AND LGPL-3.0-or-later", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
  });

  test("out-of-family copyleft under the suppressed path falls through to default:copyleft", () => {
    // CC-BY-SA is out-of-family copyleft; SSPL is now a source-available deny default: a path match alone must
    // never suppress them — that would assert a legally false in-family
    // justification.
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["apps/scratch"]),
        pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:source-available"],
    ]);
  });

  test("mixed AND with an out-of-family copyleft leaf is NOT suppressed", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mixed-pkg", "LGPL-3.0-or-later AND CC-BY-SA-4.0", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

// ===========================================================================
// Revision F: apps/scratch absorbs ALL bundled strong copyleft — an AGPL-3.0
// (GNU-family) workspace absorbs inbound-compatible weaker copyleft (MPL) in
// ADDITION to its own family (GNU). The safety floor (SSPL/CC-BY-SA), the deny
// terminal, directionality, and the GPL-prod-outside-suppression scope are all
// regression-guarded here.
// ===========================================================================

describe("WORKSPACE_ABSORBS — literal absorption relation", () => {
  test("the GNU family absorbs exactly GNU and MPL (the bundled inbound set)", () => {
    const gnu = WORKSPACE_ABSORBS.get("GNU");

    expect(gnu).toBeDefined();
    expect([...(gnu ?? [])].sort()).toEqual(["GNU", "MPL"]);
  });

  test("the GNU absorbed set NEVER includes the safety-floor families (SSPL/CC-BY-SA)", () => {
    const gnu = WORKSPACE_ABSORBS.get("GNU");

    expect(gnu?.has("SSPL")).toBe(false);
    expect(gnu?.has("CC-BY-SA")).toBe(false);
  });

  test("no non-GNU workspace family declares an absorption set (directional, scoped)", () => {
    expect([...WORKSPACE_ABSORBS.keys()]).toEqual(["GNU"]);
  });
});

describe("evaluate — absorb-all-copyleft suppression", () => {
  test("an AGPL workspace now SUPPRESSES an MPL-2.0 finding (was: fell through to fail)", () => {
    // Without absorption this fell through to default:copyleft (MPL is a
    // different family from GNU). apps/scratch re-releases bundled MPL files
    // under AGPL, so it absorbs them.
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
    // The audit-trail reason names the absorption, not an in-family assertion.
    expect(verdicts[0].reason).toContain("absorbed by the GNU workspace license");
  });

  test("it STILL suppresses GPL-3.0 and LGPL (exact-family regression intact)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("gpl-pkg", "GPL-3.0-only", ["apps/scratch"]),
        pkgSpec("lgpl-pkg", "LGPL-3.0-or-later", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => v.status)).toEqual(["suppressed", "suppressed"]);
    // The same-family path keeps its "same GNU family" wording.
    expect(verdicts[0].reason).toContain("same GNU family as the workspace license AGPL-3.0-only");
  });

  test("it STILL does NOT suppress SSPL-1.0 or CC-BY-SA (the safety floor)", () => {
    // CC-BY-SA falls to copyleft (out-of-family); SSPL-1.0 is now a source-available deny default — both prove the floor (neither is suppressed).
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["apps/scratch"]),
        pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"]),
      ],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:source-available"],
    ]);
  });

  test("a DENIED license under the scratch path still FAILS (deny terminal beats suppression)", () => {
    // SSPL-1.0 is both copyleft AND on the deny list: the deny terminal sits
    // ABOVE suppression, so even if it were in the absorbed set it would fail.
    const policyText = [
      "[[deny]]",
      'match = "license"',
      'pattern = "SSPL-1.0"',
      'reason = "source-available; cannot ship"',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("sspl-pkg", "SSPL-1.0", ["apps/scratch"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("absorption is DIRECTIONAL: a non-AGPL (MPL) workspace does NOT absorb GNU-family GPL", () => {
    // WORKSPACE_ABSORBS declares no MPL key, so an MPL-distributed workspace
    // absorbs only its own license via branch (a) (satisfies), never GNU.
    const mplWorkspace = [
      "[[workspace.copyleft_suppressed]]",
      'path = "apps/scratch"',
      'license = "MPL-2.0"',
      'description = "hypothetical MPL-distributed workspace"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["apps/scratch"])],
      mplWorkspace,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("W2 GUARD: a GPL-3.0 PRODUCTION occurrence under a NON-suppressed workspace still FAILS default:copyleft", () => {
    // The absorb-all widening must NOT leak outside the declared suppressed
    // path. A GPL-3.0 prod dep under backend/ (not suppressed) stays a hard
    // fail — assert the EXACT verdict so the scope is proven.
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "GPL-3.0-only", ["backend"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].occurrenceTarget).toBe("backend");
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — election gates the copyleft flag", () => {
  test("(MIT OR GPL-3.0-or-later) elects MIT → default:ok with ZERO policy rules", () => {
    const { verdicts } = runEngine(
      [pkgSpec("or-pkg", "(MIT OR GPL-3.0-or-later)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("(GPL-2.0-only OR GPL-3.0-only) cannot avoid copyleft → fail without a rule", () => {
    const { verdicts } = runEngine(
      [pkgSpec("gpl-pkg", "(GPL-2.0-only OR GPL-3.0-only)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — CR-01 copyleft families reach default:copyleft", () => {
  test("CC-BY-SA-4.0, Sleepycat, and GFDL-1.3-only packages fail (no more silent default:ok)", () => {
    const { verdicts } = runEngine(
      [
        pkgSpec("cc-sa-pkg", "CC-BY-SA-4.0", ["backend"]),
        pkgSpec("gfdl-pkg", "GFDL-1.3-only", ["backend"]),
        pkgSpec("sleepycat-pkg", "Sleepycat", ["backend"]),
      ],
      "",
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
    ]);
  });

  test("OR-with-permissive still elects the permissive branch for the new ids", () => {
    const { verdicts } = runEngine([pkgSpec("dual-pkg", "(CC-BY-SA-4.0 OR MIT)", ["backend"])], "");

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });
});

describe("evaluate — copyleft dominates a permissive sibling end-to-end (C2/W2)", () => {
  const multi = (name: string, claims: ReadonlyArray<string>): PackageSpec => ({
    purl: `pkg:npm/${name}@1.0.0`,
    name,
    version: "1.0.0",
    claims,
    occurrences: ["backend"],
  });

  test("C2: imprecise permissive + precise copyleft → default:copyleft fail (not a non-gating warn)", () => {
    const { verdicts } = runEngine(
      [
        multi("apache-plus-agpl", ["Apache", "AGPL-3.0-only"]),
        multi("bsd-plus-gpl", ["BSD", "GPL-3.0-only"]),
      ],
      "",
    );

    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["fail", "default:copyleft"],
      ["fail", "default:copyleft"],
    ]);
  });

  test("W2: two conflicting imprecise families route to default:imprecise-copyleft order-independently", () => {
    const { verdicts } = runEngine(
      [
        multi("bsd-then-gpl", ["BSD License", "GPL"]),
        multi("gpl-then-bsd", ["GPL", "BSD License"]),
      ],
      "",
    );

    // Both packages, regardless of claim order, reach the could-be-copyleft
    // review lane — never the non-gating default:imprecise.
    expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
      ["warn", "default:imprecise-copyleft"],
      ["warn", "default:imprecise-copyleft"],
    ]);
  });
});

// ===========================================================================
// Imprecise findings + the could-be-copyleft literal token set.
// ===========================================================================

describe("COULD_BE_COPYLEFT_FAMILIES — literal token set", () => {
  test("contains the bare GNU-family copyleft tokens", () => {
    expect(COULD_BE_COPYLEFT_FAMILIES.has("GPL")).toBe(true);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("AGPL")).toBe(true);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("LGPL")).toBe(true);
  });

  test("does NOT contain permissive family tokens (BSD/Apache/MIT)", () => {
    expect(COULD_BE_COPYLEFT_FAMILIES.has("BSD")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("Apache")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("MIT")).toBe(false);
  });

  test("deliberately excludes the weak-copyleft family tokens (MPL/EPL/CDDL)", () => {
    // These are gated on the EXPRESSION path via COPYLEFT_FAMILY; an imprecise
    // finding never reaches it, and no producing path emits a bare MPL/EPL/CDDL
    // family token, so adding them would be untested dead data.
    expect(COULD_BE_COPYLEFT_FAMILIES.has("MPL")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("EPL")).toBe(false);
    expect(COULD_BE_COPYLEFT_FAMILIES.has("CDDL")).toBe(false);
  });

  test("contains EUPL — the copyleft family correct() cross-maps to permissive (W1)", () => {
    // "EUPL" → spdx-correct → UPL-1.0 (permissive). Intercepting it as the
    // imprecise copyleft family routes it to the could-be-copyleft review lane
    // instead of a silent default:ok.
    expect(COULD_BE_COPYLEFT_FAMILIES.has("EUPL")).toBe(true);
  });

  test("is exactly the four-token set", () => {
    expect([...COULD_BE_COPYLEFT_FAMILIES].sort()).toEqual(["AGPL", "EUPL", "GPL", "LGPL"]);
  });
});

describe("evaluate — imprecise findings route to a safe lane", () => {
  test("a permissive imprecise family (BSD) gets a non-gating default:imprecise status", () => {
    const { verdicts } = runEngine([pkgSpec("jinja2-ish", "BSD License", ["frontend"])], "");

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).toBe("default:imprecise");
    // The signal must be visible — not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("an imprecise BSD family is NOT copyleft-flagged and NOT a hard fail in a non-suppressed workspace", () => {
    const { verdicts } = runEngine([pkgSpec("bsd-pkg", "BSD", ["backend"])], "");

    expect(verdicts[0].rule).not.toBe("default:copyleft");
    expect(verdicts[0].status).not.toBe("fail");
  });

  test("a could-be-copyleft imprecise family (GPL) is flagged for review, never silently passed", () => {
    const { verdicts } = runEngine([pkgSpec("gpl-ish", "GPL", ["backend"])], "");

    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // Not the permissive lane and not a silent default:ok.
    expect(verdicts[0].rule).not.toBe("default:imprecise");
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare EUPL routes to default:imprecise-copyleft, never a silent default:ok (W1)", () => {
    const { verdicts } = runEngine([pkgSpec("eupl-pkg", "EUPL", ["backend"])], "");

    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
    expect(verdicts[0].status).not.toBe("ok");
    // The masking this kills: EUPL → UPL-1.0 (permissive) → default:ok.
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test("bare imprecise AGPL and LGPL are likewise flagged for review (the WARNING-2 regression)", () => {
    for (const token of ["AGPL", "LGPL"]) {
      const { verdicts } = runEngine([pkgSpec(`${token}-ish`, token, ["backend"])], "");

      expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
      expect(verdicts[0].status).not.toBe("ok");
      // The regression this kills: a COPYLEFT_FAMILY.get("GPL") lookup returns
      // undefined and would mis-route it to the permissive lane.
      expect(verdicts[0].rule).not.toBe("default:imprecise");
    }
  });

  test("the engine never throws on an imprecise finding (no spdx-satisfies on a null expression)", () => {
    const impreciseFinding: LicenseFinding = {
      expression: null,
      elected: null,
      source: "registry",
      confidence: "imprecise",
      impreciseFamily: "GPL",
    };
    const model: CanonicalDependencies = {
      packages: [
        {
          purl: "pkg:pypi/imp@1.0.0",
          name: "imp",
          version: "1.0.0",
          occurrences: [{ target: "backend", isDevDependency: false }],
          licenseClaims: [],
          scope: "app",
          finding: impreciseFinding,
        },
      ],
    };

    expect(() => evaluate(model, parsePolicy(""), WITHOUT_DEPENDENCY_GRAPHS)).not.toThrow();
    const verdicts = evaluate(model, parsePolicy(""), WITHOUT_DEPENDENCY_GRAPHS);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });

  test("an imprecise finding is NOT governed by the unknown knob (it is present, not unknown)", () => {
    // Under handling="fail", a genuinely unknown package fails; an imprecise
    // permissive family must NOT — it is present-but-needs-clarify.
    const { verdicts } = runEngine(
      [pkgSpec("bsd-pkg", "BSD", ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).toBe("default:imprecise");
  });
});

describe("evaluate — unknown handling knob", () => {
  test('zero-claim package warns under handling "warn" (the absent-table default)', () => {
    const { verdicts } = runEngine([pkgSpec("no-claims", null, ["backend"])], "");

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test('zero-claim package fails under handling "fail"', () => {
    const { verdicts } = runEngine(
      [pkgSpec("no-claims", null, ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });
});

describe("evaluate — per-occurrence verdicts", () => {
  test("copyleft package in a suppressed AND a non-suppressed target yields TWO verdicts", () => {
    const { verdicts } = runEngine(
      // Occurrence input order deliberately unsorted: output order must come
      // from the compareCodeUnits sort on (purl, occurrenceTarget).
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["backend", "apps/scratch"])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts).toHaveLength(2);
    expect(verdicts.map((v) => v.occurrenceTarget)).toEqual(["apps/scratch", "backend"]);
    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[1].status).toBe("fail");
    // Fail reasons MUST name the occurrence target AND the elected
    // expression — Phase-4 violation messages build on this.
    expect(verdicts[1].reason).toContain("backend");
    expect(verdicts[1].reason).toContain("AGPL-3.0-only");
    for (const v of verdicts) {
      expect(v.rule.length).toBeGreaterThan(0);
      expect(v.reason.length).toBeGreaterThan(0);
    }
  });
});

describe("evaluate — clarify usage visibility", () => {
  test("a clarified package falling through to ok cites clarify[0]", () => {
    const policyText = [
      "[[clarify]]",
      'name = "weird-pkg"',
      'version = "1.0.0"',
      'detected = { registry = "Public Domain" }',
      'justification = "license-not-found"',
      'expression = "MIT"',
      'comment = "upstream metadata is garbage; MIT confirmed in the repository"',
    ].join("\n");
    const { verdicts, usedClarifyIndices } = runEngine(
      [pkgSpec("weird-pkg", "Public Domain", ["backend"])],
      policyText,
    );

    expect(usedClarifyIndices.has(0)).toBe(true);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });
});

describe("evaluate — LicenseRef acceptance for commercial clarifies (A4/P-05)", () => {
  test("a [[clarify]] with a LicenseRef- expression on an honest-unknown pkg:maven component VALIDATES and the verdict cites clarify[0] with the LicenseRef expression", () => {
    const policyText = [
      "[[clarify]]",
      'name = "proprietary-reporting-engine"',
      'version = "9.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "LicenseRef-commercial-vendor-agreement"',
      'comment = "system-scoped commercial jar; the vendor agreement governs, not a public license"',
    ].join("\n");
    const spec: PackageSpec = {
      purl: "pkg:maven/com.example.vendor/proprietary-reporting-engine@9.0.0",
      name: "proprietary-reporting-engine",
      version: "9.0.0",
      claims: [], // the honest unknown: no registry presence, no POM license
      occurrences: ["backend"],
    };
    const { verdicts, usedClarifyIndices, policy } = runEngine([spec], policyText);

    expect(policy.clarify[0]?.expression).toBe(
      "LicenseRef-commercial-vendor-agreement" as SpdxExpression,
    );
    expect(usedClarifyIndices.has(0)).toBe(true);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].reason).toContain("LicenseRef-commercial-vendor-agreement");
  });

  test("a LicenseRef- expression inside a compound (LicenseRef-x OR MIT) is LOCKED to whatever the in-tree machinery already does — no compound handling is extended here", () => {
    const policyText = [
      "[[clarify]]",
      'name = "dual-ref-pkg"',
      'version = "1.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "LicenseRef-x OR MIT"',
      'comment = "dual: a proprietary ref or MIT, whichever the consumer prefers"',
    ].join("\n");
    const spec: PackageSpec = {
      purl: "pkg:maven/com.example/dual-ref-pkg@1.0.0",
      name: "dual-ref-pkg",
      version: "1.0.0",
      claims: [],
      occurrences: ["backend"],
    };
    const { verdicts } = runEngine([spec], policyText);

    // LOCKED: the OR election prefers the non-copyleft, non-ref branch
    // (normalize/expression.ts elect's LicenseRef/DocumentRef tie-break) —
    // MIT wins over the opaque LicenseRef- atom.
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("normalizeRaw NEVER mints a LicenseRef from free text — a commercial-sounding raw name stays an honest unknown, not a guessed LicenseRef", () => {
    const result = normalizeRaw("Commercial License Agreement");

    expect(result.expression).toBeNull();
  });
});

describe("evaluate — an unassessed LicenseRef never reaches default:ok (silent-pass fix)", () => {
  test("a bare LicenseRef-AGPL-3.0-only expression is NOT ok — it routes to the unknown lane, not default:ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-named-ref-pkg", "LicenseRef-AGPL-3.0-only", ["backend"])],
      "",
    );

    expect(verdicts[0].status).not.toBe("ok");
    expect(verdicts[0].rule).toBe("default:unknown");
    expect(verdicts[0].rule).not.toBe("default:ok");
  });

  test('the bare-ref package fails under [unknown] handling = "fail", exactly like a genuine unknown', () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-named-ref-pkg", "LicenseRef-AGPL-3.0-only", ["backend"])],
      '[unknown]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test("(MIT OR LicenseRef-x) still elects MIT and stays default:ok — the OR election is not regressed", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-or-ref-pkg", "(MIT OR LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("(MIT AND LicenseRef-x) carries unassessed ref content alongside a known conjunct — NOT a silent default:ok", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-and-ref-pkg", "(MIT AND LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).not.toBe("ok");
    expect(verdicts[0].rule).toBe("default:unknown");
  });

  test("a copyleft leaf ANDed with a ref still fails default:copyleft — copyleft is a stronger signal than the ref-unknown lane", () => {
    const { verdicts } = runEngine(
      [pkgSpec("agpl-and-ref-pkg", "(AGPL-3.0-only AND LicenseRef-x)", ["backend"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });
});

describe("evaluate — staleness-guarded overrides", () => {
  test("a tool-level override that decides a verdict cites override:builtin[i], not default:ok", () => {
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "ipython",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD", ["backend"])], "", builtins);

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
    expect(verdicts[0].rule).not.toBe("default:ok");
    expect(verdicts[0].reason).toContain("BSD-3-Clause");
  });

  test("HEADLINE: a stale BSD→BSD-3-Clause override on a now-GPL-3.0 dep FAILS naming pkg/expected/observed", () => {
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", ["backend"])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain("relicensed");
    expect(verdicts[0].reason).toContain("BSD"); // expected
    expect(verdicts[0].reason).toContain("GPL-3.0-only"); // now-observed
  });

  test("H1: a clarify cannot mask a newly-appeared UNLICENSED claim beside MIT (fail closed)", () => {
    const policyText = [
      "[[clarify]]",
      'name = "proprietary-slipped-in"',
      'version = "1.0.0"',
      'detected = { registry = "MIT" }',
      'justification = "declared-more-complete"',
      'expression = "MIT"',
    ].join("\n");
    const spec: PackageSpec = {
      purl: "pkg:npm/proprietary-slipped-in@1.0.0",
      name: "proprietary-slipped-in",
      version: "1.0.0",
      claims: ["MIT", "UNLICENSED"],
      occurrences: ["backend"],
    };
    const { verdicts } = runEngineWith(parsePolicy(policyText), [spec]);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("a stale project clarify also fails (level surfaced in the message)", () => {
    const policyText = [
      "[[clarify]]",
      'name = "relicensed"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("project clarify WINS over tool-level on conflict, end-to-end", () => {
    const policyText = [
      "[[clarify]]",
      'name = "ipython"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "project says MIT"',
    ].join("\n");
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "ipython",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD", ["backend"])], policyText, builtins);

    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].reason).toContain("project says MIT");
  });

  test("an imprecise finding with NO matching override stays imprecise+surfaced", () => {
    const { verdicts } = runEngine([pkgSpec("orphan-bsd", "BSD", ["backend"])], "", []);

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise");
  });

  test("REDUNDANT override (metadata caught up to a precise satisfying license) does NOT fail — observed finding stands ok (gap fix)", () => {
    // The live false-positive: PyPI now reports ipython precisely as
    // "BSD-3-Clause" (no bare "BSD"). The recorded "BSD" is absent from the
    // signal, but the observed precise license already satisfies the asserted
    // BSD-3-Clause — nothing is masked, so the gate must NOT fire override:stale.
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "ipython",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine([pkgSpec("ipython", "BSD-3-Clause", ["backend"])], "", builtins);

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toContain("override:stale");
  });

  test("a genuine relicense to a NON-satisfying license still FAILS override:stale (gap fix is fail-safe)", () => {
    // The recorded "BSD" is absent AND the observed precise license (MIT) does
    // not satisfy the asserted BSD-3-Clause → genuine drift → must fail closed.
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine([pkgSpec("relicensed", "MIT", ["backend"])], "", builtins);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("an OR-only expression applies while the recorded detection still holds", () => {
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "or-expression-pkg",
        detected: { registry: "MIT" },
        expression: "MIT OR Apache-2.0" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("or-expression-pkg", "MIT", ["backend"])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
    expect(verdicts[0].reason).toContain("MIT OR Apache-2.0");
  });
});

// ===========================================================================
// The per-source `detected` precondition at verdict level: which lane a
// recorded value is checked against, what `false` asserts, what a lane that
// has gone quiet does, and how the reason names each.
// ===========================================================================

describe("evaluate — per-source detected preconditions", () => {
  /** A [[clarify]] on `detected-pkg` recording exactly the given inline table. */
  const detectedClarify = (table: string, justification = "scan-more-precise"): string =>
    [
      "[[clarify]]",
      'name = "detected-pkg"',
      'version = "1.0.0"',
      `detected = ${table}`,
      `justification = "${justification}"`,
      'expression = "BSD-3-Clause"',
    ].join("\n");

  test("HEADLINE: a value is checked against ITS OWN lane — a registry value the intensive lane happens to report does not satisfy it", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", null, "BSD", ["backend"])],
      detectedClarify('{ registry = "BSD" }'),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("no current registry detection");
  });

  test("the same value recorded against the lane that reports it APPLIES", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", null, "BSD", ["backend"])],
      detectedClarify('{ intensive = "BSD" }'),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("`false` records that a lane reports nothing, and holds while it stays quiet", () => {
    const { verdicts } = runEngine(
      [pkgSpec("detected-pkg", "BSD", ["backend"])],
      detectedClarify('{ registry = "BSD", intensive = false }', "declared-more-complete"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a `false` record is PROVEN WRONG once that lane starts reporting, even when the new report AGREES — a source that has started speaking is evidence to read", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("detected-pkg", "BSD", "BSD-3-Clause", ["backend"])],
      detectedClarify('{ registry = "BSD", intensive = false }', "declared-more-complete"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("recorded no intensive detection");
    expect(verdicts[0].reason).toContain("BSD-3-Clause");
  });
});

// ===========================================================================
// Selecting a FAMILY of packages: one entry covers every name a pattern
// matches, and one entry covers several pinned versions. Both go through the
// shared matcher, so annotate and evaluate agree on which packages an entry
// governs.
// ===========================================================================

describe("evaluate — a [[clarify]] covering a family of packages", () => {
  const patternClarify = [
    "[[clarify]]",
    'pattern = "@dicts/*"',
    'version = "1.0.0"',
    'detected = { registry = "BSD" }',
    'justification = "scan-more-precise"',
    'expression = "BSD-3-Clause"',
  ].join("\n");

  test("HEADLINE: one pattern entry clarifies every matching package, each citing the same entry", () => {
    const { verdicts, usedClarifyIndices } = runEngine(
      [pkgSpec("@dicts/en", "BSD", ["backend"]), pkgSpec("@dicts/fr", "BSD", ["backend"])],
      patternClarify,
    );

    expect(usedClarifyIndices.has(0)).toBe(true);
    for (const verdict of verdicts) {
      expect(verdict.status).toBe("ok");
      expect(verdict.rule).toBe("clarify[0]");
      expect(verdict.reason).toContain("BSD-3-Clause");
    }
  });

  test("a package outside the pattern is untouched — the entry governs the family, not the model", () => {
    const { verdicts } = runEngine([pkgSpec("@other/en", "BSD", ["backend"])], patternClarify);

    expect(verdicts[0].rule).toBe("default:imprecise");
  });

  test("a version list covers exactly the versions it names, and nothing else", () => {
    const policyText = [
      "[[clarify]]",
      'name = "pinned-pkg"',
      'version = ["1.0.0", "2.0.0"]',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
    ].join("\n");
    const covered = runEngine(
      [pkgSpec("pinned-pkg", "BSD", ["backend"], "2.0.0")],
      policyText,
    ).verdicts;
    const uncovered = runEngine(
      [pkgSpec("pinned-pkg", "BSD", ["backend"], "3.0.0")],
      policyText,
    ).verdicts;

    expect(covered[0].rule).toBe("clarify[0]");
    expect(uncovered[0].rule).toBe("default:imprecise");
  });
});

// ===========================================================================
// The reason a cited entry surfaces: the closed-set value, and the comment
// after an em-dash when the entry carries one.
// ===========================================================================

describe("evaluate — the reason a cited [[clarify]] surfaces", () => {
  const citingClarify = (extra: ReadonlyArray<string>): string =>
    [
      "[[clarify]]",
      'name = "cited-pkg"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
      ...extra,
    ].join("\n");

  test("without a comment the reason is the justification value alone", () => {
    const { verdicts } = runEngine([pkgSpec("cited-pkg", "BSD", ["backend"])], citingClarify([]));

    expect(verdicts[0].reason).toContain("scan-more-precise");
    expect(verdicts[0].reason).not.toContain("—");
  });

  test("with a comment the reason is the value, an em-dash, then the comment", () => {
    const { verdicts } = runEngine(
      [pkgSpec("cited-pkg", "BSD", ["backend"])],
      citingClarify(['comment = "the LICENSE file carries the three-clause text"']),
    );

    expect(verdicts[0].reason).toContain(
      "scan-more-precise — the LICENSE file carries the three-clause text",
    );
  });
});

// ===========================================================================
// A COMPOUND recorded detection: an entry written against a multi-license
// (AND/OR) registry claim. Both sides of the lane comparison run through
// canonicalizeExpression (flatten, dedupe, absorb, sort) before the
// case-insensitive, trimmed comparison, so a registry re-spelling of the same
// license set - reordered operands, a duplicated conjunct, an absorbable
// branch - never reopens the entry. Only a genuine change to the license SET
// does. Modeled on the real spdx-ranges dogfood case: npm declares
// "(MIT AND CC-BY-3.0)", the in-depth scan reads only the root LICENSE and
// sees "MIT" - two lanes, one of which reports the compound the entry names.
// ===========================================================================

describe("evaluate — a compound recorded detection", () => {
  const compoundClaim = "(MIT AND CC-BY-3.0)";

  /** A [[clarify]] whose recorded registry value AND expression are the same compound claim. */
  const compoundClarify = [
    "[[clarify]]",
    'name = "compound-pkg"',
    'version = "1.0.0"',
    `detected = { registry = ${JSON.stringify(compoundClaim)}, intensive = "MIT" }`,
    'justification = "declared-more-complete"',
    `expression = ${JSON.stringify(compoundClaim)}`,
  ].join("\n");

  test("HEADLINE: a compound record APPLIES while the registry claim still matches, alongside a co-present in-depth claim", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("compound-pkg", compoundClaim, "MIT", ["backend"])],
      compoundClarify,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a genuine change to the license SET goes stale (fail closed), naming expected and now-observed — not merely a re-spelling", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("compound-pkg", "(MIT AND CC0-1.0)", "MIT", ["backend"])],
      compoundClarify,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain(compoundClaim); // expected
    expect(verdicts[0].reason).toContain("(MIT AND CC0-1.0)"); // now-observed
  });

  test("a re-spelling of the SAME license set — a parenthesized recorded value (the dogfood shape) against an unparenthesized, reordered claim — stays APPLIED — canonical comparison, not a stale trigger", () => {
    const respellClaim = "(MIT AND CC0-1.0)";
    const policyText = [
      "[[clarify]]",
      'name = "respelled-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(respellClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(respellClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("respelled-pkg", "CC0-1.0 AND MIT", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a genuine set change (MIT AND CC0-1.0 -> MIT AND Apache-2.0) still flags override:stale under canonical comparison", () => {
    const baseClaim = "MIT AND CC0-1.0";
    const policyText = [
      "[[clarify]]",
      'name = "set-changed-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(baseClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(baseClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("set-changed-pkg", "MIT AND Apache-2.0", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).toContain(baseClaim); // expected
    expect(verdicts[0].reason).toContain("MIT AND Apache-2.0"); // now-observed
  });

  test("a noisy-but-equal compound claim (duplicated conjunct, an absorbable OR branch) canonicalizes to the same set and stays APPLIED", () => {
    const baseClaim = "MIT AND CC0-1.0";
    const policyText = [
      "[[clarify]]",
      'name = "noisy-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(baseClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(baseClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("noisy-pkg", "MIT AND CC0-1.0 AND (MIT OR Apache-2.0)", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("an OR-compound expression also takes the literal-equality path (either half compound trips it)", () => {
    const orClaim = "(MIT OR Apache-2.0)";
    const policyText = [
      "[[clarify]]",
      'name = "or-compound-pkg"',
      'version = "1.0.0"',
      `detected = { registry = ${JSON.stringify(orClaim)}, intensive = "MIT" }`,
      'justification = "declared-more-complete"',
      `expression = ${JSON.stringify(orClaim)}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("or-compound-pkg", orClaim, "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("parsePolicy ACCEPTS a compound recorded detection — validation never restricts its shape", () => {
    const policy = parsePolicy(compoundClarify);

    expect(policy.clarify[0]?.detected.registry).toBe(compoundClaim);
  });
});

// ===========================================================================
// The conflict:scancode fail verdict. A ScanCode-vs-quick-check
// disagreement (marker set by applyScancodeAssessment) becomes a
// distinct fail in verdictFor, slotted directly below stale and ABOVE
// compatible. Fail-not-warn (human involvement is NECESSARY; a warn is
// ignorable). Exit 1 is automatic — a "fail" verdict is a violation in
// exitCodeFor's mapping (check.ts), no new machinery.
// ===========================================================================

describe("evaluate — conflict:scancode fail verdict", () => {
  test("HEADLINE: a scancode assessment disagreeing with a precise declared claim FAILS conflict:scancode, naming both sides and the clarify remedy", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "Apache-2.0", "MIT", ["backend"])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail"); // → exitCodeFor violation → exit 1
    expect(verdicts[0].rule).toBe("conflict:scancode");
    expect(verdicts[0].reason).toContain("disputed-pkg");
    expect(verdicts[0].reason).toContain("MIT"); // the in-depth assessment
    expect(verdicts[0].reason).toContain("Apache-2.0"); // the quick-check answer
    expect(verdicts[0].reason).toContain("[[clarify]]"); // the remedy
  });

  test("chain order: an entry with BOTH a stale override and a conflict fires override:stale FIRST (a stale override is strictly more urgent)", () => {
    const policyText = [
      "[[clarify]]",
      'name = "stale-and-conflicted"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("stale-and-conflicted", "Apache-2.0", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("chain order: a denied observed member AND a conflict fires deny FIRST (deny is terminal above every lane incl. conflict)", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("denied-and-conflicted", "BUSL-1.1", "MIT", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("chain order (inverse): a denied license the ScanCode assessment ITSELF surfaces, over a permissive declared answer, fires deny FIRST — the senior assessment can never license a denied member in, and a disagreement never downgrades a deny to a mere conflict", () => {
    // The mirror of the sibling above: here the DENIED license is the in-depth
    // ScanCode answer and the declared quick-check answer is permissive. The
    // assessment disagrees with the declared claim (a conflict marker is set),
    // but the denied member still reaches the deny terminal through
    // observedExpressions (every per-claim precise expression, the scancode
    // claim included), so deny fires above the conflict lane. A denied license
    // that only the deep scan detected can never be masked by the disagreement
    // being surfaced as a conflict rather than a deny.
    const { verdicts } = runEngine(
      [scanPkgSpec("scancode-denied", "MIT", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
    expect(verdicts[0].reason).toContain("BUSL-1.1");
  });

  test("placement ABOVE compatible: a conflict on a package whose base a compatible license rule would accept still FAILS conflict:scancode", () => {
    // base = "Apache-2.0 AND MIT" (the AND-combine of the declared claim and the
    // scancode claim); the compatible allowlist [Apache-2.0, MIT] satisfies it,
    // so WITHOUT the conflict slot this would pass compatible[0]. A disputed
    // answer must never be auto-absorbed by a compatible rule.
    const { verdicts } = runEngine(
      [scanPkgSpec("compat-but-disputed", "Apache-2.0", "MIT", ["backend"])],
      licenseRuleFixture("(Apache-2.0 OR MIT)"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("conflict:scancode");
  });

  test("no warn-bucket regression: a conflict is a fail, never a warn — and an AGREEING scancode assessment yields no conflict verdict at all", () => {
    const conflicted = runEngine(
      [scanPkgSpec("c-pkg", "Apache-2.0", "MIT", ["backend"])],
      "",
    ).verdicts;

    expect(conflicted.every((v) => v.status !== "warn")).toBe(true);

    // Agreement: scancode MIT corroborates declared MIT → scancode-sourced ok,
    // no conflict verdict, no warn.
    const agreed = runEngine([scanPkgSpec("agree-pkg", "MIT", "MIT", ["backend"])], "").verdicts;

    expect(agreed.every((v) => v.rule !== "conflict:scancode")).toBe(true);
    expect(agreed[0].status).toBe("ok");
  });
});

describe("evaluate — conflict:cross-image-claims fail verdict", () => {
  test("HEADLINE: two docker occurrences declaring different licenses FAILS conflict:cross-image-claims, naming every image and the clarify remedy", () => {
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("busybox", [
          { target: "docker:image-a", claims: ["MIT"] },
          { target: "docker:image-b", claims: ["Apache-2.0"] },
        ]),
      ],
      "",
    );

    expect(verdicts).toHaveLength(2); // one verdict per occurrence
    for (const v of verdicts) {
      expect(v.status).toBe("fail"); // → exitCodeFor violation → exit 1
      expect(v.rule).toBe("conflict:cross-image-claims");
      expect(v.reason).toContain("busybox");
      expect(v.reason).toContain("docker:image-a: MIT");
      expect(v.reason).toContain("docker:image-b: Apache-2.0");
      expect(v.reason).toContain("[[clarify]]"); // the remedy
    }
  });

  test("an image with no declared claim renders '(no declared license)' in the reason, never a blank", () => {
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("partial-claim-pkg", [
          { target: "docker:image-a", claims: [] },
          { target: "docker:image-b", claims: ["MIT"] },
        ]),
      ],
      "",
    );

    expect(verdicts[0].reason).toContain("docker:image-a: (no declared license)");
  });

  test("resolution: a [[clarify]] override APPLIES, clears the conflict, and the verdict is clarify[0] ok (exit 0) — the same remedy path as a ScanCode conflict", () => {
    const policyText = [
      "[[clarify]]",
      'name = "busybox"',
      'version = "1.0.0"',
      "detected = { registry = false, intensive = false }",
      'justification = "license-not-found"',
      'expression = "MIT"',
      'comment = "reviewed: image-a is correct"',
    ].join("\n");
    const { verdicts } = runEngine(
      [
        crossImagePkgSpec("busybox", [
          { target: "docker:image-a", claims: ["MIT"] },
          { target: "docker:image-b", claims: ["Apache-2.0"] },
        ]),
      ],
      policyText,
    );

    for (const v of verdicts) {
      expect(v.status).toBe("ok");
      expect(v.rule).toBe("clarify[0]");
      expect(v.rule).not.toBe("conflict:cross-image-claims");
    }
  });

  test("without a clarify, the divergence stays a fail deterministically across repeated runs (no flapping)", () => {
    const spec = [
      crossImagePkgSpec("busybox", [
        { target: "docker:image-a", claims: ["MIT"] },
        { target: "docker:image-b", claims: ["Apache-2.0"] },
      ]),
    ];
    const a = runEngine(spec, "").verdicts;
    const b = runEngine(spec, "").verdicts;

    expect(a).toEqual(b);
    expect(a.every((v) => v.rule === "conflict:cross-image-claims")).toBe(true);
  });
});

// ===========================================================================
// The [[clarify]] resolution path, end to end. The
// conflict machinery (the marker and verdict above) is cleared by a
// human decision recorded as a clarify override — the "documented
// resolution path" the docs describe. Worked example:
// the declared/registry quick check reads MIT; the in-depth ScanCode assessment
// reads BSD-3-Clause. These are verdict-level proofs; the annotate-level marker
// semantics are locked in normalize.test.ts.
// ===========================================================================

describe("evaluate — conflict:scancode resolution via [[clarify]]", () => {
  // The human's recorded call: "the quick check reads MIT, the in-depth scan
  // reads BSD-3-Clause, and I decide the scan is right." Both sources still
  // report what the entry recorded, and recording the intensive source is what
  // settles the disagreement, so the override APPLIES and the conflict is gone.
  const clarifyResolvesToScancode = [
    "[[clarify]]",
    'name = "disputed-pkg"',
    'version = "1.0.0"',
    'detected = { registry = "MIT", intensive = "BSD-3-Clause" }',
    'justification = "scan-more-precise"',
    'expression = "BSD-3-Clause"',
  ].join("\n");

  test("HEADLINE: a [[clarify]] recording the decision APPLIES, clears the conflict, and the verdict is clarify[0] ok (exit 0) — never a lingering conflict:scancode", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "MIT", "BSD-3-Clause", ["backend"])],
      clarifyResolvesToScancode,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok"); // → exit 0
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(verdicts[0].rule).not.toBe("conflict:scancode");
  });

  test("an APPLIED override never lets a conflict marker survive into a fail — the resolved package yields no conflict verdict, deterministically across repeated runs (no permanent, un-clearable fail)", () => {
    const run = (): Verdict[] =>
      runEngine(
        [scanPkgSpec("disputed-pkg", "MIT", "BSD-3-Clause", ["backend"])],
        clarifyResolvesToScancode,
      ).verdicts;
    const a = run();
    const b = run();

    expect(a).toEqual(b);
    expect(a.every((v) => v.rule !== "conflict:scancode")).toBe(true);
    expect(a[0].status).toBe("ok");
  });

  test("the stale guard reopens it: after the registry relicenses away from the recorded expectation, the SAME clarify FAILS override:stale (the guard works both ways with zero new machinery)", () => {
    // The registry answer has moved from MIT to GPL-3.0-only, so the recorded
    // registry detection no longer holds, and the standing base (GPL-3.0-only)
    // does not satisfy the asserted BSD-3-Clause → the override is stale, fail
    // closed, and fires above the co-present conflict.
    const { verdicts } = runEngine(
      [scanPkgSpec("disputed-pkg", "GPL-3.0-only", "BSD-3-Clause", ["backend"])],
      clarifyResolvesToScancode,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
  });

  test("determinism: a conflict with NO clarify stays a conflict:scancode fail across repeated runs — same rule, byte-identical reason (no flapping)", () => {
    const run = (): Verdict[] =>
      runEngine([scanPkgSpec("unresolved-pkg", "Apache-2.0", "MIT", ["backend"])], "").verdicts;
    const a = run();
    const b = run();

    expect(a).toEqual(b); // byte-identical verdict incl. reason
    expect(a[0].status).toBe("fail");
    expect(a[0].rule).toBe("conflict:scancode");
  });
});

describe("unusedRuleIds — stale-policy hygiene", () => {
  test("unused compatible and clarify entries are reported; suppressions never are", () => {
    const policyText = [
      // Unused suppression entry — must NOT be reported (only compatible and
      // clarify entries participate in stale-policy detection).
      SUPPRESS_SCRATCH,
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "never-matches"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[clarify]]",
      'name = "never-clarified"',
      'version = "1.0.0"',
      'detected = { registry = "MIT" }',
      'justification = "scan-overdetection"',
      'expression = "MIT"',
      'comment = "no package by this name exists"',
    ].join("\n");
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", ["backend"])],
      policyText,
    );

    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([
      "compatible[1]",
      "clarify[0]",
    ]);
  });
});

describe("evaluate — where-scoped compatible matching", () => {
  test("package form: scoped rule cited ONLY at its target; segment-aware; other occurrences fall to default:copyleft", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B, TARGET_A_EXTRA])],
      scopedBusyboxPolicy([TARGET_A]),
    );

    // compareCodeUnits order: .../a/Dockerfile, .../a/Dockerfile-extra,
    // .../b/Dockerfile. Out-of-scope occurrences fall to default:copyleft,
    // os-downgraded to warn ([os_dependencies] defaults to "warn").
    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_A_EXTRA, "warn", "default:copyleft"],
      [TARGET_B, "warn", "default:copyleft"],
    ]);
  });

  test("license form: same matrix", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B, TARGET_A_EXTRA])],
      scopedGplPolicy([TARGET_A]),
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_A_EXTRA, "warn", "default:copyleft"],
      [TARGET_B, "warn", "default:copyleft"],
    ]);
  });

  test("a prefix scope matches every target under it as a whole segment and the prefix itself (both forms)", () => {
    for (const policyText of [
      scopedBusyboxPolicy([TARGET_A_PREFIX]),
      scopedGplPolicy([TARGET_A_PREFIX]),
    ]) {
      const { verdicts } = runEngine(
        [busyboxAt([TARGET_A, TARGET_A_EXTRA, TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
      ]);
    }
  });

  test("FAIL-SAFE direction: a scope never matches a SHORTER target above it (both forms)", () => {
    // The reverse comparison: the scope docker:a/Dockerfile is LONGER than the
    // target docker:a — a broader occurrence must never satisfy a narrower
    // scope, or an acceptance reviewed for one image would leak upward.
    for (const policyText of [scopedBusyboxPolicy([TARGET_A]), scopedGplPolicy([TARGET_A])]) {
      const { verdicts, usedClarifyIndices, policy } = runEngine(
        [busyboxAt([TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([["warn", "default:copyleft"]]);
      // ...and the rule that decided nothing surfaces as unused.
      expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual(["compatible[0]"]);
    }
  });

  test("first-match order per occurrence: scoped rule[0] wins at its target, unscoped rule[1] elsewhere", () => {
    const policyText = [
      scopedBusyboxPolicy([TARGET_A]),
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "busybox"',
      'version = "1.37.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts } = runEngine([busyboxAt([TARGET_A, TARGET_B])], policyText);

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_B, "ok", "compatible[1]"],
    ]);
  });

  test("byte-identity: an unscoped policy over a multi-occurrence model is unchanged — rule ids and statuses per occurrence", () => {
    // The pre-scoping contract: without `where`, a
    // compatible rule accepts the package at EVERY occurrence, package form
    // beating license form, first match in TOML order.
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "mpl-pkg"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      SUPPRESS_SCRATCH,
    ].join("\n");
    const { verdicts } = runEngine(
      [
        pkgSpec("mpl-pkg", "MPL-2.0", ["apps/scratch", "backend", "proj"]),
        pkgSpec("other-mpl", "MPL-2.0", ["backend", "proj"]),
      ],
      policyText,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "ok", "compatible[0]"],
      ["backend", "ok", "compatible[0]"],
      ["proj", "ok", "compatible[0]"],
      ["backend", "ok", "compatible[1]"],
      ["proj", "ok", "compatible[1]"],
    ]);
  });

  test('the everywhere token "/" decides at every occurrence identity (both forms)', () => {
    for (const policyText of [scopedBusyboxPolicy(["/"]), scopedGplPolicy(["/"])]) {
      const { verdicts } = runEngine(
        [busyboxAt([TARGET_A, TARGET_B, TARGET_A_PREFIX])],
        policyText,
      );

      expect(verdicts.map((v) => [v.status, v.rule])).toEqual([
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
        ["ok", "compatible[0]"],
      ]);
    }
  });

  test("the everywhere token beside a narrower prefix still covers every occurrence", () => {
    const { verdicts } = runEngine(
      [busyboxAt([TARGET_A, TARGET_B])],
      scopedBusyboxPolicy([TARGET_A, "/"]),
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      [TARGET_A, "ok", "compatible[0]"],
      [TARGET_B, "ok", "compatible[0]"],
    ]);
  });

  test("dead scoped rule: a where that matches no occurrence lands in unusedRuleIds", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [busyboxAt([TARGET_A])],
      scopedBusyboxPolicy([TARGET_B]),
    );

    expect(verdicts.map((v) => v.rule)).toEqual(["default:copyleft"]);
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual(["compatible[0]"]);
  });
});

describe("evaluate — purity and determinism", () => {
  test("identical inputs evaluate to deeply equal arrays; occurrence input order is irrelevant", () => {
    const forward = pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch", "backend"]);
    const reversed = pkgSpec("agpl-pkg", "AGPL-3.0-only", ["backend", "apps/scratch"]);
    const first = runEngine([forward], SUPPRESS_SCRATCH).verdicts;
    const second = runEngine([forward], SUPPRESS_SCRATCH).verdicts;
    const shuffled = runEngine([reversed], SUPPRESS_SCRATCH).verdicts;

    expect(second).toEqual(first);
    expect(shuffled).toEqual(first);
  });
});

describe("AGPL acceptance corpus", () => {
  // Corpus row: @scratch/scratch-vm @11.6.0-react-18 — AGPL-3.0-only,
  // occurrences apps/scratch (prod) ONLY. Expected: suppressed.
  test("scratch-vm shape: AGPL occurring only under apps/scratch is suppressed", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40scratch/scratch-vm@11.6.0-react-18",
          name: "@scratch/scratch-vm",
          version: "11.6.0-react-18",
          claims: ["AGPL-3.0-only"],
          occurrences: ["apps/scratch"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
  });

  // Corpus row: same purl with a hypothetical added backend occurrence — THE
  // The failure must name the non-suppressed workspace.
  test("scratch-vm shape + backend occurrence: fail verdict names backend", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40scratch/scratch-vm@11.6.0-react-18",
          name: "@scratch/scratch-vm",
          version: "11.6.0-react-18",
          claims: ["AGPL-3.0-only"],
          occurrences: ["apps/scratch", "backend"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["backend", "fail"],
    ]);
    expect(verdicts[1].occurrenceTarget).toBe("backend");
    expect(verdicts[1].reason).toContain("backend");
  });

  // Corpus row: @img/sharp-libvips-* (10 platform pkgs @1.2.4) —
  // LGPL-3.0-or-later, occurrences apps/scratch (prod) AND frontend (prod).
  // This is the REAL live-data leakage shape.
  test("sharp-libvips shape: LGPL leaking into frontend fails naming frontend", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/%40img/sharp-libvips-linux-x64@1.2.4",
          name: "@img/sharp-libvips-linux-x64",
          version: "1.2.4",
          claims: ["LGPL-3.0-or-later"],
          occurrences: ["apps/scratch", "frontend"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["frontend", "fail"],
    ]);
    expect(verdicts[1].reason).toContain("frontend");
  });

  // Corpus row: @img/sharp-win32-* @0.34.5 — "Apache-2.0 AND
  // LGPL-3.0-or-later": AND cannot avoid the LGPL branch. The user's example
  // compatible(package) rule flips ALL occurrences to ok.
  test("sharp-win32-x64 shape: AND cannot avoid copyleft; a package rule flips all occurrences ok", () => {
    const spec: PackageSpec = {
      purl: "pkg:npm/%40img/sharp-win32-x64@0.34.5",
      name: "@img/sharp-win32-x64",
      version: "0.34.5",
      claims: ["Apache-2.0 AND LGPL-3.0-or-later"],
      occurrences: ["apps/scratch", "frontend"],
    };
    const without = runEngine([spec], ACCEPTANCE_POLICY).verdicts;

    expect(without.map((v) => [v.occurrenceTarget, v.status])).toEqual([
      ["apps/scratch", "suppressed"],
      ["frontend", "fail"],
    ]);
    expect(without[1].reason).toContain("frontend");

    const withRule = [
      ACCEPTANCE_POLICY,
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "@img/sharp-win32-x64"',
      'version = "0.34.5"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const accepted = runEngine([spec], withRule).verdicts;

    expect(accepted.map((v) => [v.occurrenceTarget, v.status, v.rule])).toEqual([
      ["apps/scratch", "ok", "compatible[0]"],
      ["frontend", "ok", "compatible[0]"],
    ]);
  });

  // Corpus row: dompurify @3.1.6/@3.3.1 — "(MPL-2.0 OR Apache-2.0)",
  // occurrence apps/scratch (prod). Elects Apache-2.0 → must NOT flag even
  // though MPL-2.0 is in COPYLEFT_IDS and the policy has no MPL rule.
  test("dompurify shape: OR-with-permissive elects Apache-2.0 → default:ok", () => {
    const { verdicts } = runEngine(
      [
        {
          purl: "pkg:npm/dompurify@3.1.6",
          name: "dompurify",
          version: "3.1.6",
          claims: ["(MPL-2.0 OR Apache-2.0)"],
          occurrences: ["apps/scratch"],
        },
      ],
      ACCEPTANCE_POLICY,
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  // Corpus row: jsonify @0.0.1 — garbage claim "Public Domain" (frontend dev
  // dep), the live corpus's only non-normalizable value. Normalizes to
  // unknown; the [unknown].handling knob governs it . NOTE: this
  // occurrence is dev-only, so under [unknown] handling="fail" the would-be FAIL
  // is dev-downgraded to warn by default (dev_dependencies=warn). A PROD
  // occurrence of the same would still fail — covered by the dev-scope suite above.
  test("jsonify shape: garbage claim is governed by the unknown knob (dev-downgraded under fail)", () => {
    const spec: PackageSpec = {
      purl: "pkg:npm/jsonify@0.0.1",
      name: "jsonify",
      version: "0.0.1",
      claims: ["Public Domain"],
      occurrences: [{ target: "frontend", dev: true }],
    };
    const warned = runEngine([spec], ACCEPTANCE_POLICY).verdicts;

    expect(warned[0].status).toBe("warn");
    expect(warned[0].rule).toBe("default:unknown");

    const failPolicy = ACCEPTANCE_POLICY.replace('handling = "warn"', 'handling = "fail"');
    // A dev-only unknown-fail downgrades to warn by default.
    const failed = runEngine([spec], failPolicy).verdicts;

    expect(failed[0].status).toBe("warn");
    expect(failed[0].rule).toBe("default:unknown");
    expect(failed[0].reason).toContain("dev-only occurrence");

    // Strict projects can restore the fail with dev_dependencies=fail.
    const strictPolicy = `${failPolicy}\n\n[dev_dependencies]\nhandling = "fail"`;
    const strict = runEngine([spec], strictPolicy).verdicts;

    expect(strict[0].status).toBe("fail");
    expect(strict[0].rule).toBe("default:unknown");
  });
});

describe("evaluate — dev-scope downgrade (default warn)", () => {
  test("HEADLINE: one copyleft package, dev occurrence WARNS + prod occurrence FAILS", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], "");

    expect(verdicts).toHaveLength(2);
    // sorted compareCodeUnits on (purl, target): apps/a before apps/b
    const [a, b] = verdicts;

    expect(a.occurrenceTarget).toBe("apps/a");
    expect(a.status).toBe("warn");
    expect(a.rule).toBe("default:copyleft");
    expect(b.occurrenceTarget).toBe("apps/b");
    expect(b.status).toBe("fail");
    expect(b.rule).toBe("default:copyleft");
  });

  test("the dev-downgraded reason names the cause and the knob value", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], "");
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");

    expect(dev?.reason).toContain("dev-only occurrence");
    expect(dev?.reason).toContain("dev_dependencies=warn");
    // the prod fail reason is a genuine default:copyleft fail, not a downgrade
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(prod?.reason).not.toContain("dev-only occurrence");
  });

  test("unknown-fail downgrade is covered too (general, both default-FAIL terminals)", () => {
    const { verdicts } = runEngine([DEV_PROD_UNKNOWN], '[unknown]\nhandling = "fail"');
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("warn");
    expect(dev?.rule).toBe("default:unknown");
    expect(dev?.reason).toContain("dev-only occurrence");
    expect(prod?.status).toBe("fail");
    expect(prod?.rule).toBe("default:unknown");
  });

  test('a default:unknown that is already "warn" is never downgraded (it is no fail)', () => {
    // unknownHandling="warn" → the dev occurrence is a plain default:unknown
    // warn, NOT a dev-downgrade; its reason carries no dev-only marker.
    const { verdicts } = runEngine([DEV_PROD_UNKNOWN], "");
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");

    expect(dev?.status).toBe("warn");
    expect(dev?.rule).toBe("default:unknown");
    expect(dev?.reason).not.toContain("dev-only occurrence");
  });
});

describe("evaluate — workspace-shape production occurrences", () => {
  // Pins the applyDevScope production terminal (evaluate.ts ~411:
  // "if (!occurrence.isDevDependency) return failVerdict;") on the EXACT
  // per-workspace repo shape the collect-loop expansion now produces —
  // {target: "frontend" | "backend", isDevDependency: false} — so the fix
  // can never silently regress under the real workspace target identities
  // instead of the older synthetic apps/a / apps/b names.

  test("HEADLINE: a production copyleft occurrence on {target:'frontend', isDevDependency:false} FAILS under dev_dependencies=warn — never downgraded", () => {
    const { verdicts } = runEngine(
      [pkgSpec("imaging-native", "LGPL-3.0-or-later", [{ target: "frontend", dev: false }])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].occurrenceTarget).toBe("frontend");
  });

  test("contrast arm: the SAME package as a dev occurrence on the workspace shape WARNS — proving the terminal, not the shape, does the work", () => {
    const { verdicts } = runEngine(
      [pkgSpec("imaging-native", "LGPL-3.0-or-later", [{ target: "frontend", dev: true }])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].occurrenceTarget).toBe("frontend");
    expect(verdicts[0].reason).toContain("dev-only occurrence");
  });

  test("deny, production: a [[deny]]-listed license on {target:'backend', isDevDependency:false} FAILS (terminal)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "backend", dev: false }])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].occurrenceTarget).toBe("backend");
  });

  test("deny, dev: the SAME deny shape with isDevDependency:true STILL FAILS — deny sits above the dev downgrade on this scan shape too", () => {
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "backend", dev: true }])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].occurrenceTarget).toBe("backend");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });
});

describe('evaluate — dev_dependencies = "fail" (the pre-knob behavior)', () => {
  test("BOTH copyleft occurrences fail (no downgrade)", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], '[dev_dependencies]\nhandling = "fail"');

    expect(verdicts.map((v) => v.status)).toEqual(["fail", "fail"]);
    expect(verdicts.every((v) => v.rule === "default:copyleft")).toBe(true);
    expect(verdicts.every((v) => !v.reason.includes("dev-only"))).toBe(true);
  });

  test("BOTH unknown-fail occurrences fail (gate dev like prod)", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_UNKNOWN],
      '[dev_dependencies]\nhandling = "fail"\n\n[unknown]\nhandling = "fail"',
    );

    expect(verdicts.map((v) => v.status)).toEqual(["fail", "fail"]);
  });
});

describe('evaluate — dev_dependencies = "ignore"', () => {
  test("dev copyleft occurrence is ok; prod copyleft occurrence still FAILS", () => {
    const { verdicts } = runEngine([DEV_PROD_COPYLEFT], '[dev_dependencies]\nhandling = "ignore"');
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("ok");
    expect(dev?.rule).toBe("default:copyleft");
    expect(dev?.reason).toContain("dev_dependencies=ignore");
    expect(prod?.status).toBe("fail");
  });

  test("dev unknown-fail occurrence is ok; prod still fails", () => {
    const { verdicts } = runEngine(
      [DEV_PROD_UNKNOWN],
      '[dev_dependencies]\nhandling = "ignore"\n\n[unknown]\nhandling = "fail"',
    );
    const dev = verdicts.find((v) => v.occurrenceTarget === "apps/a");
    const prod = verdicts.find((v) => v.occurrenceTarget === "apps/b");

    expect(dev?.status).toBe("ok");
    expect(prod?.status).toBe("fail");
  });
});

describe("evaluate — precedence is preserved (downgrade is last)", () => {
  test("a suppressed dev copyleft occurrence stays suppressed (not warn)", () => {
    // apps/scratch is family-suppressed AND the occurrence is dev: suppression
    // wins, the dev-scope downgrade never touches it.
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", [{ target: "apps/scratch", dev: true }])],
      SUPPRESS_SCRATCH,
    );

    expect(verdicts[0].status).toBe("suppressed");
    expect(verdicts[0].rule).toBe("workspace.copyleft_suppressed[0]");
  });

  test("a compatible-matched dev copyleft occurrence stays ok via compatible[i]", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mpl-pkg", "MPL-2.0", [{ target: "backend", dev: true }])],
      licenseRuleFixture("MPL-2.0"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("a stale-override dev occurrence still FAILS (a stale override is no default FAIL)", () => {
    // The load-bearing precedence guard: a stale override is a compliance gate
    // failure that must NEVER be dev-downgraded.
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "GPL-3.0-only", [{ target: "apps/a", dev: true }])],
      "",
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toContain("override:stale");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });
});

describe("denyRuleFor — pure matcher (SPDX + name + OR-election)", () => {
  const denyBusl = parsePolicy(denyLicenseFixture("BUSL-1.1"));

  test("license-mode matches an exact denied finding", () => {
    const hit = denyRuleFor(denyBusl, "BUSL-1.1", "anything");

    expect(hit?.ruleId).toBe("denied[0]");
  });

  test("license-mode does NOT match a non-denied finding", () => {
    expect(denyRuleFor(denyBusl, "MIT", "anything")).toBeUndefined();
  });

  test("an OR pattern matches either denied branch", () => {
    const policy = parsePolicy(denyLicenseFixture("(SSPL-1.0 OR Elastic-2.0)"));

    expect(denyRuleFor(policy, "SSPL-1.0", "x")?.ruleId).toBe("denied[0]");
    expect(denyRuleFor(policy, "Elastic-2.0", "x")?.ruleId).toBe("denied[0]");
  });

  test("W1: an OR finding with an electable acceptable branch is NOT denied", () => {
    // "MIT OR BUSL-1.1" elects MIT — an acceptable branch exists, so deny must
    // not fire (consistent with compatible OR-election).
    expect(denyRuleFor(denyBusl, "MIT OR BUSL-1.1", "x")).toBeUndefined();
  });

  test("W1: an OR finding with NO acceptable branch IS denied", () => {
    // Deny set covers BOTH branches → the dep cannot elect out → denied.
    const policy = parsePolicy(denyLicenseFixture("(GPL-3.0 OR BUSL-1.1)"));

    expect(denyRuleFor(policy, "GPL-3.0 OR BUSL-1.1", "x")?.ruleId).toBe("denied[0]");
  });

  test("name-mode matches the target package name (verbatim, non-SPDX rider)", () => {
    const policy = parsePolicy(denyNameFixture("commons-clause-pkg"));

    // name-mode matches on the PACKAGE NAME and does not require a parseable
    // license expression (the Commons-Clause rider rides a non-SPDX value).
    expect(denyRuleFor(policy, null, "commons-clause-pkg")?.ruleId).toBe("denied[0]");
    expect(denyRuleFor(policy, null, "unrelated-pkg")).toBeUndefined();
  });

  test("name-mode does not deny an unrelated license/package", () => {
    const policy = parsePolicy(denyNameFixture("commons-clause-pkg"));

    expect(denyRuleFor(policy, "MIT", "some-mit-pkg")).toBeUndefined();
  });
});

describe("evaluate — deny is terminal-0 (beats every accept lever)", () => {
  test("deny BEATS compatible: same license denied AND compatible → fail/denied[i]", () => {
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "BUSL-1.1"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).toContain("BUSL-1.1");
  });

  test("deny BEATS suppression: a denied in-family copyleft under a suppressed path still fails", () => {
    // AGPL-3.0-only under apps/scratch would normally be family-suppressed; the
    // deny terminal sits above suppression, so it still fails.
    const policyText = [denyLicenseFixture("AGPL-3.0-only"), "", SUPPRESS_SCRATCH].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("agpl-pkg", "AGPL-3.0-only", ["apps/scratch"])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("deny BEATS dev-downgrade: a denied license on a dev occurrence still fails", () => {
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[dev_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("busl-pkg", "BUSL-1.1", [{ target: "apps/a", dev: true }])],
      policyText,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).not.toContain("dev-only occurrence");
  });

  test("deny BEATS a would-be stale override: deny is terminal-0", () => {
    // The package carries a stale builtin override (recorded BSD, observes
    // BUSL-1.1) AND the observed license is denied → deny wins over stale.
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed",
        detected: { registry: "BSD" },
        expression: "BSD-3-Clause" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
    expect(verdicts[0].reason).not.toContain("STALE");
  });

  test("name-mode deny fails a package with an UNKNOWN finding (the rider case)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("commons-clause-pkg", null, ["backend"])],
      denyNameFixture("commons-clause-pkg"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("W1 through the verdict: 'MIT OR BUSL-1.1' is NOT a deny verdict", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-pkg", "MIT OR BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("W1 through the verdict: a no-acceptable-branch OR IS a deny verdict", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-pkg", "GPL-3.0 OR BUSL-1.1", ["backend"])],
      denyLicenseFixture("(GPL-3.0 OR BUSL-1.1)"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a non-denied package is unaffected (no regression)", () => {
    const { verdicts } = runEngine(
      [pkgSpec("mit-pkg", "MIT", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });
});

describe("evaluate — deny is terminal OVER OVERRIDES (C#1: deny reads the pre-override observed license)", () => {
  test("a blind clarify rewriting a DENIED observed license to MIT still FAILS (deny terminal)", () => {
    // Observed BUSL-1.1; a [[clarify]] rewrites it to MIT. Pre-fix the override
    // ran before evaluate, so deny saw MIT and passed it back in. Deny must
    // consult the PRE-OVERRIDE observed BUSL-1.1 and fail.
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[clarify]]",
      'name = "evil"',
      'version = "1.0.0"',
      'detected = { registry = "BUSL-1.1" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "claims MIT but the observed signal is BUSL-1.1"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("evil", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a SUCCESSFULLY-APPLIED builtin over a denied observed license still FAILS", () => {
    // The recorded BUSL-1.1 still holds → the builtin applies and rewrites the
    // finding to Apache-2.0. Deny must still fire on the observed BUSL-1.1 (a
    // denied OBSERVED license can never be licensed back in).
    const builtins: BuiltinOverrideInput[] = [
      {
        name: "relicensed-evil",
        detected: { registry: "BUSL-1.1" },
        expression: "Apache-2.0" as SpdxExpression,
      },
    ];
    const { verdicts } = runEngine(
      [pkgSpec("relicensed-evil", "BUSL-1.1", ["backend"])],
      denyLicenseFixture("BUSL-1.1"),
      builtins,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a legit clarify over a NON-denied observed license still applies normally", () => {
    // Observed "Apache" (imprecise); a clarify disambiguates to Apache-2.0.
    // The observed license is NOT denied, so the override applies as usual.
    const policyText = [
      denyLicenseFixture("BUSL-1.1"),
      "",
      "[[clarify]]",
      'name = "legit"',
      'version = "1.0.0"',
      'detected = { registry = "Apache" }',
      'justification = "scan-more-precise"',
      'expression = "Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("legit", "Apache", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a denied observed license is denied even when the override REWRITES it (project clarify)", () => {
    // Mirror of the builtin case for a project clarify whose record still holds.
    const policyText = [
      denyLicenseFixture("SSPL-1.0"),
      "",
      "[[clarify]]",
      'name = "sspl-evil"',
      'version = "1.0.0"',
      'detected = { registry = "SSPL-1.0" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
      'comment = "rewrites a denied observed license"',
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("sspl-evil", "SSPL-1.0", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — deny election across SEPARATE [[deny]] entries (C#6: union allowlist)", () => {
  // The shipped policy ships BUSL-1.1, SSPL-1.0, Elastic-2.0 as THREE separate
  // match="license" entries. An OR across two of them must be denied: neither
  // branch is electable out of the UNION of all license deny allowlists.
  const THREE_SEPARATE_DENIES = [
    denyLicenseFixture("BUSL-1.1"),
    "",
    denyLicenseFixture("SSPL-1.0"),
    "",
    denyLicenseFixture("Elastic-2.0"),
  ].join("\n");

  test("'BUSL-1.1 OR SSPL-1.0' across separate deny entries IS denied", () => {
    const { verdicts } = runEngine(
      [pkgSpec("dual-evil", "BUSL-1.1 OR SSPL-1.0", ["backend"])],
      THREE_SEPARATE_DENIES,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]"); // first contributing license rule
  });

  test("'MIT OR BUSL-1.1' (one branch denied, one not) stays electable / NOT denied", () => {
    const { verdicts } = runEngine(
      [pkgSpec("electable", "MIT OR BUSL-1.1", ["backend"])],
      THREE_SEPARATE_DENIES,
    );

    expect(verdicts[0].status).not.toBe("fail");
    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("denyRuleFor: 'SSPL-1.0 OR Elastic-2.0' across separate entries is denied, attributed to the first contributing rule", () => {
    const policy = parsePolicy(THREE_SEPARATE_DENIES);
    const hit = denyRuleFor(policy, "SSPL-1.0 OR Elastic-2.0", "x");

    // Both branches denied via the union; attribute to the FIRST license rule
    // that contributes a denied leaf (SSPL-1.0 at index 1 here).
    expect(hit?.ruleId).toBe("denied[1]");
  });
});

describe("evaluate — deny sees EVERY observed claim (#1/#5/#11: lossy combine must not hide a denied member)", () => {
  const denyBusl = denyLicenseFixture("BUSL-1.1");
  const denyElastic = denyLicenseFixture("Elastic-2.0");

  // The load-bearing regressions, in BOTH app and os scope: a denied precise
  // member co-present with an imprecise family / custom token must still FAIL
  // denied[i], even though combineKnown renders the finding imprecise/unknown.
  for (const scope of ["app", "os"] as const) {
    test(`[BUSL-1.1, GPL] in ${scope} scope → fail denied[0] (imprecise-family combine hides BUSL)`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("busl-gpl", ["BUSL-1.1", "GPL"], ["backend"], scope)],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
      expect(verdicts[0].reason).toContain("BUSL-1.1");
    });

    test(`[Elastic-2.0, GPL] in ${scope} scope → fail denied[0]`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("elastic-gpl", ["Elastic-2.0", "GPL"], ["backend"], scope)],
        denyElastic,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });

    test(`[BUSL-1.1, public-domain] in ${scope} scope → fail denied[0] (unknown token co-present)`, () => {
      const { verdicts } = runEngine(
        [multiClaimSpec("busl-pd", ["BUSL-1.1", "public-domain"], ["backend"], scope)],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });

    test(`[BUSL-1.1, <custom>] in ${scope} scope → fail denied[0] (#11 unknown collapse)`, () => {
      const { verdicts } = runEngine(
        [
          multiClaimSpec(
            "busl-custom",
            ["BUSL-1.1", "some-bespoke-corp-license"],
            ["backend"],
            scope,
          ),
        ],
        denyBusl,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    });
  }

  test("control: [BUSL-1.1, MIT] still fails denied[0] (combine renders precise, deny already saw it)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("busl-mit", ["BUSL-1.1", "MIT"], ["backend"])],
      denyBusl,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a non-denied [MIT, GPL] is UNAFFECTED (no over-denial regression)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("mit-gpl", ["MIT", "GPL"], ["backend"])],
      denyBusl,
    );

    expect(verdicts[0].rule).not.toBe("denied[0]");
  });

  test("[SSPL-1.0, GPL] still fails denied (the original copyleft+source-available case)", () => {
    const { verdicts } = runEngine(
      [multiClaimSpec("sspl-gpl", ["SSPL-1.0", "GPL"], ["backend"])],
      denyLicenseFixture("SSPL-1.0"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("a single denied claim still fails (no observedExpressions regression for the single-claim path)", () => {
    const { verdicts } = runEngine([pkgSpec("busl-only", "BUSL-1.1", ["backend"])], denyBusl);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — os-scope downgrade (default warn)", () => {
  test("HEADLINE: an os-scope copyleft WARNS under default os_dependencies=warn", () => {
    const { verdicts } = runEngine([OS_COPYLEFT], "");

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test('os_dependencies="fail" gates an os-scope copyleft exactly like an app one', () => {
    const { verdicts } = runEngine([OS_COPYLEFT], '[os_dependencies]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test('os_dependencies="ignore" makes an os-scope copyleft ok (rule id preserved)', () => {
    const { verdicts } = runEngine([OS_COPYLEFT], '[os_dependencies]\nhandling = "ignore"');

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=ignore");
  });

  test("the os-scope downgrade applies at the unknown-fail terminal too", () => {
    const { verdicts } = runEngine([OS_UNKNOWN], '[unknown]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:unknown");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an APP-scope copyleft is UNAFFECTED by os_dependencies (only scope===os routes through applyOsScope)", () => {
    // Same license, app scope, prod occurrence: os_dependencies must not touch
    // it — it fails on the genuine default:copyleft terminal.
    const { verdicts } = runEngine(
      [pkgSpec("agpl-app", "AGPL-3.0-only", ["apps/b"])],
      '[os_dependencies]\nhandling = "ignore"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).not.toContain("os_dependencies");
  });
});

describe("evaluate — deny STAYS TERMINAL over the os knob", () => {
  test("an os-scope package matching a [[deny]] license still FAILS regardless of os_dependencies", () => {
    // A source-available license in an OS package is denied: the os knob never
    // licenses it back in (denyVerdict returns first in verdictFor).
    for (const handling of ["warn", "fail", "ignore"] as const) {
      const policyText = [
        denyLicenseFixture("BUSL-1.1"),
        "",
        "[os_dependencies]",
        `handling = "${handling}"`,
      ].join("\n");
      const { verdicts } = runEngine(
        [
          osPkgSpec("pkg:deb/debian/evil-os@1.0.0", "evil-os", "BUSL-1.1", [
            "docker:img/Dockerfile",
          ]),
        ],
        policyText,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
      expect(verdicts[0].reason).not.toContain("os_dependencies");
    }
  });

  test("name-mode deny on an os-scope package with UNKNOWN finding still fails", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/rider-os@1.0.0", "rider-os", null, ["docker:img/Dockerfile"])],
      denyNameFixture("rider-os"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

describe("evaluate — os-scope and dev-scope downgraders compose without interaction", () => {
  test("an os-scope copyleft WARNS under dev_dependencies=fail AND os_dependencies=warn (dev lane never clobbers it)", () => {
    // The package is os-scope with a NON-dev (prod) occurrence: it is not a dev
    // occurrence, so the dev lane (set to fail) must not touch it. The os lane
    // (warn) downgrades the would-be FAIL. The two downgraders compose: an
    // os-scope package is not a dev occurrence, so dev_dependencies=fail is
    // inert on it and the os warn stands.
    const policyText = [
      "[dev_dependencies]",
      'handling = "fail"',
      "",
      "[os_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine([OS_COPYLEFT], policyText);

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an os-scope copyleft on a DEV occurrence under os=warn + dev=fail still warns (os downgrade owns the os package)", () => {
    // Locks the composition ORDER: even when the single occurrence is dev-marked
    // AND dev_dependencies=fail, the os-scope warn downgrade is applied so the
    // verdict is warn, not fail. The os lane is not clobbered by the dev lane.
    const policyText = [
      "[dev_dependencies]",
      'handling = "fail"',
      "",
      "[os_dependencies]",
      'handling = "warn"',
    ].join("\n");
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/libc6@2.36-9", "libc6", "LGPL-2.1-or-later", [
          { target: "docker:img/Dockerfile", dev: true },
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("an APP-scope dev copyleft still downgrades via the dev lane while os=ignore is inert on it", () => {
    // The reverse non-interaction: an app-scope dev copyleft under
    // dev=warn + os=ignore warns through the DEV lane (os lane inert on app).
    const policyText = [
      "[dev_dependencies]",
      'handling = "warn"',
      "",
      "[os_dependencies]",
      'handling = "ignore"',
    ].join("\n");
    const { verdicts } = runEngine(
      [pkgSpec("agpl-app", "AGPL-3.0-only", [{ target: "apps/a", dev: true }])],
      policyText,
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].reason).toContain("dev-only occurrence");
    expect(verdicts[0].reason).not.toContain("os_dependencies");
  });
});

describe("evaluate — os-scope partial finding", () => {
  test("os [GPL-2.0-only, BSD-3-Clause, public-domain] → known copyleft WARNS (os non-gating)", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-partial", ["GPL-2.0-only", "BSD-3-Clause", "public-domain"])],
      "",
    );

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:copyleft");
    expect(verdicts[0].reason).toContain("os_dependencies=warn");
  });

  test("a known permissive os-partial member → ok (default:ok), tokens do not gate", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-perm", ["MIT", "public-domain", "Artistic"])],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("DENY STAYS TERMINAL over an os-partial: a denied KNOWN member still FAILS", () => {
    // BUSL-1.1 is a known normalizable member; public-domain is the surfaced
    // remainder. Deny is checked before applyOsScope, so the os knob never
    // licenses the denied known member back in.
    for (const handling of ["warn", "fail", "ignore"] as const) {
      const policyText = [
        denyLicenseFixture("BUSL-1.1"),
        "",
        "[os_dependencies]",
        `handling = "${handling}"`,
      ].join("\n");
      const { verdicts } = runEngine(
        [osMultiSpec("os-denied", ["BUSL-1.1", "public-domain"])],
        policyText,
      );

      expect(verdicts[0].status).toBe("fail");
      expect(verdicts[0].rule).toBe("denied[0]");
    }
  });

  test("os_dependencies=fail gates an os-partial copyleft member exactly like an app one", () => {
    const { verdicts } = runEngine(
      [osMultiSpec("os-partial-fail", ["GPL-2.0-only", "public-domain"])],
      '[os_dependencies]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("INVARIANT: app-scope [GPL-2.0-only, custom] stays UNKNOWN (no partial, no gate weakening)", () => {
    // The same mixed claim set in app scope: still unknown. Under unknown=fail it
    // FAILS as unknown — a partial finding never licenses an app row to a clean
    // expression.
    const appMixed: PackageSpec = {
      purl: "pkg:npm/app-mixed@1.0.0",
      name: "app-mixed",
      version: "1.0.0",
      claims: ["GPL-2.0-only", "custom"],
      occurrences: ["apps/a"],
    };
    const { verdicts } = runEngine([appMixed], '[unknown]\nhandling = "fail"');

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:unknown");
  });
});

// ===========================================================================
// AGPL in a container system package escalates to a REAL fail
// (default:agpl-container), never the routine os-scope downgrade —
// network copyleft (AGPL section 13) applies to server-side container use.
// ===========================================================================

describe("AGPL_IDS — literal set (copyleft.ts)", () => {
  test("is exactly the six AGPL ids", () => {
    expect([...AGPL_IDS].sort()).toEqual([
      "AGPL-1.0",
      "AGPL-1.0-only",
      "AGPL-1.0-or-later",
      "AGPL-3.0",
      "AGPL-3.0-only",
      "AGPL-3.0-or-later",
    ]);
  });

  test("every member is in COPYLEFT_IDS", () => {
    for (const id of AGPL_IDS) {
      expect(COPYLEFT_IDS.has(id)).toBe(true);
    }
  });

  test('drift tripwire: every COPYLEFT_IDS id with the "AGPL-" prefix is in AGPL_IDS', () => {
    // TEST-only prefix scan — a future FAMILY_MEMBERS addition can never
    // silently miss the escalation set. Runtime matching stays exact-ID
    // (AGPL_IDS.has), never a prefix check.
    for (const id of COPYLEFT_IDS) {
      if (id.startsWith("AGPL-")) {
        expect(AGPL_IDS.has(id)).toBe(true);
      }
    }
  });
});

describe("evaluate — os-scope AGPL container escalation", () => {
  const AGPL_TARGET = "docker:img/Dockerfile";

  test("HEADLINE: os-scope AGPL-3.0-only under os_dependencies=warn escalates to a REAL fail, not the routine warn", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("os_dependencies=ignore does not license the AGPL container package back in (the loudest current escape)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      '[os_dependencies]\nhandling = "ignore"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("os_dependencies=fail also fails with the SAME distinct rule id (deterministic across every handling)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      '[os_dependencies]\nhandling = "fail"',
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("OR-election: AGPL-3.0-only OR MIT elects MIT and stays default:ok (election semantics preserved)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-or-mit@1.0.0", "agpl-or-mit", "AGPL-3.0-only OR MIT", [
          AGPL_TARGET,
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("default:ok");
  });

  test("AND-taint: GPL-2.0-only AND AGPL-3.0-or-later escalates (copyleftLeafIds sees both conjuncts)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec(
          "pkg:deb/debian/gpl-and-agpl@1.0.0",
          "gpl-and-agpl",
          "GPL-2.0-only AND AGPL-3.0-or-later",
          [AGPL_TARGET],
        ),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("app-scope precise AGPL stays default:copyleft UNCHANGED — the new rule id is container-only", () => {
    const { verdicts } = runEngine([pkgSpec("agpl-app", "AGPL-3.0-only", ["apps/a"])], "");

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:copyleft");
  });

  test("defensive: an os-scope AGPL occurrence marked isDevDependency=true still fails (no dev softening)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [
          { target: AGPL_TARGET, dev: true },
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("a where-scoped [[compatible]] package rule still accepts an os AGPL package (the explicit escape hatch)", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-os-accepted"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([AGPL_TARGET])}`,
    ].join("\n");
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-accepted@1.0.0", "agpl-os-accepted", "AGPL-3.0-only", [
          AGPL_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
  });

  test("a [[deny]] license match still yields denied[..] (deny is terminal above the AGPL escalation too)", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-denied@1.0.0", "agpl-os-denied", "AGPL-3.0-only", [
          AGPL_TARGET,
        ]),
      ],
      denyLicenseFixture("AGPL-3.0-only"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });

  test("regression: a docker:-prefixed suppression can no longer absorb the os-scope AGPL escalation — parsePolicy rejects the policy outright, so evaluate never even runs against it", () => {
    const policyText = [
      "[[workspace.copyleft_suppressed]]",
      `path = ${JSON.stringify(AGPL_TARGET)}`,
      'license = "AGPL-3.0-only"',
      'description = "attempted absorption of the container image"',
    ].join("\n");

    expect(() => parsePolicy(policyText)).toThrow(PolicyError);

    // With that suppression impossible to construct, the same os-scope AGPL
    // package at the same target has only one reachable outcome: the
    // container escalation fail — never suppressed.
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:deb/debian/agpl-os@1.0.0", "agpl-os", "AGPL-3.0-only", [AGPL_TARGET])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });
});

describe("evaluate — imprecise AGPL container escalation (imprecise variant)", () => {
  test("os-scope imprecise AGPL fails default:agpl-container (the imprecise escape lane is closed too, not just the precise-expression one)", () => {
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:apk/alpine/agpl-ish@1.0.0", "agpl-ish", "AGPL", ["docker:img/Dockerfile"])],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
  });

  test("app-scope imprecise AGPL stays warn default:imprecise-copyleft UNCHANGED", () => {
    const { verdicts } = runEngine([pkgSpec("agpl-ish-app", "AGPL", ["apps/a"])], "");

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });

  test("os-scope imprecise GPL (not AGPL) stays warn default:imprecise-copyleft UNCHANGED — only the literal AGPL token escalates", () => {
    const { verdicts } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/gpl-ish-os@1.0.0", "gpl-ish-os", "GPL", [
          "docker:img/Dockerfile",
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("default:imprecise-copyleft");
  });
});

// ---------------------------------------------------------------------------
// Accepted-AGPL container notices (evaluate.ts#acceptedContainerNotices): an
// os-scope AGPL obligation that was ACCEPTED (status "ok" via a
// `[[compatible]]` rule) rather than failing must still surface, as a
// non-blocking notice, distinct from the Verdict[] the CycloneDX/summary
// consumers read.
// ---------------------------------------------------------------------------

describe("evaluate — accepted-AGPL container notices (acceptedContainerNotices)", () => {
  const NOTICE_TARGET = "docker:img/Dockerfile";

  test("a precise AGPL system package accepted via a scoped [[compatible]] package rule surfaces as an accepted-container notice", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-os-notice"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([NOTICE_TARGET])}`,
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-notice@1.0.0", "agpl-os-notice", "AGPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");

    const notices = acceptedContainerNotices(model, verdicts);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({
      purl: "pkg:deb/debian/agpl-os-notice@1.0.0",
      name: "agpl-os-notice",
      version: "1.0.0",
      license: "AGPL-3.0-only",
      targets: [NOTICE_TARGET],
      rule: "compatible[0]",
    });
  });

  test('the imprecise "AGPL" family accepted via a scoped [[compatible]] package rule also surfaces as a notice', () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-ish-notice"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ${JSON.stringify([NOTICE_TARGET])}`,
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:apk/alpine/agpl-ish-notice@1.0.0", "agpl-ish-notice", "AGPL", [
          NOTICE_TARGET,
        ]),
      ],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");

    const notices = acceptedContainerNotices(model, verdicts);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({
      purl: "pkg:apk/alpine/agpl-ish-notice@1.0.0",
      license: "AGPL",
      targets: [NOTICE_TARGET],
      rule: "compatible[0]",
    });
  });

  test("regression: a routine GPL/LGPL system package (accepted or os-downgraded) is never an accepted-container notice — the fix does not widen the net", () => {
    const acceptPolicy = [
      "[[compatible]]",
      'match = "package"',
      'name = "gpl-os-accepted"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts: acceptedVerdicts, model: acceptedModel } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/gpl-os-accepted@1.0.0", "gpl-os-accepted", "GPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      acceptPolicy,
    );

    expect(acceptedVerdicts[0].status).toBe("ok");
    expect(acceptedContainerNotices(acceptedModel, acceptedVerdicts)).toHaveLength(0);

    const { verdicts: warnVerdicts, model: warnModel } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/lgpl-os-warn@1.0.0", "lgpl-os-warn", "LGPL-2.1-or-later", [
          NOTICE_TARGET,
        ]),
      ],
      "",
    );

    expect(warnVerdicts[0].status).toBe("warn");
    expect(acceptedContainerNotices(warnModel, warnVerdicts)).toHaveLength(0);
  });

  test("a FAILING AGPL system package (not accepted) is not an accepted-container notice — Problematic only, never duplicated", () => {
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/agpl-os-failing@1.0.0", "agpl-os-failing", "AGPL-3.0-only", [
          NOTICE_TARGET,
        ]),
      ],
      "",
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:agpl-container");
    expect(acceptedContainerNotices(model, verdicts)).toHaveLength(0);
  });

  test("determinism: notices sort by purl (compareCodeUnits), target lists dedupe+sort, and repeated calls are byte-identical", () => {
    const TARGET_A = "docker:a/Dockerfile";
    const TARGET_B = "docker:b/Dockerfile";
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "zeta-agpl"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
      "[[compatible]]",
      'match = "package"',
      'name = "alpha-agpl"',
      'version = "1.0.0"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      'where = ["/"]',
    ].join("\n");
    const { verdicts, model } = runEngine(
      [
        osPkgSpec("pkg:deb/debian/zeta-agpl@1.0.0", "zeta-agpl", "AGPL-3.0-only", [
          TARGET_B,
          TARGET_A,
        ]),
        osPkgSpec("pkg:deb/debian/alpha-agpl@1.0.0", "alpha-agpl", "AGPL-3.0-only", [TARGET_A]),
      ],
      policyText,
    );
    const notices1 = acceptedContainerNotices(model, verdicts);
    const notices2 = acceptedContainerNotices(model, verdicts);

    expect(notices1).toEqual(notices2);
    expect(notices1.map((n) => n.purl)).toEqual([
      "pkg:deb/debian/alpha-agpl@1.0.0",
      "pkg:deb/debian/zeta-agpl@1.0.0",
    ]);
    expect(notices1[1]!.targets).toEqual([TARGET_A, TARGET_B]);
  });
});

describe("evaluate — [[allow_source_available]] exemption (ADR-0013 opt-out)", () => {
  const exemptBusl = [
    "[[allow_source_available]]",
    'license = "BUSL-1.1"',
    'reason = "internal-only build tool, never redistributed; counsel-approved"',
  ].join("\n");

  test("an exempted source-available license WARNS (allowed), not fail", () => {
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], exemptBusl);

    expect(verdicts[0].status).toBe("warn");
    expect(verdicts[0].rule).toBe("allow_source_available[0]");
  });

  test("a non-exempted source-available license still FAILS by default", () => {
    const { verdicts } = runEngine([pkgSpec("sspl-pkg", "SSPL-1.0", ["backend"])], exemptBusl);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("default:source-available");
  });

  test("an explicit [[deny]] wins over an exemption (the consumer's own choice)", () => {
    const policyText = [
      "[[deny]]",
      'match = "license"',
      'pattern = "BUSL-1.1"',
      'reason = "we deny it regardless of the default"',
      "",
      exemptBusl,
    ].join("\n");
    const { verdicts } = runEngine([pkgSpec("busl-pkg", "BUSL-1.1", ["backend"])], policyText);

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("denied[0]");
  });
});

// ---------------------------------------------------------------------------
// A [[compatible]] package entry states whose use of a package was judged. On
// a target with a dependency graph, a package it accepts that also arrives
// around every introducer it names contradicts that statement, and the entry
// accepts nothing there.
// ---------------------------------------------------------------------------

describe("evaluate — an entry the introduction chains contradict", () => {
  const GRAPH_TARGET = "apps/web";
  const WITH_A_DEPENDENCY_GRAPH: ReadonlySet<string> = new Set([GRAPH_TARGET]);
  const JUDGED = "pkg:npm/judged@1.0.0";
  const OTHER = "pkg:npm/other@1.0.0";
  const GPL_LIB = "pkg:npm/gpl-lib@1.0.0";
  const MPL_LIB = "pkg:npm/mpl-lib@1.0.0";

  /** The judged entry: both -lib packages, accepted as dependencies of "judged" alone. */
  const LIB_FAMILY_POLICY = [
    "[[compatible]]",
    'match = "package"',
    'pattern = "*-lib"',
    'version = "1.0.0"',
    'as-dependency-of = ["judged"]',
    'rationale = "license-reviewed"',
    `where = ["${GRAPH_TARGET}"]`,
  ].join("\n");

  /** Attach the provenance a lane deriving a dependency graph would have recorded. */
  function withIntroductions(
    model: CanonicalDependencies,
    byPurl: Readonly<Record<string, DependencyIntroduction>>,
  ): CanonicalDependencies {
    for (const entry of model.packages) {
      const introduction = byPurl[entry.purl];

      for (const occurrence of entry.occurrences) {
        if (introduction !== undefined) {
          occurrence.introduction = introduction;
        }
      }
    }

    return model;
  }

  /**
   * The workspace the entry is scoped to: "judged" and "other" are declared directly, both pull in
   * gpl-lib, and only "judged" pulls in mpl-lib.
   */
  const SCANNED_INTRODUCTIONS: Readonly<Record<string, DependencyIntroduction>> = {
    [JUDGED]: { direct: true, introducedBy: [] },
    [OTHER]: { direct: true, introducedBy: [] },
    [GPL_LIB]: { direct: false, introducedBy: [JUDGED, OTHER] },
    [MPL_LIB]: { direct: false, introducedBy: [JUDGED] },
  };

  function runChainEngine(
    policyText: string,
    introductions: Readonly<Record<string, DependencyIntroduction>> = SCANNED_INTRODUCTIONS,
  ): {
    verdicts: Verdict[];
    usedClarifyIndices: ReadonlySet<number>;
    policy: Policy;
    model: CanonicalDependencies;
  } {
    const policy = parsePolicy(policyText);
    const specs = [
      pkgSpec("judged", "MIT", [GRAPH_TARGET]),
      pkgSpec("other", "MIT", [GRAPH_TARGET]),
      pkgSpec("gpl-lib", "GPL-3.0-only", [GRAPH_TARGET]),
      { ...pkgSpec("mpl-lib", "MPL-2.0", []), occurrences: [{ target: GRAPH_TARGET, dev: true }] },
    ];
    const { model, usedClarifyIndices } = annotateFindings(
      withIntroductions(makeModel(specs), introductions),
      policy.clarify,
      [],
    );

    return {
      verdicts: evaluate(model, policy, WITH_A_DEPENDENCY_GRAPH),
      usedClarifyIndices,
      policy,
      model,
    };
  }

  /** gpl-lib as the scan reports a component no chain from the project reaches. */
  const ORPHANED_GPL_LIB: Readonly<Record<string, DependencyIntroduction>> = {
    ...SCANNED_INTRODUCTIONS,
    [GPL_LIB]: { direct: false, introducedBy: [] },
  };

  test("every package the entry governs there fails, not only the one that arrives around it", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY);
    const decided = verdicts.filter((v) => v.purl === GPL_LIB || v.purl === MPL_LIB);

    expect(decided.map((v) => [v.purl, v.status, v.rule])).toEqual([
      [GPL_LIB, "fail", "compatible:voided[0]"],
      [MPL_LIB, "fail", "compatible:voided[0]"],
    ]);
  });

  test("the reason names the chain and the package that arrives through it first", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY);
    const reason = verdicts.find((v) => v.purl === MPL_LIB)?.reason ?? "";

    expect(reason).toStartWith('other → gpl-lib introduces "gpl-lib" in "apps/web"');
    expect(reason).toContain('"as-dependency-of" does not cover how it arrives');
    expect(reason).toContain("split the entry");
  });

  test("a dev-only occurrence fails with the rest - a contradicted entry is not an obligation to downgrade", () => {
    const { verdicts } = runChainEngine(
      [LIB_FAMILY_POLICY, "", "[dev_dependencies]", 'handling = "warn"'].join("\n"),
    );

    expect(verdicts.find((v) => v.purl === MPL_LIB)?.status).toBe("fail");
  });

  test("naming every introducer leaves the entry standing", () => {
    const { verdicts } = runChainEngine(
      LIB_FAMILY_POLICY.replace('["judged"]', '["judged", "other"]'),
    );

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("compatible[0]");
    expect(verdicts.find((v) => v.purl === MPL_LIB)?.rule).toBe("compatible[0]");
  });

  test("a contradicted entry is never reported unused - it decided every occurrence it governs", () => {
    const { verdicts, usedClarifyIndices, policy } = runChainEngine(LIB_FAMILY_POLICY);

    expect(verdicts.some((v) => v.rule === "compatible:voided[0]")).toBeTrue();
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("its id stays outside the compatible[ prefix, so no acceptance surface reads it as one", () => {
    const { verdicts, model } = runChainEngine(LIB_FAMILY_POLICY);
    const voided = verdicts.find((v) => v.rule.startsWith("compatible:voided")) as Verdict;

    expect(voided.rule.startsWith("compatible[")).toBeFalse();
    expect(acceptedContainerNotices(model, verdicts)).toEqual([]);
  });

  test("a package recorded as arriving from nothing reachable is not accepted by the entry", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY, ORPHANED_GPL_LIB);

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("default:copyleft");
  });

  test("it does not void the entry either - the packages that do arrive stay accepted", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY, ORPHANED_GPL_LIB);

    expect(verdicts.find((v) => v.purl === MPL_LIB)?.rule).toBe("compatible[0]");
  });

  test("an entry judged under the project itself is contradicted by any chain into the package", () => {
    const { verdicts } = runChainEngine(LIB_FAMILY_POLICY.replace('["judged"]', '["self"]'));

    expect(verdicts.find((v) => v.purl === GPL_LIB)?.rule).toBe("compatible:voided[0]");
  });

  test("a package the project declares directly is covered by the project itself", () => {
    const { verdicts } = runChainEngine(
      LIB_FAMILY_POLICY.replace('pattern = "*-lib"', 'name = "judged"').replace(
        '["judged"]',
        '["self"]',
      ),
    );

    expect(verdicts.find((v) => v.purl === JUDGED)?.rule).toBe("compatible[0]");
  });
});

describe("evaluate — a target without a dependency graph says so", () => {
  const FLAT_TARGET = "docker:img/Dockerfile";

  test("an entry judged under the project accepts, and no output implies a chain was checked", () => {
    const policyText = [
      "[[compatible]]",
      'match = "package"',
      'name = "busybox"',
      'as-dependency-of = ["self"]',
      'rationale = "os-package-unmodified"',
      `where = ["${FLAT_TARGET}"]`,
    ].join("\n");
    const { verdicts } = runEngine(
      [osPkgSpec("pkg:apk/alpine/busybox@1.0.0", "busybox", "GPL-2.0-only", [FLAT_TARGET])],
      policyText,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("compatible[0]");
    expect(verdicts[0].reason).not.toContain("→");
    expect(verdicts[0].reason).not.toContain("as-dependency-of");
  });
});

// ===========================================================================
// The invalid-justification lane. An entry whose recorded detections still
// hold, but whose stated reason the current signal disproves, fails on its
// own rule id; an entry whose reason has nothing left to correct is reported
// to maintainer tooling and never reaches a verdict.
// ===========================================================================

describe("evaluate — a clarify entry the current signal disproves", () => {
  const DUAL_CHOICE = [
    "[[clarify]]",
    'name = "choice-lib"',
    'version = "1.0.0"',
    'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
    'justification = "dual-license-choice"',
    'expression = "MIT OR Apache-2.0"',
  ].join("\n");

  test("a disproved justification fails on its own rule id, naming the refile", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      DUAL_CHOICE,
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("clarify:invalid[0]");
    expect(verdicts[0].reason).toContain("choice-lib@1.0.0");
    expect(verdicts[0].reason).toContain("contradictory-claims-recorded");
  });

  test("a justification the signal still supports decides nothing here", () => {
    const joined = [
      "[[clarify]]",
      'name = "choice-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT OR Apache-2.0", intensive = "Apache-2.0 AND MIT" }',
      'justification = "dual-license-choice"',
      'expression = "MIT OR Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "Apache-2.0 AND MIT", ["backend"])],
      joined,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("a diverged detection is the more urgent answer and decides first", () => {
    const policyText = [
      "[[clarify]]",
      'name = "choice-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
      'justification = "dual-license-choice"',
      'expression = "MIT OR Apache-2.0"',
    ].join("\n");
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "GPL-3.0-only", "MIT", ["backend"])],
      policyText,
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
  });

  test("the failing entry is never also reported as an unused entry", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      DUAL_CHOICE,
    );

    expect(verdicts[0].rule).toBe("clarify:invalid[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("a builtin override carries no justification and never enters this lane", () => {
    const { verdicts } = runEngine(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        {
          name: "choice-lib",
          detected: { registry: "MIT OR Apache-2.0", intensive: "MIT" },
          expression: "MIT OR Apache-2.0" as SpdxExpression,
        },
      ],
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("override:builtin[0]");
  });
});

// ===========================================================================
// Entries imported from the clarifications file are cited in their OWN id
// space, indexed within that file. No combined-array position may reach a
// reader: a citation names the file to open and the table in it.
// ===========================================================================

describe("evaluate — the clarifications file's own citation space", () => {
  const importable = (name: string, expression: string): string =>
    [
      "[[clarify]]",
      `name = ${JSON.stringify(name)}`,
      'version = "1.0.0"',
      'detected = { registry = "Public Domain" }',
      'justification = "license-not-found"',
      `expression = ${JSON.stringify(expression)}`,
    ].join("\n");

  test("HEADLINE: an imported entry cites clarifications[j], never its combined position", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      importable("policy-only", "MIT"),
      importable("jsonify", "Unlicense"),
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarifications[0]");
    expect(verdicts[0].reason).toBe('clarified to "Unlicense": license-not-found');
  });

  test("the policy's own entry keeps clarify[i] with imported entries beside it", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      importable("jsonify", "Unlicense"),
      importable("imported-only", "MIT"),
    );

    expect(verdicts[0].rule).toBe("clarify[0]");
  });

  test("the second imported entry is clarifications[1], with two policy entries ahead of it", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "Public Domain", ["backend"])],
      [importable("policy-one", "MIT"), importable("policy-two", "MIT")].join("\n"),
      [importable("imported-one", "MIT"), importable("jsonify", "Unlicense")].join("\n"),
    );

    expect(verdicts[0].rule).toBe("clarifications[1]");
  });

  test("a stale imported entry names the entry to update", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "GPL-3.0-only", ["backend"])],
      "",
      importable("jsonify", "Unlicense"),
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("Update or remove clarifications[0].");
  });

  test("a stale policy entry names its own citation", () => {
    const { verdicts } = runEngineWithImports(
      [pkgSpec("jsonify", "GPL-3.0-only", ["backend"])],
      importable("jsonify", "Unlicense"),
      "",
    );

    expect(verdicts[0].rule).toBe("override:stale[clarify]");
    expect(verdicts[0].reason).toContain("Update or remove clarify[0].");
  });

  test("an imported entry the signal disproves fails on clarifications:invalid[j]", () => {
    const { verdicts } = runEngineWithImports(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "choice-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
        'justification = "dual-license-choice"',
        'expression = "MIT OR Apache-2.0"',
      ].join("\n"),
    );

    expect(verdicts[0].status).toBe("fail");
    expect(verdicts[0].rule).toBe("clarifications:invalid[0]");
  });

  test("unused accounting reports each file's own ids, policy file first", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngineWithImports(
      [pkgSpec("unrelated", "MIT", ["backend"])],
      importable("policy-only", "MIT"),
      importable("imported-only", "MIT"),
    );

    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([
      "clarify[0]",
      "clarifications[0]",
    ]);
  });

  test("a failing imported entry is never also reported as an unused entry", () => {
    const { verdicts, usedClarifyIndices, policy } = runEngineWithImports(
      [scanPkgSpec("choice-lib", "MIT OR Apache-2.0", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "choice-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
        'justification = "dual-license-choice"',
        'expression = "MIT OR Apache-2.0"',
      ].join("\n"),
    );

    expect(verdicts[0].rule).toBe("clarifications:invalid[0]");
    expect(unusedRuleIds(policy, verdicts, usedClarifyIndices)).toEqual([]);
  });

  test("an imported entry with nothing left to correct is reported in the imported space", () => {
    const { model, policy } = runEngineWithImports(
      [scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"])],
      "",
      [
        "[[clarify]]",
        'name = "settled-lib"',
        'version = "1.0.0"',
        'detected = { registry = "MIT", intensive = "MIT" }',
        'justification = "contradictory-claims-recorded"',
        'expression = "MIT"',
      ].join("\n"),
    );

    expect(unnecessaryClarifyEntries(model, policy).map((entry) => entry.rule)).toEqual([
      "clarifications[0]",
    ]);
  });

  test("an imported citation is not read as a [[compatible]] acceptance of an AGPL obligation", () => {
    const purl = "pkg:deb/debian/agpl-imported@1.0.0";
    const target = "docker:img/Dockerfile";
    const model = annotateFindings(
      makeModel([osPkgSpec(purl, "agpl-imported", "AGPL-3.0-only", [target])]),
      [],
    ).model;
    const base = {
      purl,
      occurrenceTarget: target,
      status: "ok" as const,
      reason: 'clarified to "AGPL-3.0-only": license-reviewed',
    };

    expect(acceptedContainerNotices(model, [{ ...base, rule: "clarifications[0]" }])).toEqual([]);
    expect(acceptedContainerNotices(model, [{ ...base, rule: "clarify[0]" }])).toEqual([]);
    expect(acceptedContainerNotices(model, [{ ...base, rule: "compatible[0]" }])).toHaveLength(1);
  });
});

describe("unnecessaryClarifyEntries — the entries a maintainer can drop", () => {
  const AGREED = [
    "[[clarify]]",
    'name = "settled-lib"',
    'version = "1.0.0"',
    'detected = { registry = "MIT", intensive = "MIT" }',
    'justification = "contradictory-claims-recorded"',
    'expression = "MIT"',
  ].join("\n");

  test("an entry whose sources now agree is reported, and fails nothing", () => {
    const { verdicts, model, policy } = runEngine(
      [scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"])],
      AGREED,
    );

    expect(verdicts[0].status).toBe("ok");
    expect(verdicts[0].rule).toBe("clarify[0]");
    expect(unnecessaryClarifyEntries(model, policy)).toEqual([
      {
        rule: "clarify[0]",
        reason:
          '"contradictory-claims-recorded" has nothing left to correct: the declared claim and ' +
          "the in-depth scan now agree on the same licences.",
      },
    ]);
  });

  test("an entry still doing its job anywhere is not reported", () => {
    const { model, policy } = runEngine(
      [
        scanPkgSpec("settled-lib", "MIT", "MIT", ["backend"]),
        scanPkgSpec("settled-lib", "MIT", "MIT AND BSD-3-Clause", ["frontend"], "2.0.0"),
      ],
      [
        "[[clarify]]",
        'pattern = "settled-*"',
        'version = ["1.0.0", "2.0.0"]',
        'detected = { registry = "MIT" }',
        'justification = "contradictory-claims-recorded"',
        'expression = "MIT AND BSD-3-Clause"',
      ].join("\n"),
    );

    expect(unnecessaryClarifyEntries(model, policy)).toEqual([]);
  });
});
