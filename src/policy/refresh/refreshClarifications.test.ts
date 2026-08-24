/**
 * The three maintainer lanes over one scanned model: versions an entry could be extended to, entries
 * nothing needs any more, imported entries a policy entry decides ahead of - and the rewrite of the
 * imported file those answers justify.
 */

import { describe, expect, test } from "bun:test";

import { annotateFindings } from "../../normalize/normalize";
import { evaluate } from "../engine/evaluate";
import { parseClarifications, withImportedClarifications } from "../parse/clarificationsFile";
import { type ClarifyRule } from "../schema/clarify";
import { parsePolicy } from "../parse/parse";
import { claim, modelOf, pkg } from "../../../test/normalizeTestSupport";
import {
  anySuggestion,
  refreshFindings,
  rewriteClarifications,
  type RefreshFindings,
} from "./refreshClarifications";

import type { LicenseClaim, PackageEntry } from "../../model/dependencies";

const WITHOUT_DEPENDENCY_GRAPHS: ReadonlySet<string> = new Set();

const scanClaim = (raw: string): LicenseClaim => ({ raw, kind: "expression", source: "scancode" });

/** A `[[clarify]]` table over `name`, recording the registry lane and electing BSD-3-Clause. */
function bsdEntry(name: string, version?: string): string {
  return [
    "[[clarify]]",
    `name = ${JSON.stringify(name)}`,
    ...(version === undefined ? [] : [`version = ${JSON.stringify(version)}`]),
    'detected = { registry = "BSD" }',
    'justification = "license-not-found"',
    'expression = "BSD-3-Clause"',
  ].join("\n");
}

/** A scanned package carrying one quick-check claim, and optionally an in-depth one. */
function scanned(
  name: string,
  version: string,
  raw: string | null,
  intensive?: string,
): PackageEntry {
  return pkg(name, version, [
    ...(raw === null ? [] : [claim(raw, "expression")]),
    ...(intensive === undefined ? [] : [scanClaim(intensive)]),
  ]);
}

interface Run {
  readonly findings: RefreshFindings;
  readonly imported: ReadonlyArray<ClarifyRule>;
}

/** Annotate, evaluate, then read the maintainer lanes off the result - the pipeline's own order. */
function run(policyText: string, clarificationsText: string, packages: PackageEntry[]): Run {
  const imported = parseClarifications(clarificationsText);
  const policy = withImportedClarifications(parsePolicy(policyText), imported);
  const { model, usedClarifyIndices } = annotateFindings(modelOf(...packages), policy.clarify);

  return {
    findings: refreshFindings(
      model,
      policy,
      evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS),
      usedClarifyIndices,
    ),
    imported,
  };
}

describe("upgrade-ascertain", () => {
  test("a version whose detections still hold is offered for the entry's list", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", "BSD"),
    ]);

    expect(findings.upgrades).toEqual([
      {
        rule: "clarifications[0]",
        name: "lib",
        version: "2.0.0",
        outcome: "extend",
        detail: "every recorded detection still holds at 2.0.0",
      },
    ]);
  });

  test("a version whose detection diverged is left for a person, naming both readings", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", "MIT"),
    ]);

    expect(findings.upgrades[0]?.outcome).toBe("review");
    expect(findings.upgrades[0]?.detail).toBe(
      'it recorded the registry detection "BSD", but registry now reports "MIT"',
    );
  });

  test("a version nothing has been recorded for is reported as unknown, not as a divergence", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", null),
    ]);

    expect(findings.upgrades[0]?.outcome).toBe("unknown");
    expect(findings.upgrades[0]?.detail).toContain("run generate");
  });

  test("a version the sources already settle needs no entry", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", "BSD-3-Clause"),
    ]);

    expect(findings.upgrades[0]?.outcome).toBe("settled");
  });

  test("a version the entry already covers is not offered again", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [scanned("lib", "1.0.0", "BSD")]);

    expect(findings.upgrades).toEqual([]);
  });

  test("a version whose stated reason no longer holds is left for a person", () => {
    const entry = [
      "[[clarify]]",
      'name = "lib"',
      'version = "1.0.0"',
      'detected = { registry = "BSD", intensive = "MIT" }',
      'justification = "dual-license-choice"',
      'expression = "MIT OR Apache-2.0"',
    ].join("\n");
    const { findings } = run("", entry, [
      scanned("lib", "1.0.0", "BSD", "MIT"),
      scanned("lib", "2.0.0", "BSD", "MIT"),
    ]);

    expect(findings.upgrades[0]?.outcome).toBe("review");
    expect(findings.upgrades[0]?.detail).toContain("dual-license-choice");
  });

  test("rows come out entry by entry, and by package within one entry", () => {
    const { findings } = run(
      "",
      [bsdEntry("a-lib", "1.0.0"), bsdEntry("b-lib", "1.0.0")].join("\n\n"),
      [
        scanned("a-lib", "1.0.0", "BSD"),
        scanned("a-lib", "2.0.0", "BSD"),
        scanned("a-lib", "3.0.0", "BSD"),
        scanned("b-lib", "1.0.0", "BSD"),
        scanned("b-lib", "2.0.0", "BSD"),
      ],
    );

    expect(findings.upgrades.map((row) => `${row.rule} ${row.version}`)).toEqual([
      "clarifications[0] 2.0.0",
      "clarifications[0] 3.0.0",
      "clarifications[1] 2.0.0",
    ]);
  });
});

describe("the stale sweep", () => {
  test("an entry that matched nothing is reported in its own file's space", () => {
    const { findings } = run(bsdEntry("policy-only", "1.0.0"), bsdEntry("imported-only", "1.0.0"), [
      scanned("elsewhere", "1.0.0", "MIT"),
    ]);

    expect(findings.unused).toEqual(["clarify[0]", "clarifications[0]"]);
  });

  test("an entry whose sources came to agree is reported as no longer needed", () => {
    const entry = [
      "[[clarify]]",
      'name = "settled-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT", intensive = "MIT" }',
      'justification = "contradictory-claims-recorded"',
      'expression = "MIT"',
    ].join("\n");
    const { findings } = run("", entry, [scanned("settled-lib", "1.0.0", "MIT", "MIT")]);

    expect(findings.unnecessary.map((entry) => entry.rule)).toEqual(["clarifications[0]"]);
  });

  test("an entry the sources have caught up with is reported as no longer needed", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD-3-Clause"),
    ]);

    expect(findings.unnecessary).toEqual([
      {
        rule: "clarifications[0]",
        reason:
          'the sources now report "BSD-3-Clause", which already satisfies the recorded expression',
      },
    ]);
  });

  test("an entry still applying its expression is not reported as droppable", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [scanned("lib", "1.0.0", "BSD")]);

    expect(findings.unnecessary).toEqual([]);
    expect(findings.unused).toEqual([]);
  });
});

describe("the shadow report", () => {
  test("an imported entry a policy entry decides ahead of is reported, naming both", () => {
    const { findings } = run(bsdEntry("lib", "1.0.0"), bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
    ]);

    expect(findings.shadowed).toEqual([{ shadowing: "clarify[0]", shadowed: "clarifications[0]" }]);
  });
});

describe("anySuggestion", () => {
  test("a model with nothing to say leaves nothing to suggest", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [scanned("lib", "1.0.0", "BSD")]);

    expect(anySuggestion(findings)).toBe(false);
  });

  test("one offered version is enough to have something to say", () => {
    const { findings } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", "BSD"),
    ]);

    expect(anySuggestion(findings)).toBe(true);
  });
});

describe("rewriting the imported file", () => {
  const IMPORTED = [
    bsdEntry("settled-lib", "1.0.0"),
    bsdEntry("growing-lib", "1.0.0"),
    bsdEntry("steady-lib", "1.0.0"),
  ].join("\n\n");
  const PACKAGES = [
    scanned("growing-lib", "1.0.0", "BSD"),
    scanned("growing-lib", "2.0.0", "BSD"),
    scanned("settled-lib", "1.0.0", "BSD-3-Clause"),
    scanned("steady-lib", "1.0.0", "BSD"),
  ];

  test("entries nothing needs go, version lists that were ascertained grow", () => {
    const { findings, imported } = run("", IMPORTED, PACKAGES);
    const rewrite = rewriteClarifications(imported, findings);

    expect(rewrite?.removed).toEqual(["clarifications[0]"]);
    expect(rewrite?.extended).toEqual(["clarifications[1]"]);
    expect(rewrite?.text).toBe(
      `${[
        bsdEntry("growing-lib").replace(
          'detected = { registry = "BSD" }',
          'version = [ "1.0.0", "2.0.0" ]\ndetected = { registry = "BSD" }',
        ),
        bsdEntry("steady-lib", "1.0.0"),
      ].join("\n\n")}\n`,
    );
  });

  test("applying the rewrite leaves nothing further to apply", () => {
    const first = run("", IMPORTED, PACKAGES);
    const rewrite = rewriteClarifications(first.imported, first.findings);
    const second = run("", rewrite?.text ?? "", PACKAGES);

    expect(rewriteClarifications(second.imported, second.findings)).toBeUndefined();
  });

  test("emitting the rewritten text again is byte-identical", () => {
    const first = run("", IMPORTED, PACKAGES);
    const once = rewriteClarifications(first.imported, first.findings)?.text ?? "";
    const second = run("", once, PACKAGES);

    expect(rewriteClarifications(second.imported, second.findings)?.text ?? once).toBe(once);
  });

  const MULTI_VERSION_FOO = [
    "[[clarify]]",
    'name = "foo"',
    'version = [ "1.0.0", "2.0.0" ]',
    'detected = { registry = "BSD" }',
    'justification = "license-not-found"',
    'expression = "BSD-3-Clause"',
  ].join("\n");

  test("M1: an entry pinning a version absent from the scan is not removed on a present, moot one", () => {
    // foo@1.0.0 is moot - the sources now report the precise BSD-3-Clause the entry recorded - but
    // foo@2.0.0 is not in this scan at all, so the entry must be kept: dropping it would discard the
    // 2.0.0 pin the gate still needs when that version reappears.
    const { findings, imported } = run("", MULTI_VERSION_FOO, [
      scanned("foo", "1.0.0", "BSD-3-Clause"),
    ]);
    const rewrite = rewriteClarifications(imported, findings);

    expect(findings.unnecessary.map((entry) => entry.rule)).not.toContain("clarifications[0]");
    expect(rewrite?.removed ?? []).not.toContain("clarifications[0]");
  });

  test("M1 control: an entry IS removed when every version it pins is present and moot", () => {
    const { findings, imported } = run("", MULTI_VERSION_FOO, [
      scanned("foo", "1.0.0", "BSD-3-Clause"),
      scanned("foo", "2.0.0", "BSD-3-Clause"),
    ]);
    const rewrite = rewriteClarifications(imported, findings);

    expect(findings.unnecessary.map((entry) => entry.rule)).toEqual(["clarifications[0]"]);
    expect(rewrite?.removed).toEqual(["clarifications[0]"]);
  });

  test("a policy-file entry is never rewritten, however droppable it is", () => {
    const { findings, imported } = run(bsdEntry("lib", "1.0.0"), "", [
      scanned("lib", "1.0.0", "BSD-3-Clause"),
    ]);

    expect(findings.unnecessary.map((entry) => entry.rule)).toEqual(["clarify[0]"]);
    expect(rewriteClarifications(imported, findings)).toBeUndefined();
  });

  test("nothing to remove and nothing to extend leaves the file alone", () => {
    const { findings, imported } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
    ]);

    expect(rewriteClarifications(imported, findings)).toBeUndefined();
  });

  test("a version left for review never joins an entry's list on its own", () => {
    const { findings, imported } = run("", bsdEntry("lib", "1.0.0"), [
      scanned("lib", "1.0.0", "BSD"),
      scanned("lib", "2.0.0", "MIT"),
    ]);

    expect(rewriteClarifications(imported, findings)).toBeUndefined();
  });

  test("an entry that matched nothing is never removed on the tool's own say-so", () => {
    const { findings, imported } = run("", bsdEntry("never-scanned", "1.0.0"), [
      scanned("elsewhere", "1.0.0", "MIT"),
    ]);

    expect(findings.unused).toEqual(["clarifications[0]"]);
    expect(rewriteClarifications(imported, findings)).toBeUndefined();
  });
});
