/**
 * The policy-against-model pass that runs before any verdict: it rejects an acceptance whose
 * `as-dependency-of` cannot be checked where it is scoped, one naming something the scan never
 * saw, and a rationale the scanned shape contradicts.
 */

import { describe, expect, test } from "bun:test";

import { npmIntroductions } from "../../collectors/npmProvenance";
import { mergeSboms, type CollectedSbom } from "../../merge/merge";
import { parsePolicy } from "../parse/parse";
import { asTargetIdentity, asPurl } from "../../../test/brandTestSupport";
import { crossValidatePolicy } from "./crossValidate";
import type { CanonicalDependencies } from "../../model/dependencies";

const GRAPH_TARGET = asTargetIdentity("apps/web");
const FLAT_TARGET = asTargetIdentity("docker:images/app/Dockerfile");
const UI_PURL = asPurl("pkg:npm/%40acme/ui@0.0.0-use.local");
const LEFT_PAD_PURL = asPurl("pkg:npm/left-pad@1.3.0");
const RIGHT_PAD_PURL = asPurl("pkg:npm/right-pad@1.0.0");
const MS_PURL = asPurl("pkg:npm/ms@2.1.3");

/** The project depends on its own workspace member and on ms; the member pulls in left-pad. */
function workspaceBom(): unknown {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: { component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root@1.0.0" } },
    components: [
      {
        type: "library",
        group: "@acme",
        name: "ui",
        version: "0.0.0-use.local",
        purl: UI_PURL,
        "bom-ref": "ui@workspace:packages/ui",
      },
      {
        type: "library",
        name: "left-pad",
        version: "1.3.0",
        purl: LEFT_PAD_PURL,
        "bom-ref": "left-pad@npm:1.3.0",
      },
      {
        type: "library",
        name: "right-pad",
        version: "1.0.0",
        purl: RIGHT_PAD_PURL,
        "bom-ref": "right-pad@npm:1.0.0",
      },
      { type: "library", name: "ms", version: "2.1.3", purl: MS_PURL, "bom-ref": "ms@npm:2.1.3" },
    ],
    dependencies: [
      { ref: "root@workspace:.", dependsOn: ["ui@workspace:packages/ui", "ms@npm:2.1.3"] },
      {
        ref: "ui@workspace:packages/ui",
        dependsOn: ["left-pad@npm:1.3.0", "right-pad@npm:1.0.0"],
      },
      { ref: "left-pad@npm:1.3.0", dependsOn: [] },
      { ref: "right-pad@npm:1.0.0", dependsOn: [] },
      { ref: "ms@npm:2.1.3", dependsOn: [] },
    ],
  };
}

/** An image OS layer: a flat inventory, no graph of any kind. */
function osBom(names: ReadonlyArray<string>): unknown {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: names.map((name) => ({
      type: "library",
      name,
      version: "1.0.0",
      purl: `pkg:apk/alpine/${name}@1.0.0`,
    })),
  };
}

function graphInput(): CollectedSbom {
  const sbom = workspaceBom();

  return {
    sbom,
    targetIdentity: GRAPH_TARGET,
    firstPartyNames: new Set(["@acme/ui"]),
    introductions: npmIntroductions(sbom),
    derivesDependencyGraph: true,
  };
}

function osInput(names: ReadonlyArray<string> = ["busybox"]): CollectedSbom {
  return { sbom: osBom(names), targetIdentity: FLAT_TARGET, scope: "os" };
}

function bothTargets(): CanonicalDependencies {
  return mergeSboms([graphInput(), osInput()]);
}

/** Run the pass over a model holding both targets, with only the workspace target graphed. */
function validate(model: CanonicalDependencies, toml: string): void {
  crossValidatePolicy(model, parsePolicy(toml), new Set([GRAPH_TARGET]));
}

/** The version each model package is pinned at, so an injected `version` still matches it. */
const MODEL_VERSION: Readonly<Record<string, string>> = {
  '"left-pad"': '"1.3.0"',
  '"right-pad"': '"1.0.0"',
  '"ms"': '"2.1.3"',
  '"busybox"': '"1.0.0"',
  '"absent"': '"9.9.9"',
};

function packageEntry(fields: Record<string, string>): string {
  const lines = [
    "[[compatible]]",
    'match = "package"',
    ...Object.entries(fields).map(([key, value]) => `${key} = ${value}`),
  ];

  if (!("version" in fields) && !("packages" in fields)) {
    lines.push(
      "pattern" in fields
        ? 'version = ["1.3.0", "1.0.0"]'
        : `version = ${MODEL_VERSION[fields["name"] ?? ""] ?? '"1.0.0"'}`,
    );
  }

  return lines.join("\n");
}

describe("crossValidatePolicy — parents that can be checked", () => {
  test("a parent naming a package of the target's graph passes", () => {
    const toml = packageEntry({
      name: '"left-pad"',
      "as-dependency-of": '["@acme/ui"]',
      rationale: '"unused-transitive"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });

  test("a first-party workspace parent resolves even though the model carries no package for it", () => {
    const model = bothTargets();

    expect(model.packages.some((pkg) => pkg.name === "@acme/ui")).toBeFalse();
    expect(() =>
      validate(
        model,
        packageEntry({
          name: '"left-pad"',
          "as-dependency-of": '["@acme/ui"]',
          rationale: '"license-reviewed"',
          where: `["${GRAPH_TARGET}"]`,
        }),
      ),
    ).not.toThrow();
  });

  test("a parent no node of the target's graph carries is a config error naming entry, parent and target", () => {
    const toml = packageEntry({
      name: '"left-pad"',
      "as-dependency-of": '["nope"]',
      rationale: '"license-reviewed"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).toThrow(
      'compatible[0] ("left-pad"): "as-dependency-of" names "nope", which is not part of target "apps/web"\'s dependency graph',
    );
    expect(() => validate(bothTargets(), toml)).toThrow(
      'Correct the name, or narrow "where" to the targets where it is.',
    );
  });

  test("a non-self parent on a target without a dependency graph is a config error naming the fix", () => {
    const toml = packageEntry({
      name: '"busybox"',
      "as-dependency-of": '["@acme/ui"]',
      rationale: '"os-package-unmodified"',
      where: `["${FLAT_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).toThrow(
      `compatible[0] ("busybox"): "as-dependency-of" names "@acme/ui", but target "${FLAT_TARGET}" has no dependency graph`,
    );
    expect(() => validate(bothTargets(), toml)).toThrow(
      'Narrow "where" to targets that have one, or use "self"',
    );
  });

  test("self on a target without a dependency graph passes", () => {
    const toml = packageEntry({
      name: '"busybox"',
      "as-dependency-of": '["self"]',
      rationale: '"os-package-unmodified"',
      where: `["${FLAT_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });

  test("an entry scoped to a graphed target is not rejected because an unrelated graphless target exists", () => {
    const toml = packageEntry({
      name: '"left-pad"',
      "as-dependency-of": '["@acme/ui"]',
      rationale: '"license-reviewed"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });

  test("an entry governing nothing is not a config error - that is the unused-entry report's job", () => {
    const toml = packageEntry({
      name: '"absent"',
      "as-dependency-of": '["nope"]',
      rationale: '"license-reviewed"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });
});

describe("crossValidatePolicy — the reserved self token", () => {
  test("a real package named self makes every entry using the token a config error", () => {
    const model = mergeSboms([graphInput(), osInput(["busybox", "self"])]);
    const toml = packageEntry({
      name: '"busybox"',
      "as-dependency-of": '["self"]',
      rationale: '"os-package-unmodified"',
      where: `["${FLAT_TARGET}"]`,
    });

    expect(() => validate(model, toml)).toThrow(
      'compatible[0]: "as-dependency-of" uses the reserved token "self", but the scan found a real package of that name (pkg:apk/alpine/self@1.0.0)',
    );
  });

  test("a real package named self is inert while no entry uses the token", () => {
    const model = mergeSboms([graphInput(), osInput(["busybox", "self"])]);
    const toml = packageEntry({
      name: '"left-pad"',
      "as-dependency-of": '["@acme/ui"]',
      rationale: '"license-reviewed"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(model, toml)).not.toThrow();
  });
});

describe("crossValidatePolicy — rationales the scan contradicts", () => {
  test("os-package-unmodified on an occurrence outside an image's OS layer is a config error", () => {
    const toml = packageEntry({
      name: '"left-pad"',
      "as-dependency-of": '["@acme/ui"]',
      rationale: '"os-package-unmodified"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).toThrow(
      'compatible[0] ("left-pad"): rationale "os-package-unmodified" describes a distribution package shipped inside a container image, but this entry governs "left-pad" in target "apps/web", which is not one',
    );
  });

  test("os-package-unmodified on an image's own package passes", () => {
    const toml = packageEntry({
      name: '"busybox"',
      "as-dependency-of": '["self"]',
      rationale: '"os-package-unmodified"',
      where: `["${FLAT_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });

  test("unused-transitive on a direct dependency is a config error", () => {
    const toml = packageEntry({
      name: '"ms"',
      "as-dependency-of": '["self"]',
      rationale: '"unused-transitive"',
      where: `["${GRAPH_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).toThrow(
      'compatible[0] ("ms"): rationale "unused-transitive" says the package is pulled in by a dependency, but "ms" is a direct dependency of target "apps/web"',
    );
  });

  test("unused-transitive says nothing checkable where there is no graph", () => {
    const toml = packageEntry({
      name: '"busybox"',
      "as-dependency-of": '["self"]',
      rationale: '"unused-transitive"',
      where: `["${FLAT_TARGET}"]`,
    });

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });

  test("a licence-form entry is never rationale-checked - no package is resolved for it here", () => {
    const toml = [
      "[[compatible]]",
      'match = "license"',
      'pattern = "MPL-2.0"',
      'rationale = "os-package-unmodified"',
      `where = ["${GRAPH_TARGET}"]`,
    ].join("\n");

    expect(() => validate(bothTargets(), toml)).not.toThrow();
  });
});

describe("crossValidatePolicy — reporting", () => {
  test("every problem is reported together, in entry order", () => {
    const toml = [
      packageEntry({
        name: '"left-pad"',
        "as-dependency-of": '["nope"]',
        rationale: '"license-reviewed"',
        where: `["${GRAPH_TARGET}"]`,
      }),
      packageEntry({
        name: '"ms"',
        "as-dependency-of": '["self"]',
        rationale: '"unused-transitive"',
        where: `["${GRAPH_TARGET}"]`,
      }),
    ].join("\n\n");
    const message = rejectionMessage(bothTargets(), toml);

    expect(message.split("\n")).toHaveLength(2);
    expect(message).toContain('compatible[0] ("left-pad")');
    expect(message).toContain('compatible[1] ("ms")');
  });

  test("one entry reports one problem per target, however many packages it governs", () => {
    const model = bothTargets();
    const toml = packageEntry({
      pattern: '"*-pad"',
      "as-dependency-of": '["nope"]',
      rationale: '"license-reviewed"',
      where: '["/"]',
    });

    expect(model.packages.filter((pkg) => pkg.name.endsWith("-pad"))).toHaveLength(2);
    expect(rejectionMessage(model, toml).split("\n")).toHaveLength(1);
  });
});

/** The aggregated problem text of a policy the pass must reject; fails the test when it passes. */
function rejectionMessage(model: CanonicalDependencies, toml: string): string {
  try {
    validate(model, toml);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }

  throw new Error("expected the pass to reject this policy, but it accepted it");
}
