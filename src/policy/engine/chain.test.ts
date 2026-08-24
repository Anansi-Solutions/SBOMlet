/**
 * The per-target dependency graph the policy engine reconstructs from the merged model: who
 * introduces whom, which packages the project depends on directly, and what every node is called.
 */

import { describe, expect, test } from "bun:test";

import { npmIntroductions } from "../../collectors/npmProvenance";
import { mergeSboms, type CollectedSbom } from "../../merge/merge";
import { purlDisplayName } from "../../model/dependencies";
import {
  dependencyGraphsByTarget,
  firstUncoveredIntroduction,
  type TargetDependencyGraph,
} from "./chain";

const TARGET = "apps/web";
const UI_PURL = "pkg:npm/%40acme/ui@0.0.0-use.local";
const LEFT_PAD_PURL = "pkg:npm/left-pad@1.3.0";
const MS_PURL = "pkg:npm/ms@2.1.3";

/**
 * A yarn-plugin-shaped BOM: the project depends on its own workspace member and on ms; the
 * workspace member pulls in left-pad.
 */
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
        name: "ms",
        version: "2.1.3",
        purl: MS_PURL,
        "bom-ref": "ms@npm:2.1.3",
      },
    ],
    dependencies: [
      { ref: "root@workspace:.", dependsOn: ["ui@workspace:packages/ui", "ms@npm:2.1.3"] },
      { ref: "ui@workspace:packages/ui", dependsOn: ["left-pad@npm:1.3.0"] },
      { ref: "left-pad@npm:1.3.0", dependsOn: [] },
      { ref: "ms@npm:2.1.3", dependsOn: [] },
    ],
  };
}

/** The merged model of {@link workspaceBom}, with the workspace member excluded as first-party. */
export function workspaceModel(): ReturnType<typeof mergeSboms> {
  const sbom = workspaceBom();
  const input: CollectedSbom = {
    sbom,
    targetIdentity: TARGET,
    firstPartyNames: new Set(["@acme/ui"]),
    introductions: npmIntroductions(sbom),
    derivesDependencyGraph: true,
  };

  return mergeSboms([input]);
}

describe("dependencyGraphsByTarget", () => {
  test("records who introduces whom, per target", () => {
    const graph = dependencyGraphsByTarget(workspaceModel()).get(TARGET);

    expect(graph?.parents.get(LEFT_PAD_PURL)).toEqual([UI_PURL]);
    expect(graph?.parents.get(MS_PURL)).toEqual([]);
  });

  test("records which packages the project depends on directly", () => {
    const graph = dependencyGraphsByTarget(workspaceModel()).get(TARGET);

    expect([...(graph?.direct ?? [])]).toEqual([MS_PURL]);
  });

  test("names a node the model carries no package for from its purl", () => {
    const graph = dependencyGraphsByTarget(workspaceModel()).get(TARGET);

    expect(graph?.names.get(UI_PURL)).toBe("@acme/ui");
    expect(graph?.names.get(LEFT_PAD_PURL)).toBe("left-pad");
  });

  test("a target whose occurrences carry no introduction has an empty graph, not a missing one", () => {
    const model = mergeSboms([{ sbom: workspaceBom(), targetIdentity: TARGET }]);
    const graph = dependencyGraphsByTarget(model).get(TARGET);

    expect([...(graph?.direct ?? [])]).toEqual([]);
    expect(graph?.parents.size).toBe(0);
    expect(graph?.names.get(LEFT_PAD_PURL)).toBe("left-pad");
  });

  test("a node the model records no introducers for is distinguishable from one it records none of", () => {
    const graph = dependencyGraphsByTarget(workspaceModel()).get(TARGET);

    // The workspace member is a node only because left-pad names it: nothing recorded where IT
    // comes from, which is not the same answer as "recorded, and it comes from nowhere".
    expect(graph?.parents.has(UI_PURL)).toBeFalse();
    expect(graph?.parents.get(MS_PURL)).toEqual([]);
  });

  test("each scanned target gets its own graph", () => {
    const sbom = workspaceBom();
    const graphs = dependencyGraphsByTarget(
      mergeSboms([
        { sbom, targetIdentity: TARGET, introductions: npmIntroductions(sbom) },
        { sbom, targetIdentity: "apps/other" },
      ]),
    );

    expect([...graphs.keys()].sort()).toEqual(["apps/other", TARGET]);
    expect(graphs.get(TARGET)?.parents.get(LEFT_PAD_PURL)).toEqual([UI_PURL]);
    expect(graphs.get("apps/other")?.parents.get(LEFT_PAD_PURL)).toBeUndefined();
  });
});

describe("purlDisplayName", () => {
  test("reads the namespace and name, percent-decoded, and drops the version", () => {
    expect(purlDisplayName(UI_PURL)).toBe("@acme/ui");
    expect(purlDisplayName("pkg:pypi/left-pad@1.0.0?extension=whl")).toBe("left-pad");
    expect(purlDisplayName("pkg:npm/versionless")).toBe("versionless");
  });

  test("anything that is not a purl has no name to read", () => {
    expect(purlDisplayName("not-a-purl")).toBeUndefined();
    expect(purlDisplayName("pkg:npm")).toBeUndefined();
  });

  test("a malformed percent escape is kept verbatim rather than dropped", () => {
    expect(purlDisplayName("pkg:npm/%ZZ@1.0.0")).toBe("%ZZ");
  });
});

const ROOT = ".";

function purlOf(name: string): string {
  return `pkg:npm/${name}@1.0.0`;
}

function refOf(name: string): string {
  return `${name}@npm:1.0.0`;
}

/** A BOM whose dependency graph is exactly the given introducer -> introduced edges. */
function bomFrom(edges: Readonly<Record<string, readonly string[]>>): unknown {
  const names = [...new Set(Object.entries(edges).flatMap(([from, to]) => [from, ...to]))].filter(
    (name) => name !== ROOT,
  );

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: { component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root@1.0.0" } },
    components: names.map((name) => ({
      type: "library",
      name,
      version: "1.0.0",
      purl: purlOf(name),
      "bom-ref": refOf(name),
    })),
    dependencies: Object.entries(edges).map(([from, to]) => ({
      ref: from === ROOT ? "root@workspace:." : refOf(from),
      dependsOn: to.map(refOf),
    })),
  };
}

/** The target's graph, derived through the same provenance lane a real yarn scan uses. */
function graphFrom(edges: Readonly<Record<string, readonly string[]>>): TargetDependencyGraph {
  const sbom = bomFrom(edges);
  const model = mergeSboms([
    { sbom, targetIdentity: TARGET, introductions: npmIntroductions(sbom) },
  ]);

  return dependencyGraphsByTarget(model).get(TARGET) as TargetDependencyGraph;
}

/** The chain that voids an entry judged under `judgedUnder`, as package names. */
function voidingChain(
  graph: TargetDependencyGraph,
  governed: readonly string[],
  judgedUnder: readonly string[],
): readonly string[] | undefined {
  const found = firstUncoveredIntroduction(graph, governed.map(purlOf), new Set(judgedUnder));

  return found?.chain.map((purl) => graph.names.get(purl) as string);
}

describe("firstUncoveredIntroduction", () => {
  test("a package reachable only through the judged introducer is covered", () => {
    const graph = graphFrom({ [ROOT]: ["next"], next: ["gpl-lib"] });

    expect(voidingChain(graph, ["gpl-lib"], ["next"])).toBeUndefined();
  });

  test("a second path around the judged introducer is not, and the chain names it", () => {
    const graph = graphFrom({
      [ROOT]: ["next", "side"],
      next: ["gpl-lib"],
      side: ["gpl-lib"],
    });

    expect(voidingChain(graph, ["gpl-lib"], ["next"])).toEqual(["side", "gpl-lib"]);
  });

  test("self covers the direct edge", () => {
    const graph = graphFrom({ [ROOT]: ["gpl-lib"] });

    expect(voidingChain(graph, ["gpl-lib"], ["self"])).toBeUndefined();
    expect(voidingChain(graph, ["gpl-lib"], ["next"])).toEqual(["gpl-lib"]);
  });

  test("self covers nothing but the direct edge", () => {
    const graph = graphFrom({ [ROOT]: ["next"], next: ["gpl-lib"] });

    expect(voidingChain(graph, ["gpl-lib"], ["self"])).toEqual(["next", "gpl-lib"]);
  });

  test("the judged introducer may sit anywhere on the chain, not only next to the package", () => {
    const graph = graphFrom({ [ROOT]: ["next"], next: ["middle"], middle: ["gpl-lib"] });

    expect(voidingChain(graph, ["gpl-lib"], ["next"])).toBeUndefined();
    expect(voidingChain(graph, ["gpl-lib"], ["middle"])).toBeUndefined();
    expect(voidingChain(graph, ["gpl-lib"], ["absent"])).toEqual(["next", "middle", "gpl-lib"]);
  });

  test("the shortest chain is reported", () => {
    const graph = graphFrom({
      [ROOT]: ["short", "far"],
      short: ["gpl-lib"],
      far: ["farther"],
      farther: ["gpl-lib"],
    });

    expect(voidingChain(graph, ["gpl-lib"], ["self"])).toEqual(["short", "gpl-lib"]);
  });

  test("a cycle on the way up terminates", () => {
    const graph = graphFrom({ [ROOT]: ["a"], a: ["b"], b: ["c"], c: ["b"] });

    expect(voidingChain(graph, ["c"], ["absent"])).toEqual(["a", "b", "c"]);
    expect(voidingChain(graph, ["c"], ["a"])).toBeUndefined();
  });

  test("a package no chain connects to the project cannot void anything", () => {
    const graph = graphFrom({ [ROOT]: ["kept"], detached: ["stray"] });

    expect(graph.parents.get(purlOf("stray"))).toEqual([]);
    expect(voidingChain(graph, ["stray"], ["absent"])).toBeUndefined();
  });

  test("an occurrence the scan recorded no introduction for cannot void anything either", () => {
    const sbom = bomFrom({ [ROOT]: ["gpl-lib"] });
    const model = mergeSboms([{ sbom, targetIdentity: TARGET }]);
    const graph = dependencyGraphsByTarget(model).get(TARGET) as TargetDependencyGraph;

    expect(voidingChain(graph, ["gpl-lib"], ["absent"])).toBeUndefined();
  });

  test("only the governed packages are asked, and the first of them decides", () => {
    const graph = graphFrom({ [ROOT]: ["next", "side"], next: ["a"], side: ["b"] });

    expect(voidingChain(graph, ["a"], ["next"])).toBeUndefined();
    expect(voidingChain(graph, ["a", "b"], ["next"])).toEqual(["side", "b"]);
    expect(voidingChain(graph, ["b", "a"], ["next"])).toEqual(["side", "b"]);
  });

  test("the answer is the same however often it is asked", () => {
    const graph = graphFrom({ [ROOT]: ["next", "side"], next: ["gpl-lib"], side: ["gpl-lib"] });
    const ask = (): unknown => voidingChain(graph, ["gpl-lib"], ["next"]);

    expect(ask()).toEqual(ask());
  });
});
