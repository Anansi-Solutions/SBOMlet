/**
 * npm/yarn dependency provenance: bom-ref→purl join, purl-space union of
 * duplicated purls, direct-vs-transitive detection, deterministic tie-broken
 * shortest path, cycle safety, multi-parent introducedBy SET.
 *
 * The yarn-plugin BOM carries a COMPLETE root-anchored `dependencies` graph
 * whose root bom-ref is `metadata.component['bom-ref']` (NOT in components[],
 * NOT the purl). The graph keys on bom-ref; provenance is computed in purl-space
 * by translating every edge through the bom-ref→purl join and UNIONing nodes
 * that share a purl (peer-resolution `[hash]` variants resolve to one purl).
 *
 * Locked properties:
 * - direct = purl ∈ root.dependsOn (purl-space);
 * - introducedBy = sorted-unique SET of direct-parent purls (union over parents);
 * - path = deterministic tie-broken shortest root→purl chain, omitted for direct;
 * - dup-purl bom-refs union into one purl node (no fabricated self-loop);
 * - cycles are bounded by a visited set (no infinite loop, no path through self);
 * - multi-parent transitive carries the FULL introducer set, one representative path;
 * - garbage / graph-less BOM yields an empty provenance map, never throws.
 */

import { describe, expect, test } from "bun:test";

import { npmIntroductions } from "../src/collectors/npmProvenance";

/**
 * Synthetic BOM exercising: a root with two direct deps (a, b), a shared
 * transitive (c) reached via BOTH a and b (multi-parent), a deeper transitive
 * (d) under c, a duplicated purl for `a` under two peer-resolution bom-refs, and
 * a cycle (d → a).
 */
const SYNTH_BOM = {
  metadata: {
    component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
  },
  components: [
    {
      purl: "pkg:npm/a@1.0.0",
      name: "a",
      version: "1.0.0",
      "bom-ref": "a@npm:1.0.0",
    },
    // dup purl for a under a peer-resolution variant bom-ref
    {
      purl: "pkg:npm/a@1.0.0",
      name: "a",
      version: "1.0.0",
      "bom-ref": "a@npm:1.0.0 [peer]",
    },
    {
      purl: "pkg:npm/b@2.0.0",
      name: "b",
      version: "2.0.0",
      "bom-ref": "b@npm:2.0.0",
    },
    {
      purl: "pkg:npm/c@3.0.0",
      name: "c",
      version: "3.0.0",
      "bom-ref": "c@npm:3.0.0",
    },
    {
      purl: "pkg:npm/d@4.0.0",
      name: "d",
      version: "4.0.0",
      "bom-ref": "d@npm:4.0.0",
    },
  ],
  dependencies: [
    { ref: "root@workspace:.", dependsOn: ["a@npm:1.0.0", "b@npm:2.0.0"] },
    { ref: "a@npm:1.0.0", dependsOn: ["c@npm:3.0.0"] },
    { ref: "a@npm:1.0.0 [peer]", dependsOn: ["c@npm:3.0.0"] },
    { ref: "b@npm:2.0.0", dependsOn: ["c@npm:3.0.0"] },
    { ref: "c@npm:3.0.0", dependsOn: ["d@npm:4.0.0"] },
    // cycle: d depends back on a
    { ref: "d@npm:4.0.0", dependsOn: ["a@npm:1.0.0"] },
  ],
};

describe("npmIntroductions", () => {
  const intro = npmIntroductions(SYNTH_BOM);

  test("direct deps are marked direct with empty introducedBy and no path", () => {
    const a = intro.get("pkg:npm/a@1.0.0");
    expect(a).toBeDefined();
    expect(a!.direct).toBe(true);
    expect(a!.introducedBy).toEqual([]);
    expect(a!.path).toBeUndefined();
    expect("optional" in a!).toBe(false); // optionality is descoped: no optional field exists
  });

  test("a transitive's introducedBy is the sorted-unique SET of direct parents (multi-parent)", () => {
    const c = intro.get("pkg:npm/c@3.0.0");
    expect(c).toBeDefined();
    expect(c!.direct).toBe(false);
    // c is reached via a AND b (and via a's dup-purl variant, which unions to a)
    expect(c!.introducedBy).toEqual(["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"]);
  });

  test("transitive path is a deterministic tie-broken shortest root→purl chain", () => {
    const c = intro.get("pkg:npm/c@3.0.0");
    // shortest paths root→a→c and root→b→c tie at length 3; tie-break expands
    // frontier in compareCodeUnits purl order, so a (< b) wins.
    expect(c!.path).toEqual(["pkg:npm/a@1.0.0", "pkg:npm/c@3.0.0"]);
    const d = intro.get("pkg:npm/d@4.0.0");
    expect(d!.path).toEqual([
      "pkg:npm/a@1.0.0",
      "pkg:npm/c@3.0.0",
      "pkg:npm/d@4.0.0",
    ]);
  });

  test("dup-purl bom-refs union to one purl node — no self-loop, no duplicate entry", () => {
    // a appears under two bom-refs; the provenance map has exactly one a entry.
    const a = intro.get("pkg:npm/a@1.0.0");
    expect(a!.introducedBy).not.toContain("pkg:npm/a@1.0.0");
  });

  test("cycle is bounded: d→a→c→d does not loop and a never appears in its own path", () => {
    const d = intro.get("pkg:npm/d@4.0.0");
    expect(d!.path).not.toContain("pkg:npm/d@4.0.0"[0]); // sanity
    // d's introducedBy is c only (the cycle d→a does not make a a parent OF d)
    expect(d!.introducedBy).toEqual(["pkg:npm/c@3.0.0"]);
  });

  test("every component purl gets an entry", () => {
    expect(intro.size).toBe(4); // a, b, c, d (root excluded)
  });

  test("double-derive is byte-identical — provenance is deterministic from the edge set", () => {
    const a = npmIntroductions(SYNTH_BOM);
    const b = npmIntroductions(SYNTH_BOM);
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    expect(serialize(a)).toBe(serialize(b));
  });

  test("BOM line-order does NOT affect provenance (sorted BFS, not BOM order)", () => {
    // Reverse the components AND dependencies arrays: a BOM-order-dependent
    // implementation would change the tie-broken paths; the sorted BFS must not.
    const reordered = {
      ...SYNTH_BOM,
      components: [...SYNTH_BOM.components].reverse(),
      dependencies: [...SYNTH_BOM.dependencies].reverse(),
    };
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    expect(serialize(npmIntroductions(reordered))).toBe(
      serialize(npmIntroductions(SYNTH_BOM)),
    );
  });

  test("dup-purl variants do NOT fabricate a path through edges absent on the real variant (#4)", () => {
    // root→x, root→y; two bom-refs p1/p2 both purl p@1; x→p1, y→p2, p1→m, p2→n.
    // The path to n must be the REAL single-instance chain [y, p, n] (via p2),
    // never [x, p, n] (x reaches p1, which depends only on m — that chain to n
    // does not exist on any single concrete variant).
    const dupBom = {
      metadata: {
        component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
      },
      components: [
        { purl: "pkg:npm/x@1", name: "x", version: "1", "bom-ref": "x@npm:1" },
        { purl: "pkg:npm/y@1", name: "y", version: "1", "bom-ref": "y@npm:1" },
        // two bom-refs sharing one purl p@1
        { purl: "pkg:npm/p@1", name: "p", version: "1", "bom-ref": "p1@npm:1" },
        { purl: "pkg:npm/p@1", name: "p", version: "1", "bom-ref": "p2@npm:1" },
        { purl: "pkg:npm/m@1", name: "m", version: "1", "bom-ref": "m@npm:1" },
        { purl: "pkg:npm/n@1", name: "n", version: "1", "bom-ref": "n@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["x@npm:1", "y@npm:1"] },
        { ref: "x@npm:1", dependsOn: ["p1@npm:1"] },
        { ref: "y@npm:1", dependsOn: ["p2@npm:1"] },
        { ref: "p1@npm:1", dependsOn: ["m@npm:1"] },
        { ref: "p2@npm:1", dependsOn: ["n@npm:1"] },
      ],
    };
    const intro = npmIntroductions(dupBom);
    const n = intro.get("pkg:npm/n@1");
    expect(n).toBeDefined();
    // The emitted path must be the REAL chain [y, p, n]; never [x, p, n].
    expect(n!.path).toEqual(["pkg:npm/y@1", "pkg:npm/p@1", "pkg:npm/n@1"]);
    // The introducedBy SET stays correct (p introduces n).
    expect(n!.introducedBy).toEqual(["pkg:npm/p@1"]);
    // m is reached only via p1; its path is the real [x, p, m].
    const m = intro.get("pkg:npm/m@1");
    expect(m!.path).toEqual(["pkg:npm/x@1", "pkg:npm/p@1", "pkg:npm/m@1"]);
  });

  test("the dup-purl real-chain path is order-independent (BOM reversal stable, #4)", () => {
    const dupBom = {
      metadata: {
        component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
      },
      components: [
        { purl: "pkg:npm/x@1", name: "x", version: "1", "bom-ref": "x@npm:1" },
        { purl: "pkg:npm/y@1", name: "y", version: "1", "bom-ref": "y@npm:1" },
        { purl: "pkg:npm/p@1", name: "p", version: "1", "bom-ref": "p1@npm:1" },
        { purl: "pkg:npm/p@1", name: "p", version: "1", "bom-ref": "p2@npm:1" },
        { purl: "pkg:npm/m@1", name: "m", version: "1", "bom-ref": "m@npm:1" },
        { purl: "pkg:npm/n@1", name: "n", version: "1", "bom-ref": "n@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["x@npm:1", "y@npm:1"] },
        { ref: "x@npm:1", dependsOn: ["p1@npm:1"] },
        { ref: "y@npm:1", dependsOn: ["p2@npm:1"] },
        { ref: "p1@npm:1", dependsOn: ["m@npm:1"] },
        { ref: "p2@npm:1", dependsOn: ["n@npm:1"] },
      ],
    };
    const reordered = {
      ...dupBom,
      components: [...dupBom.components].reverse(),
      dependencies: [...dupBom.dependencies].reverse(),
    };
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    expect(serialize(npmIntroductions(reordered))).toBe(
      serialize(npmIntroductions(dupBom)),
    );
  });

  test("dup bom-ref with DIFFERENT purls resolves deterministically — order-independent (#1)", () => {
    // MALFORMED input: one bom-ref "dupref@npm:1" appears twice in components[]
    // with DIFFERENT purls (z@1 vs a@1). last-wins would make the join — and the
    // direct/introducedBy edges that translate through it — depend on component
    // order. The deterministic resolution (compareCodeUnits-smaller purl, a@1)
    // must hold under any permutation. Real generators never emit dup bom-refs,
    // but the tolerant posture stays order-independent.
    const dupRefBom = {
      metadata: {
        component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
      },
      components: [
        // SAME bom-ref, DIFFERENT purls — z@1 listed first.
        {
          purl: "pkg:npm/z@1",
          name: "z",
          version: "1",
          "bom-ref": "dupref@npm:1",
        },
        {
          purl: "pkg:npm/a@1",
          name: "a",
          version: "1",
          "bom-ref": "dupref@npm:1",
        },
        { purl: "pkg:npm/k@1", name: "k", version: "1", "bom-ref": "k@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["dupref@npm:1"] },
        { ref: "dupref@npm:1", dependsOn: ["k@npm:1"] },
      ],
    };
    // Asymmetric permutation: reverse ONLY the components order (the dup-ref
    // pair flips), keep dependencies as-is. A last-wins join would surface a
    // different direct purl (z@1 vs a@1); the deterministic join must not.
    const permuted = {
      ...dupRefBom,
      components: [...dupRefBom.components].reverse(),
    };
    const serialize = (m: ReadonlyMap<string, unknown>): string =>
      JSON.stringify([...m.entries()].sort());
    expect(serialize(npmIntroductions(permuted))).toBe(
      serialize(npmIntroductions(dupRefBom)),
    );
  });

  test("graph-less / garbage BOM yields an empty map, never throws", () => {
    expect(npmIntroductions({}).size).toBe(0);
    expect(npmIntroductions({ components: [] }).size).toBe(0);
    expect(npmIntroductions(null).size).toBe(0);
    expect(npmIntroductions("garbage").size).toBe(0);
    // components but no dependencies graph → no provenance derivable
    expect(npmIntroductions({ components: SYNTH_BOM.components }).size).toBe(0);
  });

  test("introducedBy is dropped when the parent is itself unreachable from the root", () => {
    // INFO (latent): introducedBy was built in purl-space from ALL non-root
    // edges, even when the parent is itself unreachable from the root.
    // realShortestPath correctly drops `path` in that case, but introducedBy
    // still named the disconnected parent → whyCellOf treated it as non-orphan
    // and rendered a FABRICATED introducer. FIX: when the real-graph chain is
    // unavailable (path dropped), drop introducedBy too → a true orphan.
    //
    // Trimmed/partial BOM: root → reachable; op → p, but `op` is NOT reachable
    // from the root (no root → op edge, no chain to op). p's only purl-space
    // parent is op, which is disconnected → p must render as an orphan.
    const trimmedBom = {
      metadata: {
        component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
      },
      components: [
        {
          purl: "pkg:npm/reachable@1",
          name: "reachable",
          version: "1",
          "bom-ref": "reachable@npm:1",
        },
        // `op` and `p` are present as components but op is NOT root-reachable.
        {
          purl: "pkg:npm/op@1",
          name: "op",
          version: "1",
          "bom-ref": "op@npm:1",
        },
        { purl: "pkg:npm/p@1", name: "p", version: "1", "bom-ref": "p@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["reachable@npm:1"] },
        // op → p, but nothing reaches op from the root.
        { ref: "op@npm:1", dependsOn: ["p@npm:1"] },
      ],
    };
    const intro = npmIntroductions(trimmedBom);
    const p = intro.get("pkg:npm/p@1");
    expect(p).toBeDefined();
    // p is a true orphan: no path (op unreachable) AND no introducedBy.
    expect(p!.path).toBeUndefined();
    expect(p!.introducedBy).toEqual([]);
    expect(p!.direct).toBe(false);
    // The reachable direct dep is unaffected.
    expect(intro.get("pkg:npm/reachable@1")!.direct).toBe(true);
  });

  test("a root-reachable parent's introducedBy is RETAINED (the orphan guard does not over-prune)", () => {
    // Sanity: when the parent IS reachable, introducedBy + path both stand.
    const intro = npmIntroductions(SYNTH_BOM);
    const c = intro.get("pkg:npm/c@3.0.0");
    expect(c!.introducedBy).toEqual(["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"]);
    expect(c!.path).toEqual(["pkg:npm/a@1.0.0", "pkg:npm/c@3.0.0"]);
  });

  test("introducedBy honors REAL bom-ref root-reachability, not purl-space union", () => {
    // 7th-review WARNING (dump-model only, trimmed BOM): introducedBy was filtered
    // against PURL-SPACE root-reachability (deriveIntroductions), while `path` was
    // recomputed on the REAL bom-ref graph (realShortestPath). A dup-purl variant
    // can make a parent purl P purl-reachable even when its ONLY real edge into X
    // exists on a ROOT-DISCONNECTED variant — so P was named as an introducer of X
    // with no real root-reachable chain. Not rendered (whyCellOf prefers `path`),
    // but the fabricated P shipped in --dump-model JSON. FIX: restrict introducedBy
    // to parents on a REAL root-reachable bom-ref edge into X, matching `path`.
    //
    // root → [A, B]; A → P_p1 (purl p@1.0.0, root-reachable via A); B → X;
    // P_p2 (DUP purl p@1.0.0, NO root-reachable in-edge) → X. In purl-space p IS
    // reachable (via a→p), and the p→x edge exists (from P_p2), so the purl-space
    // filter keeps p as an introducer of x. On the REAL graph x is reached only
    // via B→X; the P_p2→X edge sits on a root-disconnected variant.
    const dupReachBom = {
      metadata: {
        component: {
          "bom-ref": "root@workspace:.",
          purl: "pkg:npm/root@0.0.0",
        },
      },
      components: [
        {
          purl: "pkg:npm/a@1.0.0",
          name: "a",
          version: "1.0.0",
          "bom-ref": "a@npm:1.0.0",
        },
        {
          purl: "pkg:npm/b@1.0.0",
          name: "b",
          version: "1.0.0",
          "bom-ref": "b@npm:1.0.0",
        },
        // P_p1: root-reachable variant of purl p@1.0.0 (via a).
        {
          purl: "pkg:npm/p@1.0.0",
          name: "p",
          version: "1.0.0",
          "bom-ref": "p1@npm:1.0.0",
        },
        // P_p2: DUP purl p@1.0.0 with NO root-reachable in-edge.
        {
          purl: "pkg:npm/p@1.0.0",
          name: "p",
          version: "1.0.0",
          "bom-ref": "p2@npm:1.0.0",
        },
        {
          purl: "pkg:npm/x@1.0.0",
          name: "x",
          version: "1.0.0",
          "bom-ref": "x@npm:1.0.0",
        },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["a@npm:1.0.0", "b@npm:1.0.0"] },
        { ref: "a@npm:1.0.0", dependsOn: ["p1@npm:1.0.0"] },
        { ref: "b@npm:1.0.0", dependsOn: ["x@npm:1.0.0"] },
        // P_p2 → X, but nothing root-reachable reaches P_p2.
        { ref: "p2@npm:1.0.0", dependsOn: ["x@npm:1.0.0"] },
      ],
    };
    const intro = npmIntroductions(dupReachBom);
    const x = intro.get("pkg:npm/x@1.0.0");
    expect(x).toBeDefined();
    // introducedBy must be [b] only — NOT [b, p]. The p→x edge is on a
    // root-disconnected variant (P_p2); p is not a REAL introducer of x.
    expect(x!.introducedBy).toEqual(["pkg:npm/b@1.0.0"]);
    // `path` stays the real chain root→b→x.
    expect(x!.path).toEqual(["pkg:npm/b@1.0.0", "pkg:npm/x@1.0.0"]);
    expect(x!.direct).toBe(false);
    // p stays a normal root-reachable transitive (introduced by a, via P_p1).
    const p = intro.get("pkg:npm/p@1.0.0");
    expect(p!.direct).toBe(false);
    expect(p!.introducedBy).toEqual(["pkg:npm/a@1.0.0"]);
    expect(p!.path).toEqual(["pkg:npm/a@1.0.0", "pkg:npm/p@1.0.0"]);
  });

  test("partial reachability: a transitive's introducedBy keeps only its ROOT-REACHABLE parents", () => {
    // INFO: a node reached via a mix of a reachable parent and
    // a disconnected one carried BOTH in introducedBy. The shared reachability
    // filter must drop the disconnected parent while keeping the reachable one.
    //
    // root → [a]; a → t (reachable); b → t but b is NOT a root child (nothing
    // reaches b). t's introducedBy must be [a] (b dropped); path stays [a, t].
    const partialBom = {
      metadata: {
        component: { "bom-ref": "root@workspace:.", purl: "pkg:npm/root" },
      },
      components: [
        { purl: "pkg:npm/a@1", name: "a", version: "1", "bom-ref": "a@npm:1" },
        { purl: "pkg:npm/b@1", name: "b", version: "1", "bom-ref": "b@npm:1" },
        { purl: "pkg:npm/t@1", name: "t", version: "1", "bom-ref": "t@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["a@npm:1"] },
        { ref: "a@npm:1", dependsOn: ["t@npm:1"] },
        // b → t, but b is NOT reachable from the root.
        { ref: "b@npm:1", dependsOn: ["t@npm:1"] },
      ],
    };
    const intro = npmIntroductions(partialBom);
    const t = intro.get("pkg:npm/t@1");
    expect(t).toBeDefined();
    // b dropped (root-disconnected); only the reachable parent a survives.
    expect(t!.introducedBy).toEqual(["pkg:npm/a@1"]);
    expect(t!.path).toEqual(["pkg:npm/a@1", "pkg:npm/t@1"]);
    expect(t!.direct).toBe(false);
    // a stays direct; b is a root-disconnected orphan (no introducer, no direct).
    expect(intro.get("pkg:npm/a@1")!.direct).toBe(true);
    expect(intro.get("pkg:npm/b@1")!.introducedBy).toEqual([]);
    expect(intro.get("pkg:npm/b@1")!.direct).toBe(false);
  });

  test("no locatable root bom-ref → ABSTAIN (empty map), never mislabel real directs as transitive", () => {
    // CONTRACT: provenance must ABSTAIN (empty map → render "—") when the root
    // cannot be located, NEVER fabricate or mislabel. The latent bug: when
    // metadata.component carries a purl but NO bom-ref, rootBomRefOf returns
    // undefined, the root edge is never recognized (isRootEdge stays false), so
    // rootChildren stays empty and deriveIntroductions marks EVERY true direct
    // dep as direct:false → a SILENT MISLABEL ("transitive" for a real direct).
    //
    // Today this is unreachable (the pinned yarn-plugin always sets the root
    // bom-ref), but an npm-graph BOM or a generator upgrade lacking the root
    // bom-ref would degrade to mislabeling. The honest behavior is to abstain.
    //
    // This BOM has a root-anchored `dependencies` edge (keyed by some ref) and
    // two components that ARE that root's children — but metadata.component has
    // NO bom-ref, so the root is not locatable.
    const noRootBomRef = {
      metadata: {
        // purl present, but NO "bom-ref" → root not locatable.
        component: { purl: "pkg:npm/root@1.0.0" },
      },
      components: [
        { purl: "pkg:npm/a@1", name: "a", version: "1", "bom-ref": "a@npm:1" },
        { purl: "pkg:npm/b@1", name: "b", version: "1", "bom-ref": "b@npm:1" },
      ],
      dependencies: [
        // A root-anchored edge keyed by SOME ref (the would-be root ref), with
        // real children a and b.
        { ref: "root@workspace:.", dependsOn: ["a@npm:1", "b@npm:1"] },
        { ref: "a@npm:1", dependsOn: ["b@npm:1"] },
      ],
    };
    const intro = npmIntroductions(noRootBomRef);
    // ABSTAIN: empty map → every package renders the honest "—" residual.
    expect(intro.size).toBe(0);
    // Specifically, a (a TRUE direct dep) must NOT be present as a mislabeled
    // transitive {direct:false} — that is the silent mislabel we forbid.
    expect(intro.get("pkg:npm/a@1")).toBeUndefined();
  });

  test("root bom-ref present but NO dependencies edge anchors it → ABSTAIN (root not anchored)", () => {
    // CONTRACT: even with a locatable root bom-ref, if NO `dependencies` edge has
    // ref === rootBomRef, the root is not actually anchored in the graph — its
    // declared-direct set is unknown. Building a graph anyway would again mark
    // every real direct as transitive. Abstain instead.
    const rootBomRefNotAnchored = {
      metadata: {
        component: {
          "bom-ref": "root@workspace:.",
          purl: "pkg:npm/root@1.0.0",
        },
      },
      components: [
        { purl: "pkg:npm/a@1", name: "a", version: "1", "bom-ref": "a@npm:1" },
        { purl: "pkg:npm/b@1", name: "b", version: "1", "bom-ref": "b@npm:1" },
      ],
      dependencies: [
        // NO edge keyed by "root@workspace:." — the root is not anchored.
        { ref: "a@npm:1", dependsOn: ["b@npm:1"] },
      ],
    };
    const intro = npmIntroductions(rootBomRefNotAnchored);
    expect(intro.size).toBe(0);
    expect(intro.get("pkg:npm/a@1")).toBeUndefined();
  });

  test("positive baseline: a well-formed BOM (root bom-ref + root-anchored edge) still populates with correct direct:true (no over-abstention)", () => {
    // Guard against over-abstaining: the well-formed common case (root bom-ref
    // present AND a dependencies edge anchored on it) must STILL yield a
    // populated map with the root's children marked direct:true.
    const wellFormed = {
      metadata: {
        component: {
          "bom-ref": "root@workspace:.",
          purl: "pkg:npm/root@1.0.0",
        },
      },
      components: [
        { purl: "pkg:npm/a@1", name: "a", version: "1", "bom-ref": "a@npm:1" },
        { purl: "pkg:npm/b@1", name: "b", version: "1", "bom-ref": "b@npm:1" },
      ],
      dependencies: [
        { ref: "root@workspace:.", dependsOn: ["a@npm:1"] },
        { ref: "a@npm:1", dependsOn: ["b@npm:1"] },
      ],
    };
    const intro = npmIntroductions(wellFormed);
    expect(intro.size).toBe(2);
    expect(intro.get("pkg:npm/a@1")!.direct).toBe(true);
    expect(intro.get("pkg:npm/b@1")!.direct).toBe(false);
    expect(intro.get("pkg:npm/b@1")!.introducedBy).toEqual(["pkg:npm/a@1"]);
  });
});
