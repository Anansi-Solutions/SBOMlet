/**
 * npm/yarn dependency provenance (07-13) — "why is this dependency here?".
 *
 * The yarn-plugin-cyclonedx BOM carries a COMPLETE root-anchored `dependencies`
 * graph (research-verified: root bom-ref = the `@workspace:.` metadata.component,
 * 100% of components reachable, cycles bounded). This module derives, PER
 * COMPONENT PURL: direct-vs-transitive and the introducer SET in PURL-SPACE, so
 * peer-resolution `[hash]` bom-ref variants that share one purl collapse to a
 * single node (the union is correct for direct-detection and `introducedBy`).
 *
 * The representative `path`, however, is computed on the REAL bom-ref graph and
 * mapped ref-chain→purl-chain (#4): a path found on the purl-space union could
 * enter a dup-purl node via one variant's subtree and leave via a DIFFERENT
 * variant's out-edge, fabricating a chain that exists on no single concrete
 * instance. The bom-ref BFS uses the same per-level tie-break (frontier sorted
 * by purl-chain then bom-ref). When a target is unreachable on the real graph,
 * `path` is dropped AND `introducedBy` is dropped too (07-20 Fix 3) — its
 * purl-space parents are themselves root-disconnected, so the node becomes a
 * true orphan rather than naming a fabricated introducer. NOTE: the tie-break
 * is a per-level smallest-purl representative, NOT a whole-path lexicographic
 * minimum (see provenanceGraph.shortestPath).
 *
 * The BOM keys its graph on bom-ref, never purl, so the first step is a
 * bomRef→purl join from components[]; the root bom-ref
 * (metadata.component['bom-ref']) is NOT in components[] and is treated as the
 * synthetic graph root — its purl, when present, anchors the purl-space root so
 * the root never appears as an introducer of itself.
 *
 * Optional/peer is NOT available in this BOM and is therefore never set (the
 * model field stays omitted) — provenance never fabricates a value.
 *
 * Determinism + tolerance are inherited from the shared provenanceGraph: the
 * result derives from the edge SET (not BOM order), and a graph-less or
 * malformed BOM yields an empty map, never throws.
 */

import { type } from "arktype";

import {
  compareCodeUnits,
  type DependencyIntroduction,
} from "../model/dependencies";
import {
  SbomComponent,
  SbomDependencyEdge,
  SbomDocument,
} from "../validate/sbom";
import {
  addToSetMap,
  deriveIntroductions,
  sortSetMap,
  type PurlGraph,
} from "./provenanceGraph";

/** Tolerant root-bom-ref extraction — independent of the document narrow. */
const RootBomRef = type({
  "metadata?": { "component?": { "bom-ref?": "string" } },
}).pipe((doc) => doc.metadata?.component?.["bom-ref"]);

function rootBomRefOf(sbom: unknown): string | undefined {
  const result = RootBomRef(sbom);
  return result instanceof type.errors ? undefined : result;
}

/** Tolerant root-purl extraction (the metadata.component purl). */
const RootPurl = type({
  "metadata?": { "component?": { "purl?": "string" } },
}).pipe((doc) => doc.metadata?.component?.purl);

function rootPurlOf(sbom: unknown): string | undefined {
  const result = RootPurl(sbom);
  return result instanceof type.errors ? undefined : result;
}

/**
 * bom-ref → purl join over components, plus the component-purl universe. The
 * root bom-ref (NOT in components[]) is registered to its purl when both are
 * present so root edges translate to the root purl.
 */
function buildBomRefJoin(
  components: readonly unknown[],
  rootBomRef: string | undefined,
  rootPurl: string | undefined,
): { bomRefToPurl: Map<string, string>; componentPurls: Set<string> } {
  const bomRefToPurl = new Map<string, string>();
  const componentPurls = new Set<string>();
  for (const raw of components) {
    const component = SbomComponent(raw);
    if (component instanceof type.errors) continue;
    const bomRef = component["bom-ref"];
    const purl = component.purl;
    if (bomRef === undefined || purl === undefined) continue;
    // #1 (07-17): MALFORMED dup bom-ref with a DIFFERENT purl. last-wins would
    // make the join — and every direct/introducedBy edge that translates
    // through it — depend on components[] order. Resolve deterministically:
    // keep the compareCodeUnits-smaller purl so the output is order-independent.
    // Real generators never emit dup bom-refs; the tolerant posture stays
    // deterministic regardless.
    const existing = bomRefToPurl.get(bomRef);
    if (existing === undefined || compareCodeUnits(purl, existing) < 0) {
      bomRefToPurl.set(bomRef, purl);
    }
    componentPurls.add(purl);
  }
  if (rootBomRef !== undefined && rootPurl !== undefined) {
    bomRefToPurl.set(rootBomRef, rootPurl);
  }
  return { bomRefToPurl, componentPurls };
}

/** The mutable purl-space edge accumulators threaded through edge ingestion. */
interface EdgeAccumulator {
  edgeSets: Map<string, Set<string>>;
  parentSets: Map<string, Set<string>>;
  rootChildren: Set<string>;
  /**
   * #4: the REAL bom-ref adjacency — parent bom-ref → sorted-unique child
   * bom-refs (root bom-ref included as a key). Every edge here exists on a
   * single concrete variant, so a path computed on THIS graph is a real
   * single-instance chain (unlike the purl-space union, where a path can hop
   * between dup-purl variants through edges that do not co-exist on any one).
   */
  refEdges: Map<string, Set<string>>;
}

/**
 * Fold one bom-ref dependency edge into the purl-space accumulators AND the real
 * bom-ref adjacency. A root edge contributes to rootChildren (the declared-direct
 * set); every other edge contributes a forward + reverse purl edge, dropping
 * self-edges (dup-purl twins) and edges whose endpoints fail the bom-ref→purl
 * join. The real bom-ref edge is always recorded (#4) when both endpoints join.
 */
function ingestEdge(
  acc: EdgeAccumulator,
  bomRefToPurl: Map<string, string>,
  ref: string,
  dependsOn: readonly unknown[],
  rootBomRef: string | undefined,
  rootPurl: string | undefined,
): void {
  const isRootEdge = ref === rootBomRef;
  const parentPurl = bomRefToPurl.get(ref);
  for (const rawTarget of dependsOn) {
    if (typeof rawTarget !== "string") continue;
    const childPurl = bomRefToPurl.get(rawTarget);
    if (childPurl === undefined) continue;
    // Real bom-ref edge (#4): recorded for every join-resolvable edge, including
    // the root edge, so the bom-ref BFS can start at the root.
    addToSetMap(acc.refEdges, ref, rawTarget);
    if (isRootEdge) {
      // Root's declared-direct set; the root purl itself is never a child.
      if (childPurl !== rootPurl) acc.rootChildren.add(childPurl);
      continue;
    }
    if (parentPurl === undefined || childPurl === parentPurl) continue;
    addToSetMap(acc.edgeSets, parentPurl, childPurl);
    addToSetMap(acc.parentSets, childPurl, parentPurl);
  }
}

/** Carries the purl-space graph plus the real bom-ref data for path realization. */
interface NpmGraph {
  graph: PurlGraph;
  /** Real bom-ref adjacency (sorted children), root bom-ref included as a key. */
  refEdges: Map<string, string[]>;
  /** bom-ref → purl, for mapping a real ref-chain to a purl-chain. */
  bomRefToPurl: Map<string, string>;
  rootBomRef: string | undefined;
}

/**
 * Does any `dependencies` edge anchor the root — i.e. is there an edge whose
 * `ref` equals the root bom-ref? If not, the root's declared-direct set is
 * absent from the graph and direct-detection would mark every real direct as
 * transitive. The caller abstains in that case (07-24 contract).
 */
function hasRootAnchorEdge(
  dependencies: readonly unknown[],
  rootBomRef: string,
): boolean {
  for (const raw of dependencies) {
    const edge = SbomDependencyEdge(raw);
    if (edge instanceof type.errors) continue;
    if (edge.ref === rootBomRef) return true;
  }
  return false;
}

/**
 * Translate the bom-ref graph into a purl-space PurlGraph plus the real bom-ref
 * adjacency for #4 path realization. Returns undefined when the BOM carries no
 * usable graph — the caller then emits no provenance.
 *
 * 07-24 ABSTAIN contract: the lane MUST abstain (return undefined → empty map →
 * render "—") rather than silently mislabel when the root cannot be located or
 * anchored. Two added guards beyond the prior no-array / no-purls checks:
 *  (a) rootBomRef is undefined — no locatable root bom-ref. Without it
 *      isRootEdge can never be true, rootChildren stays empty, and EVERY true
 *      direct dep would be derived as direct:false (a silent mislabel).
 *  (b) no `dependencies` edge has ref === rootBomRef — the root is named but not
 *      actually anchored in the graph, so its declared-direct set is unknown and
 *      the same mislabel results.
 * Today the pinned yarn-plugin always emits both, so neither guard fires on real
 * input; they harden the lane against an npm-graph BOM or a future generator
 * that omits the root bom-ref. This mirrors the honest-residual / abstain-on-
 * ambiguity posture the rest of the provenance code follows.
 */
function buildNpmGraph(sbom: unknown): NpmGraph | undefined {
  const doc = SbomDocument(sbom);
  if (doc instanceof type.errors) return undefined;
  const components = doc.components;
  const dependencies = doc.dependencies;
  if (components === undefined || dependencies === undefined) return undefined;

  const rootBomRef = rootBomRefOf(sbom);
  // (a) No locatable root bom-ref → abstain (never mislabel real directs).
  if (rootBomRef === undefined) return undefined;
  // (b) Root bom-ref present but no edge anchors it → abstain (root unanchored).
  if (!hasRootAnchorEdge(dependencies, rootBomRef)) return undefined;

  const rootPurl = rootPurlOf(sbom);
  const { bomRefToPurl, componentPurls } = buildBomRefJoin(
    components,
    rootBomRef,
    rootPurl,
  );
  if (componentPurls.size === 0) return undefined;

  const acc: EdgeAccumulator = {
    edgeSets: new Map<string, Set<string>>(),
    parentSets: new Map<string, Set<string>>(),
    rootChildren: new Set<string>(),
    refEdges: new Map<string, Set<string>>(),
  };
  for (const raw of dependencies) {
    const edge = SbomDependencyEdge(raw);
    if (edge instanceof type.errors || edge.ref === undefined) continue;
    ingestEdge(
      acc,
      bomRefToPurl,
      edge.ref,
      edge.dependsOn ?? [],
      rootBomRef,
      rootPurl,
    );
  }

  const graph: PurlGraph = {
    edges: sortSetMap(acc.edgeSets),
    parents: sortSetMap(acc.parentSets),
    rootChildren: acc.rootChildren,
    nodes: componentPurls,
  };
  return {
    graph,
    refEdges: sortSetMap(acc.refEdges),
    bomRefToPurl,
    rootBomRef,
  };
}

interface RefBfsNode {
  ref: string;
  /** purl-chain accumulated so far (root-excluded, each ref mapped to its purl). */
  path: string[];
}

/** Stable frontier order: by PURL-chain, then bom-ref — the #4 tie-break. */
function sortRefFrontier(nodes: RefBfsNode[]): RefBfsNode[] {
  return nodes.sort(
    (a, b) =>
      compareCodeUnits(a.path.join("\0"), b.path.join("\0")) ||
      compareCodeUnits(a.ref, b.ref),
  );
}

/**
 * Expand one bom-ref BFS level into the next, marking visited (cycle bound) and
 * dropping children whose bom-ref fails the purl join. Result is sorted by the
 * #4 tie-break so the representative chain is stable regardless of parent order.
 */
function expandRefLevel(
  npm: NpmGraph,
  frontier: readonly RefBfsNode[],
  visited: Set<string>,
): RefBfsNode[] {
  const next: RefBfsNode[] = [];
  for (const node of frontier) {
    for (const child of npm.refEdges.get(node.ref) ?? []) {
      if (visited.has(child)) continue;
      visited.add(child);
      const purl = npm.bomRefToPurl.get(child);
      if (purl === undefined) continue;
      next.push({ ref: child, path: [...node.path, purl] });
    }
  }
  return sortRefFrontier(next);
}

/**
 * The SET of bom-refs reachable from the root on the REAL bom-ref graph. A
 * multi-source BFS bounded by `reachable` (cycle-safe, order-independent). The
 * root bom-ref seeds the walk and is itself a member; only join-resolvable refs
 * are traversed. This is the same machinery `realShortestPath` walks, surfaced
 * as a SET so introducedBy can honor real root-reachability (07-22) the way
 * `path` already does.
 */
function expandReachableRefs(
  npm: NpmGraph,
  frontier: readonly string[],
  reachable: Set<string>,
): string[] {
  const next: string[] = [];
  for (const ref of frontier) {
    for (const child of npm.refEdges.get(ref) ?? []) {
      if (reachable.has(child)) continue;
      reachable.add(child);
      next.push(child);
    }
  }
  return next;
}

function reachableRefsFromRoot(npm: NpmGraph): Set<string> {
  const { rootBomRef } = npm;
  if (rootBomRef === undefined) return new Set();
  const reachable = new Set<string>([rootBomRef]);
  let frontier: string[] = [rootBomRef];
  while (frontier.length > 0) {
    frontier = expandReachableRefs(npm, frontier, reachable);
  }
  return reachable;
}

/**
 * Does any child bom-ref of `children` that is itself root-reachable map to
 * `targetPurl`? Extracted from {@link realIntroducerPurls} to keep nesting shallow.
 */
function hasReachableChildPurl(
  bomRefToPurl: Map<string, string>,
  children: readonly string[],
  reachableRefs: Set<string>,
  targetPurl: string,
): boolean {
  for (const childRef of children) {
    if (!reachableRefs.has(childRef)) continue;
    if (bomRefToPurl.get(childRef) === targetPurl) return true;
  }
  return false;
}

/**
 * 07-22: the REAL-graph introducer purls of `targetPurl` — the purls of parent
 * bom-refs that (a) are themselves root-reachable on the real bom-ref graph AND
 * (b) have a real edge into a root-reachable bom-ref whose purl == targetPurl.
 *
 * This closes the 7th-review WARNING: `introducedBy` was derived in purl-space
 * (deriveIntroductions), where a dup-purl variant can make a parent purl appear
 * reachable even when its only real edge into the target sits on a
 * root-disconnected variant. Computing introducers directly on the real,
 * root-reachable bom-ref graph makes introducedBy honor the same reachability
 * `path` (realShortestPath) already does — consistent for BOTH the rendered cell
 * and --dump-model. Returns a sorted-unique purl set (root purl excluded — the
 * root is never an introducer; the declared-direct set carries root children).
 */
function realIntroducerPurls(
  npm: NpmGraph,
  targetPurl: string,
  reachableRefs: Set<string>,
): string[] {
  const { bomRefToPurl, rootBomRef } = npm;
  const introducers = new Set<string>();
  for (const [parentRef, children] of npm.refEdges) {
    if (!reachableRefs.has(parentRef) || parentRef === rootBomRef) continue;
    const parentPurl = bomRefToPurl.get(parentRef);
    if (parentPurl === undefined || parentPurl === targetPurl) continue;
    if (
      hasReachableChildPurl(bomRefToPurl, children, reachableRefs, targetPurl)
    ) {
      introducers.add(parentPurl);
    }
  }
  return [...introducers].sort(compareCodeUnits);
}

/**
 * #4: the REAL single-instance shortest path to `targetPurl`, computed on the
 * bom-ref graph (where every edge exists on a concrete variant) and mapped to
 * purls. BFS seeds the root bom-ref's children; the FIRST bom-ref whose purl ==
 * targetPurl yields the chain. Determinism mirrors the purl-space BFS: each
 * frontier is sorted by the PURL-chain (then bom-ref) so two byte-different
 * serializations of the same graph pick the identical representative chain.
 * Returns undefined when the target purl is unreachable on the real graph.
 */
function realShortestPath(
  npm: NpmGraph,
  targetPurl: string,
): string[] | undefined {
  const { bomRefToPurl, rootBomRef } = npm;
  if (rootBomRef === undefined) return undefined;
  const visited = new Set<string>([rootBomRef]);
  const seed: RefBfsNode = { ref: rootBomRef, path: [] };
  let frontier = expandRefLevel(npm, [seed], visited);
  while (frontier.length > 0) {
    for (const node of frontier) {
      if (bomRefToPurl.get(node.ref) === targetPurl) return node.path;
    }
    frontier = expandRefLevel(npm, frontier, visited);
  }
  return undefined;
}

/**
 * Per-purl provenance for every component in the BOM. Empty map when the BOM
 * carries no usable graph. The result is keyed by purl (the merge dedup key);
 * the caller threads each entry onto the matching occurrence.
 *
 * #4: direct detection + the introducedBy SET are derived in purl-space (the
 * dup-purl union is correct for those), but `path` is REPLACED with the real
 * single-instance bom-ref-graph chain so the emitted chain never hops between
 * dup-purl variants through edges that do not co-exist on one concrete variant.
 *
 * Fix 3 (07-20) / 07-21: when the target is UNREACHABLE on the real graph (its
 * only purl-space parents are themselves disconnected from the root — an
 * artifact of trimmed/partial BOMs), `realShortestPath` returns undefined. The
 * shared `deriveIntroductions` now ALREADY guarantees introducedBy ⊆
 * root-reachable (07-21 central invariant), so a fully root-disconnected node's
 * introducedBy is [] before this loop runs and a partially-disconnected node has
 * only its reachable parents. This local guard (drop both path and introducedBy
 * when realShortestPath is undefined) is therefore REDUNDANT for the
 * fully-disconnected case; it is RETAINED as harmless belt-and-braces and to
 * keep the npm `path` and `introducedBy` consistent at this seam. On a
 * 100%-reachable BOM (yarn-plugin output) neither the shared filter nor this
 * branch changes anything, so the common case is unchanged.
 */
export function npmIntroductions(
  sbom: unknown,
): ReadonlyMap<string, DependencyIntroduction> {
  const npm = buildNpmGraph(sbom);
  if (npm === undefined) return new Map();
  const introductions = deriveIntroductions(npm.graph);
  const reachableRefs = reachableRefsFromRoot(npm);
  for (const [purl, introduction] of introductions) {
    if (introduction.direct) continue;
    const realPath = realShortestPath(npm, purl);
    if (realPath === undefined) {
      // Fix 3: no real root-reachable chain → the purl-space introducedBy names
      // only disconnected parents. Drop BOTH so the node is a true orphan, never
      // a fabricated introducer.
      delete introduction.path;
      introduction.introducedBy = [];
      continue;
    }
    introduction.path = realPath;
    // 07-22: tighten the all-or-nothing Fix-3 guard into a PER-PARENT real
    // root-reachability filter. The purl-space introducedBy (deriveIntroductions)
    // can name a parent whose only edge into this node exists on a dup-purl
    // variant that is itself root-disconnected — purl-reachable but not REAL-
    // reachable. Re-derive introducedBy from the real, root-reachable bom-ref
    // graph so it honors the same reachability `path` (realShortestPath) does,
    // making the two consistent for BOTH the rendered cell and --dump-model.
    introduction.introducedBy = realIntroducerPurls(npm, purl, reachableRefs);
  }
  return introductions;
}
