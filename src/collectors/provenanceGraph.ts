/**
 * Shared purl-space provenance graph + deterministic introducer derivation.
 * Both the npm/yarn lane (BOM `dependencies` graph) and the python lane
 * (poetry.lock `[package.dependencies]` tables) translate their source edges
 * into THIS purl-space adjacency, then call {@link deriveIntroductions} for an
 * identical, deterministic direct/introducedBy/path computation.
 *
 * Determinism is structural: derived purely from the edge SET, never source byte
 * or line order. Every frontier expansion and every emitted set/path is sorted
 * by {@link compareCodeUnits}, so two byte-different serializations of the same
 * graph yield identical provenance.
 *
 * The `path` is a deterministic REPRESENTATIVE shortest chain tie-broken by the
 * smallest child purl at each BFS level (see {@link shortestPath}) — NOT a
 * whole-path lexicographic minimum. The npm lane recomputes its representative
 * `path` on the REAL bom-ref graph rather than this purl-space union (the union
 * can fabricate a chain across dup-purl variants), but uses the same per-level
 * sorted tie-break; see npmProvenance. `introducedBy` carries the COMPLETE
 * introducer set, so the single representative `path` is an honest one-of-many
 * for a multi-parent package, never the only introducer.
 */

import {
  compareCodeUnits,
  type DependencyIntroduction,
} from "../model/dependencies";

/** Purl-space directed graph anchored at a synthetic root (the scanned target). */
export interface PurlGraph {
  /** parent purl → sorted-unique child purls (self-edges excluded). */
  edges: Map<string, string[]>;
  /** child purl → sorted-unique parent purls (root excluded). */
  parents: Map<string, string[]>;
  /** The root's declared-direct child purls. */
  rootChildren: Set<string>;
  /** The universe of package purls to emit provenance for (root excluded). */
  nodes: Set<string>;
}

/** Insert one (key→value) into a Set-of-values map. */
export function addToSetMap(
  map: Map<string, Set<string>>,
  key: string,
  value: string,
): void {
  let set = map.get(key);
  if (set === undefined) {
    set = new Set<string>();
    map.set(key, set);
  }
  set.add(value);
}

/** Materialize a Set-of-values map into a sorted-array adjacency map. */
export function sortSetMap(
  map: Map<string, Set<string>>,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const [key, set] of map) {
    out.set(key, [...set].sort(compareCodeUnits));
  }
  return out;
}

interface BfsNode {
  purl: string;
  path: string[];
}

/**
 * Expand one BFS level into the next, marking visited (cycle bound). The result
 * is sorted by purl so the tie-break is stable regardless of parent processing
 * order.
 */
function expandLevel(
  graph: PurlGraph,
  frontier: readonly BfsNode[],
  visited: Set<string>,
): BfsNode[] {
  const next: BfsNode[] = [];
  for (const node of frontier) {
    for (const child of graph.edges.get(node.purl) ?? []) {
      if (visited.has(child)) continue;
      visited.add(child);
      next.push({ purl: child, path: [...node.path, child] });
    }
  }
  return next.sort((a, b) => compareCodeUnits(a.purl, b.purl));
}

/**
 * Deterministic representative shortest root→target purl chain (root-excluded,
 * target-included). BFS seeds the root children sorted by purl; each level is
 * expanded into a frontier re-sorted by CHILD purl ({@link expandLevel}) and a
 * visited set bounds cycles, so the FIRST time `target` is reached yields a
 * stable representative chain.
 *
 * Tie-break is NOT a whole-path lexicographic minimum: among the shortest paths
 * it picks the one reached first by this per-level purl-sorted expansion — i.e.
 * tie-broken by the smallest child purl at each BFS frontier (the
 * smallest-introducer-at-each-level order). This is fully deterministic
 * (derived from the edge SET, never source order) but a different chain than a
 * global lexicographically-smallest-path comparison would select. Returns
 * undefined when unreachable from the root.
 */
export function shortestPath(
  graph: PurlGraph,
  target: string,
): string[] | undefined {
  const visited = new Set<string>();
  let frontier: BfsNode[] = [];
  for (const child of [...graph.rootChildren].sort(compareCodeUnits)) {
    if (visited.has(child)) continue;
    visited.add(child);
    frontier.push({ purl: child, path: [child] });
  }
  while (frontier.length > 0) {
    for (const node of frontier) {
      if (node.purl === target) return node.path;
    }
    frontier = expandLevel(graph, frontier, visited);
  }
  return undefined;
}

/**
 * The SET of purls REACHABLE from the declared roots over the introducer graph
 * (root children seed the frontier; each node's children expand it). Computed
 * ONCE per derivation. A multi-source BFS bounded by a visited set, so cycles
 * terminate and the result is order-independent (derived from the edge SET, not
 * source order). The root itself is not a member; only package purls are.
 *
 * Central reachability invariant: `introducedBy` is intersected with
 * this set in {@link deriveIntroductions}, so a node may name ONLY parents that
 * are themselves root-reachable — making a root-disconnected fabricated
 * introducer unrepresentable for BOTH lanes.
 */
/**
 * Expand one reachability frontier into the next, marking newly-discovered purls
 * in `reachable` (the visited set that bounds cycles). Extracted from
 * {@link reachableFromRoots} to keep nesting shallow.
 */
function expandReachable(
  graph: PurlGraph,
  frontier: readonly string[],
  reachable: Set<string>,
): string[] {
  const next: string[] = [];
  for (const purl of frontier) {
    for (const child of graph.edges.get(purl) ?? []) {
      if (reachable.has(child)) continue;
      reachable.add(child);
      next.push(child);
    }
  }
  return next;
}

function reachableFromRoots(graph: PurlGraph): Set<string> {
  const reachable = new Set<string>();
  let frontier: string[] = [];
  for (const child of graph.rootChildren) {
    if (reachable.has(child)) continue;
    reachable.add(child);
    frontier.push(child);
  }
  while (frontier.length > 0) {
    frontier = expandReachable(graph, frontier, reachable);
  }
  return reachable;
}

/**
 * Per-purl provenance for every node in the graph. Direct nodes carry an empty
 * introducedBy and no path; transitive nodes carry the sorted-unique parent SET
 * (INTERSECTED with the root-reachable set) and a representative tie-broken
 * shortest path (when reachable).
 *
 * CENTRAL REACHABILITY INVARIANT: a node's `introducedBy` may name ONLY
 * parents that are themselves reachable from a declared root. The reachable set
 * is computed once ({@link reachableFromRoots}) and every node's parent set is
 * intersected with it. Consequences (now guaranteed for BOTH the npm and poetry
 * lanes, which both route through this shared function):
 *  - a transitive whose parents are ALL root-disconnected → introducedBy [] →
 *    a true orphan (whyCellOf renders the honest "—", never a fabricated
 *    introducer);
 *  - a transitive with a MIX of reachable + disconnected parents keeps ONLY the
 *    reachable parents;
 *  - `path` stays gated on shortestPath (root-reachability), so introducedBy and
 *    path are now consistent — both honor root-reachability.
 * This makes the npm lane's local Fix-3 introducedBy=[] guard (npmProvenance)
 * redundant; it is retained as a harmless belt-and-braces.
 *
 * Optionality is descoped — no `optional` field is ever emitted.
 */
export function deriveIntroductions(
  graph: PurlGraph,
): Map<string, DependencyIntroduction> {
  const reachable = reachableFromRoots(graph);
  const result = new Map<string, DependencyIntroduction>();
  for (const purl of graph.nodes) {
    const direct = graph.rootChildren.has(purl);
    if (direct) {
      result.set(purl, { direct: true, introducedBy: [] });
      continue;
    }
    // Intersect the purl-space parent SET with the root-reachable set: a parent
    // unreachable from every declared root cannot be a real introducer (the bad
    // state is unrepresentable). Already sorted (parents is a sorted adjacency),
    // so the filter preserves order.
    const introducedBy = (graph.parents.get(purl) ?? []).filter((parent) =>
      reachable.has(parent),
    );
    const introduction: DependencyIntroduction = {
      direct: false,
      introducedBy,
    };
    const path = shortestPath(graph, purl);
    if (path !== undefined) introduction.path = path;
    result.set(purl, introduction);
  }
  return result;
}
