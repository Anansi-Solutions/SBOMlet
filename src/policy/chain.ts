/**
 * Per-target dependency graphs, reconstructed from the merged model.
 *
 * A `[[compatible]]` package entry states whose use of a package was judged, so the engine has to
 * know how that package actually arrives at each target. Every occurrence collected by a lane that
 * derives a dependency graph carries its complete direct-introducer set, which is all the graph
 * this needs: reversing those sets per target rebuilds the introducer edges, and the packages the
 * project declared directly are marked as such.
 *
 * The graph lives in PURL space, so two components sharing a purl collapse into one node. That can
 * join a chain through a node the two halves of which never co-existed on one concrete instance,
 * inventing a path that is not there. The direction is safe: an invented path can only make an
 * acceptance look less covered than it is, never more.
 */

import {
  compareCodeUnits,
  purlDisplayName,
  type CanonicalDependencies,
} from "../model/dependencies";
import { SELF_PARENT } from "./schema";

/** One target's introducer graph over the packages the scan reported for it. */
export interface TargetDependencyGraph {
  /**
   * Node purl -> the purls recorded as introducing it. A node ABSENT from this map has no recorded
   * provenance at all - a first-party workspace member the merge excluded, say - which is a
   * different answer from a recorded empty list (reported, and introduced by nothing reachable).
   */
  readonly parents: ReadonlyMap<string, readonly string[]>;
  /** Node purl -> display name: the model's own where it has one, else read from the purl. */
  readonly names: ReadonlyMap<string, string>;
  /** The purls the project at this target declared as direct dependencies. */
  readonly direct: ReadonlySet<string>;
}

interface MutableGraph {
  parents: Map<string, readonly string[]>;
  names: Map<string, string>;
  direct: Set<string>;
  /** Introducer purls seen so far; named from their purl unless the model names them first. */
  introducers: Set<string>;
}

function emptyGraph(): MutableGraph {
  return {
    parents: new Map(),
    names: new Map(),
    direct: new Set(),
    introducers: new Set(),
  };
}

/** Name every introducer the model itself never reported a package for. */
function nameRemainingIntroducers(graph: MutableGraph): void {
  for (const purl of [...graph.introducers].sort(compareCodeUnits)) {
    if (graph.names.has(purl)) {
      continue;
    }

    const name = purlDisplayName(purl);

    if (name !== undefined) {
      graph.names.set(purl, name);
    }
  }
}

/**
 * One introducer graph per scanned target, built in a single pass over the model. Targets whose
 * occurrences carry no provenance still get a graph - an empty one - so a caller never has to tell
 * "no such target" apart from "nothing recorded there".
 */
export function dependencyGraphsByTarget(
  model: CanonicalDependencies,
): ReadonlyMap<string, TargetDependencyGraph> {
  const graphs = new Map<string, MutableGraph>();

  for (const entry of model.packages) {
    for (const occurrence of entry.occurrences) {
      let graph = graphs.get(occurrence.target);

      if (graph === undefined) {
        graph = emptyGraph();
        graphs.set(occurrence.target, graph);
      }

      graph.names.set(entry.purl, entry.name);

      const introduction = occurrence.introduction;

      if (introduction === undefined) {
        continue;
      }

      if (introduction.direct) {
        graph.direct.add(entry.purl);
      }

      graph.parents.set(entry.purl, introduction.introducedBy);
      for (const introducer of introduction.introducedBy) {
        graph.introducers.add(introducer);
      }
    }
  }

  for (const graph of graphs.values()) {
    nameRemainingIntroducers(graph);
  }

  return graphs;
}

/** One step of the walk upward: a node and the chain from it down to the package asked about. */
interface Ascent {
  purl: string;
  chain: readonly string[];
}

/** The package an entry cannot cover, and the chain that carries it. */
export interface UncoveredIntroduction {
  /** The governed package the chain ends at - the one to name first when reporting it. */
  readonly purl: string;
  /** Purls from the project's own dependency down to that package. */
  readonly chain: readonly string[];
}

/**
 * Does this node hang off the project itself - is the chain that reaches it complete?
 *
 * Either the project declared it directly, or the model records nothing about where it comes from:
 * an introducer the inventory excludes, a first-party workspace member. The second case is the
 * fail-more reading, and the reserved token never covers it - the package arrives through that
 * member, which is a named parent or nothing.
 *
 * The reserved token is not consulted here because it covers one edge only, the subject's own
 * direct edge, which {@link uncoveredChain} settles before the walk starts. Every other node on the
 * way up was already checked against the judged names by {@link ascend}.
 */
function hangsOffProject(graph: TargetDependencyGraph, purl: string): boolean {
  return graph.direct.has(purl) || !graph.parents.has(purl);
}

/**
 * Expand one level of the walk toward the project, skipping every introducer the entry named
 * - those chains ARE what it judged. Sorted by the chain it carries, then by purl, so the first
 * answer found is the same on every run.
 */
function ascend(
  graph: TargetDependencyGraph,
  frontier: readonly Ascent[],
  visited: Set<string>,
  judgedUnder: ReadonlySet<string>,
): Ascent[] {
  const next: Ascent[] = [];

  for (const node of frontier) {
    for (const introducer of graph.parents.get(node.purl) ?? []) {
      if (visited.has(introducer)) {
        continue;
      }

      visited.add(introducer);
      if (judgedUnder.has(graph.names.get(introducer) ?? "")) {
        continue;
      }

      next.push({ purl: introducer, chain: [introducer, ...node.chain] });
    }
  }

  return next.sort(
    (a, b) =>
      compareCodeUnits(a.chain.join("\u0000"), b.chain.join("\u0000")) ||
      compareCodeUnits(a.purl, b.purl),
  );
}

/**
 * The shortest chain by which `purl` reaches the project without passing through anything
 * `judgedUnder` names, or undefined when every chain it has does.
 *
 * Breadth-first toward the project, so the reported chain is the shortest one; a visited set bounds
 * cycles. An occurrence the scan recorded no provenance for yields undefined - nothing is known
 * about how it arrives, and an unverifiable path is not evidence of a bypass.
 */
function uncoveredChain(
  graph: TargetDependencyGraph,
  purl: string,
  judgedUnder: ReadonlySet<string>,
): readonly string[] | undefined {
  if (!graph.parents.has(purl)) {
    return undefined;
  }

  // The one edge the reserved token covers: this package, declared directly by the project. A
  // declared-direct package has no introducers, so there is nothing else to walk.
  if (graph.direct.has(purl)) {
    return judgedUnder.has(SELF_PARENT) ? undefined : [purl];
  }

  const visited = new Set<string>([purl]);
  let frontier: Ascent[] = [{ purl, chain: [purl] }];

  while (frontier.length > 0) {
    for (const node of frontier) {
      if (hangsOffProject(graph, node.purl)) {
        return node.chain;
      }
    }

    frontier = ascend(graph, frontier, visited, judgedUnder);
  }

  return undefined;
}

/**
 * The first governed package that reaches the project through a chain the entry never judged.
 *
 * One answer per entry and target, whatever the entry governs there: an acceptance states a
 * judgment about how these packages arrive, so a single chain around it makes the whole statement
 * untrue. `governed` decides the quantification - packages outside the entry's scope are not
 * passed, and so can never void it - and its order decides which chain is reported.
 */
export function firstUncoveredIntroduction(
  graph: TargetDependencyGraph,
  governed: readonly string[],
  judgedUnder: ReadonlySet<string>,
): UncoveredIntroduction | undefined {
  for (const purl of governed) {
    const chain = uncoveredChain(graph, purl, judgedUnder);

    if (chain !== undefined) {
      return { purl, chain };
    }
  }

  return undefined;
}
