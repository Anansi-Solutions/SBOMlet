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
