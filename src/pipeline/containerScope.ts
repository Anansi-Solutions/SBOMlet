/**
 * The container re-scope transform.
 *
 * The docker-image collector stamps `scope:"os"` on every component it finds, deb and pip alike
 * (see pipeline.ts's readCommittedDockerSbom) - the collector does not distinguish base-image
 * plumbing from an application dependency installed into the image. This transform is the one place
 * that distinction is made: it re-keys `scope` (and, for a development-marked
 * container, `isDevDependency`) using the SAME {@link OS_PACKAGE_ECOSYSTEMS}
 * allowlist the render layer's System/Application split uses, so the engine carve-out and the
 * document layout can never disagree about which packages are routine.
 *
 * A base-image system package (an allowlisted ecosystem) stays scope "os" - routine, exactly as
 * before: os-downgrade, copyleft de-noise, and the AGPL escalation apply unchanged. An
 * application-ecosystem package baked into the image is an application dependency wherever it
 * lives: re-keyed to scope "app", it gates like any other application dependency in a production
 * container, and - reusing the existing dev/prod lever rather than inventing a new scope value -
 * * dev-downgrades to warn when its container occurrence is marked development, exactly like a
 * devDependency.
 *
 * Pure: returns a NEW model, cloning only the touched entries and occurrences; a package the
 * transform does not need to change is returned by reference.
 */

import {
  purlEcosystem,
  type CanonicalDependencies,
  type Occurrence,
  type PackageEntry,
} from "../model/dependencies";
import { OS_PACKAGE_ECOSYSTEMS } from "../policy/osEcosystems";

/**
 * Re-key `scope` for every still-`"os"` package against the OS-ecosystem allowlist, and dev-mark
 * occurrences for every package that ends up scope "app" - whether re-keyed here or already "app"
 * going in (the merge's shared-purl promotion, merge.ts): the docker collector never sets
 * isDevDependency itself, so a shared package's docker occurrence has no other route to the
 * [[docker.development]] marking.
 *
 * Per-occurrence honesty: only the docker occurrences whose container identity is in
 * `developmentContainers` are marked `isDevDependency: true` - a package shipped in both a
 * production and a development-marked container keeps its production occurrence gating and its
 * development occurrence downgradable, independently.
 *
 * The normative decision tree is docs/reference/dependency-classification.md - update both
 * together.
 */
export function applyContainerScopes(
  model: CanonicalDependencies,
  developmentContainers: ReadonlySet<string>,
): CanonicalDependencies {
  return {
    packages: model.packages.map((pkg) => rescoped(pkg, developmentContainers)),
  };
}

/**
 * Re-key one package; returns the SAME reference when nothing changes.
 *
 * A package already scope "app" still reaches the per-occurrence dev-mark below (never re-keyed,
 * never skipped): the merge's shared-purl promotion (merge.ts, app wins over os) settles scope
 * BEFORE this transform runs, so a package that is a real workspace dependency AND also baked into
 * a development-marked image would otherwise keep its docker occurrence's isDevDependency at the
 * docker collector's always-false default - the scope-level "it already gates" fact says nothing
 * about THIS occurrence, which has no other source of truth for the [[docker.development]] marking.
 */
function rescoped(
  pkg: PackageEntry,
  developmentContainers: ReadonlySet<string>,
): PackageEntry {
  if (
    pkg.scope === "os" &&
    OS_PACKAGE_ECOSYSTEMS.has(purlEcosystem(pkg.purl))
  ) {
    return pkg;
  }
  const occurrences = pkg.occurrences.map((occurrence) =>
    rescopedOccurrence(occurrence, developmentContainers),
  );
  const occurrencesChanged = occurrences.some(
    (occurrence, index) => occurrence !== pkg.occurrences[index],
  );
  if (pkg.scope === "app" && !occurrencesChanged) return pkg;
  return { ...pkg, scope: "app", occurrences };
}

/**
 * Mark a docker occurrence development iff its container identity is in the resolved set. A
 * non-docker occurrence (defensively - an os-scope package should carry only docker occurrences)
 * and an occurrence already marked development pass through unchanged.
 */
function rescopedOccurrence(
  occurrence: Occurrence,
  developmentContainers: ReadonlySet<string>,
): Occurrence {
  if (occurrence.isDevDependency) return occurrence;
  if (!developmentContainers.has(occurrence.target)) return occurrence;
  return { ...occurrence, isDevDependency: true };
}
