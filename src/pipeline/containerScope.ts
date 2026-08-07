/**
 * The container re-scope transform.
 *
 * The docker-image collector stamps `scope:"os"` on every component it
 * finds, deb and pip alike (see pipeline.ts's readCommittedDockerSbom) — the
 * collector does not distinguish base-image plumbing from an application
 * dependency installed into the image. This transform is the one place that
 * distinction is made: it re-keys `scope` (and, for a development-marked
 * container, `isDevDependency`) using the SAME {@link OS_PACKAGE_ECOSYSTEMS}
 * allowlist the render layer's System/Application split uses, so the engine
 * carve-out and the document layout can never disagree about which packages
 * are routine.
 *
 * A base-image system package (an allowlisted ecosystem) stays scope "os" —
 * routine, exactly as before: os-downgrade, copyleft de-noise, and the AGPL
 * escalation apply unchanged. An application-ecosystem package baked into
 * the image is an application dependency wherever it lives: re-keyed to
 * scope "app", it gates like any other application dependency in a
 * production container, and — reusing the existing dev/prod lever rather
 * than inventing a new scope value — dev-downgrades to warn when its
 * container occurrence is marked development, exactly like a devDependency.
 *
 * Pure: returns a NEW model, cloning only the touched entries and
 * occurrences; a package the transform does not need to change is returned
 * by reference.
 */

import {
  purlEcosystem,
  type CanonicalDependencies,
  type Occurrence,
  type PackageEntry,
} from "../model/dependencies";
import { OS_PACKAGE_ECOSYSTEMS } from "../policy/osEcosystems";

/**
 * Re-key `scope` and `isDevDependency` for every still-`"os"` package
 * against the OS-ecosystem allowlist and the resolved development-container
 * set. A package already scope "app" (the merge-time shared-purl promotion,
 * merge.ts) is left untouched — it already gates, and re-marking its
 * occurrences here would be a second, redundant lever for the same fact.
 *
 * Per-occurrence honesty: for a re-keyed application-ecosystem package, only
 * the docker occurrences whose container identity is in
 * `developmentContainers` are marked `isDevDependency: true` — a package
 * shipped in both a production and a development-marked container keeps its
 * production occurrence gating and its development occurrence downgradable,
 * independently.
 */
export function applyContainerScopes(
  model: CanonicalDependencies,
  developmentContainers: ReadonlySet<string>,
): CanonicalDependencies {
  return {
    packages: model.packages.map((pkg) => rescoped(pkg, developmentContainers)),
  };
}

/** Re-key one package; returns the SAME reference when nothing changes. */
function rescoped(
  pkg: PackageEntry,
  developmentContainers: ReadonlySet<string>,
): PackageEntry {
  if (pkg.scope !== "os") return pkg;
  if (OS_PACKAGE_ECOSYSTEMS.has(purlEcosystem(pkg.purl))) return pkg;
  return {
    ...pkg,
    scope: "app",
    occurrences: pkg.occurrences.map((occurrence) =>
      rescopedOccurrence(occurrence, developmentContainers),
    ),
  };
}

/**
 * Mark a docker occurrence development iff its container identity is in the
 * resolved set. A non-docker occurrence (defensively — an os-scope package
 * should carry only docker occurrences) and an occurrence already marked
 * development pass through unchanged.
 */
function rescopedOccurrence(
  occurrence: Occurrence,
  developmentContainers: ReadonlySet<string>,
): Occurrence {
  if (occurrence.isDevDependency) return occurrence;
  if (!developmentContainers.has(occurrence.target)) return occurrence;
  return { ...occurrence, isDevDependency: true };
}
