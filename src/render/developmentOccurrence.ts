/**
 * Development-occurrence predicate shared by THIRD_PARTY_LICENSES.md's development-only partition
 * and the CycloneDX `licenses-tool:scope:<target>` property, so the two can never disagree on which
 * occurrences are development.
 */

import { DOCKER_IDENTITY_PREFIX, type Occurrence } from "../model/dependencies";

/**
 * An occurrence is development when it lives in a container marked `[[docker.development]]`, or,
 * outside containers, when it is a dev dependency.
 *
 * @privateRemarks A system package in a development container keeps `isDevDependency: false` (the
 * container re-scope leaves os-scope packages to the os lanes), so container membership decides.
 */
export function isDevelopmentOccurrence(
  occurrence: Occurrence,
  developmentContainers: ReadonlySet<string>,
): boolean {
  return occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX)
    ? developmentContainers.has(occurrence.target)
    : occurrence.isDevDependency;
}
