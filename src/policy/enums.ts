/**
 * The closed value sets a policy entry chooses from.
 *
 * Closed sets are what make an entry's claim checkable: a justification the current detection
 * proves wrong can only fail the check if the tool knows what each value asserts. Free prose stays
 * in the entry's own comment field. Both lists are pinned in alphabetical order and the documented
 * tables mirror that order.
 */

/**
 * Why an otherwise-incompatible package is accepted.
 *
 * - `build-time-only`: consumed while building, absent from what ships.
 * - `development-tool-only`: a tool for working on the repository, never reached by the product.
 * - `license-reviewed`: a human read the license and accepted its obligations. The sanctioned
 *   fallback when no structural reason applies.
 * - `os-package-unmodified`: a distribution package shipped inside a container image exactly as it
 *   arrived, not linked into the software.
 * - `unused-transitive`: pulled in by a dependency but never reached at runtime.
 */
export const RATIONALE_VALUES = [
  "build-time-only",
  "development-tool-only",
  "license-reviewed",
  "os-package-unmodified",
  "unused-transitive",
] as const;

/** The reason an entry gives for accepting a package. */
export type Rationale = (typeof RATIONALE_VALUES)[number];

/**
 * Why a recorded license expression is preferred over what detection reports.
 *
 * - `contradictory-claims-recorded`: the sources disagree irreconcilably and the recorded
 *   expression is the reading the maintainer stands behind. The sanctioned fallback.
 * - `declared-more-complete`: the package's own metadata names licenses the scan cannot see.
 * - `dual-license-choice`: the package offers a choice of licenses and the entry records the one
 *   taken.
 * - `license-not-found`: no source states a license; the expression comes from evidence outside
 *   detection.
 * - `scan-found-additional-content`: the intensive scan sees further licenses that do govern
 *   content the package ships.
 * - `scan-more-precise`: the intensive scan resolves an under-specified declared label to the exact
 *   license.
 * - `scan-overdetection`: the intensive scan reports licenses from files that do not govern the
 *   package.
 */
export const JUSTIFICATION_VALUES = [
  "contradictory-claims-recorded",
  "declared-more-complete",
  "dual-license-choice",
  "license-not-found",
  "scan-found-additional-content",
  "scan-more-precise",
  "scan-overdetection",
] as const;

/** The reason an entry gives for its recorded license expression. */
export type Justification = (typeof JUSTIFICATION_VALUES)[number];
