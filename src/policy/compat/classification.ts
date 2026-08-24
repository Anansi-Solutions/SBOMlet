/**
 * The compatibility-classification vocabulary: the declared target, the license-axis outcome
 * classes, and a single leaf's axis verdict. A dependency-free leaf shared by the license-axis
 * classifier and the usage-profile gate.
 */

/** The declared target: a single FOSS SPDX id, or the literal `proprietary` keyword. */
export type TargetLicense = { kind: "oss"; id: string } | { kind: "proprietary" };

/** The license axis's five outcomes - `unassessed-ref` is distinct from `residual`: an
 * unassessed reference is never silently treated as a known permissive license. */
export type AxisClass = "compatible" | "incompatible" | "boundary" | "residual" | "unassessed-ref";

/**
 * A leaf's positively-determined obligation class, read independently of which axis tier decided
 * the class above - the usage-profile modulation's only input (profile.ts stays data-free).
 */
export type ObligationClass = "none" | "copyleft" | "agpl" | "unknown";

/**
 * One leaf's license-axis verdict: the class, its reader-facing citation, and its obligation tag.
 */
export interface AxisResult {
  readonly class: AxisClass;
  /** Reader-facing citation of the deciding tier's value, e.g. `"OSADL: No"` - never a URL/date. */
  readonly source: string;
  readonly obligation: ObligationClass;
}
