/**
 * Usage-profile scope gating: the network/distribution flags decide whether a declared obligation
 * class is IN SCOPE, never the verdict itself - the compatibility relation (classify.ts's axis
 * result) always decides the verdict for an in-scope obligation. Data-free by design: this module
 * imports no license-id data (COPYLEFT_IDS, AGPL_IDS, the OSADL/ScanCode maps) and consumes only
 * the axis result's positively-determined obligation tag, so the scope-gating contract can never
 * accidentally re-decide a compatibility question classify.ts already answered.
 *
 * One concrete example carries the principle: an AGPL-licensed, network-deployed target absorbs an
 * AGPL dependency - `network = true` keeps the AGPL obligation class in scope, and the axis (matrix
 * diagonal `Same`) already says the target discharges it, so the modulation leaves `compatible`
 * untouched. The same dependency under an MIT network-deployed target stays `incompatible` for the
 * identical reason: the flag never manufactures a verdict, in either direction.
 */
import type { AxisResult, TargetLicense } from "./classification";

/** The declared usage profile: license + the two scope-gating flags, all mandatory. */
export interface TargetProfile {
  readonly license: TargetLicense;
  /** Gates whether the AGPL/section-13 obligation class is in scope, regardless of distribution. */
  readonly network: boolean;
  /** `"internal"` takes the distribution-triggered copyleft class out of scope (the hold). */
  readonly distribution: "external" | "internal";
}

/** The modulated space: the license axis's five classes, plus the scope-gating hold outcome. */
export type ModulatedClass = AxisResult["class"] | "held-internal";

/** One leaf's post-modulation verdict: the class and its (possibly hold-appended) citation. */
export interface ModulatedResult {
  readonly class: ModulatedClass;
  readonly source: string;
}

/**
 * Pure, total scope gate. `compatible` and `distribution === "external"` are both unconditional
 * identity (the whole distribution-triggered class is in scope externally, and a compatible axis
 * result already means the target discharges the obligation - no flag combination may re-open it).
 * Under `distribution === "internal"`, a negative axis outcome (incompatible/boundary/residual)
 * becomes `held-internal` ONLY when its obligation is positively out of scope: a `copyleft`
 * obligation always holds; an `agpl` obligation holds only when `network === false` (network=true
 * keeps the section-13 class in scope regardless of distribution, so the axis result stands
 * unchanged). The floor is exhaustive: `none` and `unknown` obligations, and the `unassessed-ref`
 * class, are never held - an out-of-scope hold requires a POSITIVELY-known copyleft/agpl
 * obligation, never a guess.
 */
export function applyUsageProfile(axis: AxisResult, profile: TargetProfile): ModulatedResult {
  if (axis.class === "compatible" || profile.distribution === "external") {
    return { class: axis.class, source: axis.source };
  }

  if (axis.class === "unassessed-ref") {
    return { class: axis.class, source: axis.source };
  }

  const heldObligation: boolean =
    axis.obligation === "copyleft" || (axis.obligation === "agpl" && !profile.network);

  if (!heldObligation) {
    return { class: axis.class, source: axis.source };
  }

  return {
    class: "held-internal",
    source: `${axis.source} - held: internal-use-only distribution takes this obligation out of scope (network=${profile.network})`,
  };
}
