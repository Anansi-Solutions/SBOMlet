/**
 * License-axis classification: target license x dependency leaf, through the four-tier fallback
 * chain (OSADL matrix cell -> OSADL copyleft class -> ScanCode LicenseDB category -> SBOMlet's
 * literal copyleft sets).
 *
 * Tier order decides the axis class: the first tier that covers the leaf wins, exactly mirroring
 * the "first-tier-wins" runtime posture consistency.ts documents for the underlying data. The
 * obligation tag is a SEPARATE, tier-order-independent read of the same three datasets (never
 * guessed) - see {@link classifyLeaf}'s doc for the exact priority. Pure, deterministic, no I/O;
 * consumed by nothing yet (expression composition and the usage-profile modulation land in later
 * commits of this same wave).
 */
import { AGPL_IDS, COPYLEFT_IDS } from "../copyleft";
import {
  OSADL_COPYLEFT_CLASS,
  OSADL_MATRIX,
  SCANCODE_CATEGORY,
  type OsadlCopyleftClass,
  type OsadlMatrixCell,
} from "./data";

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

/** True for a LicenseRef-/DocumentRef- id - SPDX grammar syntax, not a license-id comparison. */
function isRefLeaf(id: string): boolean {
  return id.startsWith("LicenseRef-") || id.startsWith("DocumentRef-");
}

/**
 * The base id of a rendered leaf: strips a trailing ` WITH exception` clause, then a trailing `+`.
 * The one conservative fallback direction this module uses for both WITH and `plus` leaves the
 * vetted data does not model exactly - `X WITH e` and `X+` both read as "at least as restrictive as
 * X" (@privateRemarks: an exception only narrows obligations, `plus` only widens the accepted
 * version range, so falling back to the bare id is safe, never permissive-by-omission).
 */
function baseLeafId(rendered: string): string {
  const withoutException = rendered.replace(/ WITH .+$/, "");

  return withoutException.endsWith("+") ? withoutException.slice(0, -1) : withoutException;
}

/** Lookup keys for a rendered leaf, exact form first, then its base id (deduped when equal). */
function leafKeys(leaf: string): readonly string[] {
  const base = baseLeafId(leaf);

  return base === leaf ? [leaf] : [leaf, base];
}

/** Maps a raw OSADL matrix cell to an axis class (OSS targets only - proprietary has no rows). */
function classifyMatrixCell(cell: OsadlMatrixCell): AxisClass {
  switch (cell) {
    case "Same":
    case "Yes":
      return "compatible";
    case "No":
      return "incompatible";
    case "Unknown":
    case "Check dependency":
      return "residual";
  }
}

/**
 * Tier 1 (OSS targets only): the target's own matrix row, tried under both lookup keys. Returns
 * undefined when the target itself is not a matrix row, or the leaf is uncovered by that row - the
 * vetted-pairwise-data-only posture for OSS: only an actual cell may decide `incompatible`.
 */
function matrixTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  if (target.kind !== "oss") {
    return undefined;
  }

  const row = OSADL_MATRIX.get(target.id);

  if (row === undefined) {
    return undefined;
  }

  for (const key of keys) {
    const cell = row.get(key);

    if (cell !== undefined) {
      return { class: classifyMatrixCell(cell), source: `OSADL: ${cell}` };
    }
  }

  return undefined;
}

/**
 * Maps an OSADL copyleft class to an axis class. Proprietary targets follow D2 (`No` -> compatible,
 * `Yes (restricted)` -> boundary, `Yes` -> incompatible, `Questionable` -> residual - a real
 * posture with a boundary tier); OSS targets falling back to this tier have no pairwise data, so
 * only `No` may decide `compatible` - every other class is an honest `residual`, never
 * `incompatible`.
 */
function classifyOsadlClass(kind: TargetLicense["kind"], cls: OsadlCopyleftClass): AxisClass {
  if (kind === "proprietary") {
    switch (cls) {
      case "No":
        return "compatible";
      case "Yes (restricted)":
        return "boundary";
      case "Yes":
        return "incompatible";
      case "Questionable":
        return "residual";
    }
  }

  return cls === "No" ? "compatible" : "residual";
}

/** Tier 2: the leaf's own OSADL copyleft class, tried under both lookup keys. */
function osadlClassTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  for (const key of keys) {
    const cls = OSADL_COPYLEFT_CLASS.get(key);

    if (cls !== undefined) {
      return {
        class: classifyOsadlClass(target.kind, cls),
        source: `OSADL copyleft class: ${cls}`,
      };
    }
  }

  return undefined;
}

/**
 * Maps a ScanCode LicenseDB category to an axis class. Permissive/Public Domain are compatible for
 * both target kinds; a proprietary target additionally distinguishes Copyleft Limited (boundary)
 * from Copyleft (incompatible), per D2's ScanCode extension; every other category (and the whole
 * OSS fallback branch) is residual - no pairwise data, no fail.
 */
function classifyScancodeCategory(kind: TargetLicense["kind"], category: string): AxisClass {
  if (category === "Permissive" || category === "Public Domain") {
    return "compatible";
  }

  if (kind !== "proprietary") {
    return "residual";
  }

  if (category === "Copyleft Limited") {
    return "boundary";
  }

  return category === "Copyleft" ? "incompatible" : "residual";
}

/** Tier 3: the leaf's own ScanCode LicenseDB category, tried under both lookup keys. */
function scancodeTier(
  target: TargetLicense,
  keys: readonly string[],
): { class: AxisClass; source: string } | undefined {
  for (const key of keys) {
    const category = SCANCODE_CATEGORY.get(key);

    if (category !== undefined) {
      return {
        class: classifyScancodeCategory(target.kind, category),
        source: `ScanCode LicenseDB: ${category}`,
      };
    }
  }

  return undefined;
}

/**
 * Tier 4, the exhaustive fallback (never undefined): SBOMlet's own literal copyleft sets. A member
 * is an honest `residual` - vetted data does not cover it, but it is a known copyleft license, so
 * it is never silently `compatible`; a non-member keeps today's `default:ok` semantics.
 */
function literalSetTier(keys: readonly string[]): { class: AxisClass; source: string } {
  if (keys.some((key) => COPYLEFT_IDS.has(key))) {
    return {
      class: "residual",
      source: "SBOMlet's literal copyleft set (no vetted compatibility data)",
    };
  }

  return { class: "compatible", source: "not a known copyleft license" };
}

/**
 * The obligation tag: a positively-determined read of the leaf's OWN data (never the matrix cell
 * that decided the axis class above), independent of tier order. Priority: an AGPL_IDS member is
 * `agpl`; failing that, any of COPYLEFT_IDS membership / OSADL class Yes(-restricted) / ScanCode
 * Copyleft(-Limited) is `copyleft`; failing that, any of OSADL class No / ScanCode Permissive-or-
 * Public-Domain / no data anywhere for a non-copyleft id is `none`; otherwise `unknown` - never
 * guessed from a Questionable class or an absent dataset entry alone.
 */
function obligationFor(keys: readonly string[]): ObligationClass {
  if (keys.some((key) => AGPL_IDS.has(key))) {
    return "agpl";
  }

  const copyleftSignal =
    keys.some((key) => COPYLEFT_IDS.has(key)) ||
    keys.some((key) => {
      const cls = OSADL_COPYLEFT_CLASS.get(key);

      return cls === "Yes" || cls === "Yes (restricted)";
    }) ||
    keys.some((key) => {
      const category = SCANCODE_CATEGORY.get(key);

      return category === "Copyleft" || category === "Copyleft Limited";
    });

  if (copyleftSignal) {
    return "copyleft";
  }

  const hasAnyTierData = keys.some(
    (key) => OSADL_COPYLEFT_CLASS.has(key) || SCANCODE_CATEGORY.has(key),
  );
  const permissiveSignal =
    keys.some((key) => OSADL_COPYLEFT_CLASS.get(key) === "No") ||
    keys.some((key) => {
      const category = SCANCODE_CATEGORY.get(key);

      return category === "Permissive" || category === "Public Domain";
    }) ||
    !hasAnyTierData;

  return permissiveSignal ? "none" : "unknown";
}

/**
 * Classifies one leaf against a target license through the four-tier chain: the first tier that
 * covers the leaf decides its axis class; the obligation tag is derived separately from the SAME
 * tier data (see {@link obligationFor}). A `LicenseRef-`/`DocumentRef-` leaf is the one exception
 * to tier order - it uses matrix tier data when an exact matrix row covers it (the one class of
 * `LicenseRef-scancode-*` ids the OSADL matrix models), and `unassessed-ref` (obligation `unknown`)
 * otherwise, never falling through to the class/category/literal-set tiers a ref cannot honestly
 * satisfy honestly.
 */
export function classifyLeaf(target: TargetLicense, leaf: string): AxisResult {
  const keys = leafKeys(leaf);
  const matrixHit = matrixTier(target, keys);

  if (matrixHit !== undefined) {
    return { ...matrixHit, obligation: obligationFor(keys) };
  }

  if (isRefLeaf(keys[0]!)) {
    return {
      class: "unassessed-ref",
      source: "unassessed LicenseRef/DocumentRef reference",
      obligation: "unknown",
    };
  }

  const hit = osadlClassTier(target, keys) ?? scancodeTier(target, keys) ?? literalSetTier(keys);

  return { ...hit, obligation: obligationFor(keys) };
}
