import { basename } from "node:path";

import { sanitizeEvidenceText } from "../../merge/merge";
import { asRawLicense, compareCodeUnits, type RawLicense } from "../../model/dependencies";
import { canonicalizeExpression } from "../../normalize/expression";
import { SCANCODE_TOOL } from "./tool";

/** Cap on copyright lines returned per scanned package (extractor-cap parity). */
const MAX_SCANCODE_COPYRIGHT_LINES = 20;

/** A root-level legal file basename ScanCode's election treats as authoritative. */
const LEGAL_FILE_PATTERN = /^(LICENSE|LICENCE|COPYING|NOTICE)(\..*)?$/i;

/** A package-manifest basename - the election fallback. */
const MANIFEST_FILE_PATTERN = /^(package\.json|METADATA)$/i;

/** True when an elected SPDX expression is ScanCode's own unresolvable-noise id. */
function isLicenseRefNoise(expression: string): boolean {
  return expression.includes("LicenseRef-scancode-");
}

/**
 * True iff path sits directly at the scan root - exactly two forward-slash-separated segments
 * (`<scanRootBasename>/<filename>`). A manifest (`package.json`, METADATA) lives at the scan root
 * in every layout election sees - an npm package's root, a wheel's dist-info root - so that's a
 * property of the MANIFEST LANE itself, unlike a legal file's own-location, which is a property of
 * the LAYOUT a candidate knows about (see `isPackageOwnLegalPath` on `electFromPattern` below).
 * Fixing it here, rather than delegating to the candidate, closes a gap where a dist-info
 * candidate's widened legal-file admission (PEP 639's `licenses/` subtree) would otherwise also
 * widen the manifest lane, making a nested `licenses/METADATA` electable as the manifest.
 */
function isRootLevelManifestPath(path: string): boolean {
  return !path.includes("\\") && path.split("/").length === 2;
}

/** One narrowed `files[]` entry we read from scancode's `--json-pp` output. */
interface RawScancodeFile {
  path?: unknown;
  detected_license_expression_spdx?: unknown;
  copyrights?: unknown;
}

/** True iff a raw files[] entry is a well-shaped object we can read fields from. */
function isRawScancodeFile(raw: unknown): raw is RawScancodeFile {
  return typeof raw === "object" && raw !== null;
}

/**
 * Elect the first file entry matching a basename pattern with a non-null, non-noise expression,
 * admitted by `isAdmissiblePath` - the misattribution guard (a vendored dependency's license must
 * never be attributed to the scanned package). For the legal-file lane, that guard is decided
 * entirely by the scan candidate that produced this path (see `ScanCandidate` in sources.ts); for
 * the manifest lane, it is the lane-fixed {@link isRootLevelManifestPath} instead (see
 * `electExpression`). Either way, this function only ever asks the predicate it is given - it
 * carries no layout knowledge of its own, not which ecosystem, not where a package's own files
 * live.
 */
function electFromPattern(
  entries: RawScancodeFile[],
  pattern: RegExp,
  lane: string,
  isAdmissiblePath: (path: string) => boolean,
): { raw: RawLicense; via: string } | undefined {
  for (const entry of entries) {
    const path = entry.path;

    if (typeof path !== "string") {
      continue;
    }

    if (!isAdmissiblePath(path)) {
      continue;
    }

    if (!pattern.test(basename(path))) {
      continue;
    }

    const expression = entry.detected_license_expression_spdx;

    if (typeof expression !== "string" || expression.length === 0) {
      continue;
    }

    if (isLicenseRefNoise(expression)) {
      continue;
    }

    return {
      raw: asRawLicense(canonicalizeExpression(asRawLicense(expression))),
      via: `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/${lane}`,
    };
  }

  return undefined;
}

/**
 * Elect ONE raw SPDX expression from the scanned files: a legal file (basename matches {@link
 * LEGAL_FILE_PATTERN}) admitted by `isPackageOwnLegalPath` with a non-null, non-noise expression
 * wins; else the first package-manifest entry ({@link MANIFEST_FILE_PATTERN}) AT THE SCAN ROOT (see
 * {@link isRootLevelManifestPath}) with a non-null, non-noise expression; else undefined (never an
 * AND-combine across files). `isPackageOwnLegalPath` is the scan candidate's own admission
 * predicate (see `ScanCandidate` in sources.ts) and gates the legal-file lane only - a manifest
 * lives at the scan root in every layout election supports, so the manifest lane is root-only
 * unconditionally, never delegated to the candidate (a dist-info candidate's widened `licenses/`
 * admission is a legal-file-lane concern; letting it widen the manifest lane too would make a
 * nested `licenses/METADATA` electable as the manifest). An elected expression containing
 * `LicenseRef-scancode-` is rejected within each lane (treated as no answer there, ADR-0007) rather
 * than accepted as noise - the caller falls through to the next lane, or to a clean no-answer if
 * both lanes reject. The winning expression is simplified via {@link canonicalizeExpression} before
 * it is returned, so ScanCode's own boolean-algebra noise never reaches the memo or a claim.
 */
export function electExpression(
  files: unknown,
  isPackageOwnLegalPath: (path: string) => boolean,
): { raw: RawLicense; via: string } | undefined {
  if (!Array.isArray(files)) {
    return undefined;
  }

  const entries = files.filter(isRawScancodeFile);

  const legal = electFromPattern(
    entries,
    LEGAL_FILE_PATTERN,
    "license-file",
    isPackageOwnLegalPath,
  );

  if (legal !== undefined) {
    return legal;
  }

  return electFromPattern(entries, MANIFEST_FILE_PATTERN, "manifest", isRootLevelManifestPath);
}

/** One narrowed copyrights[] entry. */
interface RawCopyrightEntry {
  copyright?: unknown;
}

/**
 * Collect the union of all `copyrights[].copyright` strings across every scanned file, sanitized
 * via the same control-char intake rule evidence text uses ({@link sanitizeEvidenceText},
 * merge.ts), deduped, {@link compareCodeUnits}-sorted, and capped at {@link
 * MAX_SCANCODE_COPYRIGHT_LINES}.
 */
export function electCopyrights(files: unknown): string[] {
  if (!Array.isArray(files)) {
    return [];
  }

  const seen = new Set<string>();

  for (const raw of files) {
    if (!isRawScancodeFile(raw)) {
      continue;
    }

    const copyrights = (raw as { copyrights?: unknown }).copyrights;

    if (!Array.isArray(copyrights)) {
      continue;
    }

    for (const entry of copyrights) {
      // Tolerant narrowing, matching the rest of this parse path: a null or mistyped element is
      // skipped, never a TypeError mid-scan.
      if (typeof entry !== "object" || entry === null) {
        continue;
      }

      const text = (entry as RawCopyrightEntry).copyright;

      if (typeof text !== "string" || text.length === 0) {
        continue;
      }

      seen.add(sanitizeEvidenceText(text));
    }
  }

  return [...seen].sort(compareCodeUnits).slice(0, MAX_SCANCODE_COPYRIGHT_LINES);
}
