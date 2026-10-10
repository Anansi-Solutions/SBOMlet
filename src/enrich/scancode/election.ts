import { basename } from "node:path";

import { sanitizeEvidenceText } from "../../merge/merge";
import { asRawLicense, compareCodeUnits, type RawLicense } from "../../model/dependencies";
import { canonicalizeExpression } from "../../normalize/expression";
import { SCANCODE_TOOL } from "./tool";
import type { ScancodeFile } from "../../validate/scancode";

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

/** The license expression ScanCode election picked for a scanned package. */
export interface ElectedExpression {
  /** The canonicalized SPDX expression. */
  raw: RawLicense;
  /** The pinned tool and the lane that produced it, as `<tool>@<version>/<lane>`. */
  via: string;
}

/** The outcome of one election lane. */
export interface LaneElection {
  /** The lane's winner; absent when no file in the lane qualified. */
  elected?: ElectedExpression;
  /** The first lane file whose scan errored without an expression; absent when none did. */
  erroredPath?: string;
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
 *
 * @returns The winner, or the first matching admissible path whose scan errored without an
 * expression.
 */
function electFromPattern(
  files: readonly ScancodeFile[],
  pattern: RegExp,
  lane: string,
  isAdmissiblePath: (path: string) => boolean,
): LaneElection {
  let erroredPath: string | undefined;

  for (const file of files) {
    const path = file.path;

    if (path === undefined) {
      continue;
    }

    if (!isAdmissiblePath(path)) {
      continue;
    }

    if (!pattern.test(basename(path))) {
      continue;
    }

    const expression = file.detected_license_expression_spdx;

    if (expression === undefined) {
      if ((file.scan_errors?.length ?? 0) > 0) {
        erroredPath ??= path;
      }

      continue;
    }

    if (isLicenseRefNoise(expression)) {
      continue;
    }

    return {
      elected: {
        raw: asRawLicense(canonicalizeExpression(asRawLicense(expression))),
        via: `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/${lane}`,
      },
    };
  }

  return { erroredPath };
}

/**
 * Reject a lane that ended without a winner on a failed scan.
 *
 * @throws When a lane found no winner past a file whose scan errored: its missing expression is a
 * failed scan, not evidence of no license.
 */
function rejectFailedScan(erroredPath: string | undefined): void {
  if (erroredPath !== undefined) {
    throw new Error(
      `scancode reported scan errors on ${JSON.stringify(erroredPath)}, a file election reads`,
    );
  }
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
 *
 * @throws When a lane ends without a winner and one of its files errored without an expression;
 * an errored legal file also blocks the manifest fallback.
 */
export function electExpression(
  files: readonly ScancodeFile[],
  isPackageOwnLegalPath: (path: string) => boolean,
): ElectedExpression | undefined {
  const legal = electFromPattern(files, LEGAL_FILE_PATTERN, "license-file", isPackageOwnLegalPath);

  if (legal.elected !== undefined) {
    return legal.elected;
  }

  rejectFailedScan(legal.erroredPath);

  const manifest = electFromPattern(
    files,
    MANIFEST_FILE_PATTERN,
    "manifest",
    isRootLevelManifestPath,
  );

  rejectFailedScan(manifest.erroredPath);

  return manifest.elected;
}

/**
 * Collect the union of all `copyrights[].copyright` strings across every scanned file, sanitized
 * via the same control-char intake rule evidence text uses ({@link sanitizeEvidenceText},
 * merge.ts), deduped, {@link compareCodeUnits}-sorted, and capped at {@link
 * MAX_SCANCODE_COPYRIGHT_LINES}.
 */
export function electCopyrights(files: readonly ScancodeFile[]): string[] {
  const seen = new Set<string>();

  for (const text of files.flatMap((file) => file.copyrights ?? [])) {
    seen.add(sanitizeEvidenceText(text));
  }

  return [...seen].sort(compareCodeUnits).slice(0, MAX_SCANCODE_COPYRIGHT_LINES);
}
