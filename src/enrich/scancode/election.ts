import { basename } from "node:path";

import { sanitizeEvidenceText } from "../../merge/merge";
import { compareCodeUnits } from "../../model/dependencies";
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
 * True iff a scancode `files[].path` sits directly inside the scanned tree's own root - never a
 * nested/vendored/bundled subdirectory. ScanCode's `--json-pp` paths are forward-slash-separated
 * and always prefixed with the scanned directory's OWN basename (verified live: `ajv/LICENSE`,
 * `ajv/dist/ajv.bundle.js`), so a root-level file has EXACTLY two `/`-segments:
 * `<scanRootBasename>/<filename>`. Backslash-separated paths are defensively rejected too (scancode
 * never emits them; fail closed rather than trust an unexpected separator as root-level).
 *
 * A review found election previously matched on `basename(path)` alone with no depth check, so a
 * deeply-nested vendored/bundled dependency's LICENSE - carrying a DIFFERENT, potentially copyleft
 * license - could silently outrank the scanned package's own root license purely by `files[]` array
 * order (scancode's own walk order is not guaranteed root-first). This closes that gap.
 */
function isRootLevelPath(path: string): boolean {
  if (path.includes("\\")) {
    return false;
  }

  return path.split("/").length === 2;
}

/**
 * Elect the first ROOT-LEVEL file entry matching a basename pattern with a non-null, non-noise
 * expression.
 */
function electFromPattern(
  entries: RawScancodeFile[],
  pattern: RegExp,
  lane: string,
): { raw: string; via: string } | undefined {
  for (const entry of entries) {
    const path = entry.path;

    if (typeof path !== "string") {
      continue;
    }

    if (!isRootLevelPath(path)) {
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
      raw: expression,
      via: `${SCANCODE_TOOL.name}@${SCANCODE_TOOL.version}/${lane}`,
    };
  }

  return undefined;
}

/**
 * Elect ONE raw SPDX expression from the scanned files: a root-level legal file (basename matches
 * {@link LEGAL_FILE_PATTERN}) with a non-null, non-noise expression wins; else the first
 * package-manifest entry
 * ({@link MANIFEST_FILE_PATTERN}) with a non-null, non-noise expression;
 * else undefined (never an AND-combine across files). An
 * elected expression containing `LicenseRef-scancode-` is rejected within each lane (treated as no
 * answer there, ADR-0007) rather than accepted as noise - the caller falls through to the next
 * lane, or to a clean no-answer if both lanes reject.
 */
export function electExpression(files: unknown): { raw: string; via: string } | undefined {
  if (!Array.isArray(files)) {
    return undefined;
  }

  const entries = files.filter(isRawScancodeFile);

  const legal = electFromPattern(entries, LEGAL_FILE_PATTERN, "license-file");

  if (legal !== undefined) {
    return legal;
  }

  return electFromPattern(entries, MANIFEST_FILE_PATTERN, "manifest");
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
