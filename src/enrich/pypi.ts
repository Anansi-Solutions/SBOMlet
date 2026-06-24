/**
 * PyPI 3-layer raw-license resolver.
 *
 * Turns a narrowed PyPI JSON response into a RAW license string plus a `via`
 * tag and a confidence. It resolves in the measured order:
 *
 *   1. `info.license_expression` (PEP 639, authoritative SPDX) — HIGH.
 *   2. `info.license` free-text field, GUARDED — HIGH. The guard mirrors
 *      normalize.ts's full-text trap exactly: a multi-line OR >=60-char value
 *      is full license TEXT (the `comm` package put the whole BSD-3 text here),
 *      never an id, so it is rejected and falls through to Layer 3.
 *   3. `info.classifiers` "License :: OSI Approved :: X" — a precise trove
 *      mapping is HIGH; an ambiguous classifier (BSD/Apache) yields the label
 *      text as raw, tagged LOW for optional `[[clarify]]` pinning (Pitfall 3).
 *
 * The resolver returns ONLY the raw string — it never calls parse/correct.
 * normalizeRaw downstream is the single SPDX resolution authority (locked
 * decision). Returns null when no layer yields a candidate.
 */
import { narrowPypiResponse } from "../validate/registry";
import { isAmbiguousTroveClassifier, troveToSpdx } from "./trove";

/** A resolved raw license: the string, which layer won, and a confidence. */
export interface PypiResolution {
  raw: string;
  via: "license-expression" | "license-field" | "classifier";
  confidence: "high" | "low";
}

/** The full-license-TEXT guard mirrored from normalize.ts: an id is short and single-line. */
function isLicenseId(value: string): boolean {
  return !value.includes("\n") && value.length < 60;
}

/** Layer 3: resolve from the first usable "License ::" trove classifier. */
function resolveFromClassifiers(
  classifiers: readonly string[],
): PypiResolution | null {
  for (const classifier of classifiers) {
    const spdx = troveToSpdx(classifier);
    if (spdx !== undefined) {
      return { raw: spdx, via: "classifier", confidence: "high" };
    }
    if (isAmbiguousTroveClassifier(classifier)) {
      // The label after "OSI Approved :: " is the raw correct() resolves
      // downstream ("BSD License" → BSD-2-Clause), flagged LOW because the
      // classifier alone cannot pin the precise variant.
      const label = classifier.split(" :: ").at(-1) ?? classifier;
      return { raw: label, via: "classifier", confidence: "low" };
    }
  }
  return null;
}

/**
 * Resolve a raw PyPI license. Narrows the untrusted response first (a malformed
 * shape yields null, never a throw), then walks the three layers in order.
 */
export function resolvePypiLicense(response: unknown): PypiResolution | null {
  const info = narrowPypiResponse(response);
  if (info === undefined) return null;

  const expression = info.licenseExpression?.trim();
  if (expression !== undefined && expression !== "") {
    return { raw: expression, via: "license-expression", confidence: "high" };
  }

  const field = info.license?.trim();
  if (field !== undefined && field !== "" && isLicenseId(field)) {
    return { raw: field, via: "license-field", confidence: "high" };
  }

  return resolveFromClassifiers(info.classifiers ?? []);
}
