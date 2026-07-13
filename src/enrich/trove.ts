/**
 * Vendored "License :: OSI Approved :: X" trove classifier → SPDX id map.
 *
 * The data is a literal, reviewable table — never fetched at runtime. The
 * `trove-classifiers` package is PyPI-only (404 on npm) and a runtime fetch
 * would be non-deterministic, so under the supply-chain gate this stays a small
 * vendored static map. It only covers the cases `spdx-correct` MISSES: the
 * "Python Software Foundation License" label, the "ISC License (ISCL)" label,
 * and the bare "ISC license"/"ISC License" label (correct() returns null for
 * all three; the last is the suffix false-negative that dropped pexpect
 * to unknown). A handful of precise classifiers (MIT/ISC/MPL) are included for
 * exact resolution where the `license` field is empty.
 *
 * This map is the PyPI resolver's Layer 3, consulted only after
 * `info.license_expression` and `info.license` fail. Resolvers return the RAW
 * SPDX string from this map; they never call parse/correct — normalizeRaw owns
 * resolution downstream (the single SPDX resolution path).
 *
 * AMBIGUITY: the broad "BSD License" / "Apache Software License" classifiers do
 * NOT carry a precise SPDX id ("BSD License" could be 2- or 3-Clause). They are
 * deliberately absent from the map and reported by {@link isAmbiguousTroveClassifier}
 * so a resolver tags them LOW confidence for optional `[[clarify]]` pinning,
 * never a silent HIGH verdict.
 *
 * Every SPDX value here is validated against spdx-license-ids in the tests, so a
 * typo cannot silently create a resolution gap (mirrors copyleft.ts's contract).
 */

/** Literal classifier → SPDX id pairs; the single reviewable source. */
export const TROVE_TO_SPDX: ReadonlyArray<
  readonly [classifier: string, spdx: string]
> = [
  // Gaps spdx-correct misses (correct() returns null for these labels):
  [
    "License :: OSI Approved :: Python Software Foundation License",
    "Python-2.0",
  ],
  ["License :: OSI Approved :: ISC License (ISCL)", "ISC"],
  // The bare "ISC license"/"ISC License" label: spdx-correct returns null for
  // it (the suffix false-negative that dropped pexpect to unknown),
  // while bare "ISC" parses. Carry both casings so a registry-supplied label
  // resolves to the precise ISC id.
  ["ISC license", "ISC"],
  ["ISC License", "ISC"],
  // Precise classifiers (used when the license field is empty):
  ["License :: OSI Approved :: MIT License", "MIT"],
  [
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    "MPL-2.0",
  ],
  [
    "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)",
    "MPL-1.1",
  ],
];

const TROVE_MAP: ReadonlyMap<string, string> = new Map(TROVE_TO_SPDX);

/**
 * Broad classifiers whose SPDX id is genuinely ambiguous — the SPDX id cannot
 * be determined from the classifier alone ("BSD License" is 2- or 3-Clause;
 * "Apache Software License" omits the version). A resolver that falls back to
 * one of these must tag the result LOW confidence.
 */
const AMBIGUOUS_TROVE = new Set<string>([
  "License :: OSI Approved :: BSD License",
  "License :: OSI Approved :: Apache Software License",
]);

/** SPDX id for a precise trove classifier, or undefined when unmapped. */
export function troveToSpdx(classifier: string): string | undefined {
  return TROVE_MAP.get(classifier);
}

/** True when the classifier maps to a genuinely ambiguous license (flag LOW). */
export function isAmbiguousTroveClassifier(classifier: string): boolean {
  return AMBIGUOUS_TROVE.has(classifier);
}
