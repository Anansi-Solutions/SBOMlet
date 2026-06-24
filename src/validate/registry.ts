/**
 * arktype boundary for the two NEW untrusted registry JSON shapes: the PyPI
 * `info` block and the npm packument. Registry responses are third-party,
 * volatile, and may be malformed or oversized — this is the ASVS V5 input-
 * validation control for a brand-new network surface.
 *
 * Posture mirrors validate/sbom.ts exactly: undeclared keys are ignored
 * (arktype default), and any present-but-wrong-typed field coerces to undefined
 * (skip-don't-throw). A malformed response NEVER throws and NEVER feeds a bad
 * shape to a resolver — the resolver simply sees absent fields and falls
 * through. The narrows do NOT resolve licenses; resolvers return raw strings
 * and normalizeRaw owns SPDX resolution downstream.
 */
import { type } from "arktype";

import { recordOf, stringOf } from "./record";

/** Tolerant PyPI `info` projection: the only fields enrichment consumes. */
export interface PypiInfo {
  /** info.license_expression (PEP 639, authoritative SPDX) — string or absent. */
  licenseExpression?: string;
  /** info.license (free-text field) — string or absent. */
  license?: string;
  /** info.classifiers, "License :: ..." trove labels — string entries only. */
  classifiers?: string[];
}

/** Arktype shape just for the response envelope: `info` may be any value. */
const PypiResponse = type({ "info?": "unknown" });
export type PypiResponseShape = typeof PypiResponse.infer;

/**
 * Narrow a raw PyPI JSON response to {@link PypiInfo}. A non-object top-level
 * value (null/number/string) yields undefined; an `info` that is absent or
 * non-object yields a PypiInfo with every field absent. Every leaf field is
 * walked tolerantly: wrong-typed values coerce to undefined.
 */
export function narrowPypiResponse(value: unknown): PypiInfo | undefined {
  if (recordOf(value) === undefined) return undefined;
  const parsed = PypiResponse(value);
  if (parsed instanceof type.errors) return undefined;
  const info = recordOf(parsed.info);
  if (info === undefined) return {};
  return {
    licenseExpression: stringOf(info["license_expression"]),
    license: stringOf(info["license"]),
    classifiers: stringArrayOf(info["classifiers"]),
  };
}

/** Tolerant npm packument projection. */
export interface NpmVersion {
  /** versions[v].license, when string-typed. */
  license?: string;
  /** Legacy versions[v].license object `{ type }`. */
  licenseObject?: { type?: string };
  /** Legacy versions[v].licenses array `[{ type }]` (OR-combined by callers). */
  licensesArray?: Array<{ type?: string }>;
}

export interface NpmPackument {
  /** Top-level string license. */
  license?: string;
  /** Legacy top-level license object `{ type }`. */
  licenseObject?: { type?: string };
  /** Legacy top-level licenses array `[{ type }]` (OR-combined by callers). */
  licensesArray?: Array<{ type?: string }>;
  /** versions map: exactVersion → { license }. */
  versions?: Record<string, NpmVersion>;
}

const NpmDocument = type({
  "license?": "unknown",
  "licenses?": "unknown",
  "versions?": "unknown",
});

/**
 * Narrow a raw npm packument to {@link NpmPackument}. Tolerates: a top-level
 * `license` string, a legacy `{ type }` object, a `licenses: [{ type }]` array,
 * and a `versions` map of `{ license }`. A non-object top-level value or
 * `versions: null` yields the field absent — never a throw.
 */
export function narrowNpmPackument(value: unknown): NpmPackument | undefined {
  if (recordOf(value) === undefined) return undefined;
  const parsed = NpmDocument(value);
  if (parsed instanceof type.errors) return undefined;
  return {
    license: stringOf(parsed.license),
    licenseObject: licenseTypeOf(parsed.license),
    licensesArray: licensesArrayOf(parsed.licenses),
    versions: versionsOf(parsed.versions),
  };
}

/** Tolerant GitHub License API projection: the only fields enrichment consumes. */
export interface GithubLicense {
  /** license.spdx_id — the SPDX id (or "NOASSERTION"/absent for no-license). */
  spdxId?: string;
  /** download_url — raw LICENSE text URL (reused for OUT-02 verbatim bundling). */
  downloadUrl?: string;
}

const GithubLicenseDocument = type({
  "license?": "unknown",
  "download_url?": "unknown",
});

/**
 * Narrow a raw GitHub License API response to {@link GithubLicense}. A non-object
 * top-level value yields undefined; an absent/non-object `license` yields a
 * GithubLicense with `spdxId` absent. Every leaf is walked tolerantly:
 * wrong-typed values coerce to undefined (skip-don't-throw, ASVS V5).
 */
export function narrowGithubLicense(value: unknown): GithubLicense | undefined {
  if (recordOf(value) === undefined) return undefined;
  const parsed = GithubLicenseDocument(value);
  if (parsed instanceof type.errors) return undefined;
  const license = recordOf(parsed.license);
  return {
    spdxId: stringOf(license?.["spdx_id"]),
    downloadUrl: stringOf(parsed.download_url),
  };
}

/** A string[] field: non-array → undefined, non-string entries dropped. */
function stringArrayOf(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((entry): entry is string => typeof entry === "string");
}

/** A legacy `{ type }` license object, or undefined for any other shape. */
function licenseTypeOf(value: unknown): { type?: string } | undefined {
  const record = recordOf(value);
  if (record === undefined) return undefined;
  return { type: stringOf(record["type"]) };
}

/** A legacy `licenses: [{ type }]` array, or undefined for any other shape. */
function licensesArrayOf(value: unknown): Array<{ type?: string }> | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.map((entry) => ({ type: stringOf(recordOf(entry)?.["type"]) }));
}

/**
 * A `versions` map: each entry tolerated to the same license trio as the
 * top-level packument — a `license` string, a legacy `license: { type }`
 * object, and a legacy `licenses: [{ type }]` array. Older packages publish
 * their license ONLY in the version-level legacy array (e.g. compute-gcd,
 * memorystream, svg-tags, the validate.io-* family all carry MIT there with no
 * top-level field), so dropping it produced false negatives. A non-object
 * top-level value → undefined.
 */
function versionsOf(value: unknown): Record<string, NpmVersion> | undefined {
  const record = recordOf(value);
  if (record === undefined) return undefined;
  const out: Record<string, NpmVersion> = {};
  for (const [version, entry] of Object.entries(record)) {
    const versionRecord = recordOf(entry);
    out[version] = {
      license: stringOf(versionRecord?.["license"]),
      licenseObject: licenseTypeOf(versionRecord?.["license"]),
      licensesArray: licensesArrayOf(versionRecord?.["licenses"]),
    };
  }
  return out;
}
