/**
 * npm packument raw-license resolver.
 *
 * Consumes the full packument (`https://registry.npmjs.org/<name>`, fetched
 * once per name by the orchestrator) — NOT the per-version endpoint, which
 * returned false nulls and 404s on `*-cjs` alias purls in the measured run.
 * Resolution order — the version-level block is tried in full BEFORE the
 * top-level block, and within each block: string → legacy `{ type }` object →
 * legacy `licenses: [{ type }]` array (OR-joined):
 *
 *   1. `versions[version].license` (string)
 *   2. `versions[version].license` legacy `{ type }` object → its `type`
 *   3. `versions[version].licenses` legacy array → OR-joined expression
 *   4. top-level `license` (string)
 *   5. top-level legacy `{ type }` object
 *   6. top-level legacy `licenses` array → OR-joined expression
 *
 * Many older packages publish their license ONLY in the version-level legacy
 * `licenses` array (compute-gcd, memorystream, svg-tags, the validate.io-*
 * family — all MIT there, nothing at the top level), so the version block must
 * cover the legacy shapes too or they become false negatives.
 *
 * Returns ONLY the RAW string + a `via` tag — never parse/correct (normalizeRaw
 * is the single SPDX resolution authority downstream). Returns null when no
 * license is found anywhere. A malformed packument narrows to null, never a
 * throw (ASVS V5 boundary).
 */
import { narrowNpmPackument } from "../validate/registry";

/** A resolved raw license: the string and which packument field won. */
export interface NpmResolution {
  raw: string;
  via:
    | "version-license"
    | "version-license-object"
    | "version-licenses-array"
    | "top-license"
    | "top-license-object"
    | "top-licenses-array";
}

/** A trimmed non-empty string, or undefined for absent/blank values. */
function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed !== undefined && trimmed !== "" ? trimmed : undefined;
}

/** The same license-field trio at either the version or top level. */
interface LicenseFields {
  license?: string;
  licenseObject?: { type?: string };
  licensesArray?: Array<{ type?: string }>;
}

/** OR-join a legacy `licenses` array: single element unparenthesized, else `(A OR B)`. */
function joinLicensesArray(
  array: Array<{ type?: string }> | undefined,
): string | undefined {
  const types = (array ?? [])
    .map((entry) => nonEmpty(entry.type))
    .filter((type): type is string => type !== undefined);
  if (types.length === 0) return undefined;
  return types.length === 1 ? (types[0] as string) : `(${types.join(" OR ")})`;
}

/**
 * Resolve one license block (version or top level) in this fixed order:
 * string → legacy `{ type }` object → legacy `licenses` array. `vias` carries
 * the level-specific `via` tags so the audit trail names where the value won.
 */
function resolveFields(
  fields: LicenseFields,
  vias: {
    string: NpmResolution["via"];
    object: NpmResolution["via"];
    array: NpmResolution["via"];
  },
): NpmResolution | null {
  const license = nonEmpty(fields.license);
  if (license !== undefined) return { raw: license, via: vias.string };

  const objectType = nonEmpty(fields.licenseObject?.type);
  if (objectType !== undefined) return { raw: objectType, via: vias.object };

  const arrayJoined = joinLicensesArray(fields.licensesArray);
  if (arrayJoined !== undefined) return { raw: arrayJoined, via: vias.array };

  return null;
}

/** Resolve a raw npm license for an exact version from a packument. */
export function resolveNpmLicense(
  packument: unknown,
  version: string,
): NpmResolution | null {
  const doc = narrowNpmPackument(packument);
  if (doc === undefined) return null;

  const versionEntry = doc.versions?.[version];
  if (versionEntry !== undefined) {
    const fromVersion = resolveFields(versionEntry, {
      string: "version-license",
      object: "version-license-object",
      array: "version-licenses-array",
    });
    if (fromVersion !== null) return fromVersion;
  }

  return resolveFields(doc, {
    string: "top-license",
    object: "top-license-object",
    array: "top-licenses-array",
  });
}
