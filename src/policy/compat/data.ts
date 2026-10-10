/**
 * Vendored license-compatibility data - the sole module that reads the committed snapshots.
 *
 * Three files sit beside this one: osadl-matrix.json (pairwise absorption verdicts between 119
 * SPDX-parseable license ids), osadl-copyleft.json (per-license copyleft class, the
 * proprietary-target axis), scancode-licensedb-index.json (per-license category, the breadth
 * fallback tier). Each is read once at module init via readFileSync + JSON.parse - never a static
 * `import` of the JSON - so a megabyte-scale literal never enters tsc's type inference, and the
 * narrow that follows the read is the only place that decides what shape is trustworthy. Provenance
 * (retrieval URL, timestamps, sha256, attribution) lives in PROVENANCE.md beside these files, never
 * in this module.
 *
 * Every narrow throws, naming the file and the offending key, rather than returning a partial map:
 * silently dropping a row or a class would hide upstream drift instead of surfacing it. The narrow
 * functions are exported separately from the module-init reads so both the test suite (malformed-
 * shape probes) and the refresh task (validate-before-write) exercise the exact same code path
 * - never a reimplementation that could drift from what the loader actually accepts.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** A cell in the OSADL matrix: the absorption verdict for a subordinate under a leading license. */
export type OsadlMatrixCell = "Same" | "Yes" | "No" | "Unknown" | "Check dependency";

const MATRIX_CELLS: ReadonlySet<string> = new Set<OsadlMatrixCell>([
  "Same",
  "Yes",
  "No",
  "Unknown",
  "Check dependency",
]);

/** A license's copyleft class in the OSADL table - the proprietary-target axis. */
export type OsadlCopyleftClass = "No" | "Yes" | "Yes (restricted)" | "Questionable";

const COPYLEFT_CLASSES: ReadonlySet<string> = new Set<OsadlCopyleftClass>([
  "No",
  "Yes",
  "Yes (restricted)",
  "Questionable",
]);

/** The two non-row keys matrix.json carries alongside its 119 license rows. */
const MATRIX_METADATA_KEYS: ReadonlySet<string> = new Set(["timestamp", "timeformat"]);

/**
 * The metadata keys copyleft.json carries alongside its per-license class map. The class data
 * itself lives one level down, under the "copyleft" key - not a sibling of these strings.
 */
const COPYLEFT_METADATA_KEYS: ReadonlySet<string> = new Set([
  "title",
  "license",
  "attribution",
  "copyright",
  "disclaimer",
  "timeformat",
  "timestamp",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Narrow a parsed matrix.json into leading→subordinate→cell maps, skipping only the two known
 * metadata keys. Every remaining top-level value must be a row object, and every cell in every row
 * must be one of the five OSADL verdicts - anything else throws, naming the row and column.
 */
export function narrowOsadlMatrix(
  raw: unknown,
  sourceName = "osadl-matrix.json",
): ReadonlyMap<string, ReadonlyMap<string, OsadlMatrixCell>> {
  if (!isPlainObject(raw)) {
    throw new Error(`${sourceName}: expected a JSON object at the document root`);
  }

  const matrix = new Map<string, ReadonlyMap<string, OsadlMatrixCell>>();

  for (const [leading, rawRow] of Object.entries(raw)) {
    if (MATRIX_METADATA_KEYS.has(leading)) {
      continue;
    }

    if (!isPlainObject(rawRow)) {
      throw new Error(`${sourceName}: row "${leading}" is not an object`);
    }

    const row = new Map<string, OsadlMatrixCell>();

    for (const [subordinate, cell] of Object.entries(rawRow)) {
      if (typeof cell !== "string" || !MATRIX_CELLS.has(cell)) {
        throw new Error(
          `${sourceName}: cell [${leading}][${subordinate}] is ${JSON.stringify(cell)}, ` +
            `not one of the five OSADL verdicts`,
        );
      }

      row.set(subordinate, cell as OsadlMatrixCell);
    }

    matrix.set(leading, row);
  }

  return matrix;
}

/**
 * Narrow a parsed copyleft.json into an id→class map. The top-level metadata keys (attribution,
 * disclaimer, the timestamp pair, ...) are skipped by their exact literal names; the one remaining
 * key must be "copyleft", holding the per-license class object - a renamed or restructured payload
 * throws instead of silently yielding an empty map.
 */
export function narrowOsadlCopyleftClass(
  raw: unknown,
  sourceName = "osadl-copyleft.json",
): ReadonlyMap<string, OsadlCopyleftClass> {
  if (!isPlainObject(raw)) {
    throw new Error(`${sourceName}: expected a JSON object at the document root`);
  }

  const payloadKeys = Object.keys(raw).filter((key) => !COPYLEFT_METADATA_KEYS.has(key));

  if (payloadKeys.length !== 1 || payloadKeys[0] !== "copyleft") {
    throw new Error(
      `${sourceName}: expected exactly one non-metadata top-level key "copyleft", found ` +
        `${JSON.stringify(payloadKeys)}`,
    );
  }

  const rawClasses = raw["copyleft"];

  if (!isPlainObject(rawClasses)) {
    throw new Error(`${sourceName}: "copyleft" is not an object`);
  }

  const classes = new Map<string, OsadlCopyleftClass>();

  for (const [id, value] of Object.entries(rawClasses)) {
    if (typeof value !== "string" || !COPYLEFT_CLASSES.has(value)) {
      throw new Error(
        `${sourceName}: class for "${id}" is ${JSON.stringify(value)}, not one of the four OSADL ` +
          `copyleft classes`,
      );
    }

    classes.set(id, value as OsadlCopyleftClass);
  }

  return classes;
}

/** One entry in scancode-licensedb-index.json - only the fields this module reads. */
interface RawScancodeEntry {
  category?: unknown;
  spdx_license_key?: unknown;
  other_spdx_license_keys?: unknown;
}

/**
 * Narrow a parsed scancode-licensedb-index.json into a spdx-id→category map. An entry with a null
 * `spdx_license_key` and no `other_spdx_license_keys` contributes nothing (ScanCode's own
 * unmapped-license marker); a duplicate SPDX key mapping to two DIFFERENT categories throws - the
 * index is not internally consistent and callers must not pick one arbitrarily.
 */
export function narrowScancodeCategory(
  raw: unknown,
  sourceName = "scancode-licensedb-index.json",
): ReadonlyMap<string, string> {
  if (!Array.isArray(raw)) {
    throw new Error(`${sourceName}: expected a JSON array at the document root`);
  }

  const categories = new Map<string, string>();

  raw.forEach((entry: unknown, index: number) => {
    if (!isPlainObject(entry)) {
      throw new Error(`${sourceName}: entry ${index} is not an object`);
    }

    const {
      category,
      spdx_license_key: spdxKey,
      other_spdx_license_keys: otherKeys,
    } = entry as RawScancodeEntry;

    if (typeof category !== "string" || category.trim() === "") {
      throw new Error(`${sourceName}: entry ${index} has a missing or empty "category"`);
    }

    const keys: string[] = [];

    if (typeof spdxKey === "string") {
      keys.push(spdxKey);
    } else if (spdxKey !== null && spdxKey !== undefined) {
      throw new Error(`${sourceName}: entry ${index} has a non-string "spdx_license_key"`);
    }

    if (Array.isArray(otherKeys)) {
      for (const key of otherKeys) {
        if (typeof key !== "string") {
          throw new Error(`${sourceName}: entry ${index} has a non-string other_spdx_license_key`);
        }

        keys.push(key);
      }
    } else if (otherKeys !== undefined) {
      throw new Error(`${sourceName}: entry ${index} has a non-array "other_spdx_license_keys"`);
    }

    for (const key of keys) {
      const existing = categories.get(key);

      if (existing !== undefined && existing !== category) {
        throw new Error(
          `${sourceName}: "${key}" maps to conflicting categories ${JSON.stringify(existing)} ` +
            `and ${JSON.stringify(category)}`,
        );
      }

      categories.set(key, category);
    }
  });

  return categories;
}

/**
 * The matrix's own embedded upstream data timestamp - required for the property/pinning tests and
 * for the refresh task's freshness diff.
 */
function readMatrixTimestamp(raw: unknown, sourceName: string): string {
  if (!isPlainObject(raw) || typeof raw["timestamp"] !== "string") {
    throw new Error(`${sourceName}: missing or non-string top-level "timestamp"`);
  }

  return raw["timestamp"];
}

const MATRIX_PATH = join(import.meta.dir, "osadl-matrix.json");
const COPYLEFT_PATH = join(import.meta.dir, "osadl-copyleft.json");
const SCANCODE_PATH = join(import.meta.dir, "scancode-licensedb-index.json");

const rawMatrix: unknown = JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
const rawCopyleft: unknown = JSON.parse(readFileSync(COPYLEFT_PATH, "utf8"));
const rawScancode: unknown = JSON.parse(readFileSync(SCANCODE_PATH, "utf8"));

/** Leading → subordinate → absorption verdict, validated against the five-value OSADL enum. */
export const OSADL_MATRIX: ReadonlyMap<
  string,
  ReadonlyMap<string, OsadlMatrixCell>
> = narrowOsadlMatrix(rawMatrix);

/** License id → OSADL copyleft class, validated against the four-value enum. */
export const OSADL_COPYLEFT_CLASS: ReadonlyMap<string, OsadlCopyleftClass> =
  narrowOsadlCopyleftClass(rawCopyleft);

/** SPDX license id → ScanCode LicenseDB category (the breadth fallback tier). */
export const SCANCODE_CATEGORY: ReadonlyMap<string, string> = narrowScancodeCategory(rawScancode);

/** The OSADL dataset's own embedded data timestamp (matrix.json's top-level "timestamp" field). */
export const OSADL_SNAPSHOT_TIMESTAMP: string = readMatrixTimestamp(rawMatrix, "osadl-matrix.json");

/**
 * ScanCode's LicenseDB index carries no embedded data timestamp of its own (unlike the OSADL
 * files); this is the HTTP `Last-Modified` value observed at vendor time, recorded here rather than
 * in a second sidecar file so the snapshot's single source of truth for "when" stays PROVENANCE.md
 * plus this one literal. The refresh task rewrites this line alongside the data file.
 */
export const SCANCODE_SNAPSHOT_TIMESTAMP = "2026-08-10T16:21:01Z";
