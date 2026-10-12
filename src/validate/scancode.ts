/**
 * arktype boundary for the `files[]` entries of ScanCode's `--json-pp` output (tolerant posture).
 * Only a non-object entry fails the narrow, and {@link scancodeFilesOf} skips it; a missing or
 * mistyped field is simply absent.
 */
import { type } from "arktype";

import { ArrayOrAbsent } from "./record";

/** A string field where a non-string or empty value is absent. */
const NonEmptyStringOrAbsent = type("unknown").pipe((value) =>
  typeof value === "string" && value.length > 0 ? value : undefined,
);

const ScancodeCopyright = type({ copyright: "string > 0" });

/** The `copyrights[].copyright` strings in order; an entry without a usable string is skipped. */
const CopyrightsOrAbsent = type("unknown").pipe((value) => {
  if (!Array.isArray(value)) {
    return undefined;
  }

  return value.flatMap((raw: unknown) => {
    const entry = ScancodeCopyright(raw);

    return entry instanceof type.errors ? [] : [entry.copyright];
  });
});

/** One scanned file, narrowed to the fields license and copyright election read. */
export const ScancodeFileEntry = type({
  "path?": NonEmptyStringOrAbsent,
  "detected_license_expression_spdx?": NonEmptyStringOrAbsent,
  /** The errors ScanCode hit on this file; present and non-empty means the scan errored. */
  "scan_errors?": ArrayOrAbsent,
  "copyrights?": CopyrightsOrAbsent,
});

export type ScancodeFile = typeof ScancodeFileEntry.infer;

/** The narrowed entries of a `files` value; a non-array is no entries. */
export function scancodeFilesOf(files: unknown): ScancodeFile[] {
  if (!Array.isArray(files)) {
    return [];
  }

  return files.flatMap((raw: unknown) => {
    const entry = ScancodeFileEntry(raw);

    return entry instanceof type.errors ? [] : [entry];
  });
}
