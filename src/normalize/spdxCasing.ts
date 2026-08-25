/**
 * Canonical SPDX id/exception casing, loaded once at module init.
 *
 * Every valid SPDX license id and exception has one registered spelling (`mit` -> `MIT`,
 * `apache-2.0` -> `Apache-2.0`). The lists come from spdx-license-ids and spdx-exceptions, which
 * ship as a bare `index.json` with no declarations AND are dual-consumed (spdx-correct requires
 * them as CJS); a static ESM import would flip their module interpretation and break that require,
 * so they are read here with readFileSync + JSON.parse - the same posture policy/compat/data.ts
 * holds over its vendored data, which never touches the module graph.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SPDX_IDS_DIR = join(import.meta.dir, "..", "..", "node_modules", "spdx-license-ids");
const SPDX_EXCEPTIONS_FILE = join(
  import.meta.dir,
  "..",
  "..",
  "node_modules",
  "spdx-exceptions",
  "index.json",
);

function readIds(path: string): readonly string[] {
  return JSON.parse(readFileSync(path, "utf8")) as string[];
}

function lowercaseIndex(ids: readonly string[]): ReadonlyMap<string, string> {
  return new Map(ids.map((id) => [id.toLowerCase(), id]));
}

/** Lowercased license id -> its one registered SPDX spelling (current and deprecated ids). */
export const CANONICAL_LICENSE_ID = lowercaseIndex([
  ...readIds(join(SPDX_IDS_DIR, "index.json")),
  ...readIds(join(SPDX_IDS_DIR, "deprecated.json")),
]);

/** Lowercased exception id -> its one registered SPDX spelling. */
export const CANONICAL_EXCEPTION_ID = lowercaseIndex(readIds(SPDX_EXCEPTIONS_FILE));
