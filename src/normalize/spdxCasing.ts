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

/**
 * The current spelling of a deprecated SPDX id: `<base>-only` or `<base>-or-later`, plus any
 * exception.
 */
export interface DeprecatedIdSuccessor {
  /** The GNU license version the id named; a `+` on the deprecated id selects `-or-later`. */
  base: string;
  /** The exception a deprecated `-with-…-exception` id folded into its name. */
  exception?: string;
}

/** Deprecated SPDX license ids, keyed by registered spelling, with their current spelling. */
export const DEPRECATED_ID_SUCCESSOR: ReadonlyMap<string, DeprecatedIdSuccessor> = new Map([
  ["AGPL-1.0", { base: "AGPL-1.0" }],
  ["AGPL-3.0", { base: "AGPL-3.0" }],
  ["GFDL-1.1", { base: "GFDL-1.1" }],
  ["GFDL-1.2", { base: "GFDL-1.2" }],
  ["GFDL-1.3", { base: "GFDL-1.3" }],
  ["GPL-1.0", { base: "GPL-1.0" }],
  ["GPL-2.0", { base: "GPL-2.0" }],
  ["GPL-3.0", { base: "GPL-3.0" }],
  ["LGPL-2.0", { base: "LGPL-2.0" }],
  ["LGPL-2.1", { base: "LGPL-2.1" }],
  ["LGPL-3.0", { base: "LGPL-3.0" }],
  ["GPL-2.0-with-GCC-exception", { base: "GPL-2.0", exception: "GCC-exception-2.0" }],
  ["GPL-2.0-with-autoconf-exception", { base: "GPL-2.0", exception: "Autoconf-exception-2.0" }],
  ["GPL-2.0-with-bison-exception", { base: "GPL-2.0", exception: "Bison-exception-2.2" }],
  ["GPL-2.0-with-classpath-exception", { base: "GPL-2.0", exception: "Classpath-exception-2.0" }],
  ["GPL-2.0-with-font-exception", { base: "GPL-2.0", exception: "Font-exception-2.0" }],
  ["GPL-3.0-with-GCC-exception", { base: "GPL-3.0", exception: "GCC-exception-3.1" }],
  ["GPL-3.0-with-autoconf-exception", { base: "GPL-3.0", exception: "Autoconf-exception-3.0" }],
]);

/** Deprecated SPDX license ids that SPDX itself replaced with one other id, keyed by spelling. */
export const DEPRECATED_ID_RENAME: ReadonlyMap<string, string> = new Map([
  ["BSD-2-Clause-FreeBSD", "BSD-2-Clause-Views"],
  ["BSD-2-Clause-NetBSD", "BSD-2-Clause"],
  ["Nunit", "zlib-acknowledgement"],
  ["StandardML-NJ", "SMLNJ"],
  ["bzip2-1.0.5", "bzip2-1.0.6"],
]);

/** Deprecated SPDX ids that stay as declared, each with why no single id can replace it. */
export const DEPRECATED_IDS_KEPT: ReadonlyMap<string, "compound" | "no-spdx-successor"> = new Map([
  ["Net-SNMP", "no-spdx-successor"],
  ["eCos-2.0", "compound"],
  ["wxWindows", "compound"],
]);
