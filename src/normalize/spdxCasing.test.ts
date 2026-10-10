import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { DEPRECATED_ID_SUCCESSOR, DEPRECATED_IDS_KEPT } from "./spdxCasing";

const MODULES = join(import.meta.dir, "..", "..", "node_modules");
const readIds = (...path: string[]): string[] =>
  JSON.parse(readFileSync(join(MODULES, ...path), "utf8")) as string[];

describe("deprecated SPDX ids", () => {
  const deprecated = readIds("spdx-license-ids", "deprecated.json");
  const current = new Set(readIds("spdx-license-ids", "index.json"));
  const exceptions = new Set(readIds("spdx-exceptions", "index.json"));

  test("every installed deprecated id is either respelled or explicitly kept", () => {
    const unaccounted = deprecated.filter(
      (id) => !DEPRECATED_ID_SUCCESSOR.has(id) && !DEPRECATED_IDS_KEPT.has(id),
    );

    expect(unaccounted).toEqual([]);
  });

  test("no id is both respelled and kept, and every listed id is still deprecated", () => {
    const listed = [...DEPRECATED_ID_SUCCESSOR.keys(), ...DEPRECATED_IDS_KEPT];

    expect(listed.filter((id) => !deprecated.includes(id))).toEqual([]);
    expect([...DEPRECATED_IDS_KEPT].filter((id) => DEPRECATED_ID_SUCCESSOR.has(id))).toEqual([]);
  });

  test("every successor names current license and exception ids", () => {
    for (const { base, exception } of DEPRECATED_ID_SUCCESSOR.values()) {
      expect(current.has(`${base}-only`)).toBe(true);
      expect(current.has(`${base}-or-later`)).toBe(true);

      if (exception !== undefined) {
        expect(exceptions.has(exception)).toBe(true);
      }
    }
  });
});

/** The scancode-licensedb-index.json fields that map an older SPDX id to its current one. */
interface LicenseDbEntry {
  spdx_license_key: string | null;
  other_spdx_license_keys: readonly string[];
}

describe("deprecated SPDX ids against the vendored LicenseDB index", () => {
  const index = JSON.parse(
    readFileSync(
      join(import.meta.dir, "..", "policy", "compat", "scancode-licensedb-index.json"),
      "utf8",
    ),
  ) as LicenseDbEntry[];
  const currentIdOf = new Map(
    index.flatMap(({ spdx_license_key: current, other_spdx_license_keys: older }) =>
      current === null ? [] : older.map((id) => [id, current] as const),
    ),
  );
  const deprecated = readIds("spdx-license-ids", "deprecated.json");

  /** Deprecated ids the index lists under their own name only, so it names no current id. */
  const INDEX_UNMAPPED = [
    "GPL-2.0-with-GCC-exception",
    "GPL-2.0-with-autoconf-exception",
    "GPL-2.0-with-bison-exception",
    "GPL-2.0-with-classpath-exception",
    "GPL-2.0-with-font-exception",
    "GPL-3.0-with-GCC-exception",
    "GPL-3.0-with-autoconf-exception",
    "eCos-2.0",
    "wxWindows",
  ];

  test("the deprecated ids the index does not map are exactly the listed ones", () => {
    expect(deprecated.filter((id) => !currentIdOf.has(id)).sort()).toEqual(
      [...INDEX_UNMAPPED].sort(),
    );
  });

  test("a successor of an id the index maps renders the index's current id", () => {
    const drifted = [...DEPRECATED_ID_SUCCESSOR]
      .filter(([id]) => currentIdOf.has(id))
      .filter(([id, { base }]) => currentIdOf.get(id) !== `${base}-only`);

    expect(drifted).toEqual([]);
  });

  test("an exception successor keeps the base its id names, rendered as the index maps it", () => {
    const drifted = [...DEPRECATED_ID_SUCCESSOR]
      .filter(([, { exception }]) => exception !== undefined)
      .filter(
        ([id, { base }]) =>
          !id.startsWith(`${base}-with-`) || currentIdOf.get(base) !== `${base}-only`,
      );

    expect(drifted).toEqual([]);
  });
});
