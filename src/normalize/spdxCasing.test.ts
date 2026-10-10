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
