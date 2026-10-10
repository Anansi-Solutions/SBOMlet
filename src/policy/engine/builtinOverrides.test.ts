import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import parseSpdxId from "spdx-expression-parse";
import { asRawLicense, widen } from "../../../test/brandTestSupport";
import { BUILTIN_OVERRIDES } from "./builtinOverrides";

describe("BUILTIN_OVERRIDES — the shipped tool-level set", () => {
  test("is a non-empty literal array; every entry has name, detected, expression, reason", () => {
    expect(BUILTIN_OVERRIDES.length).toBeGreaterThan(0);
    for (const o of BUILTIN_OVERRIDES) {
      expect(typeof o.name).toBe("string");
      expect(o.name.trim().length).toBeGreaterThan(0);
      expect(Object.keys(o.detected).length).toBeGreaterThan(0);
      expect(typeof o.expression).toBe("string");
      expect(typeof o.reason).toBe("string");
      expect(o.reason.trim().length).toBeGreaterThan(0);
    }
  });

  test("every expression is a valid SPDX expression (typo-proof)", () => {
    for (const o of BUILTIN_OVERRIDES) {
      expect(() => parseSpdxId(o.expression)).not.toThrow();
    }
  });

  test("every expression's leaf ids are real SPDX ids", () => {
    const dataDir = join(import.meta.dir, "..", "..", "..", "node_modules", "spdx-license-ids");
    const current = JSON.parse(readFileSync(join(dataDir, "index.json"), "utf8")) as string[];
    const deprecated = JSON.parse(
      readFileSync(join(dataDir, "deprecated.json"), "utf8"),
    ) as string[];
    const known = new Set([...current, ...deprecated]);
    const leafIds: string[] = [];
    const walk = (node: unknown): void => {
      if (typeof node !== "object" || node === null) {
        return;
      }

      const n = node as Record<string, unknown>;

      if (typeof n.license === "string") {
        leafIds.push(n.license);
      }

      walk(n.left);
      walk(n.right);
    };

    for (const o of BUILTIN_OVERRIDES) {
      walk(parseSpdxId(o.expression));
    }

    expect(leafIds.filter((id) => !known.has(id))).toEqual([]);
  });

  test("ships python-dateutil's dual license as a REAL default (BLOCKER-1)", () => {
    const entry = BUILTIN_OVERRIDES.find((o) => o.name === "python-dateutil");

    expect(entry).toBeDefined();
    expect(entry?.detected).toEqual({ registry: asRawLicense("Dual License") });
    expect(widen(entry?.expression)).toBe("Apache-2.0 OR BSD-3-Clause");
    // The exact value from CONTEXT.md parses as a valid OR expression.
    const node = parseSpdxId(entry?.expression ?? "") as {
      conjunction?: string;
    };

    expect(node.conjunction).toBe("or");
  });

  test("ships the Jupyter/IPython BSD stack disambiguating the imprecise BSD value (BLOCKER-1)", () => {
    const canonical = [
      "ipython",
      "ipykernel",
      "jupyter-core",
      "jupyter-client",
      "nbformat",
      "traitlets",
    ];

    for (const name of canonical) {
      const entry = BUILTIN_OVERRIDES.find((o) => o.name === name);

      expect(entry).toBeDefined();
      // Records the imprecise BSD value the registry lane produces.
      expect(entry?.detected).toEqual({ registry: asRawLicense("BSD") });
      expect(widen(entry?.expression)).toBe("BSD-3-Clause");
    }
  });

  test("does NOT ship copier or jinja2-ansible-filters (Phase-6 project judgment)", () => {
    expect(BUILTIN_OVERRIDES.some((o) => o.name === "copier")).toBe(false);
    expect(BUILTIN_OVERRIDES.some((o) => o.name === "jinja2-ansible-filters")).toBe(false);
  });

  test("keys by package NAME (version optional) so an override survives version bumps", () => {
    // No entry pins a version: a name-only override matches every version of
    // the package as long as upstream keeps reporting the ambiguous value.
    for (const o of BUILTIN_OVERRIDES) {
      expect(o.version).toBeUndefined();
    }
  });
});
