import { describe, expect, test } from "bun:test";
import { type } from "arktype";

import { componentTreeOf, SbomDocument } from "./sbom";

describe("SbomDocument", () => {
  test("a non-array dependencies is absent and keeps the components", () => {
    for (const dependencies of [null, 5, "edges", { ref: "a" }]) {
      const doc = SbomDocument({ components: [{ name: "a" }], dependencies });

      if (doc instanceof type.errors) {
        throw new Error(doc.summary);
      }

      expect(doc.components).toEqual([{ name: "a" }]);
      expect(doc.dependencies).toBeUndefined();
    }
  });
});

describe("componentTreeOf", () => {
  test("walks nested components in document pre-order", () => {
    const a1 = { name: "a1" };
    const a2 = { name: "a2" };
    const a = { name: "a", components: [a1, a2] };
    const b = { name: "b" };

    expect(componentTreeOf([a, b])).toEqual([a, a1, a2, b]);
  });

  test("walks a very wide components array without overflowing the stack", () => {
    const children = Array.from({ length: 2_000_000 }, () => ({}));

    expect(componentTreeOf([{ components: children }])).toHaveLength(2_000_001);
  });
});
