import { describe, expect, test } from "bun:test";

import { componentTreeOf } from "./sbom";

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
