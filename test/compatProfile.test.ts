import { describe, expect, test } from "bun:test";

import {
  applyUsageProfile,
  type ModulatedClass,
  type TargetProfile,
} from "../src/policy/compat/profile";
import type { AxisClass, AxisResult, ObligationClass } from "../src/policy/compat/classify";

const AXIS_CLASSES: readonly AxisClass[] = [
  "compatible",
  "incompatible",
  "boundary",
  "residual",
  "unassessed-ref",
];
const OBLIGATIONS: readonly ObligationClass[] = ["none", "copyleft", "agpl", "unknown"];
const NETWORK_VALUES: readonly boolean[] = [false, true];
const DISTRIBUTIONS: readonly TargetProfile["distribution"][] = ["external", "internal"];

const profile = (network: boolean, distribution: TargetProfile["distribution"]): TargetProfile => ({
  license: { kind: "oss", id: "MIT" },
  network,
  distribution,
});

const axis = (cls: AxisClass, obligation: ObligationClass): AxisResult => ({
  class: cls,
  source: `pinned source for ${cls}/${obligation}`,
  obligation,
});

/**
 * The scope-gating contract, transcribed directly from the plan's acceptance criteria (not the
 * implementation): compatible and external distribution are unconditional identity; internal
 * distribution holds a negative, non-ref axis outcome only when its obligation is positively out of
 * scope (copyleft always; agpl only when network=false); the floor (none/unknown obligations, and
 * the unassessed-ref class) is never held.
 */
function expectedClass(
  cls: AxisClass,
  obligation: ObligationClass,
  network: boolean,
  distribution: TargetProfile["distribution"],
): ModulatedClass {
  if (cls === "compatible" || distribution === "external" || cls === "unassessed-ref") {
    return cls;
  }

  const outOfScope = obligation === "copyleft" || (obligation === "agpl" && !network);

  return outOfScope ? "held-internal" : cls;
}

/** Every (class, obligation, network, distribution) combination - the full 80-cell space. */
const ALL_CELLS: ReadonlyArray<{
  cls: AxisClass;
  obligation: ObligationClass;
  network: boolean;
  distribution: TargetProfile["distribution"];
}> = AXIS_CLASSES.flatMap((cls) =>
  OBLIGATIONS.flatMap((obligation) =>
    NETWORK_VALUES.flatMap((network) =>
      DISTRIBUTIONS.map((distribution) => ({ cls, obligation, network, distribution })),
    ),
  ),
);

describe("applyUsageProfile - exhaustive 80-cell scope-gating table", () => {
  test(`every one of the ${ALL_CELLS.length} cells matches the scope-gating contract`, () => {
    expect(ALL_CELLS.length).toBe(80);

    for (const { cls, obligation, network, distribution } of ALL_CELLS) {
      const result = applyUsageProfile(axis(cls, obligation), profile(network, distribution));

      expect(result.class).toBe(expectedClass(cls, obligation, network, distribution));
    }
  });
});

describe("applyUsageProfile - named cells (the principle's own worked examples)", () => {
  test("compatible is unchanged in every cell of the space (flags never break absorption)", () => {
    for (const network of NETWORK_VALUES) {
      for (const distribution of DISTRIBUTIONS) {
        const result = applyUsageProfile(
          axis("compatible", "agpl"),
          profile(network, distribution),
        );

        expect(result.class).toBe("compatible");
      }
    }
  });

  test("an AGPL-compatible target's AGPL leaf stays compatible under network=true (the case the principle protects)", () => {
    const result = applyUsageProfile(axis("compatible", "agpl"), profile(true, "internal"));

    expect(result.class).toBe("compatible");
  });

  test("distribution=external is identity for every axis result and both network values", () => {
    for (const cls of AXIS_CLASSES) {
      for (const obligation of OBLIGATIONS) {
        for (const network of NETWORK_VALUES) {
          const result = applyUsageProfile(axis(cls, obligation), profile(network, "external"));

          expect(result.class).toBe(cls);
        }
      }
    }
  });

  test("distribution=internal holds a copyleft obligation regardless of network", () => {
    expect(
      applyUsageProfile(axis("incompatible", "copyleft"), profile(false, "internal")).class,
    ).toBe("held-internal");
    expect(applyUsageProfile(axis("boundary", "copyleft"), profile(true, "internal")).class).toBe(
      "held-internal",
    );
  });

  test("distribution=internal holds an agpl obligation only when network=false", () => {
    expect(applyUsageProfile(axis("incompatible", "agpl"), profile(false, "internal")).class).toBe(
      "held-internal",
    );
    expect(applyUsageProfile(axis("incompatible", "agpl"), profile(true, "internal")).class).toBe(
      "incompatible",
    );
  });

  test("the floor: obligation none is never held - the Apache-under-GPL-2.0-only conflict stays incompatible", () => {
    expect(applyUsageProfile(axis("incompatible", "none"), profile(false, "internal")).class).toBe(
      "incompatible",
    );
  });

  test("the floor: obligation unknown is never held", () => {
    expect(applyUsageProfile(axis("residual", "unknown"), profile(false, "internal")).class).toBe(
      "residual",
    );
  });

  test("the floor: unassessed-ref is never held", () => {
    expect(
      applyUsageProfile(axis("unassessed-ref", "unknown"), profile(true, "internal")).class,
    ).toBe("unassessed-ref");
  });

  test("network=false + distribution=external x AGPL incompatible stays incompatible (folding AGPL into ordinary copyleft never rescues an in-scope failure)", () => {
    const result = applyUsageProfile(axis("incompatible", "agpl"), profile(false, "external"));

    expect(result.class).toBe("incompatible");
  });

  test("a held verdict preserves the axis source and appends the hold basis", () => {
    const result = applyUsageProfile(
      { class: "incompatible", source: "OSADL: No", obligation: "copyleft" },
      profile(false, "internal"),
    );

    expect(result.class).toBe("held-internal");
    expect(result.source).toContain("OSADL: No");
    expect(result.source).not.toBe("OSADL: No");
  });

  test("purity: identical inputs produce an identical result across repeated calls", () => {
    const first = applyUsageProfile(axis("boundary", "copyleft"), profile(false, "internal"));
    const second = applyUsageProfile(axis("boundary", "copyleft"), profile(false, "internal"));

    expect(first).toEqual(second);
  });
});
