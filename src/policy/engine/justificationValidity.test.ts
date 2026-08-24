import { describe, expect, test } from "bun:test";

import { justificationValidity, type JustificationValidity } from "./justificationValidity";
import type { ObservedSignal } from "../../normalize/normalize";

// Per-value predicates over a partitioned signal. A stale entry - one whose
// recorded detection its lane no longer reports - is a different lane's
// business and is never built here: every case below keeps the recorded
// detection satisfied and asks only whether the stated justification holds.

const signal = (registry: readonly string[], intensive: readonly string[]): ObservedSignal => ({
  registry,
  intensive,
  union: [...new Set([...registry, ...intensive])],
});

const NO_SIGNAL = signal([], []);

describe("justificationValidity — dual-license-choice", () => {
  const dual = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "dual-license-choice", expression }, s);

  test("the recorded choice matches the leaves the scan joined", () => {
    expect(dual("MIT OR CC0-1.0", signal(["(MIT OR CC0-1.0)"], ["CC0-1.0 AND MIT"]))).toEqual({
      outcome: "ok",
    });
  });

  test("recording the branch taken, rather than the choice offered, is disproved", () => {
    const result = dual("MIT", signal(["(MIT OR CC0-1.0)"], ["CC0-1.0 AND MIT"]));

    expect(result.outcome).toBe("invalid");
  });

  test("nothing was AND-joined: the scan's leaves are not the recorded choice", () => {
    const result = dual("MIT OR Apache-2.0", signal(["(MIT OR Apache-2.0)"], ["MIT"]));

    expect(result.outcome).toBe("invalid");
    expect(result.outcome === "invalid" && result.reason).toContain("MIT");
  });

  test("the declared claim no longer offers any recorded leaf", () => {
    const result = dual("MIT OR CC0-1.0", signal(["Apache-2.0"], ["CC0-1.0 AND MIT"]));

    expect(result.outcome).toBe("invalid");
    expect(result.outcome === "invalid" && result.reason).toContain("Apache-2.0");
  });

  test("an expression that is not a choice at all cannot record one", () => {
    expect(dual("MIT AND CC0-1.0", signal(["MIT AND CC0-1.0"], ["CC0-1.0 AND MIT"])).outcome).toBe(
      "invalid",
    );
  });

  test("neither lane reads a licence: nothing here disproves the choice", () => {
    expect(dual("MIT OR CC0-1.0", NO_SIGNAL)).toEqual({ outcome: "ok" });
  });
});

describe("justificationValidity — scan-overdetection", () => {
  const overdetected = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "scan-overdetection", expression }, s);

  test("the scan still reports a leaf the expression drops", () => {
    expect(overdetected("MIT", signal(["MIT"], ["MIT AND CC-BY-3.0"]))).toEqual({ outcome: "ok" });
  });

  test("nothing left to correct: the entry has become unnecessary", () => {
    const result = overdetected("MIT", signal(["MIT"], ["MIT"]));

    expect(result.outcome).toBe("unnecessary");
    expect(result.outcome === "unnecessary" && result.reason).toContain("scan");
  });

  test("a scan that reads nothing is the stale lane's business, not this one's", () => {
    expect(overdetected("MIT", signal(["MIT"], []))).toEqual({ outcome: "ok" });
  });
});

describe("justificationValidity — scan-found-additional-content", () => {
  const additional = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "scan-found-additional-content", expression }, s);

  test("the expression accounts for everything the scan reads", () => {
    expect(additional("MIT AND WTFPL", signal(["MIT"], ["WTFPL"]))).toEqual({ outcome: "ok" });
  });

  test("the scan reads content the adopted expression does not cover", () => {
    const result = additional("MIT", signal(["MIT"], ["GPL-3.0-only"]));

    expect(result.outcome).toBe("invalid");
    expect(result.outcome === "invalid" && result.reason).toContain("GPL-3.0-only");
  });

  test("a scan that reads nothing leaves the adopted reading standing", () => {
    expect(additional("MIT AND WTFPL", signal(["MIT"], []))).toEqual({ outcome: "ok" });
  });
});

describe("justificationValidity — scan-more-precise", () => {
  const precise = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "scan-more-precise", expression }, s);

  test("the precise variant is still what the scan reads", () => {
    expect(precise("BSD-2-Clause-Views", signal(["BSD-2-Clause"], ["BSD-2-Clause-Views"]))).toEqual(
      { outcome: "ok" },
    );
  });

  test("the scan has moved to a licence the recorded variant does not cover", () => {
    expect(precise("BSD-2-Clause-Views", signal(["BSD-2-Clause"], ["ISC"])).outcome).toBe(
      "invalid",
    );
  });
});

describe("justificationValidity — declared-more-complete", () => {
  const declared = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "declared-more-complete", expression }, s);

  test("the declared claim still names everything the entry adopted", () => {
    expect(declared("MIT AND CC-BY-3.0", signal(["(MIT AND CC-BY-3.0)"], ["MIT"]))).toEqual({
      outcome: "ok",
    });
  });

  test("the declared claim has dropped part of the adopted expression", () => {
    const result = declared("MIT AND CC-BY-3.0", signal(["MIT"], ["MIT"]));

    expect(result.outcome).toBe("invalid");
    expect(result.outcome === "invalid" && result.reason).toContain("CC-BY-3.0");
  });

  test("a declared side that reads nothing is the stale lane's business", () => {
    expect(declared("MIT AND CC-BY-3.0", signal([], ["MIT"]))).toEqual({ outcome: "ok" });
  });
});

describe("justificationValidity — contradictory-claims-recorded", () => {
  const contradictory = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "contradictory-claims-recorded", expression }, s);

  test("the two sides still disagree", () => {
    expect(contradictory("AGPL-3.0-only", signal(["BSD-3-Clause"], ["AGPL-3.0-only"]))).toEqual({
      outcome: "ok",
    });
  });

  test("the two sides now agree: nothing contradictory is left to record", () => {
    const result = contradictory("AGPL-3.0-only", signal(["AGPL-3.0-only"], ["AGPL-3.0-only"]));

    expect(result.outcome).toBe("unnecessary");
    expect(result.outcome === "unnecessary" && result.reason).toContain("agree");
  });

  test("agreement is on the licences read, not on how each side spelled them", () => {
    expect(
      contradictory("MIT AND CC0-1.0", signal(["MIT AND CC0-1.0"], ["CC0-1.0 AND MIT"])).outcome,
    ).toBe("unnecessary");
  });

  test("one side silent is no agreement", () => {
    expect(contradictory("AGPL-3.0-only", signal([], ["AGPL-3.0-only"]))).toEqual({
      outcome: "ok",
    });
  });
});

describe("justificationValidity — license-not-found", () => {
  const notFound = (expression: string, s: ObservedSignal): JustificationValidity =>
    justificationValidity({ justification: "license-not-found", expression }, s);

  test("neither side states a licence, so the researched expression stands", () => {
    expect(notFound("MIT", NO_SIGNAL)).toEqual({ outcome: "ok" });
  });

  test("a family label is not a licence anyone can read off the package", () => {
    expect(notFound("MIT", signal(["Dual License"], []))).toEqual({ outcome: "ok" });
  });

  test("the declared side now states a licence", () => {
    const result = notFound("MIT", signal(["Apache-2.0"], []));

    expect(result.outcome).toBe("invalid");
    expect(result.outcome === "invalid" && result.reason).toContain("Apache-2.0");
  });

  test("the scan now states a licence", () => {
    expect(notFound("MIT", signal([], ["Apache-2.0"])).outcome).toBe("invalid");
  });
});

describe("justificationValidity — the reason an invalid entry carries", () => {
  test("it names both sanctioned fallbacks, so the legal refile is in the message", () => {
    const result = justificationValidity(
      { justification: "license-not-found", expression: "MIT" },
      signal(["Apache-2.0"], []),
    );

    expect(result.outcome === "invalid" && result.reason).toContain(
      "contradictory-claims-recorded",
    );
    expect(result.outcome === "invalid" && result.reason).toContain("license-reviewed");
  });
});
