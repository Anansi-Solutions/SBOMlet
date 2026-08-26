import { describe, expect, test } from "bun:test";

import { asRawLicense, canon } from "../../test/brandTestSupport";
import { observedSignalBySource, type ObservedSignal } from "./normalize";
import type {
  LicenseClaim,
  LicenseClaimSource,
  LicenseFamily,
  LicenseFinding,
} from "../model/dependencies";

// The pre-override observed signal, split by the lane that produced it. The
// union is what the override machinery has always consumed and stays
// byte-identical; the two lane views exist so a recorded per-source detection
// can be compared against the lane that would produce it.

const sourced = (raw: string, source: LicenseClaimSource): LicenseClaim => ({
  raw: asRawLicense(raw),
  kind: "name",
  source,
});

const precise = (expression: string): LicenseFinding => ({
  expression: canon(expression),
  elected: canon(expression),
  source: "generator",
  confidence: "exact",
});

const impreciseAs = (family: LicenseFamily): LicenseFinding => ({
  expression: null,
  elected: null,
  source: "generator",
  confidence: "imprecise",
  impreciseFamily: family,
});

// The expected signal, minting the raw-domain lane members through the production mint.
const want = (
  registry: readonly string[],
  intensive: readonly string[],
  union: readonly string[],
): ObservedSignal => ({
  registry: registry.map(asRawLicense),
  intensive: intensive.map(asRawLicense),
  union: union.map(asRawLicense),
});

describe("observedSignalBySource", () => {
  test("collector and registry claims form the registry lane, scancode the intensive lane", () => {
    const claims = [
      sourced("MIT", "generator"),
      sourced("Apache-2.0", "registry"),
      sourced("MIT AND CC0-1.0", "scancode"),
    ];

    expect(observedSignalBySource(claims, precise("MIT"))).toEqual(
      want(["MIT", "Apache-2.0"], ["MIT AND CC0-1.0"], ["MIT", "Apache-2.0", "MIT AND CC0-1.0"]),
    );
  });

  test("a lane with no claim of its own is empty, never absent", () => {
    const claims = [sourced("MIT", "generator")];

    expect(observedSignalBySource(claims, precise("MIT"))).toEqual(want(["MIT"], [], ["MIT"]));
  });

  test("raw values are trimmed, blanks dropped and duplicates deduped in every view", () => {
    const claims = [
      sourced("  MIT  ", "generator"),
      sourced("   ", "generator"),
      sourced("MIT", "registry"),
      sourced("MIT", "scancode"),
    ];

    expect(observedSignalBySource(claims, precise("MIT"))).toEqual(want(["MIT"], ["MIT"], ["MIT"]));
  });

  test("the imprecise family token joins the lane whose claim yields it", () => {
    const claims = [sourced("BSD License", "registry"), sourced("MIT", "scancode")];

    expect(observedSignalBySource(claims, impreciseAs("BSD"))).toEqual(
      want(["BSD License", "BSD"], ["MIT"], ["BSD License", "MIT", "BSD"]),
    );
  });

  test("an intensive-lane family token stays out of the registry lane", () => {
    const claims = [sourced("MIT", "generator"), sourced("BSD", "scancode")];

    expect(observedSignalBySource(claims, impreciseAs("BSD"))).toEqual(
      want(["MIT"], ["BSD"], ["MIT", "BSD"]),
    );
  });

  test("a precise finding contributes no family token", () => {
    const claims = [sourced("BSD-3-Clause", "registry")];

    expect(observedSignalBySource(claims, precise("BSD-3-Clause"))).toEqual(
      want(["BSD-3-Clause"], [], ["BSD-3-Clause"]),
    );
  });

  test("no claims at all yields three empty views", () => {
    expect(observedSignalBySource([], precise("MIT"))).toEqual(want([], [], []));
  });
});
