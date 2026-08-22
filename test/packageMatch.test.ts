import { describe, expect, test } from "bun:test";

import { matchesPackage, type PackageMatchTarget } from "../src/policy/engine/match";
import { JUSTIFICATION_VALUES } from "../src/policy/schema/clarify";
import { RATIONALE_VALUES } from "../src/policy/schema/compatible";

// One matcher decides, for every policy surface, whether an entry covers a
// package: an exact `name` or a `pattern` over the display name, narrowed by an
// optional version or version list. Versions are always literal - a wildcard
// version is not in the schema, and must not sneak in through the matcher.

const target = (name: string, version: string): PackageMatchTarget => ({ name, version });

describe("matchesPackage - name and pattern", () => {
  test("an exact name is string equality", () => {
    expect(matchesPackage({ name: "sharp" }, target("sharp", "0.34.4"))).toBe(true);
    expect(matchesPackage({ name: "sharp" }, target("sharpen", "0.34.4"))).toBe(false);
    expect(matchesPackage({ name: "sharp" }, target("Sharp", "0.34.4"))).toBe(false);
  });

  test("an exact name is never read as a pattern", () => {
    expect(matchesPackage({ name: "@img/sharp-*" }, target("@img/sharp-wasm32", "1.2.3"))).toBe(
      false,
    );
  });

  test("a pattern covers the family it anchors", () => {
    const selector = { pattern: "@img/sharp-*" };

    expect(matchesPackage(selector, target("@img/sharp-wasm32", "1.2.3"))).toBe(true);
    expect(matchesPackage(selector, target("@img/sharp-libvips-darwin-arm64", "1.2.3"))).toBe(true);
    expect(matchesPackage(selector, target("@img/sharp", "1.2.3"))).toBe(false);
  });

  test("a scope pattern covers everything inside the scope", () => {
    expect(matchesPackage({ pattern: "@cspell/" }, target("@cspell/dict-django", "4.1.0"))).toBe(
      true,
    );
  });

  test("a selector naming neither a name nor a pattern covers nothing", () => {
    expect(matchesPackage({}, target("sharp", "0.34.4"))).toBe(false);
    expect(matchesPackage({ version: "0.34.4" }, target("sharp", "0.34.4"))).toBe(false);
  });
});

describe("matchesPackage - versions are literal", () => {
  test("no version narrows to any version", () => {
    expect(matchesPackage({ name: "sharp" }, target("sharp", "0.34.4"))).toBe(true);
    expect(matchesPackage({ name: "sharp" }, target("sharp", "0.33.0"))).toBe(true);
  });

  test("one version is exact equality", () => {
    expect(matchesPackage({ name: "sharp", version: "0.34.4" }, target("sharp", "0.34.4"))).toBe(
      true,
    );
    expect(matchesPackage({ name: "sharp", version: "0.34.4" }, target("sharp", "0.33.0"))).toBe(
      false,
    );
  });

  test("a version list is membership by exact equality", () => {
    const selector = { name: "type-fest", version: ["4.41.0", "5.1.0"] };

    expect(matchesPackage(selector, target("type-fest", "4.41.0"))).toBe(true);
    expect(matchesPackage(selector, target("type-fest", "5.1.0"))).toBe(true);
    expect(matchesPackage(selector, target("type-fest", "4.40.0"))).toBe(false);
  });

  test("an empty version list covers nothing", () => {
    expect(matchesPackage({ name: "type-fest", version: [] }, target("type-fest", "4.41.0"))).toBe(
      false,
    );
  });

  test("a version is never a pattern", () => {
    expect(matchesPackage({ name: "sharp", version: "0.34.*" }, target("sharp", "0.34.4"))).toBe(
      false,
    );
    expect(matchesPackage({ pattern: "@img/*", version: "1.*" }, target("@img/a", "1.2.3"))).toBe(
      false,
    );
  });

  test("a pattern and a version narrow together", () => {
    const selector = { pattern: "@img/sharp-*", version: ["1.2.3"] };

    expect(matchesPackage(selector, target("@img/sharp-wasm32", "1.2.3"))).toBe(true);
    expect(matchesPackage(selector, target("@img/sharp-wasm32", "1.2.4"))).toBe(false);
    expect(matchesPackage(selector, target("@img/other", "1.2.3"))).toBe(false);
  });
});

describe("the closed enum value sets", () => {
  test("rationale values are the closed alphabetical set", () => {
    expect(RATIONALE_VALUES).toEqual([
      "build-time-only",
      "development-tool-only",
      "license-reviewed",
      "os-package-unmodified",
      "unused-transitive",
    ]);
  });

  test("justification values are the closed alphabetical set", () => {
    expect(JUSTIFICATION_VALUES).toEqual([
      "contradictory-claims-recorded",
      "declared-more-complete",
      "dual-license-choice",
      "license-not-found",
      "scan-found-additional-content",
      "scan-more-precise",
      "scan-overdetection",
    ]);
  });
});
