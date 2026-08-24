import { describe, expect, test } from "bun:test";

import { compileNamePattern, isGlobPattern } from "./namePattern";

// The package-name pattern dialect: `*` fills one name segment, `**` crosses
// segment boundaries, and a trailing slash is shorthand for "everything inside
// this scope". Every other character is a literal, matching is case-sensitive,
// and a pattern made of nothing but wildcards is refused — it would accept
// every package in the model.

/** Does `name` match `pattern` under the dialect? */
const matches = (pattern: string, name: string): boolean => compileNamePattern(pattern).test(name);

describe("compileNamePattern", () => {
  test("`*` fills the rest of a segment after a literal prefix", () => {
    expect(matches("@img/sharp-*", "@img/sharp-libvips-darwin-arm64")).toBe(true);
    expect(matches("@img/sharp-*", "@img/sharp-wasm32")).toBe(true);
  });

  test("the literal affix is required in full", () => {
    expect(matches("@img/sharp-*", "@img/sharp")).toBe(false);
    expect(matches("@img/sharp-*", "@img/sharpen")).toBe(false);
  });

  test("`*` matches a whole segment but never crosses a slash", () => {
    expect(matches("@img/*", "@img/sharp")).toBe(true);
    expect(matches("@img/*", "@img/a/b")).toBe(false);
  });

  test("`**` crosses segment boundaries", () => {
    expect(matches("@img/**", "@img/sharp")).toBe(true);
    expect(matches("@img/**", "@img/a/b")).toBe(true);
  });

  test("a trailing slash means anything inside that scope", () => {
    expect(matches("@cspell/", "@cspell/dict-django")).toBe(true);
    expect(matches("@cspell/", "@cspell/dict/nested")).toBe(true);
    expect(matches("@cspell/", "@cspell")).toBe(false);
    expect(matches("@cspell/", "@cspellx/dict-django")).toBe(false);
  });

  test("a slash-less pattern with a literal affix is in the dialect", () => {
    expect(matches("types-*", "types-node")).toBe(true);
    expect(matches("types-*", "@types/node")).toBe(false);
  });

  test("regex metacharacters are literals: the `.` in `lodash.*`", () => {
    expect(matches("lodash.*", "lodash.merge")).toBe(true);
    expect(matches("lodash.*", "lodashXmerge")).toBe(false);
  });

  test("matching is case-sensitive", () => {
    expect(matches("LODASH.*", "lodash.merge")).toBe(false);
    expect(matches("@IMG/sharp-*", "@img/sharp-wasm32")).toBe(false);
  });

  test("the match is anchored at both ends", () => {
    expect(matches("@img/sharp-*", "x@img/sharp-wasm32")).toBe(false);
    expect(matches("lodash.*", "@scope/lodash.merge")).toBe(false);
  });

  test("a pattern with no literal character is refused", () => {
    for (const anchorless of ["*", "**", "*/*", "*/**", "**/*", "/", "", "   "]) {
      expect(() => compileNamePattern(anchorless)).toThrow(/at least one literal character/);
    }
  });

  test("a literal character anywhere is enough to anchor the pattern", () => {
    expect(() => compileNamePattern("**/dict-*")).not.toThrow();
    expect(matches("**/dict-*", "@cspell/dict-django")).toBe(true);
  });
});

describe("isGlobPattern", () => {
  test("wildcard and trailing-slash forms are patterns", () => {
    expect(isGlobPattern("@img/sharp-*")).toBe(true);
    expect(isGlobPattern("@img/**")).toBe(true);
    expect(isGlobPattern("@cspell/")).toBe(true);
    expect(isGlobPattern("types-*")).toBe(true);
  });

  test("a plain package name is not a pattern", () => {
    expect(isGlobPattern("sharp")).toBe(false);
    expect(isGlobPattern("lodash.merge")).toBe(false);
    expect(isGlobPattern("@img/sharp-wasm32")).toBe(false);
  });
});
