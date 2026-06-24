import { describe, expect, test } from "bun:test";

import { alignTables } from "../src/render/alignTables";

const lineWidths = (md: string): Set<number> =>
  new Set(md.split("\n").map((line) => line.length));

describe("alignTables", () => {
  test("pads columns so a ragged table's pipes line up", () => {
    const out = alignTables(
      [
        "| Name | Version |",
        "| --- | --- |",
        "| react | 19.2.0 |",
        "| a-very-long-package-name | 1.0.0 |",
      ].join("\n"),
    ).split("\n");
    // every row is the same width → the pipes line up
    expect(new Set(out.map((l) => l.length)).size).toBe(1);
    // the separator is regenerated to the column widths
    expect(/^\| -+ \| -+ \|$/.test(out[1]!)).toBe(true);
    expect(out[3]).toContain("a-very-long-package-name");
  });

  test("leaves fenced code blocks untouched and aligns real tables", () => {
    const out = alignTables(
      [
        "```",
        "| a | bb |",
        "| --- | --- |",
        "| x | y |",
        "```",
        "",
        "| Name | V |",
        "| --- | --- |",
        "| react | 19 |",
      ].join("\n"),
    ).split("\n");
    // the fenced table is byte-for-byte verbatim
    expect(out.slice(1, 4)).toEqual([
      "| a | bb |",
      "| --- | --- |",
      "| x | y |",
    ]);
    // the real table below the fence is aligned
    expect(lineWidths(out.slice(6, 9).join("\n")).size).toBe(1);
  });

  test("preserves an escaped pipe in a cell and counts it for width", () => {
    const out = alignTables(
      ["| Name | License |", "| --- | --- |", "| pkg | MIT \\| Apache |"].join(
        "\n",
      ),
    ).split("\n");
    expect(out[2]).toContain("MIT \\| Apache");
    expect(new Set(out.map((l) => l.length)).size).toBe(1);
  });

  test("passes non-table content through unchanged", () => {
    const input = "# Heading\n\nProse with a | pipe but no table.\n";
    expect(alignTables(input)).toBe(input);
  });

  test("aligns multiple independent tables", () => {
    const out = alignTables(
      [
        "| A | B |",
        "| --- | --- |",
        "| xxxxx | y |",
        "",
        "## next",
        "",
        "| Name | Eco |",
        "| --- | --- |",
        "| react | npm |",
      ].join("\n"),
    );
    expect(lineWidths(out.split("\n").slice(0, 3).join("\n")).size).toBe(1);
    expect(lineWidths(out.split("\n").slice(6, 9).join("\n")).size).toBe(1);
  });

  test("is idempotent", () => {
    const once = alignTables("| A | BB |\n| --- | --- |\n| x | yy |");
    expect(alignTables(once)).toBe(once);
  });
});
