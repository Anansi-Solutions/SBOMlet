/**
 * The deterministic clarifications emitter: one fixed byte answer for an entry set, the documented
 * key order, a round-trip guard that refuses anything reading back differently, and the check for
 * `#` characters a rewrite would drop.
 */

import { describe, expect, test } from "bun:test";

import { emitClarifications, rewriteWouldDropText } from "../src/maintain/tomlEmit";
import { parseClarifications } from "../src/policy/clarifications";

const FULL = [
  "[[clarify]]",
  'name = "spdx-ranges"',
  'version = "2.1.1"',
  'detected = { registry = "(MIT AND CC-BY-3.0)", intensive = "MIT" }',
  'justification = "declared-more-complete"',
  'expression = "(MIT AND CC-BY-3.0)"',
  'evidence = [ "LICENSE", "https://example.invalid/notice" ]',
  'comment = "The scan read only the root LICENSE — café, naïve, 日本語."',
].join("\n");

const PATTERNED = [
  "[[clarify]]",
  'pattern = "types-*"',
  "detected = { registry = false }",
  'justification = "license-not-found"',
  'expression = "MIT"',
].join("\n");

const VERSION_LIST = [
  "[[clarify]]",
  'name = "many-versions"',
  'version = [ "1.0.0", "2.0.0" ]',
  "detected = { intensive = false }",
  'justification = "license-not-found"',
  'expression = "MIT"',
].join("\n");

describe("emitClarifications", () => {
  test("the same entries emit the same bytes every time", () => {
    const entries = parseClarifications([FULL, PATTERNED].join("\n\n"));

    expect(emitClarifications(entries)).toBe(emitClarifications(entries));
  });

  test("an entry's keys come out in the documented order", () => {
    expect(emitClarifications(parseClarifications(FULL)).split("\n").slice(0, 9)).toEqual([
      "[[clarify]]",
      'name = "spdx-ranges"',
      'version = "2.1.1"',
      'detected = { registry = "(MIT AND CC-BY-3.0)", intensive = "MIT" }',
      'justification = "declared-more-complete"',
      'expression = "(MIT AND CC-BY-3.0)"',
      'evidence = [ "LICENSE", "https://example.invalid/notice" ]',
      'comment = "The scan read only the root LICENSE — café, naïve, 日本語."',
      "",
    ]);
  });

  test("a pattern entry emits its selector in the name slot", () => {
    expect(emitClarifications(parseClarifications(PATTERNED))).toBe(`${PATTERNED}\n`);
  });

  test("entries keep the order they were given", () => {
    const text = emitClarifications(parseClarifications([VERSION_LIST, FULL].join("\n\n")));

    expect(text.indexOf("many-versions")).toBeLessThan(text.indexOf("spdx-ranges"));
  });

  test("emitted text reads back as the entries it was given", () => {
    const entries = parseClarifications([FULL, PATTERNED, VERSION_LIST].join("\n\n"));
    const reread = parseClarifications(emitClarifications(entries));

    expect(reread).toEqual(entries);
  });

  test("re-emitting emitted text is a fixed point", () => {
    const once = emitClarifications(parseClarifications([FULL, VERSION_LIST].join("\n\n")));

    expect(emitClarifications(parseClarifications(once))).toBe(once);
  });

  test("no entries emit no bytes", () => {
    expect(emitClarifications([])).toBe("");
  });

  test("the output is LF-only", () => {
    expect(emitClarifications(parseClarifications([FULL, PATTERNED].join("\n\n")))).not.toContain(
      "\r",
    );
  });

  test("a value the encoder would drop aborts instead of writing the entry without it", () => {
    const [rule] = parseClarifications(FULL);
    const dropped = { ...rule!, comment: null as unknown as string };

    expect(() => emitClarifications([dropped])).toThrow(/would not read back/);
  });
});

describe("rewriteWouldDropText", () => {
  test("a comment line the rewrite would destroy is reported", () => {
    const text = `# researched 2026-01-01, see the ticket\n${FULL}\n`;

    expect(rewriteWouldDropText(text, parseClarifications(text))).toBe(true);
  });

  test("a trailing comment on a key is reported", () => {
    const text = `${FULL} # keep this\n`;

    expect(rewriteWouldDropText(text, parseClarifications(text))).toBe(true);
  });

  test("a file carrying no comments is not reported", () => {
    const text = `${FULL}\n`;

    expect(rewriteWouldDropText(text, parseClarifications(text))).toBe(false);
  });

  test("a hash inside a value is not read as a comment", () => {
    const text = [
      "[[clarify]]",
      'name = "sharp"',
      'detected = { registry = "C#" }',
      'justification = "license-not-found"',
      'expression = "MIT"',
      'comment = "the # is part of the name"',
      "",
    ].join("\n");

    expect(rewriteWouldDropText(text, parseClarifications(text))).toBe(false);
  });

  test("the emitter's own output never reports a loss", () => {
    const entries = parseClarifications([FULL, PATTERNED, VERSION_LIST].join("\n\n"));
    const text = emitClarifications(entries);

    expect(rewriteWouldDropText(text, parseClarifications(text))).toBe(false);
  });
});
