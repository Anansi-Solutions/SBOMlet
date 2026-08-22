/**
 * Deterministic TOML for the machine-owned clarifications file: one entry set, one byte answer,
 * whatever order the caller's own bookkeeping happens to hash things in.
 *
 * Every value is encoded by smol-toml, the parser this tool already reads TOML with, so quoting and
 * escaping have exactly one implementation. What is added here is placement: the documented key
 * order, the inline `detected` table the schema documents, and a blank line between entries. The
 * assembled text is then parsed back and compared against what it was built from, so a rewrite that
 * would not read back as the entries it was given raises instead of reaching the disk.
 */

import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

import { compareCodeUnits } from "../model/dependencies";
import { DETECTED_LANES, type DetectedSignal } from "../normalize/normalize";

import type { ClarifyRule } from "../policy/schema/clarify";

/**
 * The order an entry's keys are written in, matching the schema reference. `name` and `pattern` are
 * mutually exclusive, so listing both puts whichever one the entry states in the same first slot.
 */
const ENTRY_KEYS = [
  "name",
  "pattern",
  "version",
  "detected",
  "justification",
  "expression",
  "evidence",
  "comment",
] as const;

/** One entry reduced to the keys a file carries - the citation identity is the file's position. */
type ClarifyPayload = Record<string, unknown>;

function payloadOf(rule: ClarifyRule): ClarifyPayload {
  const payload: ClarifyPayload = {};

  for (const key of ENTRY_KEYS) {
    const value = rule[key];

    if (value !== undefined) {
      payload[key] = value;
    }
  }

  return payload;
}

/**
 * The `detected` table on one line, as the schema documents and the corpus writes it. smol-toml
 * hoists a nested table into its own `[clarify.detected]` section, which would both split an entry
 * across the file and move the key out of its documented slot, so each lane is encoded on its own
 * and the pairs are placed between braces here.
 */
function inlineDetected(detected: DetectedSignal): string {
  const pairs = DETECTED_LANES.filter((lane) => detected[lane] !== undefined).map((lane) =>
    stringifyToml({ [lane]: detected[lane] }).trimEnd(),
  );

  return pairs.length === 0 ? "{}" : `{ ${pairs.join(", ")} }`;
}

function keyLine(key: string, value: unknown): string {
  return key === "detected"
    ? `detected = ${inlineDetected(value as DetectedSignal)}`
    : stringifyToml({ [key]: value }).trimEnd();
}

function entryText(payload: ClarifyPayload): string {
  const lines = Object.entries(payload).map(([key, value]) => keyLine(key, value));

  return `[[clarify]]\n${lines.join("\n")}\n`;
}

/** JSON with every object's keys sorted, so two structures compare by content and not by order. */
function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, nested: unknown) => {
    if (nested === null || typeof nested !== "object" || Array.isArray(nested)) {
      return nested;
    }

    return Object.fromEntries(
      Object.entries(nested as Record<string, unknown>).sort(([a], [b]) => compareCodeUnits(a, b)),
    );
  });
}

/**
 * @throws Error when the assembled text does not parse back into the entries it was built from -
 * the caller must abandon the rewrite. A value the parser rejects outright (a string truncated
 * mid-surrogate is the realistic one) raises here too, with the parser's own message.
 */
function assertReadsBack(text: string, payloads: ReadonlyArray<ClarifyPayload>): void {
  const refusal = "the clarifications rewrite would not read back as the entries it was given";
  let parsed: unknown;

  try {
    parsed = parseToml(text);
  } catch (error) {
    throw new Error(`${refusal}: ${(error as Error).message}`, { cause: error });
  }

  if (canonicalJson((parsed as { clarify?: unknown }).clarify ?? []) !== canonicalJson(payloads)) {
    throw new Error(`${refusal} - the file was left untouched`);
  }
}

/**
 * The complete text of a clarifications file holding these entries, in this order.
 *
 * @throws Error when the text would not read back as `entries`; nothing is written in that case.
 */
export function emitClarifications(entries: ReadonlyArray<ClarifyRule>): string {
  const payloads = entries.map(payloadOf);
  const text = payloads.map(entryText).join("\n");

  assertReadsBack(text, payloads);
  return text;
}

const HASH = /#/g;

function hashCount(value: string): number {
  return (value.match(HASH) ?? []).length;
}

/** Every `#` the parsed entries account for: inside a key, a string, or a member of an array. */
function hashesIn(value: unknown): number {
  if (typeof value === "string") {
    return hashCount(value);
  }

  if (Array.isArray(value)) {
    return value.reduce<number>((total, member) => total + hashesIn(member), 0);
  }

  if (value === null || typeof value !== "object") {
    return 0;
  }

  return Object.entries(value as Record<string, unknown>).reduce(
    (total, [key, nested]) => total + hashCount(key) + hashesIn(nested),
    0,
  );
}

/**
 * Would rewriting this file lose text a person wrote? The file is machine-owned, so prose belongs
 * in an entry's `comment` and `evidence` fields; a `#` comment survives no rewrite, because the
 * parser discards it before the entries are ever seen.
 *
 * The signal is arithmetic rather than a second TOML reader: every `#` a rewrite reproduces is one
 * the entries carry in a key or a value, so a file whose `#` count differs from theirs carries at
 * least one the rewrite would not put back. It errs toward reporting a loss - a `#` written as a
 * unicode escape counts on one side only - which is the safe direction for a guard that stops a
 * destructive write.
 */
export function rewriteWouldDropText(text: string, entries: ReadonlyArray<ClarifyRule>): boolean {
  const accounted = entries.reduce((total, rule) => total + hashesIn(payloadOf(rule)), 0);

  return hashCount(text) !== accounted;
}
