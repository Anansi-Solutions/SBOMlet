/**
 * Pure copyright-line extraction heuristic.
 *
 * Turns a decoded license/NOTICE text into the concrete copyright lines it
 * actually contains (~90-92% hit rate on evidence-bearing packages).
 *
 * Per line, three gates:
 * 1. a copyright claim marker — the word "copyright" (case-insensitive) or the
 *    © sign (legally equivalent);
 * 2. a concreteness marker — "(c)", ©, or a 4-digit year — so prose like
 *    "copyright law of the United States" is never extracted;
 * 3. not a template placeholder — "[yyyy]", "[year]", "[fullname]",
 *    "[name ...]" bracket variants, "<year>", "<copyright holder(s)>",
 *    "<owner>", "<name>"/"<name of ...>" (case-insensitive). Covers the
 *    GitHub/choosealicense MIT template "Copyright (c) [year] [fullname]" and
 *    the BSD "<name of author>" variants on top of the bare Apache-2.0
 *    template — all render honestly empty, never fabricated.
 *
 * This module extracts existing claims only. Fabricating a copyright line from
 * `component.author` is forbidden — a copyright claim we did not find is a
 * legal statement we cannot make. The "Author:" rendering decision belongs to
 * notices.ts.
 *
 * No I/O, no logging, no model imports — a pure text transform.
 */

/** Copyright claim marker: the word or the sign. */
const CLAIM_MARKER = /copyright|©/i;

/** Concreteness marker: "(c)", the © sign, or a 4-digit year — not prose. */
const CONCRETE_MARKER = /(\(c\)|©|\d{4})/i;

/**
 * Template placeholders — never extract a fill-in-the-blank claim. The bracket
 * class `\[name[^\]]*\]` subsumes "[name of copyright owner]" and "[name of
 * author]"; the angle alternatives are deliberately narrow (`<names?>`,
 * `<name of ...>`) so a real attribution carrying an email like
 * "<nameless@example.com>" is never filtered.
 */
const TEMPLATE_PLACEHOLDER =
  /\[yyyy\]|\[year\]|\[fullname\]|\[name[^\]]*\]|<year>|<copyright holders?>|<owner>|<names?>|<name of[^>]*>/i;

/** Cap on collected lines per text — bounds pathological files. */
const MAX_LINES = 20;

/**
 * Extract the concrete copyright lines from one decoded license/NOTICE text.
 * Lines are trimmed, deduped (first-seen order), and capped at 20 distinct
 * lines — dedup happens while collecting, so a file repeating one line many
 * times (concatenated/bundled license files with per-section headers) can
 * never consume the cap and drop later distinct holders. Splits on /\r?\n/ so
 * CRLF and LF inputs yield identical output.
 */
export function extractCopyrightLines(text: string): string[] {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    if (!CLAIM_MARKER.test(line)) continue;
    if (!CONCRETE_MARKER.test(line)) continue;
    if (TEMPLATE_PLACEHOLDER.test(line)) continue;
    out.add(line.trim());
    if (out.size >= MAX_LINES) break;
  }
  return [...out];
}
