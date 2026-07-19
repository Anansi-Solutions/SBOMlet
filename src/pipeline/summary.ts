/**
 * The stderr policy summary and the log sanitizer it depends on: every
 * untrusted string printed to stderr passes through sanitizeForLog here, so
 * the fixed summary line shapes cannot be forged or erased.
 */

import { type Verdict } from "../model/dependencies";
import { unusedRuleIds } from "../policy/evaluate";
import { type Policy } from "../policy/schema";

/**
 * Reason text of an unused compatible[i]/clarify[i]/clarify[i].packages[j]
 * rule id — surfaced in the unused-entry warning so the stale policy line is
 * self-explanatory. The member shape (a dead listed package inside a USED
 * multi-package clarify rule) renders the rule's own shared `reason` — the
 * human-authored text explains the whole entry — with the specific dead
 * member's `name@version` (or bare `name` when unpinned) appended, so the
 * line points at exactly which listed package never matched. Defensive
 * empty string for an unrecognized id shape, an out-of-range rule/member
 * index, or a malformed id. Exported for direct unit testing (the
 * sanitizeForLog precedent above).
 */
export function unusedRuleReason(policy: Policy, ruleId: string): string {
  const memberMatch = /^clarify\[(\d+)\]\.packages\[(\d+)\]$/.exec(ruleId);
  if (memberMatch !== null) {
    const rule = policy.clarify[Number(memberMatch[1])];
    const member = rule?.packages[Number(memberMatch[2])];
    if (rule === undefined || member === undefined) return "";
    const coordinate =
      member.version !== undefined
        ? `${member.name}@${member.version}`
        : member.name;
    return `${rule.reason} (${coordinate})`;
  }
  const match = /^(compatible|clarify)\[(\d+)\]$/.exec(ruleId);
  if (match === null) return "";
  const index = Number(match[2]);
  const rule =
    match[1] === "compatible"
      ? policy.compatible[index]
      : policy.clarify[index];
  return rule?.reason ?? "";
}

/**
 * Maximum printed length of one untrusted field on stderr: long enough for
 * any legitimate reason/purl, short enough that a crafted megabyte policy
 * reason cannot flood CI logs.
 */
const MAX_LOG_FIELD = 500;

/**
 * Sanitize one untrusted string at the stderr print boundary.
 *
 * TOML basic strings decode \n, \r, and \uXXXX escapes, so policy-authored
 * reasons/descriptions — and SBOM-derived names, versions, and purls baked
 * into engine reasons — can carry control characters. Unsanitized, a crafted
 * reason forges summary lines (newline injection) or erases real fail lines in
 * ANSI-aware terminals (ESC[2K / ESC[1A). Every C0 control character (incl.
 * \n, \r, \t, and ESC 0x1B), DEL (0x7F), and the C1 range (0x80-0x9F) is
 * replaced with a space, then the field is length-capped. Plain printable text
 * passes through unchanged, so the fixed summary shapes below are unaffected.
 * Exported for direct unit testing.
 */
export function sanitizeForLog(value: string): string {
  const flattened = value.replace(
    // eslint-disable-next-line no-control-regex -- deliberate control-character class: sanitizer
    /[\u0000-\u001f\u007f-\u009f]/g,
    " ",
  );
  return flattened.length > MAX_LOG_FIELD
    ? `${flattened.slice(0, MAX_LOG_FIELD)} ...[truncated]`
    : flattened;
}

/**
 * The stderr verdict summary — the CLI owns stderr; the pure engine modules
 * stay silent. Shape (locked by test/cli.test.ts):
 *   policy: N fail, N warn, N suppressed, N ok (M verdicts)
 *   policy: N imprecise (review / disambiguate via [[clarify]])  (only when N>0)
 *   policy fail: <purl> in <target> — <rule>: <reason>   (per fail/warn,
 *                                                          verdict order)
 *   policy warning: unused entry <ruleId> — <reason>      (per unused rule)
 * Reasons are policy-authored text printed as plain text — no shell
 * interpolation exists anywhere (argv-array exec only). Every interpolated
 * untrusted field (purl, occurrence target, rule id, reason) passes through
 * sanitizeForLog so the line structure of this summary cannot be forged or
 * erased.
 */
export function writePolicySummary(
  policy: Policy,
  verdicts: ReadonlyArray<Verdict>,
  usedClarifyIndices: ReadonlySet<number>,
  usedClarifyMembers: ReadonlySet<string> = new Set(),
): void {
  const counts = { ok: 0, warn: 0, fail: 0, suppressed: 0 };
  for (const verdict of verdicts) counts[verdict.status] += 1;
  process.stderr.write(
    `policy: ${counts.fail} fail, ${counts.warn} warn, ` +
      `${counts.suppressed} suppressed, ${counts.ok} ok ` +
      `(${verdicts.length} verdicts)\n`,
  );
  // Surface the imprecise count on its OWN line (the counts-line shape above
  // is unchanged). Imprecise verdicts are a subset of the warn count
  // — they need clarify-disambiguation, not a gate failure. Printed only when
  // any exist, so policies with no imprecise findings keep byte-identical output.
  //
  // This count is PER-OCCURRENCE (one per package×target verdict), matching
  // the `(M verdicts)` denominator above — NOT the per-package markdown review
  // section. The "(N verdicts)" suffix mirrors the counts-line above so the
  // denominator is unambiguous and never read as a package count.
  const impreciseCount = verdicts.filter((v) =>
    v.rule.startsWith("default:imprecise"),
  ).length;
  if (impreciseCount > 0) {
    process.stderr.write(
      `policy: ${impreciseCount} imprecise (review / disambiguate via ` +
        `[[clarify]]) (${impreciseCount} verdicts)\n`,
    );
  }
  // Surface the assessment-conflict count on its OWN line (the counts-line
  // shape above is unchanged). A conflict:scancode verdict is a FAIL
  // (a subset of the fail count) — the in-depth scan disagrees with the quick
  // check and a human must resolve it via [[clarify]]. Printed only when any
  // exist, so policies with no conflicts keep byte-identical output.
  const conflictCount = verdicts.filter(
    (v) => v.rule === "conflict:scancode",
  ).length;
  if (conflictCount > 0) {
    process.stderr.write(
      `policy: ${conflictCount} assessment conflict(s) — resolve via ` +
        `[[clarify]] (${conflictCount} verdicts)\n`,
    );
  }
  // Surface how many would-be fails were dev-downgraded to warn on their own
  // line (the counts-line shape above is unchanged). These are
  // a subset of the warn count — a build-time-only copyleft/unknown that carries
  // no distribution obligation. Printed only when any exist, so policies with no
  // dev downgrades keep byte-identical output. Matched on the auditable
  // dev-downgrade marker that evaluate.applyDevScope appends to the reason.
  const devDowngradedCount = verdicts.filter(
    (v) =>
      v.status === "warn" &&
      v.reason.includes("downgraded to warn: dev-only occurrence"),
  ).length;
  if (devDowngradedCount > 0) {
    process.stderr.write(
      `policy: ${devDowngradedCount} dev-downgraded (would-be fail on a ` +
        `dev-only occurrence → warn) (${devDowngradedCount} verdicts)\n`,
    );
  }
  // Verdicts are already sorted compareCodeUnits on (purl, occurrenceTarget) —
  // print fail/warn lines in that deterministic order.
  for (const verdict of verdicts) {
    if (verdict.status === "fail" || verdict.status === "warn") {
      process.stderr.write(
        `policy ${verdict.status}: ${sanitizeForLog(verdict.purl)} in ` +
          `${sanitizeForLog(verdict.occurrenceTarget)} — ` +
          `${sanitizeForLog(verdict.rule)}: ${sanitizeForLog(verdict.reason)}\n`,
      );
    }
  }
  for (const ruleId of unusedRuleIds(
    policy,
    verdicts,
    usedClarifyIndices,
    usedClarifyMembers,
  )) {
    process.stderr.write(
      `policy warning: unused entry ${sanitizeForLog(ruleId)} — ` +
        `${sanitizeForLog(unusedRuleReason(policy, ruleId))}\n`,
    );
  }
}
