/**
 * Rule ids and reason builders for the target-compatibility lane's five outcomes. Pure string
 * builders taking already-computed engine values ({@link ReasonContext}) so the policy engine that
 * wires this lane in passes classify.ts's own results verbatim - never a second, drift-prone read
 * of the axis/profile data. Follows the existing evaluate.ts reason register: lowercase start, an
 * em-dash before the remedy clause, names in double quotes. No reason string ever carries retrieval
 * metadata (a URL or an ISO timestamp) - only the reader-facing source citation classify.ts already
 * produced.
 */
import type { TargetProfile } from "./profile";

/** ok: the axis/profile already say the elected expression is compatible. */
export const TARGET_RULE_OK = "target:ok";
/** fail: the elected expression is incompatible with the target under its profile. */
export const TARGET_RULE_INCOMPATIBLE = "target:incompatible";
/** warn: weak copyleft, usable only behind a compliant linking boundary. */
export const TARGET_RULE_BOUNDARY = "target:boundary";
/** warn/fail per the residual knob: no vetted compatibility data for this pair. */
export const TARGET_RULE_UNKNOWN_PAIR = "target:unknown-pair";
/** ok, distinct id: a copyleft/agpl obligation held out of scope by the usage profile. */
export const TARGET_RULE_INTERNAL_USE = "target:internal-use";

/** The values every reason builder below needs - all engine-computed, never re-derived here. */
export interface ReasonContext {
  /** The elected expression's rendered text. */
  readonly elected: string;
  readonly occurrenceTarget: string;
  /** The rendered profile descriptor - see {@link formatProfileLabel}. */
  readonly profileLabel: string;
  /**
   * The deciding tier's reader-facing citation (classifyLeaf's `source`, possibly hold-appended).
   */
  readonly source: string;
}

/**
 * One rendering of a usage profile in reader's words, e.g. `"proprietary, network-deployed,
 * distributed externally"` - shared by every reason builder here and, later, the report header, so
 * the profile never reads differently in two places.
 */
export function formatProfileLabel(profile: TargetProfile): string {
  const license = profile.license.kind === "proprietary" ? "proprietary" : profile.license.id;
  const network = profile.network ? "network-deployed" : "not network-deployed";
  const distribution =
    profile.distribution === "external" ? "distributed externally" : "internal use only";

  return `${license}, ${network}, ${distribution}`;
}

/** The shared opening clause every builder below extends with its own outcome-specific text. */
function reasonPrefix(ctx: ReasonContext): string {
  return `elected "${ctx.elected}" under the "${ctx.occurrenceTarget}" target profile (${ctx.profileLabel})`;
}

/** `target:ok` reason: the elected expression is compatible under the target profile. */
export function targetOkReason(ctx: ReasonContext): string {
  return `${reasonPrefix(ctx)} is compatible - ${ctx.source}`;
}

/** `target:incompatible` reason: a fail, remedied by an explicit accept or a corrected finding. */
export function targetIncompatibleReason(ctx: ReasonContext): string {
  return (
    `${reasonPrefix(ctx)} is incompatible - ${ctx.source} - accept explicitly via ` +
    `[[compatible]] or correct the finding via [[clarify]]`
  );
}

/**
 * `target:boundary` reason: weak copyleft, usable only behind a compliant linking boundary.
 */
export function targetBoundaryReason(ctx: ReasonContext): string {
  return (
    `${reasonPrefix(ctx)} is weak copyleft - ${ctx.source} - usable only behind a compliant ` +
    `boundary (dynamic linking / relinkability); confirm and accept via [[compatible]]`
  );
}

/** `target:unknown-pair` reason: honest residual, never a silent pass (A4). */
export function targetUnknownPairReason(ctx: ReasonContext): string {
  return (
    `${reasonPrefix(ctx)} has no vetted compatibility data - ${ctx.source} - not silently ` +
    `passed; accept explicitly via [[compatible]] or correct the finding via [[clarify]]`
  );
}

/**
 * `target:internal-use` reason: a distribution-triggered obligation held out of scope. `ctx.source`
 * already carries both the internal-use basis and the original axis citation (profile.ts appends
 * the hold basis onto the preserved source), so this builder names neither a second time.
 */
export function targetInternalUseReason(ctx: ReasonContext): string {
  return `${reasonPrefix(ctx)} carries a distribution-triggered obligation held out of scope for internal use - ${ctx.source}`;
}
