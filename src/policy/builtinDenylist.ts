/**
 * Shipped TOOL-LEVEL source-available deny defaults (POL-09 defaults).
 *
 * A curated, committed list of the well-known SOURCE-AVAILABLE (use-restricted,
 * non-OSI) licenses that legally cannot be redistributed in a client-shipped
 * artifact — BUSL, SSPL, and Elastic. These ship as ENGINE DEFAULTS: every
 * repository consuming this tool denies them WITHOUT authoring a single [[deny]]
 * entry, mirroring the shipped copyleft families (copyleft.ts) and the shipped
 * clarify defaults (builtinOverrides.ts). A compliance tool whose out-of-the-box
 * behaviour PASSES a source-available license has its defaults backwards — this is
 * the corrective.
 *
 * A consumer's own [[deny]] entries are evaluated ALONGSIDE these: the OR-election
 * union spans both sets (denylist.ts), so a policy deny and a builtin deny compose
 * correctly. Attribution is policy-first — a license a consumer ALSO lists is
 * cited as their `denied[i]`; a license only these defaults catch is cited as
 * `default:source-available`, naming the matched pattern and the rationale.
 *
 * License-mode only, and EVERY pattern MUST be a registered SPDX id — the
 * builtinDenylist test asserts this against spdx-license-ids. That guard is
 * load-bearing: the patterns join the satisfies allowlist union in denylist.ts,
 * and a single non-SPDX id there makes spdx-satisfies throw, which the defensive
 * catch turns into "deny nothing" for the whole union. The non-SPDX riders —
 * Commons-Clause, the Redis RSAL, the PolyForm family — have no registered id and
 * stay name-mode opt-ins in the consumer's policy: a name-mode default would have
 * to GUESS encumbered package names, which the deny matcher must never do.
 */
import type { DenyRule } from "./denylist";

/** One shipped source-available deny default, license-mode (allowlist = the id). */
function sourceAvailable(pattern: string, reason: string): DenyRule {
  return { match: "license", pattern, allowlist: [pattern], reason };
}

/** The rule id every builtin source-available deny is cited under. */
export const BUILTIN_DENY_RULE_ID = "default:source-available";

export const BUILTIN_DENY_RULES: ReadonlyArray<DenyRule> = [
  sourceAvailable(
    "BUSL-1.1",
    "Business Source License 1.1 is source-available, not open source — it forbids production and competing use until the change date, so it cannot ship in a distributed inventory.",
  ),
  sourceAvailable(
    "SSPL-1.0",
    "Server Side Public License 1.0 is source-available (OSI-rejected); its service-source copyleft makes it unredistributable in client-shipped artifacts.",
  ),
  sourceAvailable(
    "Elastic-2.0",
    "Elastic License 2.0 is source-available with use restrictions (no managed-service resale, no circumvention); it cannot ship in a distributed inventory.",
  ),
];
