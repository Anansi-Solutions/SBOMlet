/**
 * The AUTHORITATIVE could-be-copyleft imprecise-family token set, and the workspace-suppression
 * absorption test ({@link workspaceAbsorbs}).
 *
 * An imprecise finding carries a bare family TOKEN (the string "GPL", "BSD", "Apache" - see
 * normalize.ts AMBIGUOUS_FAMILY), never a parseable SPDX expression. To decide whether an imprecise
 * family could be masking a copyleft obligation, the policy engine matches that token against THIS
 * literal set.
 *
 * WHY a dedicated set and NOT COPYLEFT_FAMILY: COPYLEFT_FAMILY (copyleft.ts) is a ReadonlyMap keyed
 * by EXACT SPDX IDs ("GPL-3.0" → "GNU", "AGPL-3.0-only" → "GNU", …). `COPYLEFT_FAMILY.get("GPL")`
 * returns UNDEFINED - a bare family token is not an SPDX id. Routing the could-be-copyleft decision
 * through COPYLEFT_FAMILY would therefore silently classify EVERY bare-GPL/AGPL/LGPL imprecise
 * token as permissive (undefined → "not copyleft"), masking a real copyleft obligation.
 * copyleft.ts's docstring also explicitly forbids runtime family/prefix expansion of its map. So
 * this is a SEPARATE, small, enumerated literal token set.
 *
 * MEMBERSHIP: the strong-copyleft GNU-family tokens (GPL/AGPL/LGPL) plus EUPL. A bare "GPL" could
 * be any GPL variant (all copyleft); likewise "AGPL"/"LGPL". "EUPL" is strong copyleft but
 * spdx-correct cross-maps the bare label to a PERMISSIVE id, so it MUST be intercepted here rather
 * than left on the precise path. An imprecise finding with one of these families is
 * flagged-for-review (a warn, never a silent pass) so a maintainer disambiguates it via a
 * `[[clarify]]` override.
 *
 * DELIBERATE EXCLUSIONS:
 * - Permissive families ("BSD", "Apache", "MIT") are the explicitly NON-gating lane and are absent
 *   - they get a non-gating default:imprecise status.
 * - The weak-copyleft family tokens ("MPL", "EPL", "CDDL") are NOT included in this plan: no
 *   producing path emits a bare MPL/EPL/CDDL imprecise token (the imprecise findings this phase
 *   produces are the BSD/Apache permissive labels and the bare GPL-family copyleft labels), so
 *   adding speculative tokens would be untested dead data. The precise weak-copyleft ids are
 *   already gated by COPYLEFT_FAMILY on the EXPRESSION path, which an imprecise finding never
 *   reaches.
 *
 * The set is asserted member-by-member in the tests so a typo cannot silently drop a copyleft
 * family (mirrors copyleft.ts's literal-reviewable-data idiom).
 */

import {
  asSpdxLicenseLeaf,
  type LicenseFamily,
  type SpdxLicenseLeaf,
} from "../../model/dependencies";
import { absorptionCell } from "../compat/classify";

/** Bare imprecise family TOKENS that could carry a copyleft obligation. */
export const COULD_BE_COPYLEFT_FAMILIES: ReadonlySet<LicenseFamily> = new Set([
  "GPL",
  "AGPL",
  "LGPL",
  // EUPL: the EUPL is STRONG copyleft, but spdx-correct cross-maps the bare "EUPL" label to the
  // PERMISSIVE "UPL-1.0" - a copyleft→permissive mis-guess that silently passed the gate.
  // normalize.ts AMBIGUOUS_FAMILY now intercepts bare EUPL as this imprecise family token so it
  // reaches the flagged-for-review lane instead of default:ok. It is the only copyleft family
  // correct() crosses to a permissive id (the precise EUPL-1.x ids stay on the copyleft EXPRESSION
  // path and fail directly).
  "EUPL",
]);

/**
 * The OSADL `Check dependency` cells of the AGPL-3.0-only row that the GNU licences' own text
 * resolves: GPLv3 section 13 permits combining GPLv3 code with an AGPLv3 work, LGPLv3 is GPLv3 plus
 * permissions, and the remaining ids can be taken under GPLv3 (their "or later" clause, or LGPL-2.1
 * section 3).
 */
export const AGPL_WORKSPACE_SECTION_13: ReadonlySet<SpdxLicenseLeaf> = new Set(
  [
    "GPL-1.0-or-later",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
  ].map(asSpdxLicenseLeaf),
);

/**
 * Whether a workspace distributed under `workspace` absorbs one copyleft leaf: the OSADL matrix
 * answers `Yes` or `Same`, or an AGPL-3.0-only workspace meets a `Check dependency` cell in {@link
 * AGPL_WORKSPACE_SECTION_13}. A workspace license or leaf the matrix does not cover, and every
 * `No`, is never absorbed.
 */
export function workspaceAbsorbs(workspace: string, leaf: SpdxLicenseLeaf): boolean {
  const cell = absorptionCell(workspace, leaf);

  if (cell === "Yes" || cell === "Same") {
    return true;
  }

  return (
    cell === "Check dependency" &&
    workspace === "AGPL-3.0-only" &&
    AGPL_WORKSPACE_SECTION_13.has(leaf)
  );
}
