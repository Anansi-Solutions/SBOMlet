/**
 * The AUTHORITATIVE could-be-copyleft imprecise-family token set (INV-04).
 *
 * An imprecise finding carries a bare family TOKEN (the string "GPL", "BSD",
 * "Apache" — see normalize.ts AMBIGUOUS_FAMILY), never a parseable SPDX
 * expression. To decide whether an imprecise family could be masking a copyleft
 * obligation, the policy engine matches that token against THIS literal set.
 *
 * WHY a dedicated set and NOT COPYLEFT_FAMILY:
 * COPYLEFT_FAMILY (copyleft.ts) is a ReadonlyMap keyed by EXACT SPDX IDs
 * ("GPL-3.0" → "GNU", "AGPL-3.0-only" → "GNU", …). `COPYLEFT_FAMILY.get("GPL")`
 * returns UNDEFINED — a bare family token is not an SPDX id. Routing the
 * could-be-copyleft decision through COPYLEFT_FAMILY would therefore silently
 * classify EVERY bare-GPL/AGPL/LGPL imprecise token as permissive (undefined →
 * "not copyleft"), masking a real copyleft obligation. copyleft.ts's docstring
 * also explicitly forbids runtime family/prefix expansion of its map. So this
 * is a SEPARATE, small, enumerated literal token set.
 *
 * MEMBERSHIP: the strong-copyleft GNU-family tokens (GPL/AGPL/LGPL) plus EUPL.
 * A bare "GPL" could be any GPL variant (all copyleft); likewise "AGPL"/"LGPL".
 * "EUPL" (W1 correction) is strong copyleft but spdx-correct cross-maps the bare
 * label to a PERMISSIVE id, so it MUST be intercepted here rather than left on
 * the precise path. An imprecise finding with one of these families is
 * flagged-for-review (a warn, never a silent pass) so a maintainer disambiguates
 * it via a `[[clarify]]` override.
 *
 * DELIBERATE EXCLUSIONS:
 * - Permissive families ("BSD", "Apache", "MIT") are the explicitly NON-gating
 *   lane and are absent — they get a non-gating default:imprecise status.
 * - The weak-copyleft family tokens ("MPL", "EPL", "CDDL") are NOT included in
 *   this plan: no producing path emits a bare MPL/EPL/CDDL imprecise token (the
 *   imprecise findings this phase produces are the BSD/Apache permissive labels
 *   and the bare GPL-family copyleft labels), so adding speculative tokens would
 *   be untested dead data. The precise weak-copyleft ids are already gated by
 *   COPYLEFT_FAMILY on the EXPRESSION path, which an imprecise finding never
 *   reaches.
 *
 * The set is asserted member-by-member in the tests so a typo cannot silently
 * drop a copyleft family (mirrors copyleft.ts's literal-reviewable-data idiom).
 */

/** Bare imprecise family TOKENS that could carry a copyleft obligation. */
export const COULD_BE_COPYLEFT_FAMILIES: ReadonlySet<string> = new Set([
  "GPL",
  "AGPL",
  "LGPL",
  // EUPL (W1 correction): the EUPL is STRONG copyleft, but spdx-correct
  // cross-maps the bare "EUPL" label to the PERMISSIVE "UPL-1.0" — a
  // copyleft→permissive mis-guess that silently passed the gate. normalize.ts
  // AMBIGUOUS_FAMILY now intercepts bare EUPL as this imprecise family token so
  // it reaches the flagged-for-review lane instead of default:ok. It is the
  // only copyleft family correct() crosses to a permissive id (the precise
  // EUPL-1.x ids stay on the copyleft EXPRESSION path and fail directly).
  "EUPL",
]);

/**
 * The absorb-all-copyleft suppression relation (revision F).
 *
 * A workspace that is ITSELF distributed under a strong-copyleft license can
 * absorb the obligations of inbound copyleft dependencies it bundles, because
 * the whole workspace is re-released under that strong copyleft. apps/scratch is
 * re-released under AGPL-3.0, so it absorbs not only the exact GNU family
 * (GPL/LGPL/AGPL) but ALSO the weaker/compatible copyleft families actually
 * bundled there (notably MPL via the sharp-libvips Apache/LGPL prebuilds and the
 * MPL-licensed transitive set), since AGPL's obligations envelope them.
 *
 * WHY a LITERAL MAP and NOT a runtime strength computation: mirror the
 * copyleft.ts / COPYLEFT_FAMILY idiom — verdict-affecting data must be a
 * reviewable, enumerated relation, never a runtime prefix/ordering inference.
 * Each absorbed family is listed explicitly with the legal reason it is sound,
 * and the SAFETY FLOOR is enforced purely by ABSENCE: a family not listed here
 * is never absorbed.
 *
 * Keyed by the WORKSPACE license's COPYLEFT_FAMILY token → the set of finding
 * COPYLEFT_FAMILY tokens that workspace ABSORBS. Absorption is DIRECTIONAL and
 * DECLARED, never symmetric: an MPL workspace does NOT absorb GNU unless an MPL
 * key is added here (it is not — no MPL-distributed workspace exists in practice).
 *
 * SAFETY FLOOR (the entries deliberately NOT in the GNU set): SSPL (network /
 * use-restricted) and CC-BY-SA (content ShareAlike) are NOT inbound-compatible
 * with an AGPL software re-release and are NEVER absorbed. The source-available
 * [[deny]] terminal (06-02) additionally sits ABOVE suppression, so a denied
 * license under a suppressed path fails regardless of this map.
 */
export const WORKSPACE_ABSORBS: ReadonlyMap<
  string,
  ReadonlySet<string>
> = new Map([
  [
    // An AGPL-3.0 (GNU-family) workspace re-releases everything it bundles under
    // AGPL, absorbing the inbound-compatible copyleft families present there.
    "GNU",
    new Set([
      // GNU itself: AGPL/GPL/LGPL deps are enveloped by the AGPL re-release.
      "GNU",
      // MPL: file-level weak copyleft; an MPL file relicensed/bundled into an
      // AGPL work is compatible with (and absorbed by) the stronger AGPL
      // obligation. Present in apps/scratch via Apache/LGPL+MPL transitives.
      "MPL",
    ]),
  ],
]);
