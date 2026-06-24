/**
 * Sole copyleft data module.
 *
 * The data is a literal, reviewable list — never computed from
 * spdx-license-ids at runtime. Verdict-affecting data must not drift when a
 * transitive data package updates, and runtime family/prefix expansion would
 * re-introduce the GPL-substring collision class (LGPLLR, NGPL, SMAIL-GPL,
 * CNRI-Python-GPL-Compatible are all not copyleft) — exact-ID membership on
 * parsed expression leaves is the only matching allowed.
 *
 * Deprecated SPDX forms (GPL-2.0, AGPL-3.0, the -with-exception compounds) are
 * included because spdx-expression-parse accepts them; a `plus` leaf (GPL-2.0+)
 * is covered via its base id. Exception forms stay copyleft: an exception
 * narrows obligations but the base license remains copyleft — `[[compatible]]`
 * is the policy escape hatch.
 *
 * Membership bar: weak copyleft counts (MPL/EPL/CDDL set the bar), so every
 * reciprocal/ShareAlike license meeting it is listed: the CC-BY-SA family
 * (incl. jurisdiction ports), Sleepycat, CPAL-1.0, MS-RL, RPL, QPL-1.0, APSL,
 * and the full GFDL family. Every id is validated against spdx-license-ids in
 * the tests, so a typo here cannot silently create a default:ok gap.
 * Deliberate exclusions stay documented above (LGPLLR, NGPL, SMAIL-GPL,
 * CNRI-Python-GPL-Compatible are GPL-substring collisions, not copyleft).
 *
 * Family grouping: every id carries a family token so workspace suppression
 * can verify that a finding's copyleft obligations are compatible with the
 * workspace's own declared license. The GNU family deliberately spans
 * AGPL/GPL/LGPL (an AGPL-distributed workspace's obligations envelope its
 * GPL/LGPL dependencies); every other family is its own island — an AGPL
 * workspace never auto-suppresses SSPL or CC-BY-SA findings. Grouping is
 * deliberately coarse: `[[compatible]]` is the precise per-license/per-package
 * escape hatch.
 */

/** Literal (family → member ids) groups; the single reviewable source. */
const FAMILY_MEMBERS: ReadonlyArray<
  readonly [family: string, ids: ReadonlyArray<string>]
> = [
  [
    "GNU",
    [
      // AGPL-*
      "AGPL-1.0",
      "AGPL-1.0-only",
      "AGPL-1.0-or-later",
      "AGPL-3.0",
      "AGPL-3.0-only",
      "AGPL-3.0-or-later",
      // GPL-* (incl. deprecated -with-exception forms; exception does NOT clear copyleft)
      "GPL-1.0",
      "GPL-1.0-only",
      "GPL-1.0-or-later",
      "GPL-2.0",
      "GPL-2.0-only",
      "GPL-2.0-or-later",
      "GPL-2.0-with-GCC-exception",
      "GPL-2.0-with-autoconf-exception",
      "GPL-2.0-with-bison-exception",
      "GPL-2.0-with-classpath-exception",
      "GPL-2.0-with-font-exception",
      "GPL-3.0",
      "GPL-3.0-only",
      "GPL-3.0-or-later",
      "GPL-3.0-with-GCC-exception",
      "GPL-3.0-with-autoconf-exception",
      // LGPL-*
      "LGPL-2.0",
      "LGPL-2.0-only",
      "LGPL-2.0-or-later",
      "LGPL-2.1",
      "LGPL-2.1-only",
      "LGPL-2.1-or-later",
      "LGPL-3.0",
      "LGPL-3.0-only",
      "LGPL-3.0-or-later",
    ],
  ],
  ["MPL", ["MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception"]],
  ["EPL", ["EPL-1.0", "EPL-2.0"]],
  ["CDDL", ["CDDL-1.0", "CDDL-1.1"]],
  ["EUPL", ["EUPL-1.0", "EUPL-1.1", "EUPL-1.2"]],
  ["OSL", ["OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1", "OSL-3.0"]],
  [
    "CECILL",
    [
      "CECILL-1.0",
      "CECILL-1.1",
      "CECILL-2.0",
      "CECILL-2.1",
      "CECILL-B",
      "CECILL-C",
    ],
  ],
  ["SSPL", ["SSPL-1.0"]],
  [
    // CC ShareAlike family (ShareAlike = copyleft for adaptations), incl. the
    // jurisdiction ports — CC-BY-* (no SA) is NOT copyleft and stays out.
    "CC-BY-SA",
    [
      "CC-BY-SA-1.0",
      "CC-BY-SA-2.0",
      "CC-BY-SA-2.1-JP",
      "CC-BY-SA-2.5",
      "CC-BY-SA-3.0",
      "CC-BY-SA-3.0-AT",
      "CC-BY-SA-3.0-DE",
      "CC-BY-SA-3.0-IGO",
      "CC-BY-SA-4.0",
    ],
  ],
  // Other reciprocal licenses meeting the same bar as MPL/EPL/CDDL
  ["Sleepycat", ["Sleepycat"]],
  ["CPAL", ["CPAL-1.0"]],
  ["MS-RL", ["MS-RL"]],
  ["RPL", ["RPL-1.1", "RPL-1.5"]],
  ["QPL", ["QPL-1.0"]],
  ["APSL", ["APSL-1.0", "APSL-1.1", "APSL-1.2", "APSL-2.0"]],
  [
    // Documentation copyleft: full GFDL family (deprecated bases included,
    // mirroring the GPL convention above)
    "GFDL",
    [
      "GFDL-1.1",
      "GFDL-1.1-only",
      "GFDL-1.1-or-later",
      "GFDL-1.1-invariants-only",
      "GFDL-1.1-invariants-or-later",
      "GFDL-1.1-no-invariants-only",
      "GFDL-1.1-no-invariants-or-later",
      "GFDL-1.2",
      "GFDL-1.2-only",
      "GFDL-1.2-or-later",
      "GFDL-1.2-invariants-only",
      "GFDL-1.2-invariants-or-later",
      "GFDL-1.2-no-invariants-only",
      "GFDL-1.2-no-invariants-or-later",
      "GFDL-1.3",
      "GFDL-1.3-only",
      "GFDL-1.3-or-later",
      "GFDL-1.3-invariants-only",
      "GFDL-1.3-invariants-or-later",
      "GFDL-1.3-no-invariants-only",
      "GFDL-1.3-no-invariants-or-later",
    ],
  ],
];

/**
 * Exact-ID → family token. Derived from the literal groups above — one source,
 * no drift between membership and family data.
 */
export const COPYLEFT_FAMILY: ReadonlyMap<string, string> = new Map(
  FAMILY_MEMBERS.flatMap(([family, ids]) =>
    ids.map((id) => [id, family] as const),
  ),
);

/** Exact-ID copyleft membership — the keys of the family map. */
export const COPYLEFT_IDS: ReadonlySet<string> = new Set(
  COPYLEFT_FAMILY.keys(),
);
