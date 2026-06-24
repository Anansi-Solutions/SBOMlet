/**
 * Shipped TOOL-LEVEL disambiguation override set (POL-07).
 *
 * A curated, committed literal data module of REAL disambiguations for
 * commonly-ambiguous well-known projects. Any repo consuming this tool benefits
 * from these defaults WITHOUT re-authoring them — that is POL-07's acceptance
 * criterion. The set is GENERAL (well-known projects), NOT a per-consumer data
 * dump: project-specific judgments live in the consuming repo's policy.toml
 * `[[clarify]]` table, which WINS over this set on conflict (project-wins).
 *
 * Each entry is a PRECONDITIONED assertion, never a blind replacement. `expects`
 * records the dependency license value the override disambiguates FROM; at
 * evaluation the engine applies the asserted `expression` ONLY when the
 * dependency's pre-override observed signal still matches `expects` (see
 * normalize.ts / evaluate.ts). A MISMATCH is a STALE override that FAILS the
 * gate loudly rather than silently masking a relicense — the staleness guard is
 * the whole point of POL-07.
 *
 * The data is a literal, reviewable list — never computed at runtime and never
 * read from disk inside the pure engine (it is imported like other config; no
 * eval, no fs). Mirrors the copyleft.ts / trove.ts vendored-static-data idiom:
 * every `expression` is validated against spdx-license-ids in the tests so a
 * typo cannot silently ship.
 *
 * Keying is by package NAME (version optional) per the CONTEXT decision: an
 * override survives version bumps as long as upstream keeps reporting the same
 * ambiguous value. No entry pins a version.
 *
 * DELIBERATE SCOPE: a project-specific copier / jinja2-ansible-filters
 * GPL-3.0 judgment is DEFERRED to the Phase-6 dogfood policy.toml — it is a
 * project-specific call, not a general well-known disambiguation, so it does
 * NOT belong here.
 */

/** One shipped tool-level disambiguation override. */
export interface BuiltinOverride {
  /** Package name (matched verbatim; version-agnostic — overrides survive bumps). */
  name: string;
  /** Reserved: an override never pins a version (kept for shape parity with clarify). */
  version?: string;
  /**
   * The pre-override observed value this override disambiguates FROM. Matched
   * (case-insensitive, trimmed) against the package's pre-override observed
   * signal (normalized raw claim strings ∪ the 05-05 impreciseFamily token); on
   * mismatch the override is STALE and fails the gate.
   */
  expects: string;
  /** The asserted precise SPDX expression (validated against spdx in tests). */
  expression: string;
  /** Mandatory documentation: why this disambiguation is correct. */
  reason: string;
}

/**
 * The well-known Jupyter/IPython projects PyPI reports under the imprecise
 * "BSD"/"BSD License" classifier. The stack is uniformly BSD-3-Clause; the
 * override disambiguates the imprecise BSD signal (05-05's impreciseFamily
 * "BSD") to the precise id. Curated to the canonical, broadly-depended-on
 * projects — any repo using Jupyter benefits, and the list stays reviewable.
 */
const JUPYTER_BSD_PROJECTS: ReadonlyArray<string> = [
  "ipython",
  "ipykernel",
  "jupyter-core",
  "jupyter-client",
  "jupyter-server",
  "nbformat",
  "nbconvert",
  "nbclient",
  "traitlets",
  "jupyterlab-pygments",
  "comm",
  "ipywidgets",
  "widgetsnbextension",
  "jupyterlab-widgets",
];

const JUPYTER_BSD_REASON =
  "the Jupyter/IPython stack is uniformly BSD-3-Clause; PyPI reports the " +
  "imprecise 'BSD'/'BSD License' classifier (05-05 imprecise-BSD signal)";

/**
 * The shipped tool-level override set. POL-07's NAMED defaults ship here as REAL
 * working entries (not stubs): python-dateutil's dual license and the
 * Jupyter/IPython BSD stack.
 */
export const BUILTIN_OVERRIDES: ReadonlyArray<BuiltinOverride> = [
  {
    name: "python-dateutil",
    expects: "Dual License",
    expression: "Apache-2.0 OR BSD-3-Clause",
    reason:
      "python-dateutil is dual-licensed Apache-2.0 OR BSD-3-Clause; PyPI " +
      "reports the imprecise 'Dual License' classifier",
  },
  ...JUPYTER_BSD_PROJECTS.map(
    (name): BuiltinOverride => ({
      name,
      expects: "BSD",
      expression: "BSD-3-Clause",
      reason: JUPYTER_BSD_REASON,
    }),
  ),
];
