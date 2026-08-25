/**
 * Shipped TOOL-LEVEL disambiguation override set.
 *
 * A curated, committed literal data module of REAL disambiguations for commonly-ambiguous
 * well-known projects. Any repo consuming this tool benefits from these defaults WITHOUT
 * re-authoring them. The set is GENERAL (well-known projects), NOT a per-consumer data dump:
 * project-specific judgments live in the consuming repo's .sbomlet.policy.toml `[[clarify]]` table,
 * which WINS over this set on conflict (project-wins).
 *
 * Each entry is a PRECONDITIONED assertion, never a blind replacement. `detected` records what each
 * producing lane reported for the dependency; at evaluation the engine applies the asserted
 * `expression` ONLY while every recorded lane still reports it (see normalize.ts / evaluate.ts). A
 * divergence is a STALE override that FAILS the gate loudly rather than silently masking a
 * relicense - the staleness guard is the whole point of the shipped set. This is the same mechanism
 * a consumer's own `[[clarify]]` entries run through, not a second one.
 *
 * The data is a literal, reviewable list - never computed at runtime and never read from disk
 * inside the pure engine (it is imported like other config; no eval, no fs). Mirrors the
 * copyleft.ts / trove.ts vendored-static-data idiom: every `expression` is validated against
 * spdx-license-ids in the tests so a typo cannot silently ship.
 *
 * Keying is by package NAME (version optional) per the CONTEXT decision: an override survives
 * version bumps as long as upstream keeps reporting the same ambiguous value. No entry pins a
 * version.
 *
 * DELIBERATE SCOPE: a project-specific copier / jinja2-ansible-filters GPL-3.0 judgment is DEFERRED
 * to the Phase-6 dogfood .sbomlet.policy.toml - it is a project-specific call, not a general
 * well-known disambiguation, so it does NOT belong here.
 */
import { asRawLicense, type CanonicalLicense } from "../../model/dependencies";
import { canonicalizeExpression } from "../../normalize/expression";
import type { DetectedSignal } from "../../normalize/normalize";

/** One shipped tool-level disambiguation override. */
export interface BuiltinOverride {
  /** Package name (matched verbatim; version-agnostic - overrides survive bumps). */
  name: string;
  /** Reserved: an override never pins a version (kept for shape parity with clarify). */
  version?: string;
  /**
   * What each producing lane reported for the package when this override was written. Compared lane
   * by lane against the package's pre-override observed signal; on a divergence the override is
   * STALE and fails the gate.
   */
  detected: DetectedSignal;
  /** The asserted precise, canonical SPDX expression (validated against spdx in tests). */
  expression: CanonicalLicense;
  /** Mandatory documentation: why this disambiguation is correct. */
  reason: string;
}

/**
 * The well-known Jupyter/IPython projects PyPI reports under the imprecise "BSD"/"BSD License"
 * classifier. The stack is uniformly BSD-3-Clause; the override disambiguates the imprecise BSD
 * signal (the impreciseFamily "BSD") to the precise id. Curated to the canonical,
 * broadly-depended-on projects - any repo using Jupyter benefits, and the list stays reviewable.
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
  "imprecise 'BSD'/'BSD License' classifier (the imprecise-BSD signal)";

/**
 * The shipped tool-level override set. The NAMED defaults ship here as REAL working entries (not
 * stubs): python-dateutil's dual license and the Jupyter/IPython BSD stack.
 */
export const BUILTIN_OVERRIDES: ReadonlyArray<BuiltinOverride> = [
  {
    name: "python-dateutil",
    detected: { registry: asRawLicense("Dual License") },
    expression: canonicalizeExpression(asRawLicense("Apache-2.0 OR BSD-3-Clause")),
    reason:
      "python-dateutil is dual-licensed Apache-2.0 OR BSD-3-Clause; PyPI " +
      "reports the imprecise 'Dual License' classifier",
  },
  ...JUPYTER_BSD_PROJECTS.map(
    (name): BuiltinOverride => ({
      name,
      detected: { registry: asRawLicense("BSD") },
      expression: canonicalizeExpression(asRawLicense("BSD-3-Clause")),
      reason: JUPYTER_BSD_REASON,
    }),
  ),
];
