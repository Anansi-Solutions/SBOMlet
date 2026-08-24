import { expect } from "bun:test";
import { annotateFindings, type BuiltinOverrideInput } from "../src/normalize/normalize";
import { evaluate } from "../src/policy/engine/evaluate";
import {
  parseClarifications,
  withImportedClarifications,
} from "../src/policy/parse/clarificationsFile";
import { parsePolicy } from "../src/policy/parse/parse";
import { PolicyError } from "../src/policy/schema/diagnostics";
import type { Policy } from "../src/policy/schema";
import type {
  CanonicalDependencies,
  LicenseClaimKind,
  RawLicense,
  Verdict,
} from "../src/model/dependencies";

/** No scanned target in these scenarios is collected by a lane that derives a dependency graph. */
export const WITHOUT_DEPENDENCY_GRAPHS: ReadonlySet<string> = new Set();

// Inline TOML fixtures (dispatch.test.ts idiom) — each one is commented with
// the trap it encodes. Policy text is untrusted config: schema validation
// must reject loudly with table-path errors, never skip.

export function expectPolicyError(text: string): PolicyError {
  let thrown: unknown;

  try {
    parsePolicy(text);
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(PolicyError);
  return thrown as PolicyError;
}

/** Minimal policy with a single compatible license rule for `pattern`. */
export const licenseRuleFixture = (pattern: string): string =>
  [
    "[[compatible]]",
    'match = "license"',
    `pattern = ${JSON.stringify(pattern)}`,
    'rationale = "license-reviewed"',
    'where = ["/"]',
  ].join("\n");

/** Minimal policy with a single suppression entry for `path`. */
export const suppressionFixture = (path: string): string =>
  [
    "[[workspace.copyleft_suppressed]]",
    `path = ${JSON.stringify(path)}`,
    'license = "AGPL-3.0-only"',
    'description = "test description"',
  ].join("\n");

export const SUPPRESSION_DESCRIPTION =
  "Workspace is itself distributed under AGPL-3.0; in-family copyleft is fine.";

export const MPL_COMMENT = "Weak copyleft; compatible under AGPL-3.0 and Apache License v2.0";

export const SHARP_COMMENT =
  "Dual-licensed Apache-2.0 AND LGPL-3.0-or-later; LGPL obligations accepted.";

export const CLARIFY_COMMENT = "Upstream declares Public Domain; mapped to Unlicense deliberately.";

// Happy path: every table class present, exercising the full locked TOML
// surface.
export const VALID_POLICY = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  `description = ${JSON.stringify(SUPPRESSION_DESCRIPTION)}`,
  "",
  "[[compatible]]",
  'match = "license"',
  'pattern = "MPL-2.0"',
  'rationale = "license-reviewed"',
  'where = ["/"]',
  `comment = ${JSON.stringify(MPL_COMMENT)}`,
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "@img/sharp-win32-x64"',
  'version = "0.34.5"',
  'as-dependency-of = ["self"]',
  'rationale = "license-reviewed"',
  'where = ["/"]',
  `comment = ${JSON.stringify(SHARP_COMMENT)}`,
  "",
  "[[clarify]]",
  'name = "jsonify"',
  'version = "0.0.1"',
  'detected = { registry = "Public Domain", intensive = false }',
  'justification = "license-not-found"',
  'expression = "Unlicense"',
  `comment = ${JSON.stringify(CLARIFY_COMMENT)}`,
  "",
  "[unknown]",
  'handling = "fail"',
].join("\n");

// ===========================================================================
// The REQUIRED `where` scope on BOTH [[compatible]] forms — an array of
// occurrence-identity prefixes, each validated like a suppression path, or the
// reserved everywhere token. Empty arrays reject (a rule that can never match
// anywhere is a dead rule by construction).
// ===========================================================================

export const DOCKER_ID = "docker:examples/docker-scan/Dockerfile";

/** License-form compatible rule with a raw TOML `where` clause. */
export const scopedLicenseFixture = (whereToml: string): string =>
  [
    "[[compatible]]",
    'match = "license"',
    'pattern = "MPL-2.0"',
    'rationale = "license-reviewed"',
    `where = ${whereToml}`,
  ].join("\n");

/** Package-form compatible rule with a raw TOML `where` clause. */
export const scopedPackageFixture = (whereToml: string): string =>
  [
    "[[compatible]]",
    'match = "package"',
    'name = "busybox"',
    'version = "1.37.0"',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    `where = ${whereToml}`,
  ].join("\n");

// ===========================================================================
// The [[compatible]] schema: the package selector, the required
// `as-dependency-of` list, the closed rationale set, and the pointed errors an
// entry written against the previous schema gets.
// ===========================================================================

/** A package-form [[compatible]] entry built from the given key lines. */
export const compatiblePackageFixture = (lines: ReadonlyArray<string>): string =>
  ["[[compatible]]", 'match = "package"', ...lines].join("\n");

/** A minimal valid package-form entry. */
export const DEMO_COMPATIBLE = [
  'name = "demo-pkg"',
  'version = "1.0.0"',
  'as-dependency-of = ["self"]',
  'rationale = "build-time-only"',
  'where = ["/"]',
];

/** DEMO_COMPATIBLE without the line starting with `key`. */
export const compatibleWithout = (key: string): string[] =>
  DEMO_COMPATIBLE.filter((line) => !line.startsWith(`${key} =`));

// ===========================================================================
// The [[clarify]] schema: the package selector, the mandatory `detected`
// precondition, the closed justification set, evidence, and the pointed
// errors an entry written against the previous schema gets.
// ===========================================================================

/** A [[clarify]] entry built from the given key lines. */
export const clarifyFixture = (lines: ReadonlyArray<string>): string =>
  ["[[clarify]]", ...lines].join("\n");

/** A minimal valid entry: name, version, one recorded lane, justification, expression. */
export const DEMO_CLARIFY = [
  'name = "demo-pkg"',
  'version = "1.0.0"',
  'detected = { registry = "BSD" }',
  'justification = "scan-more-precise"',
  'expression = "BSD-3-Clause"',
];

/** DEMO_CLARIFY without the line starting with `key`, for missing-key cases. */
export const clarifyWithout = (key: string): string[] =>
  DEMO_CLARIFY.filter((line) => !line.startsWith(`${key} `) && !line.startsWith(`${key} =`));

// ===========================================================================
// Policy engine: evaluate() + unusedRuleIds(). All inputs are hand-built
// CanonicalDependencies literals run through annotateFindings — evaluate is
// pure over the model, no SBOM JSON anywhere.
// ===========================================================================

/** Occurrence spec: a bare string is a prod occurrence in that target. */
export type OccurrenceSpec = string | { target: string; dev: boolean };

export interface PackageSpec {
  purl: string;
  name: string;
  version: string;
  /** Raw license claim strings; [] = the zero-claim (unknown) population. */
  claims: ReadonlyArray<string>;
  occurrences: ReadonlyArray<OccurrenceSpec>;
  /** Package-level taxonomy; defaults to "app" ("os" routes applyOsScope). */
  scope?: "app" | "os";
  /**
   * A ScanCode-sourced claim raw: appended as a { source: "scancode" }
   * claim so annotateFindings runs applyScancodeAssessment and can attach a
   * conflict marker. Absent = the common quick-check-only case.
   */
  scancode?: string;
  /**
   * A merge-time cross-image claim divergence (mergeSboms' dockerClaimDivergence carrier) —
   * threaded straight onto the built PackageEntry so annotateFindings overlays it exactly as the
   * live pipeline does. Absent = the common no-docker-divergence case.
   */
  dockerClaimDivergence?: {
    target: string;
    claims: readonly string[];
  }[];
}

/**
 * Hand-built CanonicalDependencies literal (merge.test.ts idiom). The claim `kind`
 * is inert in normalization — only `raw` flows through normalizeRaw — so a
 * cosmetic heuristic is enough here.
 */
export function makeModel(specs: ReadonlyArray<PackageSpec>): CanonicalDependencies {
  return {
    packages: specs.map((spec) => ({
      purl: spec.purl,
      name: spec.name,
      version: spec.version,
      occurrences: spec.occurrences.map((o) =>
        typeof o === "string"
          ? { target: o, isDevDependency: false }
          : { target: o.target, isDevDependency: o.dev },
      ),
      licenseClaims: [
        ...spec.claims.map((raw) => {
          const kind: LicenseClaimKind =
            raw.includes(" ") || raw.includes("(") ? "expression" : "spdx-id";

          return { raw: raw as RawLicense, kind, source: "generator" as const };
        }),
        ...(spec.scancode !== undefined
          ? [
              {
                raw: spec.scancode as RawLicense,
                kind: "expression" as const,
                source: "scancode" as const,
              },
            ]
          : []),
      ],
      scope: spec.scope ?? "app",
      ...(spec.dockerClaimDivergence !== undefined
        ? {
            dockerClaimDivergence: {
              kind: "cross-image-claims" as const,
              byTarget: spec.dockerClaimDivergence,
            },
          }
        : {}),
    })),
  };
}

/** Shorthand for an OS-scope package (pkg:deb/pkg:apk). */
export function osPkgSpec(
  purl: string,
  name: string,
  claim: string | null,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
    scope: "os",
  };
}

/** Shorthand for the common one-package case. */
export function pkgSpec(
  name: string,
  claim: string | null,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
  };
}

/**
 * Shorthand for a package carrying a quick-check claim PLUS a scancode claim —
 * the assessment/conflict trigger. `claim === null` means the scancode
 * claim is the only license evidence (the vacuous-agreement case).
 */
export function scanPkgSpec(
  name: string,
  claim: string | null,
  scancode: string,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims: claim === null ? [] : [claim],
    occurrences,
    scancode,
  };
}

/** parse policy → annotateFindings (clarify + optional builtins) → evaluate. */
export function runEngineWith(
  policy: Policy,
  specs: ReadonlyArray<PackageSpec>,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): {
  verdicts: Verdict[];
  usedClarifyIndices: ReadonlySet<number>;
  policy: Policy;
  model: CanonicalDependencies;
} {
  const { model, usedClarifyIndices } = annotateFindings(
    makeModel(specs),
    policy.clarify,
    builtins,
  );

  return {
    verdicts: evaluate(model, policy, WITHOUT_DEPENDENCY_GRAPHS),
    usedClarifyIndices,
    policy,
    model,
  };
}

export function runEngine(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
  builtins: ReadonlyArray<BuiltinOverrideInput> = [],
): ReturnType<typeof runEngineWith> {
  return runEngineWith(parsePolicy(policyText), specs, builtins);
}

/** {@link runEngine} over both files, combined exactly as the pipeline combines them. */
export function runEngineWithImports(
  specs: ReadonlyArray<PackageSpec>,
  policyText: string,
  clarificationsText: string,
): ReturnType<typeof runEngineWith> {
  return runEngineWith(
    withImportedClarifications(parsePolicy(policyText), parseClarifications(clarificationsText)),
    specs,
  );
}

/** Suppression-only fixture policy: apps/scratch absorbs copyleft. */
export const SUPPRESS_SCRATCH = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  'description = "scratch workspace is itself distributed under AGPL-3.0"',
].join("\n");

// ===========================================================================
// The conflict:cross-image-claims fail verdict. Two or more docker
// occurrences of the SAME purl declaring different licenses (marker set at
// merge time, threaded via PackageSpec.dockerClaimDivergence) share the
// conflict:scancode lane (verdictFor) — a fail, not a warn, for the same
// reason: human involvement is necessary. Exit 1 is automatic, no new
// machinery in exitCodeFor.
// ===========================================================================

/** Shorthand for a docker-vs-docker cross-image claim divergence spec. */
export function crossImagePkgSpec(
  name: string,
  byTarget: ReadonlyArray<{ target: string; claims: readonly string[] }>,
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:apk/alpine/${name}@${version}`,
    name,
    version,
    claims: [],
    occurrences: byTarget.map((t) => t.target),
    scope: "os",
    dockerClaimDivergence: [...byTarget],
  };
}

// ===========================================================================
// Per-occurrence compatible matching. A `where`-scoped rule
// decides at each occurrence via the SAME segment-aware prefix comparison
// suppression paths use; an unscoped rule keeps pre-scoping behavior
// byte-identically. Targets here are synthetic — per-image docker identities
// do not exist yet; the engine must not care.
// ===========================================================================

export const TARGET_A = "docker:a/Dockerfile";

export const TARGET_B = "docker:b/Dockerfile";

export const TARGET_A_EXTRA = "docker:a/Dockerfile-extra";

export const TARGET_A_PREFIX = "docker:a";

/** Package-form busybox acceptance scoped to the given identity prefixes. */
export const scopedBusyboxPolicy = (where: ReadonlyArray<string>): string =>
  [
    "[[compatible]]",
    'match = "package"',
    'name = "busybox"',
    'version = "1.37.0"',
    'as-dependency-of = ["self"]',
    'rationale = "license-reviewed"',
    `where = ${JSON.stringify(where)}`,
  ].join("\n");

/** License-form GPL acceptance scoped to the given identity prefixes. */
export const scopedGplPolicy = (where: ReadonlyArray<string>): string =>
  [
    "[[compatible]]",
    'match = "license"',
    'pattern = "GPL-2.0-only"',
    'rationale = "license-reviewed"',
    `where = ${JSON.stringify(where)}`,
  ].join("\n");

/** An os-scope GPL busybox occurring at the given targets. */
export const busyboxAt = (targets: ReadonlyArray<string>): PackageSpec =>
  osPkgSpec("pkg:apk/alpine/busybox@1.37.0", "busybox", "GPL-2.0-only", targets, "1.37.0");

// ===========================================================================
// AGPL acceptance corpus — every fixture mirrors a real row of the live
// discovery run (3616 packages). These are real purls, names, versions,
// expressions, and occurrence shapes — not inventions — so future updates can
// re-verify them against the live model.
// ===========================================================================

/**
 * The fixture policy from the plan: apps/scratch suppressed as AGPL-3.0-only,
 * NO LGPL compatible rule, unknown = warn.
 */
export const ACCEPTANCE_POLICY = [
  "[[workspace.copyleft_suppressed]]",
  'path = "apps/scratch"',
  'license = "AGPL-3.0-only"',
  'description = "apps/scratch ships the AGPL-3.0 scratch-editor derivative; copyleft distribution is the workspace model."',
  "",
  "[unknown]",
  'handling = "warn"',
].join("\n");

// ===========================================================================
// Dev/prod gate downgrade — the `dev_dependencies` knob + the
// per-occurrence dev-scope downgrade at the would-be default-FAIL terminals.
// ===========================================================================

/** A copyleft package with one DEV occurrence (A) and one PROD occurrence (B). */
export const DEV_PROD_COPYLEFT = pkgSpec("agpl-pkg", "AGPL-3.0-only", [
  { target: "apps/a", dev: true },
  { target: "apps/b", dev: false },
]);

/** An UNKNOWN-license package with one DEV occurrence (A) and one PROD (B). */
export const DEV_PROD_UNKNOWN = pkgSpec("no-claims", null, [
  { target: "apps/a", dev: true },
  { target: "apps/b", dev: false },
]);

// ===========================================================================
// Terminal deny-list (highest precedence). denyRuleFor is the pure
// matcher (Task 1); the verdictFor terminal-0 wiring + the "deny beats X"
// precedence proofs live in the dedicated describe blocks (Task 2).
// ===========================================================================

/** A minimal [[deny]] license-mode policy for `pattern`. */
export const denyLicenseFixture = (pattern: string): string =>
  [
    "[[deny]]",
    'match = "license"',
    `pattern = ${JSON.stringify(pattern)}`,
    'reason = "source-available; cannot ship"',
  ].join("\n");

/** A minimal [[deny]] name-mode policy for `pattern`. */
export const denyNameFixture = (pattern: string): string =>
  [
    "[[deny]]",
    'match = "name"',
    `pattern = ${JSON.stringify(pattern)}`,
    'reason = "use-restriction rider; cannot ship"',
  ].join("\n");

// ===========================================================================
// FINDINGS #1 + #5 + #11 (same root cause): deny must see EVERY observed
// per-claim license, not just the lossy COMBINED finding expression.
//
// combineKnown (normalize.ts) elects an imprecise family BEFORE the precise
// members when hasPreciseCopyleft is false, SILENTLY DROPPING a precise
// non-copyleft DENIED member (BUSL-1.1, Elastic-2.0 — source-available,
// NOT in COPYLEFT_IDS) when an imprecise family token ("GPL") co-exists:
//   [BUSL-1.1, GPL] → combine elects family "GPL" → expression null →
//   deny terminal (which reads the COMBINED expression) never sees BUSL-1.1
//   → bypassed (warn, not fail).
// Same gap via the all-or-nothing UNKNOWN collapse in gating (app) scope
// (#11): [BUSL-1.1, <custom>] → unknown → deny can't match a null expression.
//
// FIX: the deny terminal evaluates against the SET of all observed per-claim
// normalized precise licenses (finding.observedExpressions), not just the
// single combined assessment.expression — so a denied member is seen
// regardless of whether the combine renders precise/imprecise/unknown.
// ===========================================================================

/** A multi-claim spec (pkgSpec only takes one claim). */
export function multiClaimSpec(
  name: string,
  claims: ReadonlyArray<string>,
  occurrences: ReadonlyArray<OccurrenceSpec>,
  scope: "app" | "os" = "app",
  version = "1.0.0",
): PackageSpec {
  return {
    purl: `pkg:npm/${name}@${version}`,
    name,
    version,
    claims,
    occurrences,
    scope,
  };
}

// ===========================================================================
// The `[os_dependencies]` knob + the package-level os-scope downgrade
// at the would-be default-FAIL terminals. Mirrors the dev_dependencies
// suite EXACTLY, but routes on entry.scope === "os" (package-level), not the
// occurrence-level dev marker. Deny stays terminal-0 above the os downgrade.
// ===========================================================================

/** An OS-scope copyleft package (a pkg:deb glibc-style LGPL row). */
export const OS_COPYLEFT = osPkgSpec("pkg:deb/debian/libc6@2.36-9", "libc6", "LGPL-2.1-or-later", [
  "docker:img/Dockerfile",
]);

/** An OS-scope UNKNOWN-license package (zero claims). */
export const OS_UNKNOWN = osPkgSpec("pkg:apk/alpine/mystery@1.0.0", "mystery", null, [
  "docker:img/Dockerfile",
]);

// ===========================================================================
// The os-scope PARTIAL finding evaluates on its KNOWN-member expression.
// A known copyleft member → applyOsScope → warn (non-gating); a known denied
// member STAYS terminal (deny is checked before applyOsScope). The
// unrecognizedTokens themselves never gate (os non-gating). No change to
// app-scope verdicts (the all-or-nothing → unknown invariant holds there).
// ===========================================================================

/** A multi-claim os-scope spec (the partial-finding shape). */
export const osMultiSpec = (
  name: string,
  claims: ReadonlyArray<string>,
  occurrences: ReadonlyArray<OccurrenceSpec> = ["docker:img/Dockerfile"],
): PackageSpec => ({
  purl: `pkg:deb/debian/${name}@1.0.0`,
  name,
  version: "1.0.0",
  claims,
  occurrences,
  scope: "os",
});

// ---------------------------------------------------------------------------
// [[docker.development]] — per-container development marking (glob source).
// ---------------------------------------------------------------------------

/** Minimal [docker] table with one [[docker.development]] entry. */
export const developmentFixture = (source: string, reason = "test reason"): string =>
  [
    "[docker]",
    "",
    "[[docker.development]]",
    `source = ${JSON.stringify(source)}`,
    `reason = ${JSON.stringify(reason)}`,
  ].join("\n");
