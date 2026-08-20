/**
 * Mirrors dependency-classification.md's and report-placement.md's Path
 * index tables 1:1: one test per slug, asserting classification then placement.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  DOCKER_IDENTITY_PREFIX,
  type CanonicalDependencies,
  type Verdict,
} from "../src/model/dependencies";
import { npmIntroductions } from "../src/collectors/npmProvenance";
import { withCacheClaim } from "../src/enrich/enrich";
import { targetsWithDependencyGraph } from "../src/merge/dependencyGraphs";
import { mergeSboms } from "../src/merge/merge";
import { annotateFindings } from "../src/normalize/normalize";
import { applyContainerScopes } from "../src/pipeline/containerScope";
import { BUILTIN_OVERRIDES } from "../src/policy/builtinOverrides";
import { acceptedContainerNotices, evaluate } from "../src/policy/evaluate";
import { parsePolicy, type Policy } from "../src/policy/schema";
import { suppressionOverlapNotices } from "../src/policy/target";
import { alignTables } from "../src/render/alignTables";
import { renderMarkdown, type PolicyView } from "../src/render/markdown";
import { renderNotices } from "../src/render/notices";
import { globToRegExp } from "../src/targets/discover";

const DEPENDENCY_CLASSIFICATION_DOC = join(
  import.meta.dir,
  "..",
  "docs",
  "reference",
  "dependency-classification.md",
);

const REPORT_PLACEMENT_DOC = join(
  import.meta.dir,
  "..",
  "docs",
  "reference",
  "report-placement.md",
);

/** Every path documented in both Path index tables, verified below one test each. */
const PLACEMENT_PATHS = [
  "workspace-prod-permissive",
  "workspace-dev-only",
  "shared-workspace-and-container",
  "container-only-system",
  "container-only-app-ecosystem",
  "unrecognized-ecosystem-gates",
  "system-copyleft-os-warn",
  "system-copyleft-os-fail",
  "system-copyleft-os-ignore",
  "system-agpl-escalates",
  "system-agpl-accepted-notice",
  "system-agpl-imprecise-escalates",
  "system-agpl-imprecise-accepted",
  "mixed-agpl-fail-and-accept",
  "app-copyleft-prod-container",
  "app-copyleft-dev-container",
  "app-copyleft-workspace-dev",
  "problematic-dedup-keeps-inventory",
  "imprecise-copyleft-family-only-imprecise",
  "imprecise-permissive-family",
  "unknown-license-counted",
  "licenseref-only-unknown",
  "suppressed-workspace-copyleft",
  "denied-license-terminal",
  "system-package-in-dev-container-counts-dev",
  "conflict-scancode",
  "detected-mismatch",
  "cross-image-claim-divergence",
  "target-ok-permissive",
  "target-incompatible-prod",
  "target-incompatible-dev-downgrade",
  "target-apache-gpl2-incompatible",
  "target-or-election-flip",
  "target-proprietary-boundary-external",
  "target-unknown-pair-residual",
  "target-internal-holds-gpl",
  "target-internal-network-agpl-fails",
  "target-network-agpl-absorbed",
  "target-network-false-agpl-internal-held",
  "target-internal-nondistribution-conflict-stays",
  "target-workspace-divergence",
  "target-container-app-ecosystem",
  "target-os-agpl-network-true-escalates",
  "target-os-agpl-network-false-routine",
  "target-os-scope-untouched",
  "target-supersedes-suppression",
  "target-os-agpl-network-false-ignored-notice",
  "target-held-survives-purl-fail",
  "voided-compatible",
  "invalid-justification",
] as const;

type PlacementPath = (typeof PLACEMENT_PATHS)[number];

/** The closing sentence every classification failure message shares. */
const CLASSIFICATION_RESOLUTION =
  "If the code broke the documented classification, fix the code; if the classification changed intentionally, update the doc and this suite in the same commit.";

/** The closing sentence every placement/structural failure message shares. */
const PLACEMENT_RESOLUTION =
  "If the code broke the documented placement, fix the code; if the placement changed intentionally, update the doc and this suite in the same commit.";

function classificationDivergence(slug: string, expectation: string): string {
  return `classification path "${slug}" diverged from docs/reference/dependency-classification.md — ${expectation}. ${CLASSIFICATION_RESOLUTION}`;
}

function placementDivergence(slug: string, expectation: string): string {
  return `placement path "${slug}" diverged from docs/reference/report-placement.md — ${expectation}. ${PLACEMENT_RESOLUTION}`;
}

/** Throws a classificationDivergence message naming `slug` when `condition` is false. */
function assertClassification(condition: boolean, slug: string, expectation: string): void {
  if (!condition) {
    throw new Error(classificationDivergence(slug, expectation));
  }
}

/** Throws a placementDivergence message naming `slug` when `condition` is false. */
function assertPlacement(condition: boolean, slug: string, expectation: string): void {
  if (!condition) {
    throw new Error(placementDivergence(slug, expectation));
  }
}

/** Structural (cross-page) drift: names which two id sets disagree, and how. */
function assertStructural(condition: boolean, subject: string, expectation: string): void {
  if (!condition) {
    throw new Error(
      `structural drift: ${subject} — ${expectation}. If the code broke the documented classification or placement, fix the code; if the split changed intentionally, update the affected doc(s) and this suite in the same commit.`,
    );
  }
}

function readDependencyClassificationDoc(): string {
  return readFileSync(DEPENDENCY_CLASSIFICATION_DOC, "utf-8");
}

function readReportPlacementDoc(): string {
  return readFileSync(REPORT_PLACEMENT_DOC, "utf-8");
}

/** The `id` column of a doc's "## Path index" table, in row order. */
function parseDocPathIndexIds(doc: string, docLabel: string): Set<string> {
  const heading = "## Path index (verified end to end)";
  const start = doc.indexOf(heading);

  if (start === -1) {
    throw new Error(`${docLabel} is missing its "${heading}" section`);
  }

  const ids = new Set<string>();

  for (const row of doc.slice(start).split(/\r?\n/)) {
    const match = /^\|\s*`([a-z0-9-]+)`\s*\|/.exec(row);

    if (match?.[1] !== undefined) {
      ids.add(match[1]);
    }
  }

  return ids;
}

/** Every id in `a` missing from `b`, or vice versa, reported together as one failure. */
function assertSlugSetsMatch(
  a: ReadonlySet<string>,
  aLabel: string,
  b: ReadonlySet<string>,
  bLabel: string,
): void {
  const aOnly = [...a].filter((id) => !b.has(id));
  const bOnly = [...b].filter((id) => !a.has(id));
  const subject = `${aLabel} vs ${bLabel}`;

  assertStructural(
    aOnly.length === 0,
    subject,
    `every ${aLabel} id must appear in ${bLabel}; ${aLabel}-only ids: [${aOnly.join(", ")}]`,
  );
  assertStructural(
    bOnly.length === 0,
    subject,
    `every ${bLabel} id must appear in ${aLabel}; ${bLabel}-only ids: [${bOnly.join(", ")}]`,
  );
}

// ===========================================================================
// A small local harness driving the real engine in pipeline order — merge,
// normalize, the container re-scope transform, evaluate, render — the same
// functions and sequence src/pipeline/pipeline.ts#buildOutputs wires, minus
// the network-facing enrichment stages this synthetic, fully-specified input
// never needs (mirrors test/containerReport.test.ts's scenario builder).
// ===========================================================================

interface ComponentSpec {
  name: string;
  purl: string;
  version?: string;
  /** An exact or compound SPDX expression, set on `license.id`. */
  license?: string;
  /** A free-text label, set on `license.name` (imprecise/ambiguous inputs). */
  licenseName?: string;
  /** The in-depth scan's answer, appended as a ScanCode claim after the merge. */
  intensive?: string;
  dev?: boolean;
}

function sbomComponent(spec: ComponentSpec): Record<string, unknown> {
  const licenses =
    spec.license !== undefined
      ? [{ license: { id: spec.license } }]
      : spec.licenseName !== undefined
        ? [{ license: { name: spec.licenseName } }]
        : undefined;

  return {
    type: "library",
    name: spec.name,
    version: spec.version ?? "1.0.0",
    purl: spec.purl,
    "bom-ref": spec.purl,
    ...(licenses !== undefined ? { licenses } : {}),
    ...(spec.dev === true
      ? { properties: [{ name: "cdx:npm:package:development", value: "true" }] }
      : {}),
  };
}

/** The synthetic project a graphed input's dependency edges hang off. */
const ROOT_REF = "project@workspace:.";
const ROOT_PURL = "pkg:npm/project@0.0.0";

/** The key standing for the project itself in a scenario's dependency edges. */
const ROOT_EDGE = ".";

function sbomDoc(
  components: ReadonlyArray<Record<string, unknown>>,
  edges?: DependencyEdges,
): unknown {
  if (edges === undefined) {
    return { bomFormat: "CycloneDX", specVersion: "1.6", components: [...components] };
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: { component: { "bom-ref": ROOT_REF, purl: ROOT_PURL } },
    components: [...components],
    dependencies: Object.entries(edges).map(([from, to]) => ({
      ref: from === ROOT_EDGE ? ROOT_REF : from,
      dependsOn: [...to],
    })),
  };
}

/** Introducer purl (or {@link ROOT_EDGE} for the project) -> the purls it pulls in. */
type DependencyEdges = Readonly<Record<string, ReadonlyArray<string>>>;

interface ScenarioInput {
  targetIdentity: string;
  /** Docker-image inputs pass "os"; a workspace input omits this (defaults app). */
  scope?: "os";
  components: ReadonlyArray<ComponentSpec>;
  /**
   * Root-anchored dependency edges. Present makes this a target collected by a lane that derives a
   * dependency graph, provenance and all - the yarn-plugin shape.
   */
  dependencies?: DependencyEdges;
}

interface ScenarioResult {
  doc: string;
  verdicts: ReadonlyArray<Verdict>;
  scoped: CanonicalDependencies;
}

/**
 * Resolve `[[docker.development]]` globs against the analyzed container
 * sources exactly as pipeline.ts#resolveDevelopmentContainers does, via the
 * same globToRegExp matcher (containerReport.test.ts's precedent).
 */
function resolveDevelopmentContainers(
  model: CanonicalDependencies,
  policy: Policy,
): ReadonlySet<string> {
  const sources = new Set<string>();

  for (const pkg of model.packages) {
    for (const occurrence of pkg.occurrences) {
      if (occurrence.target.startsWith(DOCKER_IDENTITY_PREFIX)) {
        sources.add(occurrence.target.slice(DOCKER_IDENTITY_PREFIX.length));
      }
    }
  }

  const resolved = new Set<string>();

  for (const devEntry of policy.docker?.development ?? []) {
    const matcher = globToRegExp(devEntry.source);

    for (const source of sources) {
      if (matcher.test(source)) {
        resolved.add(`${DOCKER_IDENTITY_PREFIX}${source}`);
      }
    }
  }

  return resolved;
}

/**
 * Append every declared in-depth answer as a ScanCode claim, through the same production helper the
 * enrichment stage uses, so a scenario exercising the intensive lane exercises the real one.
 */
function withIntensiveClaims(
  model: CanonicalDependencies,
  inputs: ReadonlyArray<ScenarioInput>,
): CanonicalDependencies {
  const byPurl = new Map<string, string>();

  for (const input of inputs) {
    for (const spec of input.components) {
      if (spec.intensive !== undefined) {
        byPurl.set(spec.purl, spec.intensive);
      }
    }
  }

  if (byPurl.size === 0) {
    return model;
  }

  return {
    packages: model.packages.map((entry) => {
      const raw = byPurl.get(entry.purl);

      return raw === undefined ? entry : withCacheClaim(entry, raw, "scancode");
    }),
  };
}

/** merge -> intensive claims -> annotate -> resolve dev containers -> re-scope -> evaluate -> render. */
function buildScenario(inputs: ReadonlyArray<ScenarioInput>, policyToml: string): ScenarioResult {
  const collected = inputs.map((input) => {
    const sbom = sbomDoc(input.components.map(sbomComponent), input.dependencies);

    return {
      sbom,
      targetIdentity: input.targetIdentity,
      ...(input.scope !== undefined ? { scope: input.scope } : {}),
      ...(input.dependencies !== undefined
        ? { introductions: npmIntroductions(sbom), derivesDependencyGraph: true }
        : {}),
    };
  });
  const merged = withIntensiveClaims(mergeSboms(collected), inputs);
  const graphTargets = targetsWithDependencyGraph(collected);
  const policy = parsePolicy(policyToml);
  const { model: annotated } = annotateFindings(merged, policy.clarify, BUILTIN_OVERRIDES);
  const developmentContainers = resolveDevelopmentContainers(annotated, policy);
  const scoped = applyContainerScopes(annotated, developmentContainers);
  const verdicts = evaluate(scoped, policy, graphTargets);
  const policyView: PolicyView = {
    policyPath: "policy.toml",
    suppressedWorkspaces: policy.suppressedWorkspaces,
    verdicts,
    developmentContainers,
    acceptedContainerNotices: acceptedContainerNotices(scoped, verdicts),
  };

  return {
    doc: alignTables(renderMarkdown(scoped, policyView)),
    verdicts,
    scoped,
  };
}

/** The post-transform scope of the package carrying `purl`, or undefined if absent. */
function findScope(scoped: CanonicalDependencies, purl: string): string | undefined {
  return scoped.packages.find((pkg) => pkg.purl === purl)?.scope;
}

/** The verdict for one (purl, occurrenceTarget) pair, or undefined if absent. */
function findVerdict(
  verdicts: ReadonlyArray<Verdict>,
  purl: string,
  occurrenceTarget: string,
): Verdict | undefined {
  return verdicts.find((v) => v.purl === purl && v.occurrenceTarget === occurrenceTarget);
}

/**
 * The classification half of a path: the package's post-transform scope, and
 * the verdict status + rule at one occurrence — the primary contract, checked
 * before any placement assertion.
 */
function assertClassificationOutcome(
  scoped: CanonicalDependencies,
  verdicts: ReadonlyArray<Verdict>,
  purl: string,
  occurrenceTarget: string,
  slug: string,
  expectedScope: string,
  expectedStatus: string,
  expectedRule: string,
): void {
  const scope = findScope(scoped, purl);

  assertClassification(
    scope === expectedScope,
    slug,
    `the package's post-transform scope is "${expectedScope}" (found "${scope ?? "none"}")`,
  );
  const verdict = findVerdict(verdicts, purl, occurrenceTarget);

  assertClassification(
    verdict?.status === expectedStatus && verdict.rule === expectedRule,
    slug,
    `the verdict at "${occurrenceTarget}" is "${expectedStatus}" via "${expectedRule}" (found "${verdict?.status ?? "none"}"/"${verdict?.rule ?? "none"}")`,
  );
}

/** Slice one "## Heading" section out of the document, up to the next "## ". */
function section(doc: string, heading: string): string {
  const start = doc.indexOf(heading);

  expect(start).toBeGreaterThanOrEqual(0);
  const rest = doc.slice(start + heading.length);
  const nextOffset = rest.indexOf("\n## ");

  return nextOffset === -1 ? rest : rest.slice(0, nextOffset);
}

/** The app-table portion of a summary section, excluding its container subsections. */
function appTableOnly(doc: string, heading: string): string {
  const full = section(doc, heading);
  const containerOffset = full.search(/\n### Container:/);

  return containerOffset === -1 ? full : full.slice(0, containerOffset);
}

/** One "### Container: <identity>" subsection, up to the next container or "## " heading. */
function containerSubsection(doc: string, identity: string): string {
  const heading = `### Container: ${identity}`;
  const start = doc.indexOf(heading);

  expect(start).toBeGreaterThanOrEqual(0);
  const rest = doc.slice(start + heading.length);
  const nextOffset = rest.search(/\n(### Container:|## )/);

  return nextOffset === -1 ? rest : rest.slice(0, nextOffset);
}

/** Split a container subsection into its System/Application halves (either may be empty). */
function containerPartition(block: string): {
  system: string;
  application: string;
} {
  const applicationOffset = block.indexOf("**Application packages**");

  return applicationOffset === -1
    ? { system: block, application: "" }
    : {
        system: block.slice(0, applicationOffset),
        application: block.slice(applicationOffset),
      };
}

const UNKNOWN_WARN = ["[unknown]", 'handling = "warn"', ""].join("\n");

const WORKSPACE = "apps/web";
const WORKSPACE_B = "apps/api";
const PROD_CONTAINER = `${DOCKER_IDENTITY_PREFIX}services/app/Dockerfile`;
const DEV_CONTAINER = `${DOCKER_IDENTITY_PREFIX}tools/build/Dockerfile`;
const OTHER_CONTAINER = `${DOCKER_IDENTITY_PREFIX}services/other/Dockerfile`;
const DEV_CONTAINER_POLICY = [
  UNKNOWN_WARN,
  "[[docker.development]]",
  'source = "tools/**"',
  'reason = "ci tooling only"',
  "",
].join("\n");

/** One `[target]` project-profile table's lines, for building inline TOML policy fixtures. */
function targetProfileLines(
  license: string,
  network: boolean,
  distribution: "external" | "internal",
): string[] {
  return [
    "[target]",
    `license = "${license}"`,
    `network = ${network}`,
    `distribution = "${distribution}"`,
    "",
  ];
}

const SCENARIOS: Record<PlacementPath, () => void> = {
  "workspace-prod-permissive": () => {
    const slug = "workspace-prod-permissive";
    const purl = "pkg:npm/permissive-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "permissive-lib", purl, license: "MIT" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "default:ok");
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("permissive-lib"),
      slug,
      "an npm workspace production dependency with a permissive license rows in the Production dependencies app table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Development-only dependencies").includes("permissive-lib"),
      slug,
      "a production package must not row in the Development-only dependencies table",
    );
    assertPlacement(
      doc.includes("- Production packages: 1") && doc.includes("- Development-only packages: 0"),
      slug,
      "the package-counts block counts the package under Production, not Development-only",
    );
  },

  "workspace-dev-only": () => {
    const slug = "workspace-dev-only";
    const purl = "pkg:npm/dev-only-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "dev-only-lib", purl, license: "MIT", dev: true }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "default:ok");
    assertPlacement(
      appTableOnly(doc, "## Development-only dependencies").includes("dev-only-lib"),
      slug,
      "a workspace dependency that is dev at every occurrence rows in the Development-only dependencies app table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("dev-only-lib"),
      slug,
      "a development-only package must not row in the Production dependencies table",
    );
    assertPlacement(
      doc.includes("- Development-only packages: 1") && doc.includes("- Production packages: 0"),
      slug,
      "the package-counts block counts the package under Development-only, not Production",
    );
  },

  "shared-workspace-and-container": () => {
    const slug = "shared-workspace-and-container";
    const purl = "pkg:npm/shared-lib@2.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "shared-lib", purl, version: "2.0.0", license: "MIT" }],
        },
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "shared-lib", purl, version: "2.0.0", license: "MIT" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "default:ok");
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("shared-lib"),
      slug,
      "a package with a workspace occurrence rows in the Production dependencies app table (app wins over os)",
    );
    const { application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("shared-lib"),
      slug,
      "the same package also rows in its production container's Application packages table (the shared-in-both rule)",
    );
  },

  "container-only-system": () => {
    const slug = "container-only-system";
    const purl = "pkg:apk/alpine/system-pkg@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "system-pkg", purl, license: "MIT" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "ok",
      "default:ok",
    );
    const { system } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      system.includes("system-pkg"),
      slug,
      "an apk container-only package rows in its container's System packages table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("system-pkg") &&
        !appTableOnly(doc, "## Development-only dependencies").includes("system-pkg"),
      slug,
      "a container-only system package must not row in either app table",
    );
  },

  "container-only-app-ecosystem": () => {
    const slug = "container-only-app-ecosystem";
    const purl = "pkg:npm/baked-npm-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "baked-npm-lib", purl, license: "MIT" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "app",
      "ok",
      "default:ok",
    );
    const { application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("baked-npm-lib"),
      slug,
      "an npm package baked into a container with no workspace occurrence rows in that container's Application packages table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("baked-npm-lib") &&
        !appTableOnly(doc, "## Development-only dependencies").includes("baked-npm-lib"),
      slug,
      "a container-only application-ecosystem package must not row in either app table",
    );
  },

  "unrecognized-ecosystem-gates": () => {
    const slug = "unrecognized-ecosystem-gates";
    const purl = "pkg:mystery-eco/mystery-pkg@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "mystery-pkg", purl, license: "GPL-3.0-only" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "app",
      "fail",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("mystery-pkg"),
      slug,
      'a copyleft package on an unrecognized purl ecosystem baked into a production container fails "default:copyleft" and rows in Problematic (the allowlist fails safe)',
    );
    const { system, application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("mystery-pkg") && !system.includes("mystery-pkg"),
      slug,
      "the unrecognized ecosystem is treated as application-level, so it rows in the container's Application packages table, never System",
    );
  },

  "system-copyleft-os-warn": () => {
    const slug = "system-copyleft-os-warn";
    const purl = "pkg:apk/alpine/gpl-tool@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "gpl-tool", purl, license: "GPL-2.0-only" }],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "warn"', ""].join("\n"),
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "warn",
      "default:copyleft",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("gpl-tool"),
      slug,
      "an os-downgraded warn must not row in Problematic",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("gpl-tool"),
      slug,
      "routine system copyleft (non-AGPL) is excluded from the Copyleft section regardless of verdict",
    );
    const { system } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      system.includes("gpl-tool"),
      slug,
      "the package still rows in its container's System packages table",
    );
  },

  "system-copyleft-os-fail": () => {
    const slug = "system-copyleft-os-fail";
    const purl = "pkg:apk/alpine/gpl-tool@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "gpl-tool", purl, license: "GPL-2.0-only" }],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "fail"', ""].join("\n"),
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("gpl-tool"),
      slug,
      "the fail rows in Problematic licenses",
    );
  },

  "system-copyleft-os-ignore": () => {
    const slug = "system-copyleft-os-ignore";
    const purl = "pkg:apk/alpine/gpl-tool@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "gpl-tool", purl, license: "GPL-2.0-only" }],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "ignore"', ""].join("\n"),
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "ok",
      "default:copyleft",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("gpl-tool") &&
        !section(doc, "## Copyleft and special notices").includes("gpl-tool"),
      slug,
      "an ignored os-scope copyleft package is neither Problematic nor a Copyleft notice",
    );
    const { system } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      system.includes("gpl-tool"),
      slug,
      "the package still rows in its container's System packages table (inventory only)",
    );
  },

  "system-agpl-escalates": () => {
    const slug = "system-agpl-escalates";
    const purl = "pkg:apk/alpine/agpl-daemon@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "agpl-daemon", purl, license: "AGPL-3.0-only" }],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "warn"', ""].join("\n"),
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "default:agpl-container",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("agpl-daemon"),
      slug,
      'an AGPL system package fails "default:agpl-container" even under os_dependencies = "warn" — the warn knob cannot soften the container AGPL escalation',
    );
  },

  "system-agpl-accepted-notice": () => {
    const slug = "system-agpl-accepted-notice";
    const purl = "pkg:apk/alpine/agpl-daemon@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-daemon"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ["${PROD_CONTAINER}"]`,
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "agpl-daemon", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "ok",
      "compatible[0]",
    );
    const copyleft = section(doc, "## Copyleft and special notices");

    assertPlacement(
      copyleft.includes("agpl-daemon") && copyleft.includes("accepted via compatible\\[0\\]"),
      slug,
      "an accepted AGPL system package renders as a non-blocking notice in Copyleft and special notices",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("agpl-daemon"),
      slug,
      "an accepted AGPL system package must not row in Problematic",
    );
    assertPlacement(
      verdicts.every((v) => v.status !== "fail"),
      slug,
      "acceptance leaves zero fail verdicts",
    );
  },

  "system-agpl-imprecise-escalates": () => {
    const slug = "system-agpl-imprecise-escalates";
    const purl = "pkg:apk/alpine/relay-imprecise@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "relay-imprecise",
              purl,
              licenseName: "GNU Affero General Public License",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "default:agpl-container",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("relay-imprecise"),
      slug,
      'an imprecise bare-"AGPL" system package fails "default:agpl-container" and rows in Problematic',
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes("relay-imprecise"),
      slug,
      "it also rows in Imprecise licenses — the overlap with Problematic is by design",
    );
  },

  "system-agpl-imprecise-accepted": () => {
    const slug = "system-agpl-imprecise-accepted";
    const purl = "pkg:apk/alpine/relay-imprecise@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'name = "relay-imprecise"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ["${PROD_CONTAINER}"]`,
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "relay-imprecise",
              purl,
              licenseName: "GNU Affero General Public License",
            },
          ],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "ok",
      "compatible[0]",
    );
    const copyleft = section(doc, "## Copyleft and special notices");

    assertPlacement(
      copyleft.includes("relay-imprecise") && copyleft.includes("accepted via compatible\\[0\\]"),
      slug,
      "an accepted imprecise-AGPL system package renders as a non-blocking notice in Copyleft and special notices",
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes("relay-imprecise"),
      slug,
      "it still rows in Imprecise licenses regardless of the accepted verdict",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("relay-imprecise"),
      slug,
      "an accepted package must not row in Problematic",
    );
  },

  "mixed-agpl-fail-and-accept": () => {
    const slug = "mixed-agpl-fail-and-accept";
    const purl = "pkg:apk/alpine/shared-agpl-daemon@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'name = "shared-agpl-daemon"',
      'as-dependency-of = ["self"]',
      'rationale = "license-reviewed"',
      `where = ["${OTHER_CONTAINER}"]`,
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "shared-agpl-daemon", purl, license: "AGPL-3.0-only" }],
        },
        {
          targetIdentity: OTHER_CONTAINER,
          scope: "os",
          components: [{ name: "shared-agpl-daemon", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "default:agpl-container",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("shared-agpl-daemon"),
      slug,
      "the unaccepted occurrence's fail rows the purl in Problematic",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("shared-agpl-daemon"),
      slug,
      "a purl already in Problematic never also shows an accepted-AGPL notice",
    );
  },

  "app-copyleft-prod-container": () => {
    const slug = "app-copyleft-prod-container";
    const purl = "pkg:golang/metrics-tool@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "metrics-tool", purl, license: "GPL-3.0-only" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "app",
      "fail",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("metrics-tool"),
      slug,
      "a golang copyleft package baked into a production container fails default:copyleft and rows in Problematic",
    );
    const { application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("metrics-tool"),
      slug,
      "it also rows in its container's Application packages table",
    );
  },

  "app-copyleft-dev-container": () => {
    const slug = "app-copyleft-dev-container";
    const purl = "pkg:npm/dev-tool-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: DEV_CONTAINER,
          scope: "os",
          components: [{ name: "dev-tool-lib", purl, license: "LGPL-2.1-or-later" }],
        },
      ],
      DEV_CONTAINER_POLICY,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      DEV_CONTAINER,
      slug,
      "app",
      "warn",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Copyleft and special notices").includes("dev-tool-lib"),
      slug,
      "an app-ecosystem copyleft package in a [[docker.development]] container dev-downgrades to a Copyleft flagged row",
    );
    const devSection = section(doc, "## Development-only dependencies");

    assertPlacement(
      devSection.includes(`### Container: ${DEV_CONTAINER}`) && devSection.includes("dev-tool-lib"),
      slug,
      "its container subsection sits under Development-only dependencies",
    );
  },

  "app-copyleft-workspace-dev": () => {
    const slug = "app-copyleft-workspace-dev";
    const purl = "pkg:npm/doc-tool@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "doc-tool",
              purl,
              license: "LGPL-2.1-or-later",
              dev: true,
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Copyleft and special notices").includes("doc-tool"),
      slug,
      "a workspace dev-dependency copyleft package dev-downgrades to warn and rows in Copyleft and special notices",
    );
    assertPlacement(
      appTableOnly(doc, "## Development-only dependencies").includes("doc-tool"),
      slug,
      "it rows in the Development-only dependencies app table",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("doc-tool"),
      slug,
      "a dev-downgraded warn must not row in Problematic",
    );
  },

  "problematic-dedup-keeps-inventory": () => {
    const slug = "problematic-dedup-keeps-inventory";
    const purl = "pkg:npm/prod-copyleft@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "prod-copyleft", purl, license: "GPL-3.0-only" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "default:copyleft",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("prod-copyleft"),
      slug,
      "a workspace production copyleft package fails default:copyleft and rows in Problematic",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("prod-copyleft"),
      slug,
      "a purl already in Problematic is deduped out of the Copyleft flagged rows",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("prod-copyleft"),
      slug,
      "it still keeps its inventory row in the Production dependencies app table",
    );
  },

  "imprecise-copyleft-family-only-imprecise": () => {
    const slug = "imprecise-copyleft-family-only-imprecise";
    const purl = "pkg:npm/bare-gpl-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "bare-gpl-lib", purl, licenseName: "GPL" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "default:imprecise-copyleft",
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes("bare-gpl-lib"),
      slug,
      'a bare "GPL" app package warns "default:imprecise-copyleft" and rows in Imprecise licenses',
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("bare-gpl-lib"),
      slug,
      'an imprecise-copyleft warn never qualifies for a Copyleft flagged row — only the exact "default:copyleft" rule does',
    );
  },

  "imprecise-permissive-family": () => {
    const slug = "imprecise-permissive-family";
    const purl = "pkg:npm/bare-bsd-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "bare-bsd-lib", purl, licenseName: "BSD" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "default:imprecise",
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes("bare-bsd-lib"),
      slug,
      'a bare "BSD" app package warns "default:imprecise" and rows in Imprecise licenses only',
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("bare-bsd-lib") &&
        !section(doc, "## Problematic licenses").includes("bare-bsd-lib"),
      slug,
      "a known-permissive imprecise family never rows in Copyleft or Problematic",
    );
  },

  "unknown-license-counted": () => {
    const slug = "unknown-license-counted";
    const purl = "pkg:npm/unknown-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "unknown-lib", purl }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "default:unknown",
    );
    assertPlacement(
      doc.includes("- Unknown license: 1"),
      slug,
      'a package with no license claim under [unknown] handling = "warn" counts under Unknown license',
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("unknown-lib"),
      slug,
      "it still keeps its inventory row in the Production dependencies app table",
    );
  },

  "licenseref-only-unknown": () => {
    const slug = "licenseref-only-unknown";
    const purl = "pkg:npm/licenseref-only-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "licenseref-only-lib",
              purl,
              license: "LicenseRef-AGPL-3.0-only",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "default:unknown",
    );
    assertPlacement(
      doc.includes("- Unknown license: 1"),
      slug,
      "a package whose only license content is an opaque LicenseRef counts under Unknown license, exactly like a genuine unknown",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("licenseref-only-lib"),
      slug,
      "it still keeps its inventory row in the Production dependencies app table",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("licenseref-only-lib") &&
        !section(doc, "## Copyleft and special notices").includes("licenseref-only-lib") &&
        !doc.includes("## Imprecise licenses (review / disambiguate)"),
      slug,
      "an unassessed LicenseRef is a warn under the unknown lane, not a flagged copyleft/imprecise/problematic row — the Problematic/Copyleft sections render their no-findings placeholder and the empty Imprecise section is omitted entirely",
    );
  },

  "suppressed-workspace-copyleft": () => {
    const slug = "suppressed-workspace-copyleft";
    const purl = "pkg:npm/gpl-inside-agpl-workspace@1.0.0";
    const suppressedWorkspace = "libs/shared";
    const policy = [
      UNKNOWN_WARN,
      "[[workspace.copyleft_suppressed]]",
      `path = "${suppressedWorkspace}"`,
      'license = "AGPL-3.0-only"',
      'description = "the workspace itself is AGPL-3.0-only, absorbing its bundled GNU-family dependencies"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: suppressedWorkspace,
          components: [
            {
              name: "gpl-inside-agpl-workspace",
              purl,
              license: "GPL-3.0-only",
            },
          ],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      suppressedWorkspace,
      slug,
      "app",
      "suppressed",
      "workspace.copyleft_suppressed[0]",
    );
    const copyleft = section(doc, "## Copyleft and special notices");

    assertPlacement(
      copyleft.includes(suppressedWorkspace) && copyleft.includes("AGPL-3.0-only"),
      slug,
      "the suppressed-workspaces list renders in Copyleft and special notices",
    );
    assertPlacement(
      !copyleft.includes("gpl-inside-agpl-workspace"),
      slug,
      "a suppressed package never rows as a Copyleft flagged row",
    );
  },

  "denied-license-terminal": () => {
    const slug = "denied-license-terminal";
    const purl = "pkg:npm/denied-pkg@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[deny]]",
      'match = "license"',
      'pattern = "MIT"',
      'reason = "this discriminator scenario denies MIT to prove deny wins over compatible"',
      "",
      "[[compatible]]",
      'match = "license"',
      'pattern = "MIT"',
      'rationale = "license-reviewed"',
      'where = ["/"]',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "denied-pkg", purl, license: "MIT" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "denied[0]",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("denied-pkg"),
      slug,
      "the denied verdict rows in Problematic",
    );
  },

  "system-package-in-dev-container-counts-dev": () => {
    const slug = "system-package-in-dev-container-counts-dev";
    const purl = "pkg:apk/alpine/sys-in-dev-container@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: DEV_CONTAINER,
          scope: "os",
          components: [{ name: "sys-in-dev-container", purl, license: "MIT" }],
        },
      ],
      DEV_CONTAINER_POLICY,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      DEV_CONTAINER,
      slug,
      "os",
      "ok",
      "default:ok",
    );
    assertPlacement(
      doc.includes("- Development-only packages: 1") && doc.includes("- Production packages: 0"),
      slug,
      "a system package whose only container is dev-marked counts Development-only via the container's classification",
    );
    const devSection = section(doc, "## Development-only dependencies");

    assertPlacement(
      devSection.includes(`### Container: ${DEV_CONTAINER}`) &&
        devSection.includes("sys-in-dev-container"),
      slug,
      "its container's System packages table sits under the Development-only subsection",
    );
  },

  "conflict-scancode": () => {
    const slug = "conflict-scancode";
    const purl = "pkg:npm/disputed-lib@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "disputed-lib", purl, license: "Apache-2.0", intensive: "MIT" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "conflict:scancode",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("disputed-lib"),
      slug,
      "an unresolved in-depth-vs-quick-check disagreement is a fail verdict, so it rows in Problematic licenses",
    );
    const conflicts = section(doc, "## Assessment conflicts");

    assertPlacement(
      conflicts.includes("### ScanCode assessment vs quick check") &&
        conflicts.includes("disputed-lib"),
      slug,
      "the disagreement rows in the Assessment conflicts section's ScanCode-assessment-vs-quick-check sub-table",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("disputed-lib"),
      slug,
      "the package keeps its inventory row in Production dependencies (inventory is never dropped by a conflict)",
    );
  },

  "detected-mismatch": () => {
    const slug = "detected-mismatch";
    const purl = "pkg:npm/moved-on-lib@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[clarify]]",
      'name = "moved-on-lib"',
      'version = "1.0.0"',
      'detected = { registry = "BSD" }',
      'justification = "scan-more-precise"',
      'expression = "BSD-3-Clause"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "moved-on-lib", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "override:stale[clarify]",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("moved-on-lib"),
      slug,
      "a clarify entry whose recorded detection no longer holds is a fail verdict, so it rows in Problematic licenses",
    );
    assertPlacement(
      !doc.includes("BSD-3-Clause"),
      slug,
      "the stale expression is never applied, so the recorded license reaches no part of the report - not the Problematic section, not the inventory row",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("moved-on-lib"),
      slug,
      "the package keeps its inventory row in Production dependencies (inventory is never dropped by a stale entry)",
    );
  },

  "cross-image-claim-divergence": () => {
    const slug = "cross-image-claim-divergence";
    const purl = "pkg:apk/alpine/shared-daemon@1.0.0";
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "shared-daemon", purl, license: "MIT" }],
        },
        {
          targetIdentity: OTHER_CONTAINER,
          scope: "os",
          components: [{ name: "shared-daemon", purl, license: "Apache-2.0" }],
        },
      ],
      UNKNOWN_WARN,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "conflict:cross-image-claims",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("shared-daemon"),
      slug,
      "a cross-image claim divergence is a fail verdict, so it rows in Problematic licenses like any other fail",
    );
    const conflicts = section(doc, "## Assessment conflicts");

    assertPlacement(
      conflicts.includes("### Cross-image license claims") && conflicts.includes("shared-daemon"),
      slug,
      "the divergence rows in the Assessment conflicts section's Cross-image license claims sub-table",
    );
    const prodSystem = containerPartition(containerSubsection(doc, PROD_CONTAINER)).system;
    const otherSystem = containerPartition(containerSubsection(doc, OTHER_CONTAINER)).system;

    assertPlacement(
      prodSystem.includes("shared-daemon") && otherSystem.includes("shared-daemon"),
      slug,
      "both diverging containers keep their complete inventory row in their own System packages table (inventory is never dropped by a conflict)",
    );
  },

  "target-ok-permissive": () => {
    const slug = "target-ok-permissive";
    const purl = "pkg:npm/target-ok-lib@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "external")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-ok-lib", purl, license: "MIT" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "target:ok");
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-ok-lib"),
      slug,
      "a compatible dependency under a declared target rows in Production dependencies like any other ok package",
    );
    assertPlacement(
      !doc.includes("## Target compatibility"),
      slug,
      "a clean target:ok verdict never triggers the Target compatibility section — no heading renders at all",
    );
  },

  "target-incompatible-prod": () => {
    const slug = "target-incompatible-prod";
    const purl = "pkg:npm/target-incompatible-prod@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "external")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-incompatible-prod", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-incompatible-prod"),
      slug,
      "a target:incompatible fail on a production occurrence rows in Problematic licenses",
    );
  },

  "target-incompatible-dev-downgrade": () => {
    const slug = "target-incompatible-dev-downgrade";
    const purl = "pkg:npm/target-dev-downgrade@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "external")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-dev-downgrade", purl, license: "GPL-3.0-only", dev: true }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "target:incompatible",
    );
    assertPlacement(
      section(doc, "## Target compatibility").includes("target-dev-downgrade"),
      slug,
      "a dev-downgraded target:incompatible (warn) rows in the Target compatibility flagged table",
    );
    assertPlacement(
      appTableOnly(doc, "## Development-only dependencies").includes("target-dev-downgrade"),
      slug,
      "it also rows in the Development-only dependencies app table",
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("target-dev-downgrade"),
      slug,
      "a dev-downgraded warn must not row in Problematic",
    );
  },

  "target-apache-gpl2-incompatible": () => {
    const slug = "target-apache-gpl2-incompatible";
    const purl = "pkg:npm/target-apache-gpl2@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("GPL-2.0-only", false, "external")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-apache-gpl2", purl, license: "Apache-2.0" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-apache-gpl2"),
      slug,
      "a permissive dependency the target's own compatibility matrix rejects fails target:incompatible — the case today's copyleft-only lane cannot see",
    );
  },

  "target-or-election-flip": () => {
    const slug = "target-or-election-flip";
    const purl = "pkg:npm/target-or-election-flip@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("GPL-2.0-only", false, "external")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "target-or-election-flip",
              purl,
              license: "Apache-2.0 OR GPL-2.0-only",
            },
          ],
        },
      ],
      policy,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "target:ok");
    const verdict = findVerdict(verdicts, purl, WORKSPACE)!;

    assertPlacement(
      verdict.reason.includes("GPL-2.0-only"),
      slug,
      "the target-aware election picks the GPL-2.0-only branch (the matrix diagonal), the opposite of the no-target elect() preference — the verdict reason cites it",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-or-election-flip") &&
        appTableOnly(doc, "## Production dependencies").includes("Apache-2.0 OR GPL-2.0-only"),
      slug,
      "the License column still shows the full unelected expression — election surfaces only through the verdict reason",
    );
  },

  "target-proprietary-boundary-external": () => {
    const slug = "target-proprietary-boundary-external";
    const purl = "pkg:npm/target-proprietary-boundary@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("proprietary", true, "external")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-proprietary-boundary", purl, license: "LGPL-2.1-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "target:boundary",
    );
    assertPlacement(
      section(doc, "## Target compatibility").includes("target-proprietary-boundary"),
      slug,
      "weak copyleft under a proprietary target warns target:boundary and rows in the Target compatibility flagged table",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-proprietary-boundary"),
      slug,
      "it also keeps its inventory row in Production dependencies",
    );
  },

  "target-unknown-pair-residual": () => {
    const slug = "target-unknown-pair-residual";
    const purl = "pkg:npm/target-unknown-pair@1.0.0";
    const warnPolicy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "external")].join("\n");
    const component = { name: "target-unknown-pair", purl, license: "QPL-1.0" };
    const warnRun = buildScenario(
      [{ targetIdentity: WORKSPACE, components: [component] }],
      warnPolicy,
    );

    assertClassificationOutcome(
      warnRun.scoped,
      warnRun.verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "warn",
      "target:unknown-pair",
    );
    assertPlacement(
      section(warnRun.doc, "## Target compatibility").includes("target-unknown-pair"),
      slug,
      "a matrix-uncovered pair warns target:unknown-pair by default (the D4 residual knob) and rows in the Target compatibility flagged table",
    );

    const failPolicy = [
      UNKNOWN_WARN,
      "[target]",
      'license = "MIT"',
      "network = false",
      'distribution = "external"',
      'unknown_pair = "fail"',
      "",
    ].join("\n");
    const failRun = buildScenario(
      [{ targetIdentity: WORKSPACE, components: [component] }],
      failPolicy,
    );

    assertClassificationOutcome(
      failRun.scoped,
      failRun.verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:unknown-pair",
    );
    assertPlacement(
      section(failRun.doc, "## Problematic licenses").includes("target-unknown-pair"),
      slug,
      'unknown_pair = "fail" routes the same residual to Problematic licenses instead',
    );
  },

  "target-internal-holds-gpl": () => {
    const slug = "target-internal-holds-gpl";
    const purl = "pkg:npm/target-internal-holds-gpl@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "internal")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-internal-holds-gpl", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "ok",
      "target:internal-use",
    );
    assertPlacement(
      section(doc, "## Target compatibility").includes("target-internal-holds-gpl"),
      slug,
      "a copyleft obligation held out of scope for internal-only distribution rows in the Target compatibility held-for-internal-use list",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-internal-holds-gpl"),
      slug,
      "it also keeps a normal inventory row in Production dependencies (ok, never gating)",
    );
  },

  "target-internal-network-agpl-fails": () => {
    const slug = "target-internal-network-agpl-fails";
    const purl = "pkg:npm/target-internal-network-agpl@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", true, "internal")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-internal-network-agpl", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-internal-network-agpl") &&
        section(doc, "## Problematic licenses").includes("network-deployed"),
      slug,
      "network = true keeps the AGPL class in scope regardless of distribution — the MIT target cannot absorb it, and the reason names the network-deployed basis",
    );
  },

  "target-network-agpl-absorbed": () => {
    const slug = "target-network-agpl-absorbed";
    const purl = "pkg:npm/target-network-agpl-absorbed@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("AGPL-3.0-only", true, "external")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "target-network-agpl-absorbed", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "app",
      "ok",
      "target:ok",
    );
    const { application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("target-network-agpl-absorbed"),
      slug,
      "an AGPL-licensed, network-deployed target absorbs an AGPL dependency (the matrix diagonal) — the scope-gating guard case a hardcoded network rule would have failed",
    );
  },

  "target-network-false-agpl-internal-held": () => {
    const slug = "target-network-false-agpl-internal-held";
    const purl = "pkg:npm/target-network-false-agpl-held@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "internal")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-network-false-agpl-held", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "ok",
      "target:internal-use",
    );
    assertPlacement(
      section(doc, "## Target compatibility").includes("target-network-false-agpl-held"),
      slug,
      "network = false joins the AGPL obligation to the ordinary distribution-gated copyleft class, which internal distribution then holds",
    );
  },

  "target-internal-nondistribution-conflict-stays": () => {
    const slug = "target-internal-nondistribution-conflict-stays";
    const purl = "pkg:npm/target-internal-nondist-conflict@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("GPL-2.0-only", false, "internal")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-internal-nondist-conflict", purl, license: "Apache-2.0" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-internal-nondist-conflict"),
      slug,
      'the internal-use hold floor: a non-copyleft-driven incompatibility (obligation "none") is never rescued by internal distribution',
    );
  },

  "target-workspace-divergence": () => {
    const slug = "target-workspace-divergence";
    const purl = "pkg:npm/target-workspace-divergence@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      ...targetProfileLines("MIT", false, "external"),
      "[[target.workspace]]",
      `path = "${WORKSPACE_B}"`,
      'license = "GPL-3.0-only"',
      'reason = "workspace B ships under GPL-3.0-only"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-workspace-divergence", purl, license: "GPL-3.0-only" }],
        },
        {
          targetIdentity: WORKSPACE_B,
          components: [{ name: "target-workspace-divergence", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE_B,
      slug,
      "app",
      "ok",
      "target:ok",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-workspace-divergence") &&
        section(doc, "## Problematic licenses").includes(WORKSPACE),
      slug,
      "the any-fail rule escalates the shared purl to Problematic, the reason naming workspace A's (the failing MIT target's) profile",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-workspace-divergence"),
      slug,
      "it keeps one inventory row in Production dependencies spanning both workspaces",
    );
  },

  "target-container-app-ecosystem": () => {
    const slug = "target-container-app-ecosystem";
    const purl = "pkg:npm/target-container-app-ecosystem@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("GPL-3.0-only", false, "external")].join(
      "\n",
    );
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "target-container-app-ecosystem", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "app",
      "ok",
      "target:ok",
    );
    const { application } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      application.includes("target-container-app-ecosystem"),
      slug,
      "the project profile governs a docker occurrence of an app-ecosystem package (never a workspace override)",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("target-container-app-ecosystem"),
      slug,
      "a container-only package never rows in the app table",
    );
  },

  "target-os-agpl-network-true-escalates": () => {
    const slug = "target-os-agpl-network-true-escalates";
    const purl = "pkg:apk/alpine/target-os-agpl-true@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", true, "external")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "target-os-agpl-true", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "fail",
      "default:agpl-container",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-os-agpl-true"),
      slug,
      "network = true keeps the container AGPL escalation exactly as it is today — now declared, not guessed",
    );
  },

  "target-os-agpl-network-false-routine": () => {
    const slug = "target-os-agpl-network-false-routine";
    const precisePurl = "pkg:apk/alpine/target-os-agpl-false-precise@1.0.0";
    const imprecisePurl = "pkg:apk/alpine/target-os-agpl-false-imprecise@1.0.0";
    const policy = [UNKNOWN_WARN, ...targetProfileLines("MIT", false, "external")].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "target-os-agpl-false-precise",
              purl: precisePurl,
              license: "AGPL-3.0-only",
            },
            {
              name: "target-os-agpl-false-imprecise",
              purl: imprecisePurl,
              licenseName: "GNU Affero General Public License",
            },
          ],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      precisePurl,
      PROD_CONTAINER,
      slug,
      "os",
      "warn",
      "default:copyleft",
    );
    assertClassificationOutcome(
      scoped,
      verdicts,
      imprecisePurl,
      PROD_CONTAINER,
      slug,
      "os",
      "warn",
      "default:copyleft",
    );
    const preciseVerdict = findVerdict(verdicts, precisePurl, PROD_CONTAINER)!;
    const impreciseVerdict = findVerdict(verdicts, imprecisePurl, PROD_CONTAINER)!;

    assertPlacement(
      preciseVerdict.reason.includes("network = false") &&
        impreciseVerdict.reason.includes("network = false"),
      slug,
      "the declared network = false demotion basis is named in both the precise and the imprecise reason",
    );
    const { system } = containerPartition(containerSubsection(doc, PROD_CONTAINER));

    assertPlacement(
      system.includes("target-os-agpl-false-precise") &&
        system.includes("target-os-agpl-false-imprecise") &&
        !section(doc, "## Problematic licenses").includes("target-os-agpl-false-precise") &&
        !section(doc, "## Copyleft and special notices").includes("target-os-agpl-false-precise"),
      slug,
      "the demoted warn rows only in its container's System packages table, exactly like routine non-AGPL system copyleft",
    );
  },

  "target-os-scope-untouched": () => {
    const slug = "target-os-scope-untouched";
    const purl = "pkg:apk/alpine/target-os-scope-untouched@1.0.0";
    const component = { name: "target-os-scope-untouched", purl, license: "GPL-2.0-only" };
    const noTargetRun = buildScenario(
      [{ targetIdentity: PROD_CONTAINER, scope: "os", components: [component] }],
      UNKNOWN_WARN,
    );
    const targetPolicy = [UNKNOWN_WARN, ...targetProfileLines("MIT", true, "external")].join("\n");
    const targetRun = buildScenario(
      [{ targetIdentity: PROD_CONTAINER, scope: "os", components: [component] }],
      targetPolicy,
    );

    assertClassificationOutcome(
      targetRun.scoped,
      targetRun.verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "warn",
      "default:copyleft",
    );
    const noTargetVerdict = findVerdict(noTargetRun.verdicts, purl, PROD_CONTAINER)!;
    const targetVerdictFound = findVerdict(targetRun.verdicts, purl, PROD_CONTAINER)!;

    assertPlacement(
      noTargetVerdict.reason === targetVerdictFound.reason,
      slug,
      "a non-AGPL os-scope copyleft package's verdict reason is byte-identical with or without a declared target — only the AGPL-container escalation ever consults the network flag",
    );
  },

  "target-supersedes-suppression": () => {
    const slug = "target-supersedes-suppression";
    const purl = "pkg:npm/target-supersedes-suppression@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      ...targetProfileLines("AGPL-3.0-only", true, "external"),
      "[[workspace.copyleft_suppressed]]",
      `path = "${WORKSPACE}"`,
      'license = "AGPL-3.0-only"',
      'description = "the workspace itself is AGPL-3.0-only, absorbing its bundled GNU-family dependencies"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-supersedes-suppression", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(scoped, verdicts, purl, WORKSPACE, slug, "app", "ok", "target:ok");
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-supersedes-suppression"),
      slug,
      "the target-compatibility lane decides the occurrence before the suppression check ever runs — the verdict is target:ok, never suppressed",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes("target-supersedes-suppression"),
      slug,
      "the package never rows as a suppressed copyleft finding",
    );

    const parsedPolicy = parsePolicy(policy);
    const notices = suppressionOverlapNotices(parsedPolicy);

    assertPlacement(
      notices.length === 1 && notices[0]!.includes(WORKSPACE),
      slug,
      "policy/target.ts's suppressionOverlapNotices surfaces the now-dead suppression entry exactly once",
    );
  },

  "target-os-agpl-network-false-ignored-notice": () => {
    const slug = "target-os-agpl-network-false-ignored-notice";
    const purl = "pkg:apk/alpine/target-os-agpl-ignored@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      ...targetProfileLines("MIT", false, "external"),
      "[os_dependencies]",
      'handling = "ignore"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [{ name: "target-os-agpl-ignored", purl, license: "AGPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      PROD_CONTAINER,
      slug,
      "os",
      "ok",
      "default:copyleft",
    );
    const copyleft = section(doc, "## Copyleft and special notices");

    assertPlacement(
      copyleft.includes("target-os-agpl-ignored") && copyleft.includes("network = false"),
      slug,
      'a network=false-demoted AGPL row landing ok via os_dependencies = "ignore" still gets notice-style visibility — never silently absent',
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("target-os-agpl-ignored"),
      slug,
      "the demoted-and-accepted package must not row in Problematic",
    );
  },

  // Adversarial gate finding: a held-internal row was silently dropped whenever the same
  // purl also carried a fail at a DIFFERENT occurrence - the Problematic dedup was purl-wide, not
  // per-occurrence, so a genuine out-of-scope exposure vanished from the report entirely instead
  // of staying enumerable per report-placement.md's own held-row invariant.
  "target-held-survives-purl-fail": () => {
    const slug = "target-held-survives-purl-fail";
    const purl = "pkg:npm/target-held-survives-purl-fail@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      ...targetProfileLines("MIT", false, "external"),
      "[[target.workspace]]",
      `path = "${WORKSPACE_B}"`,
      'license = "MIT"',
      "network = false",
      'distribution = "internal"',
      'reason = "workspace B is internal-only tooling"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [{ name: "target-held-survives-purl-fail", purl, license: "GPL-3.0-only" }],
        },
        {
          targetIdentity: WORKSPACE_B,
          components: [{ name: "target-held-survives-purl-fail", purl, license: "GPL-3.0-only" }],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "target:incompatible",
    );
    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE_B,
      slug,
      "app",
      "ok",
      "target:internal-use",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("target-held-survives-purl-fail"),
      slug,
      "workspace A's fail rows in Problematic licenses",
    );
    assertPlacement(
      section(doc, "## Target compatibility").includes("target-held-survives-purl-fail") &&
        section(doc, "## Target compatibility").includes("Held out of scope"),
      slug,
      "workspace B's held-internal row still rows in Target compatibility's held-for-internal-use list, even though the same purl fails at workspace A - the Problematic dedup must never drop a held row for an unrelated occurrence",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("target-held-survives-purl-fail"),
      slug,
      "it keeps one inventory row in Production dependencies spanning both workspaces",
    );
  },

  // A [[compatible]] package entry states whose use of a package was judged. Where the workspace
  // has a dependency graph and one of the packages it accepts also arrives around every introducer
  // it names, the entry says something the scan contradicts: it accepts nothing there, and every
  // package it governs in that workspace fails with it.
  "voided-compatible": () => {
    const slug = "voided-compatible";
    const gpl = "pkg:npm/voided-compatible-gpl-lib@1.0.0";
    const mpl = "pkg:npm/voided-compatible-mpl-lib@1.0.0";
    const judged = "pkg:npm/voided-compatible-judged@1.0.0";
    const other = "pkg:npm/voided-compatible-other@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'pattern = "voided-compatible-*-lib"',
      'version = "1.0.0"',
      'as-dependency-of = ["voided-compatible-judged"]',
      'rationale = "unused-transitive"',
      `where = ["${WORKSPACE}"]`,
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            { name: "voided-compatible-judged", purl: judged, license: "MIT" },
            { name: "voided-compatible-other", purl: other, license: "MIT" },
            { name: "voided-compatible-gpl-lib", purl: gpl, license: "GPL-3.0-only" },
            { name: "voided-compatible-mpl-lib", purl: mpl, license: "MPL-2.0" },
          ],
          dependencies: {
            ".": [judged, other],
            [judged]: [gpl, mpl],
            [other]: [gpl],
          },
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      gpl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "compatible:voided[0]",
    );
    assertClassificationOutcome(
      scoped,
      verdicts,
      mpl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "compatible:voided[0]",
    );

    const reason = findVerdict(verdicts, mpl, WORKSPACE)?.reason ?? "";

    assertClassification(
      reason.indexOf("voided-compatible-other → voided-compatible-gpl-lib") <
        reason.indexOf("as-dependency-of"),
      slug,
      "the reason leads with the chain and the package that arrives through it, before the entry's own terms - the package that carries the collateral failure is not the cause",
    );

    const problematic = section(doc, "## Problematic licenses");

    assertPlacement(
      problematic.includes("voided-compatible-gpl-lib") &&
        problematic.includes("voided-compatible-mpl-lib"),
      slug,
      "every package the entry governs in that workspace rows in Problematic licenses, not only the one that arrives around the judged introducer",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("voided-compatible-mpl-lib"),
      slug,
      "a voided package keeps its inventory row in Production dependencies",
    );
  },

  "invalid-justification": () => {
    const slug = "invalid-justification";
    const purl = "pkg:npm/choice-lib@1.0.0";
    const policy = [
      UNKNOWN_WARN,
      "[[clarify]]",
      'name = "choice-lib"',
      'version = "1.0.0"',
      'detected = { registry = "MIT OR Apache-2.0", intensive = "MIT" }',
      'justification = "dual-license-choice"',
      // A leaf no source states, so the assertion below can tell an applied expression from the
      // observed reading - both of which read "MIT OR Apache-2.0" without it.
      'expression = "MIT OR Apache-2.0 OR ISC"',
      "",
    ].join("\n");
    const { doc, verdicts, scoped } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            { name: "choice-lib", purl, license: "MIT OR Apache-2.0", intensive: "MIT" },
          ],
        },
      ],
      policy,
    );

    assertClassificationOutcome(
      scoped,
      verdicts,
      purl,
      WORKSPACE,
      slug,
      "app",
      "fail",
      "clarify:invalid[0]",
    );
    assertClassification(
      findVerdict(verdicts, purl, WORKSPACE)?.reason.includes("contradictory-claims-recorded") ===
        true,
      slug,
      "the failure names the values the entry can legally move to",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("choice-lib"),
      slug,
      "a clarify entry the current signal disproves is a fail verdict, so it rows in Problematic licenses",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("ISC"),
      slug,
      "the recorded detections still hold, so the entry's expression was applied and is what the row shows - the ISC leaf is in the entry and in no source",
    );
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("choice-lib"),
      slug,
      "the package keeps its inventory row in Production dependencies",
    );
  },
};

describe("dependency classification and report placement — Path index structural sync", () => {
  test("dependency-classification.md's Path index matches the suite", () => {
    const classificationIds = parseDocPathIndexIds(
      readDependencyClassificationDoc(),
      "dependency-classification.md",
    );
    const testIds = new Set<string>(PLACEMENT_PATHS);

    assertSlugSetsMatch(
      classificationIds,
      "dependency-classification.md",
      testIds,
      "the suite (PLACEMENT_PATHS)",
    );
  });

  test("report-placement.md's Path index matches the suite", () => {
    const placementIds = parseDocPathIndexIds(readReportPlacementDoc(), "report-placement.md");
    const testIds = new Set<string>(PLACEMENT_PATHS);

    assertSlugSetsMatch(
      placementIds,
      "report-placement.md",
      testIds,
      "the suite (PLACEMENT_PATHS)",
    );
  });

  test("both Path index intros state the number of rows the suite carries", () => {
    const stated = (doc: string, docLabel: string): number => {
      const match = /^The same (\d+) paths as\s*$/m.exec(doc);

      if (match?.[1] === undefined) {
        throw new Error(`${docLabel} is missing its "The same N paths as" Path index intro`);
      }

      return Number(match[1]);
    };
    const expectation = `the intro must state ${PLACEMENT_PATHS.length} paths, the number of rows PLACEMENT_PATHS carries`;

    assertStructural(
      stated(readDependencyClassificationDoc(), "dependency-classification.md") ===
        PLACEMENT_PATHS.length,
      "dependency-classification.md's Path index intro vs the suite",
      expectation,
    );
    assertStructural(
      stated(readReportPlacementDoc(), "report-placement.md") === PLACEMENT_PATHS.length,
      "report-placement.md's Path index intro vs the suite",
      expectation,
    );
  });

  test("dependency-classification.md and report-placement.md carry the same slug set", () => {
    const classificationIds = parseDocPathIndexIds(
      readDependencyClassificationDoc(),
      "dependency-classification.md",
    );
    const placementIds = parseDocPathIndexIds(readReportPlacementDoc(), "report-placement.md");

    assertSlugSetsMatch(
      classificationIds,
      "dependency-classification.md",
      placementIds,
      "report-placement.md",
    );
  });
});

describe("dependency classification and report placement — Path index E2E", () => {
  for (const path of PLACEMENT_PATHS) {
    test(path, () => {
      SCENARIOS[path]();
    });
  }
});

// ===========================================================================
// Cross-document invariants: THIRD_PARTY_LICENSES.md and THIRD_PARTY_NOTICES.md
// are two renderers over ONE model, and per report-placement.md and
// notices-placement.md must never disagree on what they both claim to show.
// The isUnknownLicense predicate (src/render/unknownLicense.ts) is the
// mechanism, but these tests never import it - they drive renderMarkdown and
// renderNotices from the same model and compare the rendered text, so a future
// change that keeps the predicate "consistent" but breaks a renderer's use of
// it still fails here.
// ===========================================================================

describe("cross-document invariants — LICENSES and NOTICES agree on one shared model", () => {
  const UNKNOWN_OR_IMPRECISE_WORKSPACE = "apps/mixed";

  /**
   * One workspace with four packages spanning every unknown-adjacent lane:
   * a known permissive license (must count as neither unknown nor imprecise),
   * a package with NO license claim at all (unknown), a LicenseRef-only
   * package (unknown via the ref-only rule, not a bare null expression), and
   * an imprecise bare-family label (present, NOT unknown - the negative case
   * this suite exists to guard).
   */
  function buildUnknownAdjacentScenario(): {
    doc: string;
    notices: string;
    scoped: CanonicalDependencies;
  } {
    const { doc, scoped } = buildScenario(
      [
        {
          targetIdentity: UNKNOWN_OR_IMPRECISE_WORKSPACE,
          components: [
            {
              name: "known-mit",
              purl: "pkg:npm/known-mit@1.0.0",
              license: "MIT",
            },
            { name: "unknown-null", purl: "pkg:npm/unknown-null@1.0.0" },
            {
              name: "unknown-ref",
              purl: "pkg:npm/unknown-ref@1.0.0",
              license: "LicenseRef-proprietary-eula",
            },
            {
              name: "imprecise-bsd",
              purl: "pkg:npm/imprecise-bsd@1.0.0",
              licenseName: "BSD",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );

    return { doc, notices: renderNotices(scoped), scoped };
  }

  test("unknown-agreement: a package counts unknown in LICENSES iff it rows in NOTICES' unknown section", () => {
    const { doc, notices } = buildUnknownAdjacentScenario();

    assertStructural(
      doc.includes("- Unknown license: 2"),
      "LICENSES unknown count vs the two genuinely-unknown packages",
      "known-mit (known) and imprecise-bsd (imprecise, present-but-ambiguous) must not count; only unknown-null and unknown-ref should",
    );
    assertStructural(
      notices.includes("- unknown-null@1.0.0 — unknown license, no text included") &&
        notices.includes("- unknown-ref@1.0.0 — unknown license, no text included"),
      "NOTICES unknown section vs the two genuinely-unknown packages",
      "both unknown-null (no claim) and unknown-ref (LicenseRef-only) must row in NOTICES' unknown section",
    );
    assertStructural(
      !notices.includes("known-mit") && !notices.includes("imprecise-bsd"),
      "NOTICES unknown section vs the two NON-unknown packages",
      "known-mit (known permissive) and imprecise-bsd (imprecise, not unknown) must never appear in NOTICES at all - the negative direction of the iff",
    );
  });

  test("every package NOTICES' unknown section lists also has an inventory row in LICENSES", () => {
    const { doc, notices } = buildUnknownAdjacentScenario();
    const unknownEntries = [...notices.matchAll(/^- (\S+)@\S+ — unknown license/gm)].map(
      (m) => m[1],
    );

    assertStructural(
      unknownEntries.length === 2,
      "NOTICES unknown section entry count",
      `expected exactly the two unknown packages, found: [${unknownEntries.join(", ")}]`,
    );
    for (const name of unknownEntries) {
      assertStructural(
        name !== undefined && doc.includes(name),
        `NOTICES entry "${name ?? "(unmatched)"}" vs the LICENSES inventory`,
        "every package NOTICES names must still keep its inventory row in LICENSES - nothing NOTICES lists is ever dropped from the inventory",
      );
    }
  });

  test("determinism: both documents are byte-stable across a double render of the same model", () => {
    const { scoped } = buildUnknownAdjacentScenario();
    const noticesA = renderNotices(scoped);
    const noticesB = renderNotices(scoped);
    const licensesA = renderMarkdown(scoped);
    const licensesB = renderMarkdown(scoped);

    assertStructural(
      noticesA === noticesB,
      "renderNotices double-render",
      "the same model must render byte-identical NOTICES output",
    );
    assertStructural(
      licensesA === licensesB,
      "renderMarkdown double-render",
      "the same model must render byte-identical LICENSES output",
    );
  });
});
