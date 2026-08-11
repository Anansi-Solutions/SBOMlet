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
import { mergeSboms } from "../src/merge/merge";
import { annotateFindings } from "../src/normalize/normalize";
import { applyContainerScopes } from "../src/pipeline/containerScope";
import { BUILTIN_OVERRIDES } from "../src/policy/builtinOverrides";
import { acceptedContainerNotices, evaluate } from "../src/policy/evaluate";
import { parsePolicy, type Policy } from "../src/policy/schema";
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
  "cross-image-claim-divergence",
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
    ...(licenses !== undefined ? { licenses } : {}),
    ...(spec.dev === true
      ? { properties: [{ name: "cdx:npm:package:development", value: "true" }] }
      : {}),
  };
}

function sbomDoc(components: ReadonlyArray<Record<string, unknown>>): unknown {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [...components],
  };
}

interface ScenarioInput {
  targetIdentity: string;
  /** Docker-image inputs pass "os"; a workspace input omits this (defaults app). */
  scope?: "os";
  components: ReadonlyArray<ComponentSpec>;
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

/** merge -> annotate -> resolve dev containers -> re-scope -> evaluate -> render. */
function buildScenario(inputs: ReadonlyArray<ScenarioInput>, policyToml: string): ScenarioResult {
  const merged = mergeSboms(
    inputs.map((input) => ({
      sbom: sbomDoc(input.components.map(sbomComponent)),
      targetIdentity: input.targetIdentity,
      ...(input.scope !== undefined ? { scope: input.scope } : {}),
    })),
  );
  const policy = parsePolicy(policyToml);
  const { model: annotated } = annotateFindings(merged, policy.clarify, BUILTIN_OVERRIDES);
  const developmentContainers = resolveDevelopmentContainers(annotated, policy);
  const scoped = applyContainerScopes(annotated, developmentContainers);
  const verdicts = evaluate(scoped, policy);
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
      `where = ["${PROD_CONTAINER}"]`,
      'reason = "reviewed and accepted for this image"',
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
      `where = ["${PROD_CONTAINER}"]`,
      'reason = "reviewed and accepted for this image"',
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
      `where = ["${OTHER_CONTAINER}"]`,
      'reason = "reviewed and accepted for this image only"',
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
      'reason = "would otherwise accept it"',
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
