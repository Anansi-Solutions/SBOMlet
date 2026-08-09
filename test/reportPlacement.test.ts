/**
 * Mirrors docs/reference/report-placement.md's Path index 1:1: one test per
 * slug below, plus a structural test asserting the correspondence holds exactly.
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
import { globToRegExp } from "../src/targets/discover";

const REPORT_PLACEMENT_DOC = join(
  import.meta.dir,
  "..",
  "docs",
  "reference",
  "report-placement.md",
);

/** Every path documented in the Path index, verified below one test each. */
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
  "suppressed-workspace-copyleft",
  "denied-license-terminal",
  "system-package-in-dev-container-counts-dev",
] as const;

type PlacementPath = (typeof PLACEMENT_PATHS)[number];

/** The closing sentence every placement/structural failure message shares. */
const RESOLUTION =
  "If the code broke the documented placement, fix the code; if the placement changed intentionally, update the doc and this suite in the same commit.";

function placementDivergence(slug: string, expectation: string): string {
  return `placement path "${slug}" diverged from docs/reference/report-placement.md — ${expectation}. ${RESOLUTION}`;
}

/** Throws a placementDivergence message naming `slug` when `condition` is false. */
function assertPlacement(
  condition: boolean,
  slug: string,
  expectation: string,
): void {
  if (!condition) throw new Error(placementDivergence(slug, expectation));
}

function readReportPlacementDoc(): string {
  return readFileSync(REPORT_PLACEMENT_DOC, "utf-8");
}

/** The `id` column of the doc's "## Path index" table, in row order. */
function parseDocPathIndexIds(doc: string): Set<string> {
  const heading = "## Path index (verified end to end)";
  const start = doc.indexOf(heading);
  if (start === -1) {
    throw new Error(`report-placement.md is missing its "${heading}" section`);
  }
  const ids = new Set<string>();
  for (const row of doc.slice(start).split(/\r?\n/)) {
    const match = /^\|\s*`([a-z0-9-]+)`\s*\|/.exec(row);
    if (match?.[1] !== undefined) ids.add(match[1]);
  }
  return ids;
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
      if (matcher.test(source))
        resolved.add(`${DOCKER_IDENTITY_PREFIX}${source}`);
    }
  }
  return resolved;
}

/** merge -> annotate -> resolve dev containers -> re-scope -> evaluate -> render. */
function buildScenario(
  inputs: ReadonlyArray<ScenarioInput>,
  policyToml: string,
): ScenarioResult {
  const merged = mergeSboms(
    inputs.map((input) => ({
      sbom: sbomDoc(input.components.map(sbomComponent)),
      targetIdentity: input.targetIdentity,
      ...(input.scope !== undefined ? { scope: input.scope } : {}),
    })),
  );
  const policy = parsePolicy(policyToml);
  const { model: annotated } = annotateFindings(
    merged,
    policy.clarify,
    BUILTIN_OVERRIDES,
  );
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
  return { doc: alignTables(renderMarkdown(scoped, policyView)), verdicts };
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "permissive-lib",
              purl: "pkg:npm/permissive-lib@1.0.0",
              license: "MIT",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "workspace-prod-permissive";
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes(
        "permissive-lib",
      ),
      slug,
      "an npm workspace production dependency with a permissive license rows in the Production dependencies app table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Development-only dependencies").includes(
        "permissive-lib",
      ),
      slug,
      "a production package must not row in the Development-only dependencies table",
    );
    assertPlacement(
      doc.includes("- Production packages: 1") &&
        doc.includes("- Development-only packages: 0"),
      slug,
      "the package-counts block counts the package under Production, not Development-only",
    );
  },

  "workspace-dev-only": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "dev-only-lib",
              purl: "pkg:npm/dev-only-lib@1.0.0",
              license: "MIT",
              dev: true,
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "workspace-dev-only";
    assertPlacement(
      appTableOnly(doc, "## Development-only dependencies").includes(
        "dev-only-lib",
      ),
      slug,
      "a workspace dependency that is dev at every occurrence rows in the Development-only dependencies app table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("dev-only-lib"),
      slug,
      "a development-only package must not row in the Production dependencies table",
    );
    assertPlacement(
      doc.includes("- Development-only packages: 1") &&
        doc.includes("- Production packages: 0"),
      slug,
      "the package-counts block counts the package under Development-only, not Production",
    );
  },

  "shared-workspace-and-container": () => {
    const purl = "pkg:npm/shared-lib@2.0.0";
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            { name: "shared-lib", purl, version: "2.0.0", license: "MIT" },
          ],
        },
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            { name: "shared-lib", purl, version: "2.0.0", license: "MIT" },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "shared-workspace-and-container";
    assertPlacement(
      appTableOnly(doc, "## Production dependencies").includes("shared-lib"),
      slug,
      "a package with a workspace occurrence rows in the Production dependencies app table (app wins over os)",
    );
    const { application } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      application.includes("shared-lib"),
      slug,
      "the same package also rows in its production container's Application packages table (the shared-in-both rule)",
    );
  },

  "container-only-system": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "system-pkg",
              purl: "pkg:apk/alpine/system-pkg@1.0.0",
              license: "MIT",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "container-only-system";
    const { system } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      system.includes("system-pkg"),
      slug,
      "an apk container-only package rows in its container's System packages table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes("system-pkg") &&
        !appTableOnly(doc, "## Development-only dependencies").includes(
          "system-pkg",
        ),
      slug,
      "a container-only system package must not row in either app table",
    );
  },

  "container-only-app-ecosystem": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "baked-npm-lib",
              purl: "pkg:npm/baked-npm-lib@1.0.0",
              license: "MIT",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "container-only-app-ecosystem";
    const { application } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      application.includes("baked-npm-lib"),
      slug,
      "an npm package baked into a container with no workspace occurrence rows in that container's Application packages table",
    );
    assertPlacement(
      !appTableOnly(doc, "## Production dependencies").includes(
        "baked-npm-lib",
      ) &&
        !appTableOnly(doc, "## Development-only dependencies").includes(
          "baked-npm-lib",
        ),
      slug,
      "a container-only application-ecosystem package must not row in either app table",
    );
  },

  "unrecognized-ecosystem-gates": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "mystery-pkg",
              purl: "pkg:mystery-eco/mystery-pkg@1.0.0",
              license: "GPL-3.0-only",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "unrecognized-ecosystem-gates";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("mystery-pkg"),
      slug,
      'a copyleft package on an unrecognized purl ecosystem baked into a production container fails "default:copyleft" and rows in Problematic (the allowlist fails safe)',
    );
    const { system, application } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      application.includes("mystery-pkg") && !system.includes("mystery-pkg"),
      slug,
      "the unrecognized ecosystem is treated as application-level, so it rows in the container's Application packages table, never System",
    );
  },

  "system-copyleft-os-warn": () => {
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "gpl-tool",
              purl: "pkg:apk/alpine/gpl-tool@1.0.0",
              license: "GPL-2.0-only",
            },
          ],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "warn"', ""].join("\n"),
    );
    const slug = "system-copyleft-os-warn";
    assertPlacement(
      verdicts.some(
        (v) =>
          v.purl.includes("gpl-tool") &&
          v.status === "warn" &&
          v.rule === "default:copyleft",
      ),
      slug,
      'os_dependencies = "warn" downgrades the system package\'s copyleft fail to a warn',
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
    const { system } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      system.includes("gpl-tool"),
      slug,
      "the package still rows in its container's System packages table",
    );
  },

  "system-copyleft-os-fail": () => {
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "gpl-tool",
              purl: "pkg:apk/alpine/gpl-tool@1.0.0",
              license: "GPL-2.0-only",
            },
          ],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "fail"', ""].join("\n"),
    );
    const slug = "system-copyleft-os-fail";
    assertPlacement(
      verdicts.some((v) => v.purl.includes("gpl-tool") && v.status === "fail"),
      slug,
      'os_dependencies = "fail" keeps the system package\'s copyleft verdict a fail',
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("gpl-tool"),
      slug,
      "the fail rows in Problematic licenses",
    );
  },

  "system-copyleft-os-ignore": () => {
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "gpl-tool",
              purl: "pkg:apk/alpine/gpl-tool@1.0.0",
              license: "GPL-2.0-only",
            },
          ],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "ignore"', ""].join("\n"),
    );
    const slug = "system-copyleft-os-ignore";
    assertPlacement(
      verdicts.some((v) => v.purl.includes("gpl-tool") && v.status === "ok"),
      slug,
      'os_dependencies = "ignore" downgrades the system package\'s copyleft verdict to ok',
    );
    assertPlacement(
      !section(doc, "## Problematic licenses").includes("gpl-tool") &&
        !section(doc, "## Copyleft and special notices").includes("gpl-tool"),
      slug,
      "an ignored os-scope copyleft package is neither Problematic nor a Copyleft notice",
    );
    const { system } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      system.includes("gpl-tool"),
      slug,
      "the package still rows in its container's System packages table (inventory only)",
    );
  },

  "system-agpl-escalates": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "agpl-daemon",
              purl: "pkg:apk/alpine/agpl-daemon@1.0.0",
              license: "AGPL-3.0-only",
            },
          ],
        },
      ],
      [UNKNOWN_WARN, "[os_dependencies]", 'handling = "warn"', ""].join("\n"),
    );
    const slug = "system-agpl-escalates";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("agpl-daemon"),
      slug,
      'an AGPL system package fails "default:agpl-container" even under os_dependencies = "warn" — the warn knob cannot soften the container AGPL escalation',
    );
  },

  "system-agpl-accepted-notice": () => {
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'name = "agpl-daemon"',
      `where = ["${PROD_CONTAINER}"]`,
      'reason = "reviewed and accepted for this image"',
      "",
    ].join("\n");
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "agpl-daemon",
              purl: "pkg:apk/alpine/agpl-daemon@1.0.0",
              license: "AGPL-3.0-only",
            },
          ],
        },
      ],
      policy,
    );
    const slug = "system-agpl-accepted-notice";
    const copyleft = section(doc, "## Copyleft and special notices");
    assertPlacement(
      copyleft.includes("agpl-daemon") &&
        copyleft.includes("accepted via compatible\\[0\\]"),
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "relay-imprecise",
              purl: "pkg:apk/alpine/relay-imprecise@1.0.0",
              licenseName: "GNU Affero General Public License",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "system-agpl-imprecise-escalates";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("relay-imprecise"),
      slug,
      'an imprecise bare-"AGPL" system package fails "default:agpl-container" and rows in Problematic',
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes(
        "relay-imprecise",
      ),
      slug,
      "it also rows in Imprecise licenses — the overlap with Problematic is by design",
    );
  },

  "system-agpl-imprecise-accepted": () => {
    const policy = [
      UNKNOWN_WARN,
      "[[compatible]]",
      'match = "package"',
      'name = "relay-imprecise"',
      `where = ["${PROD_CONTAINER}"]`,
      'reason = "reviewed and accepted for this image"',
      "",
    ].join("\n");
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "relay-imprecise",
              purl: "pkg:apk/alpine/relay-imprecise@1.0.0",
              licenseName: "GNU Affero General Public License",
            },
          ],
        },
      ],
      policy,
    );
    const slug = "system-agpl-imprecise-accepted";
    const copyleft = section(doc, "## Copyleft and special notices");
    assertPlacement(
      copyleft.includes("relay-imprecise") &&
        copyleft.includes("accepted via compatible\\[0\\]"),
      slug,
      "an accepted imprecise-AGPL system package renders as a non-blocking notice in Copyleft and special notices",
    );
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes(
        "relay-imprecise",
      ),
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            { name: "shared-agpl-daemon", purl, license: "AGPL-3.0-only" },
          ],
        },
        {
          targetIdentity: OTHER_CONTAINER,
          scope: "os",
          components: [
            { name: "shared-agpl-daemon", purl, license: "AGPL-3.0-only" },
          ],
        },
      ],
      policy,
    );
    const slug = "mixed-agpl-fail-and-accept";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("shared-agpl-daemon"),
      slug,
      "the unaccepted occurrence's fail rows the purl in Problematic",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes(
        "shared-agpl-daemon",
      ),
      slug,
      "a purl already in Problematic never also shows an accepted-AGPL notice",
    );
  },

  "app-copyleft-prod-container": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: PROD_CONTAINER,
          scope: "os",
          components: [
            {
              name: "metrics-tool",
              purl: "pkg:golang/metrics-tool@1.0.0",
              license: "GPL-3.0-only",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "app-copyleft-prod-container";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("metrics-tool"),
      slug,
      "a golang copyleft package baked into a production container fails default:copyleft and rows in Problematic",
    );
    const { application } = containerPartition(
      containerSubsection(doc, PROD_CONTAINER),
    );
    assertPlacement(
      application.includes("metrics-tool"),
      slug,
      "it also rows in its container's Application packages table",
    );
  },

  "app-copyleft-dev-container": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: DEV_CONTAINER,
          scope: "os",
          components: [
            {
              name: "dev-tool-lib",
              purl: "pkg:npm/dev-tool-lib@1.0.0",
              license: "LGPL-2.1-or-later",
            },
          ],
        },
      ],
      DEV_CONTAINER_POLICY,
    );
    const slug = "app-copyleft-dev-container";
    assertPlacement(
      section(doc, "## Copyleft and special notices").includes("dev-tool-lib"),
      slug,
      "an app-ecosystem copyleft package in a [[docker.development]] container dev-downgrades to a Copyleft flagged row",
    );
    const devSection = section(doc, "## Development-only dependencies");
    assertPlacement(
      devSection.includes(`### Container: ${DEV_CONTAINER}`) &&
        devSection.includes("dev-tool-lib"),
      slug,
      "its container subsection sits under Development-only dependencies",
    );
  },

  "app-copyleft-workspace-dev": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "doc-tool",
              purl: "pkg:npm/doc-tool@1.0.0",
              license: "LGPL-2.1-or-later",
              dev: true,
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "app-copyleft-workspace-dev";
    assertPlacement(
      section(doc, "## Copyleft and special notices").includes("doc-tool"),
      slug,
      "a workspace dev-dependency copyleft package dev-downgrades to warn and rows in Copyleft and special notices",
    );
    assertPlacement(
      appTableOnly(doc, "## Development-only dependencies").includes(
        "doc-tool",
      ),
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "prod-copyleft",
              purl: "pkg:npm/prod-copyleft@1.0.0",
              license: "GPL-3.0-only",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "problematic-dedup-keeps-inventory";
    assertPlacement(
      section(doc, "## Problematic licenses").includes("prod-copyleft"),
      slug,
      "a workspace production copyleft package fails default:copyleft and rows in Problematic",
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes(
        "prod-copyleft",
      ),
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "bare-gpl-lib",
              purl: "pkg:npm/bare-gpl-lib@1.0.0",
              licenseName: "GPL",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "imprecise-copyleft-family-only-imprecise";
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes(
        "bare-gpl-lib",
      ),
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
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "bare-bsd-lib",
              purl: "pkg:npm/bare-bsd-lib@1.0.0",
              licenseName: "BSD",
            },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "imprecise-permissive-family";
    assertPlacement(
      section(doc, "## Imprecise licenses (review / disambiguate)").includes(
        "bare-bsd-lib",
      ),
      slug,
      'a bare "BSD" app package warns "default:imprecise" and rows in Imprecise licenses only',
    );
    assertPlacement(
      !section(doc, "## Copyleft and special notices").includes(
        "bare-bsd-lib",
      ) && !section(doc, "## Problematic licenses").includes("bare-bsd-lib"),
      slug,
      "a known-permissive imprecise family never rows in Copyleft or Problematic",
    );
  },

  "unknown-license-counted": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            { name: "unknown-lib", purl: "pkg:npm/unknown-lib@1.0.0" },
          ],
        },
      ],
      UNKNOWN_WARN,
    );
    const slug = "unknown-license-counted";
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

  "suppressed-workspace-copyleft": () => {
    const suppressedWorkspace = "libs/shared";
    const policy = [
      UNKNOWN_WARN,
      "[[workspace.copyleft_suppressed]]",
      `path = "${suppressedWorkspace}"`,
      'license = "AGPL-3.0-only"',
      'description = "the workspace itself is AGPL-3.0-only, absorbing its bundled GNU-family dependencies"',
      "",
    ].join("\n");
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: suppressedWorkspace,
          components: [
            {
              name: "gpl-inside-agpl-workspace",
              purl: "pkg:npm/gpl-inside-agpl-workspace@1.0.0",
              license: "GPL-3.0-only",
            },
          ],
        },
      ],
      policy,
    );
    const slug = "suppressed-workspace-copyleft";
    assertPlacement(
      verdicts.some(
        (v) =>
          v.purl.includes("gpl-inside-agpl-workspace") &&
          v.status === "suppressed",
      ),
      slug,
      "a family-justified workspace copyleft suppression status is suppressed, not fail or warn",
    );
    const copyleft = section(doc, "## Copyleft and special notices");
    assertPlacement(
      copyleft.includes(suppressedWorkspace) &&
        copyleft.includes("AGPL-3.0-only"),
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
    const { doc, verdicts } = buildScenario(
      [
        {
          targetIdentity: WORKSPACE,
          components: [
            {
              name: "denied-pkg",
              purl: "pkg:npm/denied-pkg@1.0.0",
              license: "MIT",
            },
          ],
        },
      ],
      policy,
    );
    const slug = "denied-license-terminal";
    assertPlacement(
      verdicts.some(
        (v) =>
          v.purl.includes("denied-pkg") &&
          v.status === "fail" &&
          v.rule.startsWith("denied["),
      ),
      slug,
      "a [[deny]] match fails even though a [[compatible]] rule would otherwise have accepted it (deny is terminal)",
    );
    assertPlacement(
      section(doc, "## Problematic licenses").includes("denied-pkg"),
      slug,
      "the denied verdict rows in Problematic",
    );
  },

  "system-package-in-dev-container-counts-dev": () => {
    const { doc } = buildScenario(
      [
        {
          targetIdentity: DEV_CONTAINER,
          scope: "os",
          components: [
            {
              name: "sys-in-dev-container",
              purl: "pkg:apk/alpine/sys-in-dev-container@1.0.0",
              license: "MIT",
            },
          ],
        },
      ],
      DEV_CONTAINER_POLICY,
    );
    const slug = "system-package-in-dev-container-counts-dev";
    assertPlacement(
      doc.includes("- Development-only packages: 1") &&
        doc.includes("- Production packages: 0"),
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
};

describe("report placement — Path index structural sync", () => {
  test("PLACEMENT_PATHS and the doc's Path index table cover the exact same slugs", () => {
    const docIds = parseDocPathIndexIds(readReportPlacementDoc());
    const testIds = new Set<string>(PLACEMENT_PATHS);
    const docOnly = [...docIds].filter((id) => !testIds.has(id));
    const testOnly = [...testIds].filter((id) => !docIds.has(id));
    assertPlacement(
      docOnly.length === 0,
      docOnly[0] ?? "(none)",
      `every doc row must have a matching test; doc-only ids with no test: [${docOnly.join(", ")}]`,
    );
    assertPlacement(
      testOnly.length === 0,
      testOnly[0] ?? "(none)",
      `every test must have a matching doc row; test-only ids with no doc row: [${testOnly.join(", ")}]`,
    );
  });
});

describe("report placement — Path index E2E (1:1 with docs/reference/report-placement.md)", () => {
  for (const path of PLACEMENT_PATHS) {
    test(path, () => {
      SCENARIOS[path]();
    });
  }
});
