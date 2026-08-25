import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  asRawLicense,
  DOCKER_IDENTITY_PREFIX,
  type CanonicalDependencies,
  type PackageEntry,
} from "../src/model/dependencies";
import { mergeSboms } from "../src/merge/merge";
import { annotateFindings } from "../src/normalize/normalize";
import { applyContainerScopes } from "../src/pipeline/containerScope";
import { BUILTIN_OVERRIDES } from "../src/policy/engine/builtinOverrides";
import { acceptedContainerNotices, evaluate } from "../src/policy/engine/evaluate";
import { parsePolicy } from "../src/policy/parse/parse";
import { alignTables } from "../src/render/alignTables";
import { renderMarkdown, type PolicyView } from "../src/render/markdown";
import { globToRegExp } from "../src/targets/discover";
import { asPurl, asRelativePath } from "./brandTestSupport";
import type { Policy } from "../src/policy/schema";

/** No scanned target in these scenarios is collected by a lane that derives a dependency graph. */
const WITHOUT_DEPENDENCY_GRAPHS: ReadonlySet<string> = new Set();

/**
 * A synthetic scenario shaped like the real-world report that motivated the
 * container-aware restructure: a monorepo with one app workspace and two
 * containers, exercising multi-container dedup, the AGPL container
 * exception (precise and imprecise), and glob-based development marking.
 * Every identifier below is invented or a generic public shape — no
 * consumer-identifying string appears anywhere in this file.
 */

const API_CONTAINER = `${DOCKER_IDENTITY_PREFIX}services/api/Dockerfile`;
const BUILD_CONTAINER = `${DOCKER_IDENTITY_PREFIX}tools/build/Dockerfile`;
const APP_TARGET = "apps/web";

const POLICY_TOML = [
  "[unknown]",
  'handling = "fail"',
  "",
  "[os_dependencies]",
  'handling = "warn"',
  "",
  "[[docker.development]]",
  'source = "tools/**"',
  'reason = "the build container only runs CI tooling and is never shipped"',
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "coreutils"',
  'as-dependency-of = ["self"]',
  'rationale = "os-package-unmodified"',
  `where = ["${API_CONTAINER}"]`,
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "licensed-daemon"',
  'as-dependency-of = ["self"]',
  'rationale = "license-reviewed"',
  `where = ["${API_CONTAINER}"]`,
  'comment = "AGPL network-copyleft obligation accepted for the api image"',
  "",
  "[[compatible]]",
  'match = "package"',
  'name = "licensed-relay"',
  'as-dependency-of = ["self"]',
  'rationale = "license-reviewed"',
  `where = ["${API_CONTAINER}"]`,
  'comment = "imprecise AGPL family accepted for the api image"',
  "",
].join("\n");

/** Hand-built PackageEntry with sensible defaults, mirroring render.test.ts. */
function entry(
  partial: Partial<PackageEntry> & Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: APP_TARGET, isDevDependency: false }],
    licenseClaims: [],
    scope: "app",
    ...partial,
  };
}

const bash = entry({
  purl: asPurl("pkg:deb/bash@5.2-6"),
  name: "bash",
  version: "5.2-6",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("GPL-3.0-or-later"), kind: "spdx-id", source: "generator" }],
});

const libc6 = entry({
  purl: asPurl("pkg:deb/libc6@2.36-9"),
  name: "libc6",
  version: "2.36-9",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("LGPL-2.1-or-later"), kind: "spdx-id", source: "generator" }],
});

const coreutils = entry({
  purl: asPurl("pkg:deb/coreutils@9.1-1"),
  name: "coreutils",
  version: "9.1-1",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("GPL-3.0-or-later"), kind: "spdx-id", source: "generator" }],
});

/** Shared across BOTH containers — must row in each container's subsection. */
const zlib = entry({
  purl: asPurl("pkg:deb/zlib1g@1.2.13-1"),
  name: "zlib1g",
  version: "1.2.13-1",
  scope: "os",
  occurrences: [
    { target: API_CONTAINER, isDevDependency: false },
    { target: BUILD_CONTAINER, isDevDependency: false },
  ],
  licenseClaims: [{ raw: asRawLicense("Zlib"), kind: "spdx-id", source: "generator" }],
});

/**
 * Precise AGPL in the production container, application ecosystem (golang
 * is not on the OS-package allowlist) — escalates via default:copyleft, the
 * normal application-dependency path, never default:agpl-container (that
 * rule is reserved for a SYSTEM package; see diagTools below, same
 * container, opposite ecosystem).
 */
const metricsDaemon = entry({
  purl: asPurl("pkg:golang/metrics-daemon@1.2.0"),
  name: "metrics-daemon",
  version: "1.2.0",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("AGPL-3.0-only"), kind: "spdx-id", source: "generator" }],
});

/**
 * System-package AGPL in the SAME production container as metricsDaemon —
 * the discriminator's other half. An OS-allowlist ecosystem (apk) still
 * escalates via the routine container AGPL rule, default:agpl-container,
 * even though it carries the same license family as metricsDaemon: the two
 * packages land on different rules and in different container sub-tables
 * purely because of ecosystem, not because of anything else in the fixture.
 */
const diagTools = entry({
  purl: asPurl("pkg:apk/diag-tools@3.0.1"),
  name: "diag-tools",
  version: "3.0.1",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("AGPL-3.0-only"), kind: "spdx-id", source: "generator" }],
});

/**
 * Precise AGPL system package in the SAME production container, ACCEPTED via
 * a scoped `[[compatible]]` package rule (compatible[1]) — the discriminator
 * against diagTools (the same obligation, unaccepted, above): the accepted
 * occurrence surfaces as a non-blocking special notice instead of vanishing,
 * never in Problematic and never counted toward the copyleft warning total.
 */
const licensedDaemon = entry({
  purl: asPurl("pkg:deb/licensed-daemon@2.1.0"),
  name: "licensed-daemon",
  version: "2.1.0",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("AGPL-3.0-only"), kind: "spdx-id", source: "generator" }],
});

/**
 * Imprecise "AGPL" family system package, ACCEPTED via a scoped
 * `[[compatible]]` package rule (compatible[2]) — the imprecise counterpart
 * to licensedDaemon: an accepted imprecise AGPL family obligation surfaces as
 * the same kind of special notice as the precise case.
 */
const licensedRelay = entry({
  purl: asPurl("pkg:apk/licensed-relay@1.0.0"),
  name: "licensed-relay",
  version: "1.0.0",
  scope: "os",
  occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
  licenseClaims: [
    {
      raw: asRawLicense("GNU Affero General Public License"),
      kind: "name",
      source: "generator",
    },
  ],
});

/**
 * Imprecise AGPL in the development container — a name-kind claim that
 * normalizes to the bare "AGPL" family, escalating via the same
 * default:agpl-container rule as the precise case (impreciseVerdict).
 */
const relayAgent = entry({
  purl: asPurl("pkg:golang/relay-agent@0.4.0"),
  name: "relay-agent",
  version: "0.4.0",
  scope: "os",
  occurrences: [{ target: BUILD_CONTAINER, isDevDependency: false }],
  licenseClaims: [
    {
      raw: asRawLicense("GNU Affero General Public License"),
      kind: "name",
      source: "generator",
    },
  ],
});

/**
 * Precise application-ecosystem copyleft in the DEV-marked container — the
 * dev-downgraded counterpart to metricsDaemon's production fail: the same
 * default:copyleft rule and the same AGPL family, but the dev-only
 * occurrence warns instead of failing. Precise (unlike relayAgent's bare
 * "AGPL" family label), so it is a default:copyleft warn — it lands in the
 * Copyleft and special notices section, not the Imprecise review section.
 */
const cacheRelay = entry({
  purl: asPurl("pkg:pypi/cache-relay@0.9.0"),
  name: "cache-relay",
  version: "0.9.0",
  scope: "os",
  occurrences: [{ target: BUILD_CONTAINER, isDevDependency: false }],
  licenseClaims: [{ raw: asRawLicense("AGPL-3.0-only"), kind: "spdx-id", source: "generator" }],
});

/**
 * App-level production copyleft failure — sharp-shaped: transitive, with an
 * introduction path, so it exercises the Why-cell provenance rendering too.
 */
const chartRender = entry({
  purl: asPurl("pkg:npm/chart-render@2.3.1"),
  name: "chart-render",
  version: "2.3.1",
  occurrences: [
    {
      target: APP_TARGET,
      isDevDependency: false,
      introduction: {
        direct: false,
        introducedBy: ["pkg:npm/dashboard-kit@1.0.0"],
        path: [
          "pkg:npm/web-root@1.0.0",
          "pkg:npm/dashboard-kit@1.0.0",
          "pkg:npm/chart-render@2.3.1",
        ],
      },
    },
  ],
  licenseClaims: [{ raw: asRawLicense("LGPL-3.0-or-later"), kind: "spdx-id", source: "generator" }],
});

/** App-level dev-only copyleft warn — the obligation that must stay in Copyleft. */
const docGen = entry({
  purl: asPurl("pkg:npm/doc-gen@1.0.0"),
  name: "doc-gen",
  version: "1.0.0",
  occurrences: [{ target: APP_TARGET, isDevDependency: true }],
  licenseClaims: [{ raw: asRawLicense("LGPL-2.1-or-later"), kind: "spdx-id", source: "generator" }],
});

const rawModel: CanonicalDependencies = {
  packages: [
    bash,
    libc6,
    coreutils,
    zlib,
    metricsDaemon,
    diagTools,
    licensedDaemon,
    licensedRelay,
    relayAgent,
    cacheRelay,
    chartRender,
    docGen,
  ],
};

/**
 * Resolve PolicyView.developmentContainers the SAME way the pipeline does
 * (pipeline.ts#resolveDevelopmentContainers): match each
 * [[docker.development]] glob against the analyzed container sources via the
 * REAL globToRegExp matcher — the same one [docker].ignore uses. Locks the
 * ignore-dialect semantics (`**` crosses segments) live, rather than
 * hand-asserting the resolved set. Occurrence-keyed (any scope), mirroring
 * the pipeline's resolution — this runs BEFORE the container re-scope
 * transform, on the still-"os"-scoped model.
 */
function resolveDevelopmentContainersForTest(
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
 * Build the rendered document through the real engine, end to end — merge
 * (via the hand-built model) -> annotate -> resolve the development set once
 * -> the container re-scope transform -> evaluate -> render, the SAME order
 * pipeline.ts#buildOutputs wires.
 */
function renderScenario(): string {
  const policy = parsePolicy(POLICY_TOML);
  const { model: annotated } = annotateFindings(rawModel, policy.clarify, BUILTIN_OVERRIDES);
  const developmentContainers = resolveDevelopmentContainersForTest(annotated, policy);
  const scoped = applyContainerScopes(annotated, developmentContainers);
  const verdicts = evaluate(scoped, policy, WITHOUT_DEPENDENCY_GRAPHS);
  const policyView: PolicyView = {
    policyPath: asRelativePath("policy.toml"),
    suppressedWorkspaces: policy.suppressedWorkspaces,
    verdicts,
    developmentContainers,
    acceptedContainerNotices: acceptedContainerNotices(scoped, verdicts),
  };

  return alignTables(renderMarkdown(scoped, policyView));
}

function golden(name: string): string {
  return readFileSync(join(import.meta.dir, "golden", name), "utf-8");
}

/** Collapse alignTables' column padding so a row can be matched by content. */
const squish = (s: string): string => s.replace(/ {2,}/g, " ");

/** Slice one "## Heading" section out of the document, up to the next "## ". */
function section(doc: string, heading: string): string {
  const start = doc.indexOf(heading);

  expect(start).toBeGreaterThanOrEqual(0);
  const rest = doc.slice(start + heading.length);
  const nextHeadingOffset = rest.indexOf("\n## ");

  return nextHeadingOffset === -1 ? rest : rest.slice(0, nextHeadingOffset);
}

describe("containerReport — multi-container golden scenario", () => {
  test("locked byte-golden against the real engine (parsePolicy + evaluate + renderMarkdown + alignTables)", () => {
    expect(renderScenario()).toBe(golden("container-report.md"));
  });

  test("determinism: rendering twice produces byte-identical output", () => {
    expect(renderScenario()).toBe(renderScenario());
  });

  describe("invariant: at-most-once across {Problematic, Copyleft}", () => {
    test("the precise-AGPL container package is in Problematic and NOT in Copyleft", () => {
      const doc = renderScenario();

      expect(section(doc, "## Problematic licenses").includes("metrics-daemon")).toBe(true);
      expect(section(doc, "## Copyleft and special notices").includes("metrics-daemon")).toBe(
        false,
      );
    });

    test("the imprecise-AGPL application-ecosystem package (a dev-marked container) warns via default:imprecise-copyleft — it is NOT a fail, so it never reaches Problematic", () => {
      // Corrected routing: golang is an application ecosystem, not the
      // OS-package allowlist, so relay-agent gates like an application
      // dependency rather than the routine container AGPL escalation. Its
      // imprecise "AGPL" family label routes through the normal
      // could-be-copyleft review lane (a warn), never default:agpl-container.
      const policy = parsePolicy(POLICY_TOML);
      const { model: annotated } = annotateFindings(rawModel, policy.clarify, BUILTIN_OVERRIDES);
      const scoped = applyContainerScopes(
        annotated,
        resolveDevelopmentContainersForTest(annotated, policy),
      );
      const relayAgentVerdict = evaluate(scoped, policy, WITHOUT_DEPENDENCY_GRAPHS).find(
        (v) => v.purl === "pkg:golang/relay-agent@0.4.0",
      );

      expect(relayAgentVerdict?.status).toBe("warn");
      expect(relayAgentVerdict?.rule).toBe("default:imprecise-copyleft");

      const doc = renderScenario();

      expect(section(doc, "## Problematic licenses").includes("relay-agent")).toBe(false);
      // Not in the detailed Copyleft table either (that table is scoped to
      // rule === "default:copyleft" exactly) — it surfaces in the dedicated
      // Imprecise-licenses review section instead (asserted elsewhere).
      expect(section(doc, "## Copyleft and special notices").includes("relay-agent")).toBe(false);
    });

    test("the app-level copyleft failure is in Problematic and NOT in Copyleft", () => {
      const doc = renderScenario();

      expect(section(doc, "## Problematic licenses").includes("chart-render")).toBe(true);
      expect(section(doc, "## Copyleft and special notices").includes("chart-render")).toBe(false);
    });

    test("the app-level dev-only warn stays in Copyleft and is NOT in Problematic", () => {
      const doc = renderScenario();

      expect(section(doc, "## Copyleft and special notices").includes("doc-gen")).toBe(true);
      expect(section(doc, "## Problematic licenses").includes("doc-gen")).toBe(false);
    });

    test("routine container copyleft (bash, libc6) never surfaces in Copyleft or Problematic", () => {
      const doc = renderScenario();
      const copyleft = section(doc, "## Copyleft and special notices");
      const problematic = section(doc, "## Problematic licenses");

      for (const name of ["bash", "libc6"]) {
        expect(copyleft.includes(name)).toBe(false);
        expect(problematic.includes(name)).toBe(false);
      }
    });

    test("the system-package AGPL (diag-tools) is in Problematic and NOT in Copyleft", () => {
      const doc = renderScenario();

      expect(section(doc, "## Problematic licenses").includes("diag-tools")).toBe(true);
      expect(section(doc, "## Copyleft and special notices").includes("diag-tools")).toBe(false);
    });

    test("the dev-marked application-ecosystem copyleft (cache-relay) is in Copyleft and NOT in Problematic", () => {
      const doc = renderScenario();

      expect(section(doc, "## Copyleft and special notices").includes("cache-relay")).toBe(true);
      expect(section(doc, "## Problematic licenses").includes("cache-relay")).toBe(false);
    });
  });

  describe("invariant: an accepted container AGPL obligation is a non-blocking notice, not Problematic and not the copyleft table", () => {
    test("the precise-AGPL accepted system package (licensed-daemon) is a Copyleft-section notice, NOT in Problematic, and NOT in the flagged copyleft table", () => {
      const doc = renderScenario();
      const copyleft = section(doc, "## Copyleft and special notices");

      expect(copyleft.includes("licensed-daemon")).toBe(true);
      expect(section(doc, "## Problematic licenses").includes("licensed-daemon")).toBe(false);
      // Not a flagged-copyleft ROW (that table is scoped to rule ===
      // "default:copyleft"); it is the special-notice bullet list instead.
      expect(copyleft.includes("accepted via compatible\\[1\\]")).toBe(true);
    });

    test("the imprecise-AGPL accepted system package (licensed-relay) is ALSO a Copyleft-section notice, NOT in Problematic", () => {
      const doc = renderScenario();
      const copyleft = section(doc, "## Copyleft and special notices");

      expect(copyleft.includes("licensed-relay")).toBe(true);
      expect(section(doc, "## Problematic licenses").includes("licensed-relay")).toBe(false);
      expect(copyleft.includes("accepted via compatible\\[2\\]")).toBe(true);
    });

    test("an accepted container AGPL notice does NOT count toward the copyleft warning roll-up (the roll-up count is unchanged by adding two accepted-ok packages)", () => {
      const doc = renderScenario();
      const problematic = section(doc, "## Problematic licenses");

      // Same "5 copyleft warning(s)" total as before the two accepted AGPL
      // packages were added — their verdict status is "ok", never "warn".
      expect(problematic.includes("5 copyleft warning(s)")).toBe(true);
    });

    test("acceptedContainerNotices(scoped, verdicts) reports exactly the two accepted packages, sorted by purl, and excludes the failing diag-tools/metrics-daemon", () => {
      const policy = parsePolicy(POLICY_TOML);
      const { model: annotated } = annotateFindings(rawModel, policy.clarify, BUILTIN_OVERRIDES);
      const scoped = applyContainerScopes(
        annotated,
        resolveDevelopmentContainersForTest(annotated, policy),
      );
      const verdicts = evaluate(scoped, policy, WITHOUT_DEPENDENCY_GRAPHS);
      const notices = acceptedContainerNotices(scoped, verdicts);

      // Sorted by purl: asPurl("pkg:apk/...") < "pkg:deb/..." (apk before deb).
      expect(notices.map((n) => n.name)).toEqual(["licensed-relay", "licensed-daemon"]);
      expect(notices.every((n) => n.rule.startsWith("compatible["))).toBe(true);
    });
  });

  describe("invariant: inventory completeness", () => {
    test("the precise-AGPL package still rows in the api container's subsection", () => {
      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);

      expect(apiSection.includes("metrics-daemon")).toBe(true);
    });

    test("the imprecise-AGPL package rows in the build container's subsection AND the Imprecise review section", () => {
      const doc = renderScenario();
      const buildSection = section(doc, `### Container: ${BUILD_CONTAINER}`);

      expect(buildSection.includes("relay-agent")).toBe(true);
      expect(
        section(doc, "## Imprecise licenses (review / disambiguate)").includes("relay-agent"),
      ).toBe(true);
    });

    test("the app-level failure still rows in the Production dependencies table", () => {
      const doc = renderScenario();

      expect(section(doc, "## Production dependencies").includes("chart-render")).toBe(true);
    });

    test("routine GPL packages row only in their container subsection, never in a summary table", () => {
      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);

      expect(apiSection.includes("bash")).toBe(true);
      expect(apiSection.includes("coreutils")).toBe(true);
      // The [[compatible]] escape hatch renders ok, and the package still
      // rows in its container's subsection.
      expect(section(doc, "## Problematic licenses").includes("coreutils")).toBe(false);
    });

    test("the [[compatible]] where-scoped acceptance decides coreutils via compatible[0], not a fail", () => {
      const policy = parsePolicy(POLICY_TOML);
      const { model: annotated } = annotateFindings(rawModel, policy.clarify, BUILTIN_OVERRIDES);
      const coreutilsVerdict = evaluate(annotated, policy, WITHOUT_DEPENDENCY_GRAPHS).find(
        (v) => v.purl === "pkg:deb/coreutils@9.1-1",
      );

      expect(coreutilsVerdict?.status).toBe("ok");
      expect(coreutilsVerdict?.rule).toBe("compatible[0]");
    });

    test("a package shared by both containers rows in EACH container's own subsection", () => {
      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);
      const buildSection = section(doc, `### Container: ${BUILD_CONTAINER}`);

      expect(apiSection.includes("zlib1g")).toBe(true);
      expect(buildSection.includes("zlib1g")).toBe(true);
    });

    test("the system-package AGPL rows in the api container's System table AND in Problematic", () => {
      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);
      const systemPos = apiSection.indexOf("**System packages**");
      const applicationPos = apiSection.indexOf("**Application packages**");
      const systemBlock = apiSection.slice(systemPos, applicationPos);

      expect(systemBlock.includes("diag-tools")).toBe(true);
      expect(section(doc, "## Problematic licenses").includes("diag-tools")).toBe(true);
    });

    test("the dev-marked application-ecosystem copyleft rows in the build container's Application table AND in Copyleft", () => {
      const doc = renderScenario();
      const buildSection = section(doc, `### Container: ${BUILD_CONTAINER}`);
      const applicationPos = buildSection.indexOf("**Application packages**");
      const applicationBlock = buildSection.slice(applicationPos);

      expect(applicationBlock.includes("cache-relay")).toBe(true);
      expect(section(doc, "## Copyleft and special notices").includes("cache-relay")).toBe(true);
    });
  });

  describe("invariant: the discriminator is ecosystem, not scope", () => {
    test("the system package and the application-ecosystem package in the SAME production container get DIFFERENT verdict rules and land in different sub-tables", () => {
      const policy = parsePolicy(POLICY_TOML);
      const { model: annotated } = annotateFindings(rawModel, policy.clarify, BUILTIN_OVERRIDES);
      const scoped = applyContainerScopes(
        annotated,
        resolveDevelopmentContainersForTest(annotated, policy),
      );
      const verdicts = evaluate(scoped, policy, WITHOUT_DEPENDENCY_GRAPHS);
      const diagToolsVerdict = verdicts.find((v) => v.purl === "pkg:apk/diag-tools@3.0.1");
      const metricsDaemonVerdict = verdicts.find(
        (v) => v.purl === "pkg:golang/metrics-daemon@1.2.0",
      );

      expect(diagToolsVerdict?.status).toBe("fail");
      expect(diagToolsVerdict?.rule).toBe("default:agpl-container");
      expect(metricsDaemonVerdict?.status).toBe("fail");
      expect(metricsDaemonVerdict?.rule).toBe("default:copyleft");
      expect(diagToolsVerdict?.rule).not.toBe(metricsDaemonVerdict?.rule);

      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);
      const systemPos = apiSection.indexOf("**System packages**");
      const applicationPos = apiSection.indexOf("**Application packages**");
      const systemBlock = apiSection.slice(systemPos, applicationPos);
      const applicationBlock = apiSection.slice(applicationPos);

      expect(systemBlock.includes("diag-tools")).toBe(true);
      expect(systemBlock.includes("metrics-daemon")).toBe(false);
      expect(applicationBlock.includes("metrics-daemon")).toBe(true);
      expect(applicationBlock.includes("diag-tools")).toBe(false);
    });
  });

  describe("invariant: per-container System/Application split is exhaustive and non-overlapping", () => {
    test("the api container's System and Application tables partition its package set", () => {
      const doc = renderScenario();
      const apiSection = section(doc, `### Container: ${API_CONTAINER}`);
      const systemPos = apiSection.indexOf("**System packages**");
      const applicationPos = apiSection.indexOf("**Application packages**");
      const systemBlock = apiSection.slice(systemPos, applicationPos);
      const applicationBlock = apiSection.slice(applicationPos);

      for (const name of ["bash", "coreutils", "libc6", "zlib1g", "diag-tools"]) {
        expect(systemBlock.includes(name)).toBe(true);
        expect(applicationBlock.includes(name)).toBe(false);
      }

      expect(applicationBlock.includes("metrics-daemon")).toBe(true);
      expect(systemBlock.includes("metrics-daemon")).toBe(false);
    });

    test("the build container's System and Application tables partition its package set", () => {
      const doc = renderScenario();
      const buildSection = section(doc, `### Container: ${BUILD_CONTAINER}`);
      const systemPos = buildSection.indexOf("**System packages**");
      const applicationPos = buildSection.indexOf("**Application packages**");
      const systemBlock = buildSection.slice(systemPos, applicationPos);
      const applicationBlock = buildSection.slice(applicationPos);

      expect(systemBlock.includes("zlib1g")).toBe(true);
      expect(systemBlock.includes("relay-agent")).toBe(false);
      expect(systemBlock.includes("cache-relay")).toBe(false);
      for (const name of ["relay-agent", "cache-relay"]) {
        expect(applicationBlock.includes(name)).toBe(true);
        expect(systemBlock.includes(name)).toBe(false);
      }
    });
  });

  test("the Containers index names both identities, the glob-resolved classification, and a package count", () => {
    const doc = renderScenario();
    const containers = squish(section(doc, "## Containers"));

    expect(containers.includes(`| ${API_CONTAINER} | production | 8 |`)).toBe(true);
    expect(containers.includes(`| ${BUILD_CONTAINER} | development | 3 |`)).toBe(true);
  });

  test("the dev container's packages fold under Development-only, not a standalone Docker section", () => {
    const doc = renderScenario();

    expect(doc.includes("## Docker image packages")).toBe(false);
    const devSection = section(doc, "## Development-only dependencies");

    expect(devSection.includes(`### Container: ${BUILD_CONTAINER}`)).toBe(true);
    expect(devSection.includes("relay-agent")).toBe(true);
    expect(devSection.includes("cache-relay")).toBe(true);
    expect(devSection.includes("zlib1g")).toBe(true);
  });
});

// ===========================================================================
// A package shared between a real workspace occurrence and a docker
// occurrence, through the actual pipeline path: mergeSboms' own
// app-wins-over-os scope reconciliation feeding the container re-scope
// transform, not a hand-built PackageEntry. Locks that the shared package's
// docker occurrence still dev-marks under [[docker.development]] even
// though merge already settled its scope to "app" before the transform ever
// sees it.
// ===========================================================================

describe("a shared workspace+docker package through the real merge/scope/evaluate/render path", () => {
  const SHARED_PURL = "pkg:npm/shared-workspace-and-image@2.0.0";
  const WORKSPACE_TARGET = "apps/dashboard";

  function sharedCopyleftDoc(): unknown {
    return {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        {
          type: "library",
          name: "shared-workspace-and-image",
          version: "2.0.0",
          purl: SHARED_PURL,
          licenses: [{ license: { id: "LGPL-3.0-or-later" } }],
        },
      ],
    };
  }

  function buildSharedScenario(): {
    doc: string;
    prodContainerVerdict: ReturnType<typeof evaluate>[number] | undefined;
  } {
    const merged = mergeSboms([
      { sbom: sharedCopyleftDoc(), targetIdentity: WORKSPACE_TARGET },
      {
        sbom: sharedCopyleftDoc(),
        targetIdentity: BUILD_CONTAINER,
        scope: "os",
      },
    ]);
    const policyText = [
      "[[docker.development]]",
      'source = "tools/**"',
      'reason = "ci tooling only"',
      "",
    ].join("\n");
    const policy = parsePolicy(policyText);
    const { model: annotated } = annotateFindings(merged, policy.clarify, BUILTIN_OVERRIDES);
    const developmentContainers = resolveDevelopmentContainersForTest(annotated, policy);
    const scoped = applyContainerScopes(annotated, developmentContainers);
    const verdicts = evaluate(scoped, policy, WITHOUT_DEPENDENCY_GRAPHS);
    const policyView: PolicyView = {
      policyPath: asRelativePath("policy.toml"),
      suppressedWorkspaces: policy.suppressedWorkspaces,
      verdicts,
      developmentContainers,
    };

    return {
      doc: alignTables(renderMarkdown(scoped, policyView)),
      prodContainerVerdict: verdicts.find((v) => v.occurrenceTarget === BUILD_CONTAINER),
    };
  }

  test("merge promotes the shared purl to scope app (app wins over os)", () => {
    const merged = mergeSboms([
      { sbom: sharedCopyleftDoc(), targetIdentity: WORKSPACE_TARGET },
      {
        sbom: sharedCopyleftDoc(),
        targetIdentity: BUILD_CONTAINER,
        scope: "os",
      },
    ]);

    expect(merged.packages).toHaveLength(1);
    expect(merged.packages[0]!.scope).toBe("app");
  });

  test("the docker occurrence in the dev-marked container WARNS (dev-downgraded), not FAILS", () => {
    const { prodContainerVerdict } = buildSharedScenario();

    expect(prodContainerVerdict?.status).toBe("warn");
    expect(prodContainerVerdict?.rule).toBe("default:copyleft");
  });

  test("the package renders in BOTH its app Production table AND the container's Application sub-table", () => {
    const { doc } = buildSharedScenario();

    expect(section(doc, "## Production dependencies").includes("shared-workspace-and-image")).toBe(
      true,
    );
    const containerSection = section(doc, `### Container: ${BUILD_CONTAINER}`);

    expect(containerSection.includes("shared-workspace-and-image")).toBe(true);
  });
});
