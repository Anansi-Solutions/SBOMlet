/**
 * Unit tests for policy/target.ts: per-occurrence profile resolution and the two pure notice
 * builders. Policies are built directly via parsePolicy on inline TOML (the schema.test.ts idiom);
 * models are hand-built CanonicalDependencies since these builders never touch a real SBOM.
 */
import { describe, expect, test } from "bun:test";

import { parsePolicy } from "../parse/parse";
import {
  resolveTargetProfile,
  suppressionOverlapNotices,
  unusedWorkspaceTargetWarnings,
} from "./target";
import type { CanonicalDependencies, PackageEntry } from "../../model/dependencies";

function pkg(purl: string, targets: readonly string[]): PackageEntry {
  return {
    purl,
    name: purl,
    version: "1.0.0",
    scope: "app",
    licenseClaims: [],
    occurrences: targets.map((target) => ({ target, isDevDependency: false })),
  };
}

function modelOf(...packages: PackageEntry[]): CanonicalDependencies {
  return { packages };
}

describe("resolveTargetProfile", () => {
  test("no [target] table -> undefined for any occurrence", () => {
    const policy = parsePolicy('[unknown]\nhandling = "warn"\n');

    expect(resolveTargetProfile("apps/api", policy)).toBeUndefined();
    expect(resolveTargetProfile("docker:svc/Dockerfile", policy)).toBeUndefined();
  });

  test("a complete project profile governs an ungoverned workspace occurrence", () => {
    const policy = parsePolicy(
      ["[target]", 'license = "MIT"', "network = false", 'distribution = "external"', ""].join(
        "\n",
      ),
    );

    expect(resolveTargetProfile("apps/anything", policy)).toEqual({
      license: { kind: "oss", id: "MIT" },
      network: false,
      distribution: "external",
    });
  });

  test("a docker occurrence resolves ONLY the project profile, never a workspace override", () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "svc"',
        'license = "GPL-3.0-only"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("docker:svc/Dockerfile", policy)).toEqual({
      license: { kind: "oss", id: "MIT" },
      network: false,
      distribution: "external",
    });
  });

  test("a docker occurrence resolves undefined when [target] is workspaces-only", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("docker:apps/api/Dockerfile", policy)).toBeUndefined();
  });

  test("the most-specific covering [[target.workspace]] wins (longest path)", () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps"',
        'license = "Apache-2.0"',
        'reason = "broad override"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "GPL-3.0-only"',
        'reason = "narrower, more specific override"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("apps/api", policy)?.license).toEqual({
      kind: "oss",
      id: "GPL-3.0-only",
    });
    expect(resolveTargetProfile("apps/web", policy)?.license).toEqual({
      kind: "oss",
      id: "Apache-2.0",
    });
  });

  test('segment-aware matching: "apps/studio-helper" never matches the narrower "apps/studio"', () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        "",
        "[[target.workspace]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        'reason = "fork is AGPL"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("apps/studio-helper", policy)?.license).toEqual({
      kind: "oss",
      id: "MIT",
    });
    expect(resolveTargetProfile("apps/studio", policy)?.license).toEqual({
      kind: "oss",
      id: "AGPL-3.0-only",
    });
    expect(resolveTargetProfile("apps/studio/nested", policy)?.license).toEqual({
      kind: "oss",
      id: "AGPL-3.0-only",
    });
  });

  test("inherited fields resolve to the project profile's values", () => {
    const policy = parsePolicy(
      [
        "[target]",
        'license = "MIT"',
        "network = true",
        'distribution = "internal"',
        "",
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "GPL-3.0-only"',
        'reason = "diverging license only"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("apps/api", policy)).toEqual({
      license: { kind: "oss", id: "GPL-3.0-only" },
      network: true,
      distribution: "internal",
    });
  });

  test("an occurrence with no covering workspace and no project profile resolves undefined", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );

    expect(resolveTargetProfile("apps/unrelated", policy)).toBeUndefined();
  });
});

describe("unusedWorkspaceTargetWarnings", () => {
  test("no [target] table -> []", () => {
    const policy = parsePolicy('[unknown]\nhandling = "warn"\n');

    expect(unusedWorkspaceTargetWarnings(modelOf(), policy)).toEqual([]);
  });

  test("a covered workspace path produces no warning", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "apps/api"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );
    const model = modelOf(pkg("pkg:npm/x@1.0.0", ["apps/api"]));

    expect(unusedWorkspaceTargetWarnings(model, policy)).toEqual([]);
  });

  test("an uncovered workspace path warns, naming the path", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "apps/ghost"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );
    const model = modelOf(pkg("pkg:npm/x@1.0.0", ["apps/api"]));
    const warnings = unusedWorkspaceTargetWarnings(model, policy);

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("apps/ghost");
    expect(warnings[0]).toContain("matches no occurrence in this run");
  });

  test("a docker occurrence never counts as coverage for a workspace path", () => {
    const policy = parsePolicy(
      [
        "[[target.workspace]]",
        'path = "svc"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
    );
    const model = modelOf(pkg("pkg:npm/x@1.0.0", ["docker:svc/Dockerfile"]));

    expect(unusedWorkspaceTargetWarnings(model, policy)).toHaveLength(1);
  });
});

describe("suppressionOverlapNotices", () => {
  function policyWith(target: string, suppression: string): ReturnType<typeof parsePolicy> {
    return parsePolicy([target, suppression].join("\n"));
  }

  test("no [target] table -> []", () => {
    const policy = parsePolicy(
      [
        "[[workspace.copyleft_suppressed]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        'description = "n/a"',
        "",
      ].join("\n"),
    );

    expect(suppressionOverlapNotices(policy)).toEqual([]);
  });

  test("a complete project profile governs every suppression - one notice each", () => {
    const policy = policyWith(
      ["[target]", 'license = "MIT"', "network = false", 'distribution = "external"', ""].join(
        "\n",
      ),
      [
        "[[workspace.copyleft_suppressed]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        'description = "n/a"',
        "",
      ].join("\n"),
    );
    const notices = suppressionOverlapNotices(policy);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain("apps/studio");
    expect(notices[0]).toContain("governed by the declared project target profile");
  });

  test("a workspaces-only [target] overlapping the suppression path produces one notice naming both", () => {
    const policy = policyWith(
      [
        "[[target.workspace]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
      [
        "[[workspace.copyleft_suppressed]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        'description = "n/a"',
        "",
      ].join("\n"),
    );
    const notices = suppressionOverlapNotices(policy);

    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain('"apps/studio"');
    expect(notices[0]).toContain("[[target.workspace]] entry");
  });

  test("a non-overlapping workspaces-only [target] produces no notice", () => {
    const policy = policyWith(
      [
        "[[target.workspace]]",
        'path = "apps/other"',
        'license = "MIT"',
        "network = false",
        'distribution = "external"',
        'reason = "n/a"',
        "",
      ].join("\n"),
      [
        "[[workspace.copyleft_suppressed]]",
        'path = "apps/studio"',
        'license = "AGPL-3.0-only"',
        'description = "n/a"',
        "",
      ].join("\n"),
    );

    expect(suppressionOverlapNotices(policy)).toEqual([]);
  });
});
