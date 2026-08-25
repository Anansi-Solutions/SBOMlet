import { describe, expect, test } from "bun:test";
import { asPurl, asDependencyName, asDependencyVersion, widen } from "../../test/brandTestSupport";

import {
  asTargetIdentity,
  type CanonicalDependencies,
  type PackageEntry,
} from "../model/dependencies";
import { applyContainerScopes } from "./containerScope";

const API_CONTAINER = asTargetIdentity("docker:services/api/Dockerfile");
const BUILD_CONTAINER = asTargetIdentity("docker:tools/build/Dockerfile");

/** Hand-built PackageEntry with sensible defaults for the transform tests. */
function entry(
  partial: Partial<PackageEntry> & Pick<PackageEntry, "name" | "version" | "purl">,
): PackageEntry {
  return {
    occurrences: [{ target: API_CONTAINER, isDevDependency: false }],
    licenseClaims: [],
    scope: "os",
    ...partial,
  };
}

describe("applyContainerScopes — system ecosystems stay routine", () => {
  test("a deb/apk/rpm/alpm package is UNCHANGED — scope stays os, occurrences untouched", () => {
    for (const purl of [
      "pkg:deb/debian/bash@5.2-6",
      "pkg:apk/alpine/musl@1.2.4-r2",
      "pkg:rpm/fedora/glibc@2.38",
      "pkg:alpm/arch/pacman@6.1.0",
    ]) {
      const pkg = entry({
        purl: asPurl(purl),
        name: asDependencyName("sys-pkg"),
        version: asDependencyVersion("1.0.0"),
      });
      const model: CanonicalDependencies = { packages: [pkg] };
      const result = applyContainerScopes(model, new Set());

      expect(result.packages[0]!.scope).toBe("os");
      expect(result.packages[0]!.occurrences).toEqual(pkg.occurrences);
    }
  });
});

describe("applyContainerScopes — application ecosystems re-key to app", () => {
  test("a pypi/npm/golang/... package is re-keyed to scope app", () => {
    for (const purl of [
      "pkg:pypi/pip-app@1.0.0",
      "pkg:npm/npm-app@1.0.0",
      "pkg:golang/go-app@1.0.0",
      "pkg:cargo/cargo-app@1.0.0",
      "pkg:nuget/nuget-app@1.0.0",
      "pkg:maven/group/maven-app@1.0.0",
    ]) {
      const pkg = entry({
        purl: asPurl(purl),
        name: asDependencyName("app-pkg"),
        version: asDependencyVersion("1.0.0"),
      });
      const model: CanonicalDependencies = { packages: [pkg] };
      const result = applyContainerScopes(model, new Set());

      expect(result.packages[0]!.scope).toBe("app");
    }
  });

  test("a PRODUCTION container occurrence keeps isDevDependency=false (it gates)", () => {
    const pkg = entry({
      purl: asPurl("pkg:pypi/pip-app@1.0.0"),
      name: asDependencyName("pip-app"),
      version: asDependencyVersion("1.0.0"),
    });
    const result = applyContainerScopes({ packages: [pkg] }, new Set());

    expect(result.packages[0]!.scope).toBe("app");
    expect(result.packages[0]!.occurrences[0]!.isDevDependency).toBe(false);
  });

  test("a DEV-marked container occurrence is set isDevDependency=true", () => {
    const pkg = entry({
      purl: asPurl("pkg:pypi/pip-app@1.0.0"),
      name: asDependencyName("pip-app"),
      version: asDependencyVersion("1.0.0"),
    });
    const result = applyContainerScopes({ packages: [pkg] }, new Set([API_CONTAINER]));

    expect(result.packages[0]!.scope).toBe("app");
    expect(result.packages[0]!.occurrences[0]!.isDevDependency).toBe(true);
  });

  test("a package occurring in BOTH a production and a dev-marked container: production occurrence stays false, dev occurrence becomes true", () => {
    const pkg = entry({
      purl: asPurl("pkg:pypi/pip-app@1.0.0"),
      name: asDependencyName("pip-app"),
      version: asDependencyVersion("1.0.0"),
      occurrences: [
        { target: API_CONTAINER, isDevDependency: false },
        { target: BUILD_CONTAINER, isDevDependency: false },
      ],
    });
    const result = applyContainerScopes({ packages: [pkg] }, new Set([BUILD_CONTAINER]));
    const [atApi, atBuild] = result.packages[0]!.occurrences;

    expect(widen(atApi!.target)).toBe(API_CONTAINER);
    expect(atApi!.isDevDependency).toBe(false);
    expect(widen(atBuild!.target)).toBe(BUILD_CONTAINER);
    expect(atBuild!.isDevDependency).toBe(true);
  });

  test("empty developmentContainers: app-ecosystem container packages still re-key to app but every docker occurrence stays isDevDependency=false", () => {
    const pkg = entry({
      purl: asPurl("pkg:npm/npm-app@1.0.0"),
      name: asDependencyName("npm-app"),
      version: asDependencyVersion("1.0.0"),
      occurrences: [
        { target: API_CONTAINER, isDevDependency: false },
        { target: BUILD_CONTAINER, isDevDependency: false },
      ],
    });
    const result = applyContainerScopes({ packages: [pkg] }, new Set());

    expect(result.packages[0]!.scope).toBe("app");
    for (const occurrence of result.packages[0]!.occurrences) {
      expect(occurrence.isDevDependency).toBe(false);
    }
  });
});

describe("applyContainerScopes — an already-app package still dev-marks its docker occurrences", () => {
  test("regression: a package merged to scope app via the shared-purl promotion (merge.ts) still dev-marks its docker occurrence when the container is development-marked — the scope-level fact is not a substitute for the per-occurrence one", () => {
    const pkg: PackageEntry = {
      purl: asPurl("pkg:npm/shared@1.0.0"),
      name: asDependencyName("shared"),
      version: asDependencyVersion("1.0.0"),
      occurrences: [
        { target: asTargetIdentity("apps/web"), isDevDependency: false },
        { target: BUILD_CONTAINER, isDevDependency: false },
      ],
      licenseClaims: [],
      scope: "app",
    };
    const result = applyContainerScopes({ packages: [pkg] }, new Set([BUILD_CONTAINER]));

    expect(result.packages[0]!.scope).toBe("app");
    const [atApp, atBuild] = result.packages[0]!.occurrences;

    expect(widen(atApp!.target)).toBe("apps/web");
    expect(atApp!.isDevDependency).toBe(false);
    expect(widen(atBuild!.target)).toBe(BUILD_CONTAINER);
    expect(atBuild!.isDevDependency).toBe(true);
  });

  test("an already-dev occurrence and a non-development container are both left untouched, by reference", () => {
    const pkg: PackageEntry = {
      purl: asPurl("pkg:npm/shared@1.0.0"),
      name: asDependencyName("shared"),
      version: asDependencyVersion("1.0.0"),
      occurrences: [{ target: BUILD_CONTAINER, isDevDependency: false }],
      licenseClaims: [],
      scope: "app",
    };
    const result = applyContainerScopes({ packages: [pkg] }, new Set());

    expect(result.packages[0]).toBe(pkg);
  });
});

describe("applyContainerScopes — determinism", () => {
  test("is a pure function of its inputs: double-run produces identical output", () => {
    const pkg = entry({
      purl: asPurl("pkg:golang/go-app@1.0.0"),
      name: asDependencyName("go-app"),
      version: asDependencyVersion("1.0.0"),
      occurrences: [
        { target: API_CONTAINER, isDevDependency: false },
        { target: BUILD_CONTAINER, isDevDependency: false },
      ],
    });
    const model: CanonicalDependencies = { packages: [pkg] };
    const developmentContainers = new Set([BUILD_CONTAINER]);
    const first = applyContainerScopes(model, developmentContainers);
    const second = applyContainerScopes(model, developmentContainers);

    expect(second).toEqual(first);
  });
});

describe("applyContainerScopes — os-scope-implies-docker-only invariant", () => {
  test("a hand-built os-scope package with a non-docker occurrence THROWS, naming the purl and the offending target", () => {
    const pkg = entry({
      purl: asPurl("pkg:apk/alpine/musl@1.2.4-r2"),
      name: asDependencyName("musl"),
      version: asDependencyVersion("1.2.4-r2"),
      occurrences: [{ target: asTargetIdentity("apps/web"), isDevDependency: false }],
    });
    const model: CanonicalDependencies = { packages: [pkg] };

    expect(() => applyContainerScopes(model, new Set())).toThrow(
      /pkg:apk\/alpine\/musl@1\.2\.4-r2/,
    );
    expect(() => applyContainerScopes(model, new Set())).toThrow(/apps\/web/);
  });

  test("a mix of one valid docker occurrence and one offending workspace occurrence on the SAME os-scope package still throws, naming the offending target specifically", () => {
    const pkg = entry({
      purl: asPurl("pkg:deb/debian/bash@5.2-6"),
      name: asDependencyName("bash"),
      version: asDependencyVersion("5.2-6"),
      occurrences: [
        { target: API_CONTAINER, isDevDependency: false },
        { target: asTargetIdentity("apps/web"), isDevDependency: false },
      ],
    });
    const model: CanonicalDependencies = { packages: [pkg] };

    expect(() => applyContainerScopes(model, new Set())).toThrow(/apps\/web/);
  });

  test("the real pipeline never trips it: every os-scope package here carries only docker: occurrences, by construction", () => {
    // Every fixture above is either scope "os" with a docker: occurrence (the
    // default `entry()` shape) or scope "app". None throws - proven by every
    // OTHER test in this file passing. This test documents that guarantee
    // explicitly rather than leaving it implicit in "the suite is green".
    const pkg = entry({
      purl: asPurl("pkg:apk/alpine/musl@1.2.4-r2"),
      name: asDependencyName("musl"),
      version: asDependencyVersion("1.2.4-r2"),
    });
    const model: CanonicalDependencies = { packages: [pkg] };

    expect(() => applyContainerScopes(model, new Set())).not.toThrow();
  });
});
