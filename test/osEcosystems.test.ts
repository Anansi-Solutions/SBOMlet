import { describe, expect, test } from "bun:test";

import { OS_PACKAGE_ECOSYSTEMS } from "../src/policy/osEcosystems";

describe("OS_PACKAGE_ECOSYSTEMS — literal allowlist", () => {
  test("contains the Linux distro package-manager purl types", () => {
    expect(OS_PACKAGE_ECOSYSTEMS.has("deb")).toBe(true);
    expect(OS_PACKAGE_ECOSYSTEMS.has("apk")).toBe(true);
    expect(OS_PACKAGE_ECOSYSTEMS.has("rpm")).toBe(true);
    expect(OS_PACKAGE_ECOSYSTEMS.has("alpm")).toBe(true);
  });

  test("does NOT contain an application-level ecosystem", () => {
    // The safe direction: an unrecognized/application purl type is treated
    // as application-level, never routine base-image plumbing.
    expect(OS_PACKAGE_ECOSYSTEMS.has("npm")).toBe(false);
    expect(OS_PACKAGE_ECOSYSTEMS.has("pypi")).toBe(false);
    expect(OS_PACKAGE_ECOSYSTEMS.has("golang")).toBe(false);
    expect(OS_PACKAGE_ECOSYSTEMS.has("cargo")).toBe(false);
    expect(OS_PACKAGE_ECOSYSTEMS.has("nuget")).toBe(false);
    expect(OS_PACKAGE_ECOSYSTEMS.has("maven")).toBe(false);
  });

  test("is exactly the four-member set", () => {
    expect([...OS_PACKAGE_ECOSYSTEMS].sort()).toEqual([
      "alpm",
      "apk",
      "deb",
      "rpm",
    ]);
  });
});
