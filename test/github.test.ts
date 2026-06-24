import { describe, expect, test } from "bun:test";

import {
  githubLicenseRefsFor,
  githubRepoFor,
  resolveGithubLicense,
} from "../src/enrich/github";
import { narrowGithubLicense } from "../src/validate/registry";

/** A parsed terraform purl, mirroring enrich.ts ParsedPurl for the resolver. */
function parsed(
  encodedName: string,
  version: string,
): {
  type: string;
  encodedName: string;
  version: string;
} {
  return { type: "terraform", encodedName, version };
}

describe("githubRepoFor — repo-name derivation from the registry convention", () => {
  test("provider <opentofu-host>/<ns>/<name> → <ns>/terraform-provider-<name>", () => {
    const target = githubRepoFor(
      parsed("registry.opentofu.org/hashicorp/aws", "6.42.0"),
    );
    expect(target?.owner).toBe("hashicorp");
    expect(target?.repo).toBe("terraform-provider-aws");
    expect(target?.raw).toBe("github.com/hashicorp/terraform-provider-aws");
  });

  test("provider integrations/github → integrations/terraform-provider-github", () => {
    const target = githubRepoFor(
      parsed("registry.opentofu.org/integrations/github", "6.12.0"),
    );
    expect(target?.owner).toBe("integrations");
    expect(target?.repo).toBe("terraform-provider-github");
  });

  test("module <host>/<ns>/<name>/<provider> (4 segments) → <ns>/terraform-<provider>-<name> by COUNT, not host", () => {
    // OpenTofu rewrites the module host to registry.opentofu.org too — the
    // 4-segment count (host + ns/name/provider) is what marks it a module.
    const target = githubRepoFor(
      parsed("registry.opentofu.org/terraform-aws-modules/alb/aws", "9.17.0"),
    );
    expect(target?.owner).toBe("terraform-aws-modules");
    expect(target?.repo).toBe("terraform-aws-alb");
    expect(target?.raw).toBe(
      "github.com/terraform-aws-modules/terraform-aws-alb",
    );
  });

  test("module provider segment drives the repo prefix, not the namespace string", () => {
    // ecs/aws → terraform-aws-ecs; the provider is the EXPLICIT 4th segment.
    const target = githubRepoFor(
      parsed("registry.opentofu.org/terraform-aws-modules/ecs/aws", "7.5.0"),
    );
    expect(target?.owner).toBe("terraform-aws-modules");
    expect(target?.repo).toBe("terraform-aws-ecs");
  });

  test("a non-conventional namespace module still derives by explicit segments (no ns heuristic)", () => {
    // someorg/thing/aws is a 4-segment module; the OLD ns heuristic would have
    // returned null, the count-based one derives someorg/terraform-aws-thing.
    const target = githubRepoFor(
      parsed("registry.opentofu.org/someorg/thing/aws", "1.0.0"),
    );
    expect(target?.owner).toBe("someorg");
    expect(target?.repo).toBe("terraform-aws-thing");
  });

  test("a malformed encodedName (too few segments) → null", () => {
    expect(
      githubRepoFor(parsed("registry.opentofu.org/onlytwo", "1.0.0")),
    ).toBeNull();
    expect(githubRepoFor(parsed("registry.opentofu.org", "1.0.0"))).toBeNull();
  });

  test("an over-long encodedName (5+ segments) → null (never a wrong guess)", () => {
    expect(githubRepoFor(parsed("a/b/c/d/e", "1.0.0"))).toBeNull();
  });
});

describe("githubLicenseRefsFor — ordered version-ref candidates (W#4: no default branch)", () => {
  test("yields ONLY [v<version>, <version>] — no default-branch fallback", () => {
    expect(githubLicenseRefsFor("6.42.0")).toEqual(["v6.42.0", "6.42.0"]);
  });

  test("module exact pins yield the same two-tag list as a provider", () => {
    expect(githubLicenseRefsFor("5.1.2")).toEqual(["v5.1.2", "5.1.2"]);
  });

  test("the undefined default-branch sentinel is NEVER present (W#4)", () => {
    const refs = githubLicenseRefsFor("1.0.0");
    expect(refs).not.toContain(undefined);
    expect(refs.every((r) => typeof r === "string")).toBe(true);
  });
});

describe("resolveGithubLicense — raw-only contract over an already-fetched body", () => {
  test("returns { raw, via, downloadUrl } from a stubbed GitHub License API body", () => {
    const body = {
      license: { spdx_id: "MPL-2.0" },
      download_url:
        "https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v6.42.0/LICENSE",
      path: "LICENSE",
    };
    const result = resolveGithubLicense(body);
    expect(result).toEqual({
      raw: "MPL-2.0",
      via: "github-license",
      downloadUrl:
        "https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v6.42.0/LICENSE",
    });
  });

  test("integrations/github body resolves to MIT", () => {
    const result = resolveGithubLicense({
      license: { spdx_id: "MIT" },
      download_url: "https://example/LICENSE",
    });
    expect(result?.raw).toBe("MIT");
    expect(result?.via).toBe("github-license");
  });

  test("terraform-aws-modules body resolves to Apache-2.0", () => {
    const result = resolveGithubLicense({
      license: { spdx_id: "Apache-2.0" },
    });
    expect(result?.raw).toBe("Apache-2.0");
    expect(result?.downloadUrl).toBeUndefined();
  });

  test("spdx_id NOASSERTION → null (a DEFINITIVE no-license answer, not a failure)", () => {
    expect(
      resolveGithubLicense({ license: { spdx_id: "NOASSERTION" } }),
    ).toBeNull();
  });

  test("spdx_id null → null (definitive no-license)", () => {
    expect(resolveGithubLicense({ license: { spdx_id: null } })).toBeNull();
  });

  test("a malformed/non-object body → null (never throws)", () => {
    expect(resolveGithubLicense(null)).toBeNull();
    expect(resolveGithubLicense("nope")).toBeNull();
    expect(resolveGithubLicense({ license: "not-an-object" })).toBeNull();
    expect(resolveGithubLicense({})).toBeNull();
  });
});

describe("narrowGithubLicense — tolerant boundary (ASVS V5)", () => {
  test("projects { license: { spdx_id }, download_url }", () => {
    const narrowed = narrowGithubLicense({
      license: { spdx_id: "MPL-2.0" },
      download_url: "https://example/LICENSE",
      path: "LICENSE",
    });
    expect(narrowed?.spdxId).toBe("MPL-2.0");
    expect(narrowed?.downloadUrl).toBe("https://example/LICENSE");
  });

  test("wrong-typed spdx_id / download_url coerce to undefined, never throw", () => {
    const narrowed = narrowGithubLicense({
      license: { spdx_id: 5 },
      download_url: { nested: true },
    });
    expect(narrowed?.spdxId).toBeUndefined();
    expect(narrowed?.downloadUrl).toBeUndefined();
  });

  test("absent license object → spdxId undefined", () => {
    const narrowed = narrowGithubLicense({ download_url: "https://x/LICENSE" });
    expect(narrowed?.spdxId).toBeUndefined();
    expect(narrowed?.downloadUrl).toBe("https://x/LICENSE");
  });

  test("a non-object top-level value → undefined", () => {
    expect(narrowGithubLicense(null)).toBeUndefined();
    expect(narrowGithubLicense("nope")).toBeUndefined();
    expect(narrowGithubLicense(42)).toBeUndefined();
  });
});
