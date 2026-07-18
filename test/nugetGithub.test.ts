import { describe, expect, test } from "bun:test";

import {
  commitShaForRef,
  githubBlobLicenseTarget,
  githubTagObjectUrl,
  githubTagRefUrl,
  resolveUrlOnlyGithubLicense,
  type GithubApiGet,
} from "../src/enrich/nugetGithub";
import type { GithubLicenseFetch } from "../src/enrich/fetch";

describe("githubBlobLicenseTarget — pure classifier over a NuGet licenseUrl", () => {
  test("raw.githubusercontent.com/<o>/<r>/<tag>/LICENSE.txt parses to a symbol ref", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/aspnet/Home/2.0.0/LICENSE.txt",
      ),
    ).toEqual({
      owner: "aspnet",
      repo: "Home",
      ref: "2.0.0",
      refKind: "symbol",
    });
  });

  test("github.com/<o>/<r>/blob/master/LICENSE.TXT parses to a symbol ref — immutability decided later", () => {
    expect(
      githubBlobLicenseTarget(
        "https://github.com/dotnet/corefx/blob/master/LICENSE.TXT",
      ),
    ).toEqual({
      owner: "dotnet",
      repo: "corefx",
      ref: "master",
      refKind: "symbol",
    });
  });

  test("a 40-hex ref classifies as refKind sha (no lookup needed later)", () => {
    const sha = "abcdef0123456789abcdef0123456789abcdef01";
    expect(
      githubBlobLicenseTarget(
        `https://raw.githubusercontent.com/aspnet/Home/${sha}/LICENSE`,
      ),
    ).toEqual({ owner: "aspnet", repo: "Home", ref: sha, refKind: "sha" });
  });

  test("a near-miss 39/41-hex string is NOT treated as a sha (stays symbol)", () => {
    const short = "abcdef0123456789abcdef0123456789abcdef0"; // 39 chars
    const long = "abcdef0123456789abcdef0123456789abcdef012"; // 41 chars
    expect(
      githubBlobLicenseTarget(
        `https://raw.githubusercontent.com/aspnet/Home/${short}/LICENSE`,
      )?.refKind,
    ).toBe("symbol");
    expect(
      githubBlobLicenseTarget(
        `https://raw.githubusercontent.com/aspnet/Home/${long}/LICENSE`,
      )?.refKind,
    ).toBe("symbol");
  });

  test("the explicit refs/tags/<tag...>/LICENSE raw form joins a slash-containing tag", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/refs/tags/release/2.0.0/LICENSE",
      ),
    ).toEqual({
      owner: "o",
      repo: "r",
      ref: "release/2.0.0",
      refKind: "symbol",
    });
  });

  test("the explicit refs/heads/<branch>/LICENSE raw form is null — a branch by construction", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/refs/heads/master/LICENSE",
      ),
    ).toBeNull();
  });

  test("an unrecognized refs/<kind>/... form is null — never a guess", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/refs/pull/123/LICENSE",
      ),
    ).toBeNull();
  });

  test("a subdirectory LICENSE (more than one plain path segment before the file) is null", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/master/docs/LICENSE",
      ),
    ).toBeNull();
  });

  test("a non-root license filename is null (LICENSE-MIT, COPYING never match)", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/master/LICENSE-MIT",
      ),
    ).toBeNull();
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/master/COPYING",
      ),
    ).toBeNull();
  });

  test("LICENCE.md (British spelling, markdown extension) matches, case-insensitively", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/v1.0.0/licence.MD",
      ),
    ).toEqual({ owner: "o", repo: "r", ref: "v1.0.0", refKind: "symbol" });
  });

  test("a query string or fragment on an otherwise valid URL is null", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/master/LICENSE?x=1",
      ),
    ).toBeNull();
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/master/LICENSE#frag",
      ),
    ).toBeNull();
  });

  test("empty path segments (a doubled slash) are null", () => {
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o//master/LICENSE",
      ),
    ).toBeNull();
  });

  test("a fwlink / non-GitHub host never parses, regardless of shape", () => {
    expect(
      githubBlobLicenseTarget("https://go.microsoft.com/fwlink/?LinkId=329770"),
    ).toBeNull();
    expect(
      githubBlobLicenseTarget("https://example.com/o/r/blob/master/LICENSE"),
    ).toBeNull();
  });

  test("a lookalike host (github.com.evil.example) is null — exact-host compare", () => {
    expect(
      githubBlobLicenseTarget(
        "https://github.com.evil.example/o/r/blob/master/LICENSE",
      ),
    ).toBeNull();
  });

  test("a userinfo-@ URL (user@github.com) is null", () => {
    expect(
      githubBlobLicenseTarget(
        "https://user@github.com/o/r/blob/master/LICENSE",
      ),
    ).toBeNull();
  });

  test("a mixed-case host still resolves correctly (WHATWG hostname normalization, not a bypass)", () => {
    expect(
      githubBlobLicenseTarget("https://GitHub.COM/o/r/blob/master/LICENSE"),
    ).toEqual({ owner: "o", repo: "r", ref: "master", refKind: "symbol" });
  });

  test("a non-default port is null", () => {
    expect(
      githubBlobLicenseTarget(
        "https://github.com:8443/o/r/blob/master/LICENSE",
      ),
    ).toBeNull();
  });

  test("http (not https) is null", () => {
    expect(
      githubBlobLicenseTarget("http://github.com/o/r/blob/master/LICENSE"),
    ).toBeNull();
  });

  test("an unparseable string is null, never a throw", () => {
    expect(githubBlobLicenseTarget("not a url at all")).toBeNull();
    expect(githubBlobLicenseTarget("")).toBeNull();
  });

  test("Arm A mini-gate: a %2F-encoded segment stays opaque — never re-splits the path or shifts the root-LICENSE position", () => {
    // The WHATWG URL parser leaves %2F undecoded inside a path segment, so an
    // owner/ref carrying it is one literal segment, not an extra "/" boundary.
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o%2Fx/r/master/LICENSE",
      ),
    ).toEqual({ owner: "o%2Fx", repo: "r", ref: "master", refKind: "symbol" });
    // An encoded slash inside the ref segment is equally inert — still one
    // segment, so the file position (and the root-only fence) is unmoved.
    expect(
      githubBlobLicenseTarget(
        "https://raw.githubusercontent.com/o/r/mas%2Fter/LICENSE",
      ),
    ).toEqual({
      owner: "o",
      repo: "r",
      ref: "mas%2Fter",
      refKind: "symbol",
    });
  });

  test("Arm A mini-gate: a unicode-confusable host (punycode-normalized) is null — never coerces to the real github.com", () => {
    // U+0261 LATIN SMALL LETTER SCRIPT G ("ɡithub.com") normalizes to a
    // distinct xn-- punycode label, so the exact-hostname compare rejects it.
    expect(
      githubBlobLicenseTarget("https://ɡithub.com/o/r/blob/master/LICENSE"),
    ).toBeNull();
  });

  test("Arm A mini-gate: a trailing-dot FQDN host (github.com.) is null — not treated as the same domain", () => {
    expect(
      githubBlobLicenseTarget("https://github.com./o/r/blob/master/LICENSE"),
    ).toBeNull();
  });

  test("Arm A mini-gate: the backslash-authority trick (github.com\\@evil.example) is null — the real host is evil.example, not github.com", () => {
    expect(
      githubBlobLicenseTarget(
        "https://github.com\\@evil.example/o/r/blob/master/LICENSE",
      ),
    ).toBeNull();
  });

  test("Arm A mini-gate: an explicit default port (:443) is accepted — it names the real github.com, not a bypass", () => {
    expect(
      githubBlobLicenseTarget("https://github.com:443/o/r/blob/master/LICENSE"),
    ).toEqual({ owner: "o", repo: "r", ref: "master", refKind: "symbol" });
  });
});

describe("urlOnlyLicenseUrlOf — class-4 ladder ordering (imported via nuget.ts)", () => {
  test("never fires when licenseExpression, licenseFile, or a licenses.nuget.org URL wins first", async () => {
    const { urlOnlyLicenseUrlOf } = await import("../src/enrich/nuget");
    expect(
      urlOnlyLicenseUrlOf({
        licenseExpression: "MIT",
        licenseUrl: "https://github.com/o/r/blob/master/LICENSE",
      }),
    ).toBeUndefined();
    expect(
      urlOnlyLicenseUrlOf({
        licenseFile: "LICENSE.txt",
        licenseUrl: "https://aka.ms/deprecateLicenseUrl",
      }),
    ).toBeUndefined();
    expect(
      urlOnlyLicenseUrlOf({ licenseUrl: "https://licenses.nuget.org/MIT" }),
    ).toBeUndefined();
    expect(urlOnlyLicenseUrlOf({})).toBeUndefined();
  });

  test("returns the raw licenseUrl verbatim ONLY in the class-4 position", async () => {
    const { urlOnlyLicenseUrlOf } = await import("../src/enrich/nuget");
    expect(
      urlOnlyLicenseUrlOf({
        licenseUrl:
          "https://raw.githubusercontent.com/aspnet/Home/2.0.0/LICENSE.txt",
      }),
    ).toBe("https://raw.githubusercontent.com/aspnet/Home/2.0.0/LICENSE.txt");
  });
});

describe("githubTagRefUrl / githubTagObjectUrl — fixed-host builders", () => {
  test("githubTagRefUrl builds .../git/ref/tags/<tag>, encoding each segment", () => {
    expect(githubTagRefUrl("aspnet", "Home", "2.0.0")).toBe(
      "https://api.github.com/repos/aspnet/Home/git/ref/tags/2.0.0",
    );
  });

  test("a slash-containing tag preserves the slash as a path separator, not %2F", () => {
    expect(githubTagRefUrl("o", "r", "release/2.0.0")).toBe(
      "https://api.github.com/repos/o/r/git/ref/tags/release/2.0.0",
    );
  });

  test("owner/repo/tag segments are percent-encoded", () => {
    expect(githubTagRefUrl("o o", "r#r", "t?t")).toBe(
      "https://api.github.com/repos/o%20o/r%23r/git/ref/tags/t%3Ft",
    );
  });

  test("githubTagObjectUrl builds .../git/tags/<sha>", () => {
    const sha = "abcdef0123456789abcdef0123456789abcdef01";
    expect(githubTagObjectUrl("aspnet", "Home", sha)).toBe(
      `https://api.github.com/repos/aspnet/Home/git/tags/${sha}`,
    );
  });
});

describe("commitShaForRef — tag-to-commit immutability proof", () => {
  const TAG_REF_URL =
    "https://api.github.com/repos/aspnet/Home/git/ref/tags/2.0.0";
  const SHA = "abcdef0123456789abcdef0123456789abcdef01";

  function stubGet(byUrl: Record<string, GithubLicenseFetch>): GithubApiGet {
    return async (url: string): Promise<GithubLicenseFetch> => {
      const result = byUrl[url];
      if (result === undefined) throw new Error(`unexpected url ${url}`);
      return result;
    };
  }

  test("refKind sha needs no lookup — the ref is returned as-is, ZERO calls", async () => {
    const calls: string[] = [];
    const get: GithubApiGet = async (url) => {
      calls.push(url);
      throw new Error("must not be called");
    };
    const sha = await commitShaForRef("aspnet", "Home", SHA, "sha", get);
    expect(sha).toBe(SHA);
    expect(calls).toEqual([]);
  });

  test("a lightweight tag (object.type commit) resolves directly, no second hop", async () => {
    const get = stubGet({
      [TAG_REF_URL]: {
        status: 200,
        body: { object: { sha: SHA, type: "commit" } },
      },
    });
    expect(
      await commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).toBe(SHA);
  });

  test("an annotated tag (object.type tag) is peeled once via the tag-object endpoint", async () => {
    const tagObjectSha = "1111111111111111111111111111111111111a";
    const get = stubGet({
      [TAG_REF_URL]: {
        status: 200,
        body: { object: { sha: tagObjectSha, type: "tag" } },
      },
      [`https://api.github.com/repos/aspnet/Home/git/tags/${tagObjectSha}`]: {
        status: 200,
        body: { object: { sha: SHA, type: "commit" } },
      },
    });
    expect(
      await commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).toBe(SHA);
  });

  test("a 404 on the tag-ref lookup is null — not a tag, fences a branch of the same name", async () => {
    const get = stubGet({ [TAG_REF_URL]: { status: 404 } });
    expect(
      await commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).toBeNull();
  });

  test("a malformed tag-ref body (missing object.sha) is a clean null, never a throw", async () => {
    const get = stubGet({
      [TAG_REF_URL]: { status: 200, body: { object: {} } },
    });
    expect(
      await commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).toBeNull();
  });

  test("a 404 on the tag-object peel is a clean null", async () => {
    const tagObjectSha = "2222222222222222222222222222222222222b";
    const get = stubGet({
      [TAG_REF_URL]: {
        status: 200,
        body: { object: { sha: tagObjectSha, type: "tag" } },
      },
      [`https://api.github.com/repos/aspnet/Home/git/tags/${tagObjectSha}`]: {
        status: 404,
      },
    });
    expect(
      await commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).toBeNull();
  });

  test("a transient failure at the tag-ref hop propagates, never a null", async () => {
    const { GithubTransientError } = await import("../src/enrich/fetch");
    const get: GithubApiGet = async () => {
      throw new GithubTransientError("github 403 for x");
    };
    await expect(
      commitShaForRef("aspnet", "Home", "2.0.0", "symbol", get),
    ).rejects.toThrow(GithubTransientError);
  });
});

describe("resolveUrlOnlyGithubLicense — the one registration point (classify → prove tag → read License API)", () => {
  const AUTH_LICENSE_URL =
    "https://raw.githubusercontent.com/aspnet/Home/2.0.0/LICENSE.txt";
  const TAG_REF_URL =
    "https://api.github.com/repos/aspnet/Home/git/ref/tags/2.0.0";
  const SHA = "abcdef0123456789abcdef0123456789abcdef01";
  const LICENSE_AT_SHA_URL = `https://api.github.com/repos/aspnet/Home/license?ref=${SHA}`;

  function withStubbedFetch<T>(
    byUrl: Record<string, { status: number; body?: unknown }>,
    calls: string[],
    fn: () => Promise<T>,
  ): Promise<T> {
    const original = globalThis.fetch;
    globalThis.fetch = (async (
      input: string | URL | Request,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push(url);
      const stub = byUrl[url];
      if (stub === undefined) throw new Error(`unexpected fetch ${url}`);
      return new Response(
        stub.body === undefined ? "{}" : JSON.stringify(stub.body),
        {
          status: stub.status,
          headers: { "content-type": "application/json" },
        },
      );
    }) as typeof fetch;
    return fn().finally(() => {
      globalThis.fetch = original;
    });
  }

  test("a tag-pinned URL resolves the SPDX id, ref, and commit sha end-to-end", async () => {
    const calls: string[] = [];
    const result = await withStubbedFetch(
      {
        [TAG_REF_URL]: {
          status: 200,
          body: { object: { sha: SHA, type: "commit" } },
        },
        [LICENSE_AT_SHA_URL]: {
          status: 200,
          body: { license: { spdx_id: "Apache-2.0" } },
        },
      },
      calls,
      () => resolveUrlOnlyGithubLicense(AUTH_LICENSE_URL, { backoffBaseMs: 1 }),
    );
    expect(result).toEqual({ raw: "Apache-2.0", ref: "2.0.0", sha: SHA });
    expect(calls).toEqual([TAG_REF_URL, LICENSE_AT_SHA_URL]);
  });

  test("a 40-hex ref resolves with a SINGLE fetch — no tag lookup call made", async () => {
    const calls: string[] = [];
    const url = `https://raw.githubusercontent.com/aspnet/Home/${SHA}/LICENSE`;
    const licenseUrl = `https://api.github.com/repos/aspnet/Home/license?ref=${SHA}`;
    const result = await withStubbedFetch(
      { [licenseUrl]: { status: 200, body: { license: { spdx_id: "MIT" } } } },
      calls,
      () => resolveUrlOnlyGithubLicense(url, { backoffBaseMs: 1 }),
    );
    expect(result).toEqual({ raw: "MIT", ref: SHA, sha: SHA });
    expect(calls).toEqual([licenseUrl]);
  });

  test("a branch ref (blob/master) is a negative — the tag-ref 404s, NO License API call", async () => {
    const calls: string[] = [];
    const branchTagRefUrl =
      "https://api.github.com/repos/dotnet/corefx/git/ref/tags/master";
    const result = await withStubbedFetch(
      { [branchTagRefUrl]: { status: 404 } },
      calls,
      () =>
        resolveUrlOnlyGithubLicense(
          "https://github.com/dotnet/corefx/blob/master/LICENSE.TXT",
          { backoffBaseMs: 1 },
        ),
    );
    expect(result).toBeNull();
    expect(calls).toEqual([branchTagRefUrl]);
  });

  test("a fwlink / non-GitHub URL is a negative with ZERO GitHub calls", async () => {
    const calls: string[] = [];
    const result = await withStubbedFetch({}, calls, () =>
      resolveUrlOnlyGithubLicense(
        "https://go.microsoft.com/fwlink/?LinkId=329770",
        {
          backoffBaseMs: 1,
        },
      ),
    );
    expect(result).toBeNull();
    expect(calls).toEqual([]);
  });

  test("a 404 at the pinned commit's License API is a definitive negative", async () => {
    const calls: string[] = [];
    const result = await withStubbedFetch(
      {
        [TAG_REF_URL]: {
          status: 200,
          body: { object: { sha: SHA, type: "commit" } },
        },
        [LICENSE_AT_SHA_URL]: { status: 404 },
      },
      calls,
      () => resolveUrlOnlyGithubLicense(AUTH_LICENSE_URL, { backoffBaseMs: 1 }),
    );
    expect(result).toBeNull();
  });

  test("a NOASSERTION at the pinned commit is a definitive negative", async () => {
    const calls: string[] = [];
    const result = await withStubbedFetch(
      {
        [TAG_REF_URL]: {
          status: 200,
          body: { object: { sha: SHA, type: "commit" } },
        },
        [LICENSE_AT_SHA_URL]: {
          status: 200,
          body: { license: { spdx_id: "NOASSERTION" } },
        },
      },
      calls,
      () => resolveUrlOnlyGithubLicense(AUTH_LICENSE_URL, { backoffBaseMs: 1 }),
    );
    expect(result).toBeNull();
  });

  test("a transient failure at any hop propagates as GithubTransientError, never a null", async () => {
    const calls: string[] = [];
    await expect(
      withStubbedFetch({ [TAG_REF_URL]: { status: 403 } }, calls, () =>
        resolveUrlOnlyGithubLicense(AUTH_LICENSE_URL, { backoffBaseMs: 1 }),
      ),
    ).rejects.toThrow(/github 403/);
  });
});
