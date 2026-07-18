import { describe, expect, test } from "bun:test";

import { githubBlobLicenseTarget } from "../src/enrich/nugetGithub";

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
