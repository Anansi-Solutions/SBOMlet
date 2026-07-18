/**
 * The immutable-ref GitHub rung for NuGet's url-only `licenseUrl` class: a
 * pure classifier over the URL string, naming a `github.com`/
 * `raw.githubusercontent.com` root-LICENSE blob at a tag or a 40-hex commit
 * SHA.
 *
 * A NuGet package's bare `licenseUrl` (the pre-2019 metadata class,
 * superseded by `licenseExpression`) is author-controlled and can point
 * anywhere; following it blindly would let a mutable target silently change
 * what a cached answer means. This module resolves ONLY the shapes that are
 * verifiably immutable: a URL naming the repository-root LICENSE file at an
 * exact commit SHA, or at a tag — trusting a tag name is a later step (the
 * GitHub Git Refs API proof), not this module's job; the classifier only
 * decides whether a URL is shaped like a candidate at all.
 */

/** The GitHub API base — a FIXED host (the SSRF control, the NUGET_API_HOST idiom). */
export const GITHUB_API_HOST = "https://api.github.com";

/** A root-LICENSE file at a repo/ref, classified from a NuGet `licenseUrl`. */
export interface GithubBlobLicenseTarget {
  owner: string;
  repo: string;
  /** The ref exactly as named in the URL — a tag/branch name, or a 40-hex SHA. */
  ref: string;
  /** "sha" needs no lookup; "symbol" must be proven a tag before it is trusted. */
  refKind: "sha" | "symbol";
}

/** The repository-root LICENSE filename, case-insensitive, an optional .txt/.md extension. */
const ROOT_LICENSE_FILE = /^licen[cs]e(\.(txt|md))?$/i;

/** A full 40-character git object SHA, the immutable-ref sentinel. */
const FULL_SHA = /^[0-9a-f]{40}$/i;

/**
 * Classify a NuGet `licenseUrl` string as a GitHub root-LICENSE blob
 * reference, or null for every shape this rung does not resolve.
 *
 * Accepted only: `https://github.com/<owner>/<repo>/blob/<ref>/<file>` and
 * `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<file>`, PLUS the
 * raw host's explicit `refs/tags/<tag>/<file>` form (a tag name may itself
 * contain slashes, unambiguous only because the `refs/tags/` prefix marks
 * where it starts). The explicit `refs/heads/<branch>/<file>` form is a
 * branch by construction and is rejected here, before any network call. The
 * plain (non-`refs/`) forms accept exactly ONE ref segment — a URL naming a
 * subdirectory file, not the repository root, is rejected here rather than
 * silently treated as an odd ref name.
 *
 * Hostile shapes never parse: any host other than an exact (post-normalize)
 * match, userinfo, a non-default port, `https:` only, and a query string or
 * fragment all yield null.
 */
export function githubBlobLicenseTarget(
  rawUrl: string,
): GithubBlobLicenseTarget | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.port !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;

  const segments = url.pathname.slice(1).split("/");
  if (segments.some((segment) => segment === "")) return null;

  if (url.hostname === "github.com") return fromBlobPath(segments);
  if (url.hostname === "raw.githubusercontent.com") {
    return fromRawPath(segments);
  }
  return null;
}

/** `<owner>/<repo>/blob/<ref>/<file>` — exactly one ref segment, no subdirectory. */
function fromBlobPath(segments: string[]): GithubBlobLicenseTarget | null {
  if (segments.length !== 5) return null;
  const [owner, repo, blobLiteral, ref, file] = segments;
  if (blobLiteral !== "blob") return null;
  return rootLicenseTarget(owner, repo, ref, file);
}

/**
 * `<owner>/<repo>/<ref>/<file>`, or the explicit `refs/tags/<tag...>/<file>`
 * / `refs/heads/<branch>/<file>` forms.
 */
function fromRawPath(segments: string[]): GithubBlobLicenseTarget | null {
  if (segments.length < 4) return null;
  const [owner, repo] = segments;
  const rest = segments.slice(2);

  if (rest[0] === "refs") {
    if (rest.length < 4 || rest[1] !== "tags") return null; // heads/other → null
    const file = rest[rest.length - 1];
    const ref = rest.slice(2, -1).join("/");
    return rootLicenseTarget(owner, repo, ref, file);
  }

  if (rest.length !== 2) return null; // more than one segment → a subdirectory, not the root
  const [ref, file] = rest;
  return rootLicenseTarget(owner, repo, ref, file);
}

/** The shared root-license-fence + refKind classification for both host shapes. */
function rootLicenseTarget(
  owner: string,
  repo: string,
  ref: string,
  file: string,
): GithubBlobLicenseTarget | null {
  if (ref === "" || !ROOT_LICENSE_FILE.test(file)) return null;
  return { owner, repo, ref, refKind: FULL_SHA.test(ref) ? "sha" : "symbol" };
}
