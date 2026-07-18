/**
 * The immutable-ref GitHub rung for NuGet's url-only `licenseUrl` class: a
 * pure classifier over the URL string, tag-to-commit resolution through the
 * GitHub Git API, and the License API read at the resulting pinned commit.
 *
 * A NuGet package's bare `licenseUrl` (the pre-2019 metadata class,
 * superseded by `licenseExpression`) is author-controlled and can point
 * anywhere; following it blindly would let a mutable target silently change
 * what a cached answer means. This module resolves ONLY the shapes that are
 * verifiably immutable: a `github.com`/`raw.githubusercontent.com` URL
 * naming the repository-root LICENSE file at an exact commit SHA, or at a
 * tag — and a tag is only trusted after proving it exists via the GitHub
 * Git Refs API, never by reading the URL's ref segment as a fact. A branch
 * name (including one that happens to look like a version) fails that proof
 * and is fenced out by construction, never reaching the license read.
 *
 * The `licenseUrl` string itself is never fetched — every network request
 * targets a URL built from the fixed `api.github.com` host and the owner/
 * repo/ref extracted by the classifier, the same SSRF control every other
 * fixed-host resolver in this codebase uses.
 */
import {
  narrowGithubTagObject,
  narrowGithubTagRef,
} from "../validate/registry";
import {
  fetchGithubLicense,
  type FetchOptions,
  type GithubLicenseFetch,
} from "./fetch";
import { resolveGithubLicense } from "./github";

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

/** Build the Git Refs API URL that proves a symbol ref is an existing tag. */
export function githubTagRefUrl(
  owner: string,
  repo: string,
  tag: string,
): string {
  const tagPath = tag.split("/").map(encodeURIComponent).join("/");
  return `${GITHUB_API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/ref/tags/${tagPath}`;
}

/** Build the Git Tags API URL that peels an annotated tag object to its commit. */
export function githubTagObjectUrl(
  owner: string,
  repo: string,
  sha: string,
): string {
  return `${GITHUB_API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/tags/${encodeURIComponent(sha)}`;
}

/** The License API URL at an exact ref — the fixed-host shape the tag endpoints share. */
function githubLicenseAtRefUrl(
  owner: string,
  repo: string,
  ref: string,
): string {
  return `${GITHUB_API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/license?ref=${encodeURIComponent(ref)}`;
}

/** The injected GitHub API GET — `fetchGithubLicense`'s exact shape, stubbed by tests. */
export type GithubApiGet = (url: string) => Promise<GithubLicenseFetch>;

/**
 * Resolve a classified ref to the immutable commit SHA the License API must
 * read, or null when the ref is not a tag that exists — the proof that
 * fences every branch ref, including one literally named like a version, out
 * of the license read by construction (the symbol name itself is never
 * trusted, only what the tag-ref lookup returns).
 *
 * A `refKind: "sha"` ref is already immutable and needs no lookup. A
 * `refKind: "symbol"` ref is looked up via the tag-ref endpoint: a 404 means
 * it is not a tag and yields null; a lightweight tag's commit SHA is used
 * directly; an annotated tag is peeled once via the tag-object endpoint to
 * reach the commit it points at. A malformed response body is a clean null,
 * never a throw. A transient GitHub failure propagates as
 * {@link GithubTransientError} from `fetch.ts`.
 */
export async function commitShaForRef(
  owner: string,
  repo: string,
  ref: string,
  refKind: "sha" | "symbol",
  get: GithubApiGet,
): Promise<string | null> {
  if (refKind === "sha") return ref;

  const tagRefResult = await get(githubTagRefUrl(owner, repo, ref));
  if (tagRefResult.status === 404) return null; // not a tag — fences every branch ref
  const tagRef = narrowGithubTagRef(tagRefResult.body);
  if (tagRef === undefined) return null;
  if (tagRef.objectType === "commit") return tagRef.objectSha; // lightweight tag

  const tagObjectResult = await get(
    githubTagObjectUrl(owner, repo, tagRef.objectSha),
  );
  if (tagObjectResult.status === 404) return null;
  const tagObject = narrowGithubTagObject(tagObjectResult.body);
  return tagObject?.commitSha ?? null;
}

/** A resolved url-only GitHub license: the raw SPDX id plus the ref/commit audit trail. */
export interface UrlOnlyGithubResolution {
  raw: string;
  /** The ref exactly as named in the source `licenseUrl` (a tag, or a 40-hex SHA). */
  ref: string;
  /** The immutable commit SHA the License API actually read. */
  sha: string;
}

/**
 * The one registration point for the url-only NuGet `licenseUrl` GitHub
 * rung: classify, resolve the ref to an immutable commit, then read the
 * License API at that exact commit. Shared by the nuget miss path and
 * reused for cache verification.
 *
 * Returns null for every honest-negative shape: an unrecognized URL, a ref
 * that is not an existing tag, or a definitive 404/NOASSERTION answer at the
 * pinned commit — the SAME null the caller already treats as a governed
 * negative for every other class. A transient GitHub failure propagates
 * loudly, never a null.
 */
export async function resolveUrlOnlyGithubLicense(
  licenseUrl: string,
  fetchOpts: FetchOptions = {},
): Promise<UrlOnlyGithubResolution | null> {
  const target = githubBlobLicenseTarget(licenseUrl);
  if (target === null) return null;

  const get: GithubApiGet = (url) => fetchGithubLicense(url, fetchOpts);
  const sha = await commitShaForRef(
    target.owner,
    target.repo,
    target.ref,
    target.refKind,
    get,
  );
  if (sha === null) return null;

  const result = await fetchGithubLicense(
    githubLicenseAtRefUrl(target.owner, target.repo, sha),
    fetchOpts,
  );
  if (result.status === 404) return null; // no LICENSE at the pinned commit — definitive
  const resolved = resolveGithubLicense(result.body);
  if (resolved === null) return null; // NOASSERTION at the pinned commit — definitive

  return { raw: resolved.raw, ref: target.ref, sha };
}
