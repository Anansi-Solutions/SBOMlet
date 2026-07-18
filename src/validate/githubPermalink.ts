/**
 * Pure classifier for an immutable GitHub blob permalink: a
 * `https://github.com/<owner>/<repo>/blob/<40-hex-commit-sha>/<path>` URL
 * naming a file at an exact commit. Content-addressed by the SHA itself, so
 * no separate file hash is needed to prove a cited document cannot drift.
 *
 * Lives in validate/ rather than enrich/ (which owns a different, more
 * permissive GitHub blob classifier scoped to license-file resolution —
 * tag-or-sha refs, a root LICENSE filename only) because policy/ already
 * depends on validate/ and normalize/, never on enrich/; importing across
 * that boundary would run the wrong way. Uses the WHATWG URL parser for host
 * and authority normalization — the same fixed-host idiom used everywhere
 * else in this codebase — and never trusts a symbolic ref: only a full
 * 40-hex commit SHA counts as immutable.
 */

/** A full 40-character git object SHA, the immutable-ref sentinel. */
const FULL_SHA = /^[0-9a-f]{40}$/i;

/** An immutable GitHub blob permalink, decomposed. */
export interface GithubBlobPermalink {
  owner: string;
  repo: string;
  /** The 40-hex commit SHA exactly as written in the URL. */
  sha: string;
  /** The blob path after the SHA, forward-slash joined — never empty. */
  path: string;
}

/**
 * Classify a URL string as an immutable GitHub blob permalink, or null for
 * every other shape. A symbolic ref (`blob/main`, `blob/master`, a tag name)
 * is rejected outright — a mutable ref can never serve as pinned evidence.
 * Hostile shapes never parse: any host other than an exact "github.com"
 * match, userinfo, a non-default port, and a query string or fragment all
 * yield null.
 */
export function parseGithubBlobPermalink(
  rawUrl: string,
): GithubBlobPermalink | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.hostname !== "github.com") return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.port !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;

  const segments = url.pathname.slice(1).split("/");
  if (segments.some((segment) => segment === "")) return null;
  if (segments.length < 5) return null;

  const [owner, repo, blobLiteral, sha, ...pathSegments] = segments;
  if (blobLiteral !== "blob") return null;
  if (!FULL_SHA.test(sha)) return null;

  return { owner, repo, sha, path: pathSegments.join("/") };
}
