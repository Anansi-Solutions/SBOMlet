/**
 * Bounded-concurrency HTTP fetch wrapper for registry enrichment.
 *
 * Carries over the bounded-resource POSTURE from collectors/exec.ts (a hard
 * wall-clock bound + a loud, actionable error naming the operand on a
 * non-success), adapted from subprocess to `globalThis.fetch` — no
 * child_process here. Generate may fetch; a persistent failure is LOUD, never a
 * silent skip and never a negative-cache write (a deliberate reliability
 * decision).
 *
 * The wrapper does NOT construct URLs. Callers (the PyPI/npm resolvers) pass an
 * already-encoded URL built from a fixed registry base + URL-encoded
 * purl-derived name/version, so an attacker-controlled host is impossible by
 * construction (the SSRF control). The wrapper only adds the bound, the
 * exponential backoff on transient failures, and the loud terminal error.
 *
 * No custom `Accept` header is sent: the npm packument endpoint returns 406 Not
 * Acceptable for `Accept: application/vnd.npm.install-v1+json`, so the default
 * JSON Accept is used.
 */

/** Per-request wall-clock bound; an unresponsive registry aborts here (DoS bound). */
const REQUEST_TIMEOUT_MS = 15_000;
/** Max retry attempts on a transient (429/5xx/network) failure before giving up. */
const MAX_RETRIES = 4;
/** Backoff base: attempt N sleeps 500 * 2**N ms (500ms, 1s, 2s, 4s). */
const BACKOFF_BASE_MS = 500;
/** Identifies this tool to the registries; no auth, public JSON only. */
const USER_AGENT = "sbom-license-tool/0.1";

/**
 * Run `fn` over `items` with at most `limit` concurrent workers, returning
 * results in input order. A `limit` larger than `items.length` spawns only as
 * many workers as there are items (no idle over-workers).
 */
export async function mapLimit<T, R>(
  items: ReadonlyArray<T>,
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]!);
    }
  }
  const workerCount = Math.max(0, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

/** Transient statuses worth retrying: rate-limit and server errors. */
function isTransientStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Retry/backoff tuning. The default `backoffBaseMs` is production; tests pass a small value. */
export interface FetchOptions {
  /** Backoff base in ms (attempt N waits backoffBaseMs * 2**N). Defaults to {@link BACKOFF_BASE_MS}. */
  backoffBaseMs?: number;
}

/**
 * GET `url` and parse the JSON body. Retries transient failures (429/5xx and
 * network errors) with exponential backoff up to {@link MAX_RETRIES}; on a
 * persistent non-success throws `Error("registry <status> for <url>")` — never
 * a sentinel, never a silent skip. A per-request timeout bounds a slow/hung
 * response.
 */
export async function fetchJson(
  url: string,
  opts: FetchOptions = {},
  attempt = 0,
): Promise<unknown> {
  const backoffBase = opts.backoffBaseMs ?? BACKOFF_BASE_MS;
  let response: Response;
  try {
    response = await fetch(url, {
      headers: { "User-Agent": USER_AGENT }, // NO custom Accept (npm 406)
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      await sleep(backoffBase * 2 ** attempt);
      return fetchJson(url, opts, attempt + 1);
    }
    throw new Error(`registry fetch failed for ${url}`, { cause: error });
  }

  if (isTransientStatus(response.status) && attempt < MAX_RETRIES) {
    await sleep(backoffBase * 2 ** attempt);
    return fetchJson(url, opts, attempt + 1);
  }
  if (!response.ok) {
    throw new Error(`registry ${response.status} for ${url}`); // loud terminal failure
  }
  return response.json();
}

/**
 * A TRANSIENT/unreachable GitHub License failure: a 403 rate-limit,
 * a 5xx, a timeout, or a network error after retries. The enrich orchestrator
 * recognizes this type and HARD-FAILS the generate run loudly — it is NOT a
 * definitive no-license answer and must never become a (false) negative cache
 * entry. Distinct from a clean 404, which is a missing-tag/no-license signal the
 * orchestrator handles by advancing to the next candidate ref.
 */
export class GithubTransientError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "GithubTransientError";
  }
}

/** The result of a single GitHub License API fetch at one candidate ref. */
export type GithubLicenseFetch =
  | { status: 200; body: unknown }
  | { status: 404 };

/**
 * GET a GitHub License API URL with the same bound/backoff posture as
 * {@link fetchJson}, PLUS the revision-E transient-vs-definitive distinction:
 *
 *   - 200            → `{ status: 200, body }` (resolve downstream).
 *   - 404            → `{ status: 404 }` (a DEFINITIVE missing-tag/no-license
 *                      signal — NOT a throw; the caller advances to the next ref).
 *   - 429/5xx        → retried with backoff; persistent → {@link GithubTransientError}.
 *   - 403/other 4xx  → {@link GithubTransientError} (rate-limit/unreachable; hard-fail).
 *   - network/timeout→ retried; persistent → {@link GithubTransientError}.
 *
 * An optional `GITHUB_TOKEN` is honored as a Bearer header (5000/hr vs 60/hr
 * unauth); when unset the request carries no Authorization header. The URL is
 * built by the caller from the FIXED `api.github.com` host (the SSRF control);
 * the token is sent only to that host and never logged or cached.
 */
export async function fetchGithubLicense(
  url: string,
  opts: FetchOptions = {},
  attempt = 0,
): Promise<GithubLicenseFetch> {
  const backoffBase = opts.backoffBaseMs ?? BACKOFF_BASE_MS;
  const token = process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = { "User-Agent": USER_AGENT };
  if (token !== undefined && token !== "") {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      await sleep(backoffBase * 2 ** attempt);
      return fetchGithubLicense(url, opts, attempt + 1);
    }
    throw new GithubTransientError(`github fetch failed for ${url}`, {
      cause: error,
    });
  }

  if (response.status === 200) {
    return { status: 200, body: await response.json() };
  }
  if (response.status === 404) {
    return { status: 404 }; // definitive missing-tag/no-license — caller advances
  }
  if (isTransientStatus(response.status) && attempt < MAX_RETRIES) {
    await sleep(backoffBase * 2 ** attempt);
    return fetchGithubLicense(url, opts, attempt + 1);
  }
  // 403 rate-limit, persistent 5xx, or any other non-ok → transient/unreachable.
  throw new GithubTransientError(`github ${response.status} for ${url}`);
}

/** The result of a JSON fetch that treats 404 as a value: the parsed body, or a definitive not-found. */
export type JsonOr404 = { status: 200; body: unknown } | { status: 404 };

/**
 * GET `url` and parse the JSON body with {@link fetchJson}'s EXACT posture —
 * same timeout bound, same 429/5xx/network retry-with-backoff, same
 * User-Agent, no custom Accept, no auth header, and the same loud terminal
 * `registry <status> for <url>` error — with ONE divergence: a 404 returns
 * `{ status: 404 }` as a VALUE instead of a throw (the
 * {@link fetchGithubLicense} shape). The NuGet registration API 404s the leaf
 * for any package not on nuget.org — a common legitimate reality for
 * private-feed packages — so the caller classifies a clean 404 as a
 * definitive negative rather than a run-failing error. Every transient
 * failure still retries and then throws loudly, never a silent skip.
 */
export async function fetchJsonOr404(
  url: string,
  opts: FetchOptions = {},
  attempt = 0,
): Promise<JsonOr404> {
  const backoffBase = opts.backoffBaseMs ?? BACKOFF_BASE_MS;
  let response: Response;
  try {
    response = await fetch(url, {
      headers: { "User-Agent": USER_AGENT }, // NO custom Accept (fetchJson contract)
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      await sleep(backoffBase * 2 ** attempt);
      return fetchJsonOr404(url, opts, attempt + 1);
    }
    throw new Error(`registry fetch failed for ${url}`, { cause: error });
  }

  if (response.status === 404) {
    return { status: 404 }; // definitive not-on-registry — the caller records the negative
  }
  if (isTransientStatus(response.status) && attempt < MAX_RETRIES) {
    await sleep(backoffBase * 2 ** attempt);
    return fetchJsonOr404(url, opts, attempt + 1);
  }
  if (!response.ok) {
    throw new Error(`registry ${response.status} for ${url}`); // loud terminal failure
  }
  return { status: 200, body: await response.json() };
}
