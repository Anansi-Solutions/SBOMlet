/**
 * Enrichment orchestrator: the ENRICH stage between merge and annotate.
 *
 * Finds every package whose current claims resolve to unknown (mirroring
 * findingFromClaims' emptiness/any-unresolvable test) and, in GENERATE mode,
 * fetches each from its ecosystem registry (PyPI JSON for `pkg:pypi`, the npm
 * packument for `pkg:npm`), resolves a RAW license string via the Plan 02
 * resolvers, appends a `source:"registry"` LicenseClaim, and records the result
 * in the committed cache — a positive entry with the raw, OR a negative entry
 * ONLY on a clean 200-empty answer (the resolver returned null on a successful
 * fetch). A fetch FAILURE propagates loudly and writes NO entry, so a transient
 * outage can never become a false negative (Pitfall 1).
 *
 * In CHECK mode it NEVER fetches and NEVER writes: a cache miss for an unknown
 * package needing enrichment is a stale condition — the purl is returned in
 * `staleUnknowns` so the gate can map it to exit 2 (Pitfall 2 / GATE-02). A
 * fetch stubbed to throw proves check is hermetic against the committed cache.
 *
 * The appended claim flows through the SAME normalizeRaw as a generator claim
 * (it is just another claim), so `clarify > registry > generator` precedence
 * holds for free via annotateFindings downstream. The input model is never
 * mutated: new entries are produced via object spread, like annotateFindings.
 */
import { sanitizeEvidenceText } from "../merge/merge";
import {
  compareCodeUnits,
  type CanonicalDependencies,
  type LicenseClaim,
  type LicenseClaimSource,
  type PackageEntry,
} from "../model/dependencies";
import { normalizeRaw } from "../normalize/normalize";
import { writeArtifact } from "../pipeline/paths";
import {
  getEntry,
  putEntry,
  readCache,
  serializeCache,
  type CacheEntry,
} from "./cache";
import { fetchGithubLicense, fetchJson, mapLimit } from "./fetch";
import {
  githubLicenseRefsFor,
  githubRepoFor,
  resolveGithubLicense,
} from "./github";
import { resolveNpmLicense } from "./npm";
import { resolvePypiLicense } from "./pypi";

/** Cap on copyright lines attached from a scancode replay (matches the extractor/merge cap). */
const MAX_REPLAY_COPYRIGHT_LINES = 20;

/** Bounded concurrency over the generate-miss fetch set. */
const FETCH_CONCURRENCY = 8;

export interface EnrichOptions {
  /** generate may fetch+write; check never fetches and never writes. */
  mode: "generate" | "check";
  /** Committed cache path (base-dir-resolved by the caller). */
  cachePath: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to fetchJson (tests pass a small value). */
  backoffBaseMs?: number;
  /**
   * Injectable now-source for the `fetchedAt` stamp on NEW github cache entries
   * (revision D). Defaults to the real clock; tests pass a fixed source so the
   * stamped value is deterministic. Mirrors fetchJson's `backoffBaseMs` idiom
   * (default-to-production, override-in-tests) — NEVER a bare inline `new Date()`.
   */
  now?: () => Date;
}

export interface EnrichResult {
  model: CanonicalDependencies;
  /** Purls of unknowns with no cache entry in check mode (stale, exit 2). */
  staleUnknowns: string[];
}

/** A purl parsed into its ecosystem type and (encoded) name + version. */
export interface ParsedPurl {
  type: string;
  /** Verbatim (still-URL-encoded) name, e.g. "%40babel/core". */
  encodedName: string;
  version: string;
}

/**
 * Parse `pkg:<type>/<name>@<version>`. The name may contain a "/" (scoped npm)
 * and stays verbatim/URL-encoded; the version is everything after the LAST "@"
 * (a scoped name's leading "@" is encoded as %40, so the last "@" is always the
 * version separator). Returns undefined for a non-`pkg:` or malformed purl.
 */
export function parsePurl(purl: string): ParsedPurl | undefined {
  if (!purl.startsWith("pkg:")) return undefined;
  const rest = purl.slice("pkg:".length);
  const slash = rest.indexOf("/");
  if (slash === -1) return undefined;
  const type = rest.slice(0, slash);
  const nameAtVersion = rest.slice(slash + 1);
  const at = nameAtVersion.lastIndexOf("@");
  if (at === -1) return undefined;
  const encodedName = nameAtVersion.slice(0, at);
  const version = nameAtVersion.slice(at + 1);
  if (encodedName === "" || version === "") return undefined;
  return { type, encodedName, version };
}

/**
 * True when a package's current claims resolve to unknown — mirrors
 * findingFromClaims: zero distinct (kind,raw) claims, or any claim that does
 * not normalize. A package with a usable claim is left untouched.
 */
function needsEnrichment(entry: PackageEntry): boolean {
  const seen = new Set<string>();
  const distinct: LicenseClaim[] = [];
  for (const claim of entry.licenseClaims) {
    const key = `${claim.kind}\0${claim.raw}`;
    if (!seen.has(key)) {
      seen.add(key);
      distinct.push(claim);
    }
  }
  if (distinct.length === 0) return true;
  return distinct.some((c) => normalizeRaw(c.raw).expression === null);
}

/** The npm packument URL: the decoded scoped name re-encoded for the path. */
export function npmPackumentUrl(encodedName: string): string {
  // "%40babel/core" → decode → "@babel/core" → encode the "/" only → the
  // registry path "@babel%2Fcore"; an unscoped "lodash" is unchanged.
  const name = decodeURIComponent(encodedName);
  const pathName = name.startsWith("@")
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);
  return `https://registry.npmjs.org/${pathName}`;
}

/** The PyPI JSON URL for a name + exact version. */
export function pypiJsonUrl(encodedName: string, version: string): string {
  const name = decodeURIComponent(encodedName);
  return `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
}

/** A resolved raw license for a fetched registry document, or null. */
export function resolveFromDocument(
  parsed: ParsedPurl,
  document: unknown,
): { raw: string; via: string; fetchedFrom: "pypi" | "npm" } | null {
  if (parsed.type === "pypi") {
    const resolution = resolvePypiLicense(document);
    return resolution === null
      ? null
      : { raw: resolution.raw, via: resolution.via, fetchedFrom: "pypi" };
  }
  const resolution = resolveNpmLicense(document, parsed.version);
  return resolution === null
    ? null
    : { raw: resolution.raw, via: resolution.via, fetchedFrom: "npm" };
}

/**
 * Append a cache-sourced claim to a package via spread (input never mutated).
 * `source` flows from the caller — a registry resolution appends "registry",
 * a cache hit appends whatever provenance the entry carries (replay is
 * exact in every mode, never hardcoded).
 */
export function withCacheClaim(
  entry: PackageEntry,
  raw: string,
  source: LicenseClaimSource,
): PackageEntry {
  const claim: LicenseClaim = { raw, kind: "expression", source };
  return { ...entry, licenseClaims: [...entry.licenseClaims, claim] };
}

/**
 * Attach ScanCode-derived copyright lines as attribution on replay, ONLY when
 * the package has NO existing attribution (absent-not-empty invariant,
 * dependencies.ts:274-279 — an evidence-derived attribution is never
 * overwritten). Lines are sanitized via the same control-char intake rule
 * evidence text uses (merge.ts's sanitizeEvidenceText), deduped, sorted by
 * {@link compareCodeUnits}, and capped — idempotent by construction, so a
 * second replay of the same cache entry produces byte-identical output.
 */
export function withReplayAttribution(
  entry: PackageEntry,
  hit: { copyrights?: readonly string[] },
): PackageEntry {
  if (entry.attribution !== undefined) return entry;
  if (hit.copyrights === undefined || hit.copyrights.length === 0) return entry;

  const sanitized = new Set<string>();
  for (const line of hit.copyrights) {
    if (sanitized.size >= MAX_REPLAY_COPYRIGHT_LINES) break;
    sanitized.add(sanitizeEvidenceText(line));
  }
  const copyrightLines = [...sanitized].sort(compareCodeUnits);

  return {
    ...entry,
    attribution: { copyrightLines, noticeTexts: [], hasVerbatimText: false },
  };
}

/** One unknown package to enrich, with its parsed purl. */
interface Unknown {
  index: number;
  entry: PackageEntry;
  parsed: ParsedPurl;
}

/**
 * Enrich every unknown package. In generate mode a cache miss fetches (bounded,
 * loud on failure), appends the resolved registry claim, and records the result
 * (positive, or negative ONLY on a clean 200-empty answer); the updated cache
 * is written unconditionally at the end (the only enrichment write site, gated
 * on generate mode) — generate always materializes the committed artifact, and
 * an empty envelope is a valid answer when nothing needed enrichment. In check
 * mode a miss is a stale unknown — no fetch, no write.
 */
export async function enrichUnknowns(
  model: CanonicalDependencies,
  opts: EnrichOptions,
): Promise<EnrichResult> {
  const cache = readCache(opts.cachePath);

  // Identify the unknown set up front (parse skips a malformed/unsupported
  // purl — it simply stays unknown, never a crash).
  const unknowns: Unknown[] = [];
  model.packages.forEach((entry, index) => {
    if (!needsEnrichment(entry)) return;
    const parsed = parsePurl(entry.purl);
    if (parsed === undefined) return;
    if (
      parsed.type !== "pypi" &&
      parsed.type !== "npm" &&
      parsed.type !== "terraform"
    ) {
      return;
    }
    unknowns.push({ index, entry, parsed });
  });

  // Start from the input packages; replace only the entries we enrich. The
  // input arrays are never mutated (spread on append).
  const packages = [...model.packages];
  const staleUnknowns: string[] = [];

  // Cache hits resolve with zero fetch in either mode; collect genuine misses.
  const misses: Unknown[] = [];
  for (const unknown of unknowns) {
    const hit = getEntry(cache, unknown.entry.purl);
    if (hit !== undefined) {
      if (hit.resolvable && hit.license !== null) {
        const withClaim = withCacheClaim(
          unknown.entry,
          hit.license,
          "registry",
        );
        packages[unknown.index] = withClaim;
      }
      // A negative hit (resolvable:false) leaves the package unknown, no fetch.
      continue;
    }
    if (opts.mode === "check") {
      staleUnknowns.push(unknown.entry.purl);
      continue;
    }
    misses.push(unknown);
  }

  if (opts.mode === "generate") {
    if (misses.length > 0) await fetchMisses(misses, packages, cache, opts);
    // The ONLY enrichment write site, gated on generate mode: generate always
    // materializes the committed artifact; an empty envelope is a valid answer.
    writeArtifact(opts.cachePath, serializeCache(cache));
  }

  return { model: { packages }, staleUnknowns };
}

/** The GitHub License API base — a FIXED host (the SSRF control). */
const GITHUB_API_HOST = "https://api.github.com";

/** Build the GitHub License API URL for a repo at an optional ref (URL-encoded). */
export function githubLicenseUrl(
  owner: string,
  repo: string,
  ref: string | undefined,
): string {
  const base = `${GITHUB_API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/license`;
  return ref === undefined ? base : `${base}?ref=${encodeURIComponent(ref)}`;
}

/**
 * Fetch each missing unknown (bounded), append a claim on a resolution, and
 * record the cache entry. pypi/npm misses share one document per distinct
 * registry URL (a fetchJson failure propagates LOUDLY and writes NO entry —
 * unchanged). terraform misses take the version-ref GitHub path with the
 * revision-E transient-hard-fail-vs-definitive-negative classification.
 */
async function fetchMisses(
  misses: Unknown[],
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
  opts: EnrichOptions,
): Promise<void> {
  const fetchOpts =
    opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs };

  const registryMisses = misses.filter((m) => m.parsed.type !== "terraform");
  const terraformMisses = misses.filter((m) => m.parsed.type === "terraform");

  await Promise.all([
    fetchRegistryMisses(registryMisses, packages, cache, fetchOpts),
    fetchTerraformMisses(terraformMisses, packages, cache, fetchOpts, opts),
  ]);
}

/**
 * The pypi/npm path (UNCHANGED contract): one fetch per distinct registry URL,
 * fetchJson throws loudly on a persistent failure and writes NO entry.
 */
async function fetchRegistryMisses(
  misses: Unknown[],
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
  fetchOpts: { backoffBaseMs?: number },
): Promise<void> {
  // One fetch per distinct registry URL: scoped/duplicate npm names and any
  // repeated purl reuse the same document.
  const byUrl = new Map<string, Unknown[]>();
  for (const miss of misses) {
    const url =
      miss.parsed.type === "pypi"
        ? pypiJsonUrl(miss.parsed.encodedName, miss.parsed.version)
        : npmPackumentUrl(miss.parsed.encodedName);
    const group = byUrl.get(url);
    if (group === undefined) byUrl.set(url, [miss]);
    else group.push(miss);
  }

  const urls = [...byUrl.keys()];
  await mapLimit(urls, FETCH_CONCURRENCY, async (url): Promise<void> => {
    // A fetch failure throws here and propagates out of mapLimit/enrichUnknowns
    // — loud, never a silent skip, never a negative-cache write.
    const document = await fetchJson(url, fetchOpts);
    for (const miss of byUrl.get(url) ?? []) {
      applyResolution(miss, document, packages, cache);
    }
  });
}

/**
 * The terraform/github version-ref path (revision C + E). For each miss, derive
 * the source repo from the registry naming convention and try the ordered
 * candidate refs (v<version> → <version> → default branch). The FIRST ref that
 * returns a clean 200 with a resolvable license wins; a 404 advances to the next
 * candidate (a missing-tag signal, NOT a terminal failure). A
 * GithubTransientError (403 rate-limit / 5xx / network / timeout) propagates
 * LOUDLY (hard-fail, no entry). A non-conventional/non-github source, or a clean
 * answer with no license across all refs, is a DEFINITIVE no-license → a
 * negative entry → the package stays unknown (POL-04).
 */
async function fetchTerraformMisses(
  misses: Unknown[],
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
  fetchOpts: { backoffBaseMs?: number },
  opts: EnrichOptions,
): Promise<void> {
  await mapLimit(misses, FETCH_CONCURRENCY, async (miss): Promise<void> => {
    const repo = githubRepoFor(miss.parsed);
    if (repo === null) {
      // Non-github / non-conventional source → definitive no-license, never a
      // wrong guess (no fetch attempted).
      recordNegative(miss, cache, "github");
      return;
    }

    // Try the ordered refs; the first resolvable 200 wins. A GithubTransientError
    // here propagates out of mapLimit/enrichUnknowns — the LOUD hard-fail (no
    // entry written for this purl, no negative poison).
    for (const ref of githubLicenseRefsFor(miss.parsed.version)) {
      const url = githubLicenseUrl(repo.owner, repo.repo, ref);
      const result = await fetchGithubLicense(url, fetchOpts);
      if (result.status === 404) continue; // missing tag → next candidate
      const resolved = resolveGithubLicense(result.body);
      if (resolved === null) continue; // NOASSERTION/null at this ref → next
      const viaRef = ref ?? "default";
      packages[miss.index] = withCacheClaim(
        miss.entry,
        resolved.raw,
        "registry",
      );
      putEntry(cache, miss.entry.purl, {
        license: resolved.raw,
        fetchedFrom: "github",
        via: `${resolved.via}@${viaRef}`,
        resolvable: true,
        fetchedAt: (opts.now ?? defaultNow)().toISOString(),
      });
      return;
    }

    // A clean 404 across ALL candidate refs (or NOASSERTION everywhere) → a
    // DEFINITIVE no-license answer → a governed negative entry.
    recordNegative(miss, cache, "github");
  });
}

/** The production now-source for the injectable fetchedAt clock (revision D). */
function defaultNow(): Date {
  return new Date();
}

/** Record a definitive-no-license negative entry for a miss. */
function recordNegative(
  miss: Unknown,
  cache: Map<string, CacheEntry>,
  fetchedFrom: CacheEntry["fetchedFrom"],
): void {
  putEntry(cache, miss.entry.purl, {
    license: null,
    fetchedFrom,
    via: "unresolved",
    resolvable: false,
  });
}

/** Resolve one fetched document for a miss: append + record positive or clean-empty negative. */
function applyResolution(
  miss: Unknown,
  document: unknown,
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
): void {
  const resolved = resolveFromDocument(miss.parsed, document);
  if (resolved !== null) {
    packages[miss.index] = withCacheClaim(miss.entry, resolved.raw, "registry");
    putEntry(cache, miss.entry.purl, {
      license: resolved.raw,
      fetchedFrom: resolved.fetchedFrom,
      via: resolved.via,
      resolvable: true,
    });
    return;
  }
  // A clean 200 with a genuinely empty license → a negative cache entry; the
  // package stays unknown. (A fetch FAILURE never reaches here — fetchJson
  // threw — so a transient outage is never cached.)
  recordNegative(miss, cache, miss.parsed.type === "pypi" ? "pypi" : "npm");
}
