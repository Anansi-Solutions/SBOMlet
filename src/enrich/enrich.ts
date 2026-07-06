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
 *
 * On `generate --intensive` (10-04, SCAN-01/SCAN-02) a SECOND lane runs after
 * the registry fetch pass and strictly before the single write site: every
 * still-unknown (residual) package is mapped to a locally-present source dir
 * and, when present, scanned with the ScanCode toolkit collector
 * (src/enrich/scancode.ts). A positive result appends a `source:"scancode"`
 * claim, attaches attribution when the package has none, and overwrites any
 * existing registry entry (including a negative one) with a
 * `source:"scancode"` cache entry. A clean no-answer writes nothing — an
 * existing registry negative is left untouched, and scancode negatives are
 * never cached (re-scanning a tiny residual set each intensive run is
 * cheaper than the added envelope semantics). A residual whose warm-cache
 * scancode answer is already replayed onto it is skipped outright, so a warm
 * intensive run re-scans nothing and rewrites nothing (byte-identical
 * committed cache). `check` never receives the `intensive` option and never
 * scans; it replays a scancode-sourced claim from the committed cache
 * exactly like a registry-sourced one.
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
import {
  scanPackageSources,
  sourceDirFor,
  type IntensiveOptions,
} from "./scancode";

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
  /**
   * Present ONLY on `generate --intensive` (10-04, SCAN-01/SCAN-02): the
   * ScanCode residual-scan lane. `check` never receives it (the CLI/pipeline
   * layer rejects `--intensive` on check, Pitfall 4) and a default generate
   * call never constructs it — the lane is gated on this field's mere
   * presence, additionally inside `mode === "generate"`.
   */
  intensive?: IntensiveOptions;
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
 * a cache hit appends whatever provenance the entry carries (D-04: replay is
 * exact in every mode, never hardcoded).
 */
function withCacheClaim(
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
function withReplayAttribution(
  entry: PackageEntry,
  hit: CacheEntry,
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
          hit.source,
        );
        packages[unknown.index] = withReplayAttribution(withClaim, hit);
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
    // The intensive ScanCode lane (10-04): runs strictly BEFORE the single
    // write site, gated on opts.intensive being present. Recomputes the
    // residual set from the POST-registry packages (Pitfall 5 — a
    // registry-negative-entry package is a cache HIT, filtered out of
    // `misses` above, yet still an intensive scan target).
    if (opts.intensive !== undefined) {
      await scanResidual(packages, cache, opts.intensive, opts);
    }
    // The ONLY enrichment write site, gated on generate mode: generate always
    // materializes the committed artifact; an empty envelope is a valid answer.
    writeArtifact(opts.cachePath, serializeCache(cache));
  }

  return { model: { packages }, staleUnknowns };
}

/** The GitHub License API base — a FIXED host (the SSRF control, T-06-04). */
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
        source: "registry",
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

/**
 * The intensive residual set (10-04, Pitfall 5): re-run {@link needsEnrichment}
 * over the FULL post-registry `packages` array (index-tracked, mirroring the
 * `unknowns` construction above) — NOT the `misses` array. A package with a
 * registry NEGATIVE cache entry is a cache HIT (filtered out of `misses`
 * entirely) yet is STILL genuinely unknown and therefore still an intensive
 * scan target; using `misses` here would silently skip every
 * previously-registry-negative package forever.
 */
function residualUnknowns(packages: PackageEntry[]): Unknown[] {
  const residual: Unknown[] = [];
  packages.forEach((entry, index) => {
    if (!needsEnrichment(entry)) return;
    const parsed = parsePurl(entry.purl);
    if (parsed === undefined) return;
    residual.push({ index, entry, parsed });
  });
  return residual;
}

/**
 * True when a residual package's warm-cache scancode answer has ALREADY been
 * replayed onto it: the cache entry carries scancode provenance with a
 * positive license, and that exact claim is present on the package (the
 * cache-hit loop in enrichUnknowns appended it). Re-scanning such a package
 * would only re-derive the answer the cache already holds and restamp its
 * `fetchedAt` — churning the committed bytes on every warm run (and turning
 * the scheduled workflow's "artifacts unchanged" early-exit into a
 * timestamp-only commit every month). The shape that makes this matter is an
 * imprecise family claim co-existing with the scancode answer: the imprecise
 * claim never normalizes, so needsEnrichment keeps the package residual
 * forever — this skip is what takes it out of the warm burn-down set.
 */
function scancodeReplayDone(
  entry: PackageEntry,
  hit: CacheEntry | undefined,
): boolean {
  if (hit === undefined || hit.source !== "scancode" || hit.license === null) {
    return false;
  }
  const license = hit.license;
  return entry.licenseClaims.some(
    (c) => c.source === "scancode" && c.raw === license,
  );
}

/**
 * Apply one positive scancode result to a residual package: append the
 * "scancode"-sourced claim, attach attribution when the package carries none
 * (reusing {@link withReplayAttribution}'s sanitize/dedupe/sort/cap contract —
 * a fresh scan result is wrapped into the identical CacheEntry shape so the
 * replay and live-scan paths share one attribution rule, never two), and
 * record the cache entry. A positive scancode result OVERWRITES any existing
 * registry entry for this purl — including a negative one (Pitfall 5: a
 * better answer supersedes no-answer).
 */
function applyScanResult(
  residual: Unknown,
  resolved: { raw: string; via: string; copyrights: string[] },
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
  opts: EnrichOptions,
): void {
  const cacheEntry: CacheEntry = {
    license: resolved.raw,
    source: "scancode",
    fetchedFrom: "scancode",
    via: resolved.via,
    resolvable: true,
    copyrights: resolved.copyrights,
    fetchedAt: (opts.now ?? defaultNow)().toISOString(),
  };
  const withClaim = withCacheClaim(residual.entry, resolved.raw, "scancode");
  packages[residual.index] = withReplayAttribution(withClaim, cacheEntry);
  putEntry(cache, residual.entry.purl, cacheEntry);
}

/**
 * The intensive ScanCode lane (10-04, SCAN-01/SCAN-02): for every residual
 * package (still-unknown after the registry hit/miss pass above), sequentially
 * (D-03 — a per-package wall-clock timeout and honest per-package attribution
 * beat batch amortization; the residual set is tiny by design, so sequential
 * scanning is the simple, honest choice — revisit only if measured cost
 * demands otherwise) map its purl to a locally-present source dir
 * ({@link sourceDirFor}) and, when present, scan it
 * ({@link scanPackageSources}):
 *
 *  - A warm-cache scancode answer already replayed onto the package
 *    ({@link scancodeReplayDone}) → skip before any dir mapping: nothing new
 *    to learn, and a re-scan would restamp `fetchedAt` and churn the
 *    committed cache bytes on every warm run.
 *  - No locally-present source dir → honest skip, zero scan attempted, the
 *    package keeps its existing (possibly still-negative) residual (D-02).
 *  - A clean no-answer scan → writes NOTHING: the existing registry negative
 *    (if any) stays untouched, and no new entry is created (scancode
 *    negatives are not cached — Open Question 2 / the ADR-recorded tradeoff).
 *  - A positive scan → {@link applyScanResult} appends the claim, attaches
 *    attribution, and writes the cache entry (overwriting a negative).
 */
async function scanResidual(
  packages: PackageEntry[],
  cache: Map<string, CacheEntry>,
  intensive: IntensiveOptions,
  opts: EnrichOptions,
): Promise<void> {
  const residual = residualUnknowns(packages);
  const scanOpts = {
    ...(intensive.scancodeBin !== undefined
      ? { scancodeBin: intensive.scancodeBin }
      : {}),
    ...(intensive.timeoutMs !== undefined
      ? { timeoutMs: intensive.timeoutMs }
      : {}),
    ...(intensive.tempDir !== undefined ? { tempDir: intensive.tempDir } : {}),
  };
  for (const entry of residual) {
    if (scancodeReplayDone(entry.entry, getEntry(cache, entry.entry.purl))) {
      continue; // the warm cache already answered: no re-scan, no restamp
    }
    const sourceDir = sourceDirFor(entry.entry.purl, intensive.targetDirs);
    if (sourceDir === undefined) continue; // D-02: no locally-present source, honest skip
    const resolved = await scanPackageSources(sourceDir, scanOpts);
    if (resolved === null) continue; // clean no-answer: write nothing, existing negative stays
    applyScanResult(entry, resolved, packages, cache, opts);
  }
}

/** Record a definitive-no-license negative entry for a miss. */
function recordNegative(
  miss: Unknown,
  cache: Map<string, CacheEntry>,
  fetchedFrom: CacheEntry["fetchedFrom"],
): void {
  putEntry(cache, miss.entry.purl, {
    license: null,
    source: "registry",
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
      source: "registry",
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
