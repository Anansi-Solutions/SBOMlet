/**
 * Cache-integrity audit: re-resolve every re-resolvable committed
 * enrichment-cache entry against its registry and compare the stored raw
 * license.
 *
 * The committed cache is what `check` trusts OFFLINE, so a hand-edited entry —
 * a flipped license, a fabricated package, or a `resolvable:false` hiding a real
 * copyleft license — would pass the gate silently. `verify-cache` is the ONLINE
 * counterpart: for every registry-sourced entry it re-derives the registry's
 * current answer with the SAME resolvers `generate` uses (enrich.ts) and flags
 * any divergence. A divergence is either tampering or a genuine upstream
 * license change; both warrant a human look before a release or audit.
 *
 * The comparison is a single equality on the raw license string: a cached value
 * (string for a positive entry, null for a negative one) versus the freshly
 * resolved value. That one check covers every tamper shape — a changed string, a
 * fabricated entry the registry now 404s (→ null), and a negative entry the
 * registry contradicts with a real license. A registry/network FAILURE is a loud
 * inability to verify (it propagates and the CLI exits 3), NEVER silently treated
 * as agreement — exactly the reliability posture `generate` already takes.
 */
import { parseGithubBlobPermalink } from "../validate/githubPermalink";
import { narrowGithubContentsFile } from "../validate/registry";
import { compareCodeUnits } from "../model/dependencies";
import {
  githubLicenseUrl,
  npmPackumentUrl,
  parsePurl,
  pypiJsonUrl,
  resolveFromDocument,
  type ParsedPurl,
} from "./enrich";
import { depsDevVersionUrl, resolveMavenLicenses } from "./maven";
import { readCache, type CacheEntry } from "./cache";
import {
  fetchGithubLicense,
  fetchJson,
  fetchJsonOr404,
  mapLimit,
} from "./fetch";
import {
  githubLicenseRefsFor,
  githubRepoFor,
  resolveGithubLicense,
} from "./github";
import {
  catalogEntryUrlOf,
  nugetRegistrationLeafUrl,
  resolveNugetCatalogLicense,
  urlOnlyLicenseUrlOf,
} from "./nuget";
import { GITHUB_API_HOST, resolveUrlOnlyGithubLicense } from "./nugetGithub";

/** Bounded concurrency over the audit fetch set (mirrors enrich's FETCH_CONCURRENCY). */
const VERIFY_CONCURRENCY = 8;

/** The purl types the cache can hold and this audit can re-resolve. */
const VERIFIABLE_TYPES = new Set([
  "pypi",
  "npm",
  "terraform",
  "nuget",
  "maven",
]);

export interface VerifyOptions {
  /** Committed cache path (base-dir-resolved by the caller). */
  cachePath: string;
  verbose: boolean;
  /** Backoff base in ms forwarded to the fetchers (tests pass a small value). */
  backoffBaseMs?: number;
  /**
   * Evidence-pinned `[[clarify]]` decisions to drift-check against their cited
   * GitHub permalink. Shaped by the caller (verifyCache.ts) from the
   * parsed policy's `clarify` entries that carry `evidence_url` — this module
   * never reads TOML or the `Policy` type directly. Absent/empty runs zero
   * evidence fetches, so a policy with no evidence-pinned clarify is unaffected.
   */
  evidencePins?: ReadonlyArray<EvidencePin>;
}

/** One entry whose committed license disagrees with the registry's current answer. */
export interface CacheMismatch {
  purl: string;
  /** The committed raw license (null = a committed negative entry). */
  cached: string | ReadonlyArray<string> | null;
  /** The registry's current raw license (null = no license / not found). */
  current: string | ReadonlyArray<string> | null;
  /** A short, human reason for the divergence. */
  reason: string;
}

/**
 * One evidence-pinned `[[clarify]]` decision: the package/version it
 * disambiguates plus the GitHub blob permalink cited as evidence. Purl-free by
 * design — a clarify targets a package name/version pair directly, not a purl.
 */
export interface EvidencePin {
  name: string;
  version: string;
  /** The immutable GitHub blob permalink cited as evidence (schema-validated). */
  evidenceUrl: string;
}

/** One package a drifted evidence permalink was cited for. */
export interface EvidenceDriftPackage {
  name: string;
  version: string;
}

/**
 * A pinned evidence document that no longer reads the way it was cited when the
 * clarify decision was made — gone at the pinned commit, moved on the default
 * branch, or changed content at the same path. Purl-independent: keyed by
 * the permalink, naming every clarify package/version that cites it.
 */
export interface EvidenceDriftFinding {
  /** The evidence_url permalink exactly as cited in the policy. */
  permalink: string;
  /** Every clarify package/version sharing this permalink. */
  packages: EvidenceDriftPackage[];
  reason: string;
}

export interface VerifyResult {
  /** Entries actually re-resolved against a registry. */
  audited: number;
  /** Divergences, sorted by purl for deterministic reporting. */
  mismatches: CacheMismatch[];
  /** Evidence-permalink drift findings, sorted by permalink for deterministic reporting. */
  evidenceDrift: EvidenceDriftFinding[];
}

/** Memoizing document fetcher: one network call per distinct URL, shared across entries. */
type FetchDoc = (url: string) => Promise<unknown>;

/**
 * The registry's CURRENT raw license for a parsed purl, or null for a definitive
 * no-license answer. This is exactly `generate`'s per-package resolution
 * (enrich.ts) with the cache-write and claim-append stripped out: pypi/npm read
 * one registry document; terraform walks the ordered version-tag refs and takes
 * the first resolvable one. A transient fetch failure throws (loud), never null.
 */
async function currentRegistryLicense(
  parsed: ParsedPurl,
  fetchDoc: FetchDoc,
  fetchOpts: { backoffBaseMs?: number },
): Promise<string | ReadonlyArray<string> | null> {
  if (parsed.type === "pypi" || parsed.type === "npm") {
    const url =
      parsed.type === "pypi"
        ? pypiJsonUrl(parsed.encodedName, parsed.version)
        : npmPackumentUrl(parsed.encodedName);
    const resolved = resolveFromDocument(parsed, await fetchDoc(url));
    return resolved === null ? null : resolved.raw;
  }
  if (parsed.type === "nuget") return currentNugetLicense(parsed, fetchOpts);
  if (parsed.type === "maven") return currentMavenLicense(parsed, fetchOpts);
  // terraform → GitHub License API at the version tag (same ordered-ref walk as
  // generate: v<version> then <version>; first resolvable wins, 404 advances).
  const repo = githubRepoFor(parsed);
  if (repo === null) return null;
  for (const ref of githubLicenseRefsFor(parsed.version)) {
    const result = await fetchGithubLicense(
      githubLicenseUrl(repo.owner, repo.repo, ref),
      fetchOpts,
    );
    if (result.status === 404) continue;
    const resolved = resolveGithubLicense(result.body);
    if (resolved === null) continue;
    return resolved.raw;
  }
  return null;
}

/**
 * The nuget re-resolution: registration leaf → host-pinned catalogEntry →
 * {@link resolveNugetCatalogLicense} — the SAME resolver, host pin, and
 * 404→null classification `generate` uses (enrich.ts). The two-step goes
 * DIRECT rather than through the memoized fetchDoc: that memo is single-URL
 * and the cache holds one entry per purl, so memoization buys nothing here.
 * When the catalogEntry has no directly resolvable license, the SAME
 * {@link resolveUrlOnlyGithubLicense} router `generate` falls back to for a
 * url-only `licenseUrl` re-runs here too: a rung-written entry re-verifies to
 * the identical answer instead of reading as a false mismatch, and a
 * pre-rung committed negative the rung can now resolve surfaces as the
 * intended hidden-obligation mismatch, not a bug. A clean 404 (either hop)
 * and a malformed/foreign-host catalogEntry map to null — the definitive
 * no-answer — while a transient failure throws (loud).
 */
async function currentNugetLicense(
  parsed: ParsedPurl,
  fetchOpts: { backoffBaseMs?: number },
): Promise<string | null> {
  const leaf = await fetchJsonOr404(
    nugetRegistrationLeafUrl(parsed.encodedName, parsed.version),
    fetchOpts,
  );
  if (leaf.status === 404) return null;
  const catalogUrl = catalogEntryUrlOf(leaf.body);
  if (catalogUrl === undefined) return null;
  const catalog = await fetchJsonOr404(catalogUrl, fetchOpts);
  if (catalog.status === 404) return null;
  const resolved = resolveNugetCatalogLicense(catalog.body);
  if (resolved !== null) return resolved.raw;
  const licenseUrl = urlOnlyLicenseUrlOf(catalog.body);
  if (licenseUrl === undefined) return null;
  const viaGithub = await resolveUrlOnlyGithubLicense(licenseUrl, fetchOpts);
  return viaGithub === null ? null : viaGithub.raw;
}

/**
 * The deps.dev re-resolution: ONE fetch (no two-step hop) using the SAME
 * fixed-host URL builder and honest-sentinel resolver `generate` uses
 * (maven.ts). A clean 404 and an all-non-standard/empty answer both map to
 * null — the definitive no-answer — while a transient failure throws (loud).
 */
async function currentMavenLicense(
  parsed: ParsedPurl,
  fetchOpts: { backoffBaseMs?: number },
): Promise<string | ReadonlyArray<string> | null> {
  const result = await fetchJsonOr404(
    depsDevVersionUrl(parsed.encodedName, parsed.version),
    fetchOpts,
  );
  if (result.status === 404) return null;
  const resolved = resolveMavenLicenses(result.body);
  if (resolved === null) return null;
  return resolved.raws.length === 1 ? resolved.raws[0]! : resolved.raws;
}

/**
 * Order/shape-independent equality for a cache-license value: a plain string
 * and a single-element array of the same string compare equal, and two
 * arrays compare equal regardless of entry order (deps.dev's `licenses[]`
 * carries no ordering guarantee). Both null → equal (no divergence).
 */
function licenseValuesEqual(
  a: string | ReadonlyArray<string> | null,
  b: string | ReadonlyArray<string> | null,
): boolean {
  const arrA = a === null ? [] : Array.isArray(a) ? a : [a];
  const arrB = b === null ? [] : Array.isArray(b) ? b : [b];
  if (arrA.length !== arrB.length) return false;
  const sortedA = [...arrA].sort(compareCodeUnits);
  const sortedB = [...arrB].sort(compareCodeUnits);
  return sortedA.every((value, index) => value === sortedB[index]);
}

/** Describe a divergence between the committed value and the registry's answer. */
function reasonFor(
  cached: string | ReadonlyArray<string> | null,
  current: string | ReadonlyArray<string> | null,
): string {
  if (cached !== null && current === null) {
    return "committed a license; the registry now resolves none (yanked, retagged, or fabricated)";
  }
  if (cached === null && current !== null) {
    return "committed as no-license; the registry resolves a real license (a hidden obligation)";
  }
  return "license changed since the cache was written";
}

/**
 * Audit one entry: re-resolve and compare. Returns a mismatch, or null when the
 * committed license still matches the registry. An entry whose key is not a
 * re-resolvable purl is itself a finding — `generate` only ever writes
 * pypi/npm/terraform entries, so anything else was not written by this tool.
 */
async function auditEntry(
  purl: string,
  entry: CacheEntry,
  fetchDoc: FetchDoc,
  fetchOpts: { backoffBaseMs?: number },
): Promise<CacheMismatch | null> {
  const parsed = parsePurl(purl);
  if (parsed === undefined || !VERIFIABLE_TYPES.has(parsed.type)) {
    return {
      purl,
      cached: entry.license,
      current: null,
      reason: "not a re-resolvable purl — this tool never writes such an entry",
    };
  }
  const current = await currentRegistryLicense(parsed, fetchDoc, fetchOpts);
  if (licenseValuesEqual(entry.license, current)) return null;
  return {
    purl,
    cached: entry.license,
    current,
    reason: reasonFor(entry.license, current),
  };
}

/**
 * The GitHub Contents API URL for a file at a ref (fixed `api.github.com` host,
 * the same SSRF control every other GitHub resolver in this codebase uses). An
 * absent `ref` reads the repo's default branch — the mutable side of the
 * pinned-vs-current comparison.
 */
function githubContentsUrl(
  owner: string,
  repo: string,
  path: string,
  ref?: string,
): string {
  const encodedPath = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const base = `${GITHUB_API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}`;
  return ref === undefined ? base : `${base}?ref=${encodeURIComponent(ref)}`;
}

/**
 * The git blob SHA of a file at a ref — content-addressed, so equal SHAs mean
 * byte-identical content without fetching the body. Reuses
 * {@link fetchGithubLicense}'s exact posture (token, retry/backoff, the
 * transient-vs-definitive split): a 404 is DEFINITIVE (the file is gone at that
 * ref, not a retrieval failure) and returns null; a persistent failure throws
 * {@link GithubTransientError}, never a silent null.
 */
async function contentsBlobSha(
  owner: string,
  repo: string,
  path: string,
  ref: string | undefined,
  fetchOpts: { backoffBaseMs?: number },
): Promise<string | null> {
  const result = await fetchGithubLicense(
    githubContentsUrl(owner, repo, path, ref),
    fetchOpts,
  );
  if (result.status === 404) return null;
  return narrowGithubContentsFile(result.body)?.sha ?? null;
}

/**
 * Group evidence pins by their cited permalink: 42 clarify entries may share
 * one document, so the drift audit fetches each DISTINCT permalink once and
 * names every package it was cited for.
 */
function groupEvidencePins(
  pins: ReadonlyArray<EvidencePin>,
): Map<string, EvidenceDriftPackage[]> {
  const groups = new Map<string, EvidenceDriftPackage[]>();
  for (const pin of pins) {
    const packages = groups.get(pin.evidenceUrl) ?? [];
    packages.push({ name: pin.name, version: pin.version });
    groups.set(pin.evidenceUrl, packages);
  }
  return groups;
}

/**
 * Audit one distinct evidence permalink: compare the pinned blob against the
 * same path on the repo's current default branch. Three findings, each naming
 * every package the permalink was cited for: the pinned commit no longer
 * resolves (history rewritten or garbage-collected); the path is gone from the
 * default branch (moved or renamed); or the content differs (drift).
 * Whole-file granularity is intended — an unrelated edit re-firing this is
 * an acceptable false positive for an advisory signal. A malformed
 * `evidence_url` cannot reach here: the policy schema rejects it at parse time,
 * so this is a defensive null, not a real path.
 */
async function auditEvidencePermalink(
  permalink: string,
  packages: EvidenceDriftPackage[],
  fetchOpts: { backoffBaseMs?: number },
): Promise<EvidenceDriftFinding | null> {
  const target = parseGithubBlobPermalink(permalink);
  if (target === null) return null;
  const { owner, repo, sha, path } = target;
  const names = packages.map((p) => `${p.name}@${p.version}`).join(", ");

  const pinned = await contentsBlobSha(owner, repo, path, sha, fetchOpts);
  if (pinned === null) {
    return {
      permalink,
      packages,
      reason:
        `pinned evidence is no longer resolvable at commit ${sha} — the ` +
        `history may have been rewritten, or the object garbage-collected — ` +
        `for ${names}: re-verify and re-pin`,
    };
  }
  const head = await contentsBlobSha(owner, repo, path, undefined, fetchOpts);
  if (head === null) {
    return {
      permalink,
      packages,
      reason:
        `evidence file "${path}" no longer exists on the default branch ` +
        `for ${names}: re-verify and re-pin`,
    };
  }
  if (head === pinned) return null;
  return {
    permalink,
    packages,
    reason:
      `evidence for ${names} changed upstream since commit ${sha} — the ` +
      `default branch now reads differently: re-verify and re-pin`,
  };
}

/**
 * Drift-check every distinct evidence permalink cited by an evidence-pinned
 * clarify decision. Zero pins runs zero GitHub Contents fetches — a
 * policy with no `evidence_url` entries is unaffected byte-for-byte.
 */
async function auditEvidenceDrift(
  pins: ReadonlyArray<EvidencePin>,
  fetchOpts: { backoffBaseMs?: number },
): Promise<EvidenceDriftFinding[]> {
  const groups = [...groupEvidencePins(pins)];
  const findings = await mapLimit(
    groups,
    VERIFY_CONCURRENCY,
    ([permalink, packages]) =>
      auditEvidencePermalink(permalink, packages, fetchOpts),
  );
  return findings
    .filter((f): f is EvidenceDriftFinding => f !== null)
    .sort((a, b) => compareCodeUnits(a.permalink, b.permalink));
}

/**
 * Re-verify every committed cache entry against its registry. Reads the cache
 * (a malformed envelope throws loudly, as in `check`), re-resolves each entry
 * with bounded concurrency and per-URL fetch de-duplication, and returns the
 * divergences sorted by purl. A network failure propagates (the caller maps it
 * to a tool error), so an unreachable registry never reads as "all clean".
 */
export async function verifyCache(opts: VerifyOptions): Promise<VerifyResult> {
  const cache = readCache(opts.cachePath);
  const fetchOpts =
    opts.backoffBaseMs === undefined
      ? {}
      : { backoffBaseMs: opts.backoffBaseMs };

  // One network call per distinct URL: many npm versions share a packument, and
  // a repeated URL reuses the in-flight promise (dedup survives concurrency).
  const documents = new Map<string, Promise<unknown>>();
  const fetchDoc: FetchDoc = (url) => {
    let pending = documents.get(url);
    if (pending === undefined) {
      pending = fetchJson(url, fetchOpts);
      documents.set(url, pending);
    }
    return pending;
  };

  const entries = [...cache.entries()];
  const audited = await mapLimit(entries, VERIFY_CONCURRENCY, ([purl, entry]) =>
    auditEntry(purl, entry, fetchDoc, fetchOpts),
  );
  const mismatches = audited
    .filter((m): m is CacheMismatch => m !== null)
    .sort((a, b) => compareCodeUnits(a.purl, b.purl));
  const evidenceDrift = await auditEvidenceDrift(
    opts.evidencePins ?? [],
    fetchOpts,
  );

  return {
    audited: entries.length,
    mismatches,
    evidenceDrift,
  };
}
