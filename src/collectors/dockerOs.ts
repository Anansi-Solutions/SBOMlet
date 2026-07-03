/**
 * syft Docker OS-package collector — a HYBRID of the cdxgen adapter (exec +
 * version pin + specVersion assert) and the terraform collector (minimal
 * deterministic CycloneDX re-emit + size gate). It is GENERATE-ONLY and is NOT
 * a registry Collector: `gate/check.ts` runs collectTargets on the check path,
 * so a registered collector would force a docker daemon onto every CI check.
 * Its committed OS-SBOM is consumed as a merge INPUT by the pipeline (07-02),
 * never discovered per-run.
 *
 * Why syft: the 07 spike proved syft fills 96.7% dpkg + 100% apk licenses where
 * cdxgen `-t docker` fills 0% dpkg — it solves COLL-04's hard part (OS-package +
 * license extraction across BOTH dpkg and apk).
 *
 * Flow per image:
 *  1. `syft <image> -o cyclonedx-json=<tmp>` via execTool (argv array ONLY —
 *     the image ref is an operand, never a shell string: command injection is
 *     impossible by construction, ASVS V12 / T-07-01).
 *  2. assertSyftSbomSize stat-gates the output before any read (DoS bound,
 *     T-07-02), then parse and assert specVersion === "1.6" (pin verification).
 *  3. filterOsComponents keeps ONLY pkg:deb/pkg:apk components carrying
 *     name+version+purl — syft's file/operating-system/generic/golang entries
 *     are dropped.
 *  4. `docker inspect --format '{{json .RepoDigests}}' <image>` records the
 *     PLATFORM RepoDigest actually scanned (NOT `buildx imagetools inspect`,
 *     which returns the manifest-LIST digest — T-07-03).
 *
 * Emit: a minimal deterministic `{ bomFormat, specVersion:"1.6", components,
 * dockerImages }` doc and nothing else (no serialNumber, no metadata,
 * no timestamp). Serialized via the tool-wide `toSortedJson` contract so a
 * double-emit is byte-identical by construction. Zero new runtime deps — syft
 * and docker are orchestrated pinned CLIs, same posture as cdxgen/tofu.
 */

import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { compareCodeUnits, toSortedJson } from "../model/dependencies";
import { execTool } from "./exec";

/**
 * Collector tool identity. The literal version is the pin — it is mirrored in
 * mise.toml (`aqua:anchore/syft@1.45.1`) and asserted by
 * test/dockerOs.test.ts so a version bump must be conscious. Re-verify against
 * `mise x -- syft version` when refreshing (07-RESEARCH "valid until
 * ~2026-07-15").
 */
export const SYFT_TOOL = { name: "syft", version: "1.45.1" } as const;

/**
 * DoS bound: real syft CycloneDX output is sub-MiB (postgres:18 ≈ 543 KB);
 * 64 MiB is generous headroom. The stat gate fires before any read/parse so a
 * hostile/huge SBOM can never balloon memory (T-07-02, ASVS V12).
 */
export const MAX_SYFT_SBOM_BYTES = 64 * 1024 * 1024;

/** Per-run + per-image timeout for the syft scan / docker inspect spawns. */
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

/** Only deb/apk OS packages are retained; everything else syft emits is noise. */
const OS_PURL_PATTERN = /^pkg:(deb|apk)\//;

/**
 * Stat-gate a syft SBOM path against MAX_SYFT_SBOM_BYTES BEFORE any read or
 * parse. Mirrors terraform.ts assertTerraformLockSize.
 */
export function assertSyftSbomSize(path: string): void {
  const size = statSync(path).size;
  if (size > MAX_SYFT_SBOM_BYTES) {
    throw new Error(
      `syft SBOM at ${path} is ${size} bytes, over the ` +
        `${MAX_SYFT_SBOM_BYTES}-byte cap — refusing to parse it ` +
        `(real syft SBOMs are sub-MiB)`,
    );
  }
}

/**
 * The verified syft 1.45.1 argv. Options come FIRST (the `cyclonedx-json=<file>`
 * output target so syft writes deterministic JSON to the per-run temp file),
 * then a `--` END-OF-OPTIONS separator, then the image OPERAND last. The image
 * ref is always an argv operand (never a shell string — command injection is
 * impossible by construction); the `--` is DEFENSE-IN-DEPTH (#7/#8) so that even
 * a defensively dash-prefixed ref can never be parsed by syft as a flag. syft
 * accepts `syft -o <fmt>=<file> -- <image>` (verified against syft 1.45.1). The
 * literal `cyclonedx-json` format is grep-detectable and locked byte-for-byte by
 * test/dockerOs.test.ts — any flag change must consciously break that test and
 * invalidate the committed OS-SBOM goldens.
 */
export function syftArgs(image: string, outFile: string): string[] {
  return ["-o", `cyclonedx-json=${outFile}`, "--", image];
}

/**
 * docker inspect argv that prints the image's RepoDigests JSON array to stdout.
 * The image is the OPERAND after a `--` END-OF-OPTIONS separator (finding #5,
 * symmetry with syftArgs): a dash-prefixed operand can never be parsed by
 * `docker inspect` as a flag. The ref is always an argv operand, never a shell
 * string — command injection is impossible by construction.
 */
export function dockerInspectArgs(image: string): string[] {
  return ["inspect", "--format", "{{json .RepoDigests}}", "--", image];
}

/**
 * docker pull argv (opt-in `--pull` path). The image is the OPERAND after a `--`
 * END-OF-OPTIONS separator (symmetry with dockerInspectArgs/syftArgs): a
 * dash-prefixed operand can never be parsed by `docker pull` as a flag, and the
 * ref is always an argv operand, never a shell string. Pulling is OPT-IN because
 * the digest-pin contract (resolveDigest) needs the image present in the daemon,
 * yet the default path deliberately does NOT pull — a missing image surfaces
 * loudly rather than racing a network fetch into the determinism contract. The
 * discovery/targeted GitHub Action, which derives its base set only at runtime,
 * turns it on so the resolved bases are present before the scan.
 */
export function dockerPullArgs(image: string): string[] {
  return ["pull", "--", image];
}

/**
 * The three CycloneDX license-claim shapes syft emits per OS package. These are
 * EXACTLY the shapes the merge's `licenseClaimsOf` reads (validate/sbom.ts:
 * SbomExpressionClaim / SbomIdClaim / SbomNameClaim), so preserving them
 * verbatim is what makes OS packages render REAL licenses instead of unknown.
 */
export type OsLicense =
  | { license: { id: string } }
  | { license: { name: string } }
  | { expression: string };

/**
 * One retained OS component: the minimal deterministic emit shape. The
 * `licenses` array is the syft-resolved CycloneDX license claims, PRESERVED so
 * the merge picks them up (the whole reason syft was chosen — 96.7% dpkg /
 * 100% apk fill). Omitted entirely when syft resolved no license for the
 * package (field-absent, never an empty array, so the field stays meaningful
 * and the emit byte-stable).
 */
export interface OsComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  licenses?: OsLicense[];
}

/** The image→platform-digest sidecar entry. */
export interface DockerImageDigest {
  image: string;
  digest: string;
}

/** A syft CycloneDX component as we narrow it — only the fields we read. */
interface RawComponent {
  name?: unknown;
  version?: unknown;
  purl?: unknown;
  licenses?: unknown;
}

/**
 * Narrow one raw `licenses[]` entry to a known CycloneDX claim shape, returning
 * the normalized OsLicense or undefined for any foreign/malformed entry (which
 * is then dropped). The id/name/expression order mirrors licenseClaimsOf's
 * precedence: an entry carrying BOTH license.id and a stray field still maps to
 * the id claim.
 */
function narrowLicense(raw: unknown): OsLicense | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const entry = raw as {
    license?: { id?: unknown; name?: unknown };
    expression?: unknown;
  };
  const license = entry.license;
  if (license !== undefined && license !== null) {
    if (typeof license.id === "string" && license.id.length > 0) {
      return { license: { id: license.id } };
    }
    if (typeof license.name === "string" && license.name.length > 0) {
      return { license: { name: license.name } };
    }
  }
  if (typeof entry.expression === "string" && entry.expression.length > 0) {
    return { expression: entry.expression };
  }
  return undefined;
}

/**
 * Canonical sort key for a normalized OsLicense: a discriminator (`0:` id,
 * `1:` name, `2:` expression) plus its value. syft's per-component license
 * order is not guaranteed stable, so sorting by this key makes the re-emit
 * byte-identical regardless of syft's emission order (the double-emit identity
 * contract must hold WITH licenses).
 */
function licenseSortKey(license: OsLicense): string {
  if ("expression" in license) return `2:${license.expression}`;
  if ("id" in license.license) return `0:${license.license.id}`;
  return `1:${license.license.name}`;
}

/**
 * Extract + normalize + deterministically sort a component's syft license
 * claims. Returns undefined (field-absent) when the component carries no
 * recognizable license — never an empty array — so the emit shape stays
 * meaningful and byte-stable.
 */
function osLicensesOf(raw: RawComponent): OsLicense[] | undefined {
  const licenses = raw.licenses;
  if (!Array.isArray(licenses)) return undefined;
  const narrowed = licenses
    .map(narrowLicense)
    .filter((l): l is OsLicense => l !== undefined);
  if (narrowed.length === 0) return undefined;
  return narrowed.sort((a, b) =>
    compareCodeUnits(licenseSortKey(a), licenseSortKey(b)),
  );
}

/** A parsed syft CycloneDX doc — only the fields we read. */
interface RawSyftSbom {
  specVersion?: unknown;
  components?: unknown;
}

/** True iff the raw component is a deb/apk package carrying name+version+purl. */
function isOsComponent(raw: RawComponent): raw is {
  name: string;
  version: string;
  purl: string;
} {
  const { name, version, purl } = raw;
  if (typeof name !== "string" || name.length === 0) return false;
  if (typeof version !== "string" || version.length === 0) return false;
  if (typeof purl !== "string" || !OS_PURL_PATTERN.test(purl)) return false;
  return true;
}

/**
 * True iff the raw component carries a non-empty string name+version+purl,
 * with NO pattern gate — the "maximal honesty" fullContents predicate (the
 * research-chosen option over a per-ecosystem allowlist). Still drops syft's
 * purl-less file/operating-system noise and any component with an empty
 * name/version, exactly like isOsComponent, just without the deb/apk gate.
 */
function isPurlComponent(raw: RawComponent): raw is {
  name: string;
  version: string;
  purl: string;
} {
  const { name, version, purl } = raw;
  if (typeof name !== "string" || name.length === 0) return false;
  if (typeof version !== "string" || version.length === 0) return false;
  if (typeof purl !== "string" || purl.length === 0) return false;
  return true;
}

/**
 * Filter syft's raw components down to the retained set, purl-sorted and
 * purl-deduped first-wins (mirrors terraform.ts componentsOf) — the whole
 * emission is a pure function of bytes.
 *
 * Default (no options, or fullContents: false): keep ONLY pkg:deb/pkg:apk
 * components carrying name+version+purl — the OS-package gate for base-image
 * scans. Byte-identical to the pre-fullContents behavior; zero call-site edits
 * required outside this file.
 *
 * fullContents: true: keep ANY component carrying a non-empty string
 * name+version+purl, with no ecosystem pattern gate — the generated-image
 * posture (DOCK-01), so application-layer packages (npm/pypi/golang/...)
 * survive alongside the OS packages. Both modes still drop syft's purl-less
 * file/operating-system/generic noise and empty-name/version/purl entries.
 */
export function filterOsComponents(
  sbom: unknown,
  opts?: { fullContents?: boolean },
): OsComponent[] {
  const components = (sbom as RawSyftSbom).components;
  if (!Array.isArray(components)) return [];

  const predicate =
    opts?.fullContents === true ? isPurlComponent : isOsComponent;

  const byPurl = new Map<string, OsComponent>();
  for (const raw of components as RawComponent[]) {
    if (!predicate(raw)) continue;
    // First-wins keying by purl: a duplicate purl collapses to one row.
    if (byPurl.has(raw.purl)) continue;
    const licenses = osLicensesOf(raw);
    byPurl.set(raw.purl, {
      type: "library",
      name: raw.name,
      version: raw.version,
      purl: raw.purl,
      // Field-absent when syft resolved no license — keeps the emit byte-stable
      // (toSortedJson omits undefined) and the field meaningful.
      ...(licenses !== undefined ? { licenses } : {}),
    });
  }

  return [...byPurl.values()].sort((a, b) => compareCodeUnits(a.purl, b.purl));
}

/**
 * Serialize the minimal deterministic OS-SBOM doc:
 * `{ bomFormat, specVersion:"1.6", components, dockerImages }` and nothing else
 * — no serialNumber, no metadata, no timestamp. The dockerImages sidecar is
 * sorted by image. Uses the tool-wide `toSortedJson` contract (sorted keys, LF,
 * indent 2) so a double-emit from the same inputs is byte-identical.
 */
export function emitDockerOsDoc(
  components: OsComponent[],
  dockerImages: DockerImageDigest[],
): string {
  const sortedImages = [...dockerImages].sort((a, b) =>
    compareCodeUnits(a.image, b.image),
  );
  return toSortedJson({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components,
    dockerImages: sortedImages,
  });
}

/** Options mirror the cdxgen/terraform adapters' per-run temp-dir injection. */
export interface DockerOsCollectOptions {
  /** Hard wall-clock limit per spawn; defaults to 10 minutes. */
  timeoutMs?: number;
  /** Pass child stdout/stderr through to process.stderr. */
  verbose?: boolean;
  /** Executable that runs the pinned syft binary. Defaults to "syft". */
  syftBin?: string;
  /** Executable for the digest probe. Defaults to "docker". */
  dockerBin?: string;
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
  /**
   * `docker pull` each image before scanning it (opt-in). Off by default so the
   * standard maintainer path fails loudly on an absent image rather than
   * silently fetching; the discovery/targeted GitHub Action turns it on because
   * it only knows the resolved base set at runtime and cannot pre-pull.
   */
  pull?: boolean;
  /**
   * Collect from LOCALLY BUILT, never-pushed images (opt-in). Off by default —
   * turned on by built-image scan callers: the CLI's built mode and the
   * Docker-scan CI workflow. Why: a built never-pushed image has no
   * RepoDigests (resolveDigest throws by design, never weakened), and any
   * per-build digest (image ID, buildx digest) varies per rebuild — so the
   * committed identity is the stable ref with digest "" (the
   * consumeDockerOsSbom digest-less posture, #6). Built collection also
   * applies fullContents: true (the generated-image posture, DOCK-01) and
   * skips resolveDigest and docker inspect entirely; built + pull is rejected
   * synchronously (a built image is local-only and cannot be pulled).
   */
  built?: boolean;
}

/** The collector result: the serialized doc plus the per-image SBOM temp paths. */
export interface DockerOsResult {
  doc: string;
  sbomPaths: string[];
}

/**
 * Scan one image with syft and return its raw SBOM path. The size gate fires
 * before any read; specVersion is asserted with an actionable error naming the
 * full invocation (cdxgen.ts pin-verification idiom).
 */
async function scanImage(
  image: string,
  outFile: string,
  syftBin: string,
  opts: { timeoutMs: number; verbose: boolean },
): Promise<unknown> {
  const args = syftArgs(image, outFile);
  const invocation = `${syftBin} ${args.join(" ")}`;

  await execTool(syftBin, args, {
    timeoutMs: opts.timeoutMs,
    verbose: opts.verbose,
  });

  if (!existsSync(outFile)) {
    throw new Error(
      `syft produced no output file at ${outFile}\ninvocation: ${invocation}`,
    );
  }
  // Size gate BEFORE read (DoS bound, T-07-02).
  assertSyftSbomSize(outFile);

  // Read outside the parse try: an I/O failure must surface as itself, not as a
  // misleading "not valid JSON" message (cdxgen.ts idiom).
  const rawOutput = readFileSync(outFile, "utf8");
  const sbom = parseSyftOutput(rawOutput, outFile, invocation);
  return sbom;
}

/** Parse + specVersion-assert the syft output, naming the invocation on failure. */
function parseSyftOutput(
  rawOutput: string,
  outFile: string,
  invocation: string,
): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawOutput);
  } catch (error) {
    throw new Error(
      `syft output at ${outFile} is not valid JSON: ${String(error)}\n` +
        `invocation: ${invocation}`,
      { cause: error },
    );
  }
  const specVersion = (parsed as RawSyftSbom).specVersion;
  if (specVersion !== "1.6") {
    throw new Error(
      `syft output specVersion is ${JSON.stringify(specVersion)}, expected ` +
        `"1.6" — wrong syft version or flags?\ninvocation: ${invocation}`,
    );
  }
  return parsed;
}

/**
 * Resolve the PLATFORM RepoDigest of the scanned image via
 * `docker inspect --format '{{json .RepoDigests}}'`. Selects ONE digest
 * DETERMINISTICALLY from the daemon-returned set via {@link selectDigest}
 * (repo-match, else compareCodeUnits-smallest) so the committed
 * docker-os.sbom.json is byte-stable across machines (finding #2) — NOT the
 * daemon-order-dependent `digests[0]`, and NOT the manifest-list digest a
 * `buildx imagetools inspect` would return (T-07-03).
 */
async function resolveDigest(
  image: string,
  dockerBin: string,
  opts: { timeoutMs: number; verbose: boolean },
): Promise<string> {
  const args = dockerInspectArgs(image);
  const invocation = `${dockerBin} ${args.join(" ")}`;
  const { stdout } = await execTool(dockerBin, args, {
    timeoutMs: opts.timeoutMs,
    verbose: opts.verbose,
  });

  const digests = parseRepoDigests(stdout, invocation);
  const selected = selectDigest(image, digests);
  if (selected === undefined) {
    throw new Error(
      `docker inspect returned no RepoDigests for "${image}" — the image ` +
        `must be pulled/built locally before scanning\ninvocation: ${invocation}`,
    );
  }
  return selected;
}

/**
 * Deterministically select ONE RepoDigest from the daemon-returned set (finding
 * #2, 07-31). `docker inspect --format '{{json .RepoDigests}}'` returns a
 * daemon-ORDER-dependent array: an image pulled from / pushed to multiple
 * registries carries multiple RepoDigests whose array order varies by machine.
 * Selecting `digests[0]` therefore makes the committed docker-os.sbom.json
 * machine-dependent, breaking byte-determinism (the check would flag a stale
 * artifact). This selects a pure function of the digest SET, never of emission
 * order:
 *   1. PREFER the digest whose repository (the part before `@sha256:`) matches
 *      the requested image ref's repository — that is the registry the user
 *      asked about, the most meaningful identity;
 *   2. FALL BACK to the compareCodeUnits-SMALLEST digest (a deterministic
 *      function of the set) when no repository matches.
 * The common single-element case returns that one element either way — behavior
 * identical to the prior `digests[0]`. Returns undefined for an empty set (the
 * caller throws).
 */
export function selectDigest(
  image: string,
  digests: readonly string[],
): string | undefined {
  if (digests.length === 0) return undefined;
  // Sort a COPY by code units first so every subsequent pick is order-stable.
  const sorted = [...digests].sort(compareCodeUnits);
  // Prefer the digest whose repository matches the requested image's repository.
  const wantRepo = repositoryOf(image);
  if (wantRepo !== undefined) {
    const match = sorted.find((d) => repositoryOf(d) === wantRepo);
    if (match !== undefined) return match;
  }
  // No repo match → the code-unit-smallest digest (deterministic over the set).
  return sorted[0];
}

/**
 * The repository portion of an image ref or a RepoDigest — everything before an
 * `@sha256:` digest and before any `:tag`. Returns undefined for an empty input.
 * Used to match a requested image ref against a RepoDigest's repository so the
 * selected digest is the registry the user asked about (finding #2). A port in
 * a registry host (`registry:5000/app`) is preserved: only a `:tag` AFTER the
 * last `/` is stripped.
 */
function repositoryOf(ref: string): string | undefined {
  if (ref === "") return undefined;
  // Strip an `@<digest>` suffix first (RepoDigest form `repo@sha256:...`).
  const atIndex = ref.indexOf("@");
  const withoutDigest = atIndex === -1 ? ref : ref.slice(0, atIndex);
  // Strip a trailing `:tag` only when the colon is AFTER the last `/` (so a
  // registry host:port before the path is not mistaken for a tag).
  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  const repo =
    lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  return repo === "" ? undefined : repo;
}

/** Parse the `{{json .RepoDigests}}` stdout into a string array. */
export function parseRepoDigests(stdout: string, invocation: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch (error) {
    throw new Error(
      `docker inspect RepoDigests output is not valid JSON: ${String(error)}\n` +
        `invocation: ${invocation}`,
      { cause: error },
    );
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((d): d is string => typeof d === "string");
}

/**
 * Orchestrate per-image scan + digest + filter, merge all images' components
 * into one purl-deduped sorted list, build the sorted dockerImages sidecar, and
 * return the deterministic doc plus the per-image SBOM temp paths. Async for
 * interface symmetry with the other collectors.
 *
 * Images are scanned in compareCodeUnits-SORTED order (never the caller's
 * argv order): the cross-image purl dedup below is first-wins, so when two
 * images share a purl with DIFFERENT license claims, whichever image is
 * scanned first decides the committed license — an unsorted walk makes that
 * choice a function of argv order, breaking the byte-determinism contract
 * (D-14) for `--built-image b a` vs `--built-image a b` over the identical
 * image SET. Sorting here matches the existing resolveDiscoveredImages /
 * resolveTargetedDockerfiles convention (both already compareCodeUnits-sort
 * before scanning); this closes the one caller path (--built-image, --image)
 * that did not (adversarial review, 09-07, Lens 2).
 */
/**
 * Scan + filter + identify ONE image, applying the pulled-image or
 * built-image posture. Extracted from collectDockerOsSbom to keep that
 * orchestrator under the complexity bound (mirrors the resolveLiveScanImages
 * / run*Mode extraction precedent, 09-01). Pull is a no-op when built (the
 * caller already rejected built+pull); the built branch skips resolveDigest
 * entirely and applies fullContents: true.
 */
async function collectOneImage(
  image: string,
  outFile: string,
  opts: {
    syftBin: string;
    dockerBin: string;
    pull: boolean;
    built: boolean;
    spawnOpts: { timeoutMs: number; verbose: boolean };
  },
): Promise<{
  components: OsComponent[];
  digest: DockerImageDigest;
  sbomPath: string;
}> {
  // Opt-in pull BEFORE the scan so the image is in the daemon for both the
  // syft scan and the resolveDigest `docker inspect` — an absent image on the
  // no-pull default still fails loudly in resolveDigest. Unreachable when
  // built (rejected by the caller), kept as the pulled-image posture only.
  if (opts.pull) {
    await execTool(opts.dockerBin, dockerPullArgs(image), opts.spawnOpts);
  }
  const sbom = await scanImage(image, outFile, opts.syftBin, opts.spawnOpts);

  const filterOpts = opts.built ? { fullContents: true } : undefined;
  const components = filterOsComponents(sbom, filterOpts);

  if (opts.built) {
    // Never resolveDigest for a built image — it has no RepoDigests by
    // construction and any per-build digest is volatile (WR-01 lesson).
    // Record the stable, digest-less identity (consumeDockerOsSbom #6
    // posture) instead.
    return { components, digest: { image, digest: "" }, sbomPath: outFile };
  }
  const digest = await resolveDigest(image, opts.dockerBin, opts.spawnOpts);
  return { components, digest: { image, digest }, sbomPath: outFile };
}

export async function collectDockerOsSbom(
  images: string[],
  opts: DockerOsCollectOptions = {},
): Promise<DockerOsResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const verbose = opts.verbose ?? false;
  const syftBin = opts.syftBin ?? "syft";
  const dockerBin = opts.dockerBin ?? "docker";
  const pull = opts.pull ?? false;
  const built = opts.built ?? false;
  // Built images are local-only: reject synchronously BEFORE the temp-dir
  // mkdtemp or any loop iteration — no execTool call ever happens on this path.
  if (built && pull) {
    throw new Error("built images are local-only and cannot be pulled");
  }
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-syft-"));
  const spawnOpts = { timeoutMs, verbose };

  const byPurl = new Map<string, OsComponent>();
  const dockerImages: DockerImageDigest[] = [];
  const sbomPaths: string[] = [];

  const sortedImages = [...images].sort(compareCodeUnits);
  let index = 0;
  for (const image of sortedImages) {
    const outFile = join(tempDir, `syft-${index}.json`);
    index += 1;
    const result = await collectOneImage(image, outFile, {
      syftBin,
      dockerBin,
      pull,
      built,
      spawnOpts,
    });
    sbomPaths.push(result.sbomPath);
    for (const component of result.components) {
      // First-wins across images: a package shared between images is one row.
      if (!byPurl.has(component.purl)) byPurl.set(component.purl, component);
    }
    dockerImages.push(result.digest);
  }

  const components = [...byPurl.values()].sort((a, b) =>
    compareCodeUnits(a.purl, b.purl),
  );

  return { doc: emitDockerOsDoc(components, dockerImages), sbomPaths };
}

/** The `@sha256:<64 hex>` digest pattern as it appears in an image reference. */
const SHA256_DIGEST_RE = /@(sha256:[0-9a-f]{64})/;

/**
 * Recover the scanned image's @sha256 digest from a syft CycloneDX SBOM's
 * `metadata.component`. syft records the image identity there for a container
 * scan: the manifest digest in `version` (e.g. "sha256:abc…") and/or embedded
 * in the digest-pinned `name` ("registry/app@sha256:abc…"). Returns undefined
 * when no digest is recoverable — the SBOM may have been produced from a tag,
 * not a digest. NEVER fabricates one.
 */
export function digestFromSbom(sbom: unknown): string | undefined {
  const component = (sbom as { metadata?: { component?: unknown } }).metadata
    ?.component;
  if (typeof component !== "object" || component === null) return undefined;
  const { version, name } = component as { version?: unknown; name?: unknown };
  if (typeof version === "string" && /^sha256:[0-9a-f]{64}$/.test(version)) {
    return version;
  }
  if (typeof name === "string") {
    const match = SHA256_DIGEST_RE.exec(name);
    if (match) return match[1];
  }
  return undefined;
}

/**
 * Path-INDEPENDENT image identity for a digest-less SBOM (#6 determinism). A
 * digest-less SBOM (produced from a tag, not a registry digest) must never be
 * identified by its machine-specific ABSOLUTE source path — that drifts per
 * machine and makes the committed docker-os.sbom.json non-deterministic.
 * Instead:
 *   1. prefer metadata.component.name (the image ref/tag — path-free and the
 *      most meaningful identity, e.g. "postgres:18-bookworm");
 *   2. last resort, the file BASENAME (path-free), never the absolute path.
 * Never fabricates a digest; the caller records digest "" alongside this.
 */
function pathFreeImageIdentity(sbom: unknown, path: string): string {
  const component = (sbom as { metadata?: { component?: unknown } }).metadata
    ?.component;
  if (typeof component === "object" && component !== null) {
    const { name } = component as { name?: unknown };
    if (typeof name === "string" && name.trim() !== "") return name;
  }
  return basename(path);
}

/** Options for the pre-made-SBOM ingest path. */
export interface ConsumeDockerOsOptions {
  /** Pass through to the size gate / read; reserved for symmetry. */
  verbose?: boolean;
}

/**
 * INGEST a set of PRE-MADE syft/CycloneDX SBOM file paths WITHOUT running
 * docker/syft — the CI-attestation consumer path. For each SBOM: size-gate (DoS
 * bound, reusing assertSyftSbomSize), parse, filter to pkg:deb/pkg:apk
 * (PRESERVING licenses via filterOsComponents), and record the image's digest
 * from `metadata.component` when present — else the source path, so provenance
 * is never silently lost. Components merge purl-deduped first-wins across files;
 * the emit is the same deterministic doc as the live-scan path.
 *
 * This is the STATE-OF-THE-ART standard: the build CI generates the image's
 * syft SBOM by registry digest (an attestation), and the compliance tool
 * CONSUMES it via `--from-sbom` — no daemon, no network, fully offline.
 *
 * PROVENANCE NOTE (#7): produce the `--from-sbom` SBOM by scanning a
 * PLATFORM-SPECIFIC (single-arch) image, not a multi-arch tag. A manifest-LIST
 * tag resolves to a manifest-list digest, which is NOT the digest of the actual
 * scanned image layers — so the recorded `digest` would not pin the artifact
 * whose packages were inventoried. Scan e.g. `image@sha256:<single-arch>` (or
 * `--platform linux/amd64`) so the recorded digest is the real image digest.
 */
export async function consumeDockerOsSbom(
  sbomPaths: string[],
  _opts: ConsumeDockerOsOptions = {},
): Promise<DockerOsResult> {
  const byPurl = new Map<string, OsComponent>();
  const dockerImages: DockerImageDigest[] = [];

  for (const path of sbomPaths) {
    // Size gate BEFORE read (DoS bound, T-07-02/T-07-04).
    assertSyftSbomSize(path);
    const raw = readFileSync(path, "utf8");
    let sbom: unknown;
    try {
      sbom = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `--from-sbom file at ${path} is not valid JSON: ${String(error)}`,
        { cause: error },
      );
    }

    for (const component of filterOsComponents(sbom)) {
      // First-wins across SBOMs: a package shared between images is one row.
      if (!byPurl.has(component.purl)) byPurl.set(component.purl, component);
    }

    const digest = digestFromSbom(sbom);
    // When the SBOM carries a digest, the image identity IS that digest; when it
    // does not, record a PATH-INDEPENDENT identity (metadata.component.name, else
    // the file basename — #6) so the committed docker-os.sbom.json is
    // byte-identical across machines. Provenance is preserved without leaking the
    // machine-specific absolute path; the digest is never fabricated (left "").
    dockerImages.push(
      digest !== undefined
        ? { image: digest, digest }
        : { image: pathFreeImageIdentity(sbom, path), digest: "" },
    );
  }

  const components = [...byPurl.values()].sort((a, b) =>
    compareCodeUnits(a.purl, b.purl),
  );

  return {
    doc: emitDockerOsDoc(components, dockerImages),
    sbomPaths: [...sbomPaths],
  };
}
