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
 * Flow per image (ONE posture — every scan reads the image's FULL contents):
 *  1. Probe local presence with `docker inspect`; if the image is absent
 *     (nonzero exit) `docker pull` it first. A locally present ref is scanned
 *     as-is and never re-pulled, so a stale local tag is never silently
 *     refreshed and the network is never raced into the determinism contract.
 *  2. `syft <image> -o cyclonedx-json=<tmp>` via execTool (argv array ONLY —
 *     the image ref is an operand, never a shell string: command injection is
 *     impossible by construction, ASVS V12 / T-07-01).
 *  3. assertSyftSbomSize stat-gates the output before any read (DoS bound,
 *     T-07-02), then parse and assert specVersion === "1.6" (pin verification).
 *  4. filterOsComponents keeps EVERY component carrying name+version+purl,
 *     across ecosystems (deb/apk/npm/pypi/...) — syft's purl-less
 *     file/operating-system/generic entries are dropped.
 *  5. `docker inspect --format '{{json .RepoDigests}}' <image>` records the
 *     PLATFORM RepoDigest actually scanned (NOT `buildx imagetools inspect`,
 *     which returns the manifest-LIST digest — T-07-03); an image with no
 *     RepoDigests (a local-only / never-pushed build) records digest "".
 *
 * Emit: a minimal deterministic `{ bomFormat, specVersion:"1.6", components,
 * dockerImages }` doc and nothing else (no serialNumber, no metadata,
 * no timestamp). Each component carries `images` — the sorted membership of
 * `dockerImages[].image` values it was seen in — and each dockerImages entry
 * carries `source`, the identity the image came from (the Dockerfile identity
 * for built images, the requested ref verbatim otherwise). Serialized via the
 * tool-wide `toSortedJson` contract so a double-emit is byte-identical by
 * construction. Zero new runtime deps — syft and docker are orchestrated
 * pinned CLIs, same posture as cdxgen/tofu.
 */

import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
 * docker pull argv for the probe-first implicit pull. The image is the OPERAND
 * after a `--` END-OF-OPTIONS separator (symmetry with dockerInspectArgs/
 * syftArgs): a dash-prefixed operand can never be parsed by `docker pull` as a
 * flag, and the ref is always an argv operand, never a shell string. Pull runs
 * ONLY when the presence probe finds the image absent locally — a present tag
 * is scanned as-is, so the network is never raced into the determinism contract
 * and a stale local tag is never silently refreshed.
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

/**
 * One EMITTED component: an OsComponent plus its cross-image membership.
 * `images` is the sorted list of `dockerImages[].image` values the component
 * was seen in. Attribution attaches ONLY in the cross-image union
 * ({@link unionOsComponents}) — {@link filterOsComponents} stays per-image and
 * membership-free — so the emitted doc always says which image(s) each
 * component came from.
 */
export interface AttributedOsComponent extends OsComponent {
  images: string[];
}

/**
 * The image→platform-digest sidecar entry. `source` records the identity the
 * image came from: the Dockerfile identity for built images (the exact string
 * `--list-dockerfiles` prints), the requested ref verbatim for pre-existing
 * images (source === image). A digest never appears in a source — digests
 * live in `digest`, so a re-pin can never churn an identity.
 */
export interface DockerImageDigest {
  image: string;
  digest: string;
  source: string;
}

/**
 * One image to scan: the ref handed to syft/docker as an operand plus the
 * source identity it stands for, carried into the emitted
 * `dockerImages[].source` (see {@link DockerImageDigest}).
 */
export interface ScanImage {
  image: string;
  source: string;
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

/**
 * True iff the raw component carries a non-empty string name+version+purl,
 * across ALL ecosystems (deb/apk/npm/pypi/...) — the single full-image-contents
 * predicate. Drops syft's purl-less file/operating-system/generic noise and any
 * component with an empty name/version/purl.
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
 * ONE posture: keep EVERY component carrying a non-empty string
 * name+version+purl, across all ecosystems (deb/apk/npm/pypi/...) — the full
 * image contents (D-03). syft's purl-less file/operating-system/generic noise
 * and empty-name/version/purl entries are dropped.
 */
export function filterOsComponents(sbom: unknown): OsComponent[] {
  const components = (sbom as RawSyftSbom).components;
  if (!Array.isArray(components)) return [];

  const byPurl = new Map<string, OsComponent>();
  for (const raw of components as RawComponent[]) {
    if (!isPurlComponent(raw)) continue;
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
 * Cross-image membership UNION: fold each image's filtered components into one
 * purl-keyed set where a purl shared between images is ONE row whose `images`
 * lists every containing image (sorted before return). The retained
 * name/version/licenses are the FIRST-SEEN values — callers pass images in
 * compareCodeUnits-sorted order (collectDockerOsSbom's scan discipline), so
 * the license posture stays first-wins-by-sorted-image: unchanged from the
 * pre-membership dedup, just visible now that the row names both images.
 */
export function unionOsComponents(
  perImage: ReadonlyArray<{ image: string; components: OsComponent[] }>,
): AttributedOsComponent[] {
  const byPurl = new Map<string, AttributedOsComponent>();
  for (const { image, components } of perImage) {
    for (const component of components) {
      const existing = byPurl.get(component.purl);
      if (existing === undefined) {
        byPurl.set(component.purl, { ...component, images: [image] });
      } else if (!existing.images.includes(image)) {
        // Purl hit: union the membership, keep the first-seen fields. The
        // includes guard keeps a duplicated ref in the scan set from
        // double-counting one image.
        existing.images.push(image);
      }
    }
  }
  const merged = [...byPurl.values()].sort((a, b) =>
    compareCodeUnits(a.purl, b.purl),
  );
  for (const entry of merged) entry.images.sort(compareCodeUnits);
  return merged;
}

/**
 * Serialize the minimal deterministic OS-SBOM doc:
 * `{ bomFormat, specVersion:"1.6", components, dockerImages }` and nothing else
 * — no serialNumber, no metadata, no timestamp. Components carry their sorted
 * `images` membership; dockerImages entries carry `source` alongside
 * image/digest, and the sidecar is sorted by image. Uses the tool-wide
 * `toSortedJson` contract (sorted keys, LF, indent 2) so a double-emit from
 * the same inputs is byte-identical.
 */
export function emitDockerOsDoc(
  components: AttributedOsComponent[],
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
 * `buildx imagetools inspect` would return (T-07-03). Returns "" when the image
 * has no RepoDigests (a local-only / never-pushed build — e.g. a just-built
 * tag), which is the generalized digest-less identity.
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
  // Absent RepoDigests → the generalized digest-less identity (a local-only,
  // never-pushed image, e.g. a just-built tag). Never a throw: resolveDigest
  // runs only AFTER a successful scan, so "" can never mask a typo'd ref — an
  // absent ref fails earlier at the pull/scan step (T-13-05).
  return selectDigest(image, digests) ?? "";
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
 * Orchestrate per-image scan + digest + filter, union all images' components
 * into one purl-keyed sorted list carrying per-image membership, build the
 * sorted dockerImages sidecar (each entry carrying its source identity), and
 * return the deterministic doc plus the per-image SBOM temp paths. Async for
 * interface symmetry with the other collectors.
 *
 * Images are scanned in compareCodeUnits-SORTED order (never the caller's
 * argv order): the cross-image union keeps the FIRST-SEEN license claims, so
 * when two images share a purl with DIFFERENT claims, whichever image is
 * scanned first decides the committed license — an unsorted walk makes that
 * choice a function of argv order, breaking the byte-determinism contract
 * (D-14) for `--image b a` vs `--image a b` over the identical image SET.
 * Sorting here matches the existing resolveDiscoveredImages /
 * resolveTargetedDockerfiles convention (both already compareCodeUnits-sort
 * before scanning); this closes the one caller path (--image) that did not
 * (adversarial review, 09-07, Lens 2).
 */
/**
 * Scan + filter + identify ONE image with the single posture: probe local
 * presence, implicitly pull when absent, scan the FULL contents, then resolve
 * the digest (pinned when RepoDigests exist, "" when they do not). Extracted
 * from collectDockerOsSbom to keep that orchestrator under the complexity bound
 * (mirrors the resolveLiveScanImages / run*Mode extraction precedent).
 */
async function collectOneImage(
  image: string,
  outFile: string,
  opts: {
    syftBin: string;
    dockerBin: string;
    spawnOpts: { timeoutMs: number; verbose: boolean };
  },
): Promise<{
  components: OsComponent[];
  digest: string;
  sbomPath: string;
}> {
  // Probe-first implicit pull: a locally-present ref is scanned as-is (never
  // re-pulled, so a stale tag is never silently refreshed); only an absent ref
  // is pulled, and if the pull fails the error surfaces BEFORE any scan or
  // digest resolution (T-13-05 — "" can never mask a typo'd ref).
  if (!(await imageIsPresentLocally(image, opts.dockerBin, opts.spawnOpts))) {
    await execTool(opts.dockerBin, dockerPullArgs(image), opts.spawnOpts);
  }
  const sbom = await scanImage(image, outFile, opts.syftBin, opts.spawnOpts);
  const components = filterOsComponents(sbom);
  const digest = await resolveDigest(image, opts.dockerBin, opts.spawnOpts);
  return { components, digest, sbomPath: outFile };
}

/**
 * True iff `docker inspect <image>` exits zero — the image is present in the
 * local daemon. A nonzero exit (execTool rejects) means absent; we never parse
 * `docker images` output (a fragile, format-unstable hand-roll). The same
 * `docker inspect` the digest step runs, used here only for its exit code.
 */
async function imageIsPresentLocally(
  image: string,
  dockerBin: string,
  spawnOpts: { timeoutMs: number; verbose: boolean },
): Promise<boolean> {
  try {
    await execTool(dockerBin, dockerInspectArgs(image), spawnOpts);
    return true;
  } catch {
    return false;
  }
}

export async function collectDockerOsSbom(
  images: readonly ScanImage[],
  opts: DockerOsCollectOptions = {},
): Promise<DockerOsResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const verbose = opts.verbose ?? false;
  const syftBin = opts.syftBin ?? "syft";
  const dockerBin = opts.dockerBin ?? "docker";
  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-syft-"));
  const spawnOpts = { timeoutMs, verbose };

  const perImage: { image: string; components: OsComponent[] }[] = [];
  const dockerImages: DockerImageDigest[] = [];
  const sbomPaths: string[] = [];

  const sortedImages = [...images].sort((a, b) =>
    compareCodeUnits(a.image, b.image),
  );
  let index = 0;
  for (const { image, source } of sortedImages) {
    const outFile = join(tempDir, `syft-${index}.json`);
    index += 1;
    const result = await collectOneImage(image, outFile, {
      syftBin,
      dockerBin,
      spawnOpts,
    });
    sbomPaths.push(result.sbomPath);
    perImage.push({ image, components: result.components });
    dockerImages.push({ image, digest: result.digest, source });
  }

  return {
    doc: emitDockerOsDoc(unionOsComponents(perImage), dockerImages),
    sbomPaths,
  };
}
