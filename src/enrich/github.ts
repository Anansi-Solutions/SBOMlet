/**
 * GitHub-LICENSE raw-license resolver for `pkg:terraform` providers + modules.
 *
 * Terraform/OpenTofu registries expose NO license field (verified — neither the
 * OpenTofu `registry/docs` JSON nor the Terraform `/v1` API returns one), so the
 * source repo is DERIVED from the registry-enforced naming convention and the
 * license read from the GitHub License API at the component's VERSION TAG.
 *
 * Provider vs module is distinguished by the purl's encodedName SEGMENT COUNT,
 * NOT by host — OpenTofu rewrites BOTH provider and module Sources to
 * registry.opentofu.org, so a host-based branch is invalid:
 *
 *   - provider `<host>/<ns>/<name>` (3 segments)
 *       → `github.com/<ns>/terraform-provider-<name>`
 *       (hashicorp/aws → hashicorp/terraform-provider-aws)
 *   - module   `<host>/<ns>/<name>/<provider>` (4 segments)
 *       → `github.com/<ns>/terraform-<provider>-<name>` from the EXPLICIT
 *       segments (terraform-aws-modules/alb/aws → terraform-aws-modules/terraform-aws-alb).
 *       No namespace heuristic is used — the provider is the explicit 4th
 *       segment, mirroring the collector's 3-path-segment module purl.
 *
 * Like pypi.ts/npm.ts the resolver returns ONLY the RAW string (+ a `via` tag and
 * the raw-LICENSE `downloadUrl`) — it NEVER parses/corrects; normalizeRaw is the
 * single SPDX authority downstream. A NOASSERTION/null spdx_id or a malformed
 * body → null (a DEFINITIVE no-license answer, distinct from a retrieval
 * failure, which the orchestrator surfaces loudly). The resolver does NOT fetch
 * — it consumes an already-fetched body (the pypi/npm contract); fetch wiring +
 * ordered-ref fallback live in enrich.ts.
 */
import { narrowGithubLicense } from "../validate/registry";

/** A `terraform`-typed purl parsed into its encoded name + version. */
interface ParsedTerraformPurl {
  type: string;
  /**
   * The host-prefixed name: `<host>/<ns>/<name>` (3 segments = provider) or
   * `<host>/<ns>/<name>/<provider>` (4 segments = module). The SEGMENT COUNT —
   * not the host — distinguishes the two.
   */
  encodedName: string;
  version: string;
}

/** A derived GitHub source repo: the owner/repo plus a `github.com/...` raw form. */
export interface GithubTarget {
  owner: string;
  repo: string;
  /** `github.com/<owner>/<repo>` (audit trail; never used to build a fetch host). */
  raw: string;
}

/** A resolved raw license: the SPDX string, the `via` tag, and the raw-text URL. */
export interface GithubResolution {
  raw: string;
  via: "github-license";
  /** download_url to the raw LICENSE text — reused for OUT-02 notices later. */
  downloadUrl?: string;
}

/** Build a {@link GithubTarget} from an owner + repo (single raw-form site). */
function target(owner: string, repo: string): GithubTarget {
  return { owner, repo, raw: `github.com/${owner}/${repo}` };
}

/**
 * Derive the GitHub source repo from the parsed terraform purl by the registry
 * naming convention, distinguishing provider from module by the encodedName's
 * SEGMENT COUNT (3 = provider, 4 = module) rather than by host. Returns null
 * for a malformed name (any other segment count) — never a wrong guess.
 *
 *   3-segment `<host>/<ns>/<name>`            → <ns>/terraform-provider-<name>
 *   4-segment `<host>/<ns>/<name>/<provider>` → <ns>/terraform-<provider>-<name>
 */
export function githubRepoFor(
  parsed: ParsedTerraformPurl,
): GithubTarget | null {
  const segments = parsed.encodedName.split("/");

  if (segments.length === 3) {
    const [, namespace, name] = segments as [string, string, string];
    return target(namespace, `terraform-provider-${name}`);
  }
  if (segments.length === 4) {
    const [, namespace, name, provider] = segments as [
      string,
      string,
      string,
      string,
    ];
    return target(namespace, `terraform-${provider}-${name}`);
  }
  return null;
}

/**
 * The ORDERED candidate refs for the version-tag fetch (W#4): the `v<version>`
 * tag first, then the bare `<version>` tag. There is NO default-branch fallback:
 * the `undefined` (no `?ref`) sentinel is DELIBERATELY OMITTED. GitHub answers a
 * no-`?ref` request from the DEFAULT BRANCH (HEAD) — a DIFFERENT version's
 * license than the pin — which would be cached as the component's license,
 * silently wrong. Dropping it makes a missing version tag a DEFINITIVE negative
 * → unknown → an honest warn, never a confident wrong-version license. The first
 * ref returning a resolvable license wins; a missing tag (404) advances to the
 * next, and exhausting both candidates is a clean no-license answer.
 */
export function githubLicenseRefsFor(version: string): Array<string> {
  return [`v${version}`, version];
}

/**
 * Resolve a raw GitHub license from an already-fetched License API body. Narrows
 * the untrusted body first (malformed → null, never a throw), then returns the
 * spdx_id verbatim. A NOASSERTION/null spdx_id is a DEFINITIVE no-license answer
 * → null. The download_url is carried through for OUT-02.
 */
export function resolveGithubLicense(body: unknown): GithubResolution | null {
  const narrowed = narrowGithubLicense(body);
  if (narrowed === undefined) return null;

  const spdxId = narrowed.spdxId?.trim();
  if (spdxId === undefined || spdxId === "" || spdxId === "NOASSERTION") {
    return null;
  }

  return narrowed.downloadUrl === undefined
    ? { raw: spdxId, via: "github-license" }
    : { raw: spdxId, via: "github-license", downloadUrl: narrowed.downloadUrl };
}
