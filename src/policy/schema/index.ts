/**
 * The Policy aggregate: the validated shape every scan-time lane reads.
 *
 * Each field's construct - its type, validation, and closed vocabulary - is defined in its own
 * sibling module in this folder; the parsing that assembles them into a Policy lives in ../parse.
 */
import type { CacheConfig } from "./cache";
import type { DevDependencyHandling, OsDependencyHandling } from "./categories";
import type { ClarifyRule } from "./clarify";
import type { CompatibleRule } from "./compatible";
import type { DockerConfig } from "./container";
import type { DocumentConfig } from "./document";
import type { AllowSourceAvailable, SuppressedWorkspace } from "./exemptions";
import type { TargetConfig } from "./targetProfile";

import type { DenyRule } from "./deny";

export interface Policy {
  /** Default "warn" when the [unknown] table is absent. */
  unknownHandling: "warn" | "fail";
  /** Default "warn" when the [dev_dependencies] table is absent. */
  devDependencies: DevDependencyHandling;
  /** Default "warn" when the [os_dependencies] table is absent. */
  osDependencies: OsDependencyHandling;
  suppressedWorkspaces: ReadonlyArray<SuppressedWorkspace>;
  compatible: ReadonlyArray<CompatibleRule>;
  clarify: ReadonlyArray<ClarifyRule>;
  /**
   * The declared path of a file holding further `[[clarify]]` entries, repo-root-relative. Absent
   * when the policy declares none; the entries themselves arrive appended to `clarify`.
   */
  clarifications?: string;
  /**
   * Terminal deny-list: the HIGHEST-precedence lane. A matching package FORCE-FAILS regardless of
   * compatible/suppression/dev-scope. Absent [[deny]] table yields [].
   */
  deny: ReadonlyArray<DenyRule>;
  /**
   * Per-licence exemptions from the shipped source-available deny defaults (ADR-0013). A listed
   * licence is no longer force-failed by the default - the package surfaces as a WARN citing the
   * exemption, never silently. Does NOT affect a consumer's own [[deny]] (an explicit deny still
   * wins). Absent → [].
   */
  allowSourceAvailable: ReadonlyArray<AllowSourceAvailable>;
  /**
   * Author-supplied document presentation. Absent [document] table yields undefined; an empty
   * [document] yields {} (both keys optional).
   */
  document?: DocumentConfig;
  /**
   * Dockerfile-discovery exclusion globs. Absent [docker] table yields undefined; a present
   * [docker] (with or without `ignore`) yields a DockerConfig whose `ignore` defaults to [].
   */
  docker?: DockerConfig;
  /**
   * Where tool-generated committed artifacts live (the enrichment cache, the Docker OS SBOM, and
   * any added later). Absent maps to DEFAULT_CACHE_DIR.
   */
  cache?: CacheConfig;
  /**
   * The declared target usage profile that activates the compatibility lane. Absent [target] table
   * yields undefined - today's walk stays byte-identical.
   */
  target?: TargetConfig;
}
