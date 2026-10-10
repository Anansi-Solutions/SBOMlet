/**
 * The options bag every generate/check run threads through, resolved from the CLI flags. A
 * dependency-free leaf shared by the pipeline and its target-discovery lane.
 */
export interface GenerateOptions {
  /** Single-target debug mode; mutually exclusive with repoRoot. */
  targetArg?: string;
  /** Discovery-mode root; defaults to the current working directory. */
  repoRoot?: string;
  /** Repeatable --exclude globs, matched against target identities. */
  excludes?: string[];
  outputPath: string;
  /**
   * THIRD_PARTY_NOTICES.md companion output path: generate always writes the companion; main()
   * defaults this to THIRD_PARTY_NOTICES.md in the same directory as the output path when --notices
   * is absent.
   */
  noticesPath: string;
  /**
   * Optional CycloneDX 1.6 export path: rendered and written only when configured; check
   * byte-compares it when set.
   */
  cyclonedxPath?: string;
  dumpModelPath?: string;
  /**
   * generate --intensive: opt-in ScanCode assessment over the FULL package set (every package with
   * locally-present sources not already in the analysis memo). Absent-not-false (own-property gated
   * at the assessPackages call site below) so a default generate never constructs {@link
   * IntensiveOptions} and stays structurally scan-free. check REJECTS this flag outright
   * (gate/check.ts, the dump-model precedent) - the shared optionsFrom parses it, but only
   * runGenerate ever threads it through as true.
   */
  intensive?: boolean;
  /**
   * Optional override for ScanCode's per-package wall-clock timeout under --intensive
   * (--package-timeout-mins, minutes on the CLI, converted to milliseconds by cli.ts's optionsFrom
   * to match {@link IntensiveOptions.timeoutMs} / DEFAULT_SCAN_TIMEOUT_MS). Threaded ONLY into the
   * intensive lane via intensiveOptionsFor below; a default generate/check never reaches it. Absent
   * keeps the tool default (10 minutes).
   */
  packageTimeoutMs?: number;
  /**
   * Optional TOML policy file: loaded + validated before any scan; verdicts evaluated after the
   * merge and rendered into the PolicyView document. Findings are annotated unconditionally - the
   * absent flag only removes the policy-gated surfaces (pointer line, copyleft section, verdicts).
   * The document is always written even with failing verdicts - the CI gate is check mode, not
   * generate.
   */
  policyPath?: string;
  /**
   * Base directory for resolving every user-supplied relative path option (--target, --repo-root,
   * --policy, --output, --notices, --cyclonedx, --dump-model). Defaults to the current working
   * directory, so direct CLI invocations resolve relative to cwd. The Taskfile passes the task
   * invocation directory ({{.USER_WORKING_DIR}}): tasks run inside tools/sbomlet (the include
   * `dir`, mandated by the mise bun pin), so without this anchor a
   * `task generate POLICY=.sbomlet.policy.toml` would look for tools/sbomlet/.sbomlet.policy.toml
   * - and a relative CYCLONEDX would silently write (then "verify") the export inside
   * tools/sbomlet. Display surfaces keep the raw path: the policy pointer line in the rendered
   * document must stay deterministic across machines, never embedding an absolute machine-specific
   * path.
   */
  baseDir?: string;
  /**
   * Optional override for the enrichment cache path (--enrichment-cache). When unset it defaults to
   * {@link ENRICHMENT_CACHE_FILE} inside the resolved cache dir ({@link DEFAULT_CACHE_DIR}, or the
   * policy `[cache] dir`).
   */
  enrichmentCachePath?: string;
  /**
   * Optional override for the ScanCode memo path (--scancode-cache), symmetric with
   * --enrichment-cache. When unset it defaults to {@link SCANCODE_CACHE_FILE} inside the resolved
   * cache dir. Threaded through for the ScanCode replay stage to consume; the memo module owns the
   * read/write.
   */
  scancodeCachePath?: string;
  /**
   * Optional override for the committed Docker OS SBOM path (--docker-sbom). When unset it defaults
   * to {@link DOCKER_SBOM_FILE} inside the resolved cache dir. When the file exists it is
   * size-gated, parsed, and threaded into the merge as a scope:"os" input; when absent there are no
   * os entries (the offline cache-miss equivalent, never a live docker/syft scan).
   */
  dockerSbomPath?: string;
  /**
   * generate may fetch+write the enrichment cache; check NEVER fetches or writes - a
   * miss-needing-enrichment is a stale condition (exit 2), never a network call. buildOutputs stays
   * write-free regardless: the cache write lives inside enrichUnknowns gated on generate mode.
   * runGenerate forces "generate"; runCheck forces "check". Absent defaults to the hermetic "check"
   * so a direct buildOutputs call never silently fetches.
   */
  mode?: "generate" | "check";
  verbose: boolean;
}
