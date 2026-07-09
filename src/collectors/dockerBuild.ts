/**
 * The in-tool docker build step for the build-and-analyze lanes: turn a
 * Dockerfile path into a locally built, never-pushed image tag, then scan the
 * built image. It is the counterpart of the syft scan seam in dockerOs.ts —
 * argv arrays through an injected exec function, never a shell string, so a
 * user-controlled Dockerfile path can never be interpolated into a command
 * (injection is impossible by construction).
 *
 * imageTag produces the STABLE image identity that becomes the committed
 * sidecar's `dockerImages[].image`: a sanitized, path-hashed tag that is a pure
 * function of the Dockerfile path. It is locked bit-exact by a golden in
 * test/dockerBuild.test.ts against the committed identity, because any drift
 * churns the committed artifact and every consumer's offline check.
 *
 * This module stays silent (no stderr): the caller owns progress logging, the
 * same posture as dockerOs.ts (the pure engine writes nothing; the pipeline /
 * CLI narrate).
 */

import { createHash } from "node:crypto";
import { posix } from "node:path";

import { sanitizeForLog } from "../pipeline/summary";
import type { ExecOptions } from "./exec";

/** The execTool shape, injected so the build argv is testable subprocess-free. */
export type ExecFn = (
  cmd: string,
  args: string[],
  opts: ExecOptions,
) => Promise<{ stdout: string; stderr: string }>;

/**
 * Wall-clock limit for one `docker buildx build` spawn. A build is workload-
 * shaped and can be slow; CI additionally bounds the whole job with
 * timeout-minutes. Callers override via {@link BuildImageOptions.timeoutMs}.
 */
const DEFAULT_BUILD_TIMEOUT_MS = 20 * 60 * 1000;

/**
 * The stable image tag for a Dockerfile path.
 *
 * The sanitized name ALONE is not injective — `a/b/Dockerfile` and
 * `a-b/Dockerfile` sanitize identically, as do case-folded paths — and a
 * collision would let the second build silently overwrite the first image and
 * drop it from the committed inventory. Suffixing a short hash of the ORIGINAL
 * (pre-sanitization) path makes distinct Dockerfiles always get distinct tags,
 * deterministic per path, so the committed sidecar identity is stable across
 * runs and machines. Hashing the original (not the sanitized) string is what
 * keeps a mixed-case path distinct from its lowercased twin.
 */
export function imageTag(dockerfilePath: string): string {
  const sanitized = dockerfilePath.toLowerCase().replace(/[^a-z0-9._-]/g, "-");
  const hash = createHash("sha256")
    .update(dockerfilePath)
    .digest("hex")
    .slice(0, 8);
  return `sbomlet-scan/${sanitized}-${hash}`;
}

/**
 * The exact `docker buildx build` argv (operands only — the `docker` binary is
 * the exec cmd, mirroring syftArgs/dockerInspectArgs). `--load` imports the
 * built image into the local daemon so the scan step can inspect it;
 * `--provenance=false` keeps the build a single-image, no-attestation artifact.
 * The Dockerfile is the `-f` value and the build CONTEXT is its POSIX dirname,
 * so the same path produces the same argv on every platform.
 */
export function buildImageArgs(dockerfilePath: string, tag: string): string[] {
  return [
    "buildx",
    "build",
    "--load",
    "--provenance=false",
    "-f",
    dockerfilePath,
    "-t",
    tag,
    posix.dirname(dockerfilePath),
  ];
}

/** Per-build knobs; all optional with the same defaults as the scan seam. */
export interface BuildImageOptions {
  /** Executable that runs docker; defaults to "docker". */
  dockerBin?: string;
  /** Hard wall-clock limit for the build spawn; defaults to 20 minutes. */
  timeoutMs?: number;
  /** Pass child stdout/stderr through to process.stderr. */
  verbose?: boolean;
  /**
   * Working directory for the buildx spawn. The argv from {@link buildImageArgs}
   * is intentionally repo-relative (the `-f` value and the POSIX-dirname build
   * context), so buildx resolves both against THIS directory. The discovery
   * lane anchors it to the repo root; when unset the child inherits the tool's
   * process cwd (the explicit `--dockerfile` lane, where the caller's paths are
   * relative to their own cwd). Threaded through to the exec seam untouched, so
   * the argv — and therefore {@link imageTag} — stays a pure function of the path.
   */
  cwd?: string;
}

/**
 * Build one Dockerfile to its {@link imageTag} via the injected exec seam and
 * return the tag. A nonzero buildx exit throws LOUDLY, naming the Dockerfile
 * (routed through sanitizeForLog because the path is user-controlled), and no
 * tag is returned — there is no partial result to mistake for success.
 */
export async function buildImage(
  dockerfilePath: string,
  exec: ExecFn,
  opts: BuildImageOptions = {},
): Promise<string> {
  const tag = imageTag(dockerfilePath);
  const dockerBin = opts.dockerBin ?? "docker";
  const args = buildImageArgs(dockerfilePath, tag);
  try {
    await exec(dockerBin, args, {
      timeoutMs: opts.timeoutMs ?? DEFAULT_BUILD_TIMEOUT_MS,
      verbose: opts.verbose ?? false,
      cwd: opts.cwd,
    });
  } catch (error) {
    throw new Error(
      `docker buildx build failed for ${sanitizeForLog(dockerfilePath)}: ${String(error)}`,
      { cause: error },
    );
  }
  return tag;
}
