/**
 * Build a Dockerfile set to local, never-pushed tags for a docker-scan run.
 *
 * Run via `task docker-scan` (which chains discovery, this build step, the
 * built-image scan, and regeneration) or standalone:
 *
 *   mise x -- bun scripts/build-scan-images.ts [dockerfile ...]
 *
 * With no arguments, the Dockerfile set is discovered with
 * `task list-dockerfiles`. Prints the resulting space-separated tags on
 * stdout; every other message goes to stderr, so stdout stays a clean value
 * a caller can capture.
 */
import { createHash } from "node:crypto";
import { dirname } from "node:path";

async function discoverDockerfiles(): Promise<string[]> {
  const proc = Bun.spawn(
    ["mise", "x", "--", "task", "--silent", "list-dockerfiles"],
    {
      stdout: "pipe",
      stderr: "inherit",
    },
  );
  const output = await new Response(proc.stdout).text();
  const code = await proc.exited;
  if (code !== 0) {
    throw new Error(`task list-dockerfiles exited with code ${code}`);
  }
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

// The sanitized name alone is not injective (a/b/Dockerfile and a-b/Dockerfile
// collide, as do case-folded paths); a collision would let the second build
// silently overwrite the first image and drop it from the committed
// inventory. Suffix a short hash of the path so distinct Dockerfiles always
// get distinct tags -- deterministic per path, so the sidecar identity is
// stable across runs.
function imageTag(dockerfilePath: string): string {
  const sanitized = dockerfilePath.toLowerCase().replace(/[^a-z0-9._-]/g, "-");
  const hash = createHash("sha256")
    .update(dockerfilePath)
    .digest("hex")
    .slice(0, 8);
  return `sbomlet-scan/${sanitized}-${hash}`;
}

async function buildImage(dockerfilePath: string): Promise<string> {
  const tag = imageTag(dockerfilePath);
  const proc = Bun.spawn(
    [
      "docker",
      "buildx",
      "build",
      "--load",
      "--provenance=false",
      "-f",
      dockerfilePath,
      "-t",
      tag,
      dirname(dockerfilePath),
    ],
    { stdout: "inherit", stderr: "inherit" },
  );
  const code = await proc.exited;
  if (code !== 0) {
    throw new Error(
      `docker buildx build failed for ${dockerfilePath} (exit ${code})`,
    );
  }
  return tag;
}

async function main(): Promise<void> {
  const requested = process.argv.slice(2);
  const dockerfiles =
    requested.length > 0 ? requested : await discoverDockerfiles();

  if (dockerfiles.length === 0) {
    console.error("no Dockerfiles to scan");
    process.exit(1);
  }

  const tags: string[] = [];
  for (const dockerfilePath of dockerfiles) {
    console.error(`building ${dockerfilePath}`);
    tags.push(await buildImage(dockerfilePath));
  }

  console.log(tags.join(" "));
}

await main();
