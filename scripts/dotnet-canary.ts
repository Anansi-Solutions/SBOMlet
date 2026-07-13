/**
 * .NET lockfile format canary — run via `task canary:dotnet`; CI runs it
 * monthly with the newest GA SDK (.github/workflows/dotnet-canary.yml).
 *
 * packages.lock.json is written by the .NET SDK and has changed shape before
 * (format version 1 → 2). The collector breaks fast on a shape it cannot
 * read — unknown format version, non-JSON text — but only once such a lock
 * reaches a scan. This probe closes that gap proactively: restore a
 * throwaway project with the SDK on PATH, run the real collector
 * (collectWithNugetLock, not a reimplementation) over the freshly written
 * lock, and assert the pinned packages come out as purls. A format move
 * turns this red in our own CI before it reaches any adopter's repository.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { execTool } from "../src/collectors/exec";
import { collectWithNugetLock } from "../src/collectors/nugetLock";

/**
 * Pinned, well-known direct dependencies. The pins keep the expected purls
 * exact under any SDK; Microsoft.Extensions.Logging.Abstractions also pulls
 * transitives, so the probe exercises Direct and Transitive lock entries.
 */
const PINNED = [
  { id: "Newtonsoft.Json", version: "13.0.3" },
  { id: "Serilog", version: "4.2.0" },
  { id: "Microsoft.Extensions.Logging.Abstractions", version: "9.0.0" },
] as const;

/**
 * A transitive of Microsoft.Extensions.Logging.Abstractions on every target
 * framework it ships for — its presence proves Transitive entries surface.
 * Prefix only: the resolved version may move with the restore's TFM.
 */
const TRANSITIVE_PREFIX =
  "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@";

const DOTNET_ENV: NodeJS.ProcessEnv = {
  ...process.env,
  DOTNET_CLI_TELEMETRY_OPTOUT: "1",
  DOTNET_NOLOGO: "1",
};

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

/** One dotnet invocation, output passed through for run-log forensics. */
async function dotnet(args: string[], cwd: string): Promise<void> {
  await execTool("dotnet", args, {
    timeoutMs: 10 * 60 * 1000,
    verbose: true,
    cwd,
    env: DOTNET_ENV,
  });
}

/** Restore a pinned probe project and return its project directory. */
async function restoreProbeProject(scratch: string): Promise<string> {
  const project = join(scratch, "probe");
  await dotnet(
    ["new", "classlib", "--output", project, "--no-restore"],
    scratch,
  );
  for (const { id, version } of PINNED) {
    await dotnet(
      ["add", project, "package", id, "--version", version, "--no-restore"],
      scratch,
    );
  }
  await dotnet(["restore", project, "--use-lock-file"], scratch);

  const lockPath = join(project, "packages.lock.json");
  if (!existsSync(lockPath)) {
    fail(
      `restore wrote no packages.lock.json at ${lockPath} — ` +
        `the SDK's lockfile opt-in may have changed`,
    );
  }
  const lock = JSON.parse(readFileSync(lockPath, "utf8")) as {
    version?: unknown;
    dependencies?: Record<string, unknown>;
  };
  console.log(
    `lock format version ${String(lock.version)}; ` +
      `sections: ${Object.keys(lock.dependencies ?? {}).join(", ")}`,
  );
  return project;
}

/** Run the real collector over the fresh lock and assert the expected purls. */
async function assertCollectorReadsLock(
  project: string,
  scratch: string,
): Promise<void> {
  // The real code path — an unreadable format throws loudly right here.
  const collected = await collectWithNugetLock(
    { dir: project, identity: "dotnet-canary-probe" },
    { tempDir: scratch },
  );
  const bom = JSON.parse(readFileSync(collected.sbomPath, "utf8")) as {
    components?: { purl?: string }[];
  };
  const purls = (bom.components ?? []).map((c) => c.purl ?? "");
  console.log(`collector emitted ${purls.length} components`);

  const expected = PINNED.map(
    ({ id, version }) => `pkg:nuget/${id}@${version}`,
  );
  const missing = expected.filter((purl) => !purls.includes(purl));
  if (missing.length > 0) {
    fail(
      `pinned purls missing from the collector output: ` +
        `${missing.join(", ")} (emitted: ${purls.join(", ")})`,
    );
  }
  if (!purls.some((purl) => purl.startsWith(TRANSITIVE_PREFIX))) {
    fail(
      `no ${TRANSITIVE_PREFIX}* emitted — Transitive lock entries are not ` +
        `surfacing (emitted: ${purls.join(", ")})`,
    );
  }
  // Three pinned directs plus at least the asserted transitive.
  if (purls.length < PINNED.length + 1) {
    fail(
      `expected at least ${PINNED.length + 1} components, got ${purls.length}`,
    );
  }
  console.log(
    "PASS: the collector read the SDK's lockfile and emitted every expected purl",
  );
}

const sdkVersion = await execTool("dotnet", ["--version"], {
  timeoutMs: 2 * 60 * 1000,
  verbose: false,
  env: DOTNET_ENV,
}).catch(() => undefined);
if (sdkVersion === undefined) {
  console.error(
    "A .NET SDK is required on PATH (dotnet --version failed) — " +
      "install one to run this probe.",
  );
  process.exit(2);
}
console.log(`probing with .NET SDK ${sdkVersion.stdout.trim()}`);

const scratch = mkdtempSync(join(tmpdir(), "dotnet-canary-"));
try {
  const project = await restoreProbeProject(scratch);
  await assertCollectorReadsLock(project, scratch);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
