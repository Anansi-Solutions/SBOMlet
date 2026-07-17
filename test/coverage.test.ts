/**
 * Unit suite for the coverage policy's terraform arm.
 *
 * The pre-existing kinds (yarn/npm/pnpm/bun/python) are exercised through the
 * e2e suite; this file locks the one genuinely new seam — the terraform
 * skip/scan/loud-fail routing, which is a pure FILESYSTEM fact: the
 * init-has-run gate is modules.json presence + the `<dir>/.terraform/`
 * directory's existence, with no HCL parsing. The load-bearing invariant: an
 * ABSENT modules.json WITH NO `.terraform/` dir (init never ran) is NEVER
 * skip-classified to zero — it must route to the collect path so the collector's
 * loud "run tofu init/tofu get first" throw fires.
 */

import {
  closeSync,
  ftruncateSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import { classifyCoverage, coverageSkipReason } from "../src/pipeline/coverage";
import { MAX_TERRAFORM_LOCK_BYTES } from "../src/collectors/terraform";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

interface LockDirOptions {
  /** Present modules.json text → the authoritative present-path. */
  modulesJson?: string;
  /**
   * When modules.json is absent, whether `<dir>/.terraform/` exists. "none": no
   * `.terraform/` (init never ran) → loud-fail collect routing. "providers-only":
   * a `.terraform/providers/` dir exists (init ran, no module calls) → scan.
   */
  terraformDir?: "none" | "providers-only";
}

/**
 * A lock dir with the lock written. When `modulesJson` is given it is written to
 * `.terraform/modules/modules.json` (present-path). Otherwise `terraformDir`
 * decides what `.terraform/` materialization the filesystem gate observes. No
 * `.tf` files are written — the gate no longer reads any HCL.
 */
function makeLockDir(lockText: string, options: LockDirOptions = {}): string {
  const { modulesJson, terraformDir = "none" } = options;
  const dir = mkdtempSync(join(tmpdir(), "licenses-cov-"));
  tempDirs.push(dir);
  writeFileSync(join(dir, ".terraform.lock.hcl"), lockText);
  if (modulesJson !== undefined) {
    const modulesDir = join(dir, ".terraform", "modules");
    mkdirSync(modulesDir, { recursive: true });
    writeFileSync(join(modulesDir, "modules.json"), modulesJson);
  } else if (terraformDir === "providers-only") {
    mkdirSync(join(dir, ".terraform", "providers"), { recursive: true });
  }
  return dir;
}

const PROVIDER_LOCK = `provider "registry.opentofu.org/hashicorp/aws" {
  version = "6.42.0"
  hashes = [ "h1:x" ]
}
`;

const ZERO_PROVIDER_LOCK = `# only a comment header, no providers
`;

const EXTERNAL_MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    {
      Key: "vpc",
      Source: "terraform-aws-modules/vpc/aws",
      Version: "6.6.0",
      Dir: ".terraform/modules/vpc",
    },
  ],
});

const LOCAL_ONLY_MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    { Key: "net", Source: "./modules/net", Dir: "modules/net" },
  ],
});

describe("coverageSkipReason — terraform arm (filesystem-signal gate)", () => {
  test("ABSENT modules.json + no `.terraform/` dir routes to the collect path (undefined, not a skip)", () => {
    const dir = makeLockDir(PROVIDER_LOCK); // no modules.json, no .terraform/
    expect(
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  test("providers-only dir (`.terraform/` EXISTS, no modules.json) → scan (undefined), NOT loud-fail", () => {
    // The providers-only finding-B shape: tofu init wrote `.terraform/providers/` but
    // no modules.json because there were no module calls to resolve.
    const dir = makeLockDir(PROVIDER_LOCK, { terraformDir: "providers-only" });
    expect(
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  test("ABSENT modules.json + no `.terraform/` dir (init never ran) → route to collect (undefined → loud-fail at collector)", () => {
    const dir = makeLockDir(PROVIDER_LOCK, { terraformDir: "none" });
    expect(
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  test("a zero-provider lock with a present local-only modules.json is skip-classified", () => {
    const dir = makeLockDir(ZERO_PROVIDER_LOCK, {
      modulesJson: LOCAL_ONLY_MODULES_JSON,
    });
    const reason = coverageSkipReason(
      ".terraform.lock.hcl",
      ZERO_PROVIDER_LOCK,
      dir,
    );
    expect(reason).toContain("no providers and no external modules");
  });

  test("providers present + a local-only modules.json → scan (undefined)", () => {
    const dir = makeLockDir(PROVIDER_LOCK, {
      modulesJson: LOCAL_ONLY_MODULES_JSON,
    });
    expect(
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  test("zero providers but an EXTERNAL module present → scan (undefined)", () => {
    const dir = makeLockDir(ZERO_PROVIDER_LOCK, {
      modulesJson: EXTERNAL_MODULES_JSON,
    });
    expect(
      coverageSkipReason(".terraform.lock.hcl", ZERO_PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  test("an empty/whitespace lock is the generic empty skip before the terraform arm", () => {
    const dir = makeLockDir("   \n");
    const reason = coverageSkipReason(".terraform.lock.hcl", "   \n", dir);
    expect(reason).toContain("empty");
  });

  test("a providers-only `.terraform/` dir whose lock yields ZERO providers is skip-classified (legitimate no-op)", () => {
    // init ran, no module calls, AND the committed lock has no providers → the
    // dir scans to zero; skip-classify rather than hard-fail.
    const dir = makeLockDir(ZERO_PROVIDER_LOCK, {
      terraformDir: "providers-only",
    });
    const reason = coverageSkipReason(
      ".terraform.lock.hcl",
      ZERO_PROVIDER_LOCK,
      dir,
    );
    expect(reason).toContain("no providers and no external modules");
  });

  // A directory-named modules.json is a non-regular-file
  // PRESENCE — coverage must treat it as ABSENT and route to the filesystem
  // gate (which sees `.terraform/modules/` exists with no modules.json file →
  // loud throw), NOT a raw uncaught EISDIR at the coverage read.
  test("a directory-named modules.json is treated as ABSENT → routed to the gate (throws, not EISDIR)", () => {
    const dir = mkdtempSync(join(tmpdir(), "licenses-cov-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, ".terraform.lock.hcl"), PROVIDER_LOCK);
    // providers/ + modules/ exist; modules.json is a DIRECTORY (non-regular).
    mkdirSync(join(dir, ".terraform", "providers"), { recursive: true });
    mkdirSync(join(dir, ".terraform", "modules", "modules.json"), {
      recursive: true,
    });
    // The gate sees `.terraform/modules/` exists with no modules.json FILE →
    // stale/partial → absentModulesJsonShouldFail true → routes to collect
    // (undefined). The classifyCoverage zero-component throw then fires loudly.
    expect(
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toBeUndefined();
  });

  // The size gate must fire BEFORE the coverage read of
  // modules.json, mirroring the collector and the bun.lock precedent.
  test("an oversized modules.json is rejected by the size gate at the coverage read (before any parse)", () => {
    const dir = mkdtempSync(join(tmpdir(), "licenses-cov-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, ".terraform.lock.hcl"), PROVIDER_LOCK);
    const modulesDir = join(dir, ".terraform", "modules");
    mkdirSync(modulesDir, { recursive: true });
    // Sparse file one byte over the cap — no 32 MiB write, no parse reached.
    const path = join(modulesDir, "modules.json");
    const fd = openSync(path, "w");
    ftruncateSync(fd, MAX_TERRAFORM_LOCK_BYTES + 1);
    closeSync(fd);
    expect(() =>
      coverageSkipReason(".terraform.lock.hcl", PROVIDER_LOCK, dir),
    ).toThrow(/cap|bytes/i);
  });
});

describe("classifyCoverage — terraform filesystem-signal loud-fail routing", () => {
  test("absent modules.json + no `.terraform/` dir is NOT skip-classified to zero", () => {
    const dir = makeLockDir(PROVIDER_LOCK); // no modules.json, no .terraform/
    // componentCount 0 here is irrelevant: init never ran, so it must route to
    // the loud zero-component throw via the collector, never a silent skip.
    expect(() =>
      classifyCoverage("infra", ".terraform.lock.hcl", PROVIDER_LOCK, 0, dir),
    ).toThrow(/zero components|coverage assertion/);
  });

  test("a positive component count with a present modules.json is included", () => {
    const dir = makeLockDir(PROVIDER_LOCK, {
      modulesJson: EXTERNAL_MODULES_JSON,
    });
    expect(
      classifyCoverage("infra", ".terraform.lock.hcl", PROVIDER_LOCK, 2, dir),
    ).toBe("include");
  });

  test("providers-only dir (`.terraform/` exists), absent modules.json, positive provider count is INCLUDED (not loud-fail)", () => {
    // The collector collects providers-only when `.terraform/` exists but no
    // modules.json was written; the coverage policy must include it, not throw.
    const dir = makeLockDir(PROVIDER_LOCK, { terraformDir: "providers-only" });
    expect(
      classifyCoverage("infra", ".terraform.lock.hcl", PROVIDER_LOCK, 1, dir),
    ).toBe("include");
  });

  test("a zero-provider lock with a local-only modules.json is skipped", () => {
    const dir = makeLockDir(ZERO_PROVIDER_LOCK, {
      modulesJson: LOCAL_ONLY_MODULES_JSON,
    });
    expect(
      classifyCoverage(
        "infra",
        ".terraform.lock.hcl",
        ZERO_PROVIDER_LOCK,
        0,
        dir,
      ),
    ).toBe("skip");
  });
});

// nuget arm: a genuinely dependency-free packages.lock.json warns and
// skips; an unreadable one routes to the scan where the collector's loud throw
// / zero-component hard-fail fires — the strict === 0 undefined-falls-through
// pattern shared with the npm/bun arms.
const NUGET_EMPTY_SECTIONS_LOCK = '{"version":2,"dependencies":{"net9.0":{}}}';

const NUGET_PROJECT_ONLY_LOCK = JSON.stringify({
  version: 2,
  dependencies: { "net9.0": { "fixture.lib": { type: "Project" } } },
});

const NUGET_REAL_LOCK = JSON.stringify({
  version: 2,
  dependencies: {
    "net9.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.4" } },
  },
});

describe("coverageSkipReason — packages.lock.json arm (strict === 0)", () => {
  test("empty dependency sections are a positively-determined zero → skip with the house reason", () => {
    expect(
      coverageSkipReason("packages.lock.json", NUGET_EMPTY_SECTIONS_LOCK),
    ).toBe(
      "packages.lock.json has no third-party entries (only Project entries, or empty dependency sections)",
    );
  });

  test("a Project-only lock skip-classifies (first-party references are not inventory)", () => {
    expect(
      coverageSkipReason("packages.lock.json", NUGET_PROJECT_ONLY_LOCK),
    ).toContain("no third-party entries");
  });

  test("garbage text routes to the scan (undefined — the collector's loud throw fires there)", () => {
    expect(
      coverageSkipReason("packages.lock.json", "not json at all }{"),
    ).toBeUndefined();
  });

  test("a non-zero count falls through to the scan", () => {
    expect(
      coverageSkipReason("packages.lock.json", NUGET_REAL_LOCK),
    ).toBeUndefined();
  });
});

describe("classifyCoverage — packages.lock.json warn+skip vs hard-fail split", () => {
  test("a zero-entry lock with zero components is skipped (never a hard fail)", () => {
    expect(
      classifyCoverage(
        "app",
        "packages.lock.json",
        NUGET_EMPTY_SECTIONS_LOCK,
        0,
      ),
    ).toBe("skip");
  });

  test("a garbage lock that scans to zero components HARD-FAILS (unknown is never a silent skip)", () => {
    expect(() =>
      classifyCoverage("app", "packages.lock.json", "not json at all }{", 0),
    ).toThrow(/zero components|coverage assertion/);
  });

  test("a real lock with a positive component count is included", () => {
    expect(
      classifyCoverage("app", "packages.lock.json", NUGET_REAL_LOCK, 1),
    ).toBe("include");
  });
});

// maven arm: the reactor aggregator pom's sidecar (zero components) warns
// and skips; garbage/non-CycloneDX text routes to the scan where the
// collector's own loud throw fires — the same strict === 0 undefined-falls-
// through pattern shared with the npm/bun/nuget arms.
const MAVEN_AGGREGATOR_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: {
      purl: "pkg:maven/com.example.fixture/reactor-parent@1.0.0?type=pom",
    },
  },
  components: [],
});

const MAVEN_MODULE_SBOM = JSON.stringify({
  bomFormat: "CycloneDX",
  metadata: {
    component: {
      purl: "pkg:maven/com.example.fixture/liba@1.0.0?type=jar",
    },
  },
  components: [
    {
      purl: "pkg:maven/com.example.fixture/commons-lang3@3.12.0?type=jar",
    },
  ],
});

describe("coverageSkipReason — maven.sbom.json arm (strict === 0)", () => {
  test("a zero-component aggregator pom is a positively-determined zero → skip with the house reason", () => {
    expect(coverageSkipReason("maven.sbom.json", MAVEN_AGGREGATOR_SBOM)).toBe(
      "maven.sbom.json has no third-party entries (no components other than its own root, e.g. the reactor aggregator pom)",
    );
  });

  test("garbage text routes to the scan (undefined — the collector's loud throw fires there)", () => {
    expect(
      coverageSkipReason("maven.sbom.json", "not json at all }{"),
    ).toBeUndefined();
  });

  test("a non-zero count falls through to the scan", () => {
    expect(
      coverageSkipReason("maven.sbom.json", MAVEN_MODULE_SBOM),
    ).toBeUndefined();
  });
});

describe("classifyCoverage — maven.sbom.json warn+skip vs hard-fail split", () => {
  test("the aggregator pom's zero-component doc is skipped (never a hard fail)", () => {
    expect(
      classifyCoverage("reactor", "maven.sbom.json", MAVEN_AGGREGATOR_SBOM, 0),
    ).toBe("skip");
  });

  test("a garbage sidecar that scans to zero components HARD-FAILS (unknown is never a silent skip)", () => {
    expect(() =>
      classifyCoverage("reactor", "maven.sbom.json", "not json at all }{", 0),
    ).toThrow(/zero components|coverage assertion/);
  });

  test("a real module sidecar with a positive component count is included", () => {
    expect(
      classifyCoverage("liba", "maven.sbom.json", MAVEN_MODULE_SBOM, 1),
    ).toBe("include");
  });
});
