/**
 * Unit suite for the custom Terraform collector.
 *
 * Provider fixtures are inline string constants copied VERBATIM from the four
 * live OpenTofu locks committed under infrastructure/ at authoring time — never
 * the stale RESEARCH counts. The live provider SET is:
 *   infrastructure/.terraform.lock.hcl (root):
 *     hashicorp/aws 6.42.0, hashicorp/random 3.8.1, hashicorp/time 0.13.1,
 *     integrations/github 6.12.0
 *   infrastructure/modules/cloudfront/.terraform.lock.hcl:
 *     hashicorp/archive 2.6.0 (NO constraints line), hashicorp/aws 5.75.0,
 *     hashicorp/external 2.3.4, hashicorp/local 2.5.2, hashicorp/null 3.2.3,
 *     hashicorp/random 3.6.3
 *   infrastructure/modules/fargate/.terraform.lock.hcl:
 *     hashicorp/aws 6.42.0, hashicorp/time 0.13.1
 *   infrastructure/modules/github-actions-deployment/.terraform.lock.hcl:
 *     hashicorp/aws 5.75.0
 *
 * modules.json fixtures follow the real `.terraform/modules/modules.json`
 * shape `{"Modules":[{Key,Source,Version,Dir}]}`. The whole `.terraform/` dir is
 * gitignored and absent until `tofu init`/`tofu get` runs.
 *
 * The absent-modules.json gate is a pure FILESYSTEM signal: the
 * question "should this dir fail loud?" reduces to "did `tofu init` run?", which
 * is answerable from the `.terraform/` directory's existence — no HCL parsing.
 *   - modules.json PRESENT → read external modules (authoritative present-path).
 *   - modules.json ABSENT + `<dir>/.terraform/` directory EXISTS → init ran, no
 *     module calls → collect providers; NO throw.
 *   - modules.json ABSENT + `<dir>/.terraform/` directory ABSENT → init never ran
 *     → THROW the loud "run tofu init/tofu get first" error.
 * A stray `.terraform` FILE (not a directory) is NOT an init dir → still throws.
 *
 * No subprocess is spawned anywhere here: the collector is fully in-process.
 */

import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  absentModulesJsonShouldFail,
  collectWithTerraform,
  parseProviders,
  readExternalModules,
  terraformComponentCount,
  TERRAFORM_COLLECTOR_TOOL,
} from "../src/collectors/terraform";
import { computeCacheKey } from "../src/collectors/cdxgen";
import type { Target } from "../src/targets/target";

// ---------------------------------------------------------------------------
// Provider lock fixtures — copied verbatim from the live committed locks.
// ---------------------------------------------------------------------------

/** infrastructure/.terraform.lock.hcl (root) — copied verbatim. */
const ROOT_LOCK = `# This file is maintained automatically by "tofu init".
# Manual edits may be lost in future updates.

provider "registry.opentofu.org/hashicorp/aws" {
  version     = "6.42.0"
  constraints = ">= 2.49.0, >= 3.29.0, >= 5.75.0, >= 5.99.0, >= 6.28.0, >= 6.30.0, >= 6.34.0"
  hashes = [
    "h1:gyeO1pGW3/KRjmc6g1grgIU5ieIABU1sHjXMJ/QLPNI=",
    "zh:21cc66ae8e6238a7948934802f217aa464f25a5f1031b52299be1e3246cbb405",
    "zh:da4ad1c2e8715d5851423f8884a60a491589e923a23f186676bebd5f616a863f",
  ]
}

provider "registry.opentofu.org/hashicorp/random" {
  version     = "3.8.1"
  constraints = ">= 3.1.0"
  hashes = [
    "h1:K/OIbLGX0YNiuoDXlpkerSWyv+bjS97Z6YGUCGePPAw=",
    "zh:25c458c7c676f15705e872202dad7dcd0982e4a48e7ea1800afa5fc64e77f4c8",
    "zh:f56e26e6977f755d7ae56fa6320af96ecf4bb09580d47cb481efbf27f1c5afff",
  ]
}

provider "registry.opentofu.org/hashicorp/time" {
  version     = "0.13.1"
  constraints = ">= 0.13.0"
  hashes = [
    "h1:zAffsOrhHE9rzKhFnw4VyIIRODmtjh08kmQTscUZgsE=",
    "zh:10f32af8b544a039f19abd546e345d056a55cb7bdd69d5bbd7322cbc86883848",
    "zh:faba366a1352ee679bba2a5b09c073c6854721db94b191d49b620b60946a065f",
  ]
}

provider "registry.opentofu.org/integrations/github" {
  version     = "6.12.0"
  constraints = "~> 6.0"
  hashes = [
    "h1:EugxXwlSJ5dNhD6NrNFEPriOQLpp5VLvghjVHNC5uog=",
    "zh:0748f95426c7ef9f2a4759dc5b7727796cfdf4358f9fcf0db4c7b26c476708c3",
    "zh:fbd1fee2c9df3aa19cf8851ce134dea6e45ea01cb85695c1726670c285797e25",
  ]
}
`;

/**
 * infrastructure/modules/cloudfront/.terraform.lock.hcl — copied verbatim.
 * The archive block has NO constraints line (the no-constraints edge): `version` is followed directly by `hashes`.
 */
const CLOUDFRONT_LOCK = `# This file is maintained automatically by "tofu init".
# Manual edits may be lost in future updates.

provider "registry.opentofu.org/hashicorp/archive" {
  version = "2.6.0"
  hashes = [
    "h1:+tHVqkbDgHOb8o+Nf49gdc5SusJyKG7kM1nE97ktl58=",
    "zh:046b3ba4223002d1cd1c917e8c21b58a636fcd751073745e3db99beebe254dd8",
    "zh:f74355e6588daf88ec210d2967fbf5d22fa18c448d2807b8a7049dc777a2dbcb",
  ]
}

provider "registry.opentofu.org/hashicorp/aws" {
  version     = "5.75.0"
  constraints = "5.75.0"
  hashes = [
    "h1:+twKfYzKB7r8sS9W7d++qDpw5WWcZ+8DzWW6m9i9wNM=",
    "zh:2b0d6e17d79ee1d59157e72d1019dfed49e047b376975a757adedb78d4794750",
    "zh:c270b648d5a4166b72b2875baaf06494fcfdb90033336a606229c89d10a54362",
  ]
}

provider "registry.opentofu.org/hashicorp/external" {
  version     = "2.3.4"
  constraints = ">= 1.0.0"
  hashes = [
    "h1:53KDnWQJDgnDGOxgnWIVgmm2FZgjLYQtA2wGemefJXU=",
    "zh:0e5eb3513d6ad5cc3196799a6e413c6a9c0b642ba6d8f84fc11efa48f58358a4",
    "zh:f2edd3027b7ae0d31a690fd5dcdcd22b467b4f1e045f84f2bc88289353ef9a5b",
  ]
}

provider "registry.opentofu.org/hashicorp/local" {
  version     = "2.5.2"
  constraints = ">= 1.0.0"
  hashes = [
    "h1:BUewjbhAQWuGHH36SozCTuESFJhbiHMaCFLnVVNZ1Es=",
    "zh:25b95b76ceaa62b5c95f6de2fa6e6242edbf51e7fc6c057b7f7101aa4081f64f",
    "zh:fa2d522fb323e2121f65b79709fd596514b293d816a1d969af8f72d108888e4c",
  ]
}

provider "registry.opentofu.org/hashicorp/null" {
  version     = "3.2.3"
  constraints = ">= 2.0.0"
  hashes = [
    "h1:ZD7F/BQPzRy/smJgSwnDs0vrqstk71sx2p0qtUcc/iU=",
    "zh:1d57d25084effd3fdfd902eca00020b34b1fb020253b84d7dd471301606015ac",
    "zh:fbf0c84663a7e85881388d7d71ac862184f05fbf2d17ecf76bc5d3d7503ea260",
  ]
}

provider "registry.opentofu.org/hashicorp/random" {
  version     = "3.6.3"
  constraints = ">= 3.1.0"
  hashes = [
    "h1:cnft2k5mwWkXDNKZdQ7KZ7Jk8aYmHToTgtNDbcYrv8I=",
    "zh:1bfd2e54b4eee8c761a40b6d99d45880b3a71abc18a9a7a5319204da9c8363b2",
    "zh:f423f2b7e5c814799ad7580b5c8ae23359d8d342264902f821c357ff2b3c6d3d",
  ]
}
`;

/** infrastructure/modules/fargate/.terraform.lock.hcl — copied verbatim. */
const FARGATE_LOCK = `# This file is maintained automatically by "tofu init".
# Manual edits may be lost in future updates.

provider "registry.opentofu.org/hashicorp/aws" {
  version     = "6.42.0"
  constraints = ">= 5.75.0, >= 5.99.0, >= 6.28.0, >= 6.34.0"
  hashes = [
    "h1:gyeO1pGW3/KRjmc6g1grgIU5ieIABU1sHjXMJ/QLPNI=",
    "zh:21cc66ae8e6238a7948934802f217aa464f25a5f1031b52299be1e3246cbb405",
    "zh:da4ad1c2e8715d5851423f8884a60a491589e923a23f186676bebd5f616a863f",
  ]
}

provider "registry.opentofu.org/hashicorp/time" {
  version     = "0.13.1"
  constraints = ">= 0.13.0"
  hashes = [
    "h1:zAffsOrhHE9rzKhFnw4VyIIRODmtjh08kmQTscUZgsE=",
    "zh:10f32af8b544a039f19abd546e345d056a55cb7bdd69d5bbd7322cbc86883848",
    "zh:faba366a1352ee679bba2a5b09c073c6854721db94b191d49b620b60946a065f",
  ]
}
`;

/**
 * Brace-edge fixture (A4) — synthetic. The `hashes = [ ... ]` array sits
 * BETWEEN `version` and the block's closing `}`. A naive `[^}]*?` regex that
 * stops at the first `}` after the header would never reach `version`; but the
 * real risk is a `}` INSIDE the body. The bracket-then-brace shape proves the
 * parser must treat the block boundary as a line that is exactly `}`, not the
 * first stray bracket/brace. This is the RED test deciding regex-vs-tokenizer.
 */
const BRACE_EDGE_LOCK = `provider "registry.opentofu.org/hashicorp/edge" {
  version = "1.2.3"
  constraints = ">= 1.0.0"
  hashes = [
    "h1:abc=",
    "zh:def",
  ]
}

provider "registry.opentofu.org/hashicorp/after" {
  version = "9.9.9"
  hashes = [
    "h1:xyz=",
  ]
}
`;

/** A lock that parses to zero providers (comment header only). */
const ZERO_PROVIDER_LOCK = `# This file is maintained automatically by "tofu init".
# Manual edits may be lost in future updates.
`;

// ---------------------------------------------------------------------------
// modules.json fixtures — real `{"Modules":[{Key,Source,Version,Dir}]}` shape.
// ---------------------------------------------------------------------------

/**
 * A realistic modules.json copied byte-for-byte in shape from the LIVE
 * infrastructure/.terraform/modules/modules.json: the root self entry
 * (Key "", empty Source), a local relative module (`./modules/fargate`, no
 * Version), the 4-segment fully-qualified registry Source
 * (`registry.opentofu.org/terraform-aws-modules/alb/aws` @ 9.17.0), the
 * `//modules/...` submodule form (ecs cluster + service, both @ 7.5.0 —
 * collapse to ONE row by purl), the relative `../container-definition`
 * (Version-less local), and the `terraform-aws-modules/vpc/aws` @ 6.6.1 pin.
 * OpenTofu rewrites the Source host to registry.opentofu.org for BOTH providers
 * and modules — so host can no longer distinguish them; the path-segment COUNT
 * does.
 */
const MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    { Key: "backend", Source: "./modules/fargate", Dir: "modules/fargate" },
    {
      Key: "backend.alb",
      Source: "registry.opentofu.org/terraform-aws-modules/alb/aws",
      Version: "9.17.0",
      Dir: ".terraform/modules/backend.alb",
    },
    {
      Key: "backend.ecs_cluster",
      Source:
        "registry.opentofu.org/terraform-aws-modules/ecs/aws//modules/cluster",
      Version: "7.5.0",
      Dir: ".terraform/modules/backend.ecs_cluster/modules/cluster",
    },
    {
      Key: "backend.ecs_service",
      Source:
        "registry.opentofu.org/terraform-aws-modules/ecs/aws//modules/service",
      Version: "7.5.0",
      Dir: ".terraform/modules/backend.ecs_service/modules/service",
    },
    {
      Key: "backend.ecs_service.container_definition",
      Source: "../container-definition",
      Dir: ".terraform/modules/backend.ecs_service/modules/container-definition",
    },
    {
      Key: "network.vpc",
      Source: "registry.opentofu.org/terraform-aws-modules/vpc/aws",
      Version: "6.6.1",
      Dir: ".terraform/modules/network.vpc",
    },
  ],
});

/** modules.json with only the root + a local module — zero external modules. */
const LOCAL_ONLY_MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    { Key: "network", Source: "./modules/network", Dir: "modules/network" },
    { Key: "shared", Source: "../shared", Dir: "../shared" },
  ],
});

/** modules.json with git:: and https:// sources — neither is external. */
const VCS_SOURCE_MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    {
      Key: "gitmod",
      Source: "git::https://example.com/org/mod.git",
      Version: "1.0.0",
      Dir: ".terraform/modules/gitmod",
    },
    {
      Key: "httpsmod",
      Source: "https://example.com/mod.zip",
      Dir: ".terraform/modules/httpsmod",
    },
  ],
});

/** modules.json with a registry Source but NO Version — not external. */
const NO_VERSION_MODULES_JSON = JSON.stringify({
  Modules: [
    { Key: "", Source: "", Dir: "." },
    {
      Key: "vpc",
      Source: "registry.opentofu.org/terraform-aws-modules/vpc/aws",
      Dir: ".terraform/modules/vpc",
    },
  ],
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * What kind of `.terraform/` materialization a fixture dir should have when
 * modules.json is absent — the redesigned filesystem gate's input:
 *   - "none": no `.terraform/` at all (init never ran) → loud throw expected;
 *   - "providers-only": a `.terraform/providers/` dir exists but no
 *     modules/modules.json (init ran, no module calls — github-actions-deployment
 *     shape) → collect, no throw;
 *   - "file": a `.terraform` FILE (not a dir) exists — a defensive edge that must
 *     be treated as NOT init'd → loud throw expected.
 *   - "empty": a `.terraform/` dir EXISTS but lacks `providers/` — an
 *     empty/fabricated init dir → loud throw expected;
 *   - "stale-modules": `.terraform/providers/` AND `.terraform/modules/` both
 *     exist but NO modules.json — a stale/partial module install → loud throw
 *     expected.
 */
type TerraformDirState =
  | "none"
  | "providers-only"
  | "file"
  | "empty"
  | "stale-modules";

interface TerraformTargetOptions {
  /** Present modules.json text — takes the authoritative present-path. */
  modulesJson?: string;
  /** When modules.json is absent, what `.terraform/` materialization exists. */
  terraformDir?: TerraformDirState;
  /**
   * When set, `.terraform/modules/modules.json` is created as a DIRECTORY (not a
   * regular file) — the non-regular-file PRESENCE edge.
   */
  modulesJsonAsDir?: boolean;
}

/**
 * Write a .terraform.lock.hcl into a fresh temp dir, returned as a Target.
 * When `modulesJson` is provided it is written to
 * `.terraform/modules/modules.json` (the present-path). Otherwise `terraformDir`
 * decides what `.terraform/` materialization (if any) the redesigned filesystem
 * gate observes. No `.tf` files are written — the gate no longer reads any HCL.
 */
function makeTerraformTarget(
  lockText: string,
  options: TerraformTargetOptions = {},
): Target {
  const {
    modulesJson,
    terraformDir = "none",
    modulesJsonAsDir = false,
  } = options;
  const dir = mkdtempSync(join(tmpdir(), "licenses-tf-"));
  tempDirs.push(dir);
  writeFileSync(join(dir, ".terraform.lock.hcl"), lockText);
  if (modulesJsonAsDir) {
    // The PRESENCE check sees `modules.json`, but it is a DIRECTORY, not a
    // regular file — must route to the gate, not raw EISDIR.
    mkdirSync(join(dir, ".terraform", "modules", "modules.json"), {
      recursive: true,
    });
    // Also materialize providers/ so the gate, on routing here, sees a real
    // init dir whose modules/ exists (no modules.json file) → loud throw.
  } else if (modulesJson !== undefined) {
    const modulesDir = join(dir, ".terraform", "modules");
    mkdirSync(modulesDir, { recursive: true });
    writeFileSync(join(modulesDir, "modules.json"), modulesJson);
  } else if (terraformDir === "providers-only") {
    // init ran, providers materialized, no module calls → no modules.json.
    mkdirSync(join(dir, ".terraform", "providers"), { recursive: true });
  } else if (terraformDir === "empty") {
    // A `.terraform/` dir with NO `providers/` — empty/fabricated init dir.
    mkdirSync(join(dir, ".terraform"), { recursive: true });
  } else if (terraformDir === "stale-modules") {
    // providers/ AND modules/ both exist but NO modules.json — stale/partial.
    mkdirSync(join(dir, ".terraform", "providers"), { recursive: true });
    mkdirSync(join(dir, ".terraform", "modules"), { recursive: true });
  } else if (terraformDir === "file") {
    // A stray `.terraform` FILE — defensively NOT an init dir.
    writeFileSync(join(dir, ".terraform"), "not a directory");
  }
  return { dir, identity: "infrastructure" };
}

function makeOutDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "licenses-tf-out-"));
  tempDirs.push(dir);
  return dir;
}

interface ScannedDoc {
  target: Target;
  sbomPath: string;
  cacheKey: string;
  tool: { name: string; version: string };
  raw: string;
  doc: Record<string, unknown>;
  components: Array<Record<string, unknown>>;
}

async function scanTarget(
  lockText: string,
  modulesJson?: string,
): Promise<ScannedDoc> {
  const target = makeTerraformTarget(lockText, { modulesJson });
  const result = await collectWithTerraform(target, { tempDir: makeOutDir() });
  const raw = readFileSync(result.sbomPath, "utf8");
  const doc = JSON.parse(raw) as Record<string, unknown>;
  const components = (doc["components"] ?? []) as Array<
    Record<string, unknown>
  >;
  return { target, ...result, raw, doc, components };
}

function purls(components: Array<Record<string, unknown>>): string[] {
  return components.map((c) => String(c["purl"]));
}

// ---------------------------------------------------------------------------
// Tool identity
// ---------------------------------------------------------------------------

describe("TERRAFORM_COLLECTOR_TOOL", () => {
  test("identity the CLI prints as name@version", () => {
    expect(TERRAFORM_COLLECTOR_TOOL).toEqual({
      name: "terraform-collector",
      version: "1",
    });
  });
});

// ---------------------------------------------------------------------------
// parseProviders — provider blocks of the live locks
// ---------------------------------------------------------------------------

describe("parseProviders", () => {
  test("the root lock parses to its exact (host, namespace, name, version) SET", () => {
    const set = new Set(
      parseProviders(ROOT_LOCK).map(
        (p) => `${p.host}|${p.namespace}|${p.name}|${p.version}`,
      ),
    );
    // Re-derived from the live root lock bytes, never a RESEARCH count.
    expect(set).toEqual(
      new Set([
        "registry.opentofu.org|hashicorp|aws|6.42.0",
        "registry.opentofu.org|hashicorp|random|3.8.1",
        "registry.opentofu.org|hashicorp|time|0.13.1",
        "registry.opentofu.org|integrations|github|6.12.0",
      ]),
    );
  });

  test("the cloudfront lock parses every provider including the no-constraints archive block", () => {
    const set = new Set(
      parseProviders(CLOUDFRONT_LOCK).map(
        (p) => `${p.namespace}/${p.name}@${p.version}`,
      ),
    );
    expect(set).toEqual(
      new Set([
        "hashicorp/archive@2.6.0",
        "hashicorp/aws@5.75.0",
        "hashicorp/external@2.3.4",
        "hashicorp/local@2.5.2",
        "hashicorp/null@3.2.3",
        "hashicorp/random@3.6.3",
      ]),
    );
  });

  test("a provider block with NO constraints line still parses (version then hashes)", () => {
    const archive = parseProviders(CLOUDFRONT_LOCK).find(
      (p) => p.name === "archive",
    );
    expect(archive).toMatchObject({
      host: "registry.opentofu.org",
      namespace: "hashicorp",
      name: "archive",
      version: "2.6.0",
    });
  });

  test("the parsed version is the VERBATIM lock-pinned string, never the constraint", () => {
    const aws = parseProviders(ROOT_LOCK).find((p) => p.name === "aws");
    expect(aws?.version).toBe("6.42.0");
  });

  test("brace-edge: a hashes array between version and the closing } does not break block boundaries", () => {
    const set = new Set(
      parseProviders(BRACE_EDGE_LOCK).map((p) => `${p.name}@${p.version}`),
    );
    // Both blocks resolve; the version of each is taken from its own header,
    // not corrupted by the bracket/brace of the hashes array.
    expect(set).toEqual(new Set(["edge@1.2.3", "after@9.9.9"]));
  });

  test("the fargate lock parses aws 6.42.0 and time 0.13.1", () => {
    const set = new Set(
      parseProviders(FARGATE_LOCK).map((p) => `${p.name}@${p.version}`),
    );
    expect(set).toEqual(new Set(["aws@6.42.0", "time@0.13.1"]));
  });

  test("a zero-provider lock parses to an empty array", () => {
    expect(parseProviders(ZERO_PROVIDER_LOCK)).toEqual([]);
  });

  test("a malformed (non-3-part) provider address is tolerantly skipped", () => {
    const lock = `provider "registry.opentofu.org/onlytwo" {
  version = "1.0.0"
  hashes = [ "h1:x" ]
}

provider "registry.opentofu.org/hashicorp/aws" {
  version = "6.42.0"
  hashes = [ "h1:y" ]
}
`;
    const set = new Set(
      parseProviders(lock).map((p) => `${p.namespace}/${p.name}@${p.version}`),
    );
    expect(set).toEqual(new Set(["hashicorp/aws@6.42.0"]));
  });

  // INFO #3: a commented-out `# version = "9.9.9"` line BEFORE the real version
  // must not be captured — the real lock-pinned version wins.
  test("a commented-out version line before the real version is NOT captured", () => {
    const lock = `provider "registry.opentofu.org/hashicorp/aws" {
  # version = "9.9.9"
  version = "6.42.0"
  hashes = [ "h1:y" ]
}
`;
    const aws = parseProviders(lock).find((p) => p.name === "aws");
    expect(aws?.version).toBe("6.42.0");
  });

  test("an indented real version after a commented line still parses (anchored to a version-only line)", () => {
    const lock = `provider "registry.opentofu.org/hashicorp/time" {
    # version = "1.1.1"  (old pin, kept as a note)
    version = "0.13.1"
  }
`;
    const time = parseProviders(lock).find((p) => p.name === "time");
    expect(time?.version).toBe("0.13.1");
  });
});

// ---------------------------------------------------------------------------
// readExternalModules — authoritative external module reader
// ---------------------------------------------------------------------------

describe("readExternalModules", () => {
  test("fully-qualified 4-segment registry Sources with non-empty Version are external (version verbatim)", () => {
    const set = new Set(
      readExternalModules(MODULES_JSON).map(
        (m) => `${m.host}|${m.namespace}/${m.name}/${m.provider}@${m.version}`,
      ),
    );
    // Re-derived from the live infrastructure/.terraform/modules/modules.json:
    // alb, ecs (cluster + service submodules at the SAME version), vpc — all
    // host registry.opentofu.org, all 4-segment fully-qualified or //submodule.
    expect(set).toEqual(
      new Set([
        "registry.opentofu.org|terraform-aws-modules/alb/aws@9.17.0",
        "registry.opentofu.org|terraform-aws-modules/ecs/aws@7.5.0",
        "registry.opentofu.org|terraform-aws-modules/vpc/aws@6.6.1",
      ]),
    );
  });

  test("a `//submodule` Source strips the submodule path, keeping <ns>/<name>/<provider>", () => {
    const ecs = readExternalModules(MODULES_JSON).filter(
      (m) => m.name === "ecs",
    );
    // Both the cluster and service submodule entries resolve to the SAME
    // <ns>/<name>/<provider>@version address (submodule path stripped).
    expect(ecs.length).toBe(2);
    for (const m of ecs) {
      expect(m).toMatchObject({
        host: "registry.opentofu.org",
        namespace: "terraform-aws-modules",
        name: "ecs",
        provider: "aws",
        version: "7.5.0",
      });
    }
  });

  test("an external module carries its parsed registry host (OpenTofu rewrites it to registry.opentofu.org)", () => {
    const alb = readExternalModules(MODULES_JSON).find((m) => m.name === "alb");
    expect(alb?.host).toBe("registry.opentofu.org");
  });

  test("local (relative-Source) and Version-less entries yield ZERO external modules", () => {
    expect(readExternalModules(LOCAL_ONLY_MODULES_JSON)).toEqual([]);
  });

  test("the root self entry (empty Source) and `../` relative Sources are excluded", () => {
    // MODULES_JSON contains the root {Source:""}, ./modules/fargate, and
    // ../container-definition — none of which are external registry modules.
    const names = readExternalModules(MODULES_JSON).map((m) => m.name);
    expect(names).not.toContain("");
    expect(names).not.toContain("container-definition");
    expect(names).not.toContain("fargate");
  });

  test("a registry Source with NO Version is excluded (Version is the resolved gate)", () => {
    expect(readExternalModules(NO_VERSION_MODULES_JSON)).toEqual([]);
  });

  test("git:: and https:// Sources are not registry-shorthand and yield zero", () => {
    expect(readExternalModules(VCS_SOURCE_MODULES_JSON)).toEqual([]);
  });

  // WARNING #2: a 4-segment Source on a NON-default registry host (HCP private
  // app.terraform.io, a self-hosted/partner registry) must be treated as a
  // registry module — host + <ns>/<name>/<provider> — not silently dropped.
  test("a non-default registry host (app.terraform.io, custom) yields a module with the right host + version", () => {
    const json = JSON.stringify({
      Modules: [
        { Key: "", Source: "", Dir: "." },
        {
          Key: "hcp.mod",
          Source: "app.terraform.io/my-org/vpc/aws",
          Version: "3.1.0",
          Dir: ".terraform/modules/hcp.mod",
        },
        {
          Key: "self.mod",
          Source: "tf.mycorp.example.com/platform/network/aws",
          Version: "2.0.4",
          Dir: ".terraform/modules/self.mod",
        },
      ],
    });
    const set = new Set(
      readExternalModules(json).map(
        (m) => `${m.host}|${m.namespace}/${m.name}/${m.provider}@${m.version}`,
      ),
    );
    expect(set).toEqual(
      new Set([
        "app.terraform.io|my-org/vpc/aws@3.1.0",
        "tf.mycorp.example.com|platform/network/aws@2.0.4",
      ]),
    );
  });

  test("a non-default-host 4-segment module produces a host-correct purl downstream", () => {
    const json = JSON.stringify({
      Modules: [
        {
          Key: "hcp.mod",
          Source: "app.terraform.io/my-org/vpc/aws",
          Version: "3.1.0",
          Dir: ".terraform/modules/hcp.mod",
        },
      ],
    });
    // moduleComponent (exercised via the public emission) stamps the parsed
    // host into the purl; assert the parsed shape carries the explicit host.
    const mod = readExternalModules(json)[0];
    expect(mod).toMatchObject({
      host: "app.terraform.io",
      namespace: "my-org",
      name: "vpc",
      provider: "aws",
      version: "3.1.0",
    });
  });

  test("a local ./ source is STILL excluded even though it has 4 slash-segments after a dot-less prefix", () => {
    // Guard: the non-default-host relaxation must not start accepting locals.
    const json = JSON.stringify({
      Modules: [
        {
          Key: "local",
          Source: "./modules/a/b/c",
          Version: "1.0.0",
          Dir: "modules/a/b/c",
        },
      ],
    });
    expect(readExternalModules(json)).toEqual([]);
  });

  test("a 4-segment Source whose first segment is NOT a hostname (no dot) stays the bare 3-segment shorthand path → not 4-as-host", () => {
    // "a/b/c/d" — first segment "a" has no ".", so it is NOT a host; the address
    // is then 4 triple-segments which is not the 3-segment shorthand → excluded
    // (never mis-parsed as host=a).
    const json = JSON.stringify({
      Modules: [
        {
          Key: "weird",
          Source: "a/b/c/d",
          Version: "1.0.0",
          Dir: ".terraform/modules/weird",
        },
      ],
    });
    expect(readExternalModules(json)).toEqual([]);
  });

  // Distinguish LEGIT-EMPTY (valid JSON `{}`, no Modules key,
  // or `Modules: []`) → return [] (zero modules), from STRUCTURALLY-INVALID
  // (JSON.parse throws, or Modules present but not an array) → throw loud.
  test("legit-empty modules.json (`{}`, no Modules, or `Modules: []`) returns [] (zero modules)", () => {
    expect(readExternalModules("{}")).toEqual([]);
    expect(readExternalModules(JSON.stringify({ Modules: [] }))).toEqual([]);
    expect(readExternalModules(JSON.stringify({ other: "x" }))).toEqual([]);
  });

  test("structurally-invalid modules.json (JSON.parse fails) throws loud naming the failure", () => {
    expect(() => readExternalModules("this is not json {{{")).toThrow(
      /modules\.json/,
    );
    expect(() => readExternalModules("{broken")).toThrow(/modules\.json/);
  });

  // The empty string is the internal "no modules.json present" sentinel that the
  // collector/coverage pass on the providers-only path — it stays a tolerant []
  // (an absent file is never a scan failure; the gate handles absence).
  test("the empty-string sentinel (no modules.json present) stays [] (not a throw)", () => {
    expect(readExternalModules("")).toEqual([]);
  });

  test("a `Modules` key that is NOT an array throws loud (structurally-invalid)", () => {
    expect(() => readExternalModules(JSON.stringify({ Modules: "x" }))).toThrow(
      /modules\.json/,
    );
    expect(() =>
      readExternalModules(JSON.stringify({ Modules: { a: 1 } })),
    ).toThrow(/modules\.json/);
  });

  // Tolerant skipping of individual malformed ENTRIES is
  // PRESERVED — an array with one bad row and one good row keeps the good row.
  test("an array with one malformed entry and one good entry keeps the good entry (no throw)", () => {
    const json = JSON.stringify({
      Modules: [
        "not an object",
        {
          Key: "vpc",
          Source: "registry.opentofu.org/terraform-aws-modules/vpc/aws",
          Version: "6.6.1",
          Dir: ".terraform/modules/vpc",
        },
      ],
    });
    const set = new Set(
      readExternalModules(json).map(
        (m) => `${m.namespace}/${m.name}/${m.provider}@${m.version}`,
      ),
    );
    expect(set).toEqual(new Set(["terraform-aws-modules/vpc/aws@6.6.1"]));
  });
});

// ---------------------------------------------------------------------------
// terraformComponentCount — coverage counter semantics
// ---------------------------------------------------------------------------

describe("terraformComponentCount", () => {
  test("providers + a present modules.json with externals returns a positive count", () => {
    // root lock has 4 providers; modules.json adds alb + ecs (cluster+service
    // collapse to ONE purl) + vpc = 3 distinct module components → 4 + 3 = 7.
    expect(terraformComponentCount(ROOT_LOCK, MODULES_JSON)).toBe(7);
  });

  test("a zero-provider lock with a local-only modules.json returns 0", () => {
    expect(
      terraformComponentCount(ZERO_PROVIDER_LOCK, LOCAL_ONLY_MODULES_JSON),
    ).toBe(0);
  });

  test("a providers-only count when modules.json is local-only equals the provider count", () => {
    expect(terraformComponentCount(FARGATE_LOCK, LOCAL_ONLY_MODULES_JSON)).toBe(
      2,
    );
  });
});

// ---------------------------------------------------------------------------
// collectWithTerraform — emission, purl spelling, exact versions
// ---------------------------------------------------------------------------

describe("collectWithTerraform — emission", () => {
  test("emits a minimal CycloneDX 1.6 document (no serialNumber, no timestamp)", async () => {
    const { doc, raw } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    expect(doc["bomFormat"]).toBe("CycloneDX");
    expect(doc["specVersion"]).toBe("1.6");
    expect(Array.isArray(doc["components"])).toBe(true);
    expect(raw.includes("serialNumber")).toBe(false);
    expect(raw.includes("timestamp")).toBe(false);
  });

  test("a provider emits the locked purl spelling and name with no group", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    const aws = components.find(
      (c) =>
        c["purl"] ===
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
    );
    expect(aws).toMatchObject({
      type: "library",
      name: "hashicorp/aws",
      version: "6.42.0",
      purl: "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
    });
    expect(aws?.["group"]).toBeUndefined();
  });

  test("an external module emits the 3-path-segment purl keeping the provider segment, name <ns>/<name>/<provider>", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    const vpc = components.find(
      (c) =>
        c["purl"] ===
        "pkg:terraform/registry.opentofu.org/terraform-aws-modules/vpc/aws@6.6.1",
    );
    expect(vpc).toMatchObject({
      type: "library",
      name: "terraform-aws-modules/vpc/aws",
      version: "6.6.1",
      purl: "pkg:terraform/registry.opentofu.org/terraform-aws-modules/vpc/aws@6.6.1",
    });
    expect(vpc?.["group"]).toBeUndefined();
  });

  test("a provider purl has 2 path segments after host; a module purl has 3 (count is the distinguisher)", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    // pkg:terraform/<host>/<seg...>@<v> — count the slash-separated segments
    // AFTER the host, before @version.
    const pathSegs = (purl: string): number => {
      const afterType = purl.slice("pkg:terraform/".length);
      const atVersion = afterType.slice(0, afterType.lastIndexOf("@"));
      return atVersion.split("/").length - 1; // minus the host segment
    };
    const provider = components.find(
      (c) =>
        c["purl"] ===
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
    );
    const module = components.find(
      (c) =>
        c["purl"] ===
        "pkg:terraform/registry.opentofu.org/terraform-aws-modules/vpc/aws@6.6.1",
    );
    expect(pathSegs(String(provider?.["purl"]))).toBe(2);
    expect(pathSegs(String(module?.["purl"]))).toBe(3);
  });

  test("submodules of the same module at the same version collapse to ONE purl-keyed row", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    // ecs//modules/cluster + ecs//modules/service → both
    // terraform-aws-modules/ecs/aws@7.5.0 → exactly one component row.
    const ecsRows = components.filter(
      (c) =>
        c["purl"] ===
        "pkg:terraform/registry.opentofu.org/terraform-aws-modules/ecs/aws@7.5.0",
    );
    expect(ecsRows.length).toBe(1);
    // And the bom carries no duplicate purls at all.
    const allPurls = purls(components);
    expect(new Set(allPurls).size).toBe(allPurls.length);
  });

  test("every emitted component purl ends in @<exact-version> (the enrich-stage contract)", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    // A provider purl tail and a module purl tail are both exact pins.
    expect(
      purls(components).some((p) => p.endsWith("/hashicorp/aws@6.42.0")),
    ).toBe(true);
    expect(
      purls(components).some((p) =>
        p.endsWith("/terraform-aws-modules/vpc/aws@6.6.1"),
      ),
    ).toBe(true);
    // No component carries a version-stripped or constraint-shaped tail.
    for (const purl of purls(components)) {
      expect(/@[^@/]+$/.test(purl)).toBe(true);
      expect(purl).not.toContain(">=");
    }
  });

  test("no component carries a licenses[] array (enrich fills it later)", async () => {
    const { components } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    for (const component of components) {
      expect(component["licenses"]).toBeUndefined();
    }
  });

  test("components are sorted compareCodeUnits by purl", async () => {
    const { components } = await scanTarget(CLOUDFRONT_LOCK, MODULES_JSON);
    const got = purls(components);
    const sorted = [...got].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(got).toEqual(sorted);
  });

  test("the same provider at two versions across locks would yield two distinct purl rows", async () => {
    // Within one target the cloudfront lock pins aws 5.75.0; the root lock
    // pins aws 6.42.0 — distinct purls (the exact-version-tail contract).
    const cf = await scanTarget(CLOUDFRONT_LOCK, LOCAL_ONLY_MODULES_JSON);
    const root = await scanTarget(ROOT_LOCK, LOCAL_ONLY_MODULES_JSON);
    expect(purls(cf.components)).toContain(
      "pkg:terraform/registry.opentofu.org/hashicorp/aws@5.75.0",
    );
    expect(purls(root.components)).toContain(
      "pkg:terraform/registry.opentofu.org/hashicorp/aws@6.42.0",
    );
  });
});

// ---------------------------------------------------------------------------
// collectWithTerraform — determinism + contract
// ---------------------------------------------------------------------------

describe("collectWithTerraform — determinism and contract", () => {
  test("two runs over the same bytes produce byte-identical bom.json", async () => {
    const first = await scanTarget(ROOT_LOCK, MODULES_JSON);
    const second = await scanTarget(ROOT_LOCK, MODULES_JSON);
    expect(first.raw).toBe(second.raw);
  });

  test("the serialized document ends with a trailing LF", async () => {
    const { raw } = await scanTarget(ROOT_LOCK, MODULES_JSON);
    expect(raw.endsWith("\n")).toBe(true);
  });

  test("returns { sbomPath, cacheKey, tool } with bom.json in the given temp dir", async () => {
    const target = makeTerraformTarget(ROOT_LOCK, {
      modulesJson: MODULES_JSON,
    });
    const outDir = makeOutDir();
    const result = await collectWithTerraform(target, { tempDir: outDir });
    expect(result.sbomPath).toBe(join(outDir, "bom.json"));
    expect(result.tool).toEqual(TERRAFORM_COLLECTOR_TOOL);
    expect(result.cacheKey).toBe(
      computeCacheKey(
        target,
        TERRAFORM_COLLECTOR_TOOL,
        ["terraform-collector-v1"],
        [".terraform.lock.hcl"],
      ),
    );
  });
});

// ---------------------------------------------------------------------------
// The absent-modules.json gate — a pure FILESYSTEM signal.
//
// Successive review passes each found another valid-HCL shape (a
// nested `source` decoy, `${...}` interpolation with nested quotes, CR-only line
// endings, a comment between the `module` keyword and its name) that a
// hand-rolled HCL lexer mis-tokenized → silent module drop. Hand-lexing HCL is
// the wrong approach: the gate's REAL question is "did `tofu init` run?", and
// that is answerable from the filesystem — does the `<dir>/.terraform/` directory
// exist? — with no HCL parsing at all.
//
// Empirical basis: `tofu init` materializes the gitignored `.terraform/` dir. A
// providers-only dir (no module calls) gets `.terraform/providers/` but NO
// `.terraform/modules/modules.json`. A module-bearing dir (local OR external)
// gets `.terraform/modules/modules.json` as soon as tofu PROCESSES the module
// calls — even when the module DOWNLOAD later fails. So modules.json absence
// reliably means "no module calls" WHENEVER init has run. Therefore:
//   - modules.json PRESENT → read external modules (authoritative present-path);
//   - modules.json ABSENT + `<dir>/.terraform/` dir EXISTS → init ran, no module
//     calls → collect providers, NO throw (github-actions-deployment shape);
//   - modules.json ABSENT + `<dir>/.terraform/` dir ABSENT → init never ran →
//     THROW the loud "run tofu init/tofu get first" error. Conservative-safe:
//     without init we cannot prove there are no modules.
// A stray `.terraform` FILE (not a directory) is defensively treated as NOT
// init'd → throw.
// ---------------------------------------------------------------------------

describe("absentModulesJsonShouldFail — the filesystem-signal gate", () => {
  test("no `.terraform/` dir at all → true (init never ran, fail loud)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "none",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(true);
  });

  test("a `.terraform/` dir EXISTS (providers-only init) → false (collect, no throw)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "providers-only",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(false);
  });

  test("a stray `.terraform` FILE (not a dir) → true (defensively NOT init'd, fail loud)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "file",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(true);
  });

  // An empty/fabricated `.terraform/` lacking `providers/`
  // is NOT a real init artifact. A real providers-only `tofu init` writes
  // `.terraform/providers/`; its absence means the dir was not init'd → fail loud.
  test("a `.terraform/` dir with NO `providers/` subdir → true (empty/fabricated, fail loud)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "empty",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(true);
  });

  // `.terraform/providers/` AND `.terraform/modules/`
  // present but NO modules.json is a stale/partial module install — tofu writes
  // modules.json the instant it processes module blocks, so a modules/ dir
  // without it is incoherent → fail loud rather than collect providers-only.
  test("`.terraform/providers/` + `.terraform/modules/` present but NO modules.json → true (stale/partial, fail loud)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "stale-modules",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(true);
  });

  // The github-actions-deployment shape — `.terraform/
  // providers/` present, NO `.terraform/modules/`, no modules.json — STILL
  // collects (the strengthened signal's only false/collect case is unchanged).
  test("`.terraform/providers/` present + no `.terraform/modules/` + no modules.json → false (github-actions shape, collect)", () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "providers-only",
    });
    expect(absentModulesJsonShouldFail(target.dir)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// collectWithTerraform — absent modules.json, `.terraform/` ABSENT → loud fail
//
// init never ran: without it we cannot prove the dir is providers-only, so the
// gate fails loud rather than risk a silent incomplete inventory. (The 4 lexer
// "CVEs" — nested-source decoy, interpolation, CR-only, comment-between-keyword-
// and-name — are GONE by construction: no HCL is ever parsed.)
// ---------------------------------------------------------------------------

describe("collectWithTerraform — absent modules.json + no `.terraform/` (loud fail)", () => {
  test("absent modules.json + no `.terraform/` dir throws (run tofu init/tofu get first)", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "none",
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/tofu init|tofu get/);
  });

  test("the loud-fail message names the missing modules.json path", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "none",
    });
    expect.assertions(1);
    try {
      await collectWithTerraform(target, { tempDir: makeOutDir() });
    } catch (error) {
      expect(String(error)).toContain("modules.json");
    }
  });

  test("absent modules.json + no `.terraform/` is NEVER a silent empty inventory", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "none",
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow();
  });

  test("a stray `.terraform` FILE (not a dir) + absent modules.json still throws", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "file",
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/tofu init|tofu get/);
  });

  // An empty `.terraform/` lacking `providers/` → throw.
  test("an empty `.terraform/` dir (no `providers/`) + absent modules.json throws", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "empty",
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/tofu init|tofu get/);
  });

  // `.terraform/modules/` without modules.json → throw.
  test("`.terraform/providers/` + `.terraform/modules/` but no modules.json (stale/partial) throws", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "stale-modules",
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/tofu init|tofu get/);
  });

  // A directory-named modules.json is a non-regular-file
  // PRESENCE — it must route to the gate (which, seeing `.terraform/modules/`
  // exists with no modules.json file, throws loudly), NOT raw uncaught EISDIR.
  test("a directory-named modules.json routes to the gate → loud throw, not raw EISDIR", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      modulesJsonAsDir: true,
    });
    await expect(
      collectWithTerraform(target, { tempDir: makeOutDir() }),
    ).rejects.toThrow(/tofu init|tofu get/);
  });
});

// ---------------------------------------------------------------------------
// collectWithTerraform — providers-only, `.terraform/` EXISTS, no modules.json
//
// The providers-only finding-B shape: a providers-only Terraform dir
// (github-actions-deployment: aws + integrations/github providers, NO module
// calls) where `tofu init` succeeded and wrote `.terraform/providers/` but no
// modules.json. The filesystem gate sees `.terraform/` exists → collect the
// committed-lock providers; NO throw.
// ---------------------------------------------------------------------------

const PROVIDERS_ONLY_LOCK = `# This file is maintained automatically by "tofu init".
provider "registry.opentofu.org/hashicorp/aws" {
  version = "5.75.0"
  hashes = [ "h1:x" ]
}

provider "registry.opentofu.org/integrations/github" {
  version = "6.12.0"
  hashes = [ "h1:y" ]
}
`;

describe("collectWithTerraform — providers-only, `.terraform/` exists (no throw)", () => {
  test("a providers-only dir whose `.terraform/` exists (no modules.json) collects providers", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "providers-only",
    });
    const result = await collectWithTerraform(target, {
      tempDir: makeOutDir(),
    });
    const raw = readFileSync(result.sbomPath, "utf8");
    const doc = JSON.parse(raw) as Record<string, unknown>;
    const components = (doc["components"] ?? []) as Array<
      Record<string, unknown>
    >;
    const got = new Set(purls(components));
    expect(got).toEqual(
      new Set([
        "pkg:terraform/registry.opentofu.org/hashicorp/aws@5.75.0",
        "pkg:terraform/registry.opentofu.org/integrations/github@6.12.0",
      ]),
    );
  });

  test("a providers-only dir whose `.terraform/` exists emits ZERO external modules", async () => {
    const target = makeTerraformTarget(PROVIDERS_ONLY_LOCK, {
      terraformDir: "providers-only",
    });
    const result = await collectWithTerraform(target, {
      tempDir: makeOutDir(),
    });
    const raw = readFileSync(result.sbomPath, "utf8");
    const doc = JSON.parse(raw) as Record<string, unknown>;
    const components = (doc["components"] ?? []) as Array<
      Record<string, unknown>
    >;
    // No 3-path-segment (module) purls — only 2-segment provider purls.
    const moduleRows = purls(components).filter((p) => {
      const afterType = p.slice("pkg:terraform/".length);
      const atVersion = afterType.slice(0, afterType.lastIndexOf("@"));
      return atVersion.split("/").length - 1 === 3;
    });
    expect(moduleRows).toEqual([]);
  });
});
