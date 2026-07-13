/**
 * Per-lockfile-kind collector registry: the CLI's target loop resolves
 * `collectors.get(target.lockfile)` and awaits collect() — adding a target
 * kind means one registration here, never a new dispatch branch.
 *
 * Collectors NEVER write to stderr. The loop owns the
 * "collecting <id> via <name>@<version>" line (asking the registration for
 * its tool identity first), so the fixed stderr shapes are emitted from
 * exactly one place; ctx.log is the loop-provided sink should a collector
 * ever need to surface a line through the CLI.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { purlSetOf, type CollectedSbom } from "../merge/merge";
import {
  firstPartyNames,
  npmFirstPartyNames,
  pnpmImporterNames,
} from "../targets/firstParty";
import { BUN_COLLECTOR_TOOL, collectWithBunLock } from "./bunLock";
import { CDXGEN_TOOL, collectWithCdxgen } from "./cdxgen";
import { ecosystemFor, manifestFilesFor, selectJsGenerator } from "./dispatch";
import { npmIntroductions } from "./npmProvenance";
import { poetryProdPurlSet } from "./poetryLock";
import { poetryIntroductions } from "./poetryProvenance";
import { collectWithTerraform, TERRAFORM_COLLECTOR_TOOL } from "./terraform";
import { collectWithYarnPlugin, YARN_PLUGIN_TOOL } from "./yarnPlugin";
import type { DiscoveredTarget, LockfileKind } from "../targets/discover";

/** Identity printed in the loop-owned "collecting X via name@version" line. */
export interface ToolIdentity {
  readonly name: string;
  readonly version: string;
}

/** Per-target context a collector receives from the CLI loop. */
export interface CollectContext {
  /**
   * Full lockfile text — present for lockfile-dir targets (all current
   * kinds); future non-lockfile target kinds (Phase 6 Docker/Terraform)
   * simply won't receive it. Optional so the type expresses that flexibility
   * the kind-agnostic registry promises.
   */
  lockfileText?: string;
  /** Generator wall-clock budget per scan; in-process collectors ignore it. */
  timeoutMs: number;
  verbose: boolean;
  /** CLI-owned stderr sink — collectors must never write stderr directly. */
  log: (line: string) => void;
}

/**
 * Read the lockfile text a lockfile-dir collector requires. Throws (the scan
 * failure path) if a collector that needs it is somehow invoked without it —
 * unreachable for all current kinds, but it keeps the now-optional field
 * type-safe at the read sites.
 */
function requireLockfileText(ctx: CollectContext): string {
  if (ctx.lockfileText === undefined) {
    throw new Error(
      "collector requires lockfile text but the context provided none",
    );
  }
  return ctx.lockfileText;
}

export interface Collector {
  /**
   * Tool identity for the stderr line, resolved from the lockfile text:
   * yarn's generator choice is content-dependent (plugin for Yarn 4+,
   * cdxgen otherwise); every other kind ignores the argument.
   */
  tool(lockfileText: string): ToolIdentity;
  /**
   * One discovered target -> the merge-ready input. Throws on scan failure
   * (the CLI's config/tool-error exit path).
   */
  collect(
    target: DiscoveredTarget,
    ctx: CollectContext,
  ): Promise<CollectedSbom>;
}

/** Parse a collector's SBOM output file as an untrusted shape. */
function readSbom(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

/**
 * Read a target's pyproject.toml text for python provenance roots (07-13).
 * Tolerant: a missing or unreadable file yields an empty string — provenance
 * then derives no declared-direct roots (every package classifies transitive),
 * which is honest, never a scan failure.
 */
function readPyprojectText(target: DiscoveredTarget): string {
  const path = join(target.dir, "pyproject.toml");
  if (!existsSync(path)) return "";
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

/**
 * cdxgen-family collector: ecosystem and cache-key manifest list come from
 * the dispatch tables for the registered kind; the optional firstParty
 * derivation supplies the lockfile-derived member-name set the merge pairs
 * with its second first-party signal.
 */
function cdxgenCollector(
  kind: LockfileKind,
  firstParty?: (lockfileText: string) => ReadonlySet<string>,
): Collector {
  return {
    tool: (): ToolIdentity => CDXGEN_TOOL,
    async collect(target, ctx): Promise<CollectedSbom> {
      const result = await collectWithCdxgen(target, {
        timeoutMs: ctx.timeoutMs,
        verbose: ctx.verbose,
        ecosystem: ecosystemFor(kind),
        manifestFiles: manifestFilesFor(kind),
      });
      return {
        sbom: readSbom(result.sbomPath),
        targetIdentity: target.identity,
        ...(firstParty !== undefined
          ? { firstPartyNames: firstParty(requireLockfileText(ctx)) }
          : {}),
      };
    },
  };
}

/** Yarn <4 fallback: cdxgen with member names from the yarn lockfile. */
const yarnCdxgenCollector = cdxgenCollector("yarn", firstPartyNames);

/**
 * Yarn targets select their generator from the LOCKFILE CONTENT: Yarn 4+
 * (`__metadata.version >= 8`) routes to the dual-run plugin adapter — full +
 * prod SBOMs, dev scope derived downstream as full minus prod — while
 * pre-4, empty, or unparseable lockfiles fall back to cdxgen.
 */
const yarnCollector: Collector = {
  tool: (lockfileText): ToolIdentity =>
    selectJsGenerator(lockfileText) === "yarn-plugin"
      ? YARN_PLUGIN_TOOL
      : CDXGEN_TOOL,
  async collect(target, ctx): Promise<CollectedSbom> {
    const lockfileText = requireLockfileText(ctx);
    if (selectJsGenerator(lockfileText) !== "yarn-plugin") {
      return yarnCdxgenCollector.collect(target, ctx);
    }
    const result = await collectWithYarnPlugin(target, {
      timeoutMs: ctx.timeoutMs,
      verbose: ctx.verbose,
    });
    // Read the full SBOM once and derive provenance from its complete
    // root-anchored dependency graph (07-13). npmIntroductions returns an empty
    // map for a graph-less BOM, so a cdxgen-style fallback would simply carry no
    // provenance (the honest residual).
    const sbom = readSbom(result.sbomPath);
    return {
      sbom,
      targetIdentity: target.identity,
      // The --production run exists solely for this purl set: occurrence
      // dev = not in the prod set, authoritative over property markers.
      prodPurlSet: purlSetOf(readSbom(result.prodSbomPath)),
      firstPartyNames: firstPartyNames(lockfileText),
      introductions: npmIntroductions(sbom),
    };
  },
};

/**
 * bun targets use the in-process bun.lock collector (no upstream generator
 * preserves bun.lock identity). No subprocess, so timeoutMs is ignored; the
 * lockfile size gate fires inside collectWithBunLock as well as in the CLI
 * loop. NO firstPartyNames: the collector already excluded @workspace:
 * members and workspaces[*].name twins itself.
 */
const bunCollector: Collector = {
  tool: (): ToolIdentity => BUN_COLLECTOR_TOOL,
  async collect(target): Promise<CollectedSbom> {
    const result = await collectWithBunLock(target, {});
    return {
      sbom: readSbom(result.sbomPath),
      targetIdentity: target.identity,
    };
  },
};

/**
 * poetry targets run cdxgen for the component inventory but derive dev/prod
 * scope from poetry.lock, not from cdxgen properties: cdxgen --no-install-deps
 * emits NO cdx:pyproject:group marker, so every poetry dep would otherwise
 * classify prod. poetryProdPurlSet parses the lock's per-package `groups`
 * arrays into the `pkg:pypi/<pep503>@<version>` prod set, threaded into
 * prodPurlSet exactly like the yarn dual-run path — merge.ts then derives
 * occurrence dev = not in the set, authoritative over the absent markers and
 * prod-wins for a package in both main and a dev group.
 */
const poetryCollector: Collector = {
  tool: (): ToolIdentity => CDXGEN_TOOL,
  async collect(target, ctx): Promise<CollectedSbom> {
    const result = await collectWithCdxgen(target, {
      timeoutMs: ctx.timeoutMs,
      verbose: ctx.verbose,
      ecosystem: ecosystemFor("poetry"),
      manifestFiles: manifestFilesFor("poetry"),
    });
    const lockfileText = requireLockfileText(ctx);
    return {
      sbom: readSbom(result.sbomPath),
      targetIdentity: target.identity,
      prodPurlSet: poetryProdPurlSet(lockfileText),
      // Provenance (07-13) derived from poetry.lock dep tables + pyproject roots —
      // NOT cdxgen, which emits no usable poetry graph. Keyed by the same
      // pkg:pypi/<pep503>@<version> purls cdxgen emits, so the map joins onto the
      // cdxgen components by purl.
      introductions: poetryIntroductions(
        lockfileText,
        readPyprojectText(target),
      ),
    };
  },
};

/**
 * terraform targets use the in-process Terraform collector (no upstream
 * generator resolves Terraform provider/module licenses). No subprocess, so
 * timeoutMs is ignored. requireLockfileText asserts the loop passed the lock
 * text; the collector reads .terraform/modules/modules.json from target.dir
 * itself (not from ctx) and FAILS LOUD when it is absent (the init-has-run
 * gate). NO firstPartyNames / NO prodPurlSet: the collector excludes local
 * modules itself and emits a flat third-party inventory.
 */
const terraformCollector: Collector = {
  tool: (): ToolIdentity => TERRAFORM_COLLECTOR_TOOL,
  async collect(target, ctx): Promise<CollectedSbom> {
    requireLockfileText(ctx);
    const result = await collectWithTerraform(target, {});
    return {
      sbom: readSbom(result.sbomPath),
      targetIdentity: target.identity,
    };
  },
};

/**
 * The dispatch table, exhaustive over LockfileKind (locked by
 * test/registry.test.ts). npm members are emitted by cdxgen at their REAL
 * versions with cdx:npm:isWorkspace=true — the merge pairs that marker with
 * the npm lockfile-derived name set. The pnpm importer-name set is
 * defensive only: cdxgen omits pnpm workspace members from components
 * entirely, so the merge's marker condition stays load-bearing.
 */
export const collectors: ReadonlyMap<LockfileKind, Collector> = new Map<
  LockfileKind,
  Collector
>([
  ["yarn", yarnCollector],
  ["npm", cdxgenCollector("npm", npmFirstPartyNames)],
  ["pnpm", cdxgenCollector("pnpm", pnpmImporterNames)],
  ["bun", bunCollector],
  ["poetry", poetryCollector],
  ["uv", cdxgenCollector("uv")],
  ["terraform", terraformCollector],
]);
