/**
 * Custom Terraform/OpenTofu collector — a conscious exception to
 * orchestrate-don't-parse (Conflict A, settled custom), because no upstream
 * tool resolves Terraform provider/module licenses: cdxgen `-t terraform`
 * emits components with zero licenses, and no generator reads the external
 * module set at its EXACT resolved versions. This collector parses two trusted
 * artifacts the repo already commits/materializes and emits the same minimal
 * deterministic CycloneDX 1.6 document every other collector produces; license
 * resolution is deferred to the enrich-stage GitHub resolver (Plan 03).
 *
 * Two inputs, two authorities:
 * - Providers come from `.terraform.lock.hcl` (always committed): a regex over
 *   the `provider "<host>/<ns>/<name>" { version = "<v>" ... }` blocks yields
 *   the EXACT lock-pinned version verbatim. No `.tf` constraint blocks are ever
 *   parsed — the lock is the pin.
 * - External registry modules come from `.terraform/modules/modules.json`
 *   (`{"Modules":[{Key,Source,Version,Dir}]}`), the authoritative source of
 *   each module's EXACT resolved version. A module is external iff its Version
 *   is non-empty AND its Source parses as a registry address: an OPTIONAL
 *   leading `<host>/` where the host is ANY hostname-looking segment (contains
 *   a "." — the default `registry.opentofu.org`/`registry.terraform.io`, plus
 *   non-default HCP-private/self-hosted/partner registries; W#2), then
 *   `<ns>/<name>/<provider>`, then an OPTIONAL `//<submodule-path>` that is
 *   stripped. Local Sources (`./`/`../`, empty, or Version-less) are excluded as
 *   first-party. The Version is used
 *   VERBATIM. Two submodules of the same module at the same version
 *   (`ecs/aws//modules/cluster` + `ecs/aws//modules/service`) collapse to ONE
 *   component row because they share a purl.
 *
 * The "init has run" gate is a pure FILESYSTEM signal: the whole `.terraform/`
 * dir is gitignored and absent until `tofu init`/`tofu get` materializes it.
 * When a `.terraform.lock.hcl` target is detected:
 *   - modules.json PRESENT (as a REGULAR FILE) → read external modules (the
 *     authoritative present-path). A directory-named modules.json is treated as
 *     ABSENT (07-15 Fix 3) and routed to the gate below, never a raw EISDIR;
 *   - modules.json ABSENT + `.terraform/providers/` is a DIRECTORY AND
 *     `.terraform/modules/` does NOT exist → init ran but processed no module
 *     calls (the providers-only github-actions-deployment shape) → collect
 *     providers from the committed lock; NEVER a throw;
 *   - any OTHER absent-modules.json shape → FAIL LOUD with a "run tofu init/tofu
 *     get first" error: no `.terraform/providers/` dir (empty/fabricated
 *     `.terraform/`), or a `.terraform/modules/` dir without a modules.json
 *     (stale/partial install). Conservative-safe: we collect providers-only only
 *     for the exact artifact shape a real providers-only init leaves (07-15
 *     reviews #2/#4).
 * No HCL is parsed to make this decision (07-14 redesign). Empirically, `tofu
 * init` writes `.terraform/modules/modules.json` as soon as it PROCESSES module
 * calls (local OR external) — even when the module download later fails, and
 * before the provider phase — so modules.json absence reliably means "no module
 * calls" WHENEVER init has run. A residual stale-edit window (a module added to
 * `.tf` without re-init) is delegated to `tofu plan`/`validate`/`get` in CI; see
 * {@link absentModulesJsonShouldFail}. Never a silent skip, never a constraint
 * fallback.
 *
 * Every emitted purl carries the component's EXACT version verbatim. Providers
 * and modules are distinguished by the purl's PATH-SEGMENT COUNT after the host
 * (not by host — OpenTofu rewrites BOTH to registry.opentofu.org):
 *   provider: `pkg:terraform/<host>/<ns>/<name>@<v>`           (2 segments)
 *   module:   `pkg:terraform/<host>/<ns>/<name>/<provider>@<v>` (3 segments)
 * load-bearing for Plan 03's version-tag LICENSE fetch and the purl@version
 * cache.
 *
 * Fully in-process — no subprocess, no eval, no cwd change; an
 * assertTerraformLockSize stat gate bounds memory before any read/parse on both
 * the lock and the modules.json file; a malformed individual provider block or
 * modules.json entry is skipped tolerantly, while a whole-file failure throws
 * loudly (the scan-failure path). Zero new runtime dependencies.
 */

import {
  existsSync,
  mkdtempSync,
  statSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type } from "arktype";

import { recordOf, stringOf } from "../validate/record";
import { computeCacheKey, type CollectorSbomFile } from "./cdxgen";
import { manifestFilesFor } from "./dispatch";
import type { Target } from "../targets/target";

/**
 * Collector identity (the CLI prints `${name}@${version}`). Hashed into the
 * cache key — a version bump invalidates cache entries on purpose.
 */
export const TERRAFORM_COLLECTOR_TOOL = {
  name: "terraform-collector",
  version: "1",
} as const;

/**
 * DoS bound: real .terraform.lock.hcl and modules.json files are tiny (<1 MB);
 * 32 MiB is generous headroom. The stat gate fires before any read or parse so
 * a hostile file can never balloon memory. The same cap applies to both files.
 */
export const MAX_TERRAFORM_LOCK_BYTES = 32 * 1024 * 1024;

/**
 * Stat-gate a Terraform artifact path against MAX_TERRAFORM_LOCK_BYTES before
 * any read or parse. Shared by the lock and the modules.json read.
 */
export function assertTerraformLockSize(path: string): void {
  const size = statSync(path).size;
  if (size > MAX_TERRAFORM_LOCK_BYTES) {
    throw new Error(
      `Terraform file at ${path} is ${size} bytes, over the ` +
        `${MAX_TERRAFORM_LOCK_BYTES}-byte cap — refusing to parse it ` +
        `(real Terraform lock/modules files are <1 MB)`,
    );
  }
}

/** The constant pseudo-argv hashed into the cache key (no real subprocess). */
const TERRAFORM_CACHE_ARGS = ["terraform-collector-v1"];

/** Manifest files hashed into the cache key — single-sourced from dispatch. */
const TERRAFORM_MANIFEST_FILES = manifestFilesFor("terraform");

/**
 * The default registry host stamped onto a module purl when the Source is a
 * bare registry shorthand (`<ns>/<name>/<provider>` with no host prefix).
 * OpenTofu rewrites real Source records to a fully-qualified
 * `registry.opentofu.org/...` form, so this default is only the rare
 * shorthand-without-host fallback; a host present in the Source wins verbatim.
 */
const DEFAULT_MODULE_HOST = "registry.opentofu.org";

/**
 * One provider parsed from a `.terraform.lock.hcl` block: the address split on
 * "/" into host/namespace/name, plus the verbatim lock-pinned version.
 */
export interface TerraformProvider {
  host: string;
  namespace: string;
  name: string;
  version: string;
}

/**
 * §Pattern 1: match each provider block's address and its `version` field.
 * `[^}]*?` lazily spans only the whitespace/`constraints` line between the
 * block header `{` and the `version` key — neither contains `}` — so the match
 * stops at `version` and never reaches the block's closing brace or the
 * `hashes = [ ... ]` array that follows. A block with NO constraints line
 * (version directly after `{`) matches identically. The brace-edge RED fixture
 * confirms this holds; if it had broken, a line-state tokenizer was the
 * fallback — it did not, so the regex stands.
 *
 * The `version` capture is ANCHORED to the START OF A LINE (the `m` flag plus
 * `^[ \t]*`) so a COMMENTED pin (`# version = "9.9.9"`) before the real version
 * is NOT captured (I#3): a `#`-prefixed line has the `#` before `version`, so it
 * fails the `^[ \t]*version` anchor and the lazy span advances to the next line,
 * the real `version = "..."`. `[ \t]*` (horizontal whitespace only, never `\s`
 * which would cross newlines) keeps the anchor to a single line.
 */
const PROVIDER_BLOCK =
  /provider\s+"([^"]+)"\s*\{[^}]*?^[ \t]*version\s*=\s*"([^"]+)"/gms;

/**
 * Parse the lock-pinned providers from `.terraform.lock.hcl` text. Pure
 * function over text. The address must split into exactly three "/"-segments
 * (host/namespace/name); a non-conforming address is tolerantly skipped. The
 * captured version is the verbatim lock string — no normalization.
 */
export function parseProviders(lockText: string): TerraformProvider[] {
  const providers: TerraformProvider[] = [];
  for (const match of lockText.matchAll(PROVIDER_BLOCK)) {
    const address = match[1] as string;
    const version = match[2] as string;
    const parts = address.split("/");
    if (parts.length !== 3) continue; // malformed address — tolerant skip
    const [host, namespace, name] = parts as [string, string, string];
    providers.push({ host, namespace, name, version });
  }
  return providers;
}

/**
 * One external registry module resolved from modules.json: the registry host
 * (parsed from the Source or the default), the `<ns>/<name>/<provider>` address
 * split into parts, plus the verbatim resolved Version. Any `//<submodule>`
 * suffix in the Source has been stripped.
 */
export interface TerraformModule {
  host: string;
  namespace: string;
  name: string;
  provider: string;
  version: string;
}

/** The modules.json document shape, narrowed tolerantly. */
const ModulesDocument = type({
  "Modules?": "unknown[]",
});

/** A parsed registry-module address: its host plus ns/name/provider triple. */
interface ParsedModuleSource {
  host: string;
  namespace: string;
  name: string;
  provider: string;
}

/**
 * A leading Source segment is treated as a registry HOST when it looks like a
 * hostname — it contains a "." (W#2). This admits the default OpenTofu/Terraform
 * registries AND non-default hosts (HCP private `app.terraform.io`, self-hosted
 * and partner registries) that the old fixed-allowlist silently dropped. A
 * dot-less first segment is part of the bare `<ns>/<name>/<provider>` shorthand,
 * never a host — so `a/b/c/d` is not parsed as host=a (it stays a non-conforming
 * 4-tuple and is excluded). Local (`./`/`../`) and VCS Sources are rejected
 * BEFORE this check, so a leading "." in `./...` never reaches it.
 */
function looksLikeHost(segment: string): boolean {
  return segment.includes(".");
}

/**
 * Parse a modules.json `Source` into a registry-module address, or undefined
 * when it is not a registry module. Accepts:
 *   - bare shorthand `<ns>/<name>/<provider>` (host defaults to
 *     DEFAULT_MODULE_HOST),
 *   - fully-qualified `<host>/<ns>/<name>/<provider>` for ANY hostname-looking
 *     host (W#2 — not just the two default registries),
 *   - either form with a trailing `//<submodule-path>` (stripped).
 * Rejects relative (`./`/`../`/empty) and VCS/`git::` Sources. A VCS Source's
 * `::` marks it non-registry; the legitimate `//<submodule>` separator is the
 * ONLY `//` a registry Source carries, and it is split off before host parsing.
 */
function parseModuleSource(source: string): ParsedModuleSource | undefined {
  if (source === "") return undefined;
  if (source.startsWith("./") || source.startsWith("../")) return undefined;
  if (source.includes("::")) return undefined; // git::/vcs form

  // Strip an optional `//<submodule-path>` suffix (submodule address).
  const submoduleAt = source.indexOf("//");
  const address = submoduleAt === -1 ? source : source.slice(0, submoduleAt);

  const segments = address.split("/");
  if (segments.some((s) => s.length === 0)) return undefined;

  // A leading hostname-looking segment is the optional host prefix; otherwise
  // the whole address must be the bare `<ns>/<name>/<provider>` shorthand.
  let host = DEFAULT_MODULE_HOST;
  let triple = segments;
  if (segments.length === 4 && looksLikeHost(segments[0] as string)) {
    host = segments[0] as string;
    triple = segments.slice(1);
  }
  if (triple.length !== 3) return undefined;

  const [namespace, name, provider] = triple as [string, string, string];
  return { host, namespace, name, provider };
}

/**
 * Read the EXTERNAL registry modules from `.terraform/modules/modules.json`
 * text. Pure function over the `{"Modules":[{Key,Source,Version,Dir}]}` JSON,
 * narrowed tolerantly. A module is external iff its Version is non-empty AND
 * its Source parses as a registry address (see {@link parseModuleSource}:
 * optional host, `<ns>/<name>/<provider>`, optional `//submodule` stripped);
 * local/Version-less/VCS entries are excluded. The Version is used VERBATIM
 * (the EXACT resolved pin). Two submodules of the same module at the same
 * version yield two entries here that collapse to one component downstream via
 * the shared purl.
 *
 * §Whole-file failure is symmetric with the absent-path's loud-fail (07-15,
 * review #3). The module docstring promises "a whole-file failure throws
 * loudly"; this honours it. The empty-string SENTINEL (the collector/coverage
 * pass it on the providers-only path to mean "no modules.json present") stays a
 * tolerant `[]` — an absent file is never a scan failure; the filesystem gate
 * owns absence. For NON-empty text:
 *   - STRUCTURALLY-INVALID — JSON.parse throws, or a present `Modules` key is
 *     not an array — throws a loud scan-failure naming the modules.json path;
 *   - LEGIT-EMPTY — valid JSON `{}`, no `Modules` key, or `Modules: []` — keeps
 *     returning `[]` (zero modules), the genuine dependency-free shape.
 * Individual malformed ENTRIES inside the array are still tolerantly skipped (an
 * array with some bad rows keeps the good rows, never throws).
 */
export function readExternalModules(
  modulesJsonText: string,
): TerraformModule[] {
  // The empty-string sentinel = "no modules.json present" → zero modules.
  if (modulesJsonText === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(modulesJsonText);
  } catch (error) {
    throw new Error(
      "modules.json scan failed: the file is not valid JSON " +
        `(${error instanceof Error ? error.message : String(error)})`,
      { cause: error },
    );
  }
  const doc = ModulesDocument(parsed);
  if (doc instanceof type.errors) {
    // A present `Modules` key that is not an array (the narrow's only failure
    // mode here) is structurally invalid → loud scan failure.
    throw new Error(
      "modules.json scan failed: a present `Modules` key is not an array " +
        `(${doc.summary})`,
    );
  }
  const modules: TerraformModule[] = [];
  for (const raw of doc.Modules ?? []) {
    const entry = recordOf(raw);
    if (entry === undefined) continue;
    const source = stringOf(entry["Source"]);
    const version = stringOf(entry["Version"]);
    if (source === undefined || version === undefined || version === "") {
      continue;
    }
    const parsed = parseModuleSource(source);
    if (parsed === undefined) continue;
    modules.push({ ...parsed, version });
  }
  return modules;
}

/**
 * §The absent-modules.json gate — a pure FILESYSTEM signal, no HCL parsing.
 *
 * Used ONLY to decide, when `.terraform/modules/modules.json` is ABSENT, whether
 * the loud "run tofu init/tofu get" error should fire. It is NOT a module
 * inventory — modules.json remains the authoritative resolved-version source
 * when present (see {@link parseModuleSource}/{@link readExternalModules}, the
 * present-path, intentionally left untouched).
 *
 * §Why a filesystem signal, not an HCL lexer. The gate's REAL question is "did
 * `tofu init` run?". Four consecutive adversarial reviews each found another
 * valid-HCL shape (a nested `source` decoy, `${...}` interpolation with nested
 * quotes, CR-only line endings, a comment between the `module` keyword and its
 * name) that the previous hand-rolled HCL lexer mis-tokenized → silent module
 * drop. Hand-lexing HCL to answer "did init run?" is the wrong approach; the
 * answer is on the filesystem.
 *
 * §Empirical basis. `tofu init`/`tofu get` materializes the gitignored
 * `.terraform/` dir. A PROVIDERS-ONLY dir (no module calls) gets
 * `.terraform/providers/` but NO `.terraform/modules/`. A module-bearing dir
 * (local OR external) gets `.terraform/modules/modules.json` as soon as tofu
 * PROCESSES the module calls — even when the module DOWNLOAD later fails — and
 * it writes modules.json (≥ the root entry) BEFORE the provider phase. So
 * modules.json absence reliably means "no module calls" WHENEVER init has run.
 *
 * §Strengthened signal (07-15, reviews #2/#4 — cheap no-HCL defense-in-depth).
 * Rather than treat ANY `<dir>/.terraform/` directory as proof of init, the gate
 * requires the artifacts a REAL providers-only init leaves and rejects the
 * incoherent shapes:
 *   - return false (collect providers-only) ONLY when `.terraform/providers/`
 *     exists as a DIRECTORY AND `.terraform/modules/` does NOT exist — the exact
 *     github-actions-deployment shape a real providers-only init produces;
 *   - else return true (fail loud):
 *       · no `.terraform/providers/` dir → an empty/fabricated `.terraform/`
 *         that no real init produced → cannot prove providers-only;
 *       · `.terraform/modules/` exists without a modules.json → a stale/partial
 *         module install (tofu writes modules.json the instant it processes
 *         module blocks) → incoherent.
 * `existsSync` + `statSync(...).isDirectory()` is used defensively throughout: a
 * stray `.terraform` FILE has no `providers/` dir under it, so it falls into the
 * first fail-loud branch. This realigns with the module docstring's long-standing
 * observation that the whole `.terraform/` dir is gitignored and absent until
 * init materializes it.
 *
 * §Residual stale-edit limitation (07-15, reviews #1/#4 — documented, delegated).
 * A window remains that this filesystem signal cannot close cheaply: a dir whose
 * providers-only init left `.terraform/providers/` (no `.terraform/modules/`) and
 * whose `.tf` is LATER edited to ADD a module WITHOUT re-init still presents the
 * collect shape, so it collects providers-only and silently omits the new module.
 * This is delegated to `tofu plan`/`tofu validate`/`tofu get` in CI, which
 * hard-error "Module not installed; run tofu init" on exactly this stale state —
 * consistent with the tool's init-before-generate contract. An mtime freshness
 * check (`.tf` newer than `.terraform/`) is deliberately NOT added: it would
 * false-POSITIVE in CI, where `.terraform/` is commonly cache-RESTORED with an
 * older mtime than freshly-checked-out `.tf`, turning every cached CI run into a
 * spurious loud failure. The init-before-generate contract owns this window.
 *
 * This deletes the entire hand-rolled HCL lexer (`hasModuleDeclaration`,
 * `moduleHeaderAt`, `skipNonCode`, `skipHeredoc`, `skipDoubleQuotedString`, the
 * `MODULE_KEYWORD_TOKEN`/`QUOTED_LABEL_TOKEN` regexes, the `NOT_A_HEREDOC`
 * sentinel, and the `readTfTexts` helper that fed them). No source is ever
 * inspected, so the whole decoy/mis-tokenization bug class disappears by
 * construction.
 */
export function absentModulesJsonShouldFail(dir: string): boolean {
  try {
    // §Defense-in-depth signal (07-15, reviews #2/#4): a real providers-only
    // `tofu init` writes `.terraform/providers/` (after the module phase); a
    // module-bearing init writes `.terraform/modules/modules.json` the instant
    // it processes module blocks. So the ONLY shape that legitimately collects
    // providers-only (returns false) is: `.terraform/providers/` exists as a
    // DIRECTORY AND `.terraform/modules/` does NOT exist. Otherwise fail loud:
    //   - no `.terraform/providers/` dir → an empty/fabricated `.terraform/`
    //     that no real init produced → cannot prove providers-only;
    //   - `.terraform/modules/` exists without a modules.json → a stale/partial
    //     module install (tofu writes modules.json the instant it processes
    //     module blocks) → incoherent, fail loud.
    const providersDir = join(dir, ".terraform", "providers");
    if (!existsSync(providersDir) || !statSync(providersDir).isDirectory()) {
      return true; // no real providers artifact → init not proven → fail loud
    }
    const modulesDir = join(dir, ".terraform", "modules");
    if (existsSync(modulesDir)) {
      // A `.terraform/modules/` WITHOUT modules.json (the caller only reaches
      // here when modules.json is absent) is a stale/partial install.
      return true;
    }
    return false; // providers/ present, modules/ absent → providers-only collect
  } catch {
    return true; // unreadable → cannot prove init ran → fail loud
  }
}

/**
 * §The modules.json PRESENCE guard (07-15, review #5). The present-path is taken
 * ONLY when `modules.json` exists AND is a REGULAR FILE. A directory-named (or
 * other non-regular-file) `modules.json` is treated as ABSENT, routing to the
 * filesystem-signal gate ({@link absentModulesJsonShouldFail}) which — seeing
 * `.terraform/modules/` exists with no modules.json file — fails loud with the
 * guided "run tofu init/tofu get" error, instead of a raw uncaught EISDIR from a
 * `readFileSync` on a directory. No silent drop; a guided error. Shared by the
 * collector and the coverage arm so the two cannot diverge.
 */
export function modulesJsonIsPresentFile(modulesJsonPath: string): boolean {
  if (!existsSync(modulesJsonPath)) return false;
  try {
    return statSync(modulesJsonPath).isFile();
  } catch {
    return false; // unreadable → treat as absent → route to the gate
  }
}

interface TerraformComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
}

/** Provider → component: `pkg:terraform/<host>/<ns>/<name>@<v>`, no group. */
function providerComponent(provider: TerraformProvider): TerraformComponent {
  const name = `${provider.namespace}/${provider.name}`;
  return {
    type: "library",
    name,
    version: provider.version,
    purl: `pkg:terraform/${provider.host}/${name}@${provider.version}`,
  };
}

/**
 * Module → component: `pkg:terraform/<host>/<ns>/<name>/<provider>@<v>`, no
 * group. The provider segment is KEPT (3 path segments after the host) so a
 * module is structurally distinguishable from a 2-segment provider purl by
 * COUNT — the host alone cannot distinguish them (OpenTofu rewrites both to
 * registry.opentofu.org). The name is the canonical Terraform module address
 * `<ns>/<name>/<provider>`.
 */
function moduleComponent(module: TerraformModule): TerraformComponent {
  const name = `${module.namespace}/${module.name}/${module.provider}`;
  return {
    type: "library",
    name,
    version: module.version,
    purl: `pkg:terraform/${module.host}/${name}@${module.version}`,
  };
}

/**
 * Build the deterministic, purl-sorted, purl-DEDUPED component list from both
 * inputs. Two submodules of the same module at the same version share a purl
 * (the `//submodule` suffix is stripped before purl construction) and collapse
 * to one row here.
 */
function componentsOf(
  lockText: string,
  modulesJsonText: string,
): TerraformComponent[] {
  const byPurl = new Map<string, TerraformComponent>();
  for (const component of [
    ...parseProviders(lockText).map(providerComponent),
    ...readExternalModules(modulesJsonText).map(moduleComponent),
  ]) {
    // First-wins keying by purl: identical-purl submodules merge to one row.
    if (!byPurl.has(component.purl)) byPurl.set(component.purl, component);
  }
  const components = [...byPurl.values()];
  // compareCodeUnits by purl — the whole emission is a pure function of bytes.
  components.sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0));
  return components;
}

/**
 * Component count for the coverage policy when modules.json IS present:
 * providers from the lock plus external modules from modules.json. Returns
 * undefined only when the lock text is unparseable (no providers AND the text
 * is not a plausible lock) — but parseProviders is tolerant, so an empty lock
 * legitimately counts 0. The absent-modules.json case is NOT a count of 0; it
 * is the loud-fail path the coverage arm routes to separately.
 */
export function terraformComponentCount(
  lockText: string,
  modulesJsonText: string,
): number | undefined {
  return componentsOf(lockText, modulesJsonText).length;
}

/** Options mirror the cdxgen adapter's per-run temp-dir injection point. */
export interface TerraformCollectOptions {
  /** Per-run temp directory; defaults to a fresh mkdtemp under os tmpdir. */
  tempDir?: string;
}

/**
 * Scan a Terraform target by reading `.terraform.lock.hcl` and the sibling
 * `.terraform/modules/modules.json` inside it (no subprocess, no cwd change)
 * and writing a minimal deterministic CycloneDX 1.6 bom.json into the per-run
 * temp dir.
 *
 * Failure modes:
 * - missing .terraform.lock.hcl → loud error naming the path;
 * - either file over MAX_TERRAFORM_LOCK_BYTES → loud size error before parse;
 * - ABSENT (or directory-named, Fix 3) .terraform/modules/modules.json whose
 *   filesystem shape is not the exact providers-only artifact set →
 *   `tofu init`/`tofu get` never ran (or a stale/partial install) → loud "run
 *   tofu init/tofu get first" error (the strengthened filesystem-signal gate,
 *   see {@link absentModulesJsonShouldFail}). When `.terraform/providers/` exists
 *   and `.terraform/modules/` does not (init ran, providers-only — no module
 *   calls → no modules.json), the committed-lock providers collect normally;
 * - a structurally-invalid present modules.json (not JSON, or `Modules` not an
 *   array) → loud scan failure (Fix 2); a legit-empty one (`{}`/`Modules: []`)
 *   collects zero modules;
 * - malformed individual provider blocks / modules.json entries → skipped.
 *
 * Async for interface symmetry with the other collectors.
 */
export async function collectWithTerraform(
  target: Target,
  opts: TerraformCollectOptions = {},
): Promise<CollectorSbomFile> {
  const lockPath = join(target.dir, ".terraform.lock.hcl");
  if (!existsSync(lockPath)) {
    throw new Error(
      `target "${target.identity}" is missing .terraform.lock.hcl: ` +
        `expected ${lockPath}`,
    );
  }
  // Size gate FIRST — before any read or parse (DoS bound).
  assertTerraformLockSize(lockPath);
  const lockText = readFileSync(lockPath, "utf8");

  // The init-has-run gate is a filesystem signal. When modules.json is ABSENT,
  // the existence of the `<dir>/.terraform/` directory decides: it exists → init
  // ran and processed no module calls (providers-only — tofu writes
  // modules.json for ANY module call) → collect providers with an empty modules
  // document; it is absent → init never ran → we cannot prove providers-only →
  // loud fail. No `.tf`/HCL is parsed (see {@link absentModulesJsonShouldFail}).
  const modulesJsonPath = join(
    target.dir,
    ".terraform",
    "modules",
    "modules.json",
  );
  let modulesJsonText = "";
  if (modulesJsonIsPresentFile(modulesJsonPath)) {
    assertTerraformLockSize(modulesJsonPath);
    modulesJsonText = readFileSync(modulesJsonPath, "utf8");
  } else if (absentModulesJsonShouldFail(target.dir)) {
    throw new Error(
      `target "${target.identity}": \`tofu init\`/\`tofu get\` has not run ` +
        "(it materializes the `.terraform/` directory and writes " +
        ".terraform/modules/modules.json for any module call) — " +
        `not found at ${modulesJsonPath}`,
    );
  }

  const components = componentsOf(lockText, modulesJsonText);

  // Minimal deterministic CycloneDX 1.6: no serialNumber, no timestamp.
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components,
  };

  const tempDir = opts.tempDir ?? mkdtempSync(join(tmpdir(), "licenses-"));
  const sbomPath = join(tempDir, "bom.json");
  writeFileSync(sbomPath, `${JSON.stringify(doc, null, 2)}\n`);

  return {
    sbomPath,
    cacheKey: computeCacheKey(
      target,
      TERRAFORM_COLLECTOR_TOOL,
      TERRAFORM_CACHE_ARGS,
      TERRAFORM_MANIFEST_FILES,
    ),
    tool: TERRAFORM_COLLECTOR_TOOL,
  };
}
