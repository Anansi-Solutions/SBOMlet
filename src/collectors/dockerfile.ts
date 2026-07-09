/**
 * Dockerfile discovery + honest-residual FROM-base derivation (07-23).
 *
 * This module answers one narrow question per Dockerfile: which EXTERNAL base
 * image does the SHIPPED (last) stage declare? It is a TIGHT parser, never a
 * full Dockerfile AST: it extracts only what is needed to resolve the final
 * `FROM` ref — global ARG defaults, stage aliases, the optional `--platform`
 * flag, and bash-style `${VAR}` / `$VAR` / `${VAR:-default}` substitution — and
 * is HONEST (loud-skip) on anything ambiguous. It NEVER guesses a base image: an
 * unresolvable ARG, an unresolvable/cyclic alias, or a missing FROM all yield an
 * {kind:"unresolved", reason} residual the caller WARNs and SKIPS.
 *
 * ABSTAIN-ON-HEREDOC CONTRACT (finding #1, escalation — 4th review). After three
 * rounds of tokenizer whack-a-mole (terminator tracking, open-at-EOF nets, a
 * generalized ambiguity closer) a 4th wrong-base regression surfaced: an INDENTED
 * `  EOF` closed a non-dash `<<EOF` heredoc early because the terminator match
 * ignored the dash-strip flag, the body re-parsed, and a body `FROM` shipped as
 * the base. RATIONALE FOR THE ESCALATION: parsing heredoc BODIES at all is the
 * source of every wrong-base round. So we STOP parsing them. The body-consumption
 * + terminator-matching machinery is DELETED. Instead, {@link deriveBaseImage}
 * detects the mere PRESENCE of a heredoc opener — ANY `<<` pair, excluding the
 * here-string `<<<` — anywhere in the file and returns {kind:"unresolved"}. No
 * body, no terminator, no indentation rules are parsed, so a heredoc-body `FROM`
 * can NEVER be returned as the shipped base — BY CONSTRUCTION, not by a net. This
 * deliberately over-abstains on ALL heredoc-bearing Dockerfiles (safe
 * over-abstention: loud-skip → the user pins the base via --image); for a
 * compliance tool, never-wrong-base outranks never-abstain. Here-strings (`<<<`)
 * open no body and are NOT a heredoc presence signal — a `<<<`-only file resolves
 * normally.
 *
 * FROM-INTEGRITY INVARIANT (5th review — the GENERAL structural closer). The
 * tokenizer ({@link toInstructionLines}) hardcodes `\` as the
 * continuation/escape char and drops `# escape=`/`# syntax=` parser directives
 * as ordinary comments. Both can silently MANGLE the FROM structure — most
 * acutely on WINDOWS Dockerfiles, where the standard `# escape=\`` directive
 * makes `\` literal so a path like `C:\dist\` is NOT a continuation, yet our
 * tokenizer joins the next physical line into it (swallowing the FINAL FROM and
 * leaking the earlier BUILD-STAGE FROM as the shipped base). After four rounds of
 * per-variant tokenizer patches, we STOP point-patching: instead of teaching the
 * tokenizer every escape/continuation rule, {@link deriveBaseImage} asserts, AFTER
 * tokenization, that comment/continuation/escape processing did NOT change the
 * FROM structure, and ABSTAINS ({kind:"unresolved"}) if it did. THE BASE IS
 * DERIVED ONLY FOR DOCKERFILES WHOSE FROM STRUCTURE SURVIVES TOKENIZATION INTACT
 * AND WHICH USE NO HEREDOC / NO ESCAPE DIRECTIVE; anything ambiguous abstains to
 * unresolved (loud-skip → the user pins via --image) — never-wrong-base over
 * never-abstain. Three abstain conditions (any one fires):
 *   1. ESCAPE DIRECTIVE PRESENT — a leading `# escape=` parser directive (Docker
 *      only honors it as the first content line) remaps the continuation char
 *      away from `\`. Covers the #1 Windows-backslash critical class.
 *   2. FROM-COUNT INTEGRITY — the FROM count among the RAW physical lines differs
 *      from the post-continuation logical-line count → a FROM was swallowed/merged
 *      by a continuation. A LEGITIMATE `FROM \`-continued ref keeps the counts
 *      equal (1 == 1) and resolves; a normal RUN/COPY `\` not adjacent to a FROM
 *      leaves the FROM count unchanged, so neither over-abstains.
 *   3. ORPHAN AS — a logical line whose first token is `AS` (an `AS <alias>`
 *      detached from its FROM by a mid-continuation comment) is structurally
 *      impossible in a valid Dockerfile → abstain.
 *
 * SCOPE LIMITATION (documented contract): this derives the declared FROM BASE
 * image's OS packages — NOT the packages a Dockerfile's own `RUN apt/apk
 * install` steps add to the final image. Capturing those requires BUILDING the
 * image and scanning the built layers, which is the existing
 * `generate-docker-sbom --image` path. Discovery is the additive,
 * daemon-free "what base do we inherit?" inventory; the build path remains the
 * authority for the fully-assembled image.
 *
 * Discovery (discoverDockerfiles) walks the repo root and matches Dockerfile
 * basenames, EXCLUDING via the SHARED lockfile-discovery exclusion set
 * (shouldDescendDir — node_modules, .git, every dotfile dir incl. .terraform)
 * so vendored/dependency Dockerfiles are auto-excluded by construction, then the
 * CLI `--exclude` globs, then the `[docker] ignore` globs. Output is
 * deterministically sorted by repo-relative forward-slash path. Zero new
 * dependencies: pure node:fs + the shared glob/exclusion helpers.
 *
 * KNOWN LIMITATIONS (5th review, finding #3 — DELIBERATE tradeoffs, documented
 * not changed). The discovery walk does NOT auto-exclude the generic build-output
 * dir names `build`/`out`/`target`/`vendor` (the 07-28 revert was intentional:
 * these names are too generic and re-adding them recreates the prior
 * under-coverage finding where real source Dockerfiles were dropped); it does NOT
 * prune nested INDEPENDENT git repos whose `.git` is a DIRECTORY (only the
 * gitlink-FILE submodule case is pruned); and it SKIPS symlinked Dockerfiles
 * (anti-cycle / no escape from repoRoot). None of these is reachable in the
 * host monorepo. A consumer that vends non-submodule third-party trees
 * under such dirs excludes them explicitly via the `[docker] ignore` policy globs
 * or the CLI `--exclude` flag.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { compareCodeUnits } from "../model/dependencies";
import {
  DOCKERFILE_DOT_DIR_ALLOWLIST,
  globToRegExp,
  isExcluded,
  shouldDescendDir,
} from "../targets/discover";

/**
 * DoS bound: real Dockerfiles are tiny (<64 KiB); 4 MiB is generous headroom.
 * The stat gate fires before any read (mirrors terraform.ts assertTerraformLockSize).
 */
export const MAX_DOCKERFILE_BYTES = 4 * 1024 * 1024;

/**
 * True iff the file at `path` is larger than {@link MAX_DOCKERFILE_BYTES}. Stats
 * only — no read — so the gate fires before any byte of a stray or adversarial
 * file is loaded. Discovery LOUD-SKIPS an oversized name-match (records it
 * unresolved) rather than reading it or aborting the walk.
 */
export function dockerfileExceedsSizeCap(path: string): boolean {
  return statSync(path).size > MAX_DOCKERFILE_BYTES;
}

/** The shipped base resolved from a Dockerfile's final FROM. */
export type DerivedBase =
  | { kind: "image"; ref: string }
  | { kind: "scratch" }
  | { kind: "unresolved"; reason: string };

/** A discovered Dockerfile: its repo-relative identity, abs path, derived base. */
export interface DiscoveredDockerfile {
  /** Repo-relative forward-slash path, e.g. "backend/Dockerfile". */
  identity: string;
  /** Absolute filesystem path. */
  path: string;
  /** The derived shipped base image (image | scratch | unresolved). */
  base: DerivedBase;
}

export interface DiscoverDockerfilesOptions {
  /** Absolute path of this tool's own directory (excluded from the walk). */
  toolDir?: string;
  /** Repeatable --exclude globs, matched against the identity. */
  excludes?: readonly string[];
  /** `[docker] ignore` globs, matched against the identity. */
  dockerIgnore?: readonly string[];
}

export interface DiscoverDockerfilesResult {
  dockerfiles: DiscoveredDockerfile[];
  /**
   * Repo-relative identities of Dockerfiles EXCLUDED by a `[docker] ignore`
   * glob — deterministically sorted. (Files excluded by the shared descent
   * predicate or by `--exclude` are NOT listed here; only the policy-driven
   * ignores, which are the user-meaningful "I deliberately excluded this"
   * signal the summary surfaces.)
   */
  ignored: string[];
}

/**
 * True iff `name` is a Dockerfile basename. Accepts (case-insensitive on the
 * `Dockerfile`/`dockerfile` stem):
 *   - exactly `Dockerfile`
 *   - `<prefix>.Dockerfile`  (e.g. nginx.Dockerfile)
 *   - `Dockerfile.<suffix>`  (e.g. Dockerfile.prod, Dockerfile.go) — ANY suffix
 *   - `<prefix>.dockerfile`  (e.g. build.dockerfile)
 * A file merely CONTAINING "dockerfile" (e.g. notADockerfile.txt) is NOT matched.
 *
 * NAME-PATTERN ONLY (findings #4/#5): there is no extension blocklist. A blocklist
 * silently DROPS real variants (`Dockerfile.go`/`.py`/`.rs`/`.sh`/`.bak`) — an
 * under-coverage bug — while inconsistently admitting others. Instead, EVERY
 * name-pattern match is READ: a genuine Dockerfile resolves its base; a stray
 * non-Dockerfile (the tool's own `dockerfile.ts`, a consumer's `dockerfile.md`)
 * has no FROM and resolves to {kind:"unresolved"} — a LOUD-SKIP (honest residual),
 * never a silent drop and never a wrong base. The tool's OWN directory is kept out
 * of the walk by the toolDir descent prune (shouldDescendDir), not by a name rule.
 */
export function isDockerfileName(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "dockerfile") return true;
  if (lower.endsWith(".dockerfile")) return true;
  if (lower.startsWith("dockerfile.")) return true;
  return false;
}

/**
 * Walk `repoRoot` and return every non-excluded Dockerfile with its derived
 * base, deterministically sorted by repo-relative forward-slash identity.
 *
 * Exclusion order (each step strictly narrows): the SHARED descent predicate
 * (shouldDescendDir — node_modules/.git/dotfile dirs incl. .terraform/the tool
 * dir) prunes whole subtrees during the walk; then the CLI `--exclude` globs;
 * then the `[docker] ignore` globs. A Dockerfile under any excluded path is
 * never read and never derived.
 */
export function discoverDockerfiles(
  repoRoot: string,
  opts?: DiscoverDockerfilesOptions,
): DiscoverDockerfilesResult {
  const toolDir = opts?.toolDir;
  const excludeMatchers = (opts?.excludes ?? []).map(globToRegExp);
  const ignoreMatchers = (opts?.dockerIgnore ?? []).map(globToRegExp);

  const identityOf = (path: string): string =>
    relative(repoRoot, path).split(sep).join("/");

  const found: DiscoveredDockerfile[] = [];
  const ignored: string[] = [];

  const walk = (dir: string): void => {
    // Symlinks report isDirectory()/isFile() === false on Dirent entries, so
    // they are never followed/read — no cycle traversal, no escape from repoRoot.
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const sub = join(dir, entry.name);
      if (entry.isDirectory()) {
        // Dockerfile lane: pass the dot-dir allowlist so .docker/.devcontainer
        // (conventional Dockerfile homes) are descended while .git/.terraform and
        // every other dot-dir stay pruned (finding #4).
        if (
          shouldDescendDir(
            sub,
            entry.name,
            toolDir,
            DOCKERFILE_DOT_DIR_ALLOWLIST,
          )
        ) {
          walk(sub);
        }
        continue;
      }
      if (!entry.isFile() || !isDockerfileName(entry.name)) continue;
      const identity = identityOf(sub);
      // --exclude prunes silently (a generic walk filter); a [docker] ignore is
      // a deliberate user exclusion the summary surfaces by name.
      if (isExcluded(identity, excludeMatchers)) continue;
      if (isExcluded(identity, ignoreMatchers)) {
        ignored.push(identity);
        continue;
      }
      // Size-gate BEFORE any read (DoS bound). An oversized name-match is almost
      // never a real Dockerfile (real ones are <64 KiB) — so rather than ABORT
      // the whole walk on one stray or adversarial file, LOUD-SKIP it as
      // unresolved: surfaced in the summary, never read, never a wrong base. A
      // genuinely large base is pinned via --image.
      if (dockerfileExceedsSizeCap(sub)) {
        found.push({
          identity,
          path: sub,
          base: {
            kind: "unresolved",
            reason:
              `exceeds the ${MAX_DOCKERFILE_BYTES}-byte size cap — not parsed; ` +
              `pin the base via --image if this is a real Dockerfile`,
          },
        });
        continue;
      }
      const text = readFileSync(sub, "utf8");
      found.push({ identity, path: sub, base: deriveBaseImage(text) });
    }
  };

  walk(repoRoot);
  found.sort((a, b) => compareCodeUnits(a.identity, b.identity));
  ignored.sort(compareCodeUnits);
  return { dockerfiles: found, ignored };
}

// ---------------------------------------------------------------------------
// FROM-base derivation — the honest-residual parser.
// ---------------------------------------------------------------------------

/** A parsed FROM stage: its raw ref token plus an optional lower-cased alias. */
interface Stage {
  /** The ref token AFTER `--platform` strip but BEFORE ARG substitution. */
  rawRef: string;
  /** The `AS <alias>` name, lower-cased per Docker semantics, or undefined. */
  alias?: string;
}

/**
 * Bounded alias-follow depth. Each hop binds to a strictly-EARLIER stage (see
 * {@link aliasDefinedBefore}), so the followed index strictly decreases and a
 * cycle is impossible by construction — this cap is pure belt-and-suspenders
 * insurance against any future change to the resolution rule.
 */
const MAX_ALIAS_DEPTH = 1024;

/**
 * Bound on the global-ARG fixpoint iteration (resolveArgFixpoint). Real
 * Dockerfiles chain a handful of ARGs at most; this cap is cycle insurance so a
 * self-referential default (`ARG A=${B}` / `ARG B=${A}`) terminates with a
 * residual `$` rather than looping forever.
 */
const MAX_ARG_FIXPOINT_PASSES = 64;

/**
 * Conservative image-reference shape: an optional registry host[:port] segment,
 * a `/`-separated path of lowercase name components (each may contain digits,
 * `.`, `_`, `-`), an optional `:tag`, and an optional `@sha256:<digest>`. No
 * spaces, no leading dash, no shell metacharacters, no residual `${...}`. This
 * is a TIGHT validator: anything it does not recognize is treated as
 * unresolved (honest-residual) rather than emitted as a possibly-malformed base.
 *
 * Components are lowercase per Docker's repository-name rule (registry hosts and
 * tags allow uppercase, so the host and tag segments are more permissive than
 * the path). The pattern deliberately rejects a leading `-` (a flag token, never
 * a ref) and any character outside the documented ref grammar.
 */
// A name component is lowercase per Docker's repository-name rule; a host
// segment (letters/digits/dots/hyphens + optional :port) is more permissive,
// and so is the tag. A leading host[:port]/ is an optional first path segment.
const IMAGE_REF_NAME_COMPONENT = "[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*";
const IMAGE_REF_HOST = "[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]+)?";
const IMAGE_REF_PATH = `(?:${IMAGE_REF_HOST}/)?${IMAGE_REF_NAME_COMPONENT}(?:/${IMAGE_REF_NAME_COMPONENT})*`;
const IMAGE_REF_TAG = "(?::[A-Za-z0-9_][A-Za-z0-9._-]*)?";
const IMAGE_REF_DIGEST = "(?:@sha256:[0-9a-f]{64})?";
const IMAGE_REF_RE = new RegExp(
  `^${IMAGE_REF_PATH}${IMAGE_REF_TAG}${IMAGE_REF_DIGEST}$`,
);

/**
 * True iff `ref` is a clean, fully-resolved, valid image reference safe to emit
 * as `{kind:"image"}`. Rejects (→ caller emits unresolved): any residual `$`
 * (unresolved interpolation — #2); empty/whitespace-only (#3, #8); a leading
 * `-` (a flag token, never a ref — #7); or any string failing the conservative
 * {@link IMAGE_REF_RE} shape (spaces, shell metacharacters, malformed). NEVER
 * accepts a guess.
 */
function isValidImageRef(ref: string): boolean {
  if (ref.includes("$")) return false; // residual ${...}/$VAR (#2)
  if (ref.trim() === "") return false; // empty/whitespace (#3, #8)
  if (ref.startsWith("-")) return false; // flag token, never a ref (#7)
  return IMAGE_REF_RE.test(ref);
}

/**
 * Strip comments and join backslash-continued lines into logical instruction
 * lines. NO heredoc body parsing happens here (finding #1 escalation): heredoc
 * bodies are NOT recognized, consumed, or excluded — instead {@link
 * deriveBaseImage} abstains entirely whenever a heredoc opener is present (see
 * {@link containsHeredocOpener}), so this tokenizer never needs to distinguish a
 * body line from an instruction.
 *
 * Comment handling matches Docker: only a line whose first non-whitespace char
 * is `#` is a comment (dropped — this also drops `# syntax=` and parser
 * directives). A `#` anywhere else is an argument and is left intact, so a
 * `<<EOF` or trailing `\` that follows a mid-line `#` survives to be seen by the
 * heredoc and continuation logic instead of being silently cut (see {@link
 * stripComment}). FROM/ARG drop their own trailing comment at value extraction.
 *
 * Continuation: a logical line ends when a physical line does NOT end with a
 * trailing `\`; a trailing `\` joins the next physical line with a single space.
 * Comment stripping happens per PHYSICAL line BEFORE continuation joining so a
 * `\` inside a comment does not continue.
 */
export function toInstructionLines(text: string): string[] {
  const out: string[] = [];
  let buffer: string | undefined;
  for (const physical of text.split(/\r\n|\r|\n/)) {
    const stripped = stripComment(physical);
    // A blank-after-strip line cannot continue and is not itself an instruction;
    // but if a continuation is in progress it terminates it.
    const continues = stripped.endsWith("\\");
    const content = continues ? stripped.slice(0, -1) : stripped;
    if (buffer === undefined) {
      if (content.trim() === "" && !continues) continue;
      buffer = content;
    } else {
      buffer += ` ${content.trim()}`;
    }
    if (continues) continue;
    const line = buffer.trim();
    buffer = undefined;
    if (line === "") continue;
    out.push(line);
  }
  if (buffer !== undefined && buffer.trim() !== "") out.push(buffer.trim());
  return out;
}

/**
 * The heredoc opener signal (finding #1 escalation). Fires on ANY `<<` pair
 * EXCEPT the here-string `<<<` — the `(?<!<)` / `(?!<)` guards require the `<<`
 * to be a clean pair, not part of a longer `<` run. No delimiter shape is
 * parsed, so every opener form is caught with nothing to slip through: `<<EOF`,
 * `<<-EOF`, `<<"EOF"`, `<<'EOF'`, the backslash-quoted `<<\EOF`, and the
 * fd-prefixed / operator-adjacent / no-space forms `2<<EOF`, `|<<EOF`,
 * `RUN<<EOF`. An earlier version matched only a quoted-or-bareword delimiter and
 * so missed `<<\EOF`, whose body `FROM` could then leak as the base; firing on
 * the bare `<<` closes that whole evasion class by construction.
 *
 * This is the SOLE remaining heredoc machinery: a presence detector, not a body
 * parser. The broad over-detection is SAFE because a match means "abstain",
 * never "parse the body" — there is no body to mis-parse. The here-string `<<<`
 * opens no body and is therefore not a heredoc signal.
 */
const HEREDOC_OPENER_RE = /(?<!<)<<(?!<)/;

/**
 * True iff the Dockerfile text contains ANY heredoc opener token (excluding the
 * here-string `<<<`). When true, {@link deriveBaseImage} abstains — a
 * heredoc-body `FROM` can never be returned as the shipped base because no body
 * is ever parsed. Scanned over the comment-stripped instruction lines so a
 * `<<EOF` inside a `# comment` does not trip the abstain (comments are dropped
 * by {@link toInstructionLines}); a `<<EOF` in a heredoc body — if one were
 * somehow present — would also be on a line scanned here, and tripping the
 * abstain on it is the desired outcome anyway.
 */
export function containsHeredocOpener(lines: readonly string[]): boolean {
  return lines.some((line) => HEREDOC_OPENER_RE.test(line));
}

/**
 * True iff the Dockerfile opens with a parser directive of the form
 * `# escape=<char>` (the FROM-integrity invariant's first abstain condition,
 * 5th review). Docker only honors a parser directive when it appears BEFORE any
 * builder instruction or ordinary comment — concretely, as the FIRST line of the
 * file (a leading UTF-8 BOM and surrounding whitespace tolerated; Docker also
 * allows a directive block before the first comment, but the standard, and the
 * only ambiguous, form is the leading line). A `# escape=` appearing AFTER any
 * instruction or comment is an ordinary comment and is NOT a directive.
 *
 * RATIONALE: the `escape` directive RE-DEFINES the line-continuation/escape
 * character (the standard Windows value is `\`, since Windows paths use
 * backslashes). Our tokenizer hardcodes `\` as the continuation char, so under a
 * `# escape=\`` (or `# escape=` + backtick) directive a trailing `\` in a path
 * (`C:\dist\`) is treated as a continuation it is NOT, swallowing the next
 * physical line — which can be the FINAL `FROM`, leaking a build-stage base.
 * Rather than re-implement Docker's escape-char remapping (more tokenizer
 * whack-a-mole), we ABSTAIN whenever an escape directive is present. This
 * forecloses the entire Windows-backslash wrong-base class by construction.
 */
export function escapeDirectivePresent(text: string): boolean {
  // The directive must be the first content line. Strip a leading BOM, then find
  // the first non-blank physical line; Docker stops honoring directives at the
  // first non-directive line, so only that first line can be the escape
  // directive.
  const withoutBom = text.replace(/^\u{FEFF}/u, "");
  for (const physical of withoutBom.split(/\r\n|\r|\n/)) {
    if (physical.trim() === "") continue;
    return /^\s*#\s*escape\s*=/i.test(physical);
  }
  return false;
}

/**
 * Count the `FROM` instructions among the RAW PHYSICAL lines: each physical line
 * is comment-stripped and trimmed, and counts iff its first whitespace-delimited
 * token is `FROM` (case-insensitive). This is the FROM count BEFORE any
 * continuation joining — the baseline the FROM-integrity invariant compares the
 * post-join logical count against (5th review, second abstain condition).
 *
 * A divergence between this and the logical FROM count means continuation
 * processing swallowed or merged a FROM (a dangling `\` before a FROM joins it
 * into the prior line; or a FROM line's own trailing `\` legitimately continues
 * its ref — which keeps the count EQUAL, so it does not over-abstain).
 */
function physicalFromCount(text: string): number {
  let count = 0;
  for (const physical of text.split(/\r\n|\r|\n/)) {
    const stripped = stripComment(physical).trim();
    if (stripped === "") continue;
    if (firstToken(stripped).toUpperCase() === "FROM") count++;
  }
  return count;
}

/** The first whitespace-delimited token of a line (or "" if none). */
function firstToken(line: string): string {
  const match = /^(\S+)/.exec(line);
  return match ? (match[1] as string) : "";
}

/**
 * Strip a FULL-LINE `#` comment — a line whose first non-whitespace char is `#`
 * (this also drops `# syntax=`/`# escape=` parser directives) — returning "".
 * Any other line is returned verbatim.
 *
 * Docker treats `#` as a comment ONLY at the start of a line; a `#` anywhere
 * else is an argument (Dockerfile reference). So we deliberately do NOT cut a
 * mid-line ` #...`. Cutting it used to delete whatever followed on the same
 * physical line — a heredoc opener (`<<EOF`) or a trailing continuation `\` —
 * which let a heredoc body or a continuation-hidden line be mis-parsed as a
 * stage and leak a WRONG base. The value-bearing instructions that legitimately
 * tolerate a trailing comment (FROM, ARG) drop it via {@link stripTrailingComment}
 * at value extraction, never here.
 */
function stripComment(line: string): string {
  return /^\s*#/.test(line) ? "" : line;
}

/**
 * Cut a trailing ` #...` comment (whitespace then `#`) from a single FROM/ARG
 * line at the point its value is extracted. Safe there because the line is one
 * fully-joined instruction with a known grammar; NEVER used on the general
 * tokenizer path, where a mid-line ` #` can be followed by a structural `<<` or
 * a continuation `\` (see {@link stripComment}).
 */
function stripTrailingComment(line: string): string {
  const idx = line.search(/\s#/);
  return idx === -1 ? line : line.slice(0, idx);
}

/**
 * True iff any physical FROM line carries BOTH a mid-line ` #` and a trailing
 * continuation `\`. That shape is a malformed FROM by construction: Docker reads
 * the `#` as an argument and the `\` as a line continuation, so the joined
 * instruction has extra arguments after the image and Docker rejects it. It is
 * also a wrong-base trap for us — the `#` precedes the joined-in continuation, so
 * {@link stripTrailingComment} would discard whatever the next line contributed
 * (e.g. an `AS <alias>`), dropping a stage alias and letting a later
 * `FROM <alias>` resolve the alias name as a literal image. {@link deriveBaseImage}
 * abstains on it. A legit `FROM x \` (no `#`), `FROM x # comment` (no trailing
 * `\`), or `FROM x AS y # comment` (no trailing `\`) never matches, so valid
 * Dockerfiles are not over-abstained.
 */
function fromLineHasCommentedContinuation(text: string): boolean {
  for (const physical of text.split(/\r\n|\r|\n/)) {
    if (firstToken(physical.trim()).toUpperCase() !== "FROM") continue;
    if (physical.endsWith("\\") && /\s#/.test(physical)) return true;
  }
  return false;
}

/**
 * Resolve a Dockerfile's SHIPPED base from its full text. The shipped base is
 * the LAST `FROM`'s ref, resolved: `--platform=...` stripped, `${ARG}`/`$ARG`/
 * `${ARG:-default}` substituted from global ARG defaults, and stage aliases
 * followed (cycle-guarded) to a literal ref or `scratch`. Returns:
 *   - {kind:"image", ref}      — a literal external image ref (tag or @digest);
 *   - {kind:"scratch"}         — the final stage is FROM scratch (no OS pkgs);
 *   - {kind:"unresolved", reason} — no FROM, an unresolvable ARG, or a
 *     cyclic/unresolvable alias. NEVER a guess.
 */
export function deriveBaseImage(text: string): DerivedBase {
  const lines = toInstructionLines(text);
  // ABSTAIN-ON-HEREDOC (finding #1 escalation): if the file bears ANY heredoc
  // opener token, abstain BY CONSTRUCTION. No heredoc body is ever parsed, so a
  // body `FROM` can never be mistaken for a stage and returned as the shipped
  // base. This is deliberate safe over-abstention — loud-skip → the user pins
  // the base via --image. Here-strings (`<<<`) open no body and do NOT trip this.
  if (containsHeredocOpener(lines)) {
    return {
      kind: "unresolved",
      reason: "heredoc present — base not derived; pin the base via --image",
    };
  }
  // FROM-INTEGRITY INVARIANT (5th review, the GENERAL structural closer). The
  // tokenizer hardcodes `\` as the continuation/escape char and drops parser
  // directives as comments; both can silently mangle the FROM structure. Rather
  // than point-patch each variant, assert the structure SURVIVED tokenization
  // intact and ABSTAIN otherwise. Four conditions, any of which → unresolved:
  //
  //   1. Escape directive present — a leading `# escape=` parser directive
  //      remaps the continuation char away from `\`, which our tokenizer cannot
  //      honor. Abstain (covers the #1 Windows-backslash critical class).
  if (escapeDirectivePresent(text)) {
    return {
      kind: "unresolved",
      reason: "escape directive present — base not derived; pin via --image",
    };
  }
  //   2. FROM-count integrity — a FROM swallowed/merged by continuation makes
  //      the physical FROM count exceed the logical (post-join) count. A
  //      legitimate `FROM \`-continued ref keeps the counts EQUAL (1 == 1), so
  //      this does not over-abstain on real continuation.
  const logicalFromCount = lines.filter(
    (line) => instructionOf(line) === "FROM",
  ).length;
  if (physicalFromCount(text) !== logicalFromCount) {
    return {
      kind: "unresolved",
      reason:
        "continuation altered FROM structure — base uncertain; pin via --image",
    };
  }
  //   3. Orphan AS — an `AS <alias>` detached from its FROM by a
  //      mid-continuation comment lands on its own logical line. A logical line
  //      whose first token is `AS` is structurally impossible in a valid
  //      Dockerfile, so it signals a mangled FROM → abstain.
  if (lines.some((line) => instructionOf(line) === "AS")) {
    return {
      kind: "unresolved",
      reason:
        "orphan AS (alias detached from its FROM) — base uncertain; pin via --image",
    };
  }
  //   4. Commented continuation on a FROM line — a physical FROM line carrying
  //      BOTH a mid-line ` #` and a trailing `\` is a malformed FROM by
  //      construction (Docker joins the continuation, leaving extra args after
  //      the image). The `#` precedes the joined-in content, so a swallowed
  //      `AS <alias>` is dropped at value extraction and the orphan-AS guard
  //      (condition 3, which needs the `AS` on its OWN logical line) is bypassed;
  //      a later `FROM <alias>` would then ship the alias name as a literal
  //      image. Abstain rather than guess.
  if (fromLineHasCommentedContinuation(text)) {
    return {
      kind: "unresolved",
      reason:
        "comment before a continuation on a FROM line — base uncertain; pin via --image",
    };
  }
  const globalArgs = new Map<string, string>();
  const stages: Stage[] = [];
  // Alias lookup is built incrementally; a FROM can only reference an alias
  // declared by an EARLIER stage (Docker semantics), so we resolve at the end
  // over the full stage list.

  let sawFrom = false;
  for (const line of lines) {
    const instr = instructionOf(line);
    if (instr === "ARG" && !sawFrom) {
      // Global ARG (before the first FROM). A later same-name ARG default wins
      // (last-write), matching Docker's global-ARG scope.
      const parsed = parseArgDefault(line);
      if (parsed !== undefined) globalArgs.set(parsed.name, parsed.value);
      continue;
    }
    if (instr === "FROM") {
      sawFrom = true;
      const stage = parseFrom(line);
      if (stage !== undefined) stages.push(stage);
    }
  }

  const last = stages[stages.length - 1];
  if (last === undefined) {
    return { kind: "unresolved", reason: "no FROM instruction found" };
  }

  // Resolve global ARG defaults to a FIXPOINT so a default that references
  // another ARG (`ARG BASE=node:${NODE_VERSION}`) is fully expanded before any
  // FROM uses it (#2). Cycles/unresolvable refs leave a residual `$`, which the
  // resolveStage validation rejects as unresolved — never emitted as a guess.
  const resolvedArgs = resolveArgFixpoint(globalArgs);

  return resolveStage(stages, stages.length - 1, resolvedArgs);
}

/**
 * Iterate global ARG default substitution to a fixpoint so transitive
 * references resolve (`ARG NODE=22` + `ARG BASE=node:${NODE}` → BASE=node:22).
 * A depth cap bounds the iteration; a value that cannot be reduced further
 * (unresolvable VAR, or a cycle that keeps a residual `$`) is left AS-IS with
 * its residual `$`, which the downstream image-ref validation rejects — never a
 * guess, never an infinite loop.
 */
function resolveArgFixpoint(
  globalArgs: Map<string, string>,
): Map<string, string> {
  const resolved = new Map(globalArgs);
  // Each pass substitutes every value against the current map; stop when a pass
  // changes nothing (fixpoint) or the cap is hit (cycle insurance).
  for (let pass = 0; pass < MAX_ARG_FIXPOINT_PASSES; pass++) {
    let changed = false;
    for (const [name, value] of resolved) {
      if (!value.includes("$")) continue;
      const next = substituteArgs(value, resolved);
      // undefined = an unresolvable VAR with no default; keep the value as-is so
      // its residual `$` survives to the validation gate (treated unresolved).
      if (next !== undefined && next !== value) {
        resolved.set(name, next);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return resolved;
}

/**
 * The nearest-PRECEDING stage that defines `alias` (Docker semantics: a stage
 * ref binds to the most recent earlier `AS <alias>`). Returns undefined when no
 * earlier stage defines it — then the token is a literal external image ref.
 */
function aliasDefinedBefore(
  stages: Stage[],
  alias: string,
  before: number,
): number | undefined {
  for (let i = before - 1; i >= 0; i--) {
    if (stages[i]?.alias === alias) return i;
  }
  return undefined;
}

/** The leading instruction keyword, upper-cased (e.g. "FROM", "ARG"). */
function instructionOf(line: string): string {
  const match = /^(\S+)/.exec(line);
  return match ? (match[1] as string).toUpperCase() : "";
}

/** Parse `ARG <name>[=<default>]`; returns the name + default, or undefined. */
function parseArgDefault(
  line: string,
): { name: string; value: string } | undefined {
  // `ARG NAME=value` (global ARG with a default). A defaultless `ARG NAME` has
  // no value to resolve a FROM with, so it is intentionally not recorded.
  const match = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$/i.exec(line);
  if (!match) return undefined;
  return {
    name: match[1] as string,
    value: stripTrailingComment(match[2] as string).trim(),
  };
}

/**
 * Parse one `FROM` line into a Stage: strip an optional leading
 * `--platform=...` flag, take the ref token, and record an optional `AS <alias>`
 * (alias lower-cased). Returns undefined for a malformed FROM with no ref.
 */
function parseFrom(line: string): Stage | undefined {
  // Tokens after the FROM keyword (a trailing ` #...` comment dropped first).
  let rest = stripTrailingComment(line).replace(/^FROM\s+/i, "");
  // Strip a leading --platform=<value> flag (the only FROM flag we expect).
  rest = rest.replace(/^--platform=\S+\s+/i, "");
  const tokens = rest.split(/\s+/).filter((t) => t.length > 0);
  const rawRef = tokens[0];
  if (rawRef === undefined) return undefined;
  // `AS <alias>` (case-insensitive keyword); alias recorded lower-cased.
  let alias: string | undefined;
  if (tokens.length >= 3 && tokens[1]?.toUpperCase() === "AS") {
    alias = (tokens[2] as string).toLowerCase();
  }
  return alias !== undefined ? { rawRef, alias } : { rawRef };
}

/**
 * Parse a FROM ref as a bare non-negative integer stage index, or undefined if
 * it is not one (finding #1, 07-31). Docker treats a `FROM <N>` whose ref is a
 * non-negative integer as a reference to the build stage at that 0-indexed
 * position — the SAME index space as `COPY --from=0` — so it must be recognized
 * here and resolved as a stage hop, never emitted as a literal image named "0".
 *
 * STRICT shape: only `^[0-9]+$` (no sign, no decimal, no leading `+`, no
 * whitespace) qualifies. A tagged/registry ref like `0:latest` or `0/app` or
 * `registry:5000/x` is NOT a bare integer and falls through to the literal-image
 * path. Returns the parsed index, or undefined for any non-bare-integer token.
 */
function parseNumericStageIndex(ref: string): number | undefined {
  if (!/^[0-9]+$/.test(ref)) return undefined;
  const value = Number.parseInt(ref, 10);
  // Number.isSafeInteger guards a pathological all-digit ref from overflowing;
  // a non-negative match cannot be < 0, so range is bounded below by the regex.
  return Number.isSafeInteger(value) ? value : undefined;
}

/**
 * Resolve stage `index` to a DerivedBase, following alias references through the
 * stage list with a cycle guard. ARG substitution is applied to the ref BEFORE
 * the alias check, so `FROM ${BASE}` where BASE=an-alias still follows the alias.
 *
 * An alias ref binds to the nearest PRECEDING `AS <alias>` (Docker forbids
 * forward references), so each hop strictly decreases the stage index and the
 * loop always terminates; MAX_ALIAS_DEPTH is a defensive cap only (a real
 * Dockerfile cannot exceed it, and a cycle cannot form under preceding-only
 * binding).
 */
function resolveStage(
  stages: Stage[],
  index: number,
  globalArgs: Map<string, string>,
): DerivedBase {
  let current = index;
  let depth = 0;
  for (;;) {
    if (++depth > MAX_ALIAS_DEPTH) {
      return { kind: "unresolved", reason: "stage alias chain too deep" };
    }
    const stage = stages[current] as Stage;
    const substituted = substituteArgs(stage.rawRef, globalArgs);
    if (substituted === undefined) {
      return {
        kind: "unresolved",
        reason: `FROM ref "${stage.rawRef}" uses an ARG with no resolvable default`,
      };
    }
    if (substituted.toLowerCase() === "scratch") return { kind: "scratch" };
    const aliasTarget = aliasDefinedBefore(
      stages,
      substituted.toLowerCase(),
      current,
    );
    if (aliasTarget !== undefined) {
      current = aliasTarget;
      continue;
    }
    // NUMERIC STAGE-INDEX FROM (finding #1, 07-31). Docker resolves `FROM <N>`
    // whose ref is a bare non-negative integer to the build STAGE at that
    // 0-indexed position (the same index space as `COPY --from=0`), exactly
    // like a named `AS` alias — NOT to a literal image named "0". A bare integer
    // passes IMAGE_REF_RE, so without this branch resolveStage would emit
    // {kind:"image", ref:"0"} and the true shipped base (stage N's base) would
    // never be followed. Checked BEFORE the literal-image branch. The numeric
    // ref must come AFTER the named-alias check so a stage literally named `0`
    // (`FROM x AS 0`) is still reachable by its alias.
    const numericIndex = parseNumericStageIndex(substituted);
    if (numericIndex !== undefined) {
      // A valid earlier-stage index is 0 <= N < current (stages are 0-indexed
      // in FROM-appearance order; only strictly-earlier stages are referenceable,
      // matching Docker's forward-reference prohibition). Hopping to a strictly
      // earlier index keeps the index decreasing, so the loop still terminates.
      if (numericIndex < current) {
        current = numericIndex;
        continue;
      }
      // Out of range (>= current, or no earlier stage at all, e.g. single-stage
      // `FROM 0`) → abstain. NEVER emit the bare integer as {kind:"image"}.
      return {
        kind: "unresolved",
        reason: `numeric FROM ref ${numericIndex} is not a valid stage index`,
      };
    }
    // Not an alias of any earlier stage and not a numeric stage index → it must
    // be a literal external image ref. Emit `image` ONLY when the fully-resolved
    // ref is clean and valid; a residual `$`, empty/whitespace, leading-dash, or
    // malformed shape is an honest-residual unresolved, never a guessed/garbage
    // base (#2,#3,#7,#8).
    if (!isValidImageRef(substituted)) {
      return {
        kind: "unresolved",
        reason:
          `FROM ref "${stage.rawRef}" did not resolve to a clean image ` +
          `reference (got ${JSON.stringify(substituted)})`,
      };
    }
    return { kind: "image", ref: substituted };
  }
}

/**
 * Substitute `${VAR}`, `$VAR`, and `${VAR:-default}` from globalArgs. Returns
 * the substituted string, or undefined when ANY referenced VAR has no resolvable
 * value (no global ARG default AND no `:-default`) — the honest-residual signal
 * the caller turns into {kind:"unresolved"}. A ref with no `$` passes through
 * verbatim (the common literal-image case).
 */
export function substituteArgs(
  ref: string,
  globalArgs: Map<string, string>,
): string | undefined {
  if (!ref.includes("$")) return ref;
  let unresolved = false;
  // ${VAR:-default} | ${VAR} | $VAR  (VAR is a Docker-legal identifier).
  const out = ref.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (
      _match,
      braced: string | undefined,
      fallback: string | undefined,
      bare: string | undefined,
    ) => {
      const name = braced ?? (bare as string);
      const fromArg = globalArgs.get(name);
      if (fromArg !== undefined) return fromArg;
      if (fallback !== undefined) return fallback;
      unresolved = true;
      return "";
    },
  );
  return unresolved ? undefined : out;
}
