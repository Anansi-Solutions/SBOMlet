import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

import {
  deriveBaseImage,
  discoverDockerfiles,
  isDockerfileName,
  MAX_DOCKERFILE_BYTES,
  type DerivedBase,
} from "../src/collectors/dockerfile";

// Self-contained temp trees only — no reference to any host-project path.
const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "licenses-dockerfile-"));
  tempRoots.push(root);
  return root;
}

function writeFile(root: string, rel: string, content: string): void {
  const full = join(root, ...rel.split("/"));
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// deriveBaseImage — the honest-residual FROM parser (adversarial target).
// ---------------------------------------------------------------------------

describe("deriveBaseImage", () => {
  test("single-stage FROM node:22-slim → image node:22-slim", () => {
    expect(deriveBaseImage("FROM node:22-slim\n")).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("multi-stage: final distroless wins, the build stage is NOT scanned", () => {
    const text = [
      "FROM golang:1.22 AS build",
      "RUN go build -o /app",
      "FROM gcr.io/distroless/base",
      "COPY --from=build /app /app",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "gcr.io/distroless/base",
    });
  });

  test("final FROM is a stage ALIAS → resolves through the chain to the literal", () => {
    const text = [
      "FROM node:22-slim AS base",
      "RUN echo hi",
      "FROM base AS final",
      "COPY . .",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("alias shadowing resolves via nearest-PRECEDING binding, never loops/guesses", () => {
    // `FROM a AS b / FROM b AS a / FROM a` is NOT a cycle under Docker
    // forward-ref semantics — each alias hop binds to a strictly-earlier stage:
    // index2 "a" → stage1 alias "a" → ref "b" → stage0 alias "b" → ref "a" →
    // no earlier alias "a" → literal image "a". Honest, terminating, no guess.
    const text = ["FROM a AS b", "FROM b AS a", "FROM a"].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "a" });
  });

  test("a stage referencing its OWN alias name is a literal (first stage, no earlier binding)", () => {
    // `FROM base AS base`: resolving stage0 sees ref "base"; no EARLIER stage
    // defines alias "base", so it is a literal external image, never a self-loop.
    expect(deriveBaseImage("FROM base AS base\n")).toEqual({
      kind: "image",
      ref: "base",
    });
  });

  test("a deep alias chain resolves to the literal seed, terminating", () => {
    const lines = ["FROM seed AS s0"];
    for (let i = 1; i < 50; i++) {
      lines.push(`FROM s${i - 1} AS s${i}`);
    }
    lines.push("FROM s49");
    expect(deriveBaseImage(lines.join("\n"))).toEqual({
      kind: "image",
      ref: "seed",
    });
  });

  // -------------------------------------------------------------------------
  // Numeric stage-index FROM (finding #1, 07-31). Docker resolves `FROM <N>`
  // whose ref is a non-negative integer to the build STAGE at that 0-indexed
  // position (the same index space as `COPY --from=0`), exactly like a named
  // alias. The shipped base is THAT stage's resolved base — never the literal
  // integer. An out-of-range / no-earlier-stage index abstains (unresolved).
  // -------------------------------------------------------------------------

  test("FROM 0 hops to stage index 0 and ships ITS base (golang:1.22)", () => {
    const text = [
      "FROM golang:1.22 AS builder",
      "RUN go build -o /app",
      "FROM 0",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "golang:1.22",
    });
  });

  test("FROM 1 hops to stage index 1 (gcr.io/distroless/nodejs), never the integer", () => {
    const text = [
      "FROM node:22 AS deps",
      "FROM gcr.io/distroless/nodejs",
      "FROM 1",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "gcr.io/distroless/nodejs",
    });
  });

  test("FROM 0 hopping to a stage whose own base is scratch → scratch", () => {
    const text = ["FROM scratch AS empty", "FROM 0"].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "scratch" });
  });

  test("chained FROM 0 where stage 0 is FROM golang:1.22 AS b resolves to golang:1.22", () => {
    // Stage0 = golang:1.22 AS b; stage1 = `FROM b` (named alias to stage0);
    // stage2 = `FROM 0` (numeric index to stage0). Both hops land on stage0's
    // literal base.
    const text = ["FROM golang:1.22 AS b", "FROM b", "FROM 0"].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "golang:1.22",
    });
  });

  test("out-of-range FROM 5 with 3 stages → unresolved (never the integer)", () => {
    const text = ["FROM golang:1.22 AS a", "FROM node:22 AS b", "FROM 5"].join(
      "\n",
    );
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain("5");
    }
  });

  test("single-stage FROM 0 (no earlier stage) → unresolved, never image '0'", () => {
    const result = deriveBaseImage("FROM 0\n");
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain("0");
    }
  });

  test("a stage literally `FROM 0 AS zero` then `FROM zero` resolves via the named alias", () => {
    // Stage0 = `FROM 0 AS zero`: resolving stage0 sees numeric ref "0" with NO
    // earlier stage → unresolved by the numeric rule, BUT the final `FROM zero`
    // is a NAMED alias to stage0, and stage0's own base (literal integer 0 with
    // no earlier stage) is unresolved. So the whole derivation abstains — never
    // a wrong base, never the integer.
    const text = ["FROM 0 AS zero", "FROM zero"].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
  });

  test("FROM ${IDX} substituting to a valid numeric index hops to that stage", () => {
    // ARG-substituted numeric refs follow the same numeric-index rule (the
    // substitution happens BEFORE the numeric check, mirroring the alias path).
    const text = [
      "ARG IDX=0",
      "FROM golang:1.22 AS builder",
      "FROM ${IDX}",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "golang:1.22",
    });
  });

  test("ARG BASE=node:22 + FROM ${BASE} → node:22", () => {
    const text = ["ARG BASE=node:22", "FROM ${BASE}"].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "node:22" });
  });

  test("FROM ${BASE} with no resolvable default → unresolved", () => {
    const text = "FROM ${BASE}\n";
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
  });

  test("FROM ${BASE:-python:3.12} bash-default → python:3.12", () => {
    const text = "FROM ${BASE:-python:3.12}\n";
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "python:3.12",
    });
  });

  test("$BASE (no braces) resolves via the ARG default", () => {
    const text = ["ARG BASE=alpine:3.20", "FROM $BASE"].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "alpine:3.20",
    });
  });

  test("FROM --platform=linux/amd64 alpine:3.20 → alpine:3.20 (flag stripped)", () => {
    const text = "FROM --platform=linux/amd64 alpine:3.20\n";
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "alpine:3.20",
    });
  });

  test("FROM repo@sha256:... → the digest ref is kept verbatim", () => {
    const digest = "a".repeat(64);
    const ref = `myrepo/app@sha256:${digest}`;
    expect(deriveBaseImage(`FROM ${ref}\n`)).toEqual({ kind: "image", ref });
  });

  test("case-insensitive from/as", () => {
    const text = ["from node:22 as Build", "from build"].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "node:22" });
  });

  test("backslash-continued FROM is joined before parse", () => {
    const text = "FROM \\\n  node:22-slim\n";
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("full-line and trailing comments are stripped", () => {
    const text = [
      "# syntax=docker/dockerfile:1",
      "# a comment",
      "FROM node:22-slim # trailing comment",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("an ARG default with a trailing comment resolves the value, not the comment", () => {
    // The trailing comment is dropped where the ARG value is extracted, so
    // FROM ${BASE} sees node:22, not "node:22 # pin" (which would be unresolved).
    const text = ["ARG BASE=node:22 # pin", "FROM ${BASE}"].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "node:22" });
  });

  test("FROM scratch → scratch (legitimately no OS packages, not an error)", () => {
    expect(deriveBaseImage("FROM scratch\n")).toEqual({ kind: "scratch" });
  });

  test("scratch as an intermediate stage, real final image → the image", () => {
    const text = ["FROM scratch AS empty", "FROM alpine:3.20"].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "alpine:3.20",
    });
  });

  test("empty text → unresolved (no FROM at all)", () => {
    expect(deriveBaseImage("").kind).toBe("unresolved");
  });

  test("text with no FROM instruction → unresolved", () => {
    expect(deriveBaseImage("RUN echo hi\nWORKDIR /app\n").kind).toBe(
      "unresolved",
    );
  });

  test("global ARG declared AFTER the FROM it would feed is NOT used", () => {
    // Only ARGs BEFORE the FROM are global; an ARG after FROM is a build-stage
    // ARG and must not resolve a preceding FROM. Here there is no usable
    // default → unresolved (never a wrong guess).
    const text = ["FROM ${BASE}", "ARG BASE=node:22"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });
});

// ---------------------------------------------------------------------------
// Finding #1 (ESCALATION, 4th review) — abstain-on-heredoc. The heredoc-body
// parsing machinery (terminator tracking, body consumption, open-at-EOF /
// ambiguous plumbing) is DELETED. ANY Dockerfile bearing a heredoc OPENER token
// (`<<WORD`, excluding the here-string `<<<`) now resolves to
// {kind:"unresolved"} — a heredoc-body FROM can NEVER be returned as the shipped
// base, by CONSTRUCTION: no body is parsed at all. This deliberately
// over-abstains on every heredoc-bearing Dockerfile (loud-skip → user pins via
// --image) because never-wrong-base outranks never-abstain for a compliance
// tool, and it ends the 4-round tokenizer whack-a-mole.
// ---------------------------------------------------------------------------

const HEREDOC_ABSTAIN_REASON = "heredoc present";

describe("deriveBaseImage — abstain on ANY heredoc opener (finding #1, escalation)", () => {
  test("the indented-terminator repro: an INDENTED `  EOF` no longer closes a `<<EOF` early — abstain, NOT python:3.12", () => {
    // 4th heredoc round: `heredocCloses` compared `physical.trim() === word`,
    // ignoring the dashStripped flag, so an indented `  EOF` wrongly closed a
    // non-dash `<<EOF` heredoc early; the body re-parsed and the body
    // `FROM python:3.12` became the shipped base (WRONG; true base node:22). With
    // abstain-on-heredoc there is no body parse at all → unresolved.
    const text = [
      "FROM node:22",
      "RUN <<EOF",
      "echo configuring",
      "  EOF",
      "FROM python:3.12",
      "echo done",
      "EOF",
    ].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain(HEREDOC_ABSTAIN_REASON);
    }
  });

  test("a heredoc after the ONLY FROM → unresolved (heredoc present; base not derived)", () => {
    const text = ["FROM node:22-slim", "RUN <<EOT", "echo hi", "EOT"].join(
      "\n",
    );
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain(HEREDOC_ABSTAIN_REASON);
    }
  });

  test("`<<-EOF` (dash) opener → unresolved", () => {
    const text = ["FROM alpine:3.20", "RUN <<-EOF", "  echo hi", "  EOF"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test('`<<"EOF"` (quoted) opener → unresolved', () => {
    const text = ["FROM python:3.12-slim", 'RUN <<"EOF"', "x", "EOF"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("`2<<EOF` (fd-prefixed) opener → unresolved", () => {
    const text = ["FROM alpine:3.19", "RUN cat 2<<EOF", "x", "EOF"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("`|<<EOF` (operator-adjacent) opener → unresolved", () => {
    const text = ["FROM alpine:3.19", "RUN true |<<EOF", "x", "EOF"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("`RUN<<EOF` (no space) opener → unresolved", () => {
    const text = ["FROM alpine:3.19", "RUN<<EOF", "x", "EOF"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a body `FROM` in a multi-stage heredoc Dockerfile can NEVER be the base (whole file abstains)", () => {
    const text = [
      "FROM golang:1.22 AS build",
      "RUN go build -o /app",
      "FROM gcr.io/distroless/base",
      "RUN <<EOT",
      "FROM golang:1.22",
      "echo this is a script, not a stage",
      "EOT",
      "COPY --from=build /app /app",
    ].join("\n");
    // Even though distroless is the true ship base, the heredoc presence forces
    // abstain — no body FROM golang can ever leak. Safe over-abstention.
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("two heredocs on one RUN → unresolved", () => {
    const text = ["FROM node:22-slim", "RUN <<A <<B", "x", "A", "y", "B"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("`<<\\EOF` (backslash-quoted delimiter) opener → unresolved (the regex-evasion case)", () => {
    // The backslash-quoted delimiter is a valid heredoc form the earlier
    // quoted-or-bareword regex did NOT match, so its body `FROM` could leak as
    // the shipped base. Firing on the bare `<<` abstains by construction. The
    // body `FROM evil` is a decoy: it must never become the base.
    const text = [
      "FROM node:22-slim",
      "RUN <<\\EOF",
      "FROM evil:latest",
      "EOF",
    ].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("`<<'EOF'` (single-quoted delimiter) opener → unresolved", () => {
    const text = ["FROM python:3.12-slim", "RUN <<'EOF'", "x", "EOF"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a mid-line `#` before a `<<EOF` does NOT hide the heredoc (Docker: mid-line # is an argument) → unresolved", () => {
    // The comment-stripper must not cut at a mid-line ` #`, or it would delete
    // the following `<<EOF` and let the heredoc body's `FROM body-leak` leak as
    // the shipped base. With the `<<` preserved, the heredoc abstain fires.
    const text = [
      "FROM golang:1.22 AS build",
      'RUN sh -c "echo #x" <<EOF',
      "FROM body-leak:6.6.6",
      "make all",
      "EOF",
    ].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });
});

// ---------------------------------------------------------------------------
// Finding #1 (escalation) — here-strings and NON-heredoc files resolve EXACTLY
// as before. `<<<` opens no body, so it is NOT a heredoc presence signal; a file
// with no heredoc token at all resolves its real base unchanged.
// ---------------------------------------------------------------------------

describe("deriveBaseImage — here-strings and heredoc-free files resolve normally", () => {
  test("bash here-string `<<<` ALONE is NOT a heredoc — the real base still resolves", () => {
    // `RUN cat <<< "$x"` is a here-STRING (no body), so it must NOT trip the
    // abstain — the later real `FROM alpine:3.19` is the ship base.
    const text = [
      "FROM golang:1.22 AS build",
      'RUN cat <<< "$(cat c.json)"',
      "FROM alpine:3.19",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "alpine:3.19",
    });
  });

  test("a single-stage heredoc-free Dockerfile resolves unchanged", () => {
    expect(deriveBaseImage("FROM node:22-slim\n")).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("a multi-stage heredoc-free Dockerfile still picks the final base", () => {
    const text = [
      "FROM golang:1.22 AS build",
      "RUN go build -o /app",
      "FROM gcr.io/distroless/base",
      "COPY --from=build /app /app",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "gcr.io/distroless/base",
    });
  });
});

// ---------------------------------------------------------------------------
// Findings #2,#3,#7,#8 — conservative image-ref validation: resolveStage emits
// {kind:"image"} ONLY for a clean, fully-resolved, valid image reference; any
// residual `$`, empty/whitespace, leading-dash, or malformed shape → unresolved.
// ---------------------------------------------------------------------------

describe("deriveBaseImage — conservative image-ref validation", () => {
  test("#2: residual ${...} after substitution → unresolved, never an image", () => {
    // BASE resolves but its value still embeds an unresolved ${...} → the final
    // ref still contains `$` → must NOT be emitted as an image.
    const text = ["ARG BASE=node:${UNSET}", "FROM ${BASE}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("#2: transitive ARG defaults resolve to a fixpoint (node:${NODE} → node:22)", () => {
    const text = [
      "ARG NODE_VERSION=22",
      "ARG BASE=node:${NODE_VERSION}",
      "FROM ${BASE}",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "node:22" });
  });

  test("#2: a cyclic ARG default does not loop and yields unresolved", () => {
    const text = ["ARG A=${B}", "ARG B=${A}", "FROM ${A}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("#3/#8: ARG BASE= (empty) + FROM ${BASE} → unresolved (no empty ref)", () => {
    const text = ["ARG BASE=", "FROM ${BASE}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("#8: FROM ${BASE:-} (empty bash default) → unresolved", () => {
    expect(deriveBaseImage("FROM ${BASE:-}\n").kind).toBe("unresolved");
  });

  test("#7: FROM --quiet (a leading-dash token) → unresolved, never an image", () => {
    // A dash-prefixed token is never a valid image ref; after the --platform
    // strip it must not be emitted as a base.
    expect(deriveBaseImage("FROM --quiet\n").kind).toBe("unresolved");
  });

  test("#7: FROM -o foo (dash token) → unresolved", () => {
    expect(deriveBaseImage("FROM -o foo\n").kind).toBe("unresolved");
  });

  test("#7: ARG B=--quiet + FROM ${B} (substitutes to a dash token) → unresolved", () => {
    const text = ["ARG B=--quiet", "FROM ${B}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a ref with an embedded space → unresolved (malformed shape)", () => {
    const text = ["ARG B=node 22", "FROM ${B}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a ref with a shell metacharacter → unresolved", () => {
    const text = ["ARG B=node:22;rm", "FROM ${B}"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a clean registry/host:port/path:tag@digest ref still validates as image", () => {
    const digest = "a".repeat(64);
    const ref = `registry.example.com:5000/team/app:1.2.3@sha256:${digest}`;
    expect(deriveBaseImage(`FROM ${ref}\n`)).toEqual({ kind: "image", ref });
  });

  test("docker.io library shorthand (alpine) still validates as image", () => {
    expect(deriveBaseImage("FROM alpine\n")).toEqual({
      kind: "image",
      ref: "alpine",
    });
  });
});

// ---------------------------------------------------------------------------
// 5th review — the GENERAL FROM-integrity invariant (structural closer). After
// tokenization, deriveBaseImage asserts that comment/continuation/escape
// processing did NOT change the FROM structure, and ABSTAINS otherwise. Three
// abstain conditions: (1) an `# escape=` parser directive is present (Windows
// backslash class + the #1 critical), (2) the FROM count differs between the raw
// physical lines and the post-continuation logical lines (a FROM was
// swallowed/merged), (3) an orphan `AS <alias>` logical line (an AS detached
// from its FROM by a mid-continuation comment). A FROM mangled by ANY
// comment/continuation/escape processing must abstain — never emit a build-stage
// base. Never-wrong-base over never-abstain.
// ---------------------------------------------------------------------------

const ESCAPE_ABSTAIN_REASON = "escape directive present";
const FROM_INTEGRITY_ABSTAIN_REASON = "continuation altered FROM structure";

describe("deriveBaseImage — escape-directive abstain (finding #1 CRITICAL)", () => {
  test("the servercore/nanoserver repro: `# escape=\\` makes `\\` literal, the path `C:\\dist\\` swallows the final FROM — abstain, NOT servercore (the build stage)", () => {
    // With `# escape=\`` the backslash is literal, so `RUN copy out C:\dist\`
    // is NOT a continuation under Docker — but a naive tokenizer joins the next
    // physical line (the final `FROM …nanoserver…`) into the RUN, leaving only
    // the earlier BUILD-STAGE `FROM …servercore… AS build` as the last FROM →
    // WRONG base servercore. The escape-directive abstain forecloses this whole
    // Windows-backslash class.
    const text = [
      "# escape=\\",
      "FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS build",
      "RUN copy out C:\\dist\\",
      "FROM mcr.microsoft.com/windows/nanoserver:ltsc2022",
    ].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain(ESCAPE_ABSTAIN_REASON);
    }
  });

  test("any `# escape=\\` Dockerfile abstains generally (even a clean single-stage one)", () => {
    const text = ["# escape=\\", "FROM node:22-slim"].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain(ESCAPE_ABSTAIN_REASON);
    }
  });

  test("`# escape=`` (backtick escape directive) also abstains", () => {
    const text = ["# escape=`", "FROM alpine:3.20"].join("\n");
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("the escape directive is only honored as the FIRST line; a later `# escape=` is an ordinary comment and does NOT abstain", () => {
    // Docker only honors a parser directive before any builder instruction /
    // comment. A `# escape=` appearing after a FROM is an ordinary comment, so
    // the base still resolves.
    const text = ["FROM node:22-slim", "# escape=\\", "RUN echo hi"].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });
});

describe("deriveBaseImage — FROM-count-integrity abstain (#1 swallow + dangling-\\)", () => {
  test("a dangling `\\` on the line immediately before the final `FROM x` swallows it (default escape) → unresolved (physical 1 FROM vs logical 0)", () => {
    const text = ["RUN echo build \\", "FROM alpine:3.20"].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain(FROM_INTEGRITY_ABSTAIN_REASON);
    }
  });

  test("a dangling `\\` swallowing the ONLY FROM in a multi-stage file abstains (build-stage base never leaks)", () => {
    const text = [
      "FROM golang:1.22 AS build",
      "RUN go build \\",
      "FROM gcr.io/distroless/base",
    ].join("\n");
    // Physical FROM count = 2, logical = 1 (the distroless FROM was swallowed by
    // the dangling RUN \). Counts differ → abstain, never ship golang (build).
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("a LEGITIMATE FROM-line continuation (`FROM \\` then the ref) is NOT over-abstained (physical 1 == logical 1)", () => {
    const text = "FROM \\\n  node:22\n";
    expect(deriveBaseImage(text)).toEqual({ kind: "image", ref: "node:22" });
  });

  test("a normal multi-line RUN continuation NOT adjacent to any FROM keeps the FROM count unchanged → resolves the real base", () => {
    const text = [
      "FROM debian:bookworm-slim",
      "RUN apt-get install x \\",
      "  y \\",
      "  z",
      "COPY . .",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "debian:bookworm-slim",
    });
  });

  test("a mid-line `#` before a trailing `\\` does NOT hide the continuation that swallows a FROM → unresolved (physical 2 vs logical 1)", () => {
    // The mid-line ` #` must not be cut, or the trailing `\` is deleted and
    // `FROM evil` stands alone as a fabricated stage. With the `\` preserved the
    // line continues into the RUN, so physical FROM count (2) != logical (1).
    const text = ["FROM real:1.0", 'RUN echo "x #" \\', "FROM evil:1.0"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });
});

describe("deriveBaseImage — orphan-AS abstain (finding #2: comment-in-continuation alias detach)", () => {
  test("a comment between `FROM node:22 \\` and `AS build` detaches the AS onto its own logical line → unresolved (NOT image{build})", () => {
    // `FROM node:22 \` continues, but the comment line is stripped to empty and
    // terminates the continuation, so `AS build` becomes its own logical line
    // (orphan AS) and the later `FROM build` would resolve `build` as a literal
    // image. The orphan-AS guard abstains instead.
    const text = [
      "FROM node:22 \\",
      "# a comment that breaks the continuation",
      "AS build",
      "FROM build",
    ].join("\n");
    const result = deriveBaseImage(text);
    expect(result.kind).toBe("unresolved");
    if (result.kind === "unresolved") {
      expect(result.reason).toContain("AS");
    }
  });
});

// ---------------------------------------------------------------------------
// Commented-continuation-on-a-FROM-line abstain. A FROM physical line bearing
// BOTH a mid-line ` #` and a trailing `\` is a malformed FROM (Docker rejects
// it once joined), and the `#` hides whatever the continuation pulled up — e.g.
// a bare `AS <alias>` that the comment trim then drops, bypassing the orphan-AS
// guard and letting a later `FROM <alias>` ship the alias name as an image.
// Abstain. Valid FROM-comment / FROM-continuation shapes lacking this exact
// combination must still resolve.
// ---------------------------------------------------------------------------

describe("deriveBaseImage — commented continuation on a FROM line abstains", () => {
  test("`FROM x # c \\` absorbing a following bare `AS` → unresolved, never the guessed alias-as-image", () => {
    const text = ["FROM realbase:1 # x \\", "  AS poison", "FROM poison"].join(
      "\n",
    );
    expect(deriveBaseImage(text).kind).toBe("unresolved");
  });

  test("non-regression: a legit `FROM \\` continuation (no `#`) still resolves", () => {
    expect(deriveBaseImage("FROM \\\n  node:22\n")).toEqual({
      kind: "image",
      ref: "node:22",
    });
  });

  test("non-regression: a single-line `FROM x # comment` (no trailing `\\`) still resolves", () => {
    expect(deriveBaseImage("FROM node:22-slim # base\n")).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("non-regression: `FROM x AS y # comment` (AS before the `#`, no trailing `\\`) still resolves the alias chain", () => {
    const text = [
      "FROM node:22-slim AS base # the build base",
      "FROM base",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });
});

// ---------------------------------------------------------------------------
// 5th review — NON-regression: clean single/multi-stage, normal RUN
// continuations, legit FROM-continuation, scratch/digest/ARG cases all resolve
// EXACTLY as before. The FROM-integrity invariant must not over-abstain.
// ---------------------------------------------------------------------------

describe("deriveBaseImage — FROM-integrity invariant does NOT over-abstain (non-regression)", () => {
  test("clean single-stage FROM node:22-slim still resolves", () => {
    expect(deriveBaseImage("FROM node:22-slim\n")).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
  });

  test("clean multi-stage (golang build → distroless) still resolves to distroless", () => {
    const text = [
      "FROM golang:1.22 AS build",
      "RUN go build -o /app",
      "FROM gcr.io/distroless/base",
      "COPY --from=build /app /app",
    ].join("\n");
    expect(deriveBaseImage(text)).toEqual({
      kind: "image",
      ref: "gcr.io/distroless/base",
    });
  });

  test("scratch, digest, and ARG-default cases are unchanged", () => {
    expect(deriveBaseImage("FROM scratch\n")).toEqual({ kind: "scratch" });
    const digest = "a".repeat(64);
    const ref = `myrepo/app@sha256:${digest}`;
    expect(deriveBaseImage(`FROM ${ref}\n`)).toEqual({ kind: "image", ref });
    const argText = ["ARG BASE=node:22", "FROM ${BASE}"].join("\n");
    expect(deriveBaseImage(argText)).toEqual({ kind: "image", ref: "node:22" });
  });
});

// ---------------------------------------------------------------------------
// discoverDockerfiles — walk + reuse the exact lockfile exclusion set.
// ---------------------------------------------------------------------------

describe("discoverDockerfiles", () => {
  test("finds real Dockerfiles at any depth, excludes node_modules/.terraform", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "frontend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/nginx.Dockerfile", "FROM nginx:stable-alpine\n");
    // Vendored / dependency Dockerfiles that must NEVER be found:
    writeFile(
      root,
      "infrastructure/.terraform/modules/x/Dockerfile",
      "FROM ubuntu\n",
    );
    writeFile(
      root,
      "frontend/node_modules/swagger2openapi/Dockerfile",
      "FROM node\n",
    );

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "docker/nginx.Dockerfile",
      "frontend/Dockerfile",
    ]);
  });

  test("matches *.Dockerfile, Dockerfile.*, *.dockerfile basenames (case-insensitive stem)", () => {
    const root = makeTempRoot();
    writeFile(root, "a/Dockerfile", "FROM x\n");
    writeFile(root, "b/app.Dockerfile", "FROM x\n");
    writeFile(root, "c/Dockerfile.prod", "FROM x\n");
    writeFile(root, "d/build.dockerfile", "FROM x\n");
    writeFile(root, "e/notADockerfile.txt", "nope\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "a/Dockerfile",
      "b/app.Dockerfile",
      "c/Dockerfile.prod",
      "d/build.dockerfile",
    ]);
  });

  test("isDockerfileName matches name patterns WITHOUT an extension blocklist (#4)", () => {
    // The blocklist is REMOVED: real variants Dockerfile.go/.py/.rs/.sh/.bak
    // must NOT be silently dropped. Name-pattern matching is the only rule; a
    // matched non-Dockerfile is READ and loud-skips as {unresolved} — never a
    // silent drop. So Dockerfile.<anything> matches.
    expect(isDockerfileName("Dockerfile.go")).toBe(true);
    expect(isDockerfileName("Dockerfile.py")).toBe(true);
    expect(isDockerfileName("Dockerfile.rs")).toBe(true);
    expect(isDockerfileName("Dockerfile.sh")).toBe(true);
    expect(isDockerfileName("Dockerfile.bak")).toBe(true);
    // The tool's own dockerfile.ts now matches by name too — it is excluded
    // from discovery via toolDir, not via a name blocklist.
    expect(isDockerfileName("dockerfile.ts")).toBe(true);
    expect(isDockerfileName("dockerfile.test.ts")).toBe(true);
    // Real build variants still match.
    expect(isDockerfileName("Dockerfile.prod")).toBe(true);
    expect(isDockerfileName("Dockerfile.dev")).toBe(true);
    expect(isDockerfileName("Dockerfile")).toBe(true);
    expect(isDockerfileName("app.Dockerfile")).toBe(true);
    expect(isDockerfileName("build.dockerfile")).toBe(true);
    // A file merely CONTAINING dockerfile is still NOT matched.
    expect(isDockerfileName("notADockerfile.txt")).toBe(false);
    expect(isDockerfileName("readme.md")).toBe(false);
  });

  test("#4: Dockerfile.go containing a real FROM IS discovered + resolved (not dropped)", () => {
    const root = makeTempRoot();
    // This test asserts the NAME-pattern (.go suffix is not blocklisted),
    // independent of the parent dir.
    writeFile(root, "ci/Dockerfile.go", "FROM golang:1.22-alpine\n");
    const result = discoverDockerfiles(root);
    const byId = new Map(result.dockerfiles.map((d) => [d.identity, d.base]));
    expect(byId.get("ci/Dockerfile.go")).toEqual({
      kind: "image",
      ref: "golang:1.22-alpine",
    });
  });

  test("#5: a matched non-Dockerfile with no FROM loud-skips as unresolved", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // A stray matched name with no FROM is READ and resolves to unresolved —
    // never silently dropped, never a wrong base.
    writeFile(root, "tools/dockerfile.ts", "export const x = 1;\n");
    const result = discoverDockerfiles(root);
    const byId = new Map(result.dockerfiles.map((d) => [d.identity, d.base]));
    expect(byId.get("tools/dockerfile.ts")?.kind).toBe("unresolved");
    expect(byId.get("app/Dockerfile")).toEqual({
      kind: "image",
      ref: "alpine:3.20",
    });
  });

  test("an oversized name-match is LOUD-SKIPPED as unresolved — never read, never aborts the walk (DoS)", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // A stray file whose NAME matches but whose size is over the cap. The
    // leading `FROM evil` is a decoy: if the gate ever read and parsed it, the
    // base would resolve to evil — so unresolved here proves it was never read.
    const oversized = "FROM evil:latest\n" + "#".repeat(MAX_DOCKERFILE_BYTES);
    writeFile(root, "huge/Dockerfile", oversized);

    const result = discoverDockerfiles(root);
    const byId = new Map(result.dockerfiles.map((d) => [d.identity, d.base]));
    // The walk completed (no abort) and the real Dockerfile still resolved.
    expect(byId.get("app/Dockerfile")).toEqual({
      kind: "image",
      ref: "alpine:3.20",
    });
    // The oversized one is surfaced (not silently dropped) but never read.
    const huge = byId.get("huge/Dockerfile");
    expect(huge?.kind).toBe("unresolved");
    if (huge?.kind === "unresolved") {
      expect(huge.reason).toContain("size cap");
    }
  });

  test("#6: the tool's OWN directory is excluded when toolDir is set", () => {
    const root = makeTempRoot();
    writeFile(root, "app/Dockerfile", "FROM alpine:3.20\n");
    // Simulate the tool living under src/collectors with its own dockerfile.ts.
    writeFile(
      root,
      "tool/src/collectors/dockerfile.ts",
      "export const x = 1;\n",
    );
    writeFile(root, "tool/src/collectors/dockerfile.test.ts", "test();\n");

    const toolDir = join(root, "tool");
    const result = discoverDockerfiles(root, { toolDir });
    // The tool dir subtree is pruned; only the consumer Dockerfile remains.
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "app/Dockerfile",
    ]);
  });

  test("#2 (07-28 revert): only dist/ is pruned; build/out/target/vendor Dockerfiles ARE discovered", () => {
    // build/out/target/vendor are generic source names (07-26 over-broad prune
    // reverted); only the documented dist/ build-output dir stays excluded.
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "dist/Dockerfile", "FROM node:22\n");
    writeFile(root, "build/Dockerfile", "FROM node:22\n");
    writeFile(root, "out/Dockerfile", "FROM node:22\n");
    writeFile(root, "target/Dockerfile", "FROM node:22\n");
    writeFile(root, "vendor/Dockerfile", "FROM node:22\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "build/Dockerfile",
      "out/Dockerfile",
      "target/Dockerfile",
      "vendor/Dockerfile",
    ]);
  });

  test("#3: a Dockerfile under Node_Modules/ (mixed case) is excluded on Windows", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "Node_Modules/dep/Dockerfile", "FROM node\n");
    writeFile(root, "NODE_MODULES/dep/Dockerfile", "FROM node\n");
    writeFile(root, "Dist/Dockerfile", "FROM node\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("#4: Dockerfiles under .docker/ and .devcontainer/ ARE discovered", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, ".docker/Dockerfile", "FROM alpine:3.20\n");
    writeFile(root, ".devcontainer/Dockerfile", "FROM ubuntu:24.04\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      ".devcontainer/Dockerfile",
      ".docker/Dockerfile",
      "backend/Dockerfile",
    ]);
  });

  test("#4: Dockerfiles under .git/.terraform/other dot-dirs are STILL excluded", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, ".git/Dockerfile", "FROM scratch\n");
    writeFile(root, ".terraform/modules/x/Dockerfile", "FROM ubuntu\n");
    writeFile(root, ".cache/Dockerfile", "FROM busybox\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("finding #2: a git-SUBMODULE root (.git is a FILE / gitlink) is NOT descended", () => {
    // A submodule root is an ordinary-named directory whose `.git` is a FILE
    // (`gitdir: …` gitlink), not a directory — so EXCLUDED_DIR_NAMES (which names
    // `.git`) never fires and the walk would descend into vendored third-party
    // code, attributing its base image to OUR distribution. The fix detects the
    // gitlink FILE and skips descent. A SIBLING normal dir with a `.git`
    // DIRECTORY is unaffected (only the gitlink-FILE case prunes).
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    // Submodule root: `.git` is a FILE (gitlink) — its Dockerfile must NOT be found.
    writeFile(root, "vendored/.git", "gitdir: ../.git/modules/vendored\n");
    writeFile(root, "vendored/Dockerfile", "FROM ubuntu:22.04\n");
    writeFile(root, "vendored/nested/Dockerfile", "FROM ubuntu:20.04\n");
    // A normal dir that merely CONTAINS a `.git` DIRECTORY entry (pruned by the
    // dot-dir / EXCLUDED_DIR_NAMES rule) but is itself a real source dir: its own
    // Dockerfile IS still discovered.
    writeFile(root, "normal/.git/HEAD", "ref: refs/heads/main\n");
    writeFile(root, "normal/Dockerfile", "FROM alpine:3.20\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
      "normal/Dockerfile",
    ]);
  });

  test("[docker] ignore glob excludes a dev Dockerfile entirely", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "docker/dev/Dockerfile", "FROM node:22\n");

    const result = discoverDockerfiles(root, {
      dockerIgnore: ["docker/dev/**"],
    });
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("--exclude glob is honored", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "legacy/Dockerfile", "FROM node:18\n");

    const result = discoverDockerfiles(root, { excludes: ["legacy/**"] });
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "backend/Dockerfile",
    ]);
  });

  test("output is deterministically sorted by repo-relative forward-slash path", () => {
    const root = makeTempRoot();
    writeFile(root, "z/Dockerfile", "FROM x\n");
    writeFile(root, "a/Dockerfile", "FROM x\n");
    writeFile(root, "m/sub/Dockerfile", "FROM x\n");

    const result = discoverDockerfiles(root);
    expect(result.dockerfiles.map((d) => d.identity)).toEqual([
      "a/Dockerfile",
      "m/sub/Dockerfile",
      "z/Dockerfile",
    ]);
  });

  test("each discovered Dockerfile carries its derived base image", () => {
    const root = makeTempRoot();
    writeFile(root, "backend/Dockerfile", "FROM node:22-slim\n");
    writeFile(root, "empty/Dockerfile", "FROM scratch\n");

    const result = discoverDockerfiles(root);
    const byId = new Map<string, DerivedBase>(
      result.dockerfiles.map((d) => [d.identity, d.base]),
    );
    expect(byId.get("backend/Dockerfile")).toEqual({
      kind: "image",
      ref: "node:22-slim",
    });
    expect(byId.get("empty/Dockerfile")).toEqual({ kind: "scratch" });
  });
});
