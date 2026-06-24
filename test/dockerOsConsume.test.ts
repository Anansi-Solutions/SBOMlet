/**
 * Unit tests for the `--from-sbom` ingestion path (consumeDockerOsSbom): the
 * CI-attestation consumer that reads a PRE-MADE syft/CycloneDX SBOM off disk
 * instead of spawning docker+syft. This is the state-of-the-art posture — the
 * build CI produces the image's SBOM (attested by registry digest), and this
 * tool CONSUMES it. No docker daemon, no network.
 *
 * The fixture (syft-premade-mixed.json) is a trimmed real-shape syft CycloneDX
 * image SBOM carrying deb + apk + golang(noise) components, license id/name/
 * expression shapes, and a `metadata.component` with the image's @sha256 digest.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  consumeDockerOsSbom,
  digestFromSbom,
} from "../src/collectors/dockerOs";
import { runGenerateDockerSbom } from "../src/pipeline/dockerSbom";

const FIXTURE = join(import.meta.dir, "fixtures", "syft-premade-mixed.json");
const DIGEST =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";

describe("digestFromSbom (metadata.component digest extraction)", () => {
  test("pulls the @sha256 digest from metadata.component.version", () => {
    const sbom = {
      metadata: {
        component: { type: "container", name: "app", version: DIGEST },
      },
    };
    expect(digestFromSbom(sbom)).toBe(DIGEST);
  });

  test("falls back to the @sha256: suffix embedded in metadata.component.name", () => {
    const sbom = {
      metadata: {
        component: {
          type: "container",
          name: `registry.example.com/app@${DIGEST}`,
        },
      },
    };
    expect(digestFromSbom(sbom)).toBe(DIGEST);
  });

  test("returns undefined when no digest is recoverable", () => {
    expect(digestFromSbom({})).toBeUndefined();
    expect(
      digestFromSbom({ metadata: { component: { name: "app:latest" } } }),
    ).toBeUndefined();
  });
});

describe("consumeDockerOsSbom (--from-sbom ingest)", () => {
  test("filters to deb+apk, PRESERVES licenses, extracts the digest, drops noise", async () => {
    const { doc, sbomPaths } = await consumeDockerOsSbom([FIXTURE]);
    expect(sbomPaths).toEqual([FIXTURE]);

    const parsed = JSON.parse(doc) as {
      bomFormat: string;
      specVersion: string;
      components: Array<{ name: string; purl: string; licenses?: unknown }>;
      dockerImages: Array<{ image: string; digest: string }>;
    };

    expect(parsed.bomFormat).toBe("CycloneDX");
    expect(parsed.specVersion).toBe("1.6");

    // Only deb + apk survive — the golang dep and operating-system are dropped.
    const purls = parsed.components.map((c) => c.purl);
    expect(purls.some((p) => p.startsWith("pkg:deb/"))).toBe(true);
    expect(purls.some((p) => p.startsWith("pkg:apk/"))).toBe(true);
    expect(purls.some((p) => p.startsWith("pkg:golang/"))).toBe(false);

    // Licenses are PRESERVED on the consumed components (the whole point).
    const libc = parsed.components.find((c) => c.name === "libc6");
    // Sorted by the canonical key: id-shape (0:) before name-shape (1:).
    expect(libc?.licenses).toEqual([
      { license: { id: "LGPL-2.1-only" } },
      { license: { name: "GFDL-1.3" } },
    ]);
    const musl = parsed.components.find((c) => c.name === "musl");
    expect(musl?.licenses).toEqual([{ expression: "MIT" }]);

    // The image+digest is recorded from the SBOM metadata.
    expect(parsed.dockerImages.length).toBe(1);
    expect(parsed.dockerImages[0]?.digest).toBe(DIGEST);
  });

  test("#6: digest-less SBOM with NO metadata.component → image is the path-free BASENAME (deterministic)", async () => {
    // A digest-less SBOM still ingests; the recorded identity must be
    // PATH-INDEPENDENT so the committed docker-os-sbom.json is byte-identical
    // across machines. With no metadata.component (postgres fixture), the last
    // resort is the file BASENAME — never the machine-specific absolute path.
    const noDigestFixture = join(
      import.meta.dir,
      "fixtures",
      "syft-postgres-trimmed.json",
    );
    const { doc } = await consumeDockerOsSbom([noDigestFixture]);
    const parsed = JSON.parse(doc) as {
      dockerImages: Array<{ image: string; digest: string }>;
    };
    expect(parsed.dockerImages.length).toBe(1);
    // The identity is exactly the basename — path-free, digest empty
    // (provenance preserved, not fabricated).
    expect(parsed.dockerImages[0]?.image).toBe("syft-postgres-trimmed.json");
    expect(parsed.dockerImages[0]?.digest).toBe("");
    // It must NOT carry the machine-specific absolute directory.
    expect(parsed.dockerImages[0]?.image).not.toContain(import.meta.dir);
    expect(parsed.dockerImages[0]?.image.includes("/")).toBe(false);
    expect(parsed.dockerImages[0]?.image.includes("\\")).toBe(false);
  });

  test("#6: digest-less SBOM WITH metadata.component.name → image is the path-free image ref/tag", async () => {
    // When the digest-less SBOM carries metadata.component.name (the image
    // ref/tag, path-free), prefer it over the basename — it is the most
    // meaningful stable identity.
    const tagFixture = join(
      import.meta.dir,
      "fixtures",
      "syft-tagref-nodigest.json",
    );
    const { doc } = await consumeDockerOsSbom([tagFixture]);
    const parsed = JSON.parse(doc) as {
      dockerImages: Array<{ image: string; digest: string }>;
    };
    expect(parsed.dockerImages.length).toBe(1);
    expect(parsed.dockerImages[0]?.image).toBe("postgres:18-bookworm");
    expect(parsed.dockerImages[0]?.digest).toBe("");
    expect(parsed.dockerImages[0]?.image).not.toContain(import.meta.dir);
  });

  test("#6: the digest-less identity is INDEPENDENT of where the file lives (determinism)", async () => {
    // Copy the same digest-less SBOM under two different absolute paths and
    // confirm the emitted identity is byte-identical — the per-machine path
    // drift the review reported is gone.
    const { mkdtempSync, writeFileSync, readFileSync } =
      await import("node:fs");
    const { tmpdir } = await import("node:os");
    const source = readFileSync(
      join(import.meta.dir, "fixtures", "syft-postgres-trimmed.json"),
      "utf8",
    );
    const dirA = mkdtempSync(join(tmpdir(), "sbom-a-"));
    const dirB = mkdtempSync(join(tmpdir(), "sbom-b-"));
    const pathA = join(dirA, "syft-postgres-trimmed.json");
    const pathB = join(dirB, "syft-postgres-trimmed.json");
    writeFileSync(pathA, source);
    writeFileSync(pathB, source);
    const a = await consumeDockerOsSbom([pathA]);
    const b = await consumeDockerOsSbom([pathB]);
    expect(a.doc).toBe(b.doc);
  });

  test("ingesting the same SBOM twice is byte-identical (determinism)", async () => {
    const a = await consumeDockerOsSbom([FIXTURE]);
    const b = await consumeDockerOsSbom([FIXTURE]);
    expect(a.doc).toBe(b.doc);
    expect(a.doc.includes("\r")).toBe(false);
  });

  test("multiple SBOMs merge purl-deduped across files", async () => {
    const postgres = join(
      import.meta.dir,
      "fixtures",
      "syft-postgres-trimmed.json",
    );
    const { doc } = await consumeDockerOsSbom([FIXTURE, postgres]);
    const parsed = JSON.parse(doc) as {
      components: Array<{ purl: string }>;
      dockerImages: Array<{ image: string }>;
    };
    // Two source SBOMs → two dockerImages entries.
    expect(parsed.dockerImages.length).toBe(2);
    // deb rows from both, apk from the mixed fixture.
    expect(parsed.components.some((c) => c.purl.startsWith("pkg:apk/"))).toBe(
      true,
    );
    expect(parsed.components.some((c) => c.purl.startsWith("pkg:deb/"))).toBe(
      true,
    );
  });
});

describe("runGenerateDockerSbom (--from-sbom orchestration, NO docker)", () => {
  test("writes the committed doc from a pre-made SBOM without touching docker", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "licenses-from-sbom-"));
    try {
      // baseDir-resolve: pass an ABSOLUTE fromSbom path + a relative output.
      await runGenerateDockerSbom({
        fromSbomPaths: [FIXTURE],
        dockerOsSbomPath: "docker-os-sbom.json",
        baseDir: outDir,
      });
      const written = readFileSync(join(outDir, "docker-os-sbom.json"), "utf8");
      const parsed = JSON.parse(written) as {
        components: Array<{ name: string; licenses?: unknown }>;
        dockerImages: Array<{ digest: string }>;
      };
      // Licenses preserved through the orchestrator → committed bytes.
      expect(
        parsed.components.find((c) => c.name === "libc6")?.licenses,
      ).toEqual([
        { license: { id: "LGPL-2.1-only" } },
        { license: { name: "GFDL-1.3" } },
      ]);
      expect(parsed.dockerImages[0]?.digest).toBe(DIGEST);
      // LF contract.
      expect(written.includes("\r")).toBe(false);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});
