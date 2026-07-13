/**
 * RED-first unit tests for the syft Docker OS-package collector.
 *
 * The exact-array test locks the syft 1.45.1 invocation byte-for-byte (mirrors
 * cdxgen.test.ts): any flag change must consciously break this test and
 * invalidate the committed OS-SBOM goldens. The filter/emit/digest/double-emit
 * tests pin the deterministic-artifact contract (mirrors terraform.test.ts).
 *
 * No live syft spawn happens here — the two fixtures are trimmed real-syft
 * captures (postgres:18 dpkg + nginx:stable-alpine apk). The live scan is the
 * gated dogfood's job (07-03).
 */

import {
  closeSync,
  ftruncateSync,
  mkdtempSync,
  openSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import {
  SYFT_TOOL,
  MAX_SYFT_SBOM_BYTES,
  assertSyftSbomSize,
  syftArgs,
  dockerInspectArgs,
  dockerPullArgs,
  filterOsComponents,
  unionOsComponents,
  emitDockerOsDoc,
  parseRepoDigests,
  selectDigest,
  type AttributedOsComponent,
  type OsComponent,
} from "../src/collectors/dockerOs";

import postgresFixture from "./fixtures/syft-postgres-trimmed.json";
import nginxFixture from "./fixtures/syft-nginx-trimmed.json";
import builtFixture from "./fixtures/syft-built-trimmed.json";

describe("syftArgs (argv lock)", () => {
  test("returns exactly the verified syft 1.45.1 cyclonedx-json invocation", () => {
    // Exact-array lock: options FIRST, then a `--` end-of-options separator, then
    // the image OPERAND (never a shell string). The `--` is defense-in-depth
    // (#7/#8): even a defensively dash-prefixed ref can never be parsed by syft
    // as a flag. syft accepts `syft -o <fmt>=<file> -- <image>` (verified).
    expect(syftArgs("postgres:18", "/tmp/x/syft.json")).toEqual([
      "-o",
      "cyclonedx-json=/tmp/x/syft.json",
      "--",
      "postgres:18",
    ]);
  });

  test("the image operand is placed AFTER the -- end-of-options separator (#7)", () => {
    const args = syftArgs("registry/app:1.2.3", "/tmp/out.json");
    const sepIndex = args.indexOf("--");
    expect(sepIndex).toBeGreaterThanOrEqual(0);
    // The operand is the LAST token, strictly after the separator.
    expect(args[sepIndex + 1]).toBe("registry/app:1.2.3");
    expect(args[args.length - 1]).toBe("registry/app:1.2.3");
  });
});

describe("dockerInspectArgs (argv lock, finding #5)", () => {
  test("the image operand is placed AFTER a `--` end-of-options separator", () => {
    const args = dockerInspectArgs("postgres:18");
    const sepIndex = args.indexOf("--");
    expect(sepIndex).toBeGreaterThanOrEqual(0);
    // A dash-prefixed operand can no longer be parsed by docker inspect as a flag.
    expect(args[sepIndex + 1]).toBe("postgres:18");
    expect(args[args.length - 1]).toBe("postgres:18");
  });

  test("retains the {{json .RepoDigests}} format and prefixes the image with --", () => {
    expect(dockerInspectArgs("nginx:stable-alpine")).toEqual([
      "inspect",
      "--format",
      "{{json .RepoDigests}}",
      "--",
      "nginx:stable-alpine",
    ]);
  });

  test("the literal SYFT_TOOL.version pin matches the spike-captured version", () => {
    // Grep-detectable pin: 07-RESEARCH captured syft at this exact version.
    expect(SYFT_TOOL).toEqual({ name: "syft", version: "1.45.1" });
  });
});

describe("dockerPullArgs (argv lock, implicit probe-first pull)", () => {
  test("the image operand is placed AFTER a `--` end-of-options separator", () => {
    const args = dockerPullArgs("postgres:18");
    const sepIndex = args.indexOf("--");
    expect(sepIndex).toBeGreaterThanOrEqual(0);
    // A dash-prefixed operand can never be parsed by docker pull as a flag.
    expect(args[sepIndex + 1]).toBe("postgres:18");
    expect(args[args.length - 1]).toBe("postgres:18");
  });

  test("returns exactly the `pull -- <image>` invocation", () => {
    expect(dockerPullArgs("nginx:stable-alpine")).toEqual([
      "pull",
      "--",
      "nginx:stable-alpine",
    ]);
  });
});

describe("filterOsComponents (image-contents purl filter, all ecosystems)", () => {
  test("keeps every component carrying a non-empty name+version+purl, across ecosystems", () => {
    // The single predicate is ecosystem-agnostic (D-03): deb, apk, and npm all
    // survive as long as they carry name+version+purl. purl-less file /
    // operating-system noise and empty-field entries are still dropped.
    const mixed = {
      components: [
        {
          type: "library",
          name: "libc6",
          version: "2",
          purl: "pkg:deb/libc6@2",
        },
        { type: "library", name: "musl", version: "1", purl: "pkg:apk/musl@1" },
        {
          type: "library",
          name: "left-pad",
          version: "1.3.0",
          purl: "pkg:npm/left-pad@1.3.0",
        },
        { type: "operating-system", name: "alpine", version: "3.23" },
        { type: "library", name: "empty", version: "", purl: "pkg:deb/empty@" },
      ],
    };
    const kept = filterOsComponents(mixed);
    // purl-sorted (apk < deb < npm); noise + empty-version entries dropped.
    expect(kept.map((c) => c.purl)).toEqual([
      "pkg:apk/musl@1",
      "pkg:deb/libc6@2",
      "pkg:npm/left-pad@1.3.0",
    ]);
  });

  test("PRESERVES syft's license id/name shapes on deb components (the bug fix)", () => {
    // The whole point of choosing syft: its resolved OS-package licenses must
    // survive the re-emit so the merge's licenseClaimsOf picks them up. Before
    // this fix the collector dropped them and the OS section rendered unknown.
    const os = filterOsComponents(postgresFixture);
    const byName = new Map(os.map((c) => [c.name, c]));

    // adduser carries TWO license.id entries (GPL-2.0-only / GPL-2.0-or-later).
    const adduser = byName.get("adduser");
    expect(adduser?.licenses).toEqual([
      { license: { id: "GPL-2.0-only" } },
      { license: { id: "GPL-2.0-or-later" } },
    ]);

    // base-files mixes license.id and license.name shapes — both survive.
    const baseFiles = byName.get("base-files");
    expect(baseFiles?.licenses).toEqual([
      { license: { id: "GPL-2.0-or-later" } },
      { license: { name: "GPL" } },
      { license: { name: "verbatim" } },
    ]);

    // gcc-14 carries NO licenses in the fixture — the field is omitted, not [].
    const gcc = byName.get("gcc-14");
    expect(gcc).toBeDefined();
    expect("licenses" in (gcc as object)).toBe(false);
  });

  test("PRESERVES syft's license shapes on apk components (id + expression)", () => {
    const os = filterOsComponents(nginxFixture);
    const byName = new Map(os.map((c) => [c.name, c]));

    // alpine-keys: single license.id.
    expect(byName.get("alpine-keys")?.licenses).toEqual([
      { license: { id: "MIT" } },
    ]);
    // ca-certificates: an SPDX expression shape survives verbatim.
    expect(byName.get("ca-certificates")?.licenses).toEqual([
      { expression: "MPL-2.0 AND MIT" },
    ]);
    // aom-libs: mixed id + name entries all survive in order.
    expect(byName.get("aom-libs")?.licenses).toEqual([
      { license: { id: "BSD-2-Clause" } },
      { license: { name: "AND" } },
      { license: { name: "custom" } },
    ]);
  });

  test("license entries are deterministically ordered (sorted) for byte-stability", () => {
    // syft's per-component license array order is not guaranteed stable; the
    // re-emit sorts entries by their canonical string so a double-emit is
    // byte-identical even if syft reshuffles. Shuffled input → sorted output.
    const shuffled = {
      components: [
        {
          type: "library",
          name: "x",
          version: "1",
          purl: "pkg:deb/x@1",
          licenses: [
            { license: { name: "Zlib" } },
            { expression: "MIT OR Apache-2.0" },
            { license: { id: "GPL-2.0-only" } },
            { license: { id: "Apache-2.0" } },
          ],
        },
      ],
    };
    const [c] = filterOsComponents(shuffled);
    // Canonical sort key: id < name < expression discriminator + value, all
    // compared as their JSON string. The exact order is locked here so the
    // determinism contract is explicit.
    expect(c?.licenses).toEqual([
      { license: { id: "Apache-2.0" } },
      { license: { id: "GPL-2.0-only" } },
      { license: { name: "Zlib" } },
      { expression: "MIT OR Apache-2.0" },
    ]);
  });

  test("malformed/foreign license entries are dropped, not re-emitted", () => {
    const withJunk = {
      components: [
        {
          type: "library",
          name: "y",
          version: "1",
          purl: "pkg:deb/y@1",
          licenses: [
            { license: { id: "MIT" } },
            { license: {} }, // no id/name
            "garbage", // not an object
            { other: "field" }, // unknown shape
            null,
          ],
        },
      ],
    };
    const [c] = filterOsComponents(withJunk);
    expect(c?.licenses).toEqual([{ license: { id: "MIT" } }]);
  });

  test("retained components are purl-sorted via compareCodeUnits", () => {
    const os = filterOsComponents(postgresFixture);
    const purls = os.map((c) => c.purl);
    const sorted = [...purls].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(purls).toEqual(sorted);
  });

  test("duplicate purls are deduped first-wins, across ecosystems", () => {
    const dup = {
      components: [
        { type: "library", name: "a", version: "1", purl: "pkg:deb/a@1" },
        { type: "library", name: "a", version: "1", purl: "pkg:deb/a@1" },
        { type: "library", name: "b", version: "2", purl: "pkg:deb/b@2" },
        { type: "library", name: "lp", version: "1", purl: "pkg:npm/lp@1" },
        { type: "library", name: "lp", version: "1", purl: "pkg:npm/lp@1" },
      ],
    };
    const os = filterOsComponents(dup);
    expect(os.map((c) => c.purl)).toEqual([
      "pkg:deb/a@1",
      "pkg:deb/b@2",
      "pkg:npm/lp@1",
    ]);
  });
});

describe("filterOsComponents (full image contents by default)", () => {
  test("keeps apk AND npm AND pypi components, purl-sorted, licenses preserved", () => {
    const full = filterOsComponents(builtFixture);
    const purls = full.map((c) => c.purl);
    const sorted = [...purls].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(purls).toEqual(sorted);

    const byName = new Map(full.map((c) => [c.name, c]));
    expect(byName.get("musl")?.purl).toBe(
      "pkg:apk/alpine/musl@1.2.5-r9?arch=x86_64&distro=alpine-3.23.4",
    );
    expect(byName.get("busybox")?.purl).toBe(
      "pkg:apk/alpine/busybox@1.37.0-r19?arch=x86_64&distro=alpine-3.23.4",
    );
    // Scoped npm component, purl-encoded, licenses preserved through narrowLicense.
    const scoped = byName.get("@scope/pkg");
    expect(scoped?.purl).toBe("pkg:npm/%40scope/pkg@1.0.0");
    expect(scoped?.licenses).toEqual([{ license: { id: "MIT" } }]);
    // Unscoped npm component.
    const leftPad = byName.get("left-pad");
    expect(leftPad?.purl).toBe("pkg:npm/left-pad@1.3.0");
    expect(leftPad?.licenses).toEqual([{ license: { id: "MIT" } }]);
    // pypi component (hyphenated PEP-503 form).
    const pypi = byName.get("typing-extensions");
    expect(pypi?.purl).toBe("pkg:pypi/typing-extensions@4.12.2");
    expect(pypi?.licenses).toEqual([{ license: { name: "PSF-2.0" } }]);
  });

  test("drops purl-less noise and empty-name/version/purl entries", () => {
    const full = filterOsComponents(builtFixture);
    const names = full.map((c) => c.name);
    // syft's purl-less file/operating-system noise never survives.
    expect(names).not.toContain("/etc/os-release");
    expect(names).not.toContain("alpine");
    // A component with an empty version is dropped even though it carries a purl.
    expect(names).not.toContain("empty-version-pkg");
    // Every retained component carries non-empty name+version+purl.
    expect(
      full.every(
        (c) =>
          typeof c.name === "string" &&
          c.name.length > 0 &&
          typeof c.version === "string" &&
          c.version.length > 0 &&
          typeof c.purl === "string" &&
          c.purl.length > 0,
      ),
    ).toBe(true);
  });

  test("double-emit of the full-contents doc is byte-identical, with no volatile fields", () => {
    const full = unionOsComponents([
      {
        image: "local/scan-image:built",
        components: filterOsComponents(builtFixture),
      },
    ]);
    const digests = [
      {
        image: "local/scan-image:built",
        digest: "",
        source: "local/scan-image:built",
      },
    ];
    const first = emitDockerOsDoc(full, digests);
    const second = emitDockerOsDoc(full, digests);
    expect(first).toBe(second);
    expect(first).not.toContain("serialNumber");
    expect(first).not.toContain("timestamp");
  });
});

// ---------------------------------------------------------------------------
// unionOsComponents (sidecar v2 membership union) — the cross-image dedup no
// longer DISCARDS membership: a purl shared between images stays ONE row, but
// that row now lists every containing image. The retained name/version/licenses
// are still the first-seen values (callers pass images in sorted order, so the
// license posture stays first-wins-by-sorted-image — unchanged, just visible).
// ---------------------------------------------------------------------------

describe("unionOsComponents (cross-image membership union, sidecar v2)", () => {
  const sharedInA: OsComponent[] = [
    {
      type: "library",
      name: "busybox",
      version: "1.37.0-r19",
      purl: "pkg:apk/alpine/busybox@1.37.0-r19",
      licenses: [{ license: { id: "GPL-2.0-only" } }],
    },
    {
      type: "library",
      name: "musl",
      version: "1.2.5-r9",
      purl: "pkg:apk/alpine/musl@1.2.5-r9",
      licenses: [{ expression: "MIT" }],
    },
  ];
  const sharedInB: OsComponent[] = [
    {
      type: "library",
      name: "busybox",
      version: "1.37.0-r19",
      purl: "pkg:apk/alpine/busybox@1.37.0-r19",
      // A DIFFERENT claim set for the same purl: the first-seen set must win.
      licenses: [{ license: { name: "GPL" } }],
    },
    {
      type: "library",
      name: "zlib",
      version: "1.3.1-r2",
      purl: "pkg:apk/alpine/zlib@1.3.1-r2",
      licenses: [{ license: { id: "Zlib" } }],
    },
  ];

  test("a purl present in two images yields ONE row whose images lists BOTH tags sorted", () => {
    const merged = unionOsComponents([
      { image: "img/a", components: sharedInA },
      { image: "img/b", components: sharedInB },
    ]);
    const busybox = merged.find((c) => c.name === "busybox");
    expect(busybox?.images).toEqual(["img/a", "img/b"]);
    // One row per purl — the dedup posture is unchanged, only more visible.
    expect(merged.filter((c) => c.name === "busybox")).toHaveLength(1);
    // The retained licenses are the FIRST-SEEN (image a) claim set.
    expect(busybox?.licenses).toEqual([{ license: { id: "GPL-2.0-only" } }]);
  });

  test("a purl unique to one image carries exactly that one membership entry", () => {
    const merged = unionOsComponents([
      { image: "img/a", components: sharedInA },
      { image: "img/b", components: sharedInB },
    ]);
    expect(merged.find((c) => c.name === "musl")?.images).toEqual(["img/a"]);
    expect(merged.find((c) => c.name === "zlib")?.images).toEqual(["img/b"]);
  });

  test("membership arrays are sorted even when inputs arrive unsorted", () => {
    const merged = unionOsComponents([
      { image: "img/b", components: sharedInB },
      { image: "img/a", components: sharedInA },
    ]);
    expect(merged.find((c) => c.name === "busybox")?.images).toEqual([
      "img/a",
      "img/b",
    ]);
  });

  test("a duplicate image in the scan set never double-counts one membership", () => {
    const merged = unionOsComponents([
      { image: "img/a", components: sharedInA },
      { image: "img/a", components: sharedInA },
    ]);
    expect(merged.find((c) => c.name === "busybox")?.images).toEqual(["img/a"]);
  });

  test("merged rows stay purl-sorted via compareCodeUnits", () => {
    const merged = unionOsComponents([
      { image: "img/b", components: sharedInB },
      { image: "img/a", components: sharedInA },
    ]);
    const purls = merged.map((c) => c.purl);
    const sorted = [...purls].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(purls).toEqual(sorted);
  });
});

describe("emitDockerOsDoc (deterministic emit, sidecar v2)", () => {
  const DIGESTS = [
    { image: "postgres:18", digest: "sha256:abc", source: "postgres:18" },
  ];
  const postgresAttributed = (): AttributedOsComponent[] =>
    unionOsComponents([
      { image: "postgres:18", components: filterOsComponents(postgresFixture) },
    ]);

  test("emits ONLY {bomFormat, specVersion, components, dockerImages}", () => {
    const json = emitDockerOsDoc(postgresAttributed(), DIGESTS);
    const doc = JSON.parse(json) as Record<string, unknown>;
    expect(new Set(Object.keys(doc))).toEqual(
      new Set(["bomFormat", "specVersion", "components", "dockerImages"]),
    );
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.6");
    // No serialNumber, no metadata, no timestamp survive the re-emit.
    expect(doc.serialNumber).toBeUndefined();
    expect(doc.metadata).toBeUndefined();
    expect(json).not.toContain("timestamp");
    expect(json).not.toContain("serialNumber");
  });

  test("every component carries its sorted image membership (sidecar v2)", () => {
    const json = emitDockerOsDoc(postgresAttributed(), DIGESTS);
    const doc = JSON.parse(json) as {
      components: Array<{ images?: unknown }>;
    };
    expect(doc.components.length).toBeGreaterThan(0);
    // Single-image doc: every component's membership is exactly that image.
    expect(
      doc.components.every(
        (c) =>
          Array.isArray(c.images) &&
          c.images.length === 1 &&
          c.images[0] === "postgres:18",
      ),
    ).toBe(true);
  });

  test("the dockerImages sidecar is [{image, digest, source}] sorted by image", () => {
    const json = emitDockerOsDoc(postgresAttributed(), [
      {
        image: "postgres:18",
        digest: "sha256:ppp",
        source: "db/Dockerfile",
      },
      {
        image: "nginx:stable-alpine",
        digest: "sha256:nnn",
        source: "nginx:stable-alpine",
      },
    ]);
    const doc = JSON.parse(json) as {
      dockerImages: { image: string; digest: string; source: string }[];
    };
    expect(doc.dockerImages).toEqual([
      {
        image: "nginx:stable-alpine",
        digest: "sha256:nnn",
        source: "nginx:stable-alpine",
      },
      { image: "postgres:18", digest: "sha256:ppp", source: "db/Dockerfile" },
    ]);
  });

  test("double-emit from the same components+digests is byte-identical", () => {
    const components = unionOsComponents([
      {
        image: "nginx:stable-alpine",
        components: filterOsComponents(nginxFixture),
      },
    ]);
    const digests = [
      {
        image: "nginx:stable-alpine",
        digest: "sha256:zzz",
        source: "nginx:stable-alpine",
      },
    ];
    expect(emitDockerOsDoc(components, digests)).toBe(
      emitDockerOsDoc(components, digests),
    );
  });

  test("the emitted doc carries each component's preserved licenses array", () => {
    const json = emitDockerOsDoc(postgresAttributed(), DIGESTS);
    const doc = JSON.parse(json) as {
      components: Array<{
        name: string;
        licenses?: unknown;
      }>;
    };
    const adduser = doc.components.find((c) => c.name === "adduser");
    expect(adduser?.licenses).toEqual([
      { license: { id: "GPL-2.0-only" } },
      { license: { id: "GPL-2.0-or-later" } },
    ]);
    // The license shapes are exactly the CycloneDX claim shapes the merge's
    // licenseClaimsOf reads — so OS packages render REAL licenses, not unknown.
    expect(json).toContain('"GPL-2.0-only"');
  });
});

describe("assertSyftSbomSize (DoS size gate)", () => {
  test("MAX_SYFT_SBOM_BYTES is 64 MiB headroom over real syft output", () => {
    expect(MAX_SYFT_SBOM_BYTES).toBe(64 * 1024 * 1024);
  });

  test("a file under the cap passes the gate", () => {
    const dir = mkdtempSync(join(tmpdir(), "licenses-syft-test-"));
    const path = join(dir, "small.json");
    writeFileSync(path, "{}\n");
    expect(() => assertSyftSbomSize(path)).not.toThrow();
  });

  test("a synthetic over-cap input throws the size error before parse", () => {
    const dir = mkdtempSync(join(tmpdir(), "licenses-syft-test-"));
    const path = join(dir, "huge.json");
    // Sparse file: ftruncate to one byte over the cap without writing 64 MiB.
    const fd = openSync(path, "w");
    ftruncateSync(fd, MAX_SYFT_SBOM_BYTES + 1);
    closeSync(fd);
    expect(() => assertSyftSbomSize(path)).toThrow(/cap|bytes/i);
  });
});

// ---------------------------------------------------------------------------
// selectDigest (finding #2, 07-31) — deterministic RepoDigest selection. An
// image pulled from / pushed to multiple registries has multiple RepoDigests
// in a daemon-order-dependent array; selecting digests[0] makes the committed
// docker-os.sbom.json vary by machine (byte-determinism break). selectDigest
// is a pure function of the digest SET, NOT of daemon emission order: it
// prefers the digest whose repository matches the requested image ref, else
// the compareCodeUnits-smallest.
// ---------------------------------------------------------------------------

describe("selectDigest (deterministic RepoDigest selection, finding #2)", () => {
  test("a two-element RepoDigests array yields the SAME digest in BOTH daemon orders", () => {
    const a = "registry-a.io/app@sha256:" + "a".repeat(64);
    const b = "registry-b.io/app@sha256:" + "b".repeat(64);
    // The same SET in opposite daemon-emission orders must select identically.
    expect(selectDigest("app", [a, b])).toBe(selectDigest("app", [b, a]));
  });

  test("parseRepoDigests + selectDigest is order-independent end-to-end", () => {
    const a = "registry-a.io/app@sha256:" + "1".repeat(64);
    const b = "registry-b.io/app@sha256:" + "2".repeat(64);
    const fwd = selectDigest(
      "app",
      parseRepoDigests(JSON.stringify([a, b]), ""),
    );
    const rev = selectDigest(
      "app",
      parseRepoDigests(JSON.stringify([b, a]), ""),
    );
    expect(fwd).toBe(rev);
  });

  test("prefers the digest whose repository matches the requested image ref", () => {
    const matching = "docker.io/library/nginx@sha256:" + "c".repeat(64);
    const other = "ghcr.io/acme/nginx@sha256:" + "d".repeat(64);
    // Requested by the docker.io repo path → that digest is selected regardless
    // of array order, even though "ghcr.io/..." sorts smaller.
    expect(selectDigest("docker.io/library/nginx", [other, matching])).toBe(
      matching,
    );
    expect(selectDigest("docker.io/library/nginx", [matching, other])).toBe(
      matching,
    );
  });

  test("with no repo match, falls back to the compareCodeUnits-smallest digest", () => {
    const z = "z-registry.io/app@sha256:" + "e".repeat(64);
    const a = "a-registry.io/app@sha256:" + "f".repeat(64);
    // No requested-repo match → smallest by code units ("a-..." < "z-...").
    expect(selectDigest("unrelated:tag", [z, a])).toBe(a);
    expect(selectDigest("unrelated:tag", [a, z])).toBe(a);
  });

  test("the single-element common case is identical to the prior digests[0]", () => {
    const only = "postgres@sha256:" + "0".repeat(64);
    expect(selectDigest("postgres:18", [only])).toBe(only);
  });

  test("an empty RepoDigests set selects undefined (caller throws)", () => {
    expect(selectDigest("postgres:18", [])).toBeUndefined();
  });
});
