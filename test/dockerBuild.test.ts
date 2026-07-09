/**
 * Unit tests for the in-tool docker build step (imageTag + buildx argv + loud
 * failure). This logic moved bit-exact out of an untested repo-local build
 * script into tested src, so the committed sidecar identity it produces is now
 * locked by a golden here rather than resting on an unexercised script.
 *
 * The build invocation is exercised subprocess-free: buildImage takes its exec
 * seam as a parameter (the execTool shape), so a recorder captures the exact
 * argv without ever spawning docker — the argv-array mirror of the syftArgs
 * lock in dockerOs.test.ts.
 */

import { describe, expect, test } from "bun:test";

import {
  imageTag,
  buildImageArgs,
  buildImage,
} from "../src/collectors/dockerBuild";
import type { ExecOptions } from "../src/collectors/exec";

/**
 * A subprocess-free exec recorder in the execTool shape. Records every
 * invocation as [cmd, ...args]; resolves empty by default, or rejects (a
 * nonzero buildx exit) when `fail` is set.
 */
function makeRecorder(fail = false): {
  invocations: string[][];
  exec: (
    cmd: string,
    args: string[],
    opts: ExecOptions,
  ) => Promise<{ stdout: string; stderr: string }>;
} {
  const invocations: string[][] = [];
  const exec = (
    cmd: string,
    args: string[],
    _opts: ExecOptions,
  ): Promise<{ stdout: string; stderr: string }> => {
    invocations.push([cmd, ...args]);
    if (fail) return Promise.reject(new Error("buildx exit 1"));
    return Promise.resolve({ stdout: "", stderr: "" });
  };
  return { invocations, exec };
}

describe("imageTag (deterministic tag lock)", () => {
  test("golden: reproduces the committed sidecar identity bit-exact", () => {
    // This exact string is the image identity recorded in the committed
    // .sbomlet.cache/docker-os.sbom.json. The whole point of moving the build
    // step into src is that this identity survives the move byte-for-byte —
    // any drift here churns the committed artifact and every consumer's check.
    expect(imageTag("examples/docker-scan/Dockerfile")).toBe(
      "sbomlet-scan/examples-docker-scan-dockerfile-82bd3b3b",
    );
  });

  test("sanitization: lowercases and maps every char outside [a-z0-9._-] to -", () => {
    // dots, dashes and underscores survive; slashes and spaces become dashes.
    expect(imageTag("a_b.c-d/Dockerfile")).toMatch(
      /^sbomlet-scan\/a_b\.c-d-dockerfile-[0-9a-f]{8}$/,
    );
  });

  test("the sha256-8 suffix hashes the ORIGINAL path, not the sanitized form", () => {
    // A mixed-case path and its lowercased twin sanitize to the SAME prefix but
    // MUST get distinct hashes — the suffix hashes the original path string, so
    // the two never collide onto one tag.
    const mixed = imageTag("A/B/Dockerfile");
    const lower = imageTag("a/b/Dockerfile");
    expect(mixed).not.toBe(lower);
    // Same sanitized prefix, distinct 8-hex suffix.
    expect(mixed.slice(0, "sbomlet-scan/a-b-dockerfile-".length)).toBe(
      "sbomlet-scan/a-b-dockerfile-",
    );
    expect(lower.slice(0, "sbomlet-scan/a-b-dockerfile-".length)).toBe(
      "sbomlet-scan/a-b-dockerfile-",
    );
  });

  test("collision resistance: distinct paths that sanitize identically get distinct tags", () => {
    // a/b/Dockerfile and a-b/Dockerfile both sanitize to a-b-dockerfile; the
    // path-hash suffix keeps them apart so the second build can never silently
    // overwrite the first image and drop it from the committed inventory.
    expect(imageTag("a/b/Dockerfile")).not.toBe(imageTag("a-b/Dockerfile"));
  });
});

describe("buildImageArgs (argv builder)", () => {
  test("returns exactly the buildx flags/operands, POSIX dirname context", () => {
    expect(
      buildImageArgs("examples/docker-scan/Dockerfile", "the-tag"),
    ).toEqual([
      "buildx",
      "build",
      "--load",
      "--provenance=false",
      "-f",
      "examples/docker-scan/Dockerfile",
      "-t",
      "the-tag",
      "examples/docker-scan",
    ]);
  });
});

describe("buildImage (execTool seam)", () => {
  test("records exactly `docker buildx build --load --provenance=false -f P -t T dir(P)`", async () => {
    const { invocations, exec } = makeRecorder();
    const tag = await buildImage("examples/docker-scan/Dockerfile", exec);
    expect(tag).toBe("sbomlet-scan/examples-docker-scan-dockerfile-82bd3b3b");
    expect(invocations).toEqual([
      [
        "docker",
        "buildx",
        "build",
        "--load",
        "--provenance=false",
        "-f",
        "examples/docker-scan/Dockerfile",
        "-t",
        "sbomlet-scan/examples-docker-scan-dockerfile-82bd3b3b",
        "examples/docker-scan",
      ],
    ]);
  });

  test("a nonzero buildx exit throws naming the Dockerfile and returns no tag", async () => {
    const { exec } = makeRecorder(true);
    await expect(
      buildImage("examples/docker-scan/Dockerfile", exec),
    ).rejects.toThrow("examples/docker-scan/Dockerfile");
  });

  test("determinism: building the same path list twice yields identical argv and tags", async () => {
    const paths = ["a/Dockerfile", "b/Dockerfile"];
    const first = makeRecorder();
    const tags1: string[] = [];
    for (const p of paths) tags1.push(await buildImage(p, first.exec));

    const second = makeRecorder();
    const tags2: string[] = [];
    for (const p of paths) tags2.push(await buildImage(p, second.exec));

    expect(tags1).toEqual(tags2);
    expect(first.invocations).toEqual(second.invocations);
  });
});

describe("buildImage (cwd threading — repo-root anchoring)", () => {
  test("forwards opts.cwd to the exec seam so the repo-relative -f/context resolve against the repo root", async () => {
    // The consumer bug: buildImage ran the exec with NO cwd, so buildx resolved
    // the repo-relative `-f` and build-context against the tool's PROCESS cwd.
    // Any consumer invoking from a subdir (e.g. tools/sbomlet) hit
    // "unable to prepare context: path not found". The fix threads a cwd through
    // to the exec seam; here we assert it lands in ExecOptions.cwd.
    const seen: (ExecOptions | undefined)[] = [];
    const exec = (
      _cmd: string,
      _args: string[],
      opts: ExecOptions,
    ): Promise<{ stdout: string; stderr: string }> => {
      seen.push(opts);
      return Promise.resolve({ stdout: "", stderr: "" });
    };
    await buildImage("examples/docker-scan/Dockerfile", exec, {
      cwd: "/some/repo/root",
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.cwd).toBe("/some/repo/root");
  });

  test("no cwd option leaves ExecOptions.cwd unset (inherits process cwd — the explicit --dockerfile lane)", async () => {
    // The targeted/explicit lane resolves user-given relative paths against the
    // user's cwd, so buildImage without a cwd must NOT set one (spawn then
    // inherits process.cwd()).
    const seen: (ExecOptions | undefined)[] = [];
    const exec = (
      _cmd: string,
      _args: string[],
      opts: ExecOptions,
    ): Promise<{ stdout: string; stderr: string }> => {
      seen.push(opts);
      return Promise.resolve({ stdout: "", stderr: "" });
    };
    await buildImage("examples/docker-scan/Dockerfile", exec);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.cwd).toBeUndefined();
  });
});
