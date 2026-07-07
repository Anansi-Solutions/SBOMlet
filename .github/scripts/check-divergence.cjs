// PR-lane guard: fails the check red if regenerated scan artifacts are not
// committed, and stages the complete changed set for upload so a contributor
// can pull down exactly what CI expected.
//
// Shares the additions-only porcelain guard with commit-artifacts.js (the
// upload step inherits the same hazards a commit would: a rename, a
// git-quoted path, or a deletion). A path starting with "!" is also rejected
// here specifically, because upload-artifact's `path:` input treats a
// leading "!" as an exclusion glob, which would silently drop files from the
// uploaded payload.

const { execFileSync } = require("node:child_process");

function porcelainStatus() {
  return execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" });
}

function assertUploadable(status) {
  for (const line of status.split("\n")) {
    if (line === "") continue;
    const xy = line.slice(0, 2);
    if (/[DRC]/.test(xy)) {
      throw new Error(
        `upload set supports additions/modifications only; unsupported porcelain entry: ${line}`,
      );
    }
    if (line.includes('"')) {
      throw new Error(
        `upload set cannot represent a git-quoted path; unsupported porcelain entry: ${line}`,
      );
    }
    if (line.slice(3).startsWith("!")) {
      throw new Error(
        `a leading '!' would become an upload exclusion glob; unsupported porcelain entry: ${line}`,
      );
    }
  }
}

module.exports = async ({ core }) => {
  const status = porcelainStatus();
  if (status === "") {
    core.setOutput("diverged", "false");
    return;
  }

  core.error(
    "regenerated scan artifacts are not committed -- run generate and commit the result",
  );
  core.info(execFileSync("git", ["diff", "--stat"], { encoding: "utf8" }));

  assertUploadable(status);

  const changed = status
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => line.slice(3))
    .join("\n");

  core.setOutput("diverged", "true");
  core.setOutput("changed", changed);
};
