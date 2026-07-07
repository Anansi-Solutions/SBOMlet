// Commits regenerated scan artifacts back with a verified bot commit, or
// fails loudly if the working tree changed outside the expected scope.
//
// Shared by docker-scan.yml (full changed set) and intensive-scan.yml
// (artifact-scoped: only paths in `scope`). Called from a github-script step;
// `github`/`context` are the step's authenticated octokit client and event
// context. GraphQL's createCommitOnBranch takes additions/deletions as
// base64 file contents directly, so there is no temp file and no argv size
// limit to worry about.
//
// additions-only: a deletion, rename, copy, or a path git quotes in porcelain
// output (non-ASCII under default core.quotepath) would corrupt the file
// list, so any of those fails loudly naming the entry instead of producing a
// broken or silently incomplete commit.

const { execFileSync } = require("node:child_process");
const { readFileSync } = require("node:fs");

function porcelainStatus(scope) {
  const args = ["status", "--porcelain"];
  if (scope) args.push("--", ...scope);
  return execFileSync("git", args, { encoding: "utf8" });
}

function assertAdditionsOnly(status) {
  for (const line of status.split("\n")) {
    if (line === "") continue;
    const xy = line.slice(0, 2);
    if (/[DRC]/.test(xy)) {
      throw new Error(
        `commit-back supports additions/modifications only; unsupported porcelain entry: ${line}`,
      );
    }
    if (line.includes('"')) {
      throw new Error(
        `commit-back cannot represent a git-quoted path; unsupported porcelain entry: ${line}`,
      );
    }
  }
}

function changedPaths(status) {
  return status
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => line.slice(3));
}

module.exports = async ({ github, context, core }, { scope, message } = {}) => {
  // intensive-scan passes `scope`: the tree may only ever be dirty inside it.
  // Anything else dirty is an earlier step's bug -- refuse to sweep it into
  // this commit.
  if (scope) {
    const full = porcelainStatus();
    const scoped = porcelainStatus(scope);
    if (full !== scoped) {
      core.setFailed(
        `workspace drift outside the intensive-scan artifacts; refusing to commit:\n${full}`,
      );
      return;
    }
  }

  const status = porcelainStatus(scope);
  if (status === "") {
    core.info("artifacts unchanged");
    return;
  }

  assertAdditionsOnly(status);

  const headOid = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();

  const additions = changedPaths(status).map((path) => ({
    path,
    contents: readFileSync(path).toString("base64"),
  }));

  const result = await github.graphql(
    `mutation($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) {
        commit { oid }
      }
    }`,
    {
      input: {
        branch: {
          repositoryNameWithOwner: `${context.repo.owner}/${context.repo.repo}`,
          branchName: context.ref.replace(/^refs\/heads\//, ""),
        },
        expectedHeadOid: headOid,
        message: { headline: message },
        fileChanges: { additions },
      },
    },
  );

  core.info(`committed ${result.createCommitOnBranch.commit.oid}`);
};
