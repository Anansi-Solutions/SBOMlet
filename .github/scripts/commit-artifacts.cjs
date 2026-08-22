// Commits regenerated scan artifacts back with a verified bot commit, or fails
// loudly if the working tree changed outside the expected scope.
//
// Shared by docker-scan.yml (full changed set, committed to the pushed branch),
// intensive-scan.yml and update-compat-data.yml (both artifact-scoped, and
// `pullRequest: true` so their scheduled output reaches the repository's DEFAULT
// branch through a reviewable PR, never an unreviewed direct commit). A
// PR-opening caller passes `branchPrefix` and `prBody` for its own lane; the
// defaults below keep the intensive-scan wording. Called from a github-script step;
// `github`/`context` are the step's authenticated octokit client and event
// context. GraphQL's createCommitOnBranch takes additions/deletions as base64
// file contents directly, so there is no temp file and no argv size limit to
// worry about.
//
// additions-only: a deletion, rename, copy, or a path git quotes in porcelain
// output (non-ASCII under default core.quotepath) would corrupt the file list,
// so any of those fails loudly naming the entry instead of producing a broken
// or silently incomplete commit.

const { execFileSync } = require("node:child_process");
const { readFileSync } = require("node:fs");

const PR_BODY =
  "Automated refresh from the monthly intensive license scan. Review the " +
  "cache and document changes, then merge -- this lane no longer writes to the " +
  "default branch unreviewed.";

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

module.exports = async (
  { github, context, core },
  { scope, message, pullRequest, branchPrefix = "intensive-scan-refresh", prBody = PR_BODY } = {},
) => {
  // intensive-scan passes `scope`: the tree may only ever be dirty inside it.
  // Anything else dirty is an earlier step's bug -- refuse to sweep it into
  // this commit.
  if (scope) {
    const full = porcelainStatus();
    const scoped = porcelainStatus(scope);
    if (full !== scoped) {
      core.setFailed(
        `workspace drift outside the expected refresh artifacts; refusing to commit:\n${full}`,
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

  // Direct mode commits onto the checked-out branch. PR mode targets the
  // repository's DEFAULT branch (so a scheduled refresh always lands against
  // main, not wherever the run happened to check out) and stages the commit on
  // a fresh per-run branch a maintainer merges after review.
  let baseBranch = context.ref.replace(/^refs\/heads\//, "");
  let targetBranch = baseBranch;
  if (pullRequest) {
    const { data: repository } = await github.rest.repos.get({
      ...context.repo,
    });
    baseBranch = repository.default_branch;
    targetBranch = `chore/${branchPrefix}-${context.runId}`;
    try {
      await github.rest.git.createRef({
        ...context.repo,
        ref: `refs/heads/${targetBranch}`,
        sha: headOid,
      });
    } catch (err) {
      // A re-run reuses runId: the branch (and its PR) already exist. Leave the
      // prior attempt's PR in place rather than committing twice.
      if (err.status === 422) {
        core.info(`refresh branch ${targetBranch} already exists; leaving the existing PR`);
        return;
      }
      throw err;
    }
  }

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
          branchName: targetBranch,
        },
        expectedHeadOid: headOid,
        message: { headline: message },
        fileChanges: { additions },
      },
    },
  );
  const oid = result.createCommitOnBranch.commit.oid;

  if (!pullRequest) {
    core.info(`committed ${oid}`);
    return;
  }

  const pr = await github.rest.pulls.create({
    ...context.repo,
    head: targetBranch,
    base: baseBranch,
    title: message,
    body: prBody,
  });
  core.info(`opened #${pr.data.number} into ${baseBranch} (commit ${oid})`);
};
