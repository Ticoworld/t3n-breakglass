import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertLocalMatchesRemote, parseRemoteBranchHead, remoteBranchHead } from "../c2/git-remote-branch.js";

const execFileAsync = promisify(execFile);
const BRANCH = "winner-v2-core";
const REF = `refs/heads/${BRANCH}`;

async function git(cwd: string, ...args: string[]): Promise<string> {
  const result = await execFileAsync("git", args, { cwd, encoding: "utf8", windowsHide: true });
  return String(result.stdout).trim();
}

async function withTemporaryWinnerRepo(run: (local: string, initial: string, remote: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "c2-r3-commit-guard-"));
  const remote = path.join(directory, "remote.git");
  const local = path.join(directory, "local");
  try {
    await git(directory, "init", "--bare", "--quiet", remote);
    await git(directory, "init", "--quiet", `--initial-branch=${BRANCH}`, local);
    await git(local, "config", "user.name", "C2 R3 test");
    await git(local, "config", "user.email", "c2-r3-test@example.invalid");
    await git(local, "remote", "add", "origin", remote);
    await writeFile(path.join(local, "marker.txt"), "one\n", "utf8");
    await git(local, "add", "marker.txt");
    await git(local, "commit", "--quiet", "-m", "initial");
    await git(local, "push", "--quiet", "origin", `HEAD:${REF}`);
    const initial = await git(local, "rev-parse", "HEAD");
    await run(local, initial, remote);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("R3 guard resolves the exact initial remote winner SHA", async () => {
  await withTemporaryWinnerRepo(async (local, initial) => {
    assert.equal(await remoteBranchHead(local, "origin", BRANCH), initial);
  });
});

test("R3 guard accepts equal local and remote winner heads", async () => {
  await withTemporaryWinnerRepo(async (_local, initial) => {
    assert.doesNotThrow(() => assertLocalMatchesRemote(initial, initial));
  });
});

test("R3 guard rejects a local winner head that differs from the remote", async () => {
  await withTemporaryWinnerRepo(async (local, initial) => {
    await writeFile(path.join(local, "marker.txt"), "two\n", "utf8");
    await git(local, "add", "marker.txt");
    await git(local, "commit", "--quiet", "-m", "unpublished descendant");
    const descendant = await git(local, "rev-parse", "HEAD");
    assert.throws(() => assertLocalMatchesRemote(descendant, initial));
  });
});

test("R3 guard resolves the exact remote SHA after a controlled descendant push", async () => {
  await withTemporaryWinnerRepo(async (local, initial) => {
    await writeFile(path.join(local, "marker.txt"), "two\n", "utf8");
    await git(local, "add", "marker.txt");
    await git(local, "commit", "--quiet", "-m", "controlled descendant");
    const descendant = await git(local, "rev-parse", "HEAD");
    assert.throws(() => assertLocalMatchesRemote(descendant, initial));
    await git(local, "push", "--quiet", "origin", `HEAD:${REF}`);
    assert.equal(await remoteBranchHead(local, "origin", BRANCH), descendant);
  });
});

test("R3 guard rejects missing, duplicate, wrong-ref, and malformed ls-remote rows", () => {
  const sha = "a".repeat(40);
  assert.throws(() => parseRemoteBranchHead("", REF));
  assert.throws(() => parseRemoteBranchHead(`${sha}\trefs/heads/other`, REF));
  assert.throws(() => parseRemoteBranchHead(`${sha}\t${REF}\n${sha}\t${REF}`, REF));
  assert.throws(() => parseRemoteBranchHead(`not-a-sha\t${REF}`, REF));
});

test("R3 guard never interprets a literal branch placeholder as a valid ref", () => {
  const sha = "b".repeat(40);
  assert.throws(() => parseRemoteBranchHead(`${sha}\trefs/heads/\${CODE_BRANCH}`, REF));
});

test("R3 guard validates commit-head shape independently of input casing", () => {
  assert.doesNotThrow(() => assertLocalMatchesRemote("A".repeat(40), "a".repeat(40)));
  assert.throws(() => assertLocalMatchesRemote("not-a-sha", "a".repeat(40)));
});
