import assert from "node:assert/strict";
import { test } from "node:test";

import { createGithubPushSourceReader, type GithubPushSourceReaderProvider } from "../c2/push-source-reader.js";
import { PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256 } from "./c2-push-fixture.js";

const config = { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" };
const plan = { repository: "Ticoworld/t3n-breakglass-sandbox" as const, before_sha: PUSH_BEFORE_SHA, after_sha: PUSH_AFTER_SHA, path: ".breakglass-c2/exposed-deploy-key" as const };

function provider(overrides: Partial<GithubPushSourceReaderProvider> = {}): GithubPushSourceReaderProvider {
  return {
    mintContentsReadToken: async () => "contents-token",
    readImmutableContent: async (_token, operation) => operation.ref === PUSH_BEFORE_SHA
      ? { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 404 }
      : { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 200, digest_sha256: PUSH_PRIVATE_MATERIAL_SHA256 },
    revokeToken: async () => ({ status: 204, body: null, responseHeaders: {} }),
    probeRevokedToken: async () => ({ status: 401, body: null, responseHeaders: {} }),
    ...overrides,
  };
}

test("source reader performs exact BEFORE/AFTER immutable reads and cleans its contents token", async () => {
  const operations: string[] = [];
  const result = await createGithubPushSourceReader(config, provider({
    readImmutableContent: async (token, operation) => {
      operations.push(`${token}:${operation.repository}:${operation.path}:${operation.ref}`);
      return operation.ref === PUSH_BEFORE_SHA
        ? { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 404 }
        : { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 };
    },
  })).readPlan(plan);
  assert.deepEqual(operations, [`contents-token:Ticoworld/t3n-breakglass-sandbox:.breakglass-c2/exposed-deploy-key:${PUSH_BEFORE_SHA}`, `contents-token:Ticoworld/t3n-breakglass-sandbox:.breakglass-c2/exposed-deploy-key:${PUSH_AFTER_SHA}`]);
  assert.equal(result.before.status, 404);
  assert.equal(result.after.content_sha256, PUSH_PRIVATE_MATERIAL_SHA256);
  assert.equal(result.token_minted, true);
  assert.equal(result.token_revoked, true);
  assert.equal(result.revoked_token_refused, true);
});

test("source reader preserves already-present BEFORE and wrong AFTER observations for causal adjudication", async () => {
  const alreadyPresent = await createGithubPushSourceReader(config, provider({
    readImmutableContent: async (_token, operation) => ({ repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 }),
  })).readPlan(plan);
  assert.equal(alreadyPresent.before.status, 200);
  assert.equal(alreadyPresent.after.status, 200);

  const wrongAfter = await createGithubPushSourceReader(config, provider({
    readImmutableContent: async (_token, operation) => operation.ref === PUSH_BEFORE_SHA
      ? { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 404 }
      : { repository: operation.repository, commit_sha: operation.ref, path: operation.path, status: 200, content_sha256: "f".repeat(64) },
  })).readPlan(plan);
  assert.equal(wrongAfter.after.content_sha256, "f".repeat(64));
});

test("source reader refuses wrong path and repository before minting authority", async () => {
  let minted = false;
  const guarded = provider({ mintContentsReadToken: async () => { minted = true; return "token"; } });
  await assert.rejects(() => createGithubPushSourceReader(config, guarded).readPlan({ ...plan, path: "other" as typeof plan.path }), /path is outside/);
  await assert.rejects(() => createGithubPushSourceReader(config, guarded).readPlan({ ...plan, repository: "evil/repository" as typeof plan.repository }), /repository is outside/);
  assert.equal(minted, false);
});

test("source reader fails closed on token exchange, immutable read, revoke, and refusal failures", async () => {
  await assert.rejects(() => createGithubPushSourceReader(config, provider({ mintContentsReadToken: async () => { throw new Error("exchange failed"); } })).readPlan(plan), /exchange failed/);
  let revoked = false;
  await assert.rejects(() => createGithubPushSourceReader(config, provider({
    readImmutableContent: async () => { throw new Error("immutable read failed"); },
    revokeToken: async () => { revoked = true; return { status: 204, body: null, responseHeaders: {} }; },
  })).readPlan(plan), /immutable read failed/);
  assert.equal(revoked, true);
  await assert.rejects(() => createGithubPushSourceReader(config, provider({ revokeToken: async () => ({ status: 500, body: null, responseHeaders: {} }) })).readPlan(plan), /revocation failed/);
  await assert.rejects(() => createGithubPushSourceReader(config, provider({ probeRevokedToken: async () => ({ status: 200, body: null, responseHeaders: {} }) })).readPlan(plan), /was not refused/);
});
