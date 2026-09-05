import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { GithubIngressError } from "../c2/github-source.js";
import { processGithubWebhook } from "../c2/ingress.js";
import { TEST_SECRET, signedFixture, withBody } from "./c2-fixture.js";

async function storeDirectory(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "t3n-c2-ingress-"));
}

test("valid signed event produces exactly the frozen C1 create request", async (t) => {
  const directory = await storeDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const result = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  assert.equal(result.classification, "C2_SOURCE_SELECTED");
  if (result.classification !== "C2_SOURCE_SELECTED") return;
  assert.deepEqual(Object.keys(result.create_request).sort(), [
    "deploy_key_id",
    "effect_broker_did",
    "incident_id",
    "remediation_agent_did",
    "ttl_secs",
  ]);
  assert.deepEqual(result.create_request, {
    incident_id: result.incident_id,
    remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
    effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
    deploy_key_id: 162351194,
    ttl_secs: 900,
  });
  assert.equal(result.dedupe.status, "NEW");
  assert.equal((await readFile(path.join(directory, `${result.dedupe.key}.json`), "utf8")).includes("c2-local-fixture-secret"), false);
});

test("signature is checked over retained raw bytes before JSON parsing", async (t) => {
  const cases: Array<[string, (request: ReturnType<typeof signedFixture>) => ReturnType<typeof signedFixture>]> = [
    ["invalid signature", (request) => ({ ...request, headers: { ...request.headers, "X-Hub-Signature-256": `sha256=${"0".repeat(64)}` } })],
    ["malformed signature", (request) => ({ ...request, headers: { ...request.headers, "X-Hub-Signature-256": "sha256=not-hex" } })],
    ["missing signature", (request) => ({ ...request, headers: Object.fromEntries(Object.entries(request.headers).filter(([key]) => key !== "X-Hub-Signature-256") ) })],
    ["body mutation", (request) => withBody(request, Buffer.from(request.body).toString("utf8").replace('"created"', '"resolved"'))],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const directory = await storeDirectory();
      t.after(() => rm(directory, { recursive: true, force: true }));
      await assert.rejects(
        () => processGithubWebhook(mutate(signedFixture()), TEST_SECRET, directory),
        (error: unknown) => error instanceof GithubIngressError && ["INVALID_SIGNATURE", "MALFORMED_SIGNATURE", "MISSING_SIGNATURE"].includes(error.code),
      );
    });
  }
  const wrongSecretDirectory = await storeDirectory();
  t.after(() => rm(wrongSecretDirectory, { recursive: true, force: true }));
  await assert.rejects(
    () => processGithubWebhook(signedFixture(), `${TEST_SECRET}-wrong`, wrongSecretDirectory),
    (error: unknown) => error instanceof GithubIngressError && error.code === "INVALID_SIGNATURE",
  );
});

test("wrong event type and wrong repository fail closed after authentication", async (t) => {
  for (const request of [signedFixture({ eventType: "push" }), signedFixture({ action: "resolved" }), signedFixture({ repositoryFullName: "Ticoworld/other-repo" })]) {
    const directory = await storeDirectory();
    t.after(() => rm(directory, { recursive: true, force: true }));
    if (request.headers["X-GitHub-Event"] === "push") {
      await assert.rejects(() => processGithubWebhook(request, TEST_SECRET, directory), /not allowlisted/);
    } else if (request.headers["X-GitHub-Event"] !== "push" && Buffer.from(request.body).toString("utf8").includes('"resolved"')) {
      await assert.rejects(() => processGithubWebhook(request, TEST_SECRET, directory), /only a created/);
    } else {
      const result = await processGithubWebhook(request, TEST_SECRET, directory);
      assert.equal(result.classification, "C2_NO_MATCHING_POLICY");
    }
  }
});
