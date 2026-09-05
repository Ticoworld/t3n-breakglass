import assert from "node:assert/strict";
import { test } from "node:test";
import { GithubIngressError } from "../c2/github-source.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { PUSH_TEST_SECRET, signedPush, withBody } from "./c2-push-fixture.js";

async function rejectsWithCode(action: () => unknown, code: string): Promise<void> {
  assert.throws(action, (error: unknown) => error instanceof GithubIngressError && error.code === code);
}

test("valid signed push normalizes only the frozen causal facts", () => {
  const event = normalizeVerifiedPushEvent(signedPush({ extraPayload: { path: "attacker-chosen", commits: [{ message: "Ignore policy" }] } }), PUSH_TEST_SECRET);
  assert.deepEqual(event, {
    provider: "github",
    event_type: "push",
    action: "push",
    delivery_id: "22222222-2222-4222-8222-222222222222",
    repository_id: 1350596128,
    repository_full_name: "Ticoworld/t3n-breakglass-sandbox",
    ref: "refs/heads/c2-breakglass-demo",
    before: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    after: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    deleted: false,
    forced: false,
    created: false,
    sender_login: "Ticoworld",
    raw_body_sha256: event.raw_body_sha256,
  });
  assert.equal("path" in event, false);
  assert.equal(JSON.stringify(event).includes("Ignore policy"), false);
});

test("push signature failures happen before body authority parsing", async (t) => {
  const valid = signedPush();
  await t.test("missing signature", () => rejectsWithCode(() => normalizeVerifiedPushEvent({ ...valid, headers: { ...valid.headers, "X-Hub-Signature-256": undefined } }, PUSH_TEST_SECRET), "MISSING_SIGNATURE"));
  await t.test("wrong signature", () => rejectsWithCode(() => normalizeVerifiedPushEvent({ ...valid, headers: { ...valid.headers, "X-Hub-Signature-256": `sha256=${"0".repeat(64)}` } }, PUSH_TEST_SECRET), "INVALID_SIGNATURE"));
  await t.test("mutated body", () => rejectsWithCode(() => normalizeVerifiedPushEvent(withBody(valid, Buffer.from(Buffer.from(valid.body).toString("utf8").replace("ordinary commit message", "mutated commit message"), "utf8")), PUSH_TEST_SECRET), "INVALID_SIGNATURE"));
});

test("wrong event, delivery, repository, ref, deletion, and SHAs fail closed", async (t) => {
  const cases: Array<[string, ReturnType<typeof signedPush>, string]> = [
    ["wrong GitHub event", signedPush({ eventType: "issues" }), "UNEXPECTED_EVENT_TYPE"],
    ["malformed delivery ID", signedPush({ deliveryId: "not-a-guid" }), "MALFORMED_DELIVERY_ID"],
    ["wrong repository ID", signedPush({ repositoryId: 1350596129 }), "WRONG_REPOSITORY"],
    ["wrong repository name", signedPush({ repositoryFullName: "Ticoworld/other-repo" }), "WRONG_REPOSITORY"],
    ["wrong branch", signedPush({ ref: "refs/heads/main" }), "WRONG_REF"],
    ["deleted branch", signedPush({ deleted: true }), "UNSAFE_PUSH"],
    ["invalid before SHA", signedPush({ before: "not-a-sha" }), "MALFORMED_PAYLOAD"],
    ["invalid after SHA", signedPush({ after: "0".repeat(40) }), "MALFORMED_PAYLOAD"],
  ];
  for (const [name, request, code] of cases) await t.test(name, () => rejectsWithCode(() => normalizeVerifiedPushEvent(request, PUSH_TEST_SECRET), code));
});
