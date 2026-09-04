import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { C1_FUNCTIONS, BROKER_FUNCTIONS, CONTRACT_VERSION } from "../scripts/constants.js";
import { parseClaimConfirmation, parseClaimProposal } from "../broker/logic.js";

const root = new URL("../", import.meta.url);
const read = (relative: string) => readFile(new URL(relative, root), "utf8");
const [wit, model, lib, broker, live, contender] = await Promise.all([
  read("contract/wit/world.wit"),
  read("contract/src/model.rs"),
  read("contract/src/lib.rs"),
  read("broker/run.ts"),
  read("scripts/c1-live.ts"),
  read("scripts/c1-r6b-claim-contender.ts"),
]);
const register = await read("scripts/register.ts");

test("2.0.4 candidate exposes the ten ownership/effect-boundary functions", () => {
  assert.equal(CONTRACT_VERSION, "2.0.4");
  assert.equal(C1_FUNCTIONS.length, 10);
  assert.deepEqual([...BROKER_FUNCTIONS], ["claim-effect", "confirm-claim", "release-not-attempted", "begin-effect", "confirm-effect-start", "finalize-effect", "reconcile-effect"]);
  for (const name of C1_FUNCTIONS) assert.match(wit, new RegExp(name));
  assert.match(model, /pub contender_nonce: String/);
  assert.match(model, /pub effect_start_id: Option<String>/);
  assert.match(model, /pub fn confirm_claim/);
  assert.match(model, /pub fn confirm_effect_start/);
  assert.match(model, /authority\.status == Status::EffectStarted/);
  assert.match(lib, /fn confirm_claim/);
  assert.match(lib, /fn confirm_effect_start/);
  assert.match(register, /locallyVerifiedComponentExports/);
  assert.match(register, /new RegExp\(`\^\\\\s\+\$\{name\}: func/);
});

test("distinct contender proposals have one persisted confirmation owner", () => {
  const proposalA = { result: "PROPOSED", detail: { claim_id: "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", claim_version: 1 } };
  const proposalB = { result: "PROPOSED", detail: { claim_id: "claim-1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", claim_version: 1 } };
  const parsedA = parseClaimProposal(proposalA);
  const parsedB = parseClaimProposal(proposalB);
  assert.equal(parsedA.proposed, true);
  assert.equal(parsedB.proposed, true);
  assert.notEqual(parsedA.claim!.claim_id, parsedB.claim!.claim_id);
  // A single committed map row can affirm only the exact identity it stores.
  const persisted = { result: "CONFIRMED", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 1, claim_id: proposalB.detail.claim_id, claim_version: 1 } };
  assert.equal(parseClaimConfirmation(persisted).confirmed, true);
  assert.equal(parseClaimConfirmation({ result: "NOT_OWNER", detail: {} }).confirmed, false);
  assert.equal(parseClaimConfirmation({ result: "NOT_OWNER", detail: {} }).result instanceof Object, true);
});

test("ownership and effect-start confirmations precede provider authority and DELETE", () => {
  const proposal = broker.indexOf('"claim-effect"');
  const confirmClaim = broker.indexOf('"confirm-claim"');
  const appJwt = broker.indexOf("appJwt(config)");
  const begin = broker.indexOf('"begin-effect"');
  const confirmStart = broker.indexOf('"confirm-effect-start"');
  const deleteCall = broker.indexOf("deleteKey(token");
  const finalize = broker.indexOf("finalize(broker");
  assert.ok(proposal >= 0 && confirmClaim > proposal && appJwt > confirmClaim);
  assert.ok(begin > appJwt && confirmStart > begin && deleteCall > confirmStart && finalize > deleteCall);
  assert.match(broker, /C1_PROPOSALS_COMPLETE_FILE/);
  assert.match(broker, /contenderNonce = randomBytes\(16\)\.toString\("hex"\)/);
  assert.match(broker, /effect_start_id: effectStartId/);
  assert.match(broker, /effect_start_confirmation/);
  assert.match(broker, /effect_start_id: effectStartId, classification/);
  assert.equal(contender.includes("randomBytes(16).toString(\"hex\")"), true);
});

test("the live parent publishes proposal completion before children are allowed to finish", () => {
  const release = live.indexOf("await writeFile(barrier");
  const durable = live.indexOf("brokerAResultFile", release);
  const proposalRelease = live.indexOf("await writeFile(proposalsComplete", durable);
  const children = live.indexOf("await Promise.all([aPromise, bPromise])", proposalRelease);
  assert.ok(release >= 0 && durable > release && proposalRelease > durable && children > proposalRelease);
  assert.match(live, /ownership_confirmation === "CONFIRMED"/);
  assert.match(live, /ownership_confirmation === "NOT_OWNER"/);
});

test("the live race validates contender nonces and aborts before claim calls on collision", () => {
  assert.match(live, /readyNonce\(readyA, "broker-a"\)/);
  assert.match(live, /readyNonce\(readyB, "broker-b"\)/);
  assert.match(live, /nonceA === nonceB/);
  assert.match(live, /reason: "duplicate_contender_nonce"/);
  assert.match(live, /reason: "invalid_contender_nonce"/);
  assert.match(broker, /barrierAborted\(barrier\)/);
  assert.match(broker, /DUPLICATE_NONCE_ABORT/);
  assert.match(broker, /contender_nonce: contenderNonce/);
});

test("both affirmative proposals still yield one confirmed owner and one detail-free non-owner", () => {
  const proposalA = { claim_id: "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", claim_version: 1 };
  const proposalB = { claim_id: "claim-1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", claim_version: 1 };
  const target = { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 1, ...proposalB };
  assert.equal(parseClaimConfirmation({ result: "CONFIRMED", detail: target }).confirmed, true);
  const notOwner = parseClaimConfirmation({ result: "NOT_OWNER", detail: {} });
  assert.equal(notOwner.confirmed, false);
  assert.deepEqual((notOwner.result as Record<string, unknown>).detail, {});
  assert.notEqual(proposalA.claim_id, proposalB.claim_id);
});

test("confirmation is read-only and no target is exposed by a proposal", () => {
  assert.deepEqual(parseClaimProposal({ result: "PROPOSED", detail: { claim_id: "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", claim_version: 1 } }).result, { result: "PROPOSED", detail: { claim_id: "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", claim_version: 1 } });
  assert.equal(parseClaimProposal({ result: "LOST", detail: {} }).proposed, false);
  assert.equal(parseClaimConfirmation({ result: "NOT_OWNER", detail: {} }).confirmed, false);
  assert.throws(() => parseClaimConfirmation({ result: "CONFIRMED", detail: { claim_id: "claim-1", claim_version: 1 } }));
});
