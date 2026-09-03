import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readChildResultBundle, readJsonFile, writeAtomicJson } from "../scripts/result-file.js";

const root = path.resolve(import.meta.dirname, "../..");
const live = await readFile(path.join(root, "winner", "scripts", "c1-live.ts"), "utf8");
const broker = await readFile(path.join(root, "winner", "broker", "run.ts"), "utf8");
const model = await readFile(path.join(root, "winner", "contract", "src", "model.rs"), "utf8");
const wit = await readFile(path.join(root, "winner", "contract", "wit", "world.wit"), "utf8");

test("R6A source exposes the eight-function candidate and committed effect-start boundary", () => {
  for (const name of ["create-incident", "get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "begin-effect", "finalize-effect", "reconcile-effect"]) assert.match(wit, new RegExp(name));
  assert.match(model, /EffectStarted/);
  assert.match(model, /pub fn begin_effect/);
  assert.match(model, /pub expected_claim_version: u64/);
  const begin = broker.indexOf('"begin-effect"');
  const deleteCall = broker.indexOf("deleteKey(token");
  const finalize = broker.indexOf("evidence.finalize = await finalize");
  assert.ok(begin >= 0 && deleteCall > begin && finalize > deleteCall);
  assert.match(broker, /effect_attempts !== 1/);
  assert.match(broker, /beginEffectSent/);
  assert.match(broker, /http_status: null, refused: false, transport_error/);
});

test("R6A replay is gated by a final CLOSED readback", () => {
  const finalReadback = live.indexOf("preReplayReadbackResponse");
  const terminalGate = live.indexOf("requireReplayTerminal(preReplayAuthority)");
  const replay = live.indexOf("const replayEnv");
  assert.ok(finalReadback >= 0 && terminalGate > finalReadback && replay > terminalGate);
  assert.match(live, /replay is forbidden before independently verified CLOSED authority/);
  assert.match(live, /postReplayReadbackResponse/);
});

test("R6A child outcomes are atomically durable and parent reads persisted results", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "breakglass-c1-r6a-result-"));
  const resultPath = path.join(directory, "broker-a.result.json");
  try {
    await writeAtomicJson(resultPath, { claim_outcome: "CLAIM_WON", claim_id: "claim-1", token_minted: true, destructive_call_count: 1, delete_attempted: true });
    assert.deepEqual(await readJsonFile(resultPath), { claim_outcome: "CLAIM_WON", claim_id: "claim-1", token_minted: true, destructive_call_count: 1, delete_attempted: true });
    assert.match(broker, /C1_RESULT_FILE/);
    assert.match(broker, /writeAtomicJson\(resultFile, evidence\)/);
    assert.match(broker, /evidenceForFailure/);
    assert.match(live, /readJsonFile<Record<string, unknown>>\(brokerBResultFile\)/);
    assert.match(live, /persisted_child_results/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("claim generation fence rejects stale release-era contenders", () => {
  type State = { status: "RESERVED" | "EFFECT_CLAIMED" | "READY_RETRY"; generation: number; claim?: string };
  const state: State = { status: "RESERVED", generation: 0 };
  const claim = (expected: number, id: string) => {
    if (state.status !== "RESERVED" && state.status !== "READY_RETRY") return false;
    if (expected !== state.generation) return false;
    state.generation += 1;
    state.claim = id;
    state.status = "EFFECT_CLAIMED";
    return true;
  };
  assert.equal(claim(0, "A"), true);
  state.status = "READY_RETRY";
  state.claim = undefined;
  assert.equal(claim(0, "stale-B"), false);
  assert.equal(claim(1, "fresh-C"), true);
});

test("local concurrency model covers stale, refreshed, and consumed generations", () => {
  type State = { status: "RESERVED" | "EFFECT_CLAIMED" | "READY_RETRY" | "EFFECT_STARTED"; generation: number; attempts: number; claim?: string };
  const state: State = { status: "RESERVED", generation: 0, attempts: 0 };
  const snapshot = () => ({ status: state.status, generation: state.generation });
  const claim = (observed: { status: string; generation: number }, id: string) => {
    if ((state.status !== "RESERVED" && state.status !== "READY_RETRY") || observed.generation !== state.generation) return false;
    state.generation += 1;
    state.claim = id;
    state.status = "EFFECT_CLAIMED";
    return true;
  };
  const first = snapshot();
  const stale = snapshot();
  assert.equal(claim(first, "A"), true);
  assert.equal(claim(stale, "B"), false);
  state.status = "READY_RETRY";
  state.claim = undefined;
  assert.equal(claim(stale, "stale-B"), false);
  const refreshed = snapshot();
  assert.equal(claim(refreshed, "fresh-C"), true);
  state.status = "EFFECT_STARTED";
  state.attempts = 1;
  const afterBegin = snapshot();
  assert.equal(claim(afterBegin, "D"), false);
  assert.equal(state.attempts, 1);
});

test("parent failure evidence consumes durable broker and replay result files", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "breakglass-c1-r6a-parent-"));
  const failure = path.join(directory, "parent-failure.json");
  try {
    await writeAtomicJson(path.join(directory, "broker-a.result.json"), { claim_outcome: "CLAIM_WON", claim_id: "claim-a", token_minted: true, destructive_call_count: 1 });
    await writeAtomicJson(path.join(directory, "broker-b.result.json"), { claim_outcome: "CLAIM_LOST", token_minted: false, destructive_call_count: 0 });
    await writeAtomicJson(path.join(directory, "replay.result.json"), { claim_outcome: "CLAIM_LOST", token_minted: false, destructive_call_count: 0 });
    await writeAtomicJson(failure, { status: "C1_FAIL", persisted_child_results: await readChildResultBundle(directory), credentials_in_evidence: false });
    const persisted = (await readJsonFile<{ persisted_child_results: Record<string, any> }>(failure)).persisted_child_results;
    assert.equal(persisted.broker_a.claim_id, "claim-a");
    assert.equal(persisted.broker_b.claim_outcome, "CLAIM_LOST");
    assert.equal(persisted.replay.claim_outcome, "CLAIM_LOST");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("candidate runner cannot use the old final replay-before-readback order", () => {
  assert.ok(live.indexOf("const preReplayReadbackResponse") < live.indexOf("const replayPromise"));
  assert.equal(live.includes("parseChildJson(a.stdout)"), false);
  assert.equal(live.includes("parseChildJson(b.stdout)"), false);
  assert.equal(live.includes("parseChildJson(replay.stdout)"), false);
});
