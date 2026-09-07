import assert from "node:assert/strict";
import test from "node:test";
import { freezeLiveExecutionCheckpoint, type LiveExecutionCheckpointFacts } from "../c2/execution-checkpoint.js";

const facts: LiveExecutionCheckpointFacts = {
  starting_sha: "a".repeat(40),
  expected_before_sha: "b".repeat(40),
  expected_main_sha: "c".repeat(40),
  origin_winner_sha: "a".repeat(40),
  origin_main_sha: "c".repeat(40),
  sandbox_before_sha: "b".repeat(40),
  runner_implementation_final: true,
  receiver_implementation_final: true,
  verifier_implementation_final: true,
  tests_passed: true,
  implementation_commit_after_freeze: false,
};

test("live checkpoint freezes only after all readbacks and implementation gates pass", () => {
  assert.deepEqual(freezeLiveExecutionCheckpoint(facts), {
    starting_sha: "a".repeat(40),
    expected_before_sha: "b".repeat(40),
    expected_main_sha: "c".repeat(40),
    origin_winner_sha: "a".repeat(40),
    origin_main_sha: "c".repeat(40),
    sandbox_before_sha: "b".repeat(40),
    implementation_final: true,
    tests_passed: true,
    no_implementation_commit_after_freeze: true,
  });
});

test("checkpoint law rejects stale readbacks and incomplete preflight", () => {
  for (const [name, mutate] of [
    ["winner drift", (value: LiveExecutionCheckpointFacts) => { value.origin_winner_sha = "d".repeat(40); }],
    ["main drift", (value: LiveExecutionCheckpointFacts) => { value.origin_main_sha = "d".repeat(40); }],
    ["baseline drift", (value: LiveExecutionCheckpointFacts) => { value.sandbox_before_sha = "d".repeat(40); }],
    ["runner not final", (value: LiveExecutionCheckpointFacts) => { value.runner_implementation_final = false; }],
    ["receiver not final", (value: LiveExecutionCheckpointFacts) => { value.receiver_implementation_final = false; }],
    ["verifier not final", (value: LiveExecutionCheckpointFacts) => { value.verifier_implementation_final = false; }],
    ["tests incomplete", (value: LiveExecutionCheckpointFacts) => { value.tests_passed = false; }],
    ["post-freeze implementation commit", (value: LiveExecutionCheckpointFacts) => { value.implementation_commit_after_freeze = true; }],
  ] as const) {
    const candidate = { ...facts };
    mutate(candidate);
    assert.throws(() => freezeLiveExecutionCheckpoint(candidate));
  }
});
