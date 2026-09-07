export interface LiveExecutionCheckpointFacts {
  starting_sha: string;
  expected_before_sha: string;
  expected_main_sha: string;
  origin_winner_sha: string;
  origin_main_sha: string;
  sandbox_before_sha: string;
  runner_implementation_final: boolean;
  receiver_implementation_final: boolean;
  verifier_implementation_final: boolean;
  tests_passed: boolean;
  implementation_commit_after_freeze: boolean;
}

export interface LiveExecutionCheckpoint {
  starting_sha: string;
  expected_before_sha: string;
  expected_main_sha: string;
  origin_winner_sha: string;
  origin_main_sha: string;
  sandbox_before_sha: string;
  implementation_final: true;
  tests_passed: true;
  no_implementation_commit_after_freeze: true;
}

const SHA = /^[0-9a-f]{40}$/i;

/**
 * Freeze the facts that must be true before the next live run can mutate
 * anything.  This is intentionally a pure contract: the runner supplies
 * read-back facts, while tests and release tooling decide when its boolean
 * readiness assertions are true.
 */
export function freezeLiveExecutionCheckpoint(facts: LiveExecutionCheckpointFacts): LiveExecutionCheckpoint {
  const shaFields = [
    "starting_sha",
    "expected_before_sha",
    "expected_main_sha",
    "origin_winner_sha",
    "origin_main_sha",
    "sandbox_before_sha",
  ] as const;
  for (const field of shaFields) {
    if (!SHA.test(facts[field])) throw new Error(`checkpoint ${field} is not a valid commit SHA`);
  }
  if (facts.origin_winner_sha !== facts.starting_sha) throw new Error("origin winner does not match frozen starting SHA");
  if (facts.origin_main_sha !== facts.expected_main_sha) throw new Error("origin main does not match frozen main SHA");
  if (facts.sandbox_before_sha !== facts.expected_before_sha) throw new Error("sandbox head does not match frozen BEFORE SHA");
  if (!facts.runner_implementation_final || !facts.receiver_implementation_final || !facts.verifier_implementation_final) {
    throw new Error("runner, receiver, and verifier implementation must be final before checkpoint freeze");
  }
  if (!facts.tests_passed) throw new Error("all required tests must pass before checkpoint freeze");
  if (facts.implementation_commit_after_freeze) throw new Error("implementation commit occurred after checkpoint freeze");
  return {
    starting_sha: facts.starting_sha,
    expected_before_sha: facts.expected_before_sha,
    expected_main_sha: facts.expected_main_sha,
    origin_winner_sha: facts.origin_winner_sha,
    origin_main_sha: facts.origin_main_sha,
    sandbox_before_sha: facts.sandbox_before_sha,
    implementation_final: true,
    tests_passed: true,
    no_implementation_commit_after_freeze: true,
  };
}
