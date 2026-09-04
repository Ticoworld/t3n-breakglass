import { mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { writeAtomicJson } from "../scripts/result-file.js";

const [directory, contender] = process.argv.slice(2);
if (!directory || !contender) throw new Error("local-race-child requires a directory and contender id");

const barrier = path.join(directory, "barrier");
const proposalBarrier = path.join(directory, "proposals.complete");
const ready = path.join(directory, `${contender}.ready`);
const stateFile = path.join(directory, "state.json");
const lockDirectory = path.join(directory, "commit.lock");
const proposalFile = path.join(directory, `${contender}.proposal.json`);
const resultFile = path.join(directory, `${contender}.result.json`);

async function waitFor(file: string): Promise<void> {
  while (true) {
    try { await open(file, "r").then((handle) => handle.close()); return; }
    catch { await new Promise((resolve) => setTimeout(resolve, 1)); }
  }
}

async function withCommitLock<T>(work: () => Promise<T>): Promise<T> {
  while (true) {
    try {
      await mkdir(lockDirectory);
      try { return await work(); }
      finally { await rm(lockDirectory, { recursive: true, force: true }).catch(() => undefined); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
  }
}

const initial = JSON.parse(await readFile(stateFile, "utf8")) as { status: string; winner?: string };
const contenderNonce = `${contender}-local-nonce`;
await writeFile(ready, JSON.stringify({ contender, pid: process.pid }));
await waitFor(barrier);
const events: string[] = ["CLAIM_REQUEST"];
await writeAtomicJson(proposalFile, { contender, pid: process.pid, contender_nonce: contenderNonce, expected_claim_version: 0 });
await waitFor(proposalBarrier);
const committed = await withCommitLock(async () => {
  const current = JSON.parse(await readFile(stateFile, "utf8")) as { status: string; winner?: string };
  if (current.status !== "RESERVED") return { won: false, re_evaluated_status: current.status, winner: current.winner ?? null };
  await writeFile(stateFile, JSON.stringify({ status: "EFFECT_CLAIMED", winner: contender, claim_id: `claim-${contender}-1`, claim_version: 1 }));
  return { won: true, re_evaluated_status: current.status, winner: contender };
});

if (committed.won) {
  events.push("CLAIM_PROPOSAL_COMMITTED", "CLAIM_CONFIRM_CONFIRMED", "APP_JWT_MINT", "INSTALLATION_TOKEN_MINT", "PROVIDER_GET", "BEGIN_EFFECT_COMMITTED", "EFFECT_START_CONFIRM_CONFIRMED", "PROVIDER_DELETE", "PROVIDER_VERIFY", "TOKEN_REVOKE", "FINALIZE");
} else {
  events.push("CLAIM_CONFIRM_NOT_OWNER", "CLAIM_LOST");
}
const result = { contender, pid: process.pid, contender_nonce: contenderNonce, expected_claim_version: 0, initial_observed_status: initial.status, ...committed, claim_outcome: committed.won ? "CLAIM_WON" : "CLAIM_LOST", ownership_confirmation: committed.won ? "CONFIRMED" : "NOT_OWNER", claim_id: committed.won ? `claim-${contender}-1` : null, claim_version: committed.won ? 1 : null, token_mint_count: committed.won ? 1 : 0, destructive_delete_count: committed.won ? 1 : 0, events };
await writeAtomicJson(resultFile, result);
process.stdout.write(JSON.stringify(result));
