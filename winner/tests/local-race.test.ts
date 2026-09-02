import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const root = path.resolve(import.meta.dirname, "../..");
const child = path.join(root, "winner", "tests", "local-race-child.ts");

function runChild(directory: string, contender: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const processChild = spawn(process.execPath, ["--import", "tsx", child, directory, contender], { cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    processChild.stdout.on("data", (chunk) => { stdout += String(chunk); });
    processChild.stderr.on("data", (chunk) => { stderr += String(chunk); });
    processChild.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

test("two separate broker processes produce exactly one local claim winner", async () => {
  const iterations = 32;
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const directory = await mkdtemp(path.join(os.tmpdir(), "breakglass-c1-race-"));
    try {
      await writeFile(path.join(directory, "state.json"), JSON.stringify({ status: "RESERVED" }));
      const aPromise = runChild(directory, "broker-a");
      const bPromise = runChild(directory, "broker-b");
      while (true) {
        try {
          await Promise.all([readFile(path.join(directory, "broker-a.ready")), readFile(path.join(directory, "broker-b.ready"))]);
          break;
        } catch { await new Promise((resolve) => setTimeout(resolve, 1)); }
      }
      await writeFile(path.join(directory, "barrier"), "release");
      const [a, b] = await Promise.all([aPromise, bPromise]);
      assert.equal(a.code, 0, `${a.stderr} ${a.stdout}`);
      assert.equal(b.code, 0, `${b.stderr} ${b.stdout}`);
      const results = [JSON.parse(a.stdout), JSON.parse(b.stdout)] as Array<Record<string, any>>;
      assert.notEqual(results[0].pid, results[1].pid, "contenders must be separate processes");
      assert.equal(results.filter((result) => result.claim_outcome === "CLAIM_WON").length, 1);
      assert.equal(results.filter((result) => result.claim_outcome === "CLAIM_LOST").length, 1);
      assert.equal(results.reduce((sum, result) => sum + result.token_mint_count, 0), 1);
      assert.equal(results.reduce((sum, result) => sum + result.destructive_delete_count, 0), 1);
      const winner = results.find((result) => result.claim_outcome === "CLAIM_WON")!;
      const loser = results.find((result) => result.claim_outcome === "CLAIM_LOST")!;
      assert.deepEqual(winner.events.slice(0, 2), ["CLAIM_REQUEST", "CLAIM_COMMITTED_WON"]);
      assert.deepEqual(loser.events, ["CLAIM_REQUEST", "CLAIM_LOST"]);
      assert.equal(loser.token_mint_count, 0);
      assert.equal(loser.destructive_delete_count, 0);
      assert.equal(JSON.parse(await readFile(path.join(directory, "state.json"), "utf8")).winner, winner.contender);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});
