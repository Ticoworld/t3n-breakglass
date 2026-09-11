import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

import { loadDataDirectory, loadStateIntegrityKey } from "./config.js";
import { PolicyRegistry, policyRegistryInputFromJson } from "./policy-registry.js";

async function main(): Promise<void> {
  const inputFile = process.argv[2] ?? process.env.BREAKGLASS_POLICY_INPUT_FILE;
  if (!inputFile) throw new Error("usage: breakglass:policy:create <policy-input.json>");
  const evidenceFile = process.argv[3] ?? process.env.BREAKGLASS_TRUSTED_POLICY_EVIDENCE;
  if (!evidenceFile) throw new Error("usage: breakglass:policy:create <policy-input.json> <trusted-evidence-file>");
  const input = policyRegistryInputFromJson(JSON.parse(await readFile(inputFile, "utf8")));
  const evidenceBytes = await readFile(evidenceFile);
  const evidenceIdentity = `file:${path.resolve(evidenceFile)}:sha256:${createHash("sha256").update(evidenceBytes).digest("hex")}`;
  const registry = new PolicyRegistry(loadDataDirectory(), { stateIntegrityKey: loadStateIntegrityKey() });
  await registry.initialize();
  const record = await registry.create(input, { trustedEvidenceIdentity: evidenceIdentity });
  process.stdout.write(`${JSON.stringify({ policy_id: record.policy.policy_id, policy_version: record.policy.policy_version, registry_identity: record.registry_identity, activated_at: record.activated_at }, null, 2)}\n`);
}

main().catch((error) => { process.stderr.write(`breakglass policy create failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
