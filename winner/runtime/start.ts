import { connectTenant } from "../../scripts/lib.js";

import { createGithubPushSourceReader } from "../c2/push-source-reader.js";
import { BreakGlassCoordinator } from "./coordinator.js";
import { loadRuntimeConfig } from "./config.js";
import { WinnerC1Client, connectRuntimeAgent } from "./c1-client.js";
import { RuntimeJobStore } from "./job-store.js";
import { operationalLog } from "./logger.js";
import { PolicyRegistry } from "./policy-registry.js";

async function main(): Promise<void> {
  const config = loadRuntimeConfig("coordinator");
  const operator = await connectTenant();
  if (operator.tenantDid !== config.operatorDid) throw new Error("T3N_API_KEY resolved to an unexpected operator DID");
  const remediation = await connectRuntimeAgent(config.remediationApiKey!, config.remediationDid);
  const client = new WinnerC1Client({ operatorDid: config.operatorDid, operatorSession: operator.t3n, remediation });
  const coordinator = new BreakGlassCoordinator({
    config,
    registry: new PolicyRegistry(config.paths.root, { stateIntegrityKey: config.stateIntegrityKey }),
    jobs: new RuntimeJobStore(config.paths.jobs, { stateIntegrityKey: config.stateIntegrityKey }),
    c1: client,
    sourceReader: createGithubPushSourceReader(config.app),
  });
  await coordinator.start();
  const shutdown = async () => { await coordinator.stop(); process.exitCode = 0; };
  process.once("SIGINT", () => { void shutdown(); });
  process.once("SIGTERM", () => { void shutdown(); });
}

main().catch((error) => {
  operationalLog("coordinator_failed", { reason: error instanceof Error ? error.message : String(error) });
  process.exitCode = 1;
});
