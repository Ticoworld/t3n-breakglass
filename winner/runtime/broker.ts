import { BreakGlassBrokerWorker } from "./broker-worker.js";
import type { BrokerWorkerAdapters } from "./broker-worker.js";
import { loadRuntimeConfig } from "./config.js";
import { RuntimeJobStore } from "./job-store.js";
import { PolicyRegistry } from "./policy-registry.js";

export interface BrokerServiceOptions {
  env?: NodeJS.ProcessEnv;
  adapters?: BrokerWorkerAdapters;
  once?: boolean;
}

/**
 * The package command and offline child tests both enter here.  Only the
 * transport adapters are injectable; config loading, job persistence, worker
 * routing, and the broker state machine remain the production path.
 */
export async function runBrokerService(options: BrokerServiceOptions = {}): Promise<void> {
  const env = options.env ?? process.env;
  const config = loadRuntimeConfig("broker", env);
  const worker = new BreakGlassBrokerWorker(config, new RuntimeJobStore(config.paths.jobs, { stateIntegrityKey: config.stateIntegrityKey }), new PolicyRegistry(config.paths.root, { stateIntegrityKey: config.stateIntegrityKey }), options.adapters);
  await worker.start();
  if (options.once) { await worker.stop(); return; }
  const shutdown = async () => { await worker.stop(); process.exitCode = 0; };
  process.once("SIGINT", () => { void shutdown(); });
  process.once("SIGTERM", () => { void shutdown(); });
}

if (process.argv[1] && process.argv[1].replaceAll("\\", "/").endsWith("/winner/runtime/broker.ts")) {
  runBrokerService().catch((error) => {
    console.error(JSON.stringify({ event: "broker_failed", reason: error instanceof Error ? error.message : String(error) }));
    process.exitCode = 1;
  });
}
