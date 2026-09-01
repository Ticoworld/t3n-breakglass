import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectPrincipal, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

type Balance = {
  available: number;
  reserved: number;
  last_settled_seq_no: number;
  version: number;
  credit_exhausted: boolean;
};

function sanitizeBalance(balance: Balance) {
  return {
    available_base_units: balance.available,
    reserved_base_units: balance.reserved,
    last_settled_seq_no: balance.last_settled_seq_no,
    version: balance.version,
    credit_exhausted: balance.credit_exhausted,
  };
}

async function checkAccount(label: string, apiKeyEnv: string) {
  const principal = await connectPrincipal(apiKeyEnv);
  const balance = await principal.t3n.getBalance();
  return {
    label,
    api_key_env: apiKeyEnv,
    did: principal.did,
    node_url: principal.nodeUrl,
    balance: sanitizeBalance(balance),
  };
}

async function main() {
  if (process.env.GITHUB_PAT) {
    throw new Error("account balance check refuses a GitHub PAT in its environment");
  }

  const secrets = [process.env.T3N_API_KEY ?? "", process.env.T3N_API_KEY_ALT ?? ""];
  const operator = await checkAccount("current_operator", "T3N_API_KEY");
  const alternatePresent = Boolean(process.env.T3N_API_KEY_ALT);
  const alternate = alternatePresent
    ? await checkAccount("alternate_account", "T3N_API_KEY_ALT")
    : null;

  const evidence = {
    phase: "1",
    stage: "safe_account_authentication_and_balance_check",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    trusted_manifest_flow: "fetchTrustedManifest(testnet)",
    mutation_scope: {
      contract_registration: 0,
      contract_mutations: 0,
      github_destructive_calls: 0,
    },
    current_operator: operator,
    alternate_account: alternate,
    alternate_key_present: alternatePresent,
    same_did_as_current_operator: alternate ? alternate.did === operator.did : null,
    fresh_account_tested: alternatePresent,
    github_pat_in_process: false,
    t3n_api_key_values_recorded: false,
  };

  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(
    path.join(root, "evidence", "phase1-account-comparison.json"),
    JSON.stringify(evidence, null, 2) + "\n",
  );
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(
    `account balance check failed: ${redactError(error, [
      process.env.T3N_API_KEY ?? "",
      process.env.T3N_API_KEY_ALT ?? "",
    ])}`,
  );
  process.exitCode = 1;
});
