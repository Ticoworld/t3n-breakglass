import { discoverWhoami, getNodeUrl, invoke, setEnvironment } from "@terminal3/t3n-sdk";

import { CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { invokeC1OperatorSession } from "../scripts/t3n.js";

export interface C1Principal {
  apiKey: string;
  nodeUrl: string;
  did: string;
}

export interface C1OperatorSession {
  executeAndDecode(payload: unknown): Promise<unknown>;
}

export interface C1CallTransport {
  call(contractId: string, functionName: string, input: unknown): Promise<unknown>;
}

export function principalTransport(principal: C1Principal): C1CallTransport {
  return {
    call(contractId, functionName, input) {
      return invoke({
        baseUrl: principal.nodeUrl,
        apiKey: principal.apiKey,
        request: { contract_id: contractId, contract_version: CONTRACT_VERSION, function_name: functionName, input },
      });
    },
  };
}

export function operatorTransport(session: C1OperatorSession): C1CallTransport {
  return {
    call(contractId, functionName, input) {
      return invokeC1OperatorSession(session, contractId, functionName, input);
    },
  };
}

export class WinnerC1Client {
  readonly contractId: string;
  readonly operator: C1CallTransport;
  readonly remediation?: C1CallTransport;
  readonly broker?: C1CallTransport;

  constructor(options: {
    operatorDid: string;
    operatorSession: C1OperatorSession;
    remediation?: C1Principal;
    broker?: C1Principal;
  }) {
    this.contractId = contractName(options.operatorDid);
    this.operator = operatorTransport(options.operatorSession);
    this.remediation = options.remediation ? principalTransport(options.remediation) : undefined;
    this.broker = options.broker ? principalTransport(options.broker) : undefined;
  }

  private requireRemediation(): C1CallTransport { if (!this.remediation) throw new Error("remediation principal is not connected in this process"); return this.remediation; }
  private requireBroker(): C1CallTransport { if (!this.broker) throw new Error("broker principal is not connected in this process"); return this.broker; }

  createIncident(request: unknown): Promise<unknown> {
    return this.operator.call(this.contractId, "create-incident", request);
  }

  getIncident(incidentId: string): Promise<unknown> {
    return this.operator.call(this.contractId, "get-incident", { incident_id: incidentId });
  }

  reserveIncident(incidentId: string): Promise<unknown> {
    return this.requireRemediation().call(this.contractId, "reserve-incident", { incident_id: incidentId });
  }

  claimEffect(incidentId: string, expectedClaimVersion: number, contenderNonce: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "claim-effect", {
      incident_id: incidentId,
      expected_claim_version: expectedClaimVersion,
      contender_nonce: contenderNonce,
    });
  }

  confirmClaim(incidentId: string, claimId: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "confirm-claim", {
      incident_id: incidentId,
      claim_id: claimId,
    });
  }

  beginEffect(incidentId: string, claimId: string, startNonce: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "begin-effect", {
      incident_id: incidentId,
      claim_id: claimId,
      start_nonce: startNonce,
    });
  }

  confirmEffectStart(incidentId: string, claimId: string, effectStartId: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "confirm-effect-start", {
      incident_id: incidentId,
      claim_id: claimId,
      effect_start_id: effectStartId,
    });
  }

  finalizeEffect(incidentId: string, claimId: string, effectStartId: string, classification: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "finalize-effect", {
      incident_id: incidentId,
      claim_id: claimId,
      effect_start_id: effectStartId,
      classification,
    });
  }

  reconcileEffect(incidentId: string, claimId: string, effectStartId: string, classification: string): Promise<unknown> {
    return this.requireBroker().call(this.contractId, "reconcile-effect", {
      incident_id: incidentId,
      claim_id: claimId,
      effect_start_id: effectStartId,
      classification,
    });
  }
}

export function asC1Object(raw: unknown): Record<string, unknown> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("C1 response was not an object");
  return value as Record<string, unknown>;
}

export function c1State(raw: unknown): string | null {
  const value = asC1Object(raw);
  return typeof value.state === "string" ? value.state : null;
}

export function c1Detail(raw: unknown): Record<string, unknown> {
  const value = asC1Object(raw);
  return value.detail && typeof value.detail === "object" && !Array.isArray(value.detail)
    ? value.detail as Record<string, unknown>
    : {};
}

/** Runtime-only agent connection; it receives only its own C1 key and DID. */
export async function connectRuntimeAgent(apiKey: string, expectedDid: string): Promise<C1Principal> {
  if (!apiKey || !expectedDid) throw new Error("remediation principal configuration is incomplete");
  if (process.env.GITHUB_PAT) throw new Error("runtime remediation process refuses GITHUB_PAT");
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  if (whoami.did !== expectedDid) throw new Error("remediation key resolved to an unexpected DID");
  return { apiKey, nodeUrl, did: whoami.did };
}
