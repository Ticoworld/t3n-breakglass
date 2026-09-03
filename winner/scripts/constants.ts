export const CONTRACT_TAIL = "breakglass-winner-c1";
export const CONTRACT_VERSION = "2.0.2";
export const INCIDENT_MAP_TAIL = "winner-incidents";
export const ACTION = "revoke_github_deploy_key";
export const GITHUB_HOST = "api.github.com";
export const GITHUB_REPOSITORY = "t3n-breakglass-sandbox";
export const GITHUB_OWNER = "Ticoworld";
export const ORGANISATION_DID = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";

export const RESERVATION_FUNCTION = "reserve-incident";
export const BROKER_FUNCTIONS = [
  "claim-effect",
  "release-not-attempted",
  "finalize-effect",
  "reconcile-effect",
] as const;

export function contractName(operatorDid: string): string {
  if (!/^did:t3n:[0-9a-f]{40}$/i.test(operatorDid)) throw new Error("invalid operator DID");
  return `z:${operatorDid.slice("did:t3n:".length).toLowerCase()}:${CONTRACT_TAIL}`;
}
