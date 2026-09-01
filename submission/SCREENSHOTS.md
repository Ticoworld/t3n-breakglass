# BreakGlass Screenshot Plan

Keep the set small. Every screenshot must be captured from sanitized output or a public-safe view. Never show a PAT, operator key, replacement-agent opaque key, private card, SSH private key, or `.env` contents.

## Screenshot 1 — BreakGlass architecture / README hero

Show the README title, one-line explanation, live-proof table, and Mermaid architecture diagram. The frame should make the incident-bound authority and the agent-only `incident_id` boundary legible.

## Screenshot 2 — Incident Authority creation

Show the trusted operator preview before confirmation with:

- incident ID;
- replacement-agent DID;
- action `revoke_github_deploy_key`;
- exact owner/repository/key ID;
- expiry and TTL;
- `ACTIVE` and `0/1`.

Do not show environment variables or any credential-bearing process output.

## Screenshot 3 — Agent execution

Show the sanitized invocation result with the request containing only `incident_id`, the exact target projection, contract-reported DELETE `204`, contract-reported verification `404`, and `CONSUMED`.

## Screenshot 4 — Independent GitHub verification

Show the sanitized independent verification with exact deploy-key GET `404`, list GET `200`, target absent, and list count `0`.

## Screenshot 5 — Replay refusal

Show the second invocation result with `REPLAY_REFUSED`, before/after `CONSUMED`, uses `1/1`, DELETE attempted `false`, and destructive call count `0`.

## Screenshot 6 — T3N organization-owned agent

Show only safe T3N evidence: replacement DID, organization ownership, readable private-card check as a boolean, exact egress host `api.github.com`, contract, and function. Do not show the private card body or agent key.
