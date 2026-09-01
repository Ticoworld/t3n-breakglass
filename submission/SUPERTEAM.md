# BreakGlass

## Project name

BreakGlass

## One-line description

Incident-bound emergency authority for AI agents.

## Short description

BreakGlass lets an AI agent perform one exact emergency GitHub operation during a specific incident without receiving the GitHub administrative credential. A trusted operator creates a private, short-lived, one-use authority. The agent receives only the incident ID. Terminal 3 resolves the authority, performs and verifies the action, consumes it, and refuses replay.

The live proof revoked one disposable read-only deploy key: GitHub GET `200` before, T3N-reported DELETE `204`, T3N-reported verification GET `404`, independent GitHub GET `404`, authority `CONSUMED` at `1/1`, and replay with zero destructive calls.

## Public links

- GitHub: https://github.com/Ticoworld/t3n-breakglass
- Google Doc: `[PUBLIC_GOOGLE_DOC_URL]`

## Post-challenge maintenance answer

I’m happy to continue developing BreakGlass after the challenge. The current implementation is deliberately limited to one proven emergency action, and the repository includes a handover guide for Terminal 3 or another maintainer if ownership needs to transfer.

## Bug summary

- Reproducible SDK 5.3.0 trust-manifest compatibility issue; exact 5.2.0 pin retained.
- `createAgent` no-card/default-card behavior classified as documentation/API ambiguity.
- Zero-credit organization-owned agents classified as an observed testnet limitation.
- Missing useful span IDs classified as an observed diagnostic limitation.

## Social post

See [`X-POST.md`](X-POST.md). It is a draft only.
