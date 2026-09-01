# BreakGlass Competitive Notes

Internal submission material. This is not public-facing competitor criticism.

BreakGlass is not primarily a generic external tool-call gateway, an ordinary human approval gate, a secret vault, or a release gate. Those categories may provide useful adjacent controls, but they do not describe the core primitive proven here.

The differentiator is that an incident creates a temporary authority object binding:

```text
WHO          -> one authenticated agent DID
WHAT ACTION  -> revoke_github_deploy_key
WHAT TARGET  -> one exact repository and deploy-key ID
UNTIL WHEN   -> trusted-time expiry
HOW MANY     -> one use
```

The agent receives no underlying administrative credential and cannot widen the authority. One successful emergency execution consumes it. A replay is refused before another destructive call.
