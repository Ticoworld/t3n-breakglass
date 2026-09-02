# C1 pre-live crash-point matrix

This matrix classifies safety and recovery, not liveness optimism. A process
crash loses local memory and does not imply that a remote request did not
commit. No row authorizes an automatic second DELETE.

| Boundary | What may be committed/observed | Classification | Required recovery rule |
|---|---|---|---|
| A. before claim | no claim and no provider work | SAFE_RETRY | retry claim; no provider access is reachable |
| B. claim request sent, no result | claim may be committed or absent | SAFE_RECONCILE | read authority/result first; retrying claim is non-destructive and a committed winner re-evaluates as loser |
| C. claim committed, before App JWT | claim held, zero provider work | MANUAL_RECOVERY_REQUIRED | inspect authority and release only with a positive no-DELETE assertion; never mint/DELETE blindly |
| D. App JWT minted, before installation token | JWT may exist only in crashed process; no provider mutation | MANUAL_RECOVERY_REQUIRED | allow JWT expiry/revoke if possible; recover the claim without DELETE retry |
| E. installation token minted, before provider GET | token may exist; no DELETE | MANUAL_RECOVERY_REQUIRED | revoke/read cleanup and release only if the broker knows DELETE was not entered |
| F. provider GET failed before DELETE | no DELETE was entered | SAFE_RETRY | normal code attempts `release-not-attempted`; if the process also crashed, manual release is required |
| G. immediately before DELETE | local boundary says DELETE may have started | MANUAL_RECOVERY_REQUIRED | treat as attempted/ambiguous; no release and no automatic DELETE retry |
| H. DELETE possibly sent, response lost | provider outcome unknown | SAFE_RECONCILE | reads only; consistent absence may verify, otherwise reconcile/manual; zero second DELETE |
| I. DELETE 204 received, before verification | provider acknowledged request, absence not yet independently read | SAFE_RECONCILE | verify with exact GET plus valid list; finalize/reconcile only |
| J. verified absent, before token revoke | effect independently absent; claim still needs finalization | SAFE_RECONCILE | revoke token/finalize; no DELETE |
| K. token revoke succeeds, before T3N finalize | provider classification known; token cleanup complete | SAFE_RECONCILE | retry finalization/reconciliation only; finalization is non-destructive |
| L. finalize request ambiguity | finalization may have committed or rolled back | SAFE_RECONCILE | read authority and retry only the non-destructive finalization/reconciliation path |
| M. CLOSED response received, process dies | terminal `CLOSED` may be committed | SAFE_RECONCILE | read authority; never replay the provider effect |

The one deliberately conservative boundary is G: entering the DELETE function
is enough to make the effect potentially attempted. The implementation sets
`deleteMayHaveBeenInitiated = true` before the call and keeps it true when the
transport throws, so its catch path cannot use `release-not-attempted`.

## Release-not-attempted trust boundary

The contract cannot inspect GitHub. The transition proves only that the caller
is the stored effect broker, that the matching claim is active, that
`effect_attempts` is zero, and that the incident is still in cluster time. It
cannot prove that the broker did not send a network request. Therefore the
transition necessarily relies on an honest effect broker assertion.

The normal broker reaches it only from pre-DELETE paths: App/installation
validation, token mint, installation scope, precheck, or an explicit injected
precheck failure. Once the DELETE boundary is entered, all transport errors,
5xx responses, response loss, and verification failures are treated as
attempted/ambiguous and cannot release the claim.

## Provider ambiguity rules

The fake adapter tests cover `DROP_BEFORE_EFFECT`, `DROP_AFTER_EFFECT`, 204,
404/500 prechecks, 500 after DELETE, verification timeout, and both inconsistent
GET/list observations. A consistent exact 404 plus HTTP-200 well-formed list
without the key may close, including after an ambiguous DELETE. A malformed or
failed list, exact GET 404 with the key still listed, and exact GET 200 with the
key omitted cannot close. Reconciliation performs reads only. The classifier
has no destructive retry path.
