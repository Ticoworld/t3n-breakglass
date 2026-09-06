/**
 * Canonical sanitized source-reader lifecycle facts shared by live runners,
 * evidence builders, and offline tests.  This adapter deliberately drops the
 * obsolete read_http_status field so schema drift cannot be repaired by a
 * post-build mutation.
 */
export type B1SourceReaderEvidence = Record<string, unknown>;

export function buildB1SourceReaderEvidence(input: Record<string, unknown>): B1SourceReaderEvidence {
  const { read_http_status: _obsoleteReadStatus, ...safeInput } = input;
  return {
    ...safeInput,
    requested_permissions: input.requested_permissions,
    actual_permissions: input.actual_permissions,
    administration_write_granted: input.administration_write_granted,
    immutable_before_http_status: input.immutable_before_http_status,
    immutable_after_http_status: input.immutable_after_http_status,
    revoke_http_status: input.revoke_http_status,
    refusal_http_status: input.refusal_http_status,
  };
}
