/** @public */
export type VerificationStatus = "ok" | "invalid" | "inconclusive";

/** @public */
export type VerificationViolationCode =
  | "MALFORMED_EVENT"
  | "POLICY_ID_MISSING"
  | "POLICY_ID_MISMATCH"
  | "MIXED_POLICY_ID"
  | "NON_MONOTONIC_TIMESTAMP"
  | "HASH_CHAIN_INVALID"
  | "NO_STATE_ANCHOR"
  | "SNAPSHOT_CORRUPT"
  | "ENVELOPE_MALFORMED"
  | "AUTH_DECISION_INVALID"
  | "AUTH_EXPIRED"
  | "AUTH_MISSING_FIELD"
  | "AUTH_ISSUER_MISMATCH"
  | "AUTH_AUDIENCE_MISMATCH"
  | "AUTH_POLICY_ID_MISMATCH"
  | "AUTH_REPLAY";

/** @public */
export type VerificationViolation = {
  code: VerificationViolationCode;
  message?: string;
  index?: number;
};

/** @public */
export type VerificationResult = {
  ok: boolean;
  status: VerificationStatus;
  violations: VerificationViolation[];

  policyId?: string;
  stateHash?: string;
  auditHeadHash?: string;
};

/** @public */
export type VerifyAuditOptions = {
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
  requireStateAnchors?: boolean;
};

/** @public */
export type VerifyEnvelopeOptions = {
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
};
