// SPDX-License-Identifier: Apache-2.0
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
  | "AUTH_ISSUED_AT_IMPLAUSIBLE"
  | "AUTH_MISSING_FIELD"
  | "AUTH_ISSUER_MISMATCH"
  | "AUTH_AUDIENCE_MISMATCH"
  | "AUTH_POLICY_ID_MISMATCH"
  | "AUTH_REPLAY"
  | "AUTH_ALG_UNSUPPORTED"
  | "AUTH_KID_UNKNOWN"
  | "AUTH_SIGNATURE_INVALID"
  | "AUTH_TRUST_MISSING"
  | "AUTH_KEY_INACTIVE"
  | "ENVELOPE_SIGNATURE_MISSING"
  | "ENVELOPE_SIGNATURE_INVALID"
  | "ENVELOPE_ALG_UNSUPPORTED"
  | "ENVELOPE_KID_UNKNOWN"
  | "ENVELOPE_TRUST_MISSING"
  | "ENVELOPE_KEY_INACTIVE"
  | "DELEGATION_MISSING_FIELD"
  | "DELEGATION_ALG_UNSUPPORTED"
  | "DELEGATION_SIGNATURE_INVALID"
  | "DELEGATION_KID_UNKNOWN"
  | "DELEGATION_TRUST_MISSING"
  | "DELEGATION_KEY_INACTIVE"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_PARENT_HASH_MISMATCH"
  | "DELEGATION_PARENT_EXPIRED"
  | "DELEGATION_DELEGATOR_MISMATCH"
  | "DELEGATION_POLICY_ID_MISMATCH"
  | "DELEGATION_EXPIRY_EXCEEDS_PARENT"
  | "DELEGATION_AUDIENCE_MISMATCH"
  | "DELEGATION_POLICY_MISMATCH"
  | "DELEGATION_SCOPE_VIOLATION"
  | "DELEGATION_MULTIHOP_DENIED"
  | "DELEGATION_REPLAY"
  | "TRUSTED_KEYSETS_REQUIRED"
  | "KRL_MALFORMED"
  | "KRL_UNSUPPORTED_ALG"
  | "KRL_UNKNOWN_SIGNING_KID"
  | "KRL_SIGNING_KEY_INACTIVE"
  | "KRL_SIG_INVALID"
  | "KRL_EXPIRED"
  | "KRL_VERSION_REGRESSION";

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
  now?: number;
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
  expectedIssuer?: string;
  trustedKeySets?: import("../types/keyset.js").KeySet | readonly import("../types/keyset.js").KeySet[];
  requireSignatureVerification?: boolean;
};
