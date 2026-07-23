// SPDX-License-Identifier: Apache-2.0
/** @public */
export type VerificationStatus = "ok" | "invalid" | "inconclusive";

/**
 * How signature verification was performed, independent of the outcome.
 *
 * This describes the verification *posture* actually applied, and is distinct
 * from the `mode` request option (`"strict" | "best-effort"`) passed into a
 * verifier:
 *
 * - `"strict"`          — strict verification was requested (a trusted key set
 *                         is mandatory and full cryptographic verification is
 *                         enforced).
 * - `"permissive"`      — best-effort verification in which a cryptographic
 *                         signature check was actually engaged.
 * - `"structure-only"`  — no cryptographic signature verification was engaged;
 *                         only structural / semantic checks ran.
 *
 * A `"structure-only"` result must never be mistaken for a cryptographically
 * verified one — inspect {@link VerificationResult.signatureVerified}.
 *
 * @public
 */
export type VerificationMode = "strict" | "permissive" | "structure-only";

/**
 * Which authorization surface a signature check actually covered.
 *
 * - `"authorization-v1-full"` — the full normative AuthorizationV1 signing
 *                               payload was cryptographically verified.
 * - `"engine-hmac-subset"`    — only the engine-HMAC field subset was
 *                               authenticated (see `PolicyEngine.verifyAuthorization`);
 *                               this is NOT full authorization verification.
 * - `"none"`                  — no cryptographic coverage.
 *
 * @public
 */
export type VerificationCoverage =
  | "authorization-v1-full"
  | "engine-hmac-subset"
  | "none";

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

  /**
   * Whether a cryptographic signature verification actually ran AND succeeded.
   *
   * This is `true` only when a real cryptographic check executed and passed —
   * never for a result that was merely structurally or semantically validated.
   * It is orthogonal to `ok`: a validly-signed but expired authorization has
   * `signatureVerified: true` and `ok: false`.
   *
   * Optional on the shared result type so verifiers that do not perform a
   * signature check can omit it; verifiers that expose a signature surface
   * (e.g. {@link AuthorizationVerificationResult}) always populate it.
   */
  signatureVerified?: boolean;

  /** How verification was performed. See {@link VerificationMode}. */
  verificationMode?: VerificationMode;

  /** Which authorization surface the signature check covered. See {@link VerificationCoverage}. */
  verificationCoverage?: VerificationCoverage;
};

/**
 * Result of {@link verifyAuthorization}.
 *
 * A specialization of {@link VerificationResult} in which the
 * verification-surface descriptors are ALWAYS populated, so a caller can never
 * mistake a structurally-checked authorization for a cryptographically verified
 * one. To decide whether to rely on an authorization, check `signatureVerified`
 * (and `verificationCoverage`), not merely `ok`.
 *
 * @public
 */
export type AuthorizationVerificationResult = VerificationResult & {
  signatureVerified: boolean;
  verificationMode: VerificationMode;
  verificationCoverage: VerificationCoverage;
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
