// SPDX-License-Identifier: Apache-2.0

/**
 * A signed Key Revocation List (KRL) artifact — provider-neutral OxDeAI protocol type.
 *
 * Signed with an Ed25519 key whose trust is configured statically at the verifier.
 * The signing payload is produced by `signedKrlSigningPayload()` and must be signed with
 * `signatureInput(SIGNING_DOMAINS.KRL_V1, payload)` as the preimage.
 *
 * @public
 */
export type SignedKRLV1 = {
  version: "SignedKRLV1";
  issuer: string;
  /** Non-negative safe integer. Must strictly increase across successive KRLs for the same issuer. */
  krl_version: number;
  /** Unix seconds. Informational only in v1 — verifiers do not enforce a lower bound. */
  issued_at: number;
  /** Unix seconds. Strict zero-tolerance expiry: valid iff now < not_after. */
  not_after: number;
  /** Revoked key IDs. Must be deduplicated by the producer; verifier rejects duplicates as KRL_MALFORMED. */
  revoked_kids: string[];
  /** Optional replay-prevention nonce. Included in the signing payload when present. */
  nonce?: string;
  signature: {
    alg: "Ed25519";
    kid: string;
    sig: string;
  };
};

/**
 * Options for `verifySignedKrl`.
 *
 * @public
 */
export type VerifySignedKrlOptions = {
  /** Current unix seconds. Falls back to `Date.now() / 1000` if absent. */
  now?: number;
  /** Trusted KRL signing key sets. Identified by issuer + kid. */
  trustedKeySets?: import("./keyset.js").KeySet | readonly import("./keyset.js").KeySet[];
  /**
   * Per-issuer high-watermark for krl_version.
   * If `envelope.krl_version < previousKrlVersionByIssuer[envelope.issuer]`, the verifier
   * returns KRL_VERSION_REGRESSION. This is injected state only — no persistent storage.
   */
  previousKrlVersionByIssuer?: Readonly<Record<string, number>>;
};
