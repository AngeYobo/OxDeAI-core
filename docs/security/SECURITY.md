# Security Policy and Threat Model (v1.3.0)

## Status

Non-normative (developer documentation)






Non-normative. Normative protocol definitions are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned). Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.

This document defines OxDeAI protocol security scope, assumptions, and required failure behavior.

## 1. Security Scope

In scope:

- AuthorizationV1 issuance and verification
- signature verification for signed artifacts (all hashes and signature preimages MUST use `canonicalization-v1`)
- replay prevention at relying parties
- issuer/audience/policy/intent/state binding checks
- key selection by issuer+kid+alg

Out of scope:

- transport-layer security
- host compromise prevention
- network key-discovery infrastructure

## 2. Threat Model

Primary threats and required mitigations:

- Artifact forgery
  - Mitigation: Ed25519 signatures; trusted public keys; fail-closed verification.
- Replay and authorization reuse
  - Mitigation: single-use `auth_id`; relying-party consumed-id store.
- Signature confusion across artifact types
  - Mitigation: mandatory domain separation (`OXDEAI_AUTH_V1`, `OXDEAI_ENVELOPE_V1`, `OXDEAI_CHECKPOINT_V1`).
- Unknown key / stale key acceptance
  - Mitigation: issuer-scoped keysets; kid lookup; optional validity windows.
- Issuer confusion
  - Mitigation: explicit trusted-issuer policy at verifier.
- Audience confusion
  - Mitigation: mandatory audience match against relying-party identity.
- Tampered envelope
  - Mitigation: canonical payload verification; signature verification when signed.
- Non-monotonic or malformed audit evidence
  - Mitigation: deterministic verifier checks and invalid status.
- State drift between check and use (TOCTOU)
  - Mitigation: state binding + short TTL + immediate enforcement.
- Compromised signing key
  - Mitigation: key rotation, key revocation status, short TTLs, issuer controls.
- Compromised relying party
  - Mitigation: out of protocol control; deployment hardening required.

## 3. Trust Boundaries

- PDP: policy decision point; issues authorizations.
- PEP: policy enforcement point/relying party; verifies before execution.
- Signer: entity controlling private key for `issuer`.
- Verifier: system validating artifacts using configured `trustedKeySets`.

A relying party MUST NOT trust agent assertions directly.
A relying party MUST trust only valid artifacts under explicitly trusted issuers.

Verifiers MUST configure `trustedKeySets` before invoking strict-mode verification.
`trustedKeySets` is the trust boundary. In strict mode, verification without it MUST fail closed with `TRUSTED_KEYSETS_REQUIRED`.

OxDeAI does not define a global issuer authority.
Any entity that controls a signing key can produce a cryptographically valid artifact.
Cryptographic validity is a necessary but not sufficient condition for trust.
The verifier is solely responsible for deciding which issuers are trusted.

This is a deliberate design choice: OxDeAI enforces the execution boundary; issuer authority is external to the protocol.

## 4. Cryptographic Model

- Preferred algorithm: `Ed25519`.
- Signed payload: canonical encoding of artifact fields excluding `signature`.
- Signature input: `domain_separator || canonical_payload_bytes`.
- Verification is fail-closed.

Requirements:

- custom cryptography MUST NOT be used
- unsupported algorithms MUST fail closed
- ambiguous algorithm handling MUST NOT be permitted

Legacy HMAC verification MAY be supported as explicit compatibility mode.

## 5. Key Management Guidance

- Private signing keys SHOULD be stored in HSM/KMS or equivalent secure custody.
- Private keys MUST NOT be embedded in client applications.
- Issuer identity SHOULD be stable and unique per trust domain.
- `kid` SHOULD be rotated with overlap periods for verifier rollout.
- Keysets SHOULD support multiple active keys during rotation.
- Compromise recovery SHOULD include key revocation, kid retirement, and signer replacement.
- v1.2 key distribution MAY be local/offline; network discovery is optional and external to core protocol.

### Engine Secret Requirements

Implementations MUST enforce:

- minimum length: 32 characters
- no default or fallback values
- explicit configuration via environment or secure storage

The engine MUST fail fast if a valid secret is not provided.

## 6. Replay and TOCTOU Mitigations

Relying parties MUST enforce:

- single-use `auth_id`
- strict `expiry` checks
- intent binding (`intent_hash`)
- state binding (`state_hash`)
- audience binding, and issuer key trust (key resolution is issuer-scoped)
- issuer-policy authority at enforcement boundaries that accept externally supplied
  authorizations: a valid signature does not by itself establish that the issuer may
  issue for the claimed `policy_id` (#301)

Relying parties SHOULD execute immediately after successful verification.
If the execution context changes materially, verification SHOULD be repeated.

## 7. Verification Failure Policy

Verification failures MUST block execution. Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; any `ok/invalid/inconclusive` labels are interface summaries only.

Fail-closed conditions include:

- malformed artifacts
- unknown `alg`
- unknown `kid`
- missing required fields
- invalid signature
- issuer mismatch
- audience mismatch
- policy mismatch when expected
- expired authorization
- replayed `auth_id`
- strict mode invoked without `trustedKeySets` configured (`TRUSTED_KEYSETS_REQUIRED`)

Implementations MUST NOT downgrade invalid artifacts to warnings for execution gating.

### Important Distinction

Verification ensures:

- integrity of the artifact
- authenticity of the signer relative to `trustedKeySets`
- consistency with the evaluated intent and state

Verification does NOT ensure:

- that the policy was correct or legitimate
- that the state was legitimate
- that the issuer is globally authoritative
- that `policyId` originated from a trusted source — `policyId` is not a trust anchor

`policyId` is a content hash of the policy configuration.
It identifies a specific policy but does not authenticate the authority that defined it.
Verifiers MUST NOT treat a matching `policyId` as proof of issuer legitimacy.

These concerns MUST be handled at the deployment level via `trustedKeySets`.


## 8. Test Fixture Key Material

Production private keys MUST NOT be committed.

Cryptographic test fixtures are permitted only in explicit fixture paths and MUST be labeled:

- `TEST ONLY`
- `DO NOT USE IN PRODUCTION`

Deterministic fixtures SHOULD be minimized.
Where deterministic fixtures are not required, tests SHOULD generate ephemeral keypairs at runtime.

Repository scanners and reviewers SHOULD treat fixture-path key material as test scope only, while continuing strict detection for all non-fixture paths.

## 9. Vulnerability Reporting

Report vulnerabilities privately to:

security@oxdeai.dev

Do not disclose publicly before coordinated disclosure.


## 10. Issuer Model and Limitations

OxDeAI separates authorization verification from issuer authority.

Protocol properties:

- Any party that controls a signing key can produce a cryptographically valid artifact. The protocol does not prevent this.
- No global issuer registry exists. There is no built-in mechanism to determine whether an issuer is legitimate.
- No remote policy authority is enforced. `policyId` is a content hash, not a capability issued by a trusted root.
- Verification against `trustedKeySets` is the only mechanism by which the protocol establishes issuer trust.

Normative requirements:

- Verifiers MUST configure `trustedKeySets` when invoking strict-mode verification.
- When `trustedKeySets` is configured, verifiers MUST NOT accept artifacts from issuers not present in the configured set.
- Verifiers MUST NOT treat `policyId` as a trust anchor or as evidence of issuer authority.
- A cryptographically valid artifact from an unconfigured issuer MUST be treated as untrusted.

Production systems MUST:

- restrict accepted issuers via explicitly configured `trustedKeySets`
- isolate signing keys in controlled infrastructure
- treat signing key exposure as a full trust compromise for affected issuers
