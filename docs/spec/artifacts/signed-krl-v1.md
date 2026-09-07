# SignedKRLV1 Specification

**Version:** v1.0
**Patch:** Patch A - artifact definition and pure verifier only
**Status:** Draft  
**Depends on:** `canonicalization-v1.md`, `authorization-v1.md §17` (clock model)

---

## 1. Purpose

`SignedKRLV1` is a provider-neutral OxDeAI Key Revocation List artifact.

It allows a KRL publisher to cryptographically commit to a set of revoked key IDs and expiry semantics, such that any verifier with the appropriate trusted KRL signing public key can verify the list independently, without network trust, transport-layer integrity assumptions, or shared secrets.

### Protocol objective

The complete SignedKRL integration is intended to enforce the following end-to-end invariant:

```text
revoked provider key
-> must not be accepted
-> no AuthorizationV1 bridge
-> no execution path
```

Patch A does **not** by itself establish this end-to-end execution invariant.

Patch A defines:

- the `SignedKRLV1` artifact
- its signing construction
- its trusted-time semantics
- its pure verification rules
- portable conformance evidence

Enforcement of a successful KRL verification result inside a provider keystore or execution path is deferred to Patch B.

`SignedKRLV1` closes the integrity gap of an unsigned KRL whose authenticity depends entirely on transport security. A signed KRL can be authenticated independently after delivery.

---

## 2. Provider-neutral scope

`SignedKRLV1` is a standalone OxDeAI protocol artifact.

It is independent of:

- any specific provider, including Sift or OpenAI
- the `AuthorizationV1` signing key
- the `DelegationV1` signing key

The KRL signing key is a **distinct trust domain**.

Verifiers MUST be configured with a trusted KRL signing key set that is separate from authorization and delegation signing key sets.

The trust anchor used to verify a KRL MUST NOT depend on a live network fetch during verification.

---

## 3. Artifact shape

```json
{
  "version": "SignedKRLV1",
  "issuer": "krl-authority.example.com",
  "krl_version": 42,
  "issued_at": 1712448000,
  "not_after": 1712534400,
  "revoked_kids": ["key-id-1", "key-id-2"],
  "nonce": "optional-string",
  "signature": {
    "alg": "Ed25519",
    "kid": "krl-signing-key-1",
    "sig": "<base64-Ed25519-signature>"
  }
}
```

### 3.1 Field reference

| Field | Type | Required | Description |
|---|---|---:|---|
| `version` | `"SignedKRLV1"` | Yes | Artifact type discriminator. |
| `issuer` | non-empty string | Yes | Identity of the KRL publisher. |
| `krl_version` | non-negative safe integer | Yes | Per-issuer publication version. See §8. |
| `issued_at` | integer Unix seconds | Yes | Informational only in v1. See §7. |
| `not_after` | integer Unix seconds | Yes | Strict zero-tolerance expiry. See §6. |
| `revoked_kids` | array of strings | Yes | Revoked key IDs. MUST be deduplicated. See §9. |
| `nonce` | string | No | Optional signed nonce. Patch A defines no consumed-nonce replay state. See §8.2. |
| `signature.alg` | `"Ed25519"` | Yes | Only Ed25519 is accepted in v1. |
| `signature.kid` | non-empty string | Yes | Identifies the KRL signing key in the trusted KRL signing key set. |
| `signature.sig` | non-empty string | Yes | Base64-encoded Ed25519 signature over the signing input. |

Unknown or structurally invalid fields MUST cause verification failure as `KRL_MALFORMED`.

---

## 4. Canonical signing payload

The signing payload MUST include all normative artifact fields except `signature.sig`.

Example:

```json
{
  "version": "SignedKRLV1",
  "issuer": "krl-authority.example.com",
  "krl_version": 42,
  "issued_at": 1712448000,
  "not_after": 1712534400,
  "revoked_kids": ["key-id-1", "key-id-2"],
  "signature": {
    "alg": "Ed25519",
    "kid": "krl-signing-key-1"
  }
}
```

The optional `nonce` field MUST be included in the signing payload when present.

When the artifact does not contain `nonce`, the key MUST be omitted entirely from the signing payload.

### 4.1 Field inclusion summary

| Field | In signing payload? |
|---|---:|
| `version` | Yes |
| `issuer` | Yes |
| `krl_version` | Yes |
| `issued_at` | Yes |
| `not_after` | Yes |
| `revoked_kids` | Yes |
| `nonce` | Yes, when present |
| `signature.alg` | Yes |
| `signature.kid` | Yes |
| `signature.sig` | No |

This construction is specific to `SignedKRLV1`.

Implementations MUST NOT infer the signing-payload rules of `SignedKRLV1` from `AuthorizationV1` or `DelegationV1`.

---

## 5. Signing domain and signature construction

The Ed25519 signing input is:

```text
OXDEAI_KRL_V1\n + canonicalJson(signedKrlSigningPayload(envelope))
```

Equivalent reference-library construction:

```text
signatureInput(
  SIGNING_DOMAINS.KRL_V1,
  signedKrlSigningPayload(envelope)
)
```

A conforming implementation MUST use:

1. OxDeAI `canonicalization-v1`
2. the exact domain prefix `OXDEAI_KRL_V1\n`
3. Ed25519
4. direct Ed25519 signing over the resulting preimage

Implementations MUST NOT:

- use another canonicalization scheme
- omit or alter the domain prefix
- pre-hash the signing input with SHA-256 or another hash before Ed25519 signing
- encode the signature as base64url instead of the required base64 representation

`signature.sig` MUST contain the base64 encoding of the resulting Ed25519 signature bytes.

---

## 6. Strict zero-tolerance expiry semantics

`SignedKRLV1` uses the same zero-tolerance upper validity boundary as `AuthorizationV1`.

The validity condition is:

```text
now < not_after
```

Therefore:

```text
now < not_after   -> temporally valid
now >= not_after  -> KRL_EXPIRED
```

At the exact boundary:

```text
now == not_after
```

the artifact MUST be rejected as:

```text
KRL_EXPIRED
```

No grace period or clock-skew extension is applied by the SignedKRL verifier.

This is exactly parallel to the `AuthorizationV1` expiry model defined in `authorization-v1.md §17`.

Verifier deployments SHOULD maintain sufficiently synchronized trusted clocks.

Issuers SHOULD account for expected publication and delivery latency when choosing `not_after`.

---

## 7. `issued_at` is informational in v1

`issued_at` MUST be a valid integer Unix timestamp.

The verifier MUST NOT enforce `issued_at` as a lower validity boundary in SignedKRLV1 v1.

In particular, this check is not performed:

```text
now >= issued_at
```

An artifact with an `issued_at` value in the future MUST NOT be rejected solely for that reason.

It MAY be accepted if every other verification requirement succeeds.

This matches the `issued_at` semantics of `AuthorizationV1 §17.2`.

---

## 8. Per-issuer `krl_version`

### 8.1 Version requirements

`krl_version` MUST be a non-negative safe integer.

For successive KRL publications belonging to the same issuer, producers MUST assign strictly increasing `krl_version` values.

For example:

```text
issuer A: 40 -> 41 -> 42
```

is conformant producer behavior.

This is a per-issuer sequence. Versions from different issuers are independent:

```text
issuer A -> version 3
issuer B -> version 1
```

is valid.

### 8.2 Verifier regression rule

The verifier receives an optional per-issuer high-watermark through:

```text
previousKrlVersionByIssuer
```

When a previous version exists, the verifier MUST apply:

```text
if krl_version < previousKrlVersionByIssuer[issuer]:
    -> KRL_VERSION_REGRESSION
```

Equality does **not** constitute a version regression in v1:

```text
krl_version == previousKrlVersionByIssuer[issuer]
```

MUST NOT produce `KRL_VERSION_REGRESSION`.

This permits idempotent re-verification or re-delivery of a KRL carrying the same version.

A producer MUST nevertheless use a strictly higher version when publishing a new KRL for the same issuer.

Patch A does not attempt to determine whether two same-version artifacts contain identical content. Deployment logic MUST NOT treat same-version acceptance as authorization to replace an already trusted high-watermark artifact with conflicting content without an explicit state-management policy.

### 8.3 Optional nonce

`nonce` is an optional signed field.

When present, it is cryptographically bound to the artifact because it is included in the signing payload.

Patch A does **not** define:

- consumed-nonce storage
- nonce uniqueness requirements
- nonce replay rejection
- a replay-window lifecycle for KRL artifacts

Therefore, implementations MUST NOT claim Patch A nonce replay enforcement solely because the artifact contains a `nonce`.

Replay-state semantics, if required by a deployment, belong to the stateful integration layer.

### 8.4 Patch A high-watermark limitation

`previousKrlVersionByIssuer` is injected verifier state.

Patch A defines no persistent high-watermark storage.

The caller is responsible for:

- maintaining the per-issuer high-watermark
- supplying it to verification
- updating persistent state only according to the deployment's state-management rules

Persistent high-watermark enforcement is deferred to Patch B.

---

## 9. `revoked_kids` deduplication

Producers MUST emit a deduplicated `revoked_kids` array.

Verifiers MUST reject any artifact containing duplicate entries.

Example invalid input:

```json
{
  "revoked_kids": ["key-1", "key-1"]
}
```

The verifier MUST return:

```text
KRL_MALFORMED
```

Silent deduplication is NOT permitted.

The producer must correct the artifact instead.

---

## 10. Verification procedure

To provide deterministic fail-closed behavior and stable reason-code semantics, a SignedKRLV1 verifier MUST apply the following logical verification sequence.

A verifier MAY organize its internal implementation differently only if it produces exactly the same externally observable verdict and reason code for every conforming test vector and every overlapping failure covered by this specification.

### Step 1 - Structural validation

Validate:

- artifact shape
- required fields
- field types
- `version == "SignedKRLV1"`
- non-empty `issuer`
- non-negative safe-integer `krl_version`
- integer `issued_at`
- integer `not_after`
- `revoked_kids` is an array of strings
- no duplicate `revoked_kids`
- signature object shape

Failure:

```text
KRL_MALFORMED
```

### Step 2 - Signature algorithm

Require:

```text
signature.alg == "Ed25519"
```

Otherwise:

```text
KRL_UNSUPPORTED_ALG
```

This check occurs before cryptographic signature verification.

### Step 3 - Trusted signing key resolution

Resolve `signature.kid` only from the configured trusted KRL signing key set.

If the key is absent:

```text
KRL_UNKNOWN_SIGNING_KID
```

If no trusted KRL signing key set was supplied:

```text
KRL_UNKNOWN_SIGNING_KID
```

The verifier MUST NOT fetch an unknown KRL signing key from the network.

### Step 4 - Signing key lifecycle

Evaluate the resolved key using the standard key lifecycle rules at trusted time `now`.

If the key exists but is inactive:

```text
KRL_SIGNING_KEY_INACTIVE
```

### Step 5 - Signature verification

Construct the signing input exactly as defined in §§4-5 and verify the Ed25519 signature.

If verification fails:

```text
KRL_SIG_INVALID
```

### Step 6 - Artifact expiry

Apply:

```text
now < not_after
```

If:

```text
now >= not_after
```

return:

```text
KRL_EXPIRED
```

No `issued_at` lower-bound check is performed.

### Step 7 - Per-issuer version regression

When a prior per-issuer high-watermark exists:

```text
if krl_version < previousKrlVersionByIssuer[issuer]:
    -> KRL_VERSION_REGRESSION
```

Equality is not a regression.

### Step 8 - Success

If all required checks pass:

```text
status = ok
```

The pure verifier returns a successful verification result.

Patch A does not itself apply the resulting revocation set to a provider keystore or execution path.

---

## 11. Reason codes

The following reason codes are normative for SignedKRLV1 verification.

| Code | Trigger |
|---|---|
| `KRL_MALFORMED` | Missing required field, wrong type, invalid structural value, malformed `revoked_kids`, or duplicate revoked key IDs. |
| `KRL_UNSUPPORTED_ALG` | `signature.alg` is present but is not exactly `"Ed25519"`. |
| `KRL_UNKNOWN_SIGNING_KID` | `signature.kid` is absent from the trusted KRL signing key set, or no trusted KRL signing key set was supplied. |
| `KRL_SIGNING_KEY_INACTIVE` | The signing key exists but is inactive according to key lifecycle rules at `now`. |
| `KRL_SIG_INVALID` | Ed25519 signature verification fails. |
| `KRL_EXPIRED` | `now >= not_after`. |
| `KRL_VERSION_REGRESSION` | `krl_version < previousKrlVersionByIssuer[issuer]`. |

### 11.1 Unknown signing key vs inactive signing key

These conditions MUST remain distinct.

| Code | Condition |
|---|---|
| `KRL_UNKNOWN_SIGNING_KID` | `kid` is not present in the trusted KRL signing key set. |
| `KRL_SIGNING_KEY_INACTIVE` | `kid` exists, but `keyIsActiveAt(key, now)` returns false. |

This distinction mirrors `AUTH_KID_UNKNOWN` and `AUTH_KEY_INACTIVE` in AuthorizationV1 verification.

---

## 12. Static trusted KRL signing key model

KRL signing keys MUST be configured statically at the verifier.

They MUST NOT be discovered through a live network fetch during KRL verification.

This is a deliberate trust-boundary rule: the authenticity anchor for a revocation artifact must not depend on a transport path that could itself suppress or replace the trust material used to verify that artifact.

The trusted KRL signing key set uses the standard OxDeAI `KeySet` / `KeySetKey` model.

KRL signing keys use:

```text
alg = "Ed25519"
```

Standard key lifecycle fields apply, including:

- `status`
- `not_before`
- `not_after`

`keyIsActiveAt(key, now)` MUST be applied consistently with authorization signing keys.

---

## 13. Patch A limitations

Patch A includes:

| Capability | Patch A status |
|---|---|
| SignedKRLV1 artifact definition | Included |
| Canonical signing payload | Included |
| Ed25519 verification | Included |
| Strict expiry semantics | Included |
| Per-issuer version regression check | Included |
| Pure verifier | Included |
| Portable conformance vectors | Included |

The following are explicitly outside Patch A:

| Limitation | Deferred to |
|---|---|
| Integration into `SiftHttpKeyStore` | Patch B |
| `krl_mode` configuration (`signed_required`, `signed_preferred`, `unsigned_legacy`) | Patch B |
| Trusted `now` injection into `SiftHttpKeyStore.refresh()` | Patch B |
| Persistent per-issuer `krl_version` high-watermark storage | Patch B |
| Last-known-good KRL cache | Patch B |
| `krlStatus` / `getKrlStatus()` surface | Patch B |
| Rust cross-language vectors | Future |
| KRL signing-key rotation automation | Future |

Repository merge or issue status is implementation metadata and is not part of the protocol semantics defined by this specification.

---

## 14. Conformance coverage

The normative portable SignedKRLV1 vector source is:

```text
docs/spec/test-vectors/signed-krl-v1.json
```

The TypeScript conformance mirror is:

```text
packages/conformance/vectors/signed-krl-verification.json
```

The TypeScript runner is:

```text
pnpm -C packages/conformance validate
```

### 14.1 Named vectors

| Vector | Mode | Expected outcome |
|---|---|---|
| `krl-001` | `valid` | `ok` |
| `krl-002` | `invalid-signature` | `KRL_SIG_INVALID` |
| `krl-003` | `expired` | `KRL_EXPIRED` |
| `krl-004` | `malformed-revoked-kids` | `KRL_MALFORMED` |
| `krl-005` | `duplicate-revoked-kids` | `KRL_MALFORMED` |
| `krl-006` | `unknown-signing-kid` | `KRL_UNKNOWN_SIGNING_KID` |
| `krl-007` | `signing-key-inactive` | `KRL_SIGNING_KEY_INACTIVE` |
| `krl-008` | `unsupported-alg` | `KRL_UNSUPPORTED_ALG` |
| `krl-009` | `version-regression` | `KRL_VERSION_REGRESSION` |

The observable results of these normative vectors MUST remain stable unless this specification and the vector corpus are versioned together.

### 14.2 Vector relationship

`docs/spec/test-vectors/signed-krl-v1.json` is the normative portable cross-language vector source.

It contains committed `SignedKRLV1` artifacts and precomputed Ed25519 signatures suitable for independent verification.

`packages/conformance/vectors/signed-krl-verification.json` is the TypeScript conformance mirror.

Changes MUST keep the two representations semantically aligned or explicitly document an intentional divergence.

### 14.3 Independent verification model

Cross-language harnesses SHOULD reconstruct the SignedKRL signing preimage independently from committed vector inputs.

They SHOULD NOT depend on TypeScript-generated intermediate values such as:

- canonical bytes
- signing preimages
- generated signatures

Independent implementations SHOULD use their own:

- canonicalization-v1 implementation
- Ed25519 implementation
- language-native or independently linked cryptographic library

This independence provides evidence of cross-language byte equivalence rather than merely testing multiple wrappers around the same implementation.

Current repository implementation status for individual language harnesses is evidence metadata, not a normative protocol requirement.

---

## 15. Security properties and non-claims

A conforming Patch A implementation provides evidence that:

- the KRL artifact was signed by a configured trusted KRL signing key
- the signing key was active at trusted verification time
- the artifact has not expired
- its version has not regressed below the supplied per-issuer watermark
- its revoked key list is structurally valid and deduplicated
- its signed fields have not been modified without invalidating the signature

Patch A does **not** by itself prove that:

- a provider keystore actually applied the KRL
- a revoked provider key was removed from all execution paths
- persistent high-watermark state survived restart
- stale but still unexpired KRLs were replaced by fresher ones
- a nonce was consumed or replay-protected
- the verifier received the newest KRL available from the publisher

Those properties require additional stateful enforcement and deployment behavior outside the Patch A pure-verifier boundary.