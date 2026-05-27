# OxDeAI AuthorizationV1 Specification

**Version:** v1.1
**Status:** Stable (Normative Specification)

---

## 1. Purpose

`AuthorizationV1` is the canonical OxDeAI authorization artifact.

It represents a deterministic authorization decision produced by evaluating:

```text
(intent, state, policy) → ALLOW | DENY
```

Only `ALLOW` artifacts are valid for execution.

> If no valid `AuthorizationV1` is present, execution **MUST NOT** occur.

---

## 2. Relationship to ETA Core

* **ETA Core** defines the decision function
* **AuthorizationV1** defines the portable, verifiable output

This specification defines the artifact **independently of any implementation**.

---

## 3. Canonicalization Dependency

All hashing and signing **MUST** use:

→ `canonicalization-v1.md`

### Requirements

* `intent_hash` **MUST** be computed from canonicalized intent bytes
* `state_hash` **MUST** be computed from canonicalized state bytes
* The signed payload **MUST** be canonicalized before signing

### Failure rule

> If canonicalization fails:
>
> * Authorization **MUST** be considered invalid
> * Execution **MUST** fail closed

---

## 4. Canonical Semantic Model

An `AuthorizationV1` artifact **MUST** carry these semantic fields:

| Field | Type | Description |
|---|---|---|
| `auth_id` | string | Unique single-use identifier |
| `issuer` | string | Issuing authority |
| `audience` | string | Intended verifier / PEP |
| `decision` | `"ALLOW"` | Decision outcome |
| `intent_hash` | hex sha256 | Hash of canonicalized intent |
| `state_hash` | hex sha256 | Hash of canonicalized state snapshot |
| `policy_id` | string | Identifies the policy used |
| `issued_at` | integer (unix s) | Issuance timestamp |
| expiry | integer (unix s) | Expiration timestamp (see §5 for wire-format field names) |
| `alg` | string | Signature algorithm (see §5) |
| `kid` | string | Key identifier |
| `signature` | string or object | Signature bytes (see §5) |

The `decision` field **MUST** be `"ALLOW"`. Any other value **MUST** be rejected.

---

## 5. Accepted Wire Encodings

**Exactly two** wire encodings are accepted. Any encoding not listed here **MUST** be rejected.

---

### Encoding A — Core-native

Produced by `@oxdeai/core`'s `signAuthorizationEd25519`.

```json
{
  "auth_id": "string",
  "issuer": "string",
  "audience": "string",
  "decision": "ALLOW",
  "intent_hash": "lowercase hex sha256",
  "state_hash": "lowercase hex sha256",
  "policy_id": "string",
  "issued_at": 1712448000,
  "expiry": 1712448060,
  "alg": "Ed25519",
  "kid": "string",
  "signature": "base64-encoded-bytes"
}
```

**Distinguishing characteristics:**
- Expiry field: **`expiry`** (integer unix seconds)
- Algorithm identifier: **`"Ed25519"`** (capitalized, case-sensitive)
- Signature: flat string, **standard base64** encoded
- Signing preimage: `"OXDEAI_AUTH_V1\n"` + `canonicalJson(payload_without_sig_bytes)` (domain-prefixed)
- Signature shape: flat bare string (legacy) or nested `{ alg, kid, sig }` object

---

### Encoding B — Sift-compatible

Produced by the Sift adapter in `@oxdeai/sift`.

```json
{
  "auth_id": "string",
  "issuer": "string",
  "audience": "string",
  "decision": "ALLOW",
  "intent_hash": "lowercase hex sha256",
  "state_hash": "lowercase hex sha256",
  "policy_id": "string",
  "issued_at": 1712448000,
  "expires_at": 1712448060,
  "signature": {
    "alg": "ed25519",
    "kid": "string",
    "sig": "base64url-encoded-bytes"
  }
}
```

**Distinguishing characteristics:**
- Expiry field: **`expires_at`** (integer unix seconds)
- Algorithm identifier: **`"ed25519"`** (lowercase, case-sensitive)
- Signature: nested object, `sig` field is **base64url** encoded (RFC 4648 §5)
- Signing preimage: `canonicalJson(payload_without_sig_bytes)` (no domain prefix)

---

### Expiry field resolution

A verifier **MUST** resolve the effective expiry as follows:

1. If `expiry` is present and is an integer: use `expiry`
2. Else if `expires_at` is present and is an integer: use `expires_at`
3. Else: reject with `AUTH_MISSING_FIELD`

Both fields **MUST NOT** be accepted simultaneously with conflicting values. `expiry` takes precedence when both are present.

---

### Algorithm identifier resolution

The `alg` field (or `signature.alg` in nested form) **MUST** be one of:

| Value | Encoding | Notes |
|---|---|---|
| `"Ed25519"` | Core-native (Encoding A) | Capitalized; domain-prefixed preimage |
| `"ed25519"` | Sift-compatible (Encoding B) | Lowercase; non-prefixed preimage |

No other values are accepted. Matching is **exact and case-sensitive**. The following are **explicitly rejected**:

| Value | Rejection reason |
|---|---|
| `"ED25519"` | All-caps variant; not a recognized identifier |
| `"EdDSA"` | Different algorithm family; not Ed25519 |
| `"ed448"` | Different curve; not accepted |
| Any other string | `AUTH_ALG_UNSUPPORTED` |

> There is no generic case-insensitive algorithm matching. Accepting `"ed25519"` is a specific, deliberate interoperability decision for the Sift protocol. It does not create a precedent for accepting arbitrary casing variants.

---

### Deprecated legacy algorithm: `"HMAC-SHA256"`

> **DEPRECATED.** `"HMAC-SHA256"` is not a standard AuthorizationV1 verification algorithm. It is retained solely as a legacy compatibility path for deployments that pre-date the Ed25519 migration and **MUST NOT** be used in new integrations.

**Why it is not standard:**

HMAC-SHA256 is a symmetric shared-secret algorithm. It cannot be independently verified by a third party without access to the shared secret. This violates the AuthorizationV1 portability requirement: any compliant verifier **MUST** be able to verify an `AuthorizationV1` artifact using only publicly distributed key material (`trustedKeySets`).

**Current behavior (backward-compat only):**

The OxDeAI reference implementation accepts `alg: "HMAC-SHA256"` artifacts only when the caller explicitly provides `legacyHmacSecret` in `VerifyAuthorizationOptions`. It is not accepted under strict mode without explicit configuration. This behavior is preserved for backward compatibility only.

**Migration path:**

* All new `PolicyEngine` instances **SHOULD** be configured with `authorization_signing_alg: "Ed25519"` and a corresponding `authorization_private_key_pem`.
* All new PEP deployments **SHOULD** use `trustedKeySets` for verification.
* The `legacyHmacSecret` option will be formally removed in a future major release.

---

### Signature encoding

| Encoding | `signature.sig` format | Decoding |
|---|---|---|
| Core-native | Standard base64 (RFC 4648 §4) | `Buffer.from(sig, "base64")` |
| Sift-compatible | Base64url (RFC 4648 §5) | `Buffer.from(sig, "base64url")` |

Auto-detection: if `sig` contains `-` or `_` characters, it is base64url; otherwise standard base64.

Standard base64 never contains `-` or `_`. Base64url never contains `+` or `/`. The two formats are unambiguous.

---

### Signing preimage

The signed payload **MUST** be reconstructed as follows:

1. Take all fields from the authorization object **except** the signature bytes (`signature.sig` or the bare signature string)
2. For nested signatures: include `signature: { alg, kid }` (without `sig`)
3. Apply `canonicalJson` (sorted keys, deterministic serialization per `canonicalization-v1.md`)
4. Encode as UTF-8 bytes

For **Encoding A** (Core-native): prepend `"OXDEAI_AUTH_V1\n"` to the UTF-8 bytes before signing.

For **Encoding B** (Sift-compatible): use the UTF-8 bytes directly, with no prefix.

The canonicalized preimage includes whichever expiry field name (`expiry` or `expires_at`) was present in the artifact. Changing the field name invalidates the signature.

---

## 6. Field Definitions

### auth_id

* Unique identifier for the authorization
* **MUST** be treated as single-use
* Replay **MUST** be rejected

---

### issuer

* Identifies the issuing authority
* **MUST** be verified against trusted key sets

---

### audience

* Identifies the intended verifier / PEP
* **MUST** match the execution boundary

---

### decision

* **MUST** be `"ALLOW"` for execution
* Any other value **MUST** be rejected

---

### intent_hash

* SHA-256 over canonicalized intent
* **MUST** exactly match the requested action

---

### state_hash

* SHA-256 over canonicalized state snapshot
* Binds the decision to evaluation state

---

### policy_id

* Identifies the policy used during evaluation

---

### issued_at

* Unix timestamp (seconds) recording when the authorization was issued
* **Informational only** — the verifier validates that this field is an integer but does NOT enforce `now >= issued_at`. A verifier whose clock is slightly behind the issuer will still accept a valid-window authorization.
* No "not yet valid" semantics exist in this protocol version

---

### expiry / expires_at

* Unix timestamp (seconds) recording when the authorization expires
* **MUST** be strictly enforced: valid iff `now < expiry`; `now >= expiry` → `AUTH_EXPIRED`
* **No clock skew tolerance** — the protocol uses strict zero tolerance. There is no `skew` parameter and no grace period.
* Wire-format field name depends on encoding (see §5)
* Issuers operating in distributed environments should build delivery latency estimates into the expiry window; the verifier does not compensate for transport delays.

---

### alg

* Signature algorithm identifier
* Accepted values: `"Ed25519"` (Encoding A), `"ed25519"` (Encoding B)
* See §5 for exact matching rules

---

### kid

* Key identifier used for verification
* **MUST** resolve in trusted key sets for the artifact's issuer

---

### signature / signature.sig

* Signature over canonicalized payload
* Encoding (base64 vs base64url) follows the wire encoding (see §5)

---

## 7. Hash Requirements

Implementations **MUST**:

* Use SHA-256
* Encode hashes as lowercase hexadecimal
* Reject mismatches deterministically

---

## 8. Signature Requirements

Verification **MUST**:

* Identify the wire encoding from the `alg` value
* Resolve `kid` to a trusted public key for the artifact's issuer
* Reconstruct the signing preimage per §5
* Verify the Ed25519 signature over the preimage

> Any failure **MUST** result in denial.

Key lookup **MUST** use the canonical key algorithm `"Ed25519"` regardless of whether the artifact uses `"Ed25519"` or `"ed25519"` as its alg identifier — the distinction is a wire-format convention, not a different key type.

---

## 9. Trust Model

> Signature validity ≠ trust

An authorization is valid **only if all conditions hold**:

* Signature verifies against a trusted key
* Issuer is trusted and `kid` resolves in trusted key sets
* Audience matches the verifier
* Artifact is not expired
* `auth_id` has not been replayed
* `intent_hash` matches the requested action

### Failure rule

```text
Any condition fails → reject
```

### Strict mode

* Missing trust configuration **MUST** fail closed

---

## 10. Verification Procedure

A conforming verifier **MUST**:

1. Parse artifact
2. Validate all required fields are present
3. Identify wire encoding from `alg` value
4. Resolve effective expiry (`expiry` or `expires_at` per §5)
5. Check expiration: `now >= effectiveExpiry` → reject
6. Reconstruct signing preimage per §5
7. Resolve `kid` in trusted key sets for the artifact's issuer
8. Verify signature
9. Validate issuer against expected issuer
10. Validate audience against expected audience
11. Check replay: `auth_id` previously consumed → reject
12. Recompute `intent_hash` and compare
13. Reject ambiguous or unsupported encodings deterministically

### Failure rule

> If any step fails → execution **MUST NOT** occur

---

## 11. Replay Protection

* `auth_id` **MUST** be single-use

If reused:

* **MUST** return denial
* **MUST NOT** execute

Replay protection is **mandatory**.

---

## 12. Failure Semantics

Verification **MUST** fail closed.

### Includes

* Malformed artifact
* Missing fields
* Canonicalization failure
* Hash mismatch
* Signature failure
* Trust failure
* Audience mismatch
* Expiration
* Replay
* Unsupported algorithm identifier

> No fallback or partial execution is allowed.

---

## 13. Rejected Encodings

The following encodings are **explicitly rejected** and **MUST** produce `AUTH_ALG_UNSUPPORTED`:

* `alg = "EdDSA"` — different algorithm family
* `alg = "ED25519"` — all-caps; not a recognized identifier
* `alg = "ed448"` — different curve
* Any `alg` value not listed in §5

The following structural forms produce `AUTH_MISSING_FIELD`:

* Neither `expiry` nor `expires_at` present
* `expiry` or `expires_at` present but not an integer

The following produce `AUTH_SIGNATURE_INVALID`:

* Signature bytes do not verify against the reconstructed preimage
* Tampering any field covered by the preimage without re-signing

> Ambiguous inputs **MUST** be rejected. There is no partial acceptance.

---

## 14. Conformance Vectors

Conformance is verified by `packages/conformance`. The following vector groups cover wire encoding behavior:

| Vector | Encoding | Proves |
|---|---|---|
| `authorization-sig-001` | Core-native (A) | Valid Ed25519, domain-prefixed, base64 → accepted |
| `authorization-sig-010` | Sift-compatible (B) | Valid ed25519, non-prefixed, base64url → accepted |
| `authorization-sig-011` | Rejected | EdDSA → AUTH_ALG_UNSUPPORTED |
| `authorization-sig-012` | Rejected | ED25519 all-caps → AUTH_ALG_UNSUPPORTED |
| `authorization-verify-009` | Sift-compatible (B) | expires_at accepted as expiry (structural) |
| `authorization-verify-010` | Sift-compatible (B) | expires_at expiry boundary enforced |
| `authorization-sig-002` | — | Tampered signature → AUTH_SIGNATURE_INVALID |
| `authorization-sig-006` | — | Tampered field → AUTH_SIGNATURE_INVALID |
| `authorization-sig-007` | — | Expired → AUTH_EXPIRED |
| `authorization-sig-008` | — | Replay → AUTH_REPLAY |

---

## 15. Examples

### Encoding A — Core-native

```json
{
  "auth_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "issuer": "oxdeai.policy-engine",
  "audience": "merchant-gateway",
  "decision": "ALLOW",
  "intent_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "state_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "policy_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "issued_at": 1730000000,
  "expiry": 1730000060,
  "alg": "Ed25519",
  "kid": "2026-01",
  "signature": "<base64-encoded Ed25519 signature>"
}
```

### Encoding B — Sift-compatible

```json
{
  "auth_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "issuer": "adapter-issuer",
  "audience": "pep-payments",
  "decision": "ALLOW",
  "intent_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "state_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "policy_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "issued_at": 1730000000,
  "expires_at": 1730000060,
  "signature": {
    "alg": "ed25519",
    "kid": "adapter-key-1",
    "sig": "<base64url-encoded Ed25519 signature>"
  }
}
```

---

## 16. Invariant

```text
No valid AuthorizationV1
→ no verified authorization
→ no execution path
```

Unknown encoding → DENY → no execution.

---

## 17. Clock Model

### 17.1 Selected Model: Strict Zero Tolerance

The protocol uses **strict zero-tolerance** expiry enforcement. There is no `skew` parameter and no grace period.

**Validity rule:**

```text
valid iff now < expiry
```

| `now` vs `expiry` | Result |
|---|---|
| `now < expiry` | Valid — accepted |
| `now == expiry` | Expired — `AUTH_EXPIRED` |
| `now > expiry` | Expired — `AUTH_EXPIRED` |

**Rationale:** Clock ambiguity at the expiry boundary represents a time window during which authorization validity is uncertain. The fail-closed doctrine requires `DENY` under uncertainty. Introducing a skew allowance would widen this window deliberately and require agreeing on an exact tolerance value across all implementations and deployments — a fragile distributed constraint. Strict zero tolerance eliminates the ambiguity entirely.

### 17.2 issued_at Semantics

`issued_at` is **informational**. The verifier:

- Validates that `issued_at` is an integer (required field)
- Does **NOT** enforce `now >= issued_at`

There is no "not yet valid" (nbf) concept in this protocol version. An authorization whose `now` is slightly behind `issued_at` (e.g., verifier clock drift of a few seconds) is still accepted, provided `now < expiry`.

### 17.3 Distributed Deployment Requirements

| Requirement | Detail |
|---|---|
| Clock synchronization | All verifiers **MUST** use synchronized clocks (NTP or equivalent). The protocol does not compensate for unsynchronized clocks. |
| Delivery latency | Issuers operating across queues, regions, or transport layers with measurable latency **MUST** incorporate that latency into the expiry window at issuance time. |
| Verifier `now` | Verifiers **MUST** inject `now` explicitly. Ambient wall-clock inside verification logic is not permitted (see `verification-v1.md §4`). |

### 17.4 Boundary Conditions

| Scenario | `now` vs fields | Result |
|---|---|---|
| Well within window | `issued_at < now < expiry` | ok |
| Last valid second | `now = expiry - 1` | ok |
| Exact expiry | `now = expiry` | `AUTH_EXPIRED` |
| One past expiry | `now = expiry + 1` | `AUTH_EXPIRED` |
| Verifier behind issuer | `now < issued_at`, `now < expiry` | ok — `issued_at` not enforced as lower bound |
| Delayed delivery | `now = issued_at + large_offset`, `now < expiry` | ok — still within validity window |
| Stale authorization | `now >= expiry` | `AUTH_EXPIRED` |

### 17.5 Conformance Vectors

Clock semantics are covered by `clock-semantics-verification.json` (10 assertions):

| Vector | Mode | `now` relationship | Expected |
|---|---|---|---|
| `clock-001` | `last-valid-second` | `now = expiry - 1` | `ok` |
| `clock-002` | `one-past-expiry` | `now = expiry + 1` | `AUTH_EXPIRED` |
| `clock-003` | `verifier-clock-behind` | `now < issued_at` | `ok` |
| `clock-004` | `encoding-b-last-valid-second` | `now = expires_at - 1` | `ok` |
| `clock-005` | `encoding-b-verifier-clock-behind` | `now < issued_at` | `ok` |
