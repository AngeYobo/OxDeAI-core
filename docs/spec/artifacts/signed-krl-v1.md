# SignedKRLV1 Specification

**Version:** v1.0 (Patch A — artifact definition and pure verifier only)  
**Status:** Draft  
**Depends on:** `canonicalization-v1.md`, `authorization-v1.md §17` (clock model)

---

## 1. Purpose

`SignedKRLV1` is a provider-neutral OxDeAI Key Revocation List artifact.

It allows a KRL publisher to cryptographically commit to a set of revoked key IDs
and expiry semantics, such that any verifier with the correct trusted KRL signing
public key can verify the list independently — without network trust, without
transport-layer assumptions, and without shared secrets.

> **Protocol invariant being enforced:**
>
> ```
> revoked provider key
> → must not be accepted
> → no AuthorizationV1 bridge
> → no execution path
> ```

`SignedKRLV1` closes the gap where an unsigned KRL depends on transport security
(HTTPS) for its integrity. A compromised transport path can suppress revocations;
a signed KRL cannot.

---

## 2. Provider-neutral scope

`SignedKRLV1` is a standalone OxDeAI protocol artifact. It is independent of:

- Any specific provider (Sift, OpenAI, etc.)
- The `AuthorizationV1` signing key
- The `DelegationV1` signing key

The KRL signing key is a **distinct trust domain**. Verifiers are configured with
a static trusted KRL signing key set that is separate from authorization key sets.

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

### Field reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `"SignedKRLV1"` | Yes | Artifact type discriminator. |
| `issuer` | non-empty string | Yes | Identity of the KRL publisher. |
| `krl_version` | non-negative integer | Yes | Monotonically increasing version counter. See §6. |
| `issued_at` | integer (unix seconds) | Yes | Informational only in v1. Not enforced as a lower bound. See §7. |
| `not_after` | integer (unix seconds) | Yes | Strict zero-tolerance expiry. See §5. |
| `revoked_kids` | array of strings | Yes | Revoked key IDs. Must be deduplicated. See §8. |
| `nonce` | string | No | Optional replay-prevention nonce. Included in signing payload when present. |
| `signature.alg` | `"Ed25519"` | Yes | Only Ed25519 is accepted in v1. |
| `signature.kid` | non-empty string | Yes | Identifies the KRL signing key in the trusted key set. |
| `signature.sig` | non-empty string | Yes | Base64-encoded Ed25519 signature over the signing payload. |

---

## 4. Canonical signing payload

The signing payload **includes all normative fields except `signature.sig`**:

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

The `nonce` field is included when present; it is absent from the payload when the
artifact does not carry a nonce.

### Field inclusion / exclusion summary

| Field | In signing payload? |
|-------|-------------------|
| `version` | Yes |
| `issuer` | Yes |
| `krl_version` | Yes |
| `issued_at` | Yes |
| `not_after` | Yes |
| `revoked_kids` | Yes |
| `nonce` | Yes (when present) |
| `signature.alg` | Yes |
| `signature.kid` | Yes |
| `signature.sig` | **No** — excluded |

---

## 5. KRL domain prefix

The Ed25519 signature is computed over:

```
OXDEAI_KRL_V1\n + canonicalJson(signedKrlSigningPayload(envelope))
```

Using `signatureInput(SIGNING_DOMAINS.KRL_V1, signedKrlSigningPayload(envelope))`
from the OxDeAI core cryptographic library.

This domain prefix is the **provider contract for SignedKRLV1**. Any implementation
signing or verifying a `SignedKRLV1` artifact must use:

1. OxDeAI canonicalization-v1 (not Sift canonicalization or any other encoding)
2. The `OXDEAI_KRL_V1\n` domain prefix
3. Ed25519 raw signing (no hash wrapper — Ed25519 operates directly on the preimage)

---

## 6. Strict zero-tolerance expiry semantics

Validity window: `now < not_after`

```
now < not_after   → valid
now >= not_after  → KRL_EXPIRED (no grace period)
```

Exactly parallel to `AuthorizationV1` expiry semantics (see `authorization-v1.md §17`).
NTP synchronization is required at the verifier.

Issuers should build delivery latency into the `not_after` window.

---

## 7. `issued_at` — informational only in v1

`issued_at` is required to be an integer unix timestamp, but the verifier does
**not** enforce a lower bound (`now >= issued_at` is not checked). An artifact
with `issued_at` in the future is accepted if it passes all other checks.

This matches the `issued_at` semantics of `AuthorizationV1` (see §17.2 of that spec).

---

## 8. Per-issuer `krl_version` regression

`krl_version` must be a non-negative safe integer. Producers must monotonically
increase `krl_version` across successive KRL publications for the same issuer.

Verifiers enforce this via an injected `previousKrlVersionByIssuer` map:

```
if krl_version < previousKrlVersionByIssuer[issuer]:
  → KRL_VERSION_REGRESSION
```

This check is **per-issuer, not global**. A version-3 KRL from issuer A and a
version-1 KRL from issuer B are independent.

**Patch A limitation:** `previousKrlVersionByIssuer` is injected state only. There
is no persistent high-watermark storage in v1. The caller (e.g., `SiftHttpKeyStore`
in Patch B) is responsible for maintaining the per-issuer high-watermark and
injecting it into verification calls.

---

## 9. `revoked_kids` deduplication

Producers MUST emit a deduplicated `revoked_kids` list. Verifiers MUST reject
duplicate entries as `KRL_MALFORMED`. Silent deduplication is not permitted — the
artifact must be corrected at the producer.

---

## 10. Reason codes

| Code | Trigger |
|------|---------|
| `KRL_MALFORMED` | Missing required field, wrong type, `revoked_kids` not an array of strings, or duplicate entries in `revoked_kids`. |
| `KRL_UNSUPPORTED_ALG` | `signature.alg` is present but is not `"Ed25519"`. |
| `KRL_UNKNOWN_SIGNING_KID` | `signature.kid` not found in the trusted KRL signing key set (or no trusted key set was provided). |
| `KRL_SIGNING_KEY_INACTIVE` | The KRL signing key was found in the trusted key set, but `keyIsActiveAt()` returned false (revoked, retired past window, or `not_before`/`not_after` constraint). |
| `KRL_SIG_INVALID` | Ed25519 signature verification failed. |
| `KRL_EXPIRED` | `now >= not_after`. |
| `KRL_VERSION_REGRESSION` | `krl_version < previousKrlVersionByIssuer[issuer]`. |

### `KRL_UNKNOWN_SIGNING_KID` vs `KRL_SIGNING_KEY_INACTIVE`

Mirrors the existing `AUTH_KID_UNKNOWN` vs `AUTH_KEY_INACTIVE` distinction:

| Code | Condition |
|------|-----------|
| `KRL_UNKNOWN_SIGNING_KID` | `kid` is not present in the trusted key set at all. |
| `KRL_SIGNING_KEY_INACTIVE` | `kid` is present but `keyIsActiveAt(key, now)` returns `false`. |

---

## 11. Static trusted KRL signing key model

KRL signing keys are configured **statically** at the verifier — they are not
fetched over the network. This is an explicit design choice: the trust anchor for
KRL integrity must not itself depend on a network fetch that could be suppressed.

The trusted KRL signing key set is a standard `KeySet` (as defined in `keyset.ts`),
using `KeySetKey` entries with `alg: "Ed25519"`. Key lifecycle rules (`status`,
`not_before`, `not_after`) apply to KRL signing keys exactly as they do to
authorization signing keys.

---

## 12. Patch A limitations

The following are explicitly out of scope for Patch A and will be addressed in subsequent patches:

| Limitation | Deferred to |
|-----------|------------|
| Integration into `SiftHttpKeyStore` | Patch B |
| `krl_mode` configuration (`signed_required`, `signed_preferred`, `unsigned_legacy`) | Patch B |
| `now` injection into `SiftHttpKeyStore.refresh()` | Patch B |
| Persistent per-issuer `krl_version` high-watermark storage | Patch B |
| Last-known-good KRL cache | Patch B |
| Cross-language conformance vectors (Go, Python, Rust) | Future |
| KRL signing key rotation automation | Future |
| `krlStatus` / `getKrlStatus()` surface | Patch B |

---

## 13. Conformance coverage

Conformance vectors: `packages/conformance/vectors/signed-krl-verification.json`

Runner: `pnpm -C packages/conformance validate`

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `krl-001` | `valid` | `ok` — signature verifies, not expired |
| `krl-002` | `invalid-signature` | `KRL_SIG_INVALID` — tampered signature |
| `krl-003` | `expired` | `KRL_EXPIRED` — `now >= not_after` |
| `krl-004` | `malformed-revoked-kids` | `KRL_MALFORMED` — `revoked_kids` is a string |
| `krl-005` | `duplicate-revoked-kids` | `KRL_MALFORMED` — duplicate entries |
| `krl-006` | `unknown-signing-kid` | `KRL_UNKNOWN_SIGNING_KID` — kid not in trusted set |
| `krl-007` | `signing-key-inactive` | `KRL_SIGNING_KEY_INACTIVE` — key revoked |
| `krl-008` | `unsupported-alg` | `KRL_UNSUPPORTED_ALG` — `alg != "Ed25519"` |
| `krl-009` | `version-regression` | `KRL_VERSION_REGRESSION` — version went backwards |

**Coverage scope:** TypeScript / `@oxdeai/core` conformance runner. Cross-language
harnesses (Go, Python) do not yet include SignedKRLV1 vectors.
