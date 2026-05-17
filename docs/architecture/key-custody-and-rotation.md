# OxDeAI Key Custody and Rotation Guide: External Authorization Providers

**Status:** Non-normative (developer documentation)
**Scope:** Issuer key lifecycle for external authorization providers — Sift adapter, non-Core issuers, adapter-owned signing keys

---

This document complements the threat model at
[`docs/architecture/threat-model-external-providers.md`](./threat-model-external-providers.md)
and the PEP Gateway specification at
[`docs/spec/enforcement/pep-gateway-v1.md`](../spec/enforcement/pep-gateway-v1.md).

**Core invariant:**

```text
unknown issuer key or key ambiguity → DENY → no execution
```

OxDeAI does not distribute keys, host key services, or provide PKI. Key custody is a
deployment responsibility. This guide documents what OxDeAI requires from key management
infrastructure and how verifier behavior is affected by key lifecycle decisions.

---

## 1. Key Data Model

The `KeySetKey` type is OxDeAI's protocol-level key descriptor:

```typescript
type KeyStatus = "active" | "retired" | "revoked";

type KeySetKey = {
  kid:        string;           // unique key identifier within the keyset
  alg:        "Ed25519" | "HMAC-SHA256";
  public_key: string;           // PEM-encoded SPKI public key
  status?:    KeyStatus;        // absent = active
  not_before?: number;          // unix seconds — key not valid before this time
  not_after?:  number;          // unix seconds — key not valid after this time
};

type KeySet = {
  issuer:  string;              // issuer label — must match authorization.issuer exactly
  version: string;              // keyset version label (informational)
  keys:    KeySetKey[];
};
```

### Key Lifecycle States

| State | `status` value | Verifier behavior |
|---|---|---|
| **Active** | `"active"` or absent | Accepted if `now` is within `[not_before, not_after]` |
| **Transitional** | `"active"` | Two keys both active during a dual-sign overlap window |
| **Retired** | `"retired"` | Rejected — `keyIsActiveAt` returns `false` for `"retired"` |
| **Revoked** | `"revoked"` | Rejected immediately — treated as untrusted regardless of time bounds |

`keyIsActiveAt(key, now)` enforces all three constraints in order:
1. Reject if `status === "revoked"`
2. Reject if `now < not_before`
3. Reject if `now > not_after`

A key with no `status`, no `not_before`, and no `not_after` is permanently active until
explicitly retired or revoked in the `trustedKeySets` config.

---

## 2. Issuer Key Lifecycle

```text
 GENERATE        PUBLISH         ACTIVATE        IN USE
    │               │               │               │
    ▼               ▼               ▼               ▼
 [key pair]  → [distribute to] → [not_before] → [signing]
              [verifier config]    reached
                                               │
                                               │ (rotation begins)
                                               ▼
                                         DUAL-SIGN WINDOW
                                         [old key + new key both active]
                                               │
                                 ┌─────────────┴──────────────┐
                                 ▼                            ▼
                            OLD KEY                      NEW KEY
                          [not_after set]              [becomes sole
                          [status: retired]             active key]
                                 │
                                 ▼
                            RETIRED (verifier rejects)
                                 │
                                 ▼ (on compromise or scheduled destruction)
                            REVOKED (verifier rejects immediately)
```

### 2.1 Key Generation

- Generate Ed25519 keypairs using a cryptographically secure source (e.g., `node:crypto` `generateKeyPairSync` with `type: "ed25519"`)
- Export the private key as PKCS#8 PEM; store it in secure key management infrastructure (HSM, KMS, secrets manager)
- Export the public key as SPKI PEM for inclusion in `trustedKeySets`
- Assign a `kid` that is unique within the issuer's keyset — use a date-scoped label (e.g., `"2026-01"`) or a random UUID. `kid` values must not be reused after a key is revoked.

### 2.2 Publication and Distribution

The public key must be distributed to every verifier (OxDeAI Guard instance, offline verifier)
before the key is used to sign authorizations. Publication options:

- **Static config file** (recommended for production): `trustedKeySets` is loaded at startup from a versioned config artifact; updated via deployment
- **JWKS endpoint** (optional): guard instances fetch and cache at startup; not polled at runtime — OxDeAI does not support online key resolution during authorization verification
- **Out-of-band delivery**: for air-gapped or offline verifiers

The private key **must never** be distributed. Only the PEM public key appears in `trustedKeySets`.

### 2.3 Activation

Set `not_before` on the new key to the planned activation timestamp. Until `now >= not_before`,
`keyIsActiveAt` rejects the key even if `status` is `"active"`. This prevents premature use
if the key is published early.

### 2.4 Rotation

See §4 for full rotation procedures.

### 2.5 Retirement

Set `not_after` on the old key to the end of the dual-sign window, or set `status: "retired"`.
Once retired, the verifier rejects all authorizations signed with that key.

Retired keys **should** remain in `trustedKeySets` for the duration of the maximum authorization
expiry window, to allow in-flight authorizations issued just before retirement to complete.
After that window, retired key entries may be removed from the config entirely.

### 2.6 Revocation

Set `status: "revoked"` on the key in `trustedKeySets` and deploy the updated config to all
verifiers immediately. Revocation takes effect the next time a verifier loads its config.

Unlike retirement, revocation is immediate: `keyIsActiveAt` returns `false` for `"revoked"`
keys regardless of `not_before` / `not_after`. All authorizations signed with a revoked key
are rejected from that point forward.

**Revoked keys must never be reused.** The `kid` should be retired permanently.

### 2.7 Destruction

After revocation and after the maximum authorization expiry window has passed, the private key
material may be destroyed. Destruction is an operational decision outside OxDeAI's scope.

---

## 3. TrustedKeySets Management

### 3.1 Trust Root Properties

`trustedKeySets` is the **sole trust root** for authorization verification. The verifier
accepts an authorization if and only if:

1. `authorization.issuer` matches a `KeySet.issuer` in `trustedKeySets`
2. `authorization.signature.kid` (or `authorization.kid`) matches a `KeySetKey.kid` in that keyset
3. `keyIsActiveAt(key, now)` returns `true`
4. The Ed25519 signature verifies against `key.public_key`

If any condition fails, the authorization is rejected. There is no fallback or partial trust.

### 3.2 Fail-Closed Lookup Behavior

| Situation | Outcome |
|---|---|
| `issuer` not found in any `KeySet` | `AUTH_ISSUER_MISMATCH` → DENY |
| `kid` not found in issuer's keyset | `AUTH_KID_UNKNOWN` → DENY |
| Key found but `status: "revoked"` | `AUTH_KID_UNKNOWN` → DENY |
| Key found but `now < not_before` | `AUTH_KID_UNKNOWN` → DENY |
| Key found but `now > not_after` | `AUTH_KID_UNKNOWN` → DENY |
| Key active but signature invalid | `AUTH_SIGNATURE_INVALID` → DENY |
| `trustedKeySets` is empty | Hard failure at guard construction |

Key ambiguity (e.g., two keys with the same `kid` in one keyset) is resolved by first match.
Deployers must ensure `kid` uniqueness within each issuer's keyset.

### 3.3 Immutable Trust Snapshots

`trustedKeySets` passed to `createPepGatewayExecutor` or `OxDeAIGuard` is captured at
construction time. Subsequent runtime mutations to the array are not observed. This is
intentional — it prevents TOCTOU races between key updates and in-flight verifications.

To update the trust configuration, redeploy the guard with the updated `trustedKeySets`.

For offline verification (`createVerifier`), the same snapshot semantics apply. Offline
verifiers must be given an explicit keyset snapshot that corresponds to the signing epoch
of the artifacts being verified.

### 3.4 Trust Bootstrap

The initial `trustedKeySets` config must be delivered to the guard through a trusted channel
(secrets manager, sealed deployment config, CI/CD pipeline with signed artifact delivery).
OxDeAI does not specify the bootstrap mechanism — it is a deployment responsibility.

Do not load `trustedKeySets` from a source that could be written to by the agent or any
untrusted component at runtime.

### 3.5 Storage Recommendations

- Store `trustedKeySets` as a versioned, immutable config artifact alongside the deployment
- Version the config artifact separately from the keyset `version` field (which is informational)
- Apply change-detection / integrity verification to the config artifact itself (e.g., checksum in CI)
- For high-security deployments, sign the `trustedKeySets` config artifact out-of-band and verify the signature at startup

---

## 4. Rotation Semantics

### 4.1 Rotation Timeline

```text
Time ──────────────────────────────────────────────────────────────────────►

                       DUAL-SIGN WINDOW
                      ◄───────────────►

  old key  ══════════════════════════╗ (not_after set / status: retired)
                                      ╚════ RETIRED

  new key             ╔══════════════════════════════════════════════════════
                      ║ (not_before reached)
                ↑
          New key published to
          all verifiers (before
          activation)
```

**Key principle:** The new key must be in `trustedKeySets` on all verifiers *before* any
issuer signs with it. If a verifier receives an authorization signed with a key it does
not yet know about, verification fails — `AUTH_KID_UNKNOWN` → DENY.

### 4.2 Step-by-Step Rotation Procedure

**Step 1 — Generate new key**
Generate a new Ed25519 keypair. Assign a new `kid`. Store the private key securely.

**Step 2 — Publish new public key to verifiers (before signing begins)**
Add the new `KeySetKey` to `trustedKeySets` with:
- `status: "active"` (or absent)
- `not_before` = planned activation timestamp (prevents premature use)

Deploy the updated `trustedKeySets` config to all guard instances. Verify that all instances
have loaded the new config before proceeding.

**Step 3 — Begin dual-sign window**
At `not_before`, the issuer begins signing new authorizations with the new key. The old key
remains active. Both are accepted by verifiers.

During this window:
- Authorizations signed with the old key are still accepted (useful for in-flight authorizations issued before Step 3)
- Authorizations signed with the new key are accepted
- No verifier should experience `AUTH_KID_UNKNOWN` during a correctly sequenced rotation

**Step 4 — Retire the old key**
After the dual-sign window (typically: max authorization expiry duration after Step 3):
- Set `not_after` on the old key to `now` (or set `status: "retired"`)
- Deploy updated `trustedKeySets` to all verifiers

From this point, the old key is rejected. Any in-flight authorization signed with the old key
that was issued before the dual-sign window began will fail if it outlives the `not_after` time.
Size the dual-sign window accordingly.

**Step 5 — Remove the old key entry (optional)**
After the maximum authorization expiry window has passed, the old key entry may be removed
from `trustedKeySets` entirely. This keeps the config clean but has no security effect —
retired keys are already rejected.

### 4.3 Overlap Window Sizing

The dual-sign window must be at least as long as the maximum authorization expiry duration:

```text
dual_sign_window ≥ max(authorization.expiry - authorization.issued_at)
```

For example, if authorizations expire after 5 minutes, a 10-minute dual-sign window provides
adequate overlap. Longer windows are safer; they increase the period during which a compromised
old key could still produce valid authorizations.

### 4.4 Verifier Update Sequencing

The critical ordering constraint:

```text
REQUIRED ORDER:
  1. Publish new key to all verifiers
  2. Start signing with new key at issuer

NEVER:
  2. Start signing with new key at issuer      ← causes AUTH_KID_UNKNOWN
  1. Publish new key to verifiers
```

Violating this order causes legitimate authorizations to be rejected until all verifiers
are updated. Fail-closed semantics mean this is a service disruption, not a security bypass.

### 4.5 Staged Rollout

For deployments with many guard instances:

- Roll out the new `trustedKeySets` config (with the new key added) to all instances before
  switching the issuer to sign with the new key
- Verify rollout completion before activating the new signing key
- Use `not_before` on the new key as a safety gate: even if the issuer accidentally starts
  signing early, verifiers will reject until `not_before` is reached

---

## 5. Compromise Scenarios

### KC-1: Issuer Private Key Compromise

| Field | Detail |
|---|---|
| **Description** | The Ed25519 private key of an authorization issuer is exposed (leaked, stolen, or derived) |
| **Enforcement point** | Signature verification — a compromised key can produce valid-looking authorizations |
| **Verifier behavior** | Authorizations signed with the compromised key pass signature verification until the key is revoked |
| **Fail-closed outcome** | Set `status: "revoked"` on the key in `trustedKeySets` and deploy immediately. All subsequent verification calls reject the key. In-flight authorizations signed before revocation that have not been consumed may still succeed until revoked config reaches all verifiers. |
| **Residual risk** | Any authorization signed with the compromised key before revocation config propagates is cryptographically indistinguishable from legitimate ones. Rotate immediately and audit replay store for suspicious `auth_id` consumption patterns. |
| **Recovery** | Generate a new key pair. Follow §4.2 rotation procedure. Do not reuse the compromised `kid`. |

### KC-2: Adapter Signing Key Compromise

| Field | Detail |
|---|---|
| **Description** | The Ed25519 private key used by the Sift adapter (or another external adapter) to sign `AuthorizationV1` artifacts is compromised |
| **Enforcement point** | Signature verification at guard step 1 |
| **Verifier behavior** | Forged authorizations signed with the adapter's compromised key pass signature verification until the key is revoked in `trustedKeySets` |
| **Fail-closed outcome** | Same as KC-1. Revoke the adapter key in `trustedKeySets` and redeploy. The adapter's key is separate from the external provider's receipt-signing key (see §6.2). |
| **Residual risk** | Forged authorizations can authorize arbitrary actions within the configured `expectedAudience` until the key is revoked. |
| **Recovery** | Generate new adapter signing keypair, update `trustedKeySets` with new public key, redeploy adapter with new private key. |

### KC-3: Stale Verifier Keyset

| Field | Detail |
|---|---|
| **Description** | A guard instance is running with an outdated `trustedKeySets` that does not include a newly activated key |
| **Enforcement point** | `kid` lookup in `trustedKeySets` |
| **Verifier behavior** | Authorizations signed with the new key are rejected with `AUTH_KID_UNKNOWN` → DENY on stale instances |
| **Fail-closed outcome** | Legitimate authorizations are rejected on stale instances (service disruption, not security bypass). This is the expected fail-closed behavior. |
| **Residual risk** | None — stale verifiers reject unknown keys. The risk is availability, not security. |
| **Recovery** | Deploy updated `trustedKeySets` to stale instances. Follow §4.4 ordering to prevent this during planned rotations. |

### KC-4: Revoked Key Still Deployed

| Field | Detail |
|---|---|
| **Description** | A guard instance's `trustedKeySets` still lists a revoked key as `"active"` because the config update has not propagated |
| **Enforcement point** | `keyIsActiveAt` check |
| **Verifier behavior** | Authorizations signed with the revoked key are accepted on stale instances during the propagation window |
| **Fail-closed outcome** | Stale instances accept revoked-key signatures until the updated config reaches them. This is the primary window of risk after key compromise. |
| **Residual risk** | Forged authorizations signed with the compromised key may succeed on stale instances. Minimize by deploying revocation config urgently and atomically. |
| **Recovery** | Prioritize config propagation. For high-security deployments, consider a circuit-breaker that can force all instances to reload config on demand. |

### KC-5: Emergency Rotation

| Field | Detail |
|---|---|
| **Description** | A key compromise is discovered and immediate rotation is required (no planned dual-sign window) |
| **Enforcement point** | `trustedKeySets` config across all guard instances |
| **Verifier behavior** | After revocation config propagates: all authorizations signed with the compromised key are rejected, including legitimate in-flight ones |
| **Fail-closed outcome** | Brief service disruption (in-flight authorizations with old key are rejected) is acceptable. Security takes precedence. |
| **Procedure** | 1. Generate new keypair immediately. 2. Deploy updated `trustedKeySets` with new key added AND old key set to `"revoked"`. 3. Switch issuer to sign with new key simultaneously with step 2. 4. Accept brief `AUTH_KID_UNKNOWN` errors on any verifiers that receive new-key-signed authorizations before the config update arrives — these are transient and fail-closed. |

### KC-6: Partial Rollout

| Field | Detail |
|---|---|
| **Description** | A `trustedKeySets` update is deployed to some guard instances but not all; the issuer has already started signing with the new key |
| **Enforcement point** | `kid` lookup on instances without the new key |
| **Verifier behavior** | Updated instances: accept new-key-signed authorizations. Stale instances: `AUTH_KID_UNKNOWN` → DENY |
| **Fail-closed outcome** | Stale instances deny legitimate requests. This is a service disruption, not a security bypass. |
| **Recovery** | Complete the rollout. Requests failing on stale instances can be retried after the issuer issues a new authorization (in a stateless request model). |

### KC-7: Split Trust Roots

| Field | Detail |
|---|---|
| **Description** | Different guard instances have different `trustedKeySets` configurations, causing authorizations valid at one instance to be rejected at another |
| **Enforcement point** | `kid` / `issuer` lookup |
| **Verifier behavior** | Consistent within each instance; inconsistent across the deployment |
| **Fail-closed outcome** | Affected instances reject valid authorizations. |
| **Residual risk** | None — both configurations are fail-closed. The risk is availability. |
| **Recovery** | Establish a single source of truth for `trustedKeySets`. Deploy uniformly. |

### KC-8: Offline Verifier Lag

| Field | Detail |
|---|---|
| **Description** | An offline verifier (`createVerifier` with a static keyset snapshot) was provisioned with a keyset that does not include a key used during a rotation period |
| **Enforcement point** | `kid` lookup in the offline verifier's static keyset |
| **Verifier behavior** | Authorizations signed after the rotation (with the new key) are rejected with `AUTH_KID_UNKNOWN` by the lagging offline verifier |
| **Fail-closed outcome** | Offline verifier rejects authorization — fail-closed. |
| **Recovery** | Provision offline verifiers with keyset snapshots that include all keys active during the epoch being verified. For long-running offline verification workloads, use a snapshot that spans the full time range of artifacts being analyzed. |

---

## 6. External Provider Interoperability

### 6.1 Separation of Trust Roots

OxDeAI's trust root is the `trustedKeySets` config at the guard — it trusts the **adapter's
Ed25519 public key**, not the external provider's signing infrastructure.

```text
External Provider (Sift)              OxDeAI Trust Root
────────────────────────              ──────────────────
Sift receipt signing key              Adapter Ed25519 key
  (Sift's own PKI)                      (in trustedKeySets)
         │                                     │
         ▼                                     ▼
   Sift Receipt                       AuthorizationV1
   (ALLOW / DENY)                     (Ed25519 signed)
         │                                     │
         ▼                                     ▼
   Sift Adapter                          Guard / PEP
   (verifies receipt,              (verifies authorization
   produces AuthorizationV1)        against trustedKeySets)
```

**The Sift receipt-signing key is NOT the OxDeAI trust root.** The adapter verifies the
Sift receipt internally. The guard trusts only the adapter's `AuthorizationV1` signature.

This separation means:

- Sift key rotation (Sift's internal PKI) does not require changes to OxDeAI `trustedKeySets`
- Adapter key rotation (adapter's Ed25519 key) requires updating OxDeAI `trustedKeySets`
- A compromised Sift receipt-signing key does not compromise OxDeAI's execution boundary —
  only a compromised adapter Ed25519 key does

### 6.2 Sift Adapter Key Lifecycle

The Sift adapter signs `AuthorizationV1` artifacts with its own Ed25519 private key. This key
is independent of Sift's internal signing infrastructure. Treat it as an issuer key:

- Generate and store per §2.1
- Include the public key in guard `trustedKeySets` under the adapter's `issuer` label
- Rotate per §4.2 when required
- Revoke immediately on compromise per KC-2

### 6.3 JWKS Guidance

If an external provider distributes keys via a JWKS (JSON Web Key Set) endpoint:

- Fetch the JWKS at startup and convert to OxDeAI `KeySet` format
- Do **not** poll the JWKS endpoint at authorization-verification time — OxDeAI verification
  is designed to be stateless and offline-capable; online key resolution introduces availability
  coupling
- Treat fetched JWKS as a static snapshot for the lifetime of the guard instance
- On startup failure to fetch JWKS, fail closed — do not start with empty `trustedKeySets`

JWKS `kid` values map to `KeySetKey.kid`. JWKS `alg: "EdDSA"` with `crv: "Ed25519"` maps to
`KeySetKey.alg: "Ed25519"`. Note that `"EdDSA"` is **rejected** as a value in `AuthorizationV1`
signature fields — the mapping is only at the key-import stage, not at verification time.

### 6.4 Key Revocation List (KRL) Guidance

OxDeAI does not provide a KRL mechanism. Revocation is managed by:

1. Setting `status: "revoked"` in `trustedKeySets` for the affected key
2. Deploying the updated config to all verifiers

For deployments requiring explicit KRL semantics (e.g., for audit trails):

- Maintain a versioned list of revoked `kid` values alongside the `trustedKeySets` config
- Filter revoked `kid` values out of the active keyset on config load
- The `status: "revoked"` field in `KeySetKey` serves this purpose natively

### 6.5 Offline Verification Continuity

Offline verification (`createVerifier` / `verifyAuthorization` / `verifyEnvelope`) is
fully stateless. To maintain continuity through key rotations:

- Provision offline verifiers with keyset snapshots that include **all keys** active during
  the time range of artifacts being verified
- Include retired keys (with `not_after` set) in offline snapshots — they are rejected for
  current verification but required to verify historical artifacts signed with those keys
- For long-retention audit workloads, archive `trustedKeySets` snapshots alongside the
  artifact archives they correspond to

```text
Offline Verification Snapshot Requirements:

  Artifact signed at time T with key K
  → Snapshot must include K with not_before ≤ T ≤ not_after
  → Snapshot must NOT mark K as "revoked" (if K was not revoked at time T)
```

Note: verifying a historical artifact with a key that was later revoked is a policy decision.
OxDeAI enforces the keyset as configured; it does not reconstruct historical revocation state.

---

## 7. Non-Goals

OxDeAI explicitly does **not**:

| Non-goal | Implication |
|---|---|
| Distribute keys | Public keys must be distributed to verifiers through a separate trusted channel |
| Host key services | No key server, JWKS endpoint, or KMS is provided by OxDeAI |
| Provide PKI | No certificate hierarchy, CA, or certificate revocation protocol |
| Manage identities | Issuer identity binding (`issuer` string) is a deployment configuration, not a protocol-issued identity |
| Replace governance systems | Key custody policies, access controls, and audit requirements are organizational concerns |
| Guarantee key custody correctness | OxDeAI verifies signatures against configured public keys; it does not verify that private keys were generated securely or stored safely |
| Enforce rotation schedules | OxDeAI enforces `not_before` / `not_after` / `status` as configured; scheduling rotation is a deployment responsibility |
| Support online revocation | Revocation is propagated via config redeployment, not via CRL/OCSP or equivalent runtime protocol |

---

## 8. Operational Checklist

### Before Production Deployment

- [ ] Ed25519 private keys stored in a secrets manager or HSM, not in code or config files
- [ ] Public keys published to `trustedKeySets` as SPKI PEM
- [ ] `kid` values are unique within each issuer's keyset
- [ ] `expectedAudience` and `expectedIssuer` are set correctly in guard config
- [ ] `trustedKeySets` is loaded from a versioned, integrity-verified config artifact
- [ ] Replay store is backend-backed (not in-memory) for multi-process deployments
- [ ] Replay store TTL ≥ maximum authorization expiry window

### On Planned Rotation

- [ ] New key generated and private key stored securely
- [ ] New public key added to `trustedKeySets` (with `not_before` set)
- [ ] Updated `trustedKeySets` deployed to **all** guard instances before signing with new key
- [ ] Dual-sign window ≥ maximum authorization expiry duration
- [ ] Old key retired (`not_after` or `status: "retired"`) after dual-sign window

### On Key Compromise

- [ ] Compromised key immediately set to `status: "revoked"` in `trustedKeySets`
- [ ] Updated config deployed urgently to **all** guard instances
- [ ] New key generated and activated simultaneously with revocation deployment
- [ ] Replay store audited for suspicious `auth_id` consumption during the compromise window
- [ ] Compromised `kid` permanently retired — never reused

---

## 9. References

- [`packages/core/src/types/keyset.ts`](../../packages/core/src/types/keyset.ts) — `KeySet`, `KeySetKey`, `KeyStatus` types
- [`packages/core/src/crypto/signatures.ts`](../../packages/core/src/crypto/signatures.ts) — `findKeyInKeySets`, `keyIsActiveAt`
- [`packages/core/src/verification/createVerifier.ts`](../../packages/core/src/verification/createVerifier.ts) — bound verifier API
- [`docs/architecture/threat-model-external-providers.md`](./threat-model-external-providers.md) — full threat model
- [`docs/spec/enforcement/pep-gateway-v1.md`](../spec/enforcement/pep-gateway-v1.md) — PEP Gateway specification
- [`docs/spec/artifacts/authorization-v1.md`](../spec/artifacts/authorization-v1.md) — accepted wire encodings
