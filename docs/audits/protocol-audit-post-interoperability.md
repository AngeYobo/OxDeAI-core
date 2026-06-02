# Protocol Audit - Post-Interoperability Hardening

**Date:** 2026-06-02
**Scope:** OxDeAI execution authorization boundary protocol, after completion of the external-provider interoperability hardening sequence
**Auditor:** Internal protocol audit (Ange)
**Protocol invariant under audit:**

> **No valid authorization → no execution path**

---

## 1. Audit Taxonomy

| Status | Meaning |
|--------|---------|
| `DONE` | Implemented, tested, and specified. Verifiable without reading source. |
| `PARTIAL` | Implemented or specified, but coverage, portability, or documentation is incomplete. |
| `SPECIFIED ONLY` | Formal spec exists. Implementation is present but conformance vectors or tests are missing. |
| `DOCUMENTED ONLY` | Architecture or guidance doc exists. Not directly testable via conformance vectors. |
| `MISSING` | No implementation, spec, test, or doc for this area. |
| `RISK` | Present but carries a residual production or security risk that is not fully mitigated. |

---

## 2. Protocol Area Audit

### 2.1 Authorization Artifacts

| Area | Status | Notes |
|------|--------|-------|
| `AuthorizationV1` structure | `DONE` | Implemented in `@oxdeai/core`. Specified in `authorization-v1.md`. Conformance vectors cover fields, expiry, decision. |
| `decision = "ALLOW"` enforcement | `DONE` | Implemented in `verifyAuthorization`. Conformance vector `authorization-verify-001`. |
| `decision != "ALLOW"` portable vector | `MISSING` | No cross-language conformance vector for DENY decision rejection. Implementation correct; portability unverified. |
| `auth_id` uniqueness | `DONE` | Specified. Replay prevention via `ReplayStore.consumeAuthId`. Conformance vector `authorization-sig-008` (AUTH_REPLAY). |
| `issued_at` required | `DONE` | Verified in `verifyAuthorization`. Conformance vectors include missing-field cases. |
| `nonce` field | `PARTIAL` | Field exists in type. Not actively verified beyond auth_id. No conformance vector covering nonce uniqueness. |
| Public `AuthorizationV1` artifact boundary | `DONE` | Public engine authorization output narrowed to clean `AuthorizationV1`. `toPublicAuthorizationV1()` strips legacy/internal fields (`authorization_id`, `engine_signature`, `state_snapshot_hash`, `policy_version`, `expires_at`) before public signing/hash surfaces. Encoding B / Sift compatibility preserved. Resolved in #102 / #103. |

---

### 2.2 Wire Encodings

| Area | Status | Notes |
|------|--------|-------|
| Encoding A (Core-native) | `DONE` | `alg="Ed25519"`, `expiry`, base64 signature, domain-prefixed preimage. Specified in `authorization-v1.md §5`. Conformance vector `authorization-sig-001`. |
| Encoding B (Sift-compatible) | `DONE` | `alg="ed25519"`, `expires_at`, base64url signature, non-prefixed preimage. Specified. Conformance vector `authorization-sig-010`. |
| Rejected encodings (EdDSA, ED25519) | `DONE` | Vectors `authorization-sig-011`, `authorization-sig-012` enforce case-exact rejection. |
| `expiry` vs `expires_at` precedence | `DONE` | Implemented: `expiry` takes precedence; `expires_at` fallback when `expiry` absent. Specified in `authorization-v1.md §5`. Conformance vector `auth-expiry-wins-over-expires-at`: both fields present, `expiry` expired, `expires_at` valid → DENY/EXPIRED. Resolved in #106. |
| HMAC-SHA256 (legacy) | `DONE` | Explicitly deprecated. `authorization-v1.md §5` now carries a formal deprecation section: not part of the standard AuthorizationV1 wire format; symmetric shared-secret; not independently verifiable by third parties. `legacyHmacSecret` option marked `@deprecated` in `VerifyAuthorizationOptions`. `authorization_signing_alg: "HMAC-SHA256"` default marked `@deprecated` in `EngineOptions` with migration path to Ed25519. Two explicit legacy-path tests added. Resolved in #107. |

---

### 2.3 Canonicalization

| Area | Status | Notes |
|------|--------|-------|
| Core canonicalization function | `DONE` | Implemented in `hashes.ts`. Specified in `canonicalization-v1.md`. Conformance vectors `intent-hash-*.json`, `snapshot-hash-*.json`. |
| Deterministic key ordering | `DONE` | UTF-8 lexicographic sort. Tested via conformance vectors and property tests. Go harness validates cross-language. |
| Duplicate key rejection | `DONE` | Implemented: `DUPLICATE_KEY` error. |
| Float rejection | `DONE` | Implemented: `FLOAT_NOT_ALLOWED`. |
| Unicode NFC normalization | `DONE` | Implemented in `normalizeString`. |
| Unsigned integers / bigint | `DONE` | Implemented with `UNSAFE_INTEGER_NUMBER` guard. |
| Unsupported type rejection | `DONE` | Implemented: `UNSUPPORTED_TYPE` for undefined, function, symbol. |
| Malformed canonicalization edge cases (cross-language) | `PARTIAL` | TS unit tests cover these. No cross-language conformance vectors for malformed inputs (float, duplicate key, unsupported type). |

---

### 2.4 Signature Verification

| Area | Status | Notes |
|------|--------|-------|
| Ed25519 verification (Encoding A, domain-prefixed) | `DONE` | Implemented + conformance vector `authorization-sig-001`. |
| Ed25519 verification (Encoding B, non-prefixed) | `DONE` | Implemented + conformance vector `authorization-sig-010`. |
| Tampered signature → invalid | `DONE` | Conformance vector `authorization-sig-002` (AUTH_SIGNATURE_INVALID). |
| Wrong kid → unknown | `DONE` | Conformance vector `authorization-sig-003` (AUTH_KID_UNKNOWN). |
| Tampered field invalidates signature | `DONE` | Covered in signature vectors. |
| AUTH_ALG_UNSUPPORTED rejection | `DONE` | Conformance vectors `authorization-sig-009`, `authorization-sig-011`, `authorization-sig-012`. |
| Strict mode enforcement | `DONE` | `mode: "strict"` requires `trustedKeySets`; returns `TRUSTED_KEYSETS_REQUIRED` immediately. Implemented in `verifyAuthorization`. |
| `requireSignatureVerification` flag | `DONE` | Implemented; guard always sets `requireSignatureVerification: true`. |

---

### 2.5 Key Lifecycle (`trustedKeySets`)

| Area | Status | Notes |
|------|--------|-------|
| `KeyStatus = "active" \| "retired" \| "revoked"` | `DONE` | Implemented in `keyset.ts`. `keyIsActiveAt` checks `status`, `not_before`, `not_after`. |
| `status = "revoked"` → `AUTH_KEY_INACTIVE` | `DONE` | Implemented in `keyIsActiveAt`. Conformance vector `key-lifecycle-002` (revoked key rejected). Vector `key-lifecycle-009` confirms revocation overrides valid time window. |
| `not_before` enforcement | `DONE` | Implemented. Conformance vector `key-lifecycle-003` (future `not_before` → inactive). |
| `not_after` enforcement | `DONE` | Implemented. Conformance vectors `key-lifecycle-004`, `key-lifecycle-006`, `key-lifecycle-008` (expired windows). |
| Key rotation (dual-sign) | `PARTIAL` | Rotation procedure documented in `key-custody-and-rotation.md`. Dual-sign overlap verified by `key-lifecycle-007` (retired key within window → ok). No automated rotation machinery. |
| Sift KRL (Key Revocation List) | `DONE` | `SiftHttpKeyStore` now supports three KRL integrity modes: `signed_required` (closes transport gap), `signed_preferred` (default, signed when present), `unsigned_legacy` (deprecated). `verifyKrl` callback injection preserves `@oxdeai/sift` zero-dependency boundary. 29 new tests. See `packages/sift/README.md`. |
| `SignedKRLV1` artifact | `DONE` | Defined in `docs/spec/artifacts/signed-krl-v1.md`. `verifySignedKrl` verifier in `@oxdeai/core` with 9 conformance vectors. Integrated into `SiftHttpKeyStore` via `verifyKrl` callback. Phase A (#117): persistent `KrlWatermarkStore` closes restart-and-replay downgrade window. Phase B (#117): `SignedKrlCache` LKG cache closes cold-start unrevoked window; never trusted without re-verification. `RT-TRUST-2` fully closeable when `signed_required` + `KrlWatermarkStore` + `SignedKrlCache` are all configured. |

---

### 2.6 Replay Protection

| Area | Status | Notes |
|------|--------|-------|
| `ReplayStore` interface | `DONE` | Defined in `guard/src/replayStore.ts`. `consumeAuthId` + optional `consumeDelegationId`. Fail-closed contract specified in JSDoc. |
| In-memory replay store | `DONE` | Default implementation. Correct for single-process. |
| Redis replay store | `DONE` | Implemented in `replayStore.redis.ts`. Tested in `guard.replay-store.redis.test.ts`. |
| Durability gap (in-memory default) | `RISK` | Default is in-memory. Process restart loses replay state → window for replay attacks during restart. Documented but no enforcement. |
| Store unavailability → DENY | `DONE` | Guard catches store exceptions and throws `OxDeAIAuthorizationError`. Tested. |
| `expiry` TTL passed to store | `DONE` | `consumeAuthId(authId, { expiry })` interface passes TTL hint to backend. |
| `computeTtl = max(1, expiry − now)` | `DOCUMENTED ONLY` | TTL computation is specified in `replay-store-ttl-alignment.md`. Not enforced in `ReplayStore` interface itself - caller responsibility. **No conformance vector for TTL failures.** |
| Delegation replay | `DONE` | `consumeDelegationId` optional method. Guard always consumes `parentAuth.auth_id`. |
| Conformance vector (AUTH_REPLAY) | `DONE` | `authorization-sig-008` covers replay detection. |
| Cross-process replay race | `RISK` | In-memory store does not serialize across processes. Redis store provides SET NX semantics - adequate. Not verified in cross-language harnesses. |

---

### 2.7 Expiry Enforcement

| Area | Status | Notes |
|------|--------|-------|
| `expiry` boundary enforcement | `DONE` | Implemented + conformance vector `authorization-sig-007` (AUTH_EXPIRED). |
| `expires_at` fallback | `DONE` | Implemented. Conformance vectors `authorization-verify-009`, `authorization-verify-010`. |
| Clock injection via `opts.now` | `DONE` | Implemented. All tests use deterministic timestamps. |
| Clock skew tolerance | `DONE` | Strict zero-tolerance specified in `authorization-v1.md §17`. Valid iff `now < expiry`. No grace period. `issued_at` informational only. NTP required. 10 conformance vectors added (`clock-semantics-verification.json`). |

---

### 2.8 Binding Checks

| Area | Status | Notes |
|------|--------|-------|
| Audience binding (`expectedAudience`) | `DONE` | Enforced in guard config (required, no default). `verifyAuthorization` checks `AUTH_AUDIENCE_MISMATCH`. Conformance vector `authorization-sig-005`. |
| Intent binding (`intent_hash`) | `DONE` | Guard step 6d: recomputes `intentHash(intent)` and compares with `authorization.intent_hash`. Tested in `guard.intent-binding.test.ts`. No cross-language conformance vector. |
| State binding (`state_hash`) | `DONE` | Guard step 6c: computes `computeStateHash(liveState)` and compares. Tested SB-1–SB-13. Profile C vectors provide conformance coverage. |
| Policy binding (`policy_id`) | `DONE` | Guard enforces `expectedPolicyId`. Conformance vector `auth-policy-id-mismatch` present in sig vectors. |
| Issuer binding | `DONE` | `verifyAuthorization` checks `AUTH_ISSUER_MISMATCH`. Conformance vector `authorization-sig-004`. |
| Intent hash portable vector | `DONE` | Portable `auth-intent-mismatch` vector includes `proposed_action`; runner derives `expectedIntentHash = sha256(canonicalize(proposed_action))`. Portable ALLOW case `auth-intent-action-match-1` signed with `portable-key-1` (conformance fixture key). Go/Python authorization harness integration not yet implemented. Resolved in #105. |

---

### 2.9 State Hash and `computeStateHash`

| Area | Status | Notes |
|------|--------|-------|
| Default `computeStateHash` (core) | `DONE` | `engine.computeStateHash(state)` = `sha256HexFromJson`. Specified, implemented, tested. |
| Pluggable `computeStateHash` | `DONE` | `OxDeAIGuardConfig.computeStateHash` optional override. Tested SB-9–SB-13. Documented in `types.ts`. |
| `computeStateHash` throws → DENY | `DONE` | Guard catches exception, throws `OxDeAIAuthorizationError`. Tested SB-13. |
| Strategy mismatch → deterministic DENY | `DONE` | Tested SB-12. Profile C vector `profile-c-003`. |
| Cross-language `computeStateHash` | `MISSING` | Profile C vectors are TypeScript-only. No Go/Python harness supports pluggable hash strategy. External implementers cannot validate strategy-mismatch behavior cross-language. |

---

### 2.10 Interoperability Profiles

| Area | Status | Notes |
|------|--------|-------|
| Profile A (Core-native) | `DONE` | Defined, implemented, conformance covered by existing auth-sig and auth-verify vectors. |
| Profile B (External wire-compatible) | `DONE` | Defined. Encoding B accepted in verifyAuthorization. Conformance vector `authorization-sig-010`. Trust separation proven: `pb-trust-oxdeai-key-allow` (OxDeAI key in trustedKeySets → ALLOW) and `pb-trust-provider-key-rejected` (provider receipt key absent from trustedKeySets → DENY/UNKNOWN_KID). Resolved in #108. |
| Profile C (Full semantic state verification) | `DONE` | Defined. Implemented via pluggable `computeStateHash`. 12 executable conformance assertions across 8 vectors. Encoding B path tested. |
| Profile C cross-language | `DONE` | Go + Python harnesses validate state-hash semantics (modes 001–005) via `docs/spec/test-vectors/profile-c-state-verification.json`. Profile C Encoding B modes 006–008 remain TypeScript-only and are tracked separately. |
| Interoperability matrix | `DOCUMENTED ONLY` | Matrix in `external-provider-profile.md`. Not backed by conformance automation. |

---

### 2.11 PEP Gateway

| Area | Status | Notes |
|------|--------|-------|
| PEP gateway spec | `DONE` | Specified in `pep-gateway-v1.md`. |
| `OxDeAIGuard` implementation | `DONE` | Implements full 11-step guard lifecycle. Tested across ~16 test files. |
| DENY path | `DONE` | `OxDeAIDenyError` thrown before execute. Tested. |
| ALLOW without authorization → DENY | `DONE` | `OxDeAIAuthorizationError` thrown. Tested. |
| ALLOW without nextState → DENY | `DONE` | `OxDeAIAuthorizationError` thrown. Tested. |
| CAS state commit | `DONE` | `setState(nextState, version)` before execute. `OxDeAIConflictError` on mismatch. Tested in `guard.cas.test.ts`. |
| `beforeExecute` hook | `DONE` | Optional; called after all checks, before execute. |
| `onDecision` audit hook | `DONE` | Optional; exceptions swallowed. Tested. |
| HTTP PEP middleware | `MISSING` | Planned in v2.6. No implementation yet. |
| Gateway isolation (network) | `MISSING` | No spec for PEP network isolation requirements. Noted in `pep-production-guide.md`. |

---

### 2.12 Delegation

| Area | Status | Notes |
|------|--------|-------|
| `DelegationV1` structure | `DONE` | Specified in `delegation-v1.md`. Conformance vectors. |
| Delegation chain verification | `DONE` | `verifyDelegationChain`. Tested. Cross-language via Go harness. |
| Scope narrowing | `DONE` | Tools + max_amount. Tested. Conformance vectors. |
| Delegation scope verification in guard | `DONE` | Guard step 3: checks `scope.tools`, `scope.max_amount`. |
| Delegation replay | `DONE` | `consumeDelegationId` + `consumeAuthId(parentAuth)`. |
| `parentScope` requirement | `DONE` | `parentScope` is now an explicit required field on `GuardDelegationInput`. Structurally validated by `isValidDelegationScope` before delegation chain verification. The unsafe `(parentAuth as any).scope` cast has been removed. Missing or malformed `parentScope` fails closed before execution. |
| Multi-hop delegation | `SPECIFIED ONLY` | Spec allows single-hop only (`DELEGATION_SINGLE_HOP` violation). Not tested with a chain > 2. |
| `parent_auth_hash` portability | `DONE` | `delegationParentHash()` now hashes `canonicalJson(toPublicAuthorizationV1(parent))`, so `DelegationV1` parent binding no longer depends on TypeScript-specific legacy fields. Independent implementations can reproduce the parent hash from normative `AuthorizationV1` fields alone. Resolved in #102 / #103. |

---

### 2.13 Supporting Documentation

| Area | Status | Notes |
|------|--------|-------|
| External provider threat model | `DOCUMENTED ONLY` | `threat-model-external-providers.md`. 12 threat scenarios T-1–T-12. Not backed by conformance vectors or automated tests. |
| Key custody and rotation guide | `DOCUMENTED ONLY` | `key-custody-and-rotation.md`. KC-1–KC-8 scenarios. No executable test coverage for lifecycle scenarios. |
| Replay-store TTL alignment guide | `DOCUMENTED ONLY` | `replay-store-ttl-alignment.md`. RT-1–RT-10 scenarios. No conformance vectors. |
| Failure playbooks | `PARTIAL` | Threat model covers 12 attack scenarios. Operator-facing failure playbooks (runbooks) are not yet written. |
| Deployment guide | `PARTIAL` | `pep-production-guide.md` exists. Gap: network isolation requirements. Clock skew spec resolved (`authorization-v1.md §17`). |

---

## 3. Invariant Audit

| Invariant | Implemented | Tested | Specified | Documented | Portable |
|-----------|-------------|--------|-----------|------------|----------|
| No valid `AuthorizationV1` → no execution | Yes | Yes | Yes (`pep-gateway-v1.md`) | Yes | Yes (Go harness) |
| Invalid signature → DENY | Yes | Yes | Yes | Yes | Yes (cross-language sig vectors) |
| Unknown issuer / kid → DENY | Yes | Yes | Yes | Yes | Yes (conformance vector AUTH_KID_UNKNOWN) |
| Wrong audience → DENY | Yes | Yes | Yes | Yes | Yes (conformance vector AUTH_AUDIENCE_MISMATCH) |
| Expired authorization → DENY | Yes | Yes | Yes | Yes | Yes (conformance vector AUTH_EXPIRED) |
| Replay → DENY | Yes | Yes | Yes | Yes | **Partial** (conformance vector AUTH_REPLAY; durable store semantics not cross-language verified) |
| Intent mismatch → DENY | Yes | Yes | Yes (portable `authorization-v1.json` vector with `proposed_action`) | Yes | **Partial** (portable vector with independent hash derivation; Go/Python auth harness not yet integrated) |
| State mismatch → DENY | Yes | Yes | Profile C spec | Yes | **No** (Profile C vectors TypeScript-only) |
| Hash strategy ambiguity → DENY | Yes | Yes (SB-12, PC-003) | Yes (Profile C spec) | Yes | **No** (TypeScript-only) |
| Replay-store unavailability → DENY | Yes | Yes (guard test) | Yes (ReplayStore JSDoc) | Yes | **No** (no cross-language conformance vector) |
| Provider ambiguity → DENY | Yes | Partial | Yes (Profile C spec) | Yes (threat model) | **No** (TypeScript-only) |
| Revoked key → DENY | Yes (`keyIsActiveAt`) | Yes (`key-lifecycle-002`, `key-lifecycle-009`) | Yes (key-lifecycle vectors) | Yes (key-custody doc) | Yes (portable vector) |
| Key `not_before` → DENY | Yes | Yes (`key-lifecycle-003`) | Yes | Yes (key-custody doc) | Yes (portable vector) |
| Key `not_after` → DENY | Yes | Yes (`key-lifecycle-004`, `key-lifecycle-006`, `key-lifecycle-008`) | Yes | Yes (key-custody doc) | Yes (portable vector) |

---

## 4. Conformance Coverage Audit

**Current total:** 181 assertions across 15 vector files.

### 4.1 Covered Areas

| Vector Set | Count | Coverage |
|------------|-------|----------|
| `intent-hash.json` | 5 | Intent hash computation + key-order invariance |
| `authorization-payload.json` | 9 | Payload field checks, expiry, canonical signing payload, signature |
| `authorization-verification.json` | 20 | Field validation, expiry, audience, replay, Encoding B structural |
| `authorization-signature-verification.json` | 24 | Encoding A/B, tamper, wrong kid, audience, replay, alg rejection |
| `snapshot-hash.json` | 5 | State snapshot hash computation |
| `audit-chain.json` | 7 | Audit chain hash integrity |
| `audit-verification.json` | 10 | Audit event verification |
| `envelope-verification.json` | 9 | Envelope structural checks |
| `envelope-signature-verification.json` | 10 | Envelope Ed25519 signature path |
| `delegation-parent-hash.json` | 3 | SHA256 of canonical auth, key-order invariance |
| `delegation-verification.json` | 18 | Delegation field checks, scope, replay, trust |
| `delegation-chain-verification.json` | 14 | Chain hash binding, delegator, expiry, policy |
| `delegation-signature-verification.json` | 10 | Delegation Ed25519 path |
| `key-lifecycle-verification.json` | 20 | Key status (active/revoked/retired), `not_before`/`not_after` windows, wrong-kid rejection |
| `profile-c-state-verification.json` | 12 | Semantic state verification, strategies, TOCTOU, Encoding B |

### 4.2 Missing or Weak Coverage

The following areas still have **no portable conformance vector**:

| Gap | Risk Level | Notes |
|-----|-----------|-------|
| `decision != "ALLOW"` portable vector | **Medium** | Only checked structurally; no dedicated cross-language vector. |
| Both `expiry` and `expires_at` present simultaneously | ~~**Medium**~~ | ✓ Resolved: vector `auth-expiry-wins-over-expires-at` locks the precedence rule - `expiry` expired + `expires_at` valid → DENY/EXPIRED. Resolved in #106. |
| Intent hash mismatch → DENY (cross-language) | ~~**Medium**~~ | ✓ Resolved: `authorization-v1.json` now includes `proposed_action` field enabling independent hash derivation. Portable ALLOW case `auth-intent-action-match-1` and `portable-key-1` fixture key added. Go/Python authorization harness integration remains a future item. Resolved in #105. |
| Profile B trust separation vector | ~~**Medium**~~ | ✓ Resolved: `pb-trust-oxdeai-key-allow` proves OxDeAI key (in trustedKeySets) verifies correctly; `pb-trust-provider-key-rejected` proves provider receipt key absent from trustedKeySets returns DENY/UNKNOWN_KID. Resolved in #108. |
| Profile C cross-language vectors | **Medium** | Profile C vectors are TypeScript-only. `computeStateHash` requires adapter integration. |
| Replay TTL failure scenarios | **Low** | RT-1–RT-10 documented; none executable as portable conformance vectors. |
| Malformed canonicalization (float, duplicate key) cross-language | **Low** | TypeScript unit tests exist. No cross-language conformance vectors for error cases. |
| Clock skew behavior | ~~**Low**~~ | ✓ Resolved: strict zero-tolerance specified (`authorization-v1.md §17`) + 10 conformance vectors added. |

---

## 5. Trust Boundary Audit

### 5.1 Trust Model Summary

```
[External Provider / Sift]
        │
        │ Signs receipt (Sift receipt key)
        ▼
[Sift Adapter] ──── converts ────► [AuthorizationV1]
                                          │
                                          │ Signs with OxDeAI signing key
                                          ▼
                              [OxDeAI Trust Domain]
                                     │
                           ┌─────────┴─────────┐
                    [trustedKeySets]       [ReplayStore]
                                     │
                              [OxDeAIGuard / PEP]
                                     │
                              [execute() boundary]
```

### 5.2 Component Trust Assessment

| Component | Trust Assumption | Risk | Notes |
|-----------|-----------------|------|-------|
| Issuer keys (`trustedKeySets`) | Trusted at config time | Low | Required, validated, no fallback. `keyIsActiveAt` enforced. |
| Adapter (Sift) signing keys | Trusted within adapter boundary | Medium | Sift receipt key ≠ AuthorizationV1 signing key. Trust bridge is explicit but depends on adapter implementation correctness. |
| Sift KRL (Key Revocation List) | Trusted via HTTPS only | **High** | KRL payload is NOT cryptographically signature-verified. A compromised intermediary can omit revocations. Noted risk. |
| PEP gateway (`OxDeAIGuard`) | Fully trusted; must be outside agent runtime | Low | Correctly positioned. Guard validates config at construction. |
| Replay store | Trusted backend | Medium | In-memory default is not durable. Durable backends (Redis) are pluggable but not enforced. |
| State provider (`getState()`) | Fully trusted | **High** | State is accepted without integrity verification. A compromised state provider can manufacture any `state_hash`. No integrity protocol exists for the state source. |
| Upstream executor (`execute()`) | Fully trusted | Low | By design. Guard decides admission; executor decides actuation. |
| Offline verifier | No trust required | Low | `verifyAuthorization` is stateless. Can verify without network. |
| External provider (full Profile C) | Trusted within adapter scope | Medium | `computeStateHash` strategy must match. Mismatch → deterministic fail-closed. Documented. |

### 5.3 Residual Trust Risks

**RT-TRUST-1: State provider integrity**
The state provider is unconditionally trusted. A compromised `getState()` implementation can return a state that produces a matching `state_hash` for an authorization, bypassing the semantic check. **No mitigation exists at the protocol layer.** Documented in `threat-model-external-providers.md` (T-8).

**RT-TRUST-2: KRL transport integrity** *(closeable for deployments using signed_required + persistent stores)*
`SiftHttpKeyStore` supports three KRL integrity modes. `signed_required` closes the transport-integrity gap. **Phase A (#117):** `KrlWatermarkStore` + `createFileBackedKrlWatermarkStore` added — persistent watermark closes the restart-and-replay downgrade window. **Phase B (#117):** `SignedKrlCache` + `createFileBackedSignedKrlCache` added — LKG cache closes the cold-start unrevoked window; cached payloads are always re-verified before use. `RT-TRUST-2` is fully closeable when `signed_required` + `KrlWatermarkStore` + `SignedKrlCache` are all configured. **Residual risk:** without all three, some windows remain open. `signed_preferred` unsigned fallback and `unsigned_legacy` retain transport-trust-only semantics and are not production-grade revocation integrity.

**RT-TRUST-3: Replay store bootstrapping**
New deployments start with an empty replay store. Authorization artifacts issued before the store was populated can replay within their validity window. No mitigation; documented in `replay-store-ttl-alignment.md` (RT-3: clock-skew edge) and adjacent scenarios.

---

## 6. Production Readiness Audit

| Area | Status | Notes |
|------|--------|-------|
| Single-process deployment | `DONE` | In-memory replay store; CAS state; no dependencies. |
| Multi-process / horizontal scaling | `RISK` | Requires durable replay store (Redis available). **No enforcement or detection** when in-memory store is accidentally used in a scaled deployment. |
| Process restart durability | `RISK` | In-memory replay store loses state on restart. Window for replayed authorizations until store repopulates. |
| Redis replay store | `DONE` | Implemented, tested (`guard.replay-store.redis.test.ts`). |
| Clock skew | `DONE` | Strict zero-tolerance specified (`authorization-v1.md §17`). `opts.now` injection required. NTP synchronization required; issuers build latency into expiry. Undefined behavior eliminated. |
| Key rotation automation | `PARTIAL` | Manual procedures documented (dual-sign + TTL overlap). No automated rotation tooling. |
| State-source integrity | `RISK` | See RT-TRUST-1. Protocol layer cannot verify state provider integrity. |
| Monitoring / observability | `PARTIAL` | `onDecision` hook provides per-decision events. No structured event schema, no metrics contract, no alerting spec. |
| Audit log durability | `PARTIAL` | `verifyAuditEvents` and `ReplayEngine` exist. Audit log persistence is caller responsibility. No storage spec. |
| Network isolation of PEP | `PARTIAL` | `pep-production-guide.md` recommends isolation. No enforcement mechanism in the protocol. |
| Deployment checklist | `PARTIAL` | Key custody (`key-custody-and-rotation.md`) and replay store (`replay-store-ttl-alignment.md`) checklists exist. No unified deployment checklist covering all areas. |

---

## 7. Standardization Readiness Assessment

### 7.1 External Implementer Readiness

**Status: PARTIAL**

- `AuthorizationV1` is well-specified and has cross-language conformance vectors (Go harness).
- Canonicalization-v1 is fully specified with cross-language vectors.
- `DelegationV1` has cross-language vectors.
- ~~**Gap:** Key lifecycle (`revoked`, `not_before`, `not_after`) has no portable conformance vectors.~~ ✓ resolved - `key-lifecycle-verification.json` added (P0-1).
- ~~**Gap:** Intent hash mismatch has no cross-language vector.~~ ✓ resolved - portable `authorization-v1.json` vector with `proposed_action` added (P1-1).
- **Gap:** State hash mismatch has no cross-language vector.
- **Gap:** Profile C is TypeScript-only; `computeStateHash` integration requires external harness work.

### 7.2 Independent Verifier Readiness

**Status: PARTIAL**

`verifyAuthorization` is stateless and fully portable. An independent verifier can reproduce all signature checks and field validation with the existing conformance vectors. However:

- No vector for `AUTH_KEY_INACTIVE` (revoked or window-expired key).
- ~~No vector for simultaneous `expiry`/`expires_at` precedence.~~ ✓ resolved - `auth-expiry-wins-over-expires-at` vector added (P1-2).
- Strict-mode behavior (no `trustedKeySets` provided) is not covered by a portable vector.

### 7.3 Conformance Suite Readiness

**Status: PARTIAL**

191 assertions across 15 vector files + 10 portable `authorization-v1.json` vectors. Key lifecycle, intent hash mismatch, and expiry precedence coverage resolved. Remaining gaps:

1. ~~Key lifecycle vectors (revoked, not_before, not_after)~~ ✓ resolved - `key-lifecycle-verification.json`
2. ~~Intent hash mismatch portable vector~~ ✓ resolved - `authorization-v1.json` vectors include `proposed_action` mismatch case and portable ALLOW case; Go/Python auth harness integration is a future item
3. ~~`expiry`/`expires_at` simultaneous presence precedence vector~~ ✓ resolved - `auth-expiry-wins-over-expires-at` vector locks precedence rule
4. Cross-language Profile C vectors - important for Profile C adoption

### 7.4 Interoperability Profile Readiness

**Status: READY (Profile A/B), PARTIAL (Profile C)**

- Profile A: fully specified, conformance covered.
- Profile B: specified, Encoding B conformance covered, trust separation vectorized (`pb-trust-oxdeai-key-allow`, `pb-trust-provider-key-rejected`). Resolved in #108.
- Profile C: specified, 12 executable assertions. Cross-language portability requires additional harness work.

### 7.5 Security Review Readiness

**Status: PARTIAL**

- Threat model covers 12 scenarios with fail-closed analysis (T-1–T-12).
- Key custody and rotation guide covers KC-1–KC-8 compromise scenarios.
- No formal STRIDE analysis or independent cryptographic review.
- KRL transport risk is a known open item.
- State provider trust is a known open item.
- No security advisory process defined.

### 7.6 Standard Adoption Readiness

**Status: NOT READY**

Prerequisites before external standard positioning:

1. ~~Close key lifecycle conformance vector gap~~ ✓ resolved
2. ~~Define clock skew tolerance specification~~ ✓ resolved
3. ~~Separate public `AuthorizationV1` artifact boundary from internal legacy shape~~ ✓ resolved - clean public artifact projection added; `DelegationV1` parent hashing no longer depends on internal legacy fields
4. ~~Close intent hash mismatch portable vector gap~~ ✓ resolved - portable `AuthorizationV1` vector added with `proposed_action`
5. ~~Close `expiry`/`expires_at` precedence vector gap~~ ✓ resolved - `auth-expiry-wins-over-expires-at` vector locks precedence rule
6. Resolve or formally mitigate state provider trust risk
7. Resolve or formally mitigate KRL transport integrity risk
8. Independent security review
9. Establish external feedback or co-author channel

---

## 8. Maturity Map

```
Layer                        Maturity
─────────────────────────────────────────────────────────────────────
AuthorizationV1 structure    ████████████████████  DONE
Canonicalization-v1          ████████████████████  DONE
Signature verification       ████████████████████  DONE
Wire encodings (A + B)       ████████████████████  DONE
Audience / expiry / replay   ████████████████████  DONE
State binding (guard)        ████████████████████  DONE
Intent binding (guard)       ████████████████████  DONE (portable vector; Go/Python auth harness pending)
Key lifecycle (lifecycle)    ████████████████████  DONE (20 portable vectors)
DelegationV1                 ████████████████████  DONE
Profile A interop            ████████████████████  DONE
Profile B interop            ████████████████░░░░  PARTIAL (trust sep. gap)
Profile C interop            ████████████████████  DONE (state-hash semantics; Encoding B modes 006–008 TS-only)
Profile C cross-language     ████████████████████  DONE (Go + Python state-hash semantics; Encoding B modes 006–008 TS-only)
Replay durability            ████████████████░░░░  PARTIAL (in-memory default risk)
Key rotation                 ██████████░░░░░░░░░░  DOCUMENTED ONLY
Threat model                 ██████████░░░░░░░░░░  DOCUMENTED ONLY
Clock skew spec              ████████████████████  DONE (strict zero-tolerance + 10 vectors)
Public artifact boundary     ████████████████████  DONE (#103: toPublicAuthorizationV1, delegationParentHash)
SignedKRLV1 artifact         ████████████████████  DONE (verifier + 9 vectors; signed_required mode closes transport gap)
HTTP PEP                     ░░░░░░░░░░░░░░░░░░░░  MISSING (planned v2.6)
Structured events / metrics  ░░░░░░░░░░░░░░░░░░░░  MISSING
```

---

## 9. Prioritized Follow-up Issues

### P0 - Must resolve before external adoption

**P0-1: Add portable conformance vectors for key lifecycle** ✓ RESOLVED
Resolution: `key-lifecycle-verification.json` added - 10 vectors, 20 assertions covering active, revoked, retired (within/past window), `not_before`/`not_after` time windows, revocation-overrides-window, and wrong-kid-known-issuer. Conformance count: 161 → 181.

**P0-2: Define and specify clock skew tolerance** ✓ RESOLVED
Resolution: Strict zero-tolerance selected and specified. `authorization-v1.md §17` defines: valid iff `now < expiry`, no grace period, `issued_at` informational-only (no lower-bound enforcement), NTP synchronization required, issuers must build delivery latency into expiry window. `clock-semantics-verification.json` added - 5 vectors, 10 assertions covering last-valid-second, one-past-expiry, verifier-clock-behind, and Encoding B variants. Conformance count: 181 → 191.

**P0-3: Harden `parentScope` handling in `OxDeAIGuard`** ✓ RESOLVED
Resolution: `GuardDelegationInput` now requires `parentScope: DelegationScope` as an explicit typed field. `isValidDelegationScope` validates the structure before chain verification. The unsafe `(parentAuth as any).scope` cast has been removed from `guard.ts`. All delegation tests and the `delegation-demo` example updated to pass `parentScope` explicitly. Missing or malformed `parentScope` fails closed before execution; `OxDeAIAuthorizationError` is thrown before the delegation chain verification path is reached.

**P0-4: Separate public `AuthorizationV1` artifact boundary from internal legacy authorization shape** ✓ RESOLVED
Resolution: `EvaluatePureOutput.authorization` narrowed from `Authorization` (which leaked `authorization_id`, `engine_signature`, `state_snapshot_hash`, `policy_version`, `expires_at`) to clean `AuthorizationV1`. `toPublicAuthorizationV1()` added as the single explicit projection boundary: strips all legacy/internal fields before any public signing, hashing, or delegation parent computation. `delegationParentHash()` updated to hash `canonicalJson(toPublicAuthorizationV1(parent))` so `DelegationV1` parent binding is reproducible by any independent implementation without access to engine internals. Encoding B / Sift compatibility preserved (existing tokens remain verifiable without re-signing). Seven new `public-artifact-boundary.test.ts` assertions prove the boundary holds under legacy field injection. This removes one P0 standardization blocker; it does not claim standardization readiness. Resolved in #102 / #103.

---

### P1 - Should resolve before standardization positioning

**P1-1: Add intent hash mismatch portable conformance vector** ✓ RESOLVED
Resolution: `authorization-v1.json` now includes `proposed_action` on the existing `auth-intent-mismatch` vector and a new `auth-intent-action-match-1` portable ALLOW case signed with `portable-key-1` (conformance fixture key). The vector runner derives `expectedIntentHash = sha256(canonicalize(proposed_action))`, proving the intent binding invariant without TypeScript guard internals. Authorization vector count: 8 → 9. Resolved in #105.

**P1-2: Add `expiry`/`expires_at` simultaneous presence precedence vector** ✓ RESOLVED
Resolution: `authorization-v1.json` vector `auth-expiry-wins-over-expires-at` added: both `expiry` (expired: 1712447100) and `expires_at` (valid: 9999999999) present; expected DENY/EXPIRED. An implementer that incorrectly prefers `expires_at` would return ALLOW, failing the test. Authorization vector count: 9 → 10. Resolved in #106.

**P1-3: Add Profile B trust separation conformance vector** ✓ RESOLVED
Resolution: Two vectors added to `authorization-v1.json`: `pb-trust-oxdeai-key-allow` (artifact signed by `portable-key-1`, an OxDeAI key present in the runner's `keys` array → ALLOW) and `pb-trust-provider-key-rejected` (identical artifact with `signature.kid = "provider-receipt-key-1"`, a provider receipt key absent from the `keys` array → DENY/UNKNOWN_KID). Proves that the PEP must verify AuthorizationV1 artifacts against OxDeAI trustedKeySets, not the provider's receipt-signing key. Authorization vector count: 10 → 12. Resolved in #108.

**P1-4: Resolve KRL transport integrity risk** ✓ RESOLVED for `signed_required`; residual risk in default mode
Resolution: `SiftHttpKeyStore` now supports three KRL integrity modes via `verifyKrl` callback injection (Patch A + Patch B):
- `signed_required` - closes the transport-integrity gap. Every KRL must be a signed `SignedKRLV1` verified by `verifySignedKrl` from `@oxdeai/core`. Unsigned KRLs rejected before `verifyKrl` is consulted. Constructor fails fast without `verifyKrl`.
- `signed_preferred` (default) - signed KRLs verified when present; unsigned fallback for unsigned KRLs. Signed KRL with missing `verifyKrl` fails closed.
- `unsigned_legacy` - deprecated; transport-trust-only; warns at construction.
`@oxdeai/sift` zero-dependency boundary preserved via callback injection. `krl_version` per-issuer watermark tracked in memory. `getKrlStatus()` status surface added. 29 new mode tests in `siftKeyStore.krl-modes.test.ts`.
Caveats: transport-integrity gap is only fully closed when callers deploy `signed_required`. `signed_preferred` unsigned fallback and `unsigned_legacy` retain transport-trust-only semantics. Persistent high-watermark storage and cross-language KRL vectors remain future work. Non-string `revoked_kids` skipping is legacy-path-only behavior, not `SignedKRLV1` semantics.
**KRL reason-code ownership:** Four codes are Sift-local (produced by mode logic, NOT from `@oxdeai/core`): `KRL_UNSIGNED_IN_SIGNED_REQUIRED`, `KRL_MISSING_VERIFY_CALLBACK`, `KRL_VERIFY_CALLBACK_ERROR`, `KRL_VERIFY_RESULT_INCOMPLETE`. Seven core codes are passed through as opaque strings from the `verifyKrl` callback: `KRL_MALFORMED`, `KRL_SIG_INVALID`, `KRL_EXPIRED`, `KRL_UNSUPPORTED_ALG`, `KRL_UNKNOWN_SIGNING_KID`, `KRL_SIGNING_KEY_INACTIVE`, `KRL_VERSION_REGRESSION`.

**P1-5: Mark HMAC-SHA256 as deprecated** ✓ RESOLVED
Resolution: `authorization-v1.md §5` now carries an explicit "Deprecated legacy algorithm" section: HMAC-SHA256 is not standard, is symmetric/non-portable, and its migration path is documented. `legacyHmacSecret` in `VerifyAuthorizationOptions` carries a `@deprecated` JSDoc with removal notice. `authorization_signing_alg: "HMAC-SHA256"` default in `EngineOptions` carries a `@deprecated` JSDoc directing new users to Ed25519. Two explicit legacy-path tests document backward-compat guarantee and the fail-closed behavior when `legacyHmacSecret` is absent. Resolved in #107.

**P1-6: Add cross-language Profile C and SignedKRLV1 conformance vectors** ✓ RESOLVED for Profile C state-hash semantics and SignedKRLV1 cross-language coverage (Go + Python). Profile C Encoding B modes 006–008 remain TypeScript-only and are tracked separately.

Go coverage (#119 Go PR):
- `go-harness/profile_c_verify.go` validates Profile C state-hash semantics modes 001–005 independently.
- `go-harness/signed_krl_verify.go` validates all 9 SignedKRLV1 portable vectors with independent Ed25519 verification.
- Portable vector files: `docs/spec/test-vectors/profile-c-state-verification.json`, `docs/spec/test-vectors/signed-krl-v1.json`.

Python coverage (#119 Python PR):
- `python-harness/verify_profile_c_vectors.py` validates Profile C state-hash semantics modes 001–005 independently using canonicalization-v1 and SHA-256 via Python stdlib.
- `python-harness/verify_signed_krl_vectors.py` validates all 9 SignedKRLV1 portable vectors using canonicalization-v1 and Ed25519 via ctypes + libcrypto (no external packages).
- Cross-language byte-equivalence proven: duplicate-kids signature `+mwEd2QP5+tx...` verifies identically in Go and Python.

Residual limitations:
- Profile C Encoding B modes 006–008 remain TypeScript-only (require AuthorizationV1 Encoding B infrastructure; tracked separately).
- State provider trust (RT-TRUST-1, P2-4) and independent security review remain open.
- No full standardization readiness claim.

---

### P2 - Address before production scale-out

**P2-1: Enforce durable replay store configuration in scaled deployments**
Reason: Default in-memory store silently degrades to single-process semantics. No detection or warning when deployed in multi-process context. Add a configuration flag or documentation assertion that fails loudly if a non-durable store is used in an environment where durability is expected.
Scope: `OxDeAIGuardConfig` - optional `replayStoreTier` hint or guard-level warning.

**P2-2: Add replay TTL failure conformance vectors (subset of RT scenarios)**
Reason: RT-1–RT-10 are documented but not executable. At minimum, RT-1 (TTL computed as zero) and RT-3 (clock skew edge) should be vectorized to make failure semantics testable.
Scope: New `replay-ttl-verification.json` vector set.

**P2-3: Define structured decision event schema**
Reason: `onDecision` hook exists but produces no specified schema. Observability tooling cannot be built reliably without a stable event format.
Scope: `GuardDecisionRecord` type - finalize as a versioned schema; add to `pep-gateway-v1.md`.

**P2-4: Specify state provider trust boundary**
Reason: `getState()` is unconditionally trusted at the protocol layer. No minimum integrity requirements are specified for the state source. Specify access controls, CAS semantics, and audit expectations for compliant state provider implementations.
Scope: `pep-gateway-v1.md` §7 or a new `state-provider-requirements.md`.

---

## 10. Audit Summary

**Total areas audited:** 24 protocol areas, 14 invariants, 18 conformance vector sets, 9 trust components.

| Status | Count |
|--------|-------|
| `DONE` | 58 |
| `PARTIAL` | 16 |
| `SPECIFIED ONLY` | 5 |
| `DOCUMENTED ONLY` | 6 |
| `MISSING` | 5 |
| `RISK` | 4 |

**Conformance:** 209 TypeScript assertions (16 TS vector files + 12 portable `authorization-v1.json` vectors) + 25 Go harness assertions (11 canonicalization + 5 Profile C state-hash + 9 SignedKRLV1) + 25 Python harness assertions (same coverage as Go). All P0 and P1 items resolved; P1-6 cross-language coverage complete for state-hash semantics (Encoding B modes remain TS-only).

**Follow-up issue counts:** P0: 0 open · P1: 0 open · P2: 4 · Total: 4 open

**Critical path to external adoption:**

1. ~~Key lifecycle portable vectors (P0-1)~~ ✓ resolved - 20 assertions added
2. ~~Clock skew specification (P0-2)~~ ✓ resolved - strict zero-tolerance specified, 10 assertions added
3. ~~parentScope type safety in guard (P0-3)~~ ✓ resolved - unsafe cast removed, fail-closed before chain verification
4. ~~Public `AuthorizationV1` artifact boundary (P0-4)~~ ✓ resolved - clean public artifact projection added; `DelegationV1` parent hashing no longer depends on internal legacy fields
5. ~~Intent hash mismatch portable vector (P1-1)~~ ✓ resolved - portable `AuthorizationV1` vector added for `proposed_action` mismatch
6. ~~`expiry`/`expires_at` precedence vector (P1-2)~~ ✓ resolved - `auth-expiry-wins-over-expires-at` vector locks precedence rule
7. ~~HMAC-SHA256 deprecation (P1-5)~~ ✓ resolved - spec deprecation notice added; `@deprecated` JSDoc on `legacyHmacSecret` and `authorization_signing_alg`
8. Cross-language Profile C vectors (P1-6)

**Protocol positioning:**

OxDeAI is a working, tested execution authorization boundary protocol at the **interoperable protocol** maturity level. Core invariants are implemented and tested. AuthorizationV1, wire encodings, signature verification, replay protection, state binding, and delegation are all in solid shape. Profile A/B/C are specified; Profile A and C have executable conformance coverage.

The protocol is **not yet ready for standard adoption**. Key lifecycle, clock skew, parentScope type safety, public artifact boundary separation, intent hash mismatch portability, expiry precedence, HMAC-SHA256 deprecation, KRL transport integrity (for `signed_required` mode deployments), and Profile C / SignedKRLV1 cross-language coverage (Go + Python) are now resolved. State provider trust (RT-TRUST-1) and independent security review remain open before that claim can be made honestly.

---

*This document reflects the protocol state as of 2026-06-02. It should be revisited after each significant milestone.*
