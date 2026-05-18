# Protocol Audit - Post-Interoperability Hardening

**Date:** 2026-05-17  
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

---

### 2.2 Wire Encodings

| Area | Status | Notes |
|------|--------|-------|
| Encoding A (Core-native) | `DONE` | `alg="Ed25519"`, `expiry`, base64 signature, domain-prefixed preimage. Specified in `authorization-v1.md §5`. Conformance vector `authorization-sig-001`. |
| Encoding B (Sift-compatible) | `DONE` | `alg="ed25519"`, `expires_at`, base64url signature, non-prefixed preimage. Specified. Conformance vector `authorization-sig-010`. |
| Rejected encodings (EdDSA, ED25519) | `DONE` | Vectors `authorization-sig-011`, `authorization-sig-012` enforce case-exact rejection. |
| `expiry` vs `expires_at` precedence | `PARTIAL` | Implemented: `expiry` takes precedence; `expires_at` fallback when `expiry` absent. Specified in `authorization-v1.md §5`. No conformance vector testing the precedence when **both** fields are present simultaneously. |
| HMAC-SHA256 (legacy) | `PARTIAL` | Implemented with `legacyHmacSecret`. No conformance vector; treated as backward-compat only. Spec does not list as an accepted encoding. Should be marked deprecated. |

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
| Sift KRL (Key Revocation List) | `PARTIAL` | `SiftHttpKeyStore` checks `revoked_kids`. KRL payload is **not cryptographically signature-verified** - transport security (HTTPS) only. Known risk, documented in `packages/sift/README.md`. |

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
| Intent hash portable vector | `MISSING` | No cross-language conformance vector for intent hash mismatch rejection (only TypeScript guard test). |

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
| Profile B (External wire-compatible) | `PARTIAL` | Defined. Encoding B accepted in verifyAuthorization. Conformance vector `authorization-sig-010`. **No vector for Profile B trust separation** (Sift receipt trust root ≠ AuthorizationV1 signing key). |
| Profile C (Full semantic state verification) | `DONE` | Defined. Implemented via pluggable `computeStateHash`. 12 executable conformance assertions across 8 vectors. Encoding B path tested. |
| Profile C cross-language | `MISSING` | No Go/Python harness integration for Profile C vectors. |
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
| `parentScope` requirement | `RISK` | Guard requires `(parentAuth as any).scope`. Uses `as any` cast - no TypeScript safety for this field. Could silently fail if scope absent. |
| Multi-hop delegation | `SPECIFIED ONLY` | Spec allows single-hop only (`DELEGATION_SINGLE_HOP` violation). Not tested with a chain > 2. |

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
| Intent mismatch → DENY | Yes | Yes | No conformance vector | Partial | **No** (TypeScript guard test only; no cross-language vector) |
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
| Both `expiry` and `expires_at` present simultaneously | **Medium** | Precedence rule (`expiry` wins) has no test vector. |
| Intent hash mismatch → DENY (cross-language) | **Medium** | TypeScript guard test only. External implementers cannot verify intent binding. |
| Profile B trust separation vector | **Medium** | No vector where Sift receipt key ≠ AuthorizationV1 signing key for same `kid`. |
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

**RT-TRUST-2: KRL transport integrity**  
Sift KRL is not cryptographically signed. MITM can suppress revocations. Documented as known limitation in `packages/sift/README.md`. Mitigation: wait for Sift to publish a signed KRL contract.

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
- **Gap:** Key lifecycle (`revoked`, `not_before`, `not_after`) has no portable conformance vectors. An external implementer cannot validate key status handling.
- **Gap:** Intent hash mismatch and state hash mismatch have no cross-language vectors.
- **Gap:** Profile C is TypeScript-only; `computeStateHash` integration requires external harness work.

### 7.2 Independent Verifier Readiness

**Status: PARTIAL**

`verifyAuthorization` is stateless and fully portable. An independent verifier can reproduce all signature checks and field validation with the existing conformance vectors. However:

- No vector for `AUTH_KEY_INACTIVE` (revoked or window-expired key).
- No vector for simultaneous `expiry`/`expires_at` precedence.
- Strict-mode behavior (no `trustedKeySets` provided) is not covered by a portable vector.

### 7.3 Conformance Suite Readiness

**Status: PARTIAL**

181 assertions across 15 vector sets. Key lifecycle coverage resolved. Remaining gaps:

1. ~~Key lifecycle vectors (revoked, not_before, not_after)~~ ✓ resolved — `key-lifecycle-verification.json`
2. Intent hash mismatch portable vector — important for verifier correctness
3. Cross-language Profile C vectors — important for Profile C adoption
4. `expiry`/`expires_at` simultaneous presence precedence vector

### 7.4 Interoperability Profile Readiness

**Status: READY (Profile A/B), PARTIAL (Profile C)**

- Profile A: fully specified, conformance covered.
- Profile B: specified, Encoding B conformance covered. Profile B trust separation not explicitly vectorized.
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
3. Close intent hash mismatch portable vector gap
4. Resolve or formally mitigate state provider trust risk
5. Resolve or formally mitigate KRL transport integrity risk
6. Independent security review
7. Establish external feedback or co-author channel

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
Intent binding (guard)       ██████████████████░░  PARTIAL (no cross-lang vector)
Key lifecycle (lifecycle)    ████████████████████  DONE (20 portable vectors)
DelegationV1                 ████████████████████  DONE
Profile A interop            ████████████████████  DONE
Profile B interop            ████████████████░░░░  PARTIAL (trust sep. gap)
Profile C interop            ██████████████████░░  PARTIAL (TS-only vectors)
Replay durability            ████████████████░░░░  PARTIAL (in-memory default risk)
Key rotation                 ██████████░░░░░░░░░░  DOCUMENTED ONLY
Threat model                 ██████████░░░░░░░░░░  DOCUMENTED ONLY
Clock skew spec              ████████████████████  DONE (strict zero-tolerance + 10 vectors)
HTTP PEP                     ░░░░░░░░░░░░░░░░░░░░  MISSING (planned v2.6)
Structured events / metrics  ░░░░░░░░░░░░░░░░░░░░  MISSING
```

---

## 9. Prioritized Follow-up Issues

### P0 - Must resolve before external adoption

**P0-1: Add portable conformance vectors for key lifecycle** ✓ RESOLVED  
Resolution: `key-lifecycle-verification.json` added — 10 vectors, 20 assertions covering active, revoked, retired (within/past window), `not_before`/`not_after` time windows, revocation-overrides-window, and wrong-kid-known-issuer. Conformance count: 161 → 181.

**P0-2: Define and specify clock skew tolerance** ✓ RESOLVED  
Resolution: Strict zero-tolerance selected and specified. `authorization-v1.md §17` defines: valid iff `now < expiry`, no grace period, `issued_at` informational-only (no lower-bound enforcement), NTP synchronization required, issuers must build delivery latency into expiry window. `clock-semantics-verification.json` added — 5 vectors, 10 assertions covering last-valid-second, one-past-expiry, verifier-clock-behind, and Encoding B variants. Conformance count: 181 → 191.

**P0-3: Harden `parentScope` cast in `OxDeAIGuard`**  
Reason: `const parentScope = (parentAuth as any).scope` silently allows `undefined`, with a separate guard that throws after the chain check. This is a type-safety gap that could mask bugs. `DelegationV1` scope narrowing correctness depends on this.  
Scope: `packages/guard/src/guard.ts` - tighten cast and fail-closed earlier.

---

### P1 - Should resolve before standardization positioning

**P1-1: Add intent hash mismatch portable conformance vector**  
Reason: Intent binding enforced in guard, tested in TypeScript only. External implementers cannot confirm their verifier correctly rejects intent mismatches.  
Scope: New vector in `authorization-verification.json` or a new `intent-binding-verification.json`.

**P1-2: Add `expiry`/`expires_at` simultaneous presence precedence vector**  
Reason: Precedence rule (`expiry` wins over `expires_at`) is implemented and specified but untested by a vector. An implementer who gets this backwards will silently accept expired authorizations.  
Scope: `authorization-verification.json` or `authorization-signature-verification.json`.

**P1-3: Add Profile B trust separation conformance vector**  
Reason: Profile B correctness depends on the trust bridge between Sift receipt key and OxDeAI signing key. No vector exercises the separate trust root for Profile B.  
Scope: New vector in `authorization-signature-verification.json` with distinct adapter-issued key.

**P1-4: Resolve or formally mitigate KRL transport integrity risk**  
Reason: Sift KRL payload is not signature-verified. A compromised network path can suppress revocations. Either require a signed KRL contract from Sift, or formally document this as an accepted operational risk with compensating controls.  
Scope: `packages/sift/README.md` + `docs/architecture/threat-model-external-providers.md`.

**P1-5: Mark HMAC-SHA256 as deprecated**  
Reason: `legacyHmacSecret` accepts HMAC-SHA256, which is not listed as an accepted encoding in `authorization-v1.md §5`. This creates a spec/implementation mismatch. Should be formally deprecated with a removal timeline.  
Scope: `authorization-v1.md` - add deprecation notice. `verifyAuthorization` - add deprecation warning.

**P1-6: Add cross-language Profile C conformance vectors**  
Reason: Profile C is executable in TypeScript but not portable across Go/Python harnesses. Standardization positioning for Profile C requires external verifiers to validate `computeStateHash` integration against the same vectors. TypeScript-only coverage is insufficient for a multi-implementer profile claim.  
Scope: Go harness extension to support a pluggable `computeStateHash` callback or equivalent; expose at minimum `live-state-match`, `live-state-mismatch`, and `compute-throws` modes.

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

**Total areas audited:** 23 protocol areas, 14 invariants, 15 conformance vector sets, 9 trust components.

| Status | Count |
|--------|-------|
| `DONE` | 49 |
| `PARTIAL` | 19 |
| `SPECIFIED ONLY` | 5 |
| `DOCUMENTED ONLY` | 6 |
| `MISSING` | 7 |
| `RISK` | 5 |

**Conformance:** 191 assertions. 6 remaining gaps (P0-1, P0-2 resolved).

**Follow-up issue counts:** P0: 0 open (P0-1, P0-2 resolved) · P1: 6 · P2: 4 · Total: 10 open

**Critical path to external adoption:**

1. ~~Key lifecycle portable vectors (P0-1)~~ ✓ resolved — 20 assertions added
2. ~~Clock skew specification (P0-2)~~ ✓ resolved — strict zero-tolerance specified, 10 assertions added
3. Intent hash mismatch portable vector (P1-1)
4. `expiry`/`expires_at` precedence vector (P1-2)
5. Cross-language Profile C vectors (P1-6)
6. HMAC-SHA256 deprecation (P1-5)

**Protocol positioning:**

OxDeAI is a working, tested execution authorization boundary protocol at the **interoperable protocol** maturity level. Core invariants are implemented and tested. AuthorizationV1, wire encodings, signature verification, replay protection, state binding, and delegation are all in solid shape. Profile A/B/C are specified; Profile A and C have executable conformance coverage.

The protocol is **not yet ready for standard adoption**. Key lifecycle and clock skew are now resolved. State provider trust, intent hash mismatch portability, and independent security review remain open before that claim can be made honestly.

---

*This document reflects the protocol state as of 2026-05-17. It should be revisited after each significant milestone.*
