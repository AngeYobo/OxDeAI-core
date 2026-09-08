# OxDeAI Threat Model: External Authorization Providers

**Status:** Non-normative (developer documentation)
**Scope:** External provider integrations — Sift adapter, non-Core authorization issuers, pluggable state hash strategies

---

This document complements the base threat model at [`docs/security/threat-model.md`](../security/threat-model.md)
and the PEP Gateway specification at [`docs/spec/enforcement/pep-gateway-v1.md`](../spec/enforcement/pep-gateway-v1.md).

It addresses the expanded trust surface introduced by:

- Sift → Guard interoperability (accepted external `AuthorizationV1` wire encodings)
- Pluggable `computeStateHash` strategies (`OxDeAIGuardConfig.computeStateHash`)
- Durable replay-store infrastructure
- External authorization issuers and adapters

**Core invariant (unchanged):**

```text
authorization ambiguity or trust-boundary ambiguity → DENY → no execution
```

---

## 1. What OxDeAI Is and Is Not

OxDeAI is an **execution authorization boundary**. It gates whether a proposed action is
permitted to execute at the moment of submission, based on a cryptographically verifiable
authorization artifact.

OxDeAI is **not**:

- An agent framework or runtime sandbox
- A policy governance or compliance system
- A monitoring or audit-only infrastructure
- A solution to identity management or key custody
- A guarantee of agent or policy correctness
- A substitute for business-logic validation in downstream systems

Understanding this boundary is prerequisite to correctly interpreting the trust assumptions below.

---

## 2. Trust Boundary Map

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  EXTERNAL (untrusted)                                                   │
│                                                                         │
│  ┌────────────┐   ┌──────────────────┐   ┌────────────────────────┐   │
│  │ Agent /    │   │ External Auth    │   │ LLM output /           │   │
│  │ Orchestr.  │   │ Provider (Sift)  │   │ Tool proposals         │   │
│  └─────┬──────┘   └────────┬─────────┘   └──────────┬─────────────┘   │
│        │                  │                          │                  │
└────────│──────────────────│──────────────────────────│──────────────────┘
         │                  │                          │
         ▼                  ▼                          │
┌─────────────────────────────────────────────────────│──────────────────┐
│  ADAPTER LAYER (trusted if correctly wired)          │                  │
│                                                      │                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Sift Adapter (@oxdeai/sift)                                     │   │
│  │  - Verifies Sift receipt (ALLOW/DENY)                           │   │
│  │  - Normalizes intent and state                                  │   │
│  │  - Computes state_hash = siftCanonicalJsonHash(normalizedState) │   │
│  │  - Signs AuthorizationV1 with adapter Ed25519 key               │   │
│  └──────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                       │
└─────────────────────────────────│───────────────────────────────────────┘
                                  │  AuthorizationV1 (Encoding B)
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  ENFORCEMENT LAYER (trusted)                                           │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ OxDeAI Guard / PEP Gateway (@oxdeai/guard)                       │  │
│  │                                                                  │  │
│  │  Step 1: Verify AuthorizationV1 signature (Ed25519)              │  │
│  │  Step 2: Verify audience + issuer                                │  │
│  │  Step 3: Check expiry                                            │  │
│  │  Step 4: Consume auth_id (replay store — atomic)                 │  │
│  │  Step 5: Verify intent_hash matches proposed action              │  │
│  │  Step 6: Verify state_hash (live state, via computeStateHash)    │  │
│  │  Step 7: CAS state commit                                        │  │
│  │  Step 8: Execute upstream                                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────┐  ┌──────────────────┐  ┌────────────────┐   │
│  │ Trusted KeySet store │  │ Replay Store     │  │ State Provider │   │
│  │ (static config)      │  │ (Redis/DynamoDB) │  │ (getState/CAS) │   │
│  └──────────────────────┘  └──────────────────┘  └────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                  │  Verified, consumed
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│  EXECUTION LAYER (trusted)                                             │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Upstream Executor                                                │  │
│  │  - Rejects requests without x-internal-executor-token           │  │
│  │  - Never reachable directly by agents                           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Trust Assumptions by Component

### 3.1 Authorization Issuers

| Aspect | Detail |
|---|---|
| **Trusted inputs** | An issuer is trusted if and only if its public key appears in `trustedKeySets` with a matching `kid` and `issuer` label |
| **Verified** | Ed25519 signature over canonical preimage (both Encoding A and B); audience; expiry; issuer label |
| **Assumption** | The issuer's private key is not compromised. Key rotation is the deployer's responsibility. |
| **Fail-closed** | Unknown `kid`, unknown `issuer`, or failed signature → `AUTH_KID_UNKNOWN` / `AUTH_ISSUER_MISMATCH` / `AUTH_SIGNATURE_INVALID` → DENY |
| **Non-goal** | OxDeAI does not verify the issuer's internal authorization logic or policy correctness |

### 3.2 Adapters (e.g., Sift Adapter)

| Aspect | Detail |
|---|---|
| **Trusted inputs** | The adapter's output `AuthorizationV1` is trusted only after Ed25519 signature verification at the guard |
| **Verified** | The guard independently verifies the adapter's signature; it does not trust the adapter's claim that the auth is valid |
| **Assumption** | The adapter correctly maps external provider decisions to OxDeAI `AuthorizationV1` artifacts; adapter compromise is a deployment concern |
| **Fail-closed** | A compromised adapter that produces a forged `AuthorizationV1` cannot bypass the guard without the adapter's Ed25519 private key |
| **Non-goal** | OxDeAI does not verify the external provider's decision logic (e.g., Sift's internal policy) |

The adapter is a **trust boundary translator**, not a trust root. The guard's cryptographic verification is the trust root.

### 3.3 PEP Gateway

| Aspect | Detail |
|---|---|
| **Trusted inputs** | Trusted KeySet config; Replay Store responses; State Provider (`getState`); `computeStateHash` function |
| **Verified** | All 8 verification steps above; any step failure → DENY |
| **Assumption** | The gateway process itself is not compromised; its configuration (KeySets, `computeStateHash`) is correctly set at deployment |
| **Fail-closed** | Any verification exception blocks execution with `OxDeAIAuthorizationError` |
| **Non-goal** | The gateway does not verify that the upstream executor is semantically correct |

### 3.4 Replay Stores

| Aspect | Detail |
|---|---|
| **Trusted inputs** | `consumeAuthId(auth_id)` returns `true` (first use) or `false` (replay) |
| **Verified** | The guard treats any thrown error as DENY; `false` → `AUTH_REPLAY` → DENY |
| **Assumption** | The replay store is **fail-closed**: it throws rather than returning permissive results when unavailable; atomic consume semantics are maintained |
| **Fail-closed** | Replay-store exception → DENY; `false` → DENY. There is no fail-open path. |
| **Non-goal** | OxDeAI does not define the durability model of the underlying store; this is an operational deployment requirement |

### 3.5 PolicyEngines

| Aspect | Detail |
|---|---|
| **Trusted inputs** | `evaluatePure(intent, state)` output (decision + authorization artifact + nextState) |
| **Verified** | The guard verifies the authorization artifact produced by the engine independently, via `verifyAuthorization` |
| **Assumption** | The engine's policy modules are correctly configured; policy correctness is not verified by the guard |
| **Fail-closed** | ALLOW without a valid authorization artifact → `OxDeAIAuthorizationError` |
| **Non-goal** | OxDeAI does not guarantee that the policy reflects business intent |

### 3.6 State Providers

| Aspect | Detail |
|---|---|
| **Trusted inputs** | `getState()` → `{ state, version }` snapshot used for state_hash verification and policy evaluation |
| **Verified** | `state_hash` commitment in the authorization is verified against `computeStateHash(state)` at execution time |
| **Assumption** | `getState()` returns a consistent snapshot; the CAS version is monotonically advancing |
| **Fail-closed** | State_hash mismatch → DENY; CAS conflict → `OxDeAIConflictError` → DENY |
| **Non-goal** | OxDeAI does not guarantee the correctness of the state data itself |

### 3.7 Upstream Executors

| Aspect | Detail |
|---|---|
| **Trusted inputs** | The executor receives `x-internal-executor-token`; it must reject requests without it |
| **Verified** | The token enforces that only the PEP gateway can reach the executor |
| **Assumption** | The executor is correctly isolated from direct agent access at the network/process level |
| **Fail-closed** | Execution without a valid token → executor rejects; agents cannot bypass the PEP |
| **Non-goal** | OxDeAI does not verify executor behavior after the action is dispatched |

---

## 4. Execution-Boundary Guarantees

### 4.1 Integrity Guarantees (cryptographic, unconditional)

These hold as long as the Ed25519 private key of the issuer is not compromised:

| Guarantee | Mechanism |
|---|---|
| **Signature integrity** | Ed25519 signature over canonical preimage; any field tampered → `AUTH_SIGNATURE_INVALID` |
| **Intent binding** | `intent_hash` = SHA-256 of canonical intent bytes; tampered action → `INTENT_HASH_MISMATCH` |
| **State binding (signature level)** | `state_hash` is covered by the Ed25519 signature; tampered hash → `AUTH_SIGNATURE_INVALID` |
| **Expiry enforcement** | Effective expiry extracted from `expiry` or `expires_at`; past expiry → `AUTH_EXPIRED` |
| **Algorithm exclusivity** | Only `"Ed25519"` and `"ed25519"` accepted; any other alg string → `AUTH_ALG_UNSUPPORTED` |
| **Audience binding** | `audience` must exactly match `expectedAudience`; mismatch → `AUTH_AUDIENCE_MISMATCH` |
| **Issuer key trust** | `issuer` must have a key set in `trustedKeySets`; key resolution is issuer-scoped, so an unknown issuer cannot resolve a signing key |
| **Issuer-policy authority** | Distinct from key trust (#301). A trusted signing key does NOT imply the issuer may issue for the claimed `policy_id`. Externally supplied authorizations must match a deployer-configured `(issuer, policyId)` pair; otherwise → `AUTH_ISSUER_POLICY_NOT_AUTHORIZED` |

### 4.2 Semantic Guarantees (require correct deployment configuration)

These hold only when the deployment is correctly configured:

| Guarantee | Condition | What breaks it |
|---|---|---|
| **Replay protection** | Replay store is atomic and fail-closed | Replay store returns permissive result under failure (misconfiguration) |
| **State semantic verification** | `computeStateHash` matches the algorithm used by the authorization issuer | Wrong `computeStateHash` configured → deterministic mismatch → DENY (still fail-closed, but blocks legitimate execution) |
| **Non-bypassability** | Upstream executor is isolated from direct agent access | Network/process isolation not enforced at deployment |
| **CAS isolation** | `getState`/`setState` use atomic compare-and-set | Underlying store allows dirty reads or non-atomic commits |

### 4.3 Operational Guarantees (require operational hygiene)

| Guarantee | Requirement |
|---|---|
| **Key rotation hygiene** | Expired or compromised keys are removed from `trustedKeySets` promptly |
| **Replay-store durability** | After process restart, previously consumed `auth_id` values remain consumed |
| **State-store consistency** | `getState()` and `setState()` operate on the same consistent snapshot under concurrent load |
| **Offline verification** | `VerificationEnvelope` + audit chain enable stateless verification independent of runtime state |

### 4.4 What OxDeAI Does NOT Guarantee

- That the authorized action has the intended real-world effect
- That the policy configuration is correct or complete
- That the agent's reasoning is sound
- That the upstream executor behaves correctly
- That infrastructure isolation prevents all bypass paths (this is a deployment requirement)

---

## 5. External Provider Interoperability

### 5.1 Accepted Wire Encodings

Exactly two `AuthorizationV1` wire encodings are accepted. See
[`docs/spec/artifacts/authorization-v1.md §5`](../spec/artifacts/authorization-v1.md) for the normative definition.

| Encoding | Expiry field | Algorithm | Signature | Preimage |
|---|---|---|---|---|
| A (Core-native) | `expiry` | `"Ed25519"` (capitalized) | flat base64 string | `"OXDEAI_AUTH_V1\n"` + canonical JSON |
| B (Sift-compatible) | `expires_at` | `"ed25519"` (lowercase) | nested object, base64url `sig` | canonical JSON (no prefix) |

Any encoding not matching A or B exactly is rejected. There is no partial acceptance or fallback matching.

### 5.2 State Hash Algorithm Responsibility

State_hash is verified at two levels:

**Level 1 — Signature integrity (always performed):**
The guard verifies the Ed25519 signature, which covers `state_hash` as a signed field.
Tampering `state_hash` without re-signing → `AUTH_SIGNATURE_INVALID`.
This level requires no live-state access and is always enforced.

**Level 2 — Semantic verification (`OxDeAIGuard` only, requires live-state access):**
The guard recomputes the hash from the live state snapshot (`computeStateHash(state)`) and
compares against the authorization's committed `state_hash`.

`createPepGatewayExecutor` performs only Level 1. It has no live-state access by design.

`OxDeAIGuard` performs both levels. Step 6c uses:

```text
config.computeStateHash (if configured)
  ?? config.engine.computeStateHash
```

**Deployment requirement for external providers:**

If the authorization was produced by an external provider using a non-Core canonicalization
algorithm (e.g., Sift adapter's `siftCanonicalJsonHash`), the guard **must** be configured with
`computeStateHash: siftCanonicalJsonHash`. Using the wrong function produces a deterministic
mismatch — execution is blocked, fail-closed. There is no fallback.

### 5.3 Replay-Store Requirements for External Providers

External providers issue `auth_id` values. The replay store must:

- Atomically consume each `auth_id` on first use → return `true`
- Return `false` on re-use → `AUTH_REPLAY` → DENY
- Throw (not return permissive result) when unavailable → fail-closed
- Persist across process restarts when durability is required

In-memory replay stores (single-process only) are acceptable for development. Production deployments
serving external providers must use a backend-backed store (Redis, DynamoDB, etc.) that survives
restarts and is shared across all guard instances.

### 5.4 Verifier Strictness

`verifyAuthorization` applies the following checks in order, accumulating violations:

1. Signature algorithm recognized
2. Key (`kid`) found in trusted keyset for issuer
3. Audience matches
4. Issuer matches
5. Effective expiry present and not expired
6. Signature verifies against canonical preimage
7. Decision is `"ALLOW"`

Any violation → authorization rejected. Violations are accumulated (not short-circuited) to
expose the full failure reason, but execution is blocked on any single violation.

---

## 6. Threat Scenarios

### T-1: Replay Attack

| Field | Detail |
|---|---|
| **Description** | Attacker captures a valid `AuthorizationV1` and re-submits it to execute the same action again |
| **Enforcement point** | Replay store (`consumeAuthId`) at guard step 4 |
| **Expected behavior** | First use: `consumeAuthId` returns `true` → execution proceeds. Second use: returns `false` → `AUTH_REPLAY` → DENY |
| **Fail-closed outcome** | Execution never runs on replay; the auth_id is consumed atomically on first use |
| **Condition** | Requires a durable, atomic replay store. In-memory stores do not survive process restarts. |

### T-2: Authorization Reuse / Cross-Context Use

| Field | Detail |
|---|---|
| **Description** | Attacker uses an authorization issued for agent A at the guard for agent B, or for action X to authorize action Y |
| **Enforcement point** | Audience check (step 2); intent hash check (step 5) |
| **Expected behavior** | Audience mismatch → `AUTH_AUDIENCE_MISMATCH`. Different action → intent hash mismatch → `INTENT_HASH_MISMATCH` |
| **Fail-closed outcome** | Cross-context reuse is cryptographically blocked; the authorization is audience-bound and intent-bound |

### T-3: Adapter Compromise

| Field | Detail |
|---|---|
| **Description** | The Sift adapter (or any external adapter) is compromised; it produces a forged `AuthorizationV1` |
| **Enforcement point** | Signature verification at guard step 1 |
| **Expected behavior** | A forged authorization without the adapter's Ed25519 private key fails signature verification → `AUTH_SIGNATURE_INVALID` → DENY |
| **Fail-closed outcome** | Adapter compromise without key compromise cannot produce a guard-accepted authorization |
| **Residual risk** | If the adapter's Ed25519 private key is also compromised, forged authorizations can pass. Key custody is a deployment concern outside OxDeAI's scope. |

### T-4: Intent Tampering

| Field | Detail |
|---|---|
| **Description** | Attacker intercepts an `AuthorizationV1` and submits it with a modified action payload (e.g., different transfer amount or destination) |
| **Enforcement point** | Intent hash verification at guard step 5 |
| **Expected behavior** | Canonical hash of tampered action ≠ `intent_hash` in authorization → `INTENT_HASH_MISMATCH` → DENY |
| **Fail-closed outcome** | Intent tampering is cryptographically detected; the authorization is intent-bound by SHA-256 hash |

### T-5: State Tampering

| Field | Detail |
|---|---|
| **Description** | Attacker modifies `state_hash` in a captured authorization to claim a different state context |
| **Enforcement point** | Signature integrity check at guard step 1 (Level 1); semantic hash check at step 6 (Level 2) |
| **Expected behavior** | Tampered `state_hash` without re-signing → `AUTH_SIGNATURE_INVALID`. Stale hash with valid signature → semantic mismatch at step 6 → DENY |
| **Fail-closed outcome** | Both tampering and stale-state scenarios block execution |

### T-6: Canonicalization Mismatch

| Field | Detail |
|---|---|
| **Description** | An external provider uses a different state canonicalization algorithm than what the guard expects, causing `state_hash` computed at signing to differ from what the guard computes at verification |
| **Enforcement point** | `computeStateHash` at guard step 6 |
| **Expected behavior** | Deterministic hash mismatch → `OxDeAIAuthorizationError` → DENY |
| **Fail-closed outcome** | Mismatch is deterministic — execution is consistently blocked. No partial acceptance. Deployer must align `computeStateHash` with the issuer's algorithm. |
| **Diagnosis** | This is a configuration error, not an attack. Both the mismatch and an actual TOCTOU state change produce the same DENY. |

### T-7: Wire Encoding Ambiguity

| Field | Detail |
|---|---|
| **Description** | Attacker or misconfigured provider submits an authorization with an unrecognized `alg` value (e.g., `"EdDSA"`, `"ED25519"`, `"ed448"`) |
| **Enforcement point** | Algorithm check at guard step 1 |
| **Expected behavior** | Any `alg` value not in `{"Ed25519", "ed25519"}` → `AUTH_ALG_UNSUPPORTED` → DENY |
| **Fail-closed outcome** | Encoding ambiguity is rejected; there is no generic case-insensitive matching or fallback |

### T-8: Replay-Store Outage

| Field | Detail |
|---|---|
| **Description** | The replay store becomes unavailable (network partition, crash); `consumeAuthId` throws |
| **Enforcement point** | Guard step 4 error handling |
| **Expected behavior** | Any exception from the replay store is caught → DENY. There is no fail-open path. |
| **Fail-closed outcome** | Execution is blocked during store outage. This is an explicit availability/security trade-off: correctness over availability. |
| **Operational implication** | Deploy the replay store with appropriate availability guarantees for the use case. |

### T-9: Stale Authorization Execution

| Field | Detail |
|---|---|
| **Description** | Attacker (or delayed legitimate request) submits an authorization after the state it was issued against has advanced (TOCTOU) |
| **Enforcement point** | State hash check at guard step 6 (`OxDeAIGuard`); expiry check at step 3 |
| **Expected behavior** | If state has changed: `state_hash` mismatch → DENY. If authorization has expired: `AUTH_EXPIRED` → DENY. |
| **Fail-closed outcome** | State-bound authorizations cannot be replayed against a different state |
| **Note** | `createPepGatewayExecutor` only enforces expiry and signature (Level 1); live-state semantic verification requires `OxDeAIGuard` with `computeStateHash` configured. |

### T-10: Bypass Attempt

| Field | Detail |
|---|---|
| **Description** | Agent attempts to call the upstream executor directly, bypassing the PEP gateway |
| **Enforcement point** | `x-internal-executor-token` at the upstream executor; network/process isolation |
| **Expected behavior** | Upstream rejects requests without the internal token. Agents never hold this token. |
| **Fail-closed outcome** | Architectural isolation enforces the boundary; the token is not derivable by agents |
| **Non-goal** | OxDeAI specifies the requirement; enforcement of network isolation is a deployment concern |

### T-11: Key Substitution

| Field | Detail |
|---|---|
| **Description** | Attacker generates a new Ed25519 keypair and signs a forged authorization under a known `kid` |
| **Enforcement point** | Key lookup in `trustedKeySets` + signature verification |
| **Expected behavior** | The forged signature does not verify against the trusted public key for that `kid` → `AUTH_SIGNATURE_INVALID` → DENY |
| **Fail-closed outcome** | Key substitution is cryptographically blocked by the trusted public key binding |

### T-12: Computestatehash Throws (Broken Hash Implementation)

| Field | Detail |
|---|---|
| **Description** | The `computeStateHash` function (built-in or pluggable) throws an exception during execution |
| **Enforcement point** | Guard step 6 try/catch |
| **Expected behavior** | Exception is caught → wrapped in `OxDeAIAuthorizationError("State canonicalization failed: ...")` → DENY |
| **Fail-closed outcome** | A broken hash implementation cannot silently pass execution; it produces a deterministic DENY |

---

## 7. Replay Durability Assumptions

### 7.1 Atomic Consume Requirement

`consumeAuthId(auth_id, expiry)` **must** be atomic. The following race is the primary concern:

```text
Guard instance A: consumeAuthId(x) → true   (executing)
Guard instance B: consumeAuthId(x) → true   (should return false — RACE)
```

An atomic implementation (e.g., Redis `SET NX`, DynamoDB conditional write) prevents this.
Non-atomic implementations (e.g., read-then-write) allow replay in concurrent deployments.

### 7.2 Distributed Deployment

When multiple guard instances serve the same execution boundary, the replay store **must** be shared:

- A per-process in-memory store does not prevent cross-process replay
- The store must be reachable by all guard instances simultaneously
- Network partitions must produce errors (fail-closed), not silent permissiveness

### 7.3 Process Restart Behavior

After a guard process restarts:

- In-memory replay stores lose all consumed `auth_id` records → replay window reopens
- Backend-backed stores (Redis, DynamoDB) retain consumed records across restarts

For production deployments, use a backend-backed store with TTL set to at least the authorization
expiry window to guarantee replay protection through restarts.

### 7.4 Expiry and TTL

The replay store TTL for a given `auth_id` should be no shorter than the authorization's `expiry`
minus `issued_at`. Shorter TTL creates a window where a consumed auth_id can be re-consumed after
TTL expires but before the authorization itself expires. The guard does not detect this — it is an
operational guarantee that the deployer must enforce.

---

## 8. Non-Goals

OxDeAI explicitly does **not**:

| Non-goal | Implication |
|---|---|
| Guarantee agent correctness | A correctly-authorized agent can still take harmful actions |
| Guarantee policy correctness | Misconfigured policy can authorize actions that should be denied |
| Validate business semantics | OxDeAI does not know if `amount: 1000000` is a mistake or intentional |
| Provide runtime sandboxing | Process isolation and network controls are deployment responsibilities |
| Replace infrastructure isolation | The non-bypassability guarantee requires network-level enforcement |
| Prevent malicious authorized actions | Authorization confirms policy allowed the intent; it does not validate the intent's real-world effect |
| Solve identity governance | Key custody, key rotation, and identity federation are external concerns |
| Monitor execution correctness | OxDeAI gates entry; it does not observe what the upstream executor does |

---

## 9. Fail-Closed Invariant Summary

All uncertainty paths in the OxDeAI execution boundary result in DENY:

| Condition | Error / Code | Outcome |
|---|---|---|
| Unknown algorithm | `AUTH_ALG_UNSUPPORTED` | DENY |
| Unknown key ID | `AUTH_KID_UNKNOWN` | DENY |
| Signature invalid | `AUTH_SIGNATURE_INVALID` | DENY |
| Audience mismatch | `AUTH_AUDIENCE_MISMATCH` | DENY |
| Issuer mismatch | `AUTH_ISSUER_MISMATCH` | DENY |
| Authorization expired | `AUTH_EXPIRED` | DENY |
| Missing required field | `AUTH_MISSING_FIELD` | DENY |
| Replay detected | `AUTH_REPLAY` | DENY |
| Replay store throws | `OxDeAIAuthorizationError` | DENY |
| Intent hash mismatch | `INTENT_HASH_MISMATCH` | DENY |
| State hash mismatch | `OxDeAIAuthorizationError` | DENY |
| `computeStateHash` throws | `OxDeAIAuthorizationError` | DENY |
| CAS conflict | `OxDeAIConflictError` | DENY |
| ALLOW without artifact | `OxDeAIAuthorizationError` | DENY |
| Engine DENY | `OxDeAIDenyError` | DENY |
| Unsupported wire encoding | `AUTH_ALG_UNSUPPORTED` | DENY |

There is no fail-open path. Every ambiguous, missing, or failed verification step blocks execution.

---

## 10. References

- [Authorization-V1 wire encodings](../spec/artifacts/authorization-v1.md)
- [PEP Gateway Specification](../spec/enforcement/pep-gateway-v1.md)
- [Base threat model](../security/threat-model.md)
- [Protocol invariants](invariants.md)
- [Conformance vectors](../conformance/conformance-vectors.md)
- [Guard state-binding tests](../../packages/guard/src/test/guard.state-binding.test.ts) — SB-1 through SB-13
- [Guard integration test](../../examples/reference-sift-oxdeai/test/guard-integration.test.ts) — GUARD/* scenarios
