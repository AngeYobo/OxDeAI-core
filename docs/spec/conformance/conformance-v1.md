# ETA Conformance Specification v1

## 1. Purpose

This specification defines the conformance requirements for Execution-Time Authorization (ETA) implementations.

Conformance ensures that independent implementations:
- behave deterministically
- enforce fail-closed authorization
- produce verifiable and reproducible outcomes
- cannot be bypassed at execution time

---

## 2. Conformance Definition

An implementation is ETA-conformant if and only if it satisfies ALL of the following:

1. Deterministic evaluation
2. Canonicalization compliance
3. Fail-closed behavior
4. Non-bypassable enforcement
5. Artifact correctness and verification
6. Cross-implementation consistency

Failure in any category results in non-conformance.

---

## 3. Test Categories

### 3.1 Determinism Tests

Goal: identical inputs → identical outputs

Test:
- Run authorization N times with identical `(intent, state, policy)`

Requirement:
- decision MUST be identical
- produced artifacts MUST be byte-identical

Failure conditions:
- decision drift
- hash mismatch
- artifact mismatch

---

### 3.2 Canonicalization Tests

Goal: ensure stable canonical representation

Test cases:
- object key reordering
- nested structures
- unicode normalization (NFC)
- integer boundary handling
- float rejection
- duplicate key rejection

Requirement:
- canonical bytes MUST be identical across equivalent inputs
- invalid inputs MUST fail

Conformance vector source of truth:
- `docs/spec/test-vectors/canonicalization-v1.json`
  - canonical JSON and SHA-256 hex MUST match exactly
  - expected error codes MUST match exactly

---

### 3.3 Fail-Closed Tests

Goal: ensure system never allows ambiguous execution

Inject failures:
- missing policy
- malformed input
- canonicalization failure
- verification failure
- unknown key / issuer

Requirement:
- decision MUST be DENY

### 3.4 PEP Gateway Boundary Tests

Goal: no execution path without authorization.

Tests:
- Direct call to upstream without internal token MUST be 403.
- Gateway must return structured ALLOW/DENY per `pep-gateway-v1` §6.
- Replay of `auth_id` MUST be denied.

### 3.5 Authorization Verification

Requirement: signature, audience, expiry, intent_hash match, and trust config MUST be verified; any failure → DENY.

### 3.6 Delegation (if implemented)

Requirement: DelegationV1 chain MUST be strictly narrowing, single-hop, signed, and parent AuthorizationV1 valid; otherwise DENY.

---

## 4. Conformance Artifacts and Execution

Normative vector files:
- `docs/spec/test-vectors/canonicalization-v1.json`
- `docs/spec/test-vectors/authorization-v1.json`
- `docs/spec/test-vectors/pep-vectors-v1.json`

Implementations SHOULD provide runnable harnesses that consume the same vectors and exit non-zero on any mismatch (e.g., TS/Go/Python verifiers).

### 4.1 Minimal runnable checks (current repository)

From repo root:
- TypeScript reference: `pnpm test:vectors:ts`
- Go verifier: `pnpm test:vectors:go`
- Python verifier: `pnpm test:vectors:py`
- Authorization vectors: `pnpm test:vectors:auth`
- PEP vectors: `pnpm test:vectors:pep`
- Trusted-time vectors: `pnpm test:vectors:trusted-time`
- Aggregate: `pnpm test:vectors:all`

Pass/Fail rule: any mismatch in canonical JSON, SHA-256, or expected error code MUST exit non-zero and is non-conformant.

### 4.2 Trusted-time vector schema

`packages/conformance/vectors/trusted-time.json` uses strict schema version
`1.0.0` and one category-discriminated `vectors` collection. Every vector has
an ID unique across the file, an explicit `active` or `pending` status, a
description, category-specific `input`, and category-specific `expected`
behavior. Pending vectors additionally require a non-empty `blocked_by` and are
reported separately; they never count as passing.

The schema names clock domains explicitly (`intent_timestamp`,
`evaluation_time`, `authorization_issued_at`, `authorization_expiry`,
`nonce_first_seen_time`, `velocity_window_start`, `tool_window_start`, and
`verifier_time`). Generic or overloaded timestamp fields are forbidden.

The TypeScript reference runner rejects duplicate IDs, unknown categories or
fields, malformed status, unsupported public reason codes, and malformed or
unsafe protocol-second values before executing any vector. Active vectors run
through Core reference surfaces and are release-blocking through both
`pnpm -C packages/conformance validate` and `pnpm test:vectors:all`.

The active `tool_window` category executes stateful tool-call sequences through
`PolicyEngine.evaluatePure`. It verifies trusted window creation,
caller-timestamp noninterference, denial without quota consumption,
exact-boundary expiry, backward-time and malformed-state failure, exact state
propagation, and deterministic repeated execution.

TypeScript executes every active trusted-time category. The current Go and
Python harnesses claim canonicalization, Profile C verification, and SignedKRL
verification only; they do not expose PolicyEngine freshness, issuance,
stateful replay, velocity, or the standalone trusted-time authorization
verification surface. Those categories are explicitly unsupported in those
runtimes and MUST NOT be emulated in a harness merely to claim parity. All
languages enforce the JavaScript safe-integer bound for protocol numeric data
in the categories they implement.

### 4.3 Pending vectors

Locked vectors exist for canonicalization, authorization, and PEP gateway behavior as listed above. Delegation conformance is presently validated via code-level harnesses; additional locked vectors MAY be added in future versions.

Failure condition:
- any ALLOW under invalid conditions

---

### 3.4 Authorization Binding Tests

Goal: ensure authorization is bound to intent/state/policy

Test:
- reuse authorization with modified intent
- reuse with modified state
- reuse under different policy

Requirement:
- MUST be rejected

---

### 3.5 Replay Protection Tests

Goal: prevent reuse of authorization

Test:
- reuse same authorization artifact twice

Requirement:
- second execution MUST be rejected

---

### 3.6 Artifact Verification Tests

Goal: ensure artifacts are independently verifiable

Test:
- verify signature correctness
- verify hash binding
- verify issuer / key resolution
- tamper with payload

Requirement:
- tampered artifact MUST fail verification
- valid artifact MUST verify successfully

---

### 3.7 Cross-Implementation Tests

Goal: ensure cross-language consistency

Implementations:
- TypeScript (reference)
- Go
- Python

Test:
- same inputs → same canonical bytes
- same hash
- same decision

Requirement:
- byte-for-byte equality

---

### 3.8 Non-Bypassability Tests (Critical)

Goal: ensure execution cannot bypass authorization

Test scenarios:
- direct tool execution without authorization
- skipped authorization step
- partial verification

Requirement:
- execution MUST NOT occur

Failure condition:
- any execution without valid authorization

---

## 4. Conformance Vectors

A conformant implementation MUST pass all official test vectors.

Vectors MUST include:
- valid cases
- invalid cases
- edge cases

Vectors MUST define:
- input
- canonical output
- expected hash
- expected decision
- expected verification result

---

## 5. Verification Ordering

Verification steps MUST be deterministic.

Violation ordering MUST be consistent.

Implementations MUST NOT:
- short-circuit inconsistently
- produce non-deterministic error sets

---

## 6. Failure Semantics

Any ambiguity MUST result in:

DENY

Ambiguity includes:
- parsing uncertainty
- key resolution failure
- multiple matching keys
- undefined behavior

---

## 7. Reference Implementation

A conformant ecosystem MUST provide:

- one reference implementation (source of truth)
- independent verifiers in at least two languages
- reproducible test harness

---

## 8. Conformance Output

A conformance run MUST produce:

- pass/fail per test category
- deterministic logs
- reproducible outputs

Optional:
- hash of conformance run
- CI integration output

---

## 9. Minimal Conformance Criteria

An implementation is ETA-conformant if:

- 100% of required test vectors pass
- no non-determinism is observed
- no bypass is possible
- all failure modes result in DENY

---

## 10. Security Guarantees

Conformance ensures:

- deterministic authorization behavior
- non-forgeable decision verification
- replay resistance
- enforcement integrity

Conformance does NOT guarantee:

- correctness of policy logic
- absence of in-scope misuse
- runtime security outside the authorization boundary

---

## 11. Invariant Summary

Conformance enforces:

canonicalization → stable bytes 
→ stable hash 
→ deterministic decision 
→ verifiable artifact 
→ enforced execution 

Any violation:

→ DENY 
→ NO EXECUTION
