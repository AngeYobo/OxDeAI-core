# Verification Specification v1

**Status:** Stable (Normative Specification for verification semantics; artifact statuses defined in their respective specs)  
**Version:** v1.0.0  
**Non-normative sources of truth:** None - this file is normative for verification behavior. Canonical artifact definitions remain in `docs/spec/authorization-v1.md`, `delegation-v1.md`, `pep-gateway-v1.md`, and `canonicalization-v1.md`.

## 1. Scope

This specification defines the mandatory verification semantics for OxDeAI artifacts:

- `AuthorizationV1`
- `DelegationV1` and the parent/child chain
- PEP gateway boundary verification (pre-execution gate)
- Verification envelopes (post-execution evidence) - pending full envelope spec; apply general verification rules here

## 2. Dependencies

- `canonicalization-v1.md` - all hashes and signature preimages **MUST** use canonicalization-v1.
- `authorization-v1.md`
- `delegation-v1.md`
- `pep-gateway-v1.md`
- `conformance-v1.md` - deterministic ordering and fail-closed doctrine.

## 3. Decision Surface

- Protocol decisions: `ALLOW` or `DENY`.
- Deterministic error/reason codes **MUST** be emitted as defined in the relevant artifact specs (e.g., `INVALID_SIGNATURE`, `INTENT_HASH_MISMATCH`, `DELEGATION_SCOPE_VIOLATION`, `DELEGATION_MULTIHOP_DENIED`, etc.).
- Interface summaries such as `ok | invalid | inconclusive` are optional UI layers; they **MUST NOT** replace the underlying ALLOW/DENY decision.

## 4. Common Inputs

Verifiers **MUST** operate on explicit, injected inputs:

- `artifact` (AuthorizationV1, DelegationV1, envelope, etc.)
- `now` (unix seconds) - **MUST NOT** rely on ambient wall-clock inside verification logic.
- `trustedKeySets` (issuer-scoped public keys). In strict mode, absence of `trustedKeySets` **MUST** fail closed.
- `audience` expected by the relying party.
- `replayStore` (for `auth_id` / `delegation_id`) when replay protection is enforced.
- Optional `expectedDelegatee`/`expectedPolicyId` when required by integration.

## 5. AuthorizationV1 Verification (Required Ordering)

1. Structural validation (required fields, types).
2. Algorithm support (`alg` == `Ed25519`).
3. Key resolution via `issuer`, `kid`, `alg` in `trustedKeySets` (strict mode).
4. Signature check over canonicalized payload excluding `signature` (canonicalization-v1).
5. Expiry: `now < expiry` (**strict zero tolerance** — `now >= expiry` → `AUTH_EXPIRED`, no grace period; see `authorization-v1.md §17`).
6. Audience match.
7. Intent hash match to the proposed action (`intent_hash`).
8. Replay check on `auth_id` (if replay store present).

Any failure **MUST** yield `DENY` with the corresponding reason code.

## 6. Delegation Verification (Chain)

Input: `parent AuthorizationV1`, `delegation DelegationV1`, `action`, `trustedKeySets`, `now`, optional `consumedDelegationIds`.

Required steps (in order):
1. Parent type check: parent **MUST NOT** be a `DelegationV1` → else `DELEGATION_MULTIHOP_DENIED`.
2. Verify parent AuthorizationV1 per §5 (all steps).
3. Delegation structural + alg check (`Ed25519`).
4. Delegation signature over canonicalized payload excluding `signature` (canonicalization-v1); key via `kid`/`alg`/issuer in `trustedKeySets`.
5. Parent hash binding: `parent_auth_hash == SHA256(canonical(parent))` → else `DELEGATION_PARENT_HASH_MISMATCH`.
6. Delegator binding: `delegation.delegator == parent.audience`.
7. Policy binding: `delegation.policy_id == parent.policy_id`.
8. Expiry ceiling: `delegation.expiry <= parent.expiry` and `delegation.expiry > now`; else `DELEGATION_EXPIRED` or `DELEGATION_SCOPE_WIDENING`.
9. Scope narrowing:
   - `scope.tools` subset of parent tools.
   - `scope.max_amount` ≤ parent amount (if present).
10. Action scope check:
    - `action.tool` in `scope.tools` (if defined).
    - `action.params.amount` ≤ `scope.max_amount` (if defined).
11. Delegatee match: if an expected delegatee is provided, it **MUST** equal `delegation.delegatee`; else `DELEGATION_DELEGATEE_MISMATCH`.
12. Replay: `delegation_id` not previously consumed; else `DELEGATION_REPLAY`.

Any violation **MUST** return `DENY` with the precise reason code. Success returns `ALLOW`.

## 7. PEP Gateway Verification

PEP **MUST**:
- Perform Authorization (and Delegation chain, if present) verification per §§5–6 before execution.
- Enforce fail-closed: any verification failure → HTTP 403 with structured `DENY` and reason code.
- Upstream error mapping follows `pep-gateway-v1.md` (e.g., 502 for upstream error, 504 for timeout). These HTTP statuses do **not** override the protocol decision surface (still DENY when applicable).

Direct upstream calls without the internal token MUST be rejected (403).

## 8. Verification Envelope (Pending Full Spec)

Until a dedicated envelope spec is finalized:
- Treat envelope verification as:
  - Validate canonical snapshot hash and audit chain integrity.
  - If signed, verify signature with canonicalization-v1 and domain separation.
  - Return ALLOW/DENY with reason codes; `ok/invalid/inconclusive` may be exposed as UI summaries only.
- Envelope verification does **not** grant execution authority; it is post-execution evidence validation.

## 9. Determinism and Ordering

- Check ordering **MUST** follow the sequences in §§5–6 to ensure deterministic results across implementations.
- Implementations MUST NOT short-circuit in ways that alter observable reason ordering from these lists.
- Any ambiguity (missing inputs, unresolved keys, absent `now`, absent `trustedKeySets` in strict mode) **MUST** fail closed (DENY).

## 10. Conformance and Vectors

- Implementations **MUST** pass the locked vectors:
  - `docs/spec/test-vectors/canonicalization-v1.json`
  - `docs/spec/test-vectors/authorization-v1.json`
  - `docs/spec/test-vectors/pep-vectors-v1.json`
  - `docs/spec/test-vectors/delegation-vectors-v1.json`
- Additional verification vectors MAY be added in future versions; passing official vectors is required for conformance.

## 11. Non-Bypassability

- Execution MUST NOT proceed without successful verification per this spec.
- Any execution path that bypasses verification is **NON-CONFORMANT**.
