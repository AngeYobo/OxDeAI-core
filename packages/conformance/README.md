# @oxdeai/conformance
Conformance vectors and validator for the OxDeAI execution-time authorization protocol.
Ensures implementations reproduce deterministic AuthorizationV1 artifacts and boundary verification (fail-closed).

## Purpose
`@oxdeai/conformance` verifies that an implementation matches the frozen protocol behavior for a specific version.

Passing validation means the implementation reproduces expected deterministic artifacts (hashes, statuses, and verification outputs) from frozen vectors.

## Version Coupling
- `@oxdeai/conformance@1.5.0` targets `@oxdeai/core@1.7.0` behavior.
- Use matching major/minor protocol versions when validating.

## Included Vector Sets

### Core protocol (pre-v1.3)
- `intent-hash.json`
- `authorization-payload.json`
- `snapshot-hash.json`
- `audit-chain.json`
- `audit-verification.json`
- `envelope-verification.json`
- `authorization-verification.json`
- `authorization-signature-verification.json`
- `envelope-signature-verification.json`

### DelegationV1 (v1.3+)
- `delegation-parent-hash.json` - `delegation_parent_hash = SHA256(canonical_json(AuthorizationV1))`; key-order invariance (I1)
- `delegation-verification.json` - `verifyDelegation()` field-level checks: expiry, scope narrowing, delegatee, policy, replay, trust-missing
- `delegation-chain-verification.json` - `verifyDelegationChain()` chain checks: hash binding, delegator, parent expiry, expiry ceiling, single-hop, policy binding
- `delegation-signature-verification.json` - Ed25519 signature path: valid, tampered sig, wrong kid, tampered field, expired

### Profile C - Semantic State Verification (v1.5+)

- `profile-c-state-verification.json` - exercises the full semantic state verification path (Profile C, guard step 10): `computeStateHash(liveState)` compared against the committed `state_hash` in the authorization.

Eight vectors covering:

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `profile-c-001` | `live-state-match` | `ok` - same state at signing and verification |
| `profile-c-002` | `live-state-mismatch` | `state-hash-mismatch` - state advanced between signing and execution |
| `profile-c-003` | `hash-strategy-mismatch` | `state-hash-mismatch` - provider hash committed, Core algorithm at verification |
| `profile-c-004` | `compute-throws` | `compute-error` - `computeStateHash` throws; execution blocked fail-closed |
| `profile-c-005` | `toctou-stale-state` | `state-hash-mismatch` - TOCTOU: state advanced since authorization was issued |
| `profile-c-006` | `encoding-b-live-state-match` | `ok` - Encoding B (Sift-compatible) + matching state |
| `profile-c-007` | `encoding-b-live-state-mismatch` | `state-hash-mismatch` - Encoding B + stale state |
| `profile-c-008` | `encoding-b-hash-strategy-mismatch` | `state-hash-mismatch` - Encoding B + strategy mismatch |

Two hash strategies modelled:

| Strategy | Algorithm |
|----------|-----------|
| `core` | `sha256HexFromJson` (Core-native) |
| `provider` | SHA-256 of `"PROVIDER:" + canonicalJson(state)` (simulates external provider hash) |

Encoding B vectors (`profile-c-006` through `profile-c-008`) exercise the Sift-compatible wire format (`alg="ed25519"`, `expires_at`, base64url signature) combined with live-state semantic verification.

Current validator assertion count: `161`.

### Adapter ops required for DelegationV1

| Op | Input | Output | Independence |
|----|-------|--------|--------------|
| `delegation_parent_hash` | `{ parent: AuthorizationV1 }` | `{ parent_auth_hash: hex }` | Full - SHA256 + canonical JSON |
| `verify_delegation` | `{ delegation: DelegationV1, opts }` | `{ status, violations, policyId }` | Full - no crypto required |
| `verify_delegation_chain` | `{ parent, delegation, opts }` (inline) | `{ status, violations }` | Full - hash recomputation + structural checks |
| `verify_delegation_signature` | `{ parent, delegation, opts }` (inline) | `{ status, violations }` | Full - chain checks + Ed25519 via test key material |
| `verify_delegation_chain_case` | `{ id: string }` | `{ status, violations }` | Lookup (frozen) |
| `verify_delegation_signature_case` | `{ id: string }` | `{ status, violations }` | Lookup (frozen) |

The Go harness uses `verify_delegation_chain` and `verify_delegation_signature`
with inline `input` from the vector files. Each adapter independently recomputes
`SHA256(canonical_json(parent))`, performs the chain-level structural checks,
and (for signature cases) performs Ed25519 verification using the test key
material embedded in `opts.trustedKeySets`. Lookup ops are retained for
compatibility but not used by the harness runners.

### Coverage distinction

| Layer | What it covers | Cross-language? |
|-------|---------------|-----------------|
| `delegation-parent-hash.json` | Hash stability, I1 key-order invariance | Yes - SHA256 + canonical JSON only |
| `delegation-verification.json` | Field checks, expiry, scope, replay, trust-missing | Yes - no crypto required |
| `delegation-chain-verification.json` | Chain structural checks (hash binding, delegator, expiry ceiling, policy) | Yes - independently recomputed |
| `delegation-signature-verification.json` | Ed25519 verification path | Yes - independently verified |
| `profile-c-state-verification.json` | Semantic state verification: hash comparison, strategy mismatch, compute-throws, TOCTOU, Encoding B | TypeScript only (requires `computeStateHash` integration) |
| `delegation.property.test.ts` (D-P1–D-P5) | PBT over scope / hash / mutation | TypeScript only |
| `guard.delegation.property.test.ts` (G-D1–G-D3) | Guard PEP delegation path | TypeScript only |
| `cross-adapter.test.ts` (CA-1–CA-10) | Cross-adapter equivalence, I6 | TypeScript only |

## Usage
From repo root:

```bash
pnpm -C packages/conformance extract
pnpm -C packages/conformance validate
```

Expected success output includes:

```text
Conformance passed: 161 assertions
```

## Adapter Contract
The validator is built around a pluggable adapter (`ConformanceAdapter`) so non-TypeScript runtimes can be checked against the same vectors.

An adapter must provide deterministic implementations for:
- canonical serialization used by vectors
- intent hashing
- authorization generation checks
- snapshot encoding + snapshot verification
- envelope verification

Reference adapter: `@oxdeai/core` (implemented in `src/validate.ts`).

## Verification Artifact Scope

![Verification envelope flow](../../docs/diagrams/verification-envelope-flow.svg)

Conformance checks deterministic behavior for artifacts and verifiers used in this flow (snapshot, audit, authorization, envelope, and verification status outputs).

Diagram source/editing policy:
- [`docs/diagrams/README.md`](../../docs/diagrams/README.md)

## Freeze Policy
Vectors are frozen per protocol version.

- Do not regenerate vectors for the same protocol version after behavior changes.
- Any behavior-impacting change requires a new protocol/versioned vector release.
- Regeneration is allowed only when intentionally producing a new version baseline.

## Interoperability Profiles

OxDeAI defines three interoperability profiles. Conformance coverage maps directly to profile requirements:

| Profile | Description | Vector sets required |
|---------|-------------|----------------------|
| A | Core-native `AuthorizationV1` | Core protocol + DelegationV1 |
| B | External provider wire-compatible (Encoding A and Encoding B accepted) | Core + authorization-signature vectors |
| C | Full semantic state verification via `computeStateHash` | Core + DelegationV1 + Profile C state vectors |

Profile C now has **executable conformance coverage** via `profile-c-state-verification.json` (12 assertions).

See [External Provider Interoperability Profile](../../docs/spec/interoperability/external-provider-profile.md) for the full profile specification, wire encoding reference, and fail-closed rules.

## Using OxDeAI Conformance from Other Languages

Conformance vectors are the behavioral truth source for protocol compatibility.

Rust, Go, and Python implementations should validate their verifier/engine behavior against these vectors.
Passing conformance means the implementation is behaviorally aligned with the OxDeAI protocol profile for that version line, including executable interoperability coverage where applicable.

Profile C vectors (`profile-c-state-verification.json`) require a `computeStateHash` integration point. Cross-language harnesses must supply a compatible hash function to exercise those vectors.

Related implementer docs:

- [`docs/verification/multi-language.md`](../../docs/verification/multi-language.md)
- [`docs/conformance/conformance-vectors.md`](../../docs/conformance/conformance-vectors.md)
- [`docs/spec/interoperability/external-provider-profile.md`](../../docs/spec/interoperability/external-provider-profile.md)
- [`packages/conformance/go-harness`](./go-harness)
