# Conformance Vectors Index

Actual runtime coverage is documented in [corpus authority](corpus-authority.md). Root Go/Python
validators cover canonicalization, Profile-C and SignedKRL only. The optional
package Go driver is separate and requires an adapter; its bundled Python adapter
fails at import (#306) and supplies no passing coverage. Rust tests consume only
`examples/rust-verifier/auth_case.json` and its key fixture, not either vector tree.


## Status

Non-normative (developer documentation)






Non-normative overview. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned). Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`. All hashes and signature preimages MUST use `canonicalization-v1`. Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; any `ok/invalid/inconclusive` labels are interface summaries only.

This index helps non-TypeScript implementers choose where to start in `packages/conformance/vectors`.

## Core Vector Categories

- `intent-hash.json`: intent binding projection and hash determinism
- `authorization-payload.json`: authorization artifact evaluation outputs
- `authorization-verification.json`: authorization verification status and violations
- `authorization-signature-verification.json`: signature-specific authorization checks
- `snapshot-hash.json`: canonical snapshot encoding/hash expectations
- `audit-chain.json`: deterministic audit hash-chain behavior
- `envelope-verification.json`: envelope verification outcomes
- `envelope-signature-verification.json`: envelope signature verification behavior

## DelegationV1 Vector Categories (v1.3+)

- `delegation-parent-hash.json`: `SHA256(canonical_json(AuthorizationV1))` - key-order invariance (I1); no crypto required
- `delegation-verification.json`: `verifyDelegation()` field/structural checks - expiry, scope narrowing, replay, trust-missing; no crypto required
- `delegation-chain-verification.json`: `verifyDelegationChain()` - hash recomputation, delegator match, parent expiry, expiry ceiling, single-hop, policy binding; independently verifiable
- `delegation-signature-verification.json`: Ed25519 path - valid, tampered sig, wrong kid, tampered field, expired; independently verifiable via `opts.trustedKeySets`

## Suggested Start Order

### Core protocol
1. `snapshot-hash.json`
2. `authorization-verification.json`
3. `authorization-signature-verification.json`
4. `audit-chain.json`
5. `envelope-verification.json`
6. `envelope-signature-verification.json`

### DelegationV1 (after core)
7. `delegation-parent-hash.json`
8. `delegation-verification.json`
9. `delegation-chain-verification.json`
10. `delegation-signature-verification.json`

Passing all relevant vectors indicates behavioral alignment with the protocol profile for the selected version line.

See [`packages/conformance/go-harness/README.md`](../../packages/conformance/go-harness/README.md) for the adapter op protocol used by the Go harness.
