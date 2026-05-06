# OxDeAI Threat Model

## Status

Non-normative (developer documentation)





This document is a companion reference (non-normative). For the canonical normative specification, see [../SPEC.md](../SPEC.md) and `docs/spec/`; artifact status is defined there.

# OxDeAI Threat Model

This document captures the protocol threat model for OxDeAI.
All hashes and signature preimages MUST use `canonicalization-v1`; protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs.

Reference:
- Primary protocol spec: [SPEC.md](../SPEC.md)
- Protocol overview: [PROTOCOL.md](../PROTOCOL.md)
- Developer companion: [protocol/spec.md](./spec.md)
- Conformance guidance (fail-closed, deterministic ordering): [docs/spec/conformance-v1.md](../docs/spec/conformance-v1.md)
- Delegation invariants and replay/multi-hop constraints: [docs/spec/delegation-v1.md](../docs/spec/delegation-v1.md)

## Covered Risks
- Replay abuse
- Runaway execution/tool loops
- Concurrency explosion
- Silent budget drain
- Recursive planning escalation

### DelegationV1 threat surface (v1.3+)
- **Authority escalation** - delegatee claims tools/amounts/depth beyond what the parent authorization permits; mitigated by strictly narrowing scope enforcement at the PEP
- **Parent hash forgery** - delegation claims binding to a parent authorization it was not issued under; mitigated by `parent_auth_hash = SHA256(canonical_json(parent))` verified at chain-check time
- **Delegator spoofing** - delegation claims a delegator that does not match `parent.audience`; caught by delegator-match check before inner verification
- **Re-delegation / multi-hop escalation** - `DelegationV1` re-delegating authority from another `DelegationV1`; blocked by single-hop constraint (multi-hop denied if parent has `delegation_id`)
- **Delegation replay** - reusing a consumed `delegation_id`; mitigated by replay check against `consumedDelegationIds`
- **Expired delegation abuse** - presenting a delegation after its `expiry`; caught by expiry check at verification time with explicit `now` injection
- **Signature forgery** - presenting a delegation with a tampered payload or forged signature; mitigated by Ed25519 domain-separated canonical signature verification when `trustedKeySets` is provided
- **Key substitution** - presenting a delegation with a `kid` not in the trusted keyset for the issuer; caught by `DELEGATION_KID_UNKNOWN`

## Security Goals
- Deterministic, fail-closed policy decisions
- Pre-execution authorization boundary (fail-closed)
- Tamper-evident audit chain
- Verifiable protocol artifacts
- Delegation authority strictly bounded by parent authorization scope and expiry

## Out of Scope
- Business logic correctness of downstream systems
- Key custody / wallet infrastructure
- Host runtime compromise
- Multi-hop delegation (not supported in current protocol line)
- Cross-org trust federation / revocation mesh
