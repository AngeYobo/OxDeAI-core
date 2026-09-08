# Multi-Language Implementation Guide

Actual runtime coverage is documented in [corpus authority](../conformance/corpus-authority.md). Root Go/Python
validators cover canonicalization, Profile-C and SignedKRL only. The optional
package Go driver is separate and requires an adapter; its bundled Python adapter
fails at import (#306) and supplies no passing coverage. Rust tests consume only
`examples/rust-verifier/auth_case.json` and its key fixture, not either vector tree.


## Status

Non-normative (developer documentation)






OxDeAI protocol artifacts are language-agnostic. Rust, Go, and Python teams can implement interoperable verification today without rewriting the TypeScript engine first.

## What You Can Implement Today

Non-TypeScript implementers can verify:

- `AuthorizationV1`
- canonical snapshots
- audit chains
- verification envelopes

You can also run the TypeScript reference engine as a boundary service while building native verification components.

## Requirements for Native Implementations

A compliant native implementation needs:

- canonical JSON support exactly as defined by the protocol
- SHA-256 hashing compatibility
- Ed25519 signature verification
- exact signing-input byte reconstruction (`domain || 0x0A || canonical_payload`)
- fail-closed verification behavior

## Recommended Path

1. Start with verification-only support (`verifyAuthorization`, snapshot/audit/envelope checks).
2. Validate behavior against OxDeAI conformance vectors.
3. Add a native decision engine only after verification parity is stable.

This reduces risk and gives immediate interoperability.

Go implementers can bootstrap with the harness scaffold:
- `packages/conformance/go-harness`

## Language Mapping

### Rust

- Canonical JSON: `serde_json` + deterministic key ordering strategy
- SHA-256: `sha2`
- Ed25519: `ed25519-dalek` (or equivalent)
- Suggested first target: stateless verifier library + conformance runner harness

### Go

- Canonical JSON: deterministic map/key handling + canonical encoder
- SHA-256: `crypto/sha256`
- Ed25519: `crypto/ed25519`
- Suggested first target: verifier package for envelope + authorization paths

### Python

- Canonical JSON: deterministic serializer with sorted keys and exact protocol formatting
- SHA-256: `hashlib`
- Ed25519: `cryptography`/libsodium-backed implementation
- Suggested first target: verification CLI/library that consumes frozen vectors

## Implementation Checklist

- Parse artifact and validate required fields.
- Canonicalize payload exactly per protocol rules.
- Reconstruct signing input bytes exactly.
- Verify signature (alg + kid + key resolution).
- Validate issuer/audience/policy bindings.
- Validate expiry and decision semantics (`ALLOW` when required).
- Fail closed on malformed input, unknown alg/kid, signature mismatch, or ambiguity.

## Reference vs. Compliance

The TypeScript stack is the current reference implementation.
It is not the only valid implementation.

Rust/Go/Python implementations are compliant if they follow the spec and pass conformance.
