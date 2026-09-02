# Rust Verifier Skeleton (Reference)

Reference-only Rust starter for OxDeAI protocol verification.

This example is intentionally minimal and is **not** a normative implementation.
TypeScript (`@oxdeai/core`) remains the protocol reference implementation.

## Scope

This skeleton demonstrates verifier-first implementation shape:

- `types.rs` - protocol-facing artifact/result structs
- `canonical.rs` - canonical JSON + signing input construction
- `keyset.rs` - issuer/kid/alg key lookup
- `verify_authorization.rs` - fail-closed `AuthorizationV1` verification

## Why this exists

To help Rust implementers start with protocol-compatible verification before building a native decision engine.

## Run

The repo ships a minimal working pair for quick testing:

- `auth_case.json` - single AuthorizationV1
- `keyset.json` - matching Ed25519 public key

`auth_case.json` is signed with a fixed `issued_at`/`expiry` and does not
resign itself, so verifying it against the real wall clock will DENY
`AUTH_EXPIRED` once real time passes its `expiry` (1775656952). Verify it at
its own deterministic protocol time with `VERIFY_NOW` instead:

```bash
cd examples/rust-verifier
VERIFY_NOW=1775656951 cargo run -- ./auth_case.json ./keyset.json pep-gateway.local
```

Expected outcome: `ALLOW` (`1775656951` is the fixture's last valid second,
`expiry - 1`).

`VERIFY_NOW` is optional. Omit it to verify against the real wall clock, the
normal path for a freshly issued authorization:

```bash
cargo run -- ./auth_case.json ./keyset.json pep-gateway.local
```

Against the bundled fixture this now returns `DENY (AUTH_EXPIRED: ...)`,
since real time has passed the fixture's fixed expiry. That is the expiry
check working as intended, not a defect: `cargo test` (below) pins the
`ALLOW` case at the fixture's own deterministic time so it does not depend on
today's date.

Expected outcomes in general:

- `ALLOW` when verification passes
- `DENY` with an explicit violation code otherwise

## Tests

```bash
cargo test
```

`tests/verify_authorization.rs` verifies the bundled fixture directly:

- ALLOW at its last valid second (`expiry - 1`)
- DENY `AUTH_EXPIRED` at the exact expiry boundary (`now == expiry`)
- DENY `AUTH_EXPIRED` when actually expired
- DENY `AUTH_SIGNATURE_INVALID` when a signed field is tampered with after signing

## Notes

- Domain separator is fixed to `OXDEAI_AUTH_V1`.
- Signing input is `domain + "\n" + canonical_json(payload_without_signature)`.
- Verification is fail-closed on malformed payloads, unknown keys/algorithms, and signature mismatch.
