# Architecture

## Overview

This reference implementation demonstrates strict execution-boundary enforcement
for an AI agent pipeline using Sift governance receipts and OxDeAI authorization tokens.

```
Agent
  │
  ├─→ Mock-Sift  (POST /receipt)
  │       │
  │       └─→ returns ReceiptEnvelope { kid, receipt }
  │
  ├─→ Adapter  (library call)
  │       │
  │       ├─ verifyReceiptWithKeyStore   (sig + freshness + ALLOW)
  │       ├─ normalizeIntent             (tool binding + param normalization)
  │       ├─ normalizeState             (state normalization)
  │       ├─ receiptToAuthorization      (unsigned AuthorizationV1)
  │       └─ Ed25519 sign               (signs the canonical signing payload)
  │
  └─→ PEP Gateway  (POST /execute)
          │
          ├─ 1.  Parse            structural validation
          ├─ 2.  Signature        Ed25519 verify (adapter public key)
          ├─ 3.  Issuer           known-issuers allowlist
          ├─ 4.  Audience         must equal PEP's configured audience
          ├─ 5.  Decision         must be "ALLOW"
          ├─ 6.  Expiry           expires_at > now
          ├─ 7.  Policy           known-policies allowlist
          ├─ 8.  Intent hash      SHA-256(siftCanonical(intent)) == intent_hash
          ├─ 9.  State hash       SHA-256(siftCanonical(state))  == state_hash
          ├─ 10. Replay           auth_id consumed atomically (last)
          │
          └─→ Upstream  (POST /execute + X-Internal-Execution-Token)
                  │
                  └─ Token check  → 403 if missing or wrong
                                  → 200 + execute if valid
```

## Components

### Mock-Sift (`mock-sift/`)

Issues Ed25519-signed SiftReceipts with valid `receipt_hash` and `signature`.
Exposes `/sift-jwks.json` and `/sift-krl.json` for key store resolution.
Test-only. Not for production use.

### Adapter (`packages/adapter/`)

The only path through which a Sift governance decision becomes an executable
authorization. Calls `@oxdeai/sift` APIs in sequence, then signs the result.

Returned `authorization.signature.sig` is a real Ed25519 signature over the
Sift-canonical signing payload. The PEP verifies it independently.

### PEP Gateway (`apps/pep-gateway/`)

The non-bypassable execution boundary. Implements the 10-step verification
sequence. Every failure returns HTTP 403. No fallback paths exist.

The internal execution token is generated at startup and held in memory.
It is never returned in any response and never logged.

### Upstream (`apps/upstream/`)

The protected execution target. Accepts only requests carrying the exact
`X-Internal-Execution-Token` value set at startup. Returns 403 on any
other request, regardless of body content.

The upstream has no knowledge of AuthorizationV1, Sift, or the PEP protocol.
Its only invariant is: the internal token is required.

### Replay Store (`packages/replay-store/`)

Atomic single-use enforcement for `auth_id`. The in-memory implementation
is test-only. Replace with a distributed store (Redis, DynamoDB, Postgres)
for production.

## Key design decisions

**Adapter returns `{ intent, state }` alongside `authorization`.**
The adapter returns the normalized intent and state objects it used to compute
the hashes, so the agent can send them verbatim to the PEP without
re-constructing them. Any deviation produces an `INTENT_HASH_MISMATCH` or
`STATE_HASH_MISMATCH` at the PEP.

**Replay check is last.**
The `auth_id` is consumed only after all other checks pass. This prevents
valid auth IDs from being burned by a partial-verification attack.

**Canonical JSON is inlined in `shared/canonical.ts`.**
`siftCanonicalJsonBytes` is not part of `@oxdeai/sift`'s public API.
Both the adapter (signing) and the PEP (verification) import from this
shared module to guarantee identical digest computation.

**No runtime dependency on Sift during execution.**
The PEP verifies the adapter's Ed25519 signature over the `AuthorizationV1`
payload. Sift is not reachable from the PEP. The chain of custody ends at
the adapter's signing step.

## Production deployment notes

**`apps/pep-gateway/` is a pedagogical PEP implementation.**

The PEP gateway in this reference example implements the 10-step
`AuthorizationV1` verification sequence inline to make the ordering readable
and independently testable.  It is not the production PEP implementation.

For production deployments, use `packages/guard` (the hardened PEP library)
or an equivalent implementation with equivalent test coverage.  `packages/guard`
provides the same verification sequence with additional hardening:
- strict mode requiring non-empty trusted key sets
- pluggable replay store with Redis support
- CAS-based state versioning for TOCTOU prevention
- 136 conformance tests

**Replay store.**

`packages/replay-store` (in-memory `MemoryReplayStore`) is suitable for
single-process tests only.  It is not restart-durable and does not
coordinate across multiple processes or instances.

Production deployments MUST replace it with a durable, distributed store
that provides atomic consume semantics (check-and-set in a single operation).
`packages/guard` includes `createRedisReplayStore` for this purpose.
