# Architecture

OxDeAI is structured as protocol + reference implementation.

## Layers
- Protocol: deterministic economic containment rules (`protocol/`)
- Reference implementation: `@oxdeai/core`
- Conformance: frozen vectors + validator (`@oxdeai/conformance`)

## Runtime Flow
1. Build intent
2. Evaluate via `PolicyEngine.evaluatePure(intent, state)`
3. If `ALLOW`, execute and commit next state
4. Emit/consume audit artifacts and optional envelopes
5. Verify artifacts statelessly (`verifySnapshot`, `verifyAuditEvents`, `verifyEnvelope`)

## Deterministic Artifacts
- `policyId` — policy identity
- `stateHash` — canonical state hash
- `auditHeadHash` — hash-chain head

## Composition
Policy behavior is module-based (budget, velocity, replay, recursion, concurrency, tool limits, kill switch, allowlists), with deterministic ordering and fail-closed semantics.
