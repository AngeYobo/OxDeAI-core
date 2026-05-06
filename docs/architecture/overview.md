# Architecture

## Core Invariants

- No authorization → no execution
- (intent, state, policy) → deterministic ALLOW | DENY
- Same input → same decision
- Verification failure → fail closed

## Status

Non-normative (developer documentation)






Non-normative overview. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned). All hashes and signature preimages MUST use `canonicalization-v1`. Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; any `ok/invalid/inconclusive` labels are interface summaries only. Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.

OxDeAI is structured as protocol + reference implementation + adapter stack.

## Layers

Protocol and core:
- **`@oxdeai/core`** - protocol reference implementation: `PolicyEngine`, `AuthorizationV1`, audit chain, snapshot, envelope, verification
- **`@oxdeai/sdk`** - integration helpers: intent builders, state builders, conformance utilities
- **`@oxdeai/conformance`** - frozen test vectors and compatibility validator

PEP enforcement:
- **`@oxdeai/guard`** - universal Policy Enforcement Point; all authorization logic lives here; adapters delegate to this package

Runtime adapter bindings (thin, no auth logic):
- **`@oxdeai/langgraph`** - LangGraph tool call → `ProposedAction`
- **`@oxdeai/openai-agents`** - OpenAI Agents SDK tool call → `ProposedAction`
- **`@oxdeai/crewai`** - CrewAI tool call → `ProposedAction`
- **`@oxdeai/autogen`** - AutoGen function call → `ProposedAction`
- **`@oxdeai/openclaw`** - OpenClaw action → `ProposedAction`

## Stack

![Adapter stack flow](../diagrams/adapter-stack-flow.svg)

## Runtime Flow

### Via guard adapter (standard integration path)

1. Runtime adapter translates tool call into `ProposedAction` and delegates to `OxDeAIGuard`
2. Guard calls `evaluatePure(intent, state)` on the `PolicyEngine`
3. On `ALLOW`: guard verifies `AuthorizationV1`, then invokes the execute callback
4. On `DENY`: guard throws `OxDeAIDenyError` - execute callback is never called
5. On `ALLOW` without a valid authorization artifact: guard throws `OxDeAIAuthorizationError` (fail-closed)
6. Audit events, snapshot, and envelope are produced for offline verification

### Via core directly (reference / protocol-level)

1. Build intent
2. Evaluate via `PolicyEngine.evaluatePure(intent, state)`
3. If `ALLOW`, execute and commit next state
4. Emit/consume audit artifacts and optional envelopes
5. Verify artifacts statelessly (`verifySnapshot`, `verifyAuditEvents`, `verifyEnvelope`)

## Deterministic Artifacts

- `AuthorizationV1` - cryptographically verifiable pre-execution authorization artifact
- `policyId` - policy identity
- `stateHash` - canonical state hash
- `auditHeadHash` - hash-chain head
- `verificationEnvelope` - packages snapshot + audit events for offline stateless verification

## Composition

Policy behavior is module-based (budget, velocity, replay, recursion, concurrency, tool limits, kill switch, allowlists), with deterministic ordering and fail-closed semantics.

Framework choice changes adapter code, not protocol semantics.

## References

- [Adapter reference architecture](../adapters/adapter-reference-architecture.md)
- [Adapter stack](../integrations/adapter-stack.md)
- [Production PEP wiring guide](./pep-production-guide.md)
