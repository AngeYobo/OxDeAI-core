# System M Execution Boundary

## Status

Non-normative (developer documentation)





Non-normative positioning. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned).

**Objective**
Reframe OxDeAI as the mandatory enforcement layer for autonomous learning systems derived from System M architectures.

**Framing**
- System M enables agents to learn and act. OxDeAI makes those actions enforceable.  
- Without an execution boundary, System M is control without enforcement.  
- OxDeAI is required for production deployment; without it, systems are incomplete.

**Territory**
- Paper domain: learning, adaptation, autonomy.  
- OxDeAI domain: deterministic constraints, enforcement, execution guarantees.  
- Learning introduces uncertainty. Execution must remain deterministic.

**Architectures**
- Paper: `System M → Agent → Action → World`  
- Production: `System M → Agent → OxDeAI → Execution → World`  
OxDeAI sits on the critical path non-optional, not a sidecar.

**Enforcement Invariants (replacing “learning-aware policies”)**
- Capability invariant: actions restricted to approved capability set.  
- Budget invariant: resource/time/financial ceilings enforced before dispatch.  
- Failure invariant: repeated or critical faults force deny/lockdown.  
For protected actions routed exclusively through the configured PEP, learning
cannot escape those constraints. Alternate execution paths remain a deployment
responsibility.

**Learning-Safe Execution Semantics**
- State inconclusive → DENY  
- Policy mismatch → DENY  
- Unknown action class → DENY  
- Verification failure → DENY  
Fail-closed is the default; authorization is deterministic.
All hashes and signature preimages MUST use `canonicalization-v1`. Deterministic ordering and fail-closed semantics align with `docs/spec/conformance/conformance-v1.md`; Delegation single-hop/replay constraints align with `docs/spec/artifacts/delegation-v1.md`.

**Positioning**
- Deterministic execution authorization for autonomous learning systems.  
- OxDeAI is the enforcement layer for System M architectures.

**Market Insight**
- System M architectures will emerge; enforcement is the missing piece.  
- OxDeAI fills that gap with deterministic, verifiable execution control.

**Assets to Publish**
1) Public note: “Why autonomous learning systems need an execution boundary.”  
2) Architecture diagram (ASCII):  
   ```
   System M
      ↓
    Agent
      ↓
    OxDeAI (enforcement boundary)
      ↓
   Execution substrate
      ↓
    World
   ```
3) Case study: runaway learning agent  
   - Without boundary: agent escalates resource use, triggers unintended actions; no deterministic stop.  
   - With OxDeAI: capability/budget/failure invariants trip; execution denied; system fails closed.

**Roadmap Emphasis**
- Solidify enforcement invariants across capability, budget, failure.  
- Expand verification paths to keep unknown/ambiguous states in DENY.  
- Tighten attestable artifacts so System M decisions are always bound by OxDeAI authorization.

**Final TL;DR**
The paper describes how agents will learn and act continuously. What it misses is enforcement.  
System M decides what to do. OxDeAI decides what is allowed to happen.  
Without an execution boundary, learning systems are not deployable.

Status signals: Canonicalization locked; AuthorizationV1 / PEP / DelegationV1 are Stable; VerificationEnvelopeV1 pending; ExecutionReceiptV1 planned. Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.
