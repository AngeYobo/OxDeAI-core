# Eta Positioning Note

## Status

Non-normative (developer documentation)





Non-normative positioning. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned).

**Purpose**
Assert OxDeAI as the production enforcement layer for autonomous learning systems derived from System M architectures.

**1) Framing Correction**
- Before: OxDeAI is complementary.  
- After: An execution authorization boundary is a condition of deployability. Without one, System M is control without enforcement; learning systems are not deployable.

**2) Territory**
- Paper domain: learning, adaptation, autonomy.  
- OxDeAI domain: deterministic constraints, enforcement, execution guarantees.  
- Learning introduces uncertainty. Execution must remain deterministic.

**3) Architecture Upgrade**
- Paper path: `System M → Agent → Action → World`  
- Production path: `System M → Agent → OxDeAI → Execution → World`  
OxDeAI is on the critical execution path. Authorization enforcement is mandatory, regardless of whether the PEP is deployed inline, as a sidecar, or through another non-bypassable topology.

**4) Mapping to OxDeAI**
- Auth(A,P,S): present (intent+policy+state → decision)  
- Canonicalization: partial; needs formal spec for cross-language guarantees  
- Determinism: aligned (AuthorizationV1)  
- Fail-closed: aligned (verifyAuthorization / verifyEnvelope)  
- Decision artifact: aligned  
- Replayability: aligned  
- Non-bypassability: weak; depends on integration correctness

**5) Hard Gaps**
- Non-bypassability not yet enforced when embeddings/integration are imperfect.  
- Canonicalization lacks formal, language-agnostic definition.  
- Conformance not explicitly tied to ETA requirements.  
- ABSTAIN outcome absent; may be needed to force explicit caller handling.

**6) Roadmap Hardening - Enforcement Invariants**
Define non-bypassable constraints independent of model behavior. Examples:  
- Capability invariant: only approved capabilities are executable.  
- Budget invariant: resource/time/financial ceilings enforced pre-dispatch.  
- Failure invariant: repeated/critical faults trigger deny/lockdown.  
Learning cannot escape constraints.

**7) Learning-Safe Execution Semantics**
- State inconclusive → DENY  
- Policy mismatch → DENY  
- Unknown action class → DENY  
- Verification failure → DENY  
Fully compatible with fail-closed doctrine.
All hashes and signature preimages MUST use `canonicalization-v1`. Deterministic ordering per `docs/spec/conformance/conformance-v1.md`; delegation constraints per `docs/spec/artifacts/delegation-v1.md`.

**8) Positioning**
- Deterministic execution authorization for autonomous learning systems.  
- Execution enforcement layer for autonomous learning systems.  
- OxDeAI is the enforcement layer for System M architectures.

**9) Strategic Opportunity**
- The paper validates the category but stops short of production implementation.  
- OxDeAI can stand as the reference implementation of the model.  
- “Meyman defines the model. OxDeAI implements it.”

**10) Priority Assets**
- Public note: “Why autonomous learning systems need an execution boundary.”  
- Architecture diagram (System M → Agent → OxDeAI → Execution → World).  
- Case study: runaway learning agent with vs. without boundary (OxDeAI trips capability/budget/failure invariants and fails closed).

**11) Final TL;DR**
The paper describes how agents will learn and act continuously. What it misses is enforcement.  
System M decides what to do. OxDeAI decides what is allowed to happen.  
Without an execution boundary, learning systems are not deployable.

Status signals: Canonicalization locked; AuthorizationV1 / PEP / DelegationV1 Stable; VerificationEnvelopeV1 pending; ExecutionReceiptV1 planned. Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`. ABSTAIN outcome remains a future consideration, not present in current specs.
