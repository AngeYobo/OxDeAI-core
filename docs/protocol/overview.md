# OxDeAI Protocol

## Status

Non-normative (developer documentation)






Non-normative overview. Normative specs live in `SPEC.md` and `docs/spec/`; some artifacts remain Draft until conformance vectors and CI are fully locked.

OxDeAI is a deterministic execution-time authorization protocol for autonomous systems.

---

## Core Model

```
(intent, state, policy) → ALLOW | DENY
```

An agent proposes an action.
OxDeAI evaluates deterministically against the current policy state before execution.
If the decision is `ALLOW`, a signed authorization artifact is emitted.
If the decision is `DENY`, execution MUST NOT proceed.

No valid authorization artifact → no execution.
Execution is only reachable through a verified authorization boundary.

---

## Protocol Artifacts

OxDeAI defines the following first-class protocol artifacts:

| Artifact | Purpose |
|---|---|
| **AuthorizationV1** | Pre-execution `ALLOW` artifact. Signed, expiring, bound to intent and policy state. |
| **DelegationV1** | Narrowed sub-authorization issued by a principal to a delegatee. Strictly scoped, locally verifiable. |
| **VerificationEnvelopeV1** | Portable post-execution evidence bundle. Contains canonical snapshot + audit chain. *(pending specification in docs/spec/)* |
| **ExecutionReceiptV1** | *(planned; not specified in this document)* Execution attestation binding receipt to a verified authorization. |

Artifacts are language-independent and MUST be interpreted identically across conformant implementations.

---

## Action-Surface Independence

OxDeAI does not define how agents express their actions.

Agent runtimes may use structured tool calls, CLI-style invocations, MCP tool calls, workflow engines, or framework-specific adapters.

Runtimes SHOULD normalize proposed actions into a deterministic **intent** before submitting to the policy engine:

```
action surface
→ normalization
→ intent
→ OxDeAI PDP evaluation
→ AuthorizationV1 (or DENY)
→ PEP enforcement
→ side effect
```

Deterministic intent normalization is what makes policy evaluation reproducible across action surfaces.
The protocol does not mandate one universal normalization schema; implementations MUST ensure that supported surfaces map to intent deterministically.
All hashes and signature preimages MUST use `canonicalization-v1`.

---

## Verification Surface

Authorization artifacts are portable and independently verifiable without re-running the policy engine.

The protocol-stable verifier surface is:

| Verifier | What it checks |
|---|---|
| `verifyAuthorization` | Pre-execution gate. Validates an `AuthorizationV1` before allowing execution. |
| `verifyDelegation` | Validates a `DelegationV1` artifact structurally and against its parent hash. |
| `verifyDelegationChain` | Validates a delegation + parent authorization pair as a complete chain. |
| `verifyEnvelope` | Post-execution evidence check. Validates a `VerificationEnvelopeV1` snapshot + audit chain. |

Protocol decisions are ALLOW or DENY; error codes are defined in the respective specs (canonicalization, PEP, delegation).
`ok` / `invalid` / `inconclusive` are interface-level summaries, not protocol-level decisions.
Violation ordering follows conformance guidance in `docs/spec/conformance-v1.md` for determinism.

---

## Boundary Model

OxDeAI separates two distinct concerns:

- **Capability** - what an agent *can* do (tool definitions, runtime affordances)
- **Authority** - what an agent *is authorized* to do at this moment under current policy

The OxDeAI boundary sits between them. An agent may have the capability to call an action. It may not execute unless a valid authorization exists for that specific intent and state.

Delegation preserves this invariant: `DelegationV1` can only narrow the delegator's existing authority. Authority cannot be amplified through delegation.
No valid authorization → no execution path (fail-closed).

---

## Where to Go Next

- Normative spec: [`SPEC.md`](./SPEC.md)
- Delegation artifact details: [`docs/spec/delegation-v1.md`](./docs/spec/delegation-v1.md)
- Conformance vectors: [`packages/conformance`](./packages/conformance)
- Locked vectors: [`docs/spec/test-vectors/canonicalization-v1.json`](./docs/spec/test-vectors/canonicalization-v1.json), [`docs/spec/test-vectors/authorization-v1.json`](./docs/spec/test-vectors/authorization-v1.json), [`docs/spec/test-vectors/pep-vectors-v1.json`](./docs/spec/test-vectors/pep-vectors-v1.json), [`docs/spec/test-vectors/delegation-vectors-v1.json`](./docs/spec/test-vectors/delegation-vectors-v1.json)
- Invariant mapping: [`docs/invariants.md`](./docs/invariants.md)
- Adapter integration: [`docs/integrations/README.md`](./docs/integrations/README.md)

---

## Legacy Compatibility

The v1.0.2 protocol profile is preserved for historical and reference compatibility at:

[`docs/archive/PROTOCOL-v1.0.2.md`](./docs/archive/PROTOCOL-v1.0.2.md)

That document is archival only and does not describe the current protocol surface.
The current normative protocol is defined in [`SPEC.md`](./SPEC.md).