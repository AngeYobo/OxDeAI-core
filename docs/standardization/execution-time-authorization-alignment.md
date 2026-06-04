# OxDeAI Alignment with the Execution-Time Authorization Framework

**Document type:** Standardization positioning artifact  
**Status:** Working draft  
**Scope:** Conceptual alignment mapping only - no protocol changes, no code changes, no conformance vector changes
**Related audit:** `docs/audits/protocol-audit-post-interoperability.md`

---

## 1. Purpose and Scope

This document maps OxDeAI's architecture and conformance artifacts to the Execution-Time Authorization (ETA) framework formalized in:

> Meyman, E. "Execution-Time Authorization for AI Agents: A Formal Framework for Deterministic Governance Boundaries." FERZ, Inc., February 2026. DOI: 10.5281/zenodo.18764561. Licensed CC-BY-4.0.

**What this document is:**

- A mapping artifact for standardization positioning
- An explicit record of which OxDeAI protocol components address which ETA invariants
- An honest account of residuals and open problems shared between OxDeAI and the ETA framework
- A statement of independent development history

**What this document is not:**

- A conformance claim against the ETA framework
- A declaration of full standardization readiness (see §9)
- A protocol change, a code change, or a conformance vector change
- A marketing document

The tone of this document follows the same discipline as `docs/audits/protocol-audit-post-interoperability.md`: precise about coverage, precise about residuals, conservative about claims. If a gap exists, it is named explicitly rather than hidden in qualifications.

---

## 2. The ETA Framework in Brief

The ETA framework formalizes a class of systems that enforce pre-execution authorization at the boundary between an agent's decision-making process and its actuation of side-effecting operations. The framework defines six invariants (§4 of the paper) that a system must satisfy to qualify as an execution-time authorization implementation:

| Invariant | Location | Core requirement |
|-----------|----------|-----------------|
| I1: Determinism | §3.2, §4.1 | Authorization outcomes are fully determined by inputs; identical inputs must produce identical outputs across implementations and executions |
| I2: Fail-closed enforcement | §4.2 | Any verification failure or ambiguity produces non-execution - there is no path to execution through failure |
| I3: Non-bypassability | §4.3 | The enforcement boundary cannot be circumvented by actors within the agent runtime |
| I4: Decision artifact completeness | §4.4 | The authorization decision is captured in a verifiable artifact that carries the full decision context |
| I5: Replayability | §4.5 | Governance decisions are independently reproducible from committed evidence |
| I6: Time-bounded evaluation without fail-open | §4.6 | Evaluation is bounded in time; expiry of an authorization produces non-execution, not continued execution |

The paper further addresses ABSTAIN-with-escalation as a first-class authorization verdict (§3.4), open research directions (§10), and proof-carrying decision artifacts (§8.2). These are addressed in §4 and §7 of this document, respectively.

Attribution: the invariant names and section references above are drawn from the Meyman paper, reproduced here under CC-BY-4.0 for the purpose of this alignment mapping. OxDeAI's own component names (AuthorizationV1, DelegationV1, SignedKRLV1, OxDeAIGuard, canonicalization-v1) are the canonical references for OxDeAI throughout this document.

---

## 3. Invariant-by-Invariant Mapping

### 3.1 I1: Determinism (ETA §3.2, §4.1)

**ETA requirement:** Authorization outcomes are fully determined by inputs. Identical inputs must produce identical outputs across implementations, languages, and execution times. Non-determinism in any path from input to authorization decision is a protocol violation.

**OxDeAI mechanisms:**

**Canonicalization-v1** ([`docs/spec/core/canonicalization-v1.md`](../spec/core/canonicalization-v1.md)) defines a deterministic serialization procedure with explicit rules for: UTF-8 byte-order key sorting, NFC normalization, safe-integer-only numeric encoding (floats rejected), duplicate key rejection, and unsupported-type rejection. The procedure is implemented independently in Go (`go-harness/canonicalization_verify.go`), Python (`python-harness/verify_canonicalization_vectors.py`), and TypeScript (`packages/core/src/crypto/hashes.ts`). Cross-language agreement is verified by the portable conformance vector suite (`docs/spec/test-vectors/canonicalization-v1.json`, 11 vectors).

**AuthorizationV1 and signing domain prefixes** ([`docs/spec/artifacts/authorization-v1.md`](../spec/artifacts/authorization-v1.md)) bind each verification operation to a distinct domain (`OXDEAI_AUTH_V1\n`, `OXDEAI_DELEGATION_V1\n`, `OXDEAI_KRL_V1\n`) via `signatureInput()` in `packages/core/src/crypto/signatures.ts`. This prevents cross-artifact signature confusion without coordination between contexts.

**The cross-language conformance suite** demonstrates that determinism holds across implementations. All three Encoding B Profile C vectors (modes 006–008) now have independent Go and Python verification (#120): the duplicate-kids SignedKRLV1 signature (`+mwEd2QP5+tx6pCKAiF8BKzMAHf1c28mcTQF575pDn/DwgRiJ+PkYnv+sasIdgj1S7E9mSZZK1pOTP43nlnsDA==`) serves as the cross-language byte-equivalence proof point - three independent implementations computing identical canonical bytes from the same input.

**Relevant conformance artifacts:** canonicalization vectors v1-object-key-ordering through i4-float-timestamp-rejected; authorization-sig-001 (Encoding A); authorization-sig-010 (Encoding B); profile-c-001 through profile-c-008; KRL_SIGNED_VALID through KRL_VERSION_REGRESSION (Go and Python).

**Residual:** The property "identical outputs across implementations" is verified for the surfaces currently covered. Surfaces without cross-language vectors (e.g., replay store durability semantics, state provider behavior) have not been verified cross-language. See §7.

---

### 3.2 I2: Fail-Closed Enforcement (ETA §4.2)

**ETA requirement:** Any verification failure or ambiguity produces non-execution. There is no silent success path through failure. The enforcement boundary does not pass execution on partial verification.

**OxDeAI mechanisms:**

**OxDeAIGuard** (`packages/guard/src/guard.ts`) implements the PEP (Policy Enforcement Point) gateway. The guard follows a sequential verification pipeline in which any failure throws `OxDeAIAuthorizationError` or `OxDeAIDenyError` before `execute()` is called. The guard does not reach execution until all of: ALLOW decision, valid `AuthorizationV1`, state hash match, intent hash match, replay check, audience match, and issuer match have passed. `setState()` is called before `execute()` and only if all verification steps pass.

**Throw-before-cache-swap** in `SiftHttpKeyStore.refresh()` ([`packages/sift/src/siftKeyStore.ts`](../../packages/sift/src/siftKeyStore.ts)) implements a parallel fail-closed guarantee for the KRL path: the in-memory revocation cache is not updated unless both JWKS and KRL fetch, parse, and integrity checks succeed. In `signed_required` mode, `KrlWatermarkStore.set()` must succeed before the cache is swapped; if it fails, `refresh()` throws `KRL_WATERMARK_PERSIST_FAILED` before any cache update ([#117 Phase A](../audits/protocol-audit-post-interoperability.md)).

**`signed_required` mode** closes the KRL transport-integrity gap: unsigned KRLs are rejected before `verifyKrl` is consulted (`KRL_UNSIGNED_IN_SIGNED_REQUIRED`), ensuring revocation data is never accepted via transport trust when the configuration mandates cryptographic verification.

**Property tests** in `packages/guard/src/test/guard.pep-conformance.test.ts` (GPC-1 through GPC-11) explicitly verify that every failure mode - kill-switch DENY, invalid signature, audience mismatch, expiry, state hash mismatch, auth_id replay, CAS version conflict, missing auth artifact, missing required fields - blocks `execute()`, `setState()`, and `beforeExecute()`.

**Residual:** Fail-closed behavior is only as strong as the configuration. In `signed_preferred` mode with unsigned KRL fallback, the revocation data is transport-trusted rather than cryptographically verified. This is documented in `RT-TRUST-2` of the audit and explicitly surfaced in the status surface (`unsignedFallbackActive: true`, `DEP_OXDEAI_KRL_UNSIGNED_FALLBACK` warning). Callers who do not configure `signed_required` + `KrlWatermarkStore` + `SignedKrlCache` retain residual risk on the KRL path. The #116 v-next migration PR establishes the deprecation trajectory; the default flip to `signed_required` remains pending a versioned release.

---

### 3.3 I3: Non-Bypassability (ETA §4.3)

**ETA requirement:** The enforcement boundary cannot be circumvented by actors within the agent runtime. Authorization cannot be short-circuited by any code path accessible to the agent.

**OxDeAI mechanisms:**

**Guard placement.** `OxDeAIGuard` is a higher-order function that wraps `execute()`. The contract is structural: the guarded action is only reachable via the returned `guard(action, execute)` function, which enforces verification before forwarding. Agents within the OxDeAI execution boundary do not receive a direct reference to `execute()` - they receive the guarded closure. This is an architectural constraint, not a runtime check.

**No bypass paths in the PEP.** The guard implementation in `guard.ts` has no escape hatch, no `trusted_caller` flag, and no backdoor that allows verification to be skipped. All 11 GPC conformance tests verify this under different failure conditions. Property test G1 (`engine DENY always prevents execute() and setState()`) and G5 (`successful ALLOW always calls setState() before execute()`) confirm the invariant holds across arbitrary `ProposedAction` inputs.

**DelegationV1 scope narrowing** ([`docs/spec/artifacts/delegation-v1.md`](../spec/artifacts/delegation-v1.md)) ensures that a delegatee agent cannot claim authority the delegator does not possess. `verifyDelegationChain()` enforces `DELEGATION_SCOPE_VIOLATION` when a child delegation exceeds the parent's scope on tools, max_amount, max_actions, or max_depth. The `parentScope` field on `GuardDelegationInput` is structurally validated before chain verification; the unsafe `(parentAuth as any).scope` cast was removed in [#113 P0-3](../audits/protocol-audit-post-interoperability.md).

**Limits of the claim.** Non-bypassability is enforced at the TypeScript/Node.js level. OxDeAI does not claim hardware-bound enforcement, OS-level process isolation, or protection against a fully compromised host process. These are acknowledged as out-of-scope in §7 below.

---

### 3.4 I4: Decision Artifact Completeness (ETA §4.4)

**ETA requirement:** The authorization decision is captured in a verifiable, self-contained artifact that carries the full decision context. A verifier must be able to reproduce the verification from the artifact without access to internal engine state.

**OxDeAI mechanisms:**

**AuthorizationV1** ([`docs/spec/artifacts/authorization-v1.md`](../spec/artifacts/authorization-v1.md)) is the primary decision artifact. It carries: `auth_id` (unique single-use identifier), `issuer`, `audience`, `intent_hash` (binds decision to the specific proposed action), `state_hash` (binds decision to the specific state snapshot at evaluation time), `policy_id`, `decision`, `issued_at`, `expiry`, `alg`, `kid`, and `signature`. The signed artifact is verifiable by any implementation with the correct `trustedKeySets` - no access to internal engine state is required.

**`toPublicAuthorizationV1()`** ([`packages/core/src/verification/verifyAuthorization.ts`](../../packages/core/src/verification/verifyAuthorization.ts)) strips all engine-internal fields (`authorization_id`, `engine_signature`, `state_snapshot_hash`, `policy_version`, `expires_at`) from the signing and hashing surface, resolved in [P0-4](../audits/protocol-audit-post-interoperability.md). Independent implementations can reproduce the same hash and signature preimage without access to engine internals.

**DelegationV1** ([`docs/spec/artifacts/delegation-v1.md`](../spec/artifacts/delegation-v1.md)) carries `parent_auth_hash = SHA-256(canonicalJson(toPublicAuthorizationV1(parent)))`, binding the delegation cryptographically to a specific parent evaluation context. The parent_auth_hash is independently verifiable by any conforming implementation.

**Audit log.** `HashChainedLog` in `packages/core/src/audit/HashChainedLog.ts` provides a tamper-evident chain of `INTENT_RECEIVED`, `DECISION`, `STATE_CHECKPOINT` events. `verifyAuditEvents()` verifies the chain independently of execution context. Envelope signing via `signEnvelopeEd25519()` seals the log with an Ed25519 signature over the canonical envelope, enabling post-hoc verification by any verifier with the issuer's public key.

**The distinction the ETA paper draws in §8.2** between "we have a governance policy" and "we can prove this action was governed" is concretely instantiated: `intent_hash` proves the specific proposed action was evaluated; `state_hash` proves the specific state was presented; `auth_id` ensures single-use via the ReplayStore; the audit log chain proves the sequence of events; the envelope signature proves the log was not tampered post-signing.

**Residual:** `state_hash` is computed by the adapter using a configured `computeStateHash` function. The guard verifies the hash at execution time but cannot verify the integrity of the state source itself (RT-TRUST-1 in the audit). This is a known open residual addressed in §7.

---

### 3.5 I5: Replayability (ETA §4.5)

**ETA requirement:** Governance decisions are independently reproducible from committed evidence. A verifier operating only from public artifacts must be able to arrive at the same verdict as the original enforcement boundary.

**OxDeAI mechanisms:**

**The portable conformance vector suite** ([`docs/spec/test-vectors/`](../spec/test-vectors/)) establishes that verification is independently reproducible. The 12 portable `authorization-v1.json` vectors (Encoding A and Encoding B), the 8 Profile C state-hash vectors (modes 001–008), and the 9 SignedKRLV1 vectors are each exercised by independent Go and Python harnesses that:

- Independently implement canonicalization-v1
- Independently compute Ed25519 preimages
- Independently perform Ed25519 verification using platform-native crypto libraries
- Independently compare results against committed expected verdicts

**Byte-equivalence proof.** The `KRL_DUPLICATE_REVOKED_KIDS` vector signature (`+mwEd2QP5+tx6pCKAiF8BKzMAHf1c28mcTQF575pDn/DwgRiJ+PkYnv+sasIdgj1S7E9mSZZK1pOTP43nlnsDA==`) and the Profile C mode 006–008 Encoding B artifact signature (`jMyip7h-GMgl2nV_q8Cz-MuqbD4vgba6vseRejY13e-w8WZeW7UU7ft58JHJFJR0fyZ3NGXvjJBGeKSSJLThCA`) serve as concrete byte-equivalence proof points: three independent implementations (TypeScript, Go, Python) compute identical preimage bytes from identical inputs and verify identical signatures. This is not a claimed property - it is a mechanically verified fact with every run of `pnpm test:vectors:all`.

**Cross-language harness assertion counts** as of #120: 209 TypeScript assertions, 28 Go assertions, 28 Python assertions, covering canonicalization, AuthorizationV1 verification, Profile C state-hash semantics, Profile C Encoding B, and SignedKRLV1.

**Replayability of individual authorization decisions.** Any verifier holding the issuer's public key, the AuthorizationV1 artifact, and the proposed action can independently verify: signature validity, expiry, audience, issuer, intent hash binding, and (with the live state) state hash binding. The `verify-authorization-vectors.mjs` script demonstrates this for the portable authorization vectors.

**Residual:** Replayability is verified for the cryptographic surfaces of AuthorizationV1. State provider behavior - whether the `state_hash` committed in an authorization accurately represents the state that was presented - is not verifiable from the artifact alone. This is the RT-TRUST-1 residual.

---

### 3.6 I6: Time-Bounded Evaluation Without Fail-Open (ETA §4.6)

**ETA requirement:** Evaluation is bounded in time. When an authorization's validity window expires, execution is blocked - there is no grace period, no implicit extension, and no silent fallthrough.

**OxDeAI mechanisms:**

**Strict zero-tolerance expiry** ([`docs/spec/artifacts/authorization-v1.md §17`](../spec/artifacts/authorization-v1.md)): valid iff `now < expiry`. There is no configurable grace period, no skew parameter, no fallback path when `now >= expiry`. The protocol explicitly requires NTP synchronization; issuers are required to build delivery latency into the `expiry` window.

**`issued_at` is informational only.** The verifier does not enforce a lower bound (`now >= issued_at` is not checked). This is a deliberate design choice: `issued_at` serves as an audit timestamp, not an activation gate, avoiding the undefined behavior that would result if clock skew produced a future `issued_at`. This is documented in [§17.2 of the AuthorizationV1 spec](../spec/artifacts/authorization-v1.md) and validated by conformance vector `clock-003` (verifier clock behind `issued_at` still accepts the authorization).

**Conformance vectors** `clock-001` through `clock-005` cover: last-valid-second (`now = expiry - 1`, status ok), one-past-expiry (`now = expiry + 1`, status AUTH_EXPIRED), verifier-clock-behind, and Encoding B variants of the same boundary conditions.

**KRL expiry** follows the same zero-tolerance model: `now >= not_after` → `KRL_EXPIRED`. Conformance vector `KRL_SIGNED_EXPIRED` exercises this across TypeScript, Go, and Python independently.

---

## 4. Binary Execution Gate vs. ABSTAIN-with-Escalation

### 4.1 OxDeAI's binary gate

OxDeAI v1 uses a binary execution gate. `AuthorizationV1.decision` is either `"ALLOW"` or excluded from the execution path entirely. A non-ALLOW outcome - including invalid artifacts, expired artifacts, audience mismatch, signature failure, state hash mismatch, or replay detection - produces `OxDeAIAuthorizationError` or `OxDeAIDenyError` before `execute()` is reached. There is no `"ABSTAIN"` verdict in `AuthorizationV1` v1.

### 4.2 Why ABSTAIN is not a first-class protocol verdict in v1

The ETA paper (§3.4, §4) discusses ABSTAIN-with-escalation as a mechanism for handling cases where a governance system cannot reach a binary decision and must hand off to a higher-level process (human review, secondary authorization path, or escalation workflow).

OxDeAI deliberately separates two concerns that ABSTAIN would conflate:

**Decision authority** belongs to the protocol layer. The PEP says ALLOW or non-ALLOW; that verdict is deterministic, bounded, and verifiable. Introducing ABSTAIN at the protocol level would make the authorization verdict non-deterministic in a way that cannot be mechanically tested: whether a given input produces ABSTAIN or a binary outcome becomes a function of policy state that varies by deployment.

**Workflow continuation** belongs to the orchestration layer above the PEP. What happens when the PEP says no - whether the action is terminally refused, escalated to a human, retried with narrowed parameters, queued for out-of-band review, or delegated to a different agent - is an orchestration decision. OxDeAI does not prescribe orchestration behavior; it provides a reliable ALLOW/non-ALLOW signal that orchestration systems can act on.

This separation keeps AuthorizationV1's semantics narrow, decidable, and independently verifiable. It is consistent with the ETA framework's requirement that enforcement boundaries be non-bypassable: a first-class ABSTAIN verdict, if improperly handled by an orchestration layer, could create a path to execution through unresolved authorization - precisely the failure mode I2 (fail-closed enforcement) is designed to prevent.

### 4.3 ABSTAIN at the orchestration layer

ABSTAIN-with-escalation is not precluded; it is simply out of scope for the protocol layer. An orchestration system consuming OxDeAI can implement any escalation behavior it chooses when it receives a non-ALLOW signal from the guard. The protocol makes no assumption about what the orchestration layer does with that signal - it only guarantees that execution did not occur.

Future versions of the protocol may revisit this separation if escalation patterns prove to need first-class protocol support (e.g., multi-round authorization workflows, federated delegation with escalation paths). This is acknowledged as a potential future direction, not a current gap.

---

## 5. Audit Posture Mapping: ETA §4.4 and §4.5

### 5.1 Proof-carrying decision artifacts (ETA §4.4)

The ETA paper (§8.2) draws a distinction between governance policies and proof-carrying governance evidence: a governance policy says what was supposed to happen; a proof-carrying artifact demonstrates what was authorized for a specific action instance.

OxDeAI's audit posture makes the following proof-carrying artifacts available:

| Artifact | What it proves |
|----------|---------------|
| `AuthorizationV1` with `intent_hash` | A specific proposed action (by canonical hash) was evaluated and ALLOW was produced |
| `AuthorizationV1` with `state_hash` | The evaluation was against a specific state snapshot (by canonical hash) |
| `AuthorizationV1` with `auth_id` | The decision was single-use; replay is detectable |
| `DelegationV1` with `parent_auth_hash` | A delegation was issued against a specific parent evaluation context |
| `HashChainedLog` audit events | The sequence of governance events is tamper-evident |
| Signed envelope | The audit log was sealed by a verifiable issuer at a specific time |

The combination of these artifacts means: for any executed action in an OxDeAI-governed system, a post-hoc auditor can verify not just "governance existed" but "this specific action was authorized by this specific evaluation against this specific state at this specific time by this specific policy engine."

### 5.2 Replayable conformance evidence (ETA §4.5)

OxDeAI's conformance vector approach goes beyond self-attestation. The 209 TypeScript, 28 Go, and 28 Python conformance assertions are mechanically reproducible by any party holding the `docs/spec/test-vectors/` vector files and the committed fixture key material. This means OxDeAI's protocol behavior can be independently replicated, not just described.

This is the same epistemological standard the ETA paper applies to governance decisions: the ability to reproduce the decision from committed evidence, not just trust that the original actor described it accurately.

---

## 6. Integration Patterns

### 6.1 External systems and the authority path

OxDeAI's execution boundary is defined by the authority path:

```
(intent, state, policy) → AuthorizationV1 → OxDeAIGuard → execute()
```

External systems that interact with OxDeAI-governed agents must not breach this path. Specifically:

- External systems may not substitute an alternative AuthorizationV1 that circumvents the policy engine evaluation
- External metadata may not influence `computeStateHash` output unless it is included in the canonical state structure that the policy engine evaluates
- External keys may not be substituted for the trusted key sets configured at the guard without explicit reconfiguration of the guard itself

### 6.2 Non-authoritative metadata pattern

**Worked example: Issue #122 (AetherisRouteEvidence non-authoritative metadata pattern)**

Issue #122 establishes the following pattern for attaching external observability or audit metadata to OxDeAI-governed actions:

External systems may attach metadata that audits, explains, or annotates agent behavior, provided that metadata:

1. Is cryptographically isolated from `AuthorizationV1` - it does not appear in `intent_hash`, `state_hash`, or any field that influences the PEP's ALLOW/non-ALLOW decision
2. Does not influence PEP enforcement - the guard's verification pipeline is not conditioned on the presence or content of the external metadata
3. Follows its own versioned canonicalization, separate from canonicalization-v1 - external metadata schemas evolve independently without affecting the protocol's verification surfaces

This pattern allows rich external observability (routing evidence, provenance attestations, cost attribution metadata) without creating a side-channel through which external actors could influence authorization outcomes. The metadata is evidence; the `AuthorizationV1` is authority.

**General principle.** The pattern generalizes to any external system that attaches contextual information to agent actions: the test is whether the metadata can, through any path, cause the PEP to produce a different ALLOW/non-ALLOW verdict than it would without the metadata. If yes, it is authoritative and must go through the policy engine. If no, it is non-authoritative and may be attached externally using the isolation pattern above.

---

## 7. Open Problems Shared with the ETA Framework

The ETA paper (§10) identifies open research directions. OxDeAI has concrete experience with several of these.

### 7.1 Policy composability (ETA §10.1)

**ETA framing:** How should authorization policies be composed across multiple policy engines, organizational boundaries, and trust contexts?

**OxDeAI status:** P2-4 ✓ SPECIFIED WITH RESIDUAL (#130). RT-TRUST-1 moves from RISK to SPECIFIED WITH RESIDUAL.

`docs/spec/state-provider-requirements.md` defines minimum integrity requirements for compliant OxDeAI state providers: read consistency and CAS semantics, state provenance, write access control, audit emission, replay/rollback expectations, compromise indicators, and compliance evidence. Pointers added to `pep-gateway-v1.md §27` and `external-provider-profile.md §2.3.3`.

The state provider boundary remains open as a named residual: **OxDeAI defines minimum requirements; the protocol cannot enforce state-source compliance at the wire level.** A compromised state provider that satisfies no requirement in the spec can still return manufactured state that produces a matching `state_hash`. `getState()` remains trusted input to the guard. Deployment compliance is operator responsibility.

This is the concrete instantiation of ETA §10.1 policy composability: when authorization spans multiple components (the policy engine, the state provider, the PEP), the integrity of the overall authorization chain depends on the integrity of each component. OxDeAI has closed the boundary at the PEP and policy engine layers and has now specified what the state provider boundary must satisfy. The residual is bounded; it is not closed.

### 7.2 Cross-domain authorization (ETA §10.2)

**ETA framing:** How should authorization be extended across organizational trust boundaries?

**OxDeAI coverage:** Profile B ([`docs/spec/interoperability/external-provider-profile.md`](../spec/interoperability/external-provider-profile.md)) establishes the adapter trust model: an external provider (e.g., Sift) signs a receipt with its own key; the adapter re-signs an `AuthorizationV1` with an OxDeAI key from `trustedKeySets`. The external provider receipt key and the OxDeAI signing key are distinct trust domains - the cross-domain boundary is explicit and cryptographically enforced.

DelegationV1 handles intra-agent cross-domain cases: a parent agent's authority can be narrowed and delegated to a child agent with explicit scope constraints, policy binding, and expiry enforcement.

**Residual:** Full cross-organizational federation - where multiple independent policy engines from different organizations share a single execution boundary - is not in scope for v1. Profile B handles the specific case of an external governance layer (Sift) delegating to the OxDeAI enforcement layer; it does not handle arbitrary organizational federation.

### 7.3 Formal verification (ETA §10.4)

Out of scope for v1. The protocol's invariants are mechanically tested via the conformance vector suite and property tests, but no formal proof of correctness exists. Acknowledged as a future direction for deployments requiring regulatory certification.

### 7.4 Semantic stability of state representations (ETA §10.5)

Out of scope for v1. `state_hash` binds the authorization to a specific state snapshot by SHA-256 hash; it does not address whether the state's semantic interpretation is stable across policy versions or schema changes. This is a known limitation of hash-based binding. Acknowledged as a future direction.

### 7.5 Hardware-bound enforcement (ETA §10.6)

Out of scope for v1. OxDeAI operates at the TypeScript/Node.js layer. Non-bypassability is enforced architecturally within the process; it does not extend to OS-level isolation, secure enclaves, or hardware attestation. Acknowledged as a future direction for high-assurance deployments.

---

## 8. Independent-Development Statement

OxDeAI's core architecture - canonicalization-v1, AuthorizationV1, the PEP boundary and OxDeAIGuard implementation, DelegationV1, SignedKRLV1, the cross-language conformance vector suite (TypeScript, Go, Python), and the Sift/Profile B integration - was developed independently of the Meyman ETA paper and predates its February 2026 publication.

The alignment described in this document is **convergent design**: two independent efforts arriving at structurally similar conclusions because the underlying problem (deterministic pre-execution authorization for AI agents) constrains the solution space. Systems that must enforce a verifiable, non-bypassable, fail-closed boundary between agent decision-making and action execution are led by the problem structure toward similar architectural choices: canonical serialization, signed decision artifacts, replay protection, time-bounded validity, independent verifiability.

This is a stronger validation signal than a paper-driven implementation would be. Independent convergence on the same invariants suggests those invariants are capturing something real about the problem, not just one team's design preferences.

No FERZ-specific system names (LASO, DELIA, 4TS, Type-Level Policy Encoding) are used as OxDeAI component names or references. OxDeAI's own terminology remains the canonical vocabulary throughout. The ETA framework is referenced as the category name and as the source of the formal invariant structure; OxDeAI's design is described in OxDeAI's own terms.

---

## 9. Standardization Positioning Summary

### What this alignment supports

- OxDeAI can be accurately described as **an execution-time authorization system**, in the sense developed by Meyman et al. (2026) and consistent with prior work in the field
- The six ETA invariants provide a vocabulary for describing OxDeAI's design choices to external audiences - policy makers, procurement, integrators - who may be familiar with the ETA framework or adjacent governance literature
- Cross-language independent verification (Go + Python) of all 8 Profile C modes and 9 SignedKRLV1 vectors provides external evidence of the determinism and replayability invariants that goes beyond self-attestation
- The convergent independent design is itself a validation signal that the invariants OxDeAI implements are structurally necessary for the problem, not arbitrary design choices

### What this alignment does not claim

- **Full standardization readiness.** The audit (`docs/audits/protocol-audit-post-interoperability.md §7.6`) marks this NOT READY. RT-TRUST-1 is now SPECIFIED WITH RESIDUAL - minimum requirements defined, deployment compliance is operator responsibility. Independent security review and a formal external feedback channel remain open prerequisites.
- **Conformance with the ETA framework.** No formal conformance process exists. This document is a mapping artifact, not a certification.
- **Closure of the open problems in ETA §10.** Policy composability (ETA §10.1) is partially addressed: P2-4 is specified with residual; the state provider boundary is bounded, not closed. Cross-domain federation beyond Profile B, formal verification, semantic stability, and hardware-bound enforcement all remain open.
- **Resolution of audit residuals.** State provider trust (RT-TRUST-1) moves from RISK to SPECIFIED WITH RESIDUAL (#130). KRL unsigned fallback risk and independent security review remain open. The ETA alignment mapping in §3 accurately describes residuals; this document does not retroactively close them.
- **Any claim of regulatory compliance or legal certification.** This is a technical mapping document.

### Re-read commitment

Per the acceptance criteria for this document, it should be re-read with at least 12 hours of separation between drafting and merging, specifically to check for rhetorical inflation or overclaim. The most likely failure modes are: (a) framing coverage as completeness, (b) describing residuals with qualifications that obscure their seriousness, and (c) treating convergent design as endorsement. All three failure modes are addressed explicitly in §2, §3.x (residuals), and §9.

---

*This document was added alongside the completion of Profile C Encoding B cross-language conformance coverage (#120). RT-TRUST-1 / P2-4 was addressed in #130 (state provider trust boundary specified with residual). This document should be revisited when an independent security review is commissioned.*
