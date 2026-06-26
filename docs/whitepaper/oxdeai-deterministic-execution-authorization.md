# OxDeAI: A Deterministic Execution Authorization Protocol

**Ange Yobo**
*OxDeAI Project*
*research@oxdeai.dev*

**Version:** Working draft, June 2026
**License:** This paper is licensed under CC-BY-4.0.

> **Working draft notice.** This document is not a final protocol paper and is not ready for publication. Concrete field names, vector identifiers, assertion counts, cryptographic examples, file paths, and references marked `[verify]` must be reconciled against the live repository before external publication.

---

## Abstract

Modern execution systems — AI agents, workflow engines, automation platforms, orchestrators, and human-operated software — increasingly invoke external services, infrastructure, and side-effecting operations on behalf of users and organizations. The reliability of these invocations depends on a question that conventional authorization infrastructure does not address: at the moment an execution is attempted, has the specific action been authorized by a deterministic governance process, and can that authorization be verified before the action executes?

This paper presents OxDeAI, a protocol that answers this question with a deterministic, verifiable, fail-closed enforcement mechanism. OxDeAI defines a small set of signed protocol artifacts (`AuthorizationV1`, `DelegationV1`, `SignedKRLV1`) and a canonical serialization (`canonicalization-v1`) that together establish a pre-execution authorization boundary between decision-making and action actuation. Authorization decisions are produced by a policy engine, captured in cryptographically signed artifacts, and enforced by a policy enforcement point (PEP) before any side-effecting operation occurs. The protocol's invariants are verified by a conformance suite of 265 assertions reproducible across independently implemented TypeScript, Go, and Python harnesses (TypeScript, Go, Python).

OxDeAI operates at a layer that existing authorization systems do not occupy. Identity-centric frameworks (OAuth 2.0, JWT, IAM systems) authenticate principals and authorize resource access for sessions or scopes. Capability-based systems delegate authority through unforgeable tokens. OxDeAI authorizes individual execution attempts against a specific intent, policy, and state snapshot, producing a binary, deterministic verdict that is captured in evidence reproducible by independent verifiers.

We describe the protocol's design, its security properties, its limitations, and its residual trust assumptions. We define six security goals (G1-G6) and map every protocol mechanism to those goals. We discuss the protocol's positioning within the broader category of execution-time authorization systems that recent literature has begun to formalize as a distinct architectural category, and describe the convergent independent design that produced architectural choices aligned with that formalization.

OxDeAI does not solve every problem in execution governance. It does not classify execution behavior, predict execution intentions, or replace organizational policy decisions. It addresses one narrow but critical question: given a proposed action, can we deterministically verify, before execution, whether that action is authorized by a governance process whose decision is captured in evidence that can be independently reproduced?

---

## 1. Introduction

### 1.1 The execution authorization gap

A modern execution system — whether an AI agent, a workflow engine, a CI/CD pipeline, an automation platform, or a human-operated script — invokes external services through structured action calls. These calls reach APIs, databases, payment systems, infrastructure provisioning, and communication channels. Each invocation has consequences in systems that the executing process does not control.

The conventional security mechanisms governing these invocations were designed for a different operating model. API keys, OAuth tokens, IAM policies, and network ACLs authenticate identity and check coarse-grained permissions. They establish that a principal (user, service account, or system) is permitted to access a resource. They do not address the questions specific to deterministic execution governance: was this specific action, as proposed at this moment, against this specific state of the world, deliberately authorized by a governance process? Can that authorization be verified, after the fact, by an auditor who was not present when the decision was made? Does the absence of authorization produce non-execution rather than partial execution or undefined behavior?

These are not new questions. Capability-based security systems have asked them for decades [Levy 1984, Miller 2006], and distributed authorization systems have answered them in specific contexts [Hardt 2012, Jones 2015, Birgisson 2014]. What is operationally new is the scale and rate at which automated systems — particularly AI agents — now invoke external actions, the difficulty of mapping their reasoning processes to traditional authorization vocabularies, and the cost of fail-open failure modes when an automated executor proceeds without explicit governance.

Existing authorization frameworks address related but distinct problems. OAuth 2.0 [Hardt 2012] authenticates principals and delegates resource access for sessions or scopes; it does not produce a decision artifact bound to a specific intent and state. JWT [Jones 2015] provides signed claims about a principal; the claims do not constitute a deterministic governance decision over a proposed action. Capability tokens [Miller 2006, Birgisson 2014] grant unforgeable rights but do not bind those rights to the specific computational context in which they are exercised. None of these systems are wrong; they operate at a different layer.

OxDeAI authorizes individual execution attempts against a specific intent, policy, and state snapshot. The protocol therefore operates at a different layer than identity-centric authorization frameworks: it does not replace them, it composes with them. A system using OxDeAI may use OAuth for principal authentication, IAM for resource access, and OxDeAI for the deterministic governance decision about whether a specific proposed action may execute under the current state of the world.

Most current execution governance infrastructure addresses this layer implicitly. Automated executors are configured with credentials at startup; their actions execute as long as those credentials remain valid. Some platforms add monitoring that flags suspicious behavior after execution; some add model-based classifiers that score risk before execution. Both are useful, but neither produces a deterministic, independently verifiable decision artifact. A risk score is not a deterministic decision. A flagged anomaly is not a refused action.

This paper presents an alternative architecture. We define a protocol that produces a binary, deterministic, signed authorization decision before any side effect occurs. The decision is captured in a verifiable artifact; the artifact is checked by a policy enforcement point; the execution boundary is unreachable without artifact verification. We call this protocol OxDeAI.

### 1.2 Contributions

This paper makes the following contributions:

*A deterministic execution authorization model* that separates authorization production from authorization enforcement through signed, independently verifiable decision artifacts. The model establishes a structural boundary between the policy engine (which decides) and the policy enforcement point (which enforces), with the decision artifact (`AuthorizationV1`) serving as the only authorized bridge between them. This separation is the central architectural contribution of the work.

*A protocol specification* comprising four normative artifacts: `AuthorizationV1` (decision artifact), `DelegationV1` (scoped delegation), `SignedKRLV1` (key revocation), and `canonicalization-v1` (deterministic serialization). Each artifact is fully specified in this paper and at the project repository, with conformance vectors that constrain the implementation space.

*An enforcement architecture* (`OxDeAIGuard`) that demonstrates how the protocol artifacts compose into a policy enforcement point. The architecture preserves the protocol's invariants and admits independent implementation in any language with Ed25519 cryptographic primitives.

*A conformance methodology* that establishes byte-equivalent cross-implementation reproducibility. We describe the 265-assertion conformance suite, the three language implementations (TypeScript, Go, Python) that validate it, and the byte-equivalence proof points that anchor cross-language verification. The TypeScript reference, Go harness, and Python harness are implemented independently of each other at the code level; all are currently project-maintained.

*Three interoperability profiles* (A, B, C) that allow the protocol to integrate with external governance providers at varying levels of semantic verification. We describe the trust separation between external providers and the OxDeAI enforcement boundary and demonstrate the pattern with a deployed adapter (`@oxdeai/sift`) for an external governance provider.

*An audit methodology* that ties every claim about the protocol's behavior to specific conformance vectors, specifications, or named residuals. The methodology produces conservative, evidence-tied documentation that resists overclaim failure modes common in security infrastructure literature.

### 1.3 What this paper is not

This paper does not claim that OxDeAI is a finished standard. The protocol has not undergone independent security review. The project has not been adopted by a standards body. The state-provider trust boundary is specified but cannot be cryptographically enforced at the protocol layer. Independent academic peer review of the protocol is forthcoming.

This paper does not claim that OxDeAI solves execution governance broadly. It addresses one specific layer — execution-time authorization — within a much larger set of concerns. Decision-making correctness, policy specification correctness, organizational governance, deployment hygiene, and many other concerns are outside the protocol's scope.

This paper does not claim novelty in cryptographic primitives. OxDeAI uses Ed25519 [Bernstein et al. 2012, RFC 8032], SHA-256 [FIPS 180-4], and canonical serialization techniques that have been studied for decades. The contribution is in the protocol-level composition of these primitives, the architectural discipline that maintains the protocol's invariants, and the conformance methodology that makes the resulting protocol independently verifiable.

### 1.4 Paper structure

Section 2 defines six security goals (G1-G6) that the protocol is designed to satisfy. Section 3 develops the threat model. Section 4 surveys related work in capability security, distributed authorization, execution governance, and recent execution-time authorization literature. Section 5 describes the protocol architecture at the level of decision flow and enforcement boundary. Section 6 specifies `AuthorizationV1`. Section 7 specifies `DelegationV1`. Section 8 describes the PEP architecture (`OxDeAIGuard`). Section 9 specifies the verification model. Section 10 describes the conformance methodology. Section 11 specifies the interoperability profiles. Section 12 returns to the security goals and maps every mechanism to specific goals. Section 13 names the protocol's limitations and residual trust assumptions. Section 14 positions OxDeAI within the broader category of execution-time authorization systems. Section 15 outlines future work.

The appendices provide complete specifications for the protocol artifacts, the canonicalization grammar, the error code taxonomy, and the conformance vector catalog.

---

## 2. Security Goals

We define six security goals that OxDeAI is designed to satisfy. Every protocol mechanism in this paper maps to one or more of these goals; Section 12 provides the explicit mapping.

These goals are stated as security properties, not as marketing claims. Each goal is satisfied by specific mechanisms with named residuals. The goal statements below are intentionally narrow; broader claims (such as "OxDeAI provides security against compromise") would not be defensible without specifying threat models and residuals.

### G1: Authorization authenticity

An authorization artifact accepted by a conformant PEP was produced by an issuer holding a private key that the PEP's verifier has been explicitly configured to trust.

*Mechanism:* Ed25519 signature over canonical serialization, with the PEP's `trustedKeySets` configuration defining the trust boundary. A signature alone is not sufficient; the signing key must be present in `trustedKeySets` and not present in the current key revocation list.

*Residual:* Compromise of an issuer's private key produces forged artifacts indistinguishable from legitimate ones until the key is revoked. Key compromise detection is out of scope for the protocol; key revocation propagation is bounded by the KRL polling interval and signing latency.

### G2: Authorization integrity

An authorization artifact cannot be modified after signing without invalidating the signature, regardless of which fields are modified.

*Mechanism:* The Ed25519 signature covers a domain-prefixed canonical serialization of the entire artifact. Any modification — to fields, to ordering, to encoding — produces a different signature input and thus signature verification failure.

*Residual:* The canonical serialization (`canonicalization-v1`) defines the signature input precisely. Implementation bugs in canonicalization that produce divergent canonical forms across implementations could in principle allow an artifact to verify in one implementation and fail in another. The conformance suite (Section 10) is designed to detect such divergence; the suite cannot prove its absence in implementations not tested.

### G3: Replay resistance

An authorization artifact accepted once by a conformant PEP cannot be accepted a second time by a conformant deployment with durable replay state.

*Mechanism:* Each artifact carries a unique `auth_id`. The PEP consumes the `auth_id` through a `ReplayStore` interface implementing atomic single-use semantics. Production deployments configure durable backing stores (e.g., Redis with SET NX, PostgreSQL with serializable isolation, DynamoDB with conditional writes) to provide replay guarantees that survive process restarts and span multiple PEP instances.

*Residual:* The protocol specifies the replay store contract; it does not enforce the choice of backing store at the wire level. Single-process deployments using the default in-memory `ReplayStore` lose replay state on process restart, creating a replay window during the restart interval. Multi-process deployments using the in-memory default lose replay coherence across instances entirely. The protocol's replay guarantee is therefore conditional on deployment configuration. This conditionality is documented in the audit (RT-TRUST-3) and the replay-store deployment guide. Detection of misconfigured deployments is not enforced at the protocol layer.

### G4: Delegation non-expansion

A delegation artifact cannot grant a delegatee any authority that the delegating authorization did not itself possess.

*Mechanism:* `DelegationV1` carries a `parent_auth_hash` that cryptographically binds the delegation to a specific parent `AuthorizationV1`. The verifier checks that the delegation's scope (tools, budget ceiling, expiry) is a strict narrowing of the parent's scope. Any scope expansion produces `DELEGATION_SCOPE_VIOLATION`.

*Residual:* `DelegationV1` v1 supports only single-hop delegation. Multi-hop delegation is specified but not in scope for v1. The current verifier explicitly rejects chains deeper than one hop with `DELEGATION_SINGLE_HOP`.

### G5: Deterministic verification

Two conformant implementations, given the same authorization artifact and the same verifier configuration, produce identical verification verdicts.

*Mechanism:* The canonical serialization is deterministic and byte-equivalent across implementations. Ed25519 verification is deterministic by construction [RFC 8032]. The verifier's decision is a pure function of the artifact, the verifier configuration, and the wall-clock time injected as a parameter (`opts.now`). The conformance suite verifies determinism across three independent implementations.

*Residual:* Determinism is verified for the surfaces covered by conformance vectors. Surfaces not currently covered (e.g., specific canonicalization edge cases for unusual Unicode sequences) may exhibit implementation divergence not detected by the current suite. This residual is bounded by the suite's coverage and reduced with each additional vector.

### G6: Fail-closed enforcement

Any verification failure, configuration ambiguity, or absence of authorization produces non-execution. There is no execution path through partial verification or graceful degradation.

*Mechanism:* The PEP (`OxDeAIGuard`) implements a sequential verification pipeline in which any failure throws before the execution boundary is reached. The `trustedKeySets` configuration, when absent in strict mode, produces `TRUSTED_KEYSETS_REQUIRED` as a hard failure. The `signed_required` KRL mode rejects unsigned revocation lists before any verification proceeds.

*Residual:* Fail-closed behavior is only as strong as the deployment's configuration. A deployment configured with `signed_preferred` mode (the current default) accepts unsigned KRL fallback during transport failures; this is documented in the audit (RT-TRUST-2) and tracked for migration to `signed_required` as the default in a future protocol version.

---

These six goals serve as the evaluation framework for the rest of the paper. When we describe a protocol mechanism, we reference the goals it serves. When we discuss limitations, we name the residuals that bound the goals. When we describe conformance, we describe how the goals are verified.

The goals are deliberately separated from the threat model (Section 3). The threat model defines the adversary; the goals define what we want to be true regardless of the adversary's actions within the model. This separation follows established practice in security protocol literature [Anderson 2008].

---

## 3. Threat Model

This section defines the adversary OxDeAI is designed to resist, the components the protocol treats as trusted, the components it treats as untrusted, the capabilities the adversary is assumed to have, the attacks that are explicitly out of scope, and the deployment assumptions that the protocol's security properties depend on.

The threat model is stated narrowly. OxDeAI does not claim to resist arbitrary adversaries; it claims to resist specific adversary capabilities, against specific protected assets, under specific deployment assumptions. Claims outside this model are not made.

### 3.1 Protected assets

The protocol protects three classes of assets:

*The authorization decision itself.* For each proposed action, the protocol produces a binary verdict (ALLOW or non-ALLOW) that determines whether the action's side effects may occur. The protocol's primary security property is that this verdict is produced by a designated policy engine, captured in a verifiable artifact, and enforced before any side effect.

*The integrity of the authorization artifact.* Once produced, the artifact must not be modifiable without invalidating its signature. Any modification — to its decision field, its expiry, its intent binding, its state binding, or any other field — must produce a verifiable failure rather than a silent acceptance.

*The single-use property of authorization.* Each authorization artifact authorizes one execution. An adversary that obtains a valid artifact must not be able to replay it to obtain multiple executions, regardless of whether the replay attempt occurs in the same process, a different process, or after a process restart, subject to the deployment-configuration constraints described in §3.7 and Section 12.

The protocol does not directly protect the *contents* of executions. What an authorized action does after it executes is governed by the execution environment, not by OxDeAI. The protocol protects the gate, not the room behind the gate.

### 3.2 Trusted components

The protocol designates the following components as trusted within its security model:

*The policy engine* that produces authorization decisions. The policy engine is the source of truth for the ALLOW/non-ALLOW verdict. The protocol does not verify the correctness of the policy engine's reasoning; it verifies that the engine's decision is captured in a properly signed artifact.

*The signing keys* that the policy engine uses to produce `AuthorizationV1` and `DelegationV1` artifacts. Compromise of a signing key allows an adversary to produce valid-looking artifacts indistinguishable from legitimate ones until the key is revoked.

*The verifier's `trustedKeySets` configuration.* The verifier accepts artifacts signed by keys in `trustedKeySets`. An adversary who can modify the verifier's `trustedKeySets` configuration to include their own keys can produce artifacts that the verifier accepts. Protection of `trustedKeySets` integrity is a deployment-layer concern; the protocol does not enforce it.

*The current key revocation list (KRL).* The verifier rejects artifacts signed by keys present in the current KRL, even when those keys are also in `trustedKeySets`. The integrity of KRL distribution depends on the deployment's chosen KRL mode (`signed_required`, `signed_preferred`, or `unsigned_legacy`); see §3.7 for the corresponding residuals.

*The state provider* (when Profile C is in use). The state provider supplies the live state object that the PEP hashes and compares against the authorization's `state_hash`. The PEP cannot verify that the state provider's output is honest, current, or derived from a compliant source of truth. The state provider's integrity is bounded by deployment compliance with the state-provider requirements specification rather than by protocol-layer enforcement. This is one of the protocol's primary residual trust assumptions.

*The clock source* that the verifier consults for expiry checks. A clock that is significantly behind the issuer's clock can cause the verifier to accept expired artifacts; a clock significantly ahead can cause it to reject valid ones. NTP synchronization is assumed. The protocol does not enforce clock integrity.

*The replay store* that maintains the set of consumed `auth_id` values. A compromised or unavailable replay store either accepts replays (compromising G3) or fails verification (which is the protocol's intended fail-closed behavior). The protocol's `ReplayStore` contract requires fail-closed behavior on store unavailability.

### 3.3 Untrusted components

The protocol treats the following components as untrusted, meaning their inputs and behavior are not relied upon for security properties:

*The action proposal source.* Whether the proposing component is an AI agent, a workflow engine, a CI/CD pipeline, an automation script, or a human-operated process, the protocol does not trust the proposal itself. The proposal is an input to the policy engine; the policy engine decides whether the proposed action is authorized.

**OxDeAI treats action proposals as untrusted even when produced by trusted identities.** A workflow engine running with a trusted identity may propose an action that the policy engine refuses, and the protocol's invariants hold regardless of the proposer's identity. The identity-trust layer (who can propose) is separate from the action-authorization layer (what can be executed).

*Network transports.* The protocol assumes that artifacts may transit untrusted networks. Artifact integrity is protected by signature; artifact confidentiality is not a protocol concern. Deployments requiring confidentiality should use TLS or equivalent transport protection, but the protocol's security properties do not depend on it.

*Storage of artifacts at rest.* Authorization artifacts may be stored in databases, message queues, or filesystems that the protocol does not control. Storage integrity is bounded by the deployment's storage choices; the protocol's signature verification detects tampering whenever the artifact is verified.

*Audit logs.* The protocol produces audit events via the `HashChainedLog` mechanism, but audit log durability and access control are deployment-layer concerns. An adversary who can delete or modify audit logs cannot forge new authorizations (signature verification prevents this) but can obscure historical activity.

*External governance providers* (in Profile B integrations). When an external provider (e.g., Sift) produces governance evidence that an adapter translates into `AuthorizationV1`, the external provider's signing key is distinct from the OxDeAI signing key in the verifier's `trustedKeySets`. The external provider is not trusted to produce `AuthorizationV1` directly; only the adapter, signing with an OxDeAI-trusted key, can do so. The trust separation is structural.

### 3.4 Adversary capabilities

The protocol is designed to resist an adversary with the following capabilities:

*Observation of artifacts in transit.* The adversary may observe `AuthorizationV1`, `DelegationV1`, and `SignedKRLV1` artifacts as they traverse the network. The artifacts contain decision metadata but no secret material; observation does not compromise the protocol.

*Capture and replay attempts.* The adversary may attempt to replay captured artifacts. The protocol resists replay through the `auth_id` mechanism (G3), subject to the deployment-configuration constraints documented in §3.7.

*Modification of artifacts in transit or at rest.* The adversary may modify artifacts. The Ed25519 signature ensures that any modification produces verification failure (G2).

*Substitution of artifacts.* The adversary may attempt to substitute one valid artifact for another (e.g., presenting an authorization issued for a different action). The protocol resists substitution through intent binding (`intent_hash`), state binding (`state_hash`), audience binding, and issuer binding. Any mismatch produces verification failure.

*Compromise of the proposing component.* The adversary may control the component proposing actions to the policy engine. This is treated as a normal operating condition rather than an attack, since the proposer is untrusted by design.

*Submission of malformed inputs.* The adversary may submit malformed canonical serializations, signatures, or field values. The protocol's verification pipeline rejects malformed inputs through specific error codes; the canonicalization-v1 specification rejects ambiguous serializations (duplicate keys, floats, unsupported types).

*Attempted denial of service against verifier components.* The adversary may attempt to exhaust verifier resources by submitting large numbers of verification requests. The protocol does not include DoS mitigation mechanisms at the protocol layer; deployments are responsible for rate limiting and resource protection.

*Manipulation of clock sources observable to the verifier.* The adversary may attempt to influence the clock the verifier uses for expiry checks. The protocol's strict zero-tolerance expiry semantics bound the impact: a clock significantly behind real time may accept expired artifacts within the skew window, but the verifier cannot be coerced into accepting an artifact whose `expiry` is past the verifier's observed time.

### 3.5 Adversary capabilities explicitly out of scope

The protocol does not claim to resist the following adversary capabilities:

*Compromise of a signing key.* An adversary who obtains a signing key in the verifier's `trustedKeySets` can produce valid-looking artifacts until the key is revoked. Detection of key compromise is out of scope for the protocol. Revocation propagation is bounded by the deployment's KRL polling interval and signed-KRL signing latency.

*Compromise of the verifier configuration.* An adversary who can modify the verifier's `trustedKeySets` configuration to include their own keys can produce artifacts the verifier accepts. Protection of verifier configuration integrity is a deployment-layer concern (filesystem permissions, configuration management security, etc.).

*Compromise of the state provider.* An adversary who controls the state provider can return manufactured state objects whose hash matches a valid authorization's `state_hash`. The PEP cannot distinguish this from legitimate state. This is the central residual trust assumption (RT-TRUST-1); the state-provider-requirements specification defines what compliant deployments must satisfy, but compliance is not enforceable at the protocol layer.

*Insider threats at the policy engine.* An authorized actor at the policy engine who issues authorizations against policy is not detectable by the protocol. The protocol verifies that the engine's signing key was used; it does not verify that the engine's decision was correct.

*Hardware-level attacks.* The protocol operates at the software layer. Physical attacks on hardware containing signing keys, side-channel attacks against Ed25519 implementations, and similar hardware-level adversaries are out of scope. Deployments requiring hardware-bound enforcement should use hardware security modules or secure enclaves for key custody; the protocol composes with such systems but does not provide them.

*Cryptographic compromise of underlying primitives.* If Ed25519 or SHA-256 is broken by future cryptographic advances, the protocol's guarantees weaken proportionally. This residual is shared with most cryptographic protocols and is not OxDeAI-specific.

*Quantum-cryptographic adversaries.* The protocol uses Ed25519, which is not post-quantum secure. A sufficiently capable quantum adversary could forge signatures. The protocol does not currently address post-quantum migration; this is acknowledged as future work.

*Denial of service.* Attacks that prevent the protocol from functioning (network partition isolating the verifier from the replay store, exhaustion of verifier CPU, KRL distribution failures) cause fail-closed behavior in conformant implementations. The protocol prefers unavailability over incorrect authorization, but the protocol does not prevent denial-of-service attacks from occurring.

*Social engineering against operators.* An adversary who tricks an operator into adding their key to `trustedKeySets` or removing a legitimate key from the KRL has bypassed the protocol's trust boundary entirely. The protocol provides no defense against such attacks.

### 3.6 Fail-closed assumptions

The protocol's fail-closed behavior depends on the following implementation assumptions:

*Verification failures terminate the verification pipeline before reaching execution.* The PEP's sequential verification pipeline is structured so that any failure throws before the execution boundary is reached. Conformance vectors in the GPC (Guard PEP Conformance) series verify this behavior across all known failure modes.

*Configuration errors produce explicit failure rather than implicit defaults.* The strict-mode behavior requiring `trustedKeySets` produces `TRUSTED_KEYSETS_REQUIRED` rather than silently disabling verification. Similarly, `signed_required` KRL mode rejects unsigned KRLs explicitly rather than silently falling back to transport trust.

*Replay store unavailability produces verification failure.* The `ReplayStore` interface specifies that store exceptions must cause verification failure rather than implicit acceptance. The guard catches store exceptions and throws `OxDeAIAuthorizationError`.

*Clock unavailability produces explicit failure.* The protocol requires `opts.now` to be passed explicitly in strict mode rather than reading the system clock implicitly. Implementations that read the system clock implicitly may exhibit non-deterministic behavior; this is detected by conformance vectors that inject specific timestamps.

*Adapter and integration code preserves fail-closed semantics.* External governance provider adapters (Profile B) and integration code must preserve the fail-closed property. The protocol provides the verification primitives; the adapter is responsible for not introducing graceful-degradation paths that bypass them.

### 3.7 Deployment assumptions

The protocol's security properties depend on the following deployment-layer assumptions, which the protocol cannot enforce at the wire level:

*Signing key custody.* Issuers are assumed to maintain custody of their signing keys using appropriate operational security: key rotation procedures, hardware security modules or equivalent where the threat model warrants them, separation of key access from general system access, and audit of key usage. The protocol provides key revocation as the mechanism for handling compromise but does not provide custody itself.

*Verifier configuration integrity.* The verifier's `trustedKeySets` configuration is assumed to be protected against unauthorized modification. Configuration management discipline, filesystem permissions, secret management systems, and review processes for configuration changes are deployment-layer responsibilities.

*Replay store durability for multi-process and restart-resilient deployments.* Deployments requiring replay resistance across process restarts or across multiple PEP instances must configure durable backing stores (Redis, PostgreSQL, DynamoDB, or equivalent). The in-memory default is suitable only for single-process deployments where replay resistance across restarts is not required. Detection of misconfigured deployments is not enforced at the protocol layer (RT-TRUST-3).

*KRL transport integrity.* Deployments requiring cryptographic verification of revocation data must configure `signed_required` KRL mode. The current default (`signed_preferred`) accepts unsigned fallback during transport failures, retaining transport-trust-only semantics for unsigned cases (RT-TRUST-2). This is tracked for migration to `signed_required` as the default in a future protocol version.

*State provider compliance for Profile C deployments.* Deployments using Profile C (live-state re-verification at the PEP) must use state providers compliant with the `state-provider-requirements` specification. The PEP verifies hash binding between the authorization artifact and the live state object but cannot verify state-source compliance (RT-TRUST-1). Non-compliant state providers retain the full residual risk.

*Clock synchronization.* Issuers and verifiers are assumed to synchronize via NTP or equivalent. The protocol's strict zero-tolerance expiry semantics depend on clock alignment; significant skew can cause valid artifacts to be rejected or expired artifacts to be accepted.

*PEP placement.* The PEP must be placed such that the proposing component cannot bypass it. Architectural placement of the PEP is a deployment concern; the protocol provides the enforcement primitives but does not enforce that they are actually placed in the execution path.

### 3.8 Residual trust assumptions summary

The protocol's security properties hold under the model described in §3.1–§3.7. The following residual trust assumptions are not covered by the protocol's mechanisms and must be addressed at the deployment layer:

| Residual | Description | Mitigation |
|----------|-------------|------------|
| RT-TRUST-1 | State provider integrity is trusted; the PEP cannot verify state-source compliance | Deployment compliance with `state-provider-requirements` |
| RT-TRUST-2 | KRL transport integrity in `signed_preferred` mode with unsigned fallback | Configure `signed_required` mode |
| RT-TRUST-3 | In-memory replay store loses state on restart and across processes | Configure durable replay store (Redis, PostgreSQL, etc.) |
| Key custody | Signing key compromise produces forged-but-valid artifacts | Operational security; HSMs where warranted |
| Configuration integrity | Modification of `trustedKeySets` admits adversary keys | Deployment-layer configuration management |
| Clock integrity | Clock skew can cause incorrect expiry behavior | NTP synchronization |
| PEP placement | PEP can be bypassed if not architecturally enforced | Deployment architecture |

This taxonomy is not a list of weaknesses to be ashamed of. Every security protocol has residual trust assumptions; the discipline of stating them explicitly is what allows deployments to evaluate whether the protocol's threat model matches their operating environment.

OxDeAI's approach to residuals is to name them, specify what deployment compliance must satisfy to mitigate them, and refrain from making protocol-layer claims that the residuals would contradict. A protocol that names its residuals provides a more useful security artifact than one that elides them, even when the elision would produce a more impressive-looking specification.

---

Picking the whitepaper back up. We finished the revised Introduction, Section 2 (Security Goals, G1–G6), and Section 3 (Threat Model). Next in the agreed ordering is Section 4 (Related Work), then Section 5 (Protocol Architecture).

Here's Section 4. This is the section where the Meyman reference lands in full, since it was deliberately moved out of the introduction.

---

## 4. Related Work

OxDeAI draws on four bodies of prior work: capability-based security, identity-centric authorization frameworks, distributed and decentralized authorization tokens, and the emerging literature on governance for autonomous and agentic systems. We survey each, then position OxDeAI relative to the recent formalization of execution-time authorization as a distinct architectural category.

The purpose of this section is to locate OxDeAI precisely. The protocol is not novel in its cryptographic primitives, nor in the general idea of authorizing actions before they occur. Its contribution is a specific composition — deterministic decision artifacts, separated production and enforcement, cross-implementation conformance — that addresses a problem the surveyed systems do not directly solve.

### 4.1 Capability-based security

Capability-based security [Dennis and Van Horn 1966, Levy 1984] models authority as unforgeable tokens that both designate a resource and convey the right to access it. A process holding a capability can act; a process without it cannot. The model unifies designation and authorization, avoiding the ambient-authority problems of access-control-list systems where a process's permissions are determined by its identity rather than by the specific authority it was granted.

The object-capability (ocap) refinement [Miller 2006] extends this to programming-language and distributed-system settings, where capabilities are references that can only be obtained through explicit delegation. The ocap discipline — no ambient authority, authority only by introduction — directly informs OxDeAI's stance that an executing component receives only the guarded closure, never a direct reference to the execution function (Section 8).

OxDeAI shares the capability model's core intuition: authority should be explicit, unforgeable, and narrowable. `DelegationV1` is, in effect, a capability that narrows a parent authorization's scope and cannot expand it (G4). Where OxDeAI departs from classical capability systems is in binding the authority to a specific computational context — a specific intent, a specific state snapshot, a specific time window — rather than granting a standing right to a resource. A classical capability says "the holder may access resource R." An OxDeAI authorization says "this specific proposed action, against this specific state, is authorized to execute until this specific time." The binding to intent and state is what makes the authorization a governance decision rather than a standing permission.

### 4.2 Identity-centric authorization frameworks

OAuth 2.0 [Hardt 2012] and its surrounding ecosystem (OpenID Connect, JWT [Jones 2015]) dominate contemporary authorization for web and API systems. These frameworks authenticate a principal and issue tokens that convey scopes — coarse-grained statements about what resources the principal may access. A bearer token grants its holder the associated scopes for the token's lifetime.

These systems solve a different problem than OxDeAI. They answer "is this principal allowed to access this resource?" OxDeAI answers "is this specific proposed action, against the current state, authorized to execute?" The distinction matters in three ways.

First, scope granularity. OAuth scopes are typically static strings (`read:email`, `write:repo`) checked against a token. They do not bind to the specific parameters of an action or the state of the world at execution time. An OxDeAI authorization binds to the canonical hash of the proposed action (`intent_hash`) and the canonical hash of the state snapshot (`state_hash`), making it specific to one execution attempt.

Second, decision determinism. An OAuth authorization server may make access decisions through arbitrary internal logic; the token reflects the outcome but not a reproducible decision. OxDeAI requires that the decision be a deterministic function of (intent, state, policy), reproducible by any conformant implementation (G5).

Third, single-use semantics. OAuth bearer tokens are reusable within their validity window by design. OxDeAI authorizations are single-use, consumed through a replay store (G3), because an execution authorization governs one execution, not a session.

OxDeAI composes with these frameworks rather than replacing them. A deployment may authenticate principals with OAuth, authorize resource access with IAM, and use OxDeAI for the deterministic governance decision about whether a specific action executes. The layers are orthogonal.

### 4.3 Distributed and decentralized authorization tokens

A line of work extends bearer tokens with cryptographic delegation and attenuation. Macaroons [Birgisson et al. 2014] are bearer tokens that support caveats — restrictions that can be added by any holder without contacting the issuer, narrowing the token's authority. Biscuit [biscuit-auth] applies a similar attenuation model with a Datalog-based authorization logic. Verifiable credentials [W3C VC] and related decentralized-identity systems provide signed claims that a holder can present and a verifier can check without contacting the issuer.

These systems share OxDeAI's interest in offline verifiability and in delegation that can only narrow authority. Macaroon caveats and `DelegationV1` scope narrowing express the same principle: a delegated authority must be a subset of the delegating authority. The cryptographic binding differs — macaroons use HMAC chaining, OxDeAI uses Ed25519 signatures with a `parent_auth_hash` binding — but the attenuation discipline is shared.

OxDeAI differs in its determinism requirement and its binding to computational context. Macaroons and biscuits express authorization logic that may be evaluated against a request, but they do not require that the authorization decision be a deterministic, reproducible function of a canonical intent and state. OxDeAI's conformance methodology (Section 10) is, to our knowledge, a more stringent cross-implementation reproducibility discipline than these systems specify, in that it requires byte-equivalent canonical serialization verified across independent implementations.

### 4.4 Governance for autonomous and agentic systems

The recent growth of AI agents — systems that use language models to plan and invoke tools — has produced a body of work on agent safety, guardrails, and governance. Much of this work operates at the level of model behavior: constraining what an agent proposes through prompt design, fine-tuning, or output classification. Tool-use frameworks [various agent SDKs] provide mechanisms for registering and invoking tools but generally treat authorization as a configuration concern (which tools an agent may call) rather than a per-action deterministic decision.

A subset of this work addresses execution-time enforcement specifically: intercepting agent actions before they execute and applying policy. Commercial and open-source systems provide such enforcement, often combined with model-based risk scoring. These systems are closest in purpose to OxDeAI, and OxDeAI's external integration with one such system (Section 11) demonstrates the composition: an external governance layer makes a risk-informed decision; OxDeAI provides the deterministic, verifiable enforcement boundary that translates that decision into a fail-closed execution gate.

OxDeAI's distinctive stance in this space is its insistence on determinism and verifiability. Model-based risk scoring is probabilistic by nature; OxDeAI does not score risk, it enforces a deterministic decision. The two are complementary: a risk scorer can inform the policy engine's decision, but the enforcement boundary itself must be deterministic so that its behavior is reproducible and auditable. A flagged anomaly is not a refused action; OxDeAI provides the refused action.

### 4.5 Execution-time authorization as a category

Recent work has begun to formalize execution-time authorization as a distinct architectural category rather than an implementation detail of specific systems. Meyman [Meyman 2026] presents a formal framework defining execution-time authorization (ETA) through six invariants: determinism, fail-closed enforcement, non-bypassability, decision artifact completeness, replayability, and time-bounded evaluation without fail-open. The framework characterizes the class of systems that enforce pre-execution authorization at the boundary between an autonomous system's decision-making and its actuation of side effects, and identifies these six invariants as the defining requirements for membership in the category.

OxDeAI's architecture was developed independently of this framework and predates its February 2026 publication. The two efforts converge: OxDeAI's design satisfies all six ETA invariants, not because it was built to the framework's specification, but because the underlying problem — deterministic, verifiable, fail-closed authorization at the execution boundary — constrains the solution space toward similar architectural choices. We discuss this convergence in detail in Section 14, including an invariant-by-invariant mapping and an account of why independent convergence is a stronger validation signal than framework-driven implementation would be.

We adopt the ETA framework's vocabulary (the invariant labels) as shared terminology for describing the category, while developing OxDeAI's design in OxDeAI's own terms. We do not claim conformance to the framework in any formal sense — no formal conformance process exists — and we do not adopt implementation-specific names from any particular ETA system. The framework provides a category vocabulary; OxDeAI provides a concrete protocol within that category.

### 4.6 Summary of positioning

OxDeAI occupies a position defined by the intersection of four commitments, each shared with some prior work but not jointly realized by the systems surveyed above:

From capability security, the commitment that authority is explicit, unforgeable, and narrowable. From identity-centric frameworks, the commitment to offline-verifiable signed artifacts. From distributed authorization tokens, the commitment to delegation that can only attenuate. From agent governance, the commitment to enforcement at the execution boundary before side effects occur.

What OxDeAI adds is the conjunction of these commitments with two further requirements: that the authorization decision be a deterministic function of intent, state, and policy, reproducible across independent implementations; and that the protocol's behavior be specified by a conformance suite stringent enough to detect cross-implementation divergence. The next section describes the architecture that realizes these commitments.

---

## 5. Protocol Architecture

This section describes OxDeAI's architecture at the level of decision flow and enforcement boundary. It establishes the structural separation between authorization production and authorization enforcement, the role of the decision artifact as the only authorized bridge between them, and the trust boundary that determines which authorizations a verifier accepts. The artifact specifications that follow (Sections 6–9) fill in the detail; this section establishes the shape.

### 5.1 The production–enforcement separation

OxDeAI's central architectural commitment is that the component which *decides* whether an action is authorized is structurally separate from the component which *enforces* that decision at the execution boundary. We call these the policy engine (the producer) and the policy enforcement point or PEP (the enforcer). The decision artifact — `AuthorizationV1` — is the only authorized channel between them.

This separation is not merely an implementation convenience. It is the property that makes the protocol's other guarantees possible:

*It makes the decision verifiable.* Because the decision is captured in a signed artifact rather than communicated through a function call or shared memory, any party with the issuer's public key can verify that the decision was made by the designated engine. The PEP does not trust the producer because they share a process; it trusts the producer because the artifact carries a signature from a key in the PEP's trust configuration.

*It makes the decision portable.* The artifact can cross process boundaries, network boundaries, and time. A decision made by an engine in one process can be enforced by a PEP in another process, or verified by an auditor weeks later, without either needing access to the engine's internal state.

*It makes the decision reproducible.* Because the artifact is self-contained — it carries the intent binding, the state binding, the policy identity, and the validity window — an independent verifier can reproduce the verification verdict from the artifact alone (G5). The verifier does not re-run the engine's decision logic; it checks that the artifact the engine produced is valid, properly bound, and unexpired.

The separation also clarifies what each component is and is not responsible for. The policy engine is responsible for the *correctness* of the decision — whether the action should be authorized under the policy. The PEP is responsible for the *enforcement* of the decision — that no execution occurs without a valid authorization. The protocol verifies the second responsibility cryptographically; it does not and cannot verify the first. An engine that makes a wrong decision but signs it correctly produces an artifact the PEP will accept. The protocol's guarantee is that the PEP enforces what the engine decided, not that the engine decided correctly.

### 5.2 The decision flow

The authorization flow proceeds through a fixed sequence. A proposing component — an AI agent, a workflow engine, an automation script, or any execution system — submits a proposed action to the policy engine. The proposed action is untrusted input; the engine evaluates it, it does not defer to it.

The engine evaluates the proposed action against the current policy state. This evaluation is deterministic: given the same intent, the same state, and the same policy configuration, the engine produces the same decision and the same derived hashes (G5). The evaluation considers the policy domains — budget, velocity, concurrency, recursion, replay, capability — as deterministic authorization invariants rather than as heuristics or scores.

The evaluation produces one of two outcomes. If the action is not authorized, the engine produces a DENY outcome and no authorization artifact is issued. The proposing component receives the denial; no execution path exists. If the action is authorized, the engine produces an `AuthorizationV1` artifact: a signed, scoped, state-bound, time-limited decision artifact bound to the specific proposed action.

The authorization artifact, if issued, is presented to the PEP. The PEP verifies the artifact through a sequential pipeline: signature validity against the trusted key sets, issuer match, audience match, expiry check, intent binding check, state binding check (in Profile C), and replay consumption. Any failure terminates the pipeline before the execution boundary is reached (G6). Only when every check passes does the PEP permit the execution to proceed.

Optionally, between the parent authorization and a sub-component, a `DelegationV1` artifact may narrow the parent's authority and bind it to a delegatee. The delegation cannot expand the parent's scope (G4); it can only restrict the tools, the budget ceiling, or the validity window. The PEP verifies the delegation chain alongside the authorization.

This flow is illustrated in Figure 1 (the Core Model diagram). The critical structural property is visible in the diagram: the path from proposed action to execution passes through the PEP, and the PEP is unreachable around. Execution is not a sibling of authorization that happens to follow it; execution is downstream of a verification gate that fails closed.

### 5.3 Non-bypassability as a structural property

The non-bypassability invariant (I3 in the ETA vocabulary; supporting G6) requires that the enforcement boundary cannot be circumvented by actors within the execution runtime. OxDeAI realizes this structurally rather than through runtime checks.

In the reference implementation, the PEP (`OxDeAIGuard`) is a higher-order function that wraps the execution function. The proposing component does not receive a reference to the execution function directly; it receives the guarded closure produced by `guard(action, execute)`. The only way to reach the execution function is through the guarded closure, and the guarded closure performs verification before forwarding. There is no escape hatch, no trusted-caller flag, no path that skips verification.

This is the object-capability discipline (§4.1) applied to the execution boundary: authority to execute is conveyed only by introduction (the guarded closure), and the proposing component cannot fabricate that authority. A component that does not hold the guarded closure cannot execute; a component that holds it can only execute through the verification it performs.

The limit of this claim is important and stated explicitly in the threat model (§3.5). Non-bypassability holds at the level of the language runtime in which the PEP operates. It does not extend to a fully compromised host process that can manipulate memory directly, to operating-system-level circumvention, or to hardware attacks. The protocol's non-bypassability is structural within its operating layer; it is not hardware-bound enforcement. Deployments requiring stronger isolation must compose OxDeAI with operating-system or hardware isolation mechanisms.

### 5.4 The trust boundary

A recurring source of confusion in authorization systems is the conflation of two distinct questions: is this artifact cryptographically valid, and is this artifact trusted? OxDeAI separates them explicitly, and this separation is one of the protocol's clearest design statements.

Any party that holds a signing key can produce a cryptographically valid `AuthorizationV1` artifact. The signature will verify against the corresponding public key. Cryptographic validity is a property of the artifact and the key, available to anyone with a key.

A cryptographically valid artifact is not trusted by default. Trust is determined by the verifier's configuration — specifically, by the `trustedKeySets` that the verifier has been explicitly configured with. An artifact is trusted only when its signing key is present in the verifier's `trustedKeySets` and absent from the current key revocation list. A valid signature from a key the verifier does not trust produces a verification failure (`AUTH_KID_UNKNOWN`), not acceptance.

This separation has a sharp operational consequence, enforced in strict mode: a verifier configured with no `trustedKeySets` does not accept all artifacts (the fail-open interpretation) and does not accept none silently. It produces an explicit hard failure, `TRUSTED_KEYSETS_REQUIRED`. The absence of a trust configuration is treated as a configuration error, not as a permissive default. This is the fail-closed principle (G6) applied to trust configuration itself.

The protocol also distinguishes policy identity from issuer authority. The `policy_id` field is a content hash of the policy configuration; it identifies which policy was applied but does not authenticate who applied it. A verifier must not treat a matching `policy_id` as evidence of issuer legitimacy. Two issuers using the same policy configuration produce the same `policy_id`; the distinguishing factor is the signing key, verified against `trustedKeySets`. Validity is cryptographic; trust is explicit; policy identity is neither.

This trust model is illustrated in Figure 2 (the Trust Boundary diagram). The diagram makes the two-input nature of the trust decision visible: the verifier accepts an artifact only when the signature is valid *and* the signing key is in `trustedKeySets` *and* the key is not in the current KRL. All three conditions are necessary; none alone is sufficient.

### 5.5 The role of state binding

The protocol binds each authorization to a specific snapshot of the policy state through the `state_hash` field. This binding is what distinguishes an OxDeAI authorization from a standing permission: the authorization is valid not in general, but against the specific state of the world that the engine evaluated.

The state binding operates differently across the interoperability profiles (Section 11). In all profiles, the `state_hash` is part of the signed artifact, so tampering with it invalidates the signature (G2). In Profile C, the PEP additionally re-computes the hash of the live state at enforcement time and compares it against the authorization's `state_hash`, refusing execution if they diverge. This live re-verification is what allows Profile C deployments to detect a state that has changed between authorization and enforcement.

The state binding is also the locus of one of the protocol's principal residual trust assumptions (RT-TRUST-1, §3.5, §3.8). The PEP can verify that the live state hashes to the same value committed in the authorization. It cannot verify that the live state was supplied by an honest, compliant state provider. A compromised provider that returns a manufactured state matching the committed hash passes the check. The protocol verifies hash consistency; it does not verify state-source honesty. The state-provider-requirements specification defines what compliant deployments must satisfy to mitigate this residual, but the mitigation is a deployment responsibility, not a protocol-layer guarantee.

We discuss the state binding mechanism in detail in Section 6 (within the `AuthorizationV1` specification) and the state provider trust boundary in Section 13 (Limitations). For the architecture, the salient point is that state binding is what makes the authorization a decision about a specific situation rather than a standing grant — and that the binding is verified at the hash level, not at the source-integrity level.

### 5.6 Composition and layering

OxDeAI is designed to compose with, not replace, the surrounding infrastructure. The architecture occupies a specific layer — the deterministic governance decision about whether a proposed action executes — and leaves adjacent concerns to adjacent systems.

Beneath OxDeAI, identity and resource-access systems (OAuth, IAM, network policy) authenticate principals and control resource access. OxDeAI does not authenticate the proposing component's identity; it assumes that identity authentication, where required, is handled by these systems. The proposing component's identity is, in fact, untrusted at the OxDeAI layer (§3.3): the protocol's guarantees hold regardless of who proposes the action.

Above OxDeAI, orchestration systems decide what happens after a decision. When the PEP produces a non-ALLOW outcome, the orchestration layer decides whether the action is terminally refused, escalated to a human, retried with narrowed parameters, or routed elsewhere. The protocol provides a reliable ALLOW/non-ALLOW signal; it does not prescribe the orchestration response. This is why the protocol uses a binary execution gate rather than a first-class ABSTAIN verdict: the decision authority belongs to the protocol layer, the workflow continuation belongs to the orchestration layer, and conflating them would create a path to execution through unresolved authorization (Section 14 discusses this design choice in relation to the ETA framework's treatment of escalation).

Alongside OxDeAI, external governance providers may make risk-informed or domain-specific decisions that feed into the authorization. The interoperability profiles (Section 11) define how an external provider's decision is translated into an `AuthorizationV1` while preserving the trust separation: the external provider's signing key is distinct from the OxDeAI signing key in `trustedKeySets`, and only an adapter signing with an OxDeAI-trusted key can produce an artifact the PEP accepts.

This layering is the architectural expression of the protocol's scope discipline. OxDeAI does one thing — deterministic, verifiable, fail-closed authorization at the execution boundary — and composes with systems that do the adjacent things. The next sections specify the artifacts that realize this architecture, beginning with the central decision artifact, `AuthorizationV1`.

---

## 6. AuthorizationV1: The Decision Artifact

`AuthorizationV1` is the central artifact of the protocol. It captures a single authorization decision in a self-contained, cryptographically signed form that an independent verifier can validate without access to the policy engine's internal state. Every other artifact in the protocol exists in relation to it: `DelegationV1` binds to a parent `AuthorizationV1`, `SignedKRLV1` governs the keys that sign it, and the PEP exists to verify it.

This section specifies the artifact's structure, its two wire encodings, the signing preimage, the binding fields that tie it to a specific computational context, and the expiry model. The complete field catalog, including optional and reserved fields, appears in Appendix A.

### 6.1 Purpose and design constraints

`AuthorizationV1` is designed to satisfy the decision-artifact-completeness requirement (I4 in the ETA vocabulary): the authorization decision must be captured in a verifiable artifact that carries the full decision context, such that a verifier can reproduce the verification without access to internal engine state.

This constraint produces several design decisions. The artifact must carry, in self-contained form, everything a verifier needs: the decision itself, the bindings that make it specific to one execution, the issuer and audience that scope its applicability, the validity window, and the cryptographic material (algorithm, key identifier, signature) required to verify it. The artifact must not depend on the verifier having access to the engine's internal representations — a verifier holding only the artifact, the proposing action, the live state (in Profile C), and the issuer's public key must be able to reach the same verdict the engine reached.

A second constraint is that the artifact's signed form must be reproducible byte-for-byte across implementations. Two conformant implementations serializing the same logical artifact must produce identical bytes, because the signature is computed over those bytes; any divergence in serialization produces signature verification failure. This constraint is satisfied by the canonical serialization (`canonicalization-v1`, Appendix B) and verified by the conformance suite (Section 10).

A third constraint, learned from the integration experience described in Section 11, is that the artifact must accommodate two wire encodings without ambiguity. External governance providers may produce artifacts in a wire form that differs from the core-native form in field naming and signature encoding. The protocol specifies both encodings precisely, with a defined precedence rule, so that an artifact in either encoding verifies deterministically.

### 6.2 Core fields

An `AuthorizationV1` artifact carries the following fields. We describe their semantics here; the exact types and serialization rules are in Appendix A.

The *decision* field carries the verdict. In the protocol's binary execution gate (§5.6), the value relevant to the execution path is `ALLOW`. An artifact carrying any other decision value, or an artifact that fails any verification check, produces non-execution. The protocol does not define an `ABSTAIN` decision at the artifact level; the rationale is discussed in Section 14.

The *identity fields* establish who issued the artifact and for whom it is intended. The `issuer` field identifies the issuing policy engine. The `audience` field identifies the intended verifier or enforcement context; a verifier checks that the audience matches its own configured identity, refusing artifacts intended for a different audience (`AUTH_AUDIENCE_MISMATCH`). Audience binding prevents an artifact issued for one enforcement context from being replayed against another.

The *binding fields* tie the artifact to a specific computational context and are the subject of §6.4. The `intent_hash` binds the artifact to a specific proposed action. The `state_hash` binds it to a specific policy state snapshot. The `policy_id` binds it to a specific policy configuration.

The *uniqueness field*, `auth_id`, is a unique single-use identifier. It is the basis of replay protection (G3): the PEP consumes the `auth_id` through the replay store, and a second presentation of the same `auth_id` is refused (`AUTH_REPLAY`). The `auth_id` must be unique per decision; the protocol does not prescribe its generation method beyond uniqueness, and implementations have bound it to server-side nonces where the issuing system provides them (Section 11).

The *temporal fields* establish the validity window. The `issued_at` field records when the artifact was issued; it is informational and is not enforced as a lower bound (§6.5). The `expiry` field (or its Encoding-B equivalent `expires_at`, §6.3) establishes the upper bound of validity, enforced with strict zero-tolerance semantics (§6.5).

The *cryptographic fields* carry the verification material. The `alg` field specifies the signature algorithm. The `kid` field identifies the signing key, used by the verifier to resolve the correct public key from `trustedKeySets`. The `signature` field carries the Ed25519 signature over the signing preimage (§6.4).

Optional fields, including `nonce` and `capability`, are described in Appendix A. The `nonce` field exists in the type but, in the current protocol version, replay protection is enforced through `auth_id` rather than through a separately verified nonce; this is noted as a partial element in the protocol audit.

### 6.3 Two wire encodings

The protocol defines two wire encodings of `AuthorizationV1`. Both encode the same logical artifact; they differ in field naming and in signature encoding. The distinction arose from integration with an external governance provider whose wire format predated the core-native form, and the protocol accommodates both rather than forcing one party to re-sign.

*Encoding A (core-native).* Algorithm identifier is the literal string `Ed25519`. The temporal upper bound field is named `expiry`. The signature is base64-encoded. The signing preimage is domain-prefixed (§6.4).

*Encoding B (external-provider-compatible).* Algorithm identifier is the literal string `ed25519` (lowercase). The temporal upper bound field is named `expires_at`. The signature and public keys are base64url-encoded without padding. Public keys are raw 32-byte Ed25519 keys without DER, PEM, or JWK wrapping. The signing preimage is not domain-prefixed (§6.4).

The algorithm identifiers are matched case-exactly. An artifact declaring `EdDSA` or `ED25519` is rejected (`AUTH_ALG_UNSUPPORTED`); the conformance suite includes vectors that enforce this case-exact rejection. This strictness is deliberate: permitting case-insensitive algorithm matching would expand the set of accepted artifacts in a way that conformant implementations might handle divergently, violating G5.

When an artifact carries both `expiry` and `expires_at`, `expiry` takes precedence. The conformance suite includes a vector (`auth-expiry-wins-over-expires-at`) that locks this precedence: an artifact with an expired `expiry` and a valid `expires_at` must be rejected as expired. An implementation that incorrectly preferred `expires_at` would accept the artifact and fail the vector. This precedence rule eliminates an ambiguity that would otherwise allow two implementations to disagree about an artifact carrying both fields.

### 6.4 The signing preimage and binding semantics

The signature covers a canonical serialization of the artifact's signed fields. The exact preimage construction differs between the two encodings, and specifying it precisely is essential: the signature verifies only if the verifier reconstructs the identical preimage bytes.

In Encoding A, the preimage is domain-prefixed. The signed bytes are the concatenation of a domain-separation prefix (`OXDEAI_AUTH_V1\n`) and the canonical JSON serialization of the signed fields. The domain prefix binds the signature to the artifact type, preventing a signature produced for one artifact type from verifying against another (cross-artifact signature confusion). The protocol uses distinct domain prefixes for each signed artifact type: `OXDEAI_AUTH_V1\n` for `AuthorizationV1`, `OXDEAI_DELEGATION_V1\n` for `DelegationV1`, and `OXDEAI_KRL_V1\n` for `SignedKRLV1`.

In Encoding B, the preimage is not domain-prefixed. The signed bytes are the canonical JSON serialization of the signing payload directly. This reflects the external provider's pre-existing signing convention. The absence of a domain prefix is accommodated rather than required; an Encoding-B artifact is verified against its own preimage construction.

The canonical serialization in both cases follows `canonicalization-v1` (Appendix B): UTF-8 byte-order key sorting, NFC Unicode normalization, safe-integer-only numeric encoding with floats rejected, duplicate key rejection, and unsupported-type rejection. The determinism of this serialization is what allows independent implementations to reconstruct identical preimage bytes.

The binding fields establish the artifact's specificity. The `intent_hash` is the canonical hash of the proposed action: `intent_hash = SHA-256(canonicalize(proposed_action))`. A verifier in possession of the proposed action recomputes this hash and compares it against the artifact's `intent_hash`, refusing execution on mismatch. This binds the authorization to the exact action that was proposed; an authorization issued for one action cannot authorize a different action, because the recomputed `intent_hash` would diverge.

The `state_hash` is the canonical hash of the policy state snapshot the engine evaluated. Its enforcement depends on the profile (Section 11): in all profiles the `state_hash` is signed and thus tamper-evident; in Profile C the PEP additionally recomputes the hash of the live state and compares it, detecting state divergence between authorization and enforcement. The state binding and its residual trust assumption are discussed in §5.5 and Section 13.

The `policy_id` is a content hash of the policy configuration. It identifies which policy produced the decision but, as emphasized in §5.4, does not authenticate the issuer. A verifier checks `policy_id` against its expected policy where applicable, but never treats a matching `policy_id` as evidence of issuer legitimacy.

A note on the public-artifact boundary. The artifact a verifier sees — the "public" `AuthorizationV1` — is a projection that excludes engine-internal fields. The reference implementation defines a projection (`toPublicAuthorizationV1`) that strips internal fields (such as engine-internal identifiers and legacy signing artifacts) before any signing or hashing surface. This ensures that the signed preimage, and the `parent_auth_hash` that `DelegationV1` computes over a parent authorization (Section 7), depend only on the normative public fields. An independent implementation can reproduce the signing preimage and the parent hash from the normative fields alone, without access to engine internals. This boundary was a specific hardening step in the protocol's development, ensuring decision-artifact completeness (I4) holds against implementations that do not share the reference engine's internal representations.

### 6.5 The expiry model

`AuthorizationV1` uses a strict zero-tolerance expiry model. An artifact is valid with respect to time if and only if the verifier's observed time is strictly less than the artifact's `expiry`. There is no grace period, no configurable skew tolerance, and no fallback path when the observed time reaches or exceeds `expiry`.

This strictness is a deliberate design choice with a specific rationale. A configurable grace period would introduce a parameter on which two conformant implementations could be configured differently, producing divergent verdicts for the same artifact at the same time — a violation of G5. By fixing the rule at strict inequality, the protocol ensures that the only input to the expiry decision is the artifact's `expiry` and the verifier's observed time, both of which are unambiguous.

The model places a corresponding obligation on issuers and on deployment. Because there is no grace period, issuers must build delivery and processing latency into the `expiry` window when issuing — an artifact that must traverse a network and be processed before enforcement should carry an `expiry` far enough in the future to accommodate that latency. And because the verifier's observed time is the reference, deployments must synchronize clocks (NTP or equivalent); significant clock skew can cause valid artifacts to be rejected or, in the case of a verifier clock behind real time, expired artifacts to be accepted within the skew window. These deployment obligations are stated in the threat model (§3.7).

The `issued_at` field is informational and is not enforced as a lower bound. The verifier does not check that its observed time is at or after `issued_at`. This is a deliberate choice: enforcing a lower bound would create undefined behavior under clock skew, where an artifact issued moments ago by an issuer whose clock is slightly ahead would carry a future `issued_at` and be rejected by a verifier whose clock is behind. By treating `issued_at` as an audit timestamp rather than an activation gate, the protocol avoids this failure mode. The conformance suite includes a vector (`clock-003`) verifying that a verifier whose clock is behind the artifact's `issued_at` still accepts the artifact, confirming that `issued_at` is not enforced as a lower bound.

The expiry model is exercised by the `clock-semantics` conformance vectors (`clock-001` through `clock-005`), which cover the last-valid-second case (observed time equal to `expiry` minus one, accepted), the one-past-expiry case (observed time equal to `expiry` plus one, rejected as expired), the verifier-clock-behind case, and Encoding-B variants of the same boundary conditions. These vectors are validated across the TypeScript, Go, and Python implementations, establishing that the expiry semantics are reproduced identically across implementations.

### 6.6 What a verifier checks

To summarize the verification of an `AuthorizationV1` artifact, a conformant verifier performs the following checks. Any failure terminates verification and produces non-execution (G6). The checks are described here at the level of semantics; the PEP's sequential pipeline that performs them in order is specified in Section 8, and the stateless verification surface that exposes them is specified in Section 9.

The verifier confirms that the signature is cryptographically valid over the reconstructed preimage, using the public key resolved from `trustedKeySets` by the artifact's `kid`. It confirms that the resolving key is present in `trustedKeySets` and absent from the current key revocation list. It confirms that the algorithm identifier matches the expected literal case-exactly. It confirms that the `issuer` and `audience` match the verifier's configuration. It confirms that the observed time is strictly less than `expiry` (applying the precedence rule if both `expiry` and `expires_at` are present). It confirms that the recomputed `intent_hash` matches the artifact's `intent_hash`. In Profile C, it confirms that the recomputed hash of the live state matches the artifact's `state_hash`. It consumes the `auth_id` through the replay store, confirming the artifact has not been presented before. In strict mode, it confirms that `trustedKeySets` is configured at all, failing with `TRUSTED_KEYSETS_REQUIRED` if not.

Only when every check passes is the artifact accepted and the execution path reachable. The artifact specification that follows for `DelegationV1` (Section 7) builds on this verification, adding the chain-binding and scope-narrowing checks that govern delegated authority.

---

## 7. DelegationV1: Scoped Delegation

`DelegationV1` extends the protocol to the case where an authorized principal delegates a narrowed portion of its authority to a sub-component. A parent holds an `AuthorizationV1`; it issues a `DelegationV1` that grants a delegatee the right to act, but only within a scope that is a strict subset of the parent's. The delegation cannot expand the parent's authority; it can only restrict it. This is the protocol's realization of the delegation-non-expansion goal (G4).

This section specifies the artifact's structure, the parent-binding mechanism, the scope-narrowing rules, the single-hop constraint, and the verification the PEP performs. The complete field catalog appears in Appendix A.

### 7.1 Purpose and the delegation problem

Execution systems frequently decompose work across multiple components. A primary agent may delegate a subtask to a sub-agent; an orchestrator may dispatch a bounded operation to a worker; a workflow may hand a constrained capability to a downstream stage. In each case, the delegating party holds some authority and wishes to convey a portion of it to the delegatee, without conveying all of it.

The security requirement in these cases is precise: the delegatee must not be able to do anything the delegator could not. If the delegator is authorized to spend up to a budget ceiling, call a specific set of tools, and act until a specific expiry, the delegatee's authority must be bounded by those same limits or tighter. A delegation that allowed the delegatee to exceed the delegator's budget, call tools the delegator could not, or act beyond the delegator's expiry would be an authority *expansion*, and expansion is precisely the failure the protocol must prevent.

This is the attenuation discipline shared with capability systems and macaroons (§4.1, §4.3): delegated authority may only narrow. `DelegationV1` enforces it cryptographically and structurally, so that a non-conforming delegation is rejected at verification rather than relied upon to be well-formed by convention.

### 7.2 Structure and parent binding

A `DelegationV1` artifact carries, in addition to its own identity and cryptographic fields, a binding to the specific parent authorization it derives from and a scope that defines the narrowed authority.

The parent binding is the field `parent_auth_hash`. It is the canonical hash of the public projection of the parent `AuthorizationV1`:

`parent_auth_hash = SHA-256(canonicalize(toPublicAuthorizationV1(parent)))`

This binds the delegation cryptographically to one specific parent authorization. The hash is computed over the *public* projection of the parent (§6.4) — the normative fields only, with engine-internal fields stripped — so that any conforming implementation can reproduce the parent hash from the parent artifact's normative fields alone, without access to engine internals. An independent verifier holding the parent `AuthorizationV1` and the `DelegationV1` can recompute `parent_auth_hash` and confirm the binding. A delegation whose `parent_auth_hash` does not match the presented parent is rejected.

The parent binding has a specific consequence: a delegation is meaningful only in relation to its parent. A `DelegationV1` artifact cannot stand alone as an authorization; it must be presented together with the parent `AuthorizationV1` it binds to, and the parent must itself be valid. If the parent authorization is invalid — expired, revoked, signature-failed — the delegation derived from it confers no authority, because the delegation's validity is contingent on the parent's.

The delegation carries its own signature, over a domain-prefixed preimage (`OXDEAI_DELEGATION_V1\n`, §6.4), distinct from the authorization domain prefix. This domain separation prevents an `AuthorizationV1` signature from being reinterpreted as a `DelegationV1` signature or vice versa. The signing key for the delegation is resolved against `trustedKeySets` in the same way as for authorizations.

### 7.3 Scope narrowing

The delegation's `scope` defines the narrowed authority. The protocol enforces narrowing on the scope dimensions it defines: the tool allowlist, the budget ceiling (maximum amount), the action count, and the expiry. For each dimension, the delegation's value must be equal to or more restrictive than the parent's.

For the tool allowlist, the delegation's permitted tools must be a subset of the parent's permitted tools. A delegation that lists a tool the parent does not permit is a scope violation. For the budget ceiling, the delegation's maximum amount must not exceed the parent's. For the action count, the delegation's maximum must not exceed the parent's. For the expiry, the delegation's expiry must not extend beyond the parent's; a delegatee cannot act after the parent's own authority has lapsed.

Any violation of these narrowing rules — a tool not in the parent's set, a higher budget ceiling, a larger action count, a later expiry — produces `DELEGATION_SCOPE_VIOLATION` at verification, and the delegation confers no authority. The verifier checks each dimension; a delegation that narrows some dimensions but expands another is rejected on the expanded dimension.

The scope is validated structurally before the delegation chain is verified. The reference implementation requires the parent scope to be supplied as an explicit, typed field (`parentScope`) on the delegation input, structurally validated before chain verification proceeds. An earlier design that inferred the parent scope through an unsafe cast was removed during the protocol's hardening (audit item P0-3); the explicit typed field ensures that a missing or malformed parent scope fails closed before the chain verification path is reached, rather than being silently coerced. This is the fail-closed principle (G6) applied to the delegation input itself: ambiguity in the parent scope produces rejection, not a permissive default.

### 7.4 The single-hop constraint

`DelegationV1` in the current protocol version supports single-hop delegation only. A parent authorization may delegate to a delegatee; the delegatee may not further delegate to a third party using the same mechanism. A delegation chain deeper than one hop is rejected with `DELEGATION_SINGLE_HOP`.

This is a deliberate restriction for the current version, not an oversight. Multi-hop delegation introduces complexity in the scope-narrowing verification — each hop must narrow relative to the previous, the chain must be verified end-to-end, and the failure modes multiply — and the protocol's conservative posture is to specify and verify the single-hop case fully before extending to multi-hop. The protocol audit records multi-hop delegation as specified-but-not-yet-tested-with-chains-deeper-than-two, and Section 15 (Future Work) identifies multi-hop delegation as a candidate for a future protocol version once the single-hop case has accumulated deployment experience.

The single-hop constraint bounds the delegation model to a case that is fully verifiable with the current conformance vectors. A deployment requiring deeper delegation chains in the current version must compose multiple single-hop delegations through application logic, accepting that each hop is independently verified against its immediate parent rather than relying on the protocol to verify a multi-hop chain in one operation.

### 7.5 Verification

The PEP verifies a `DelegationV1` alongside the parent `AuthorizationV1`. The verification extends the authorization verification of §6.6 with the delegation-specific checks.

The verifier first confirms that the parent `AuthorizationV1` is itself valid, applying the full authorization verification: signature, issuer, audience, expiry, intent binding, and (in Profile C) state binding. A delegation derived from an invalid parent confers no authority.

The verifier then confirms the parent binding: it recomputes `parent_auth_hash` over the public projection of the presented parent and confirms it matches the delegation's `parent_auth_hash`. A mismatch indicates the delegation was issued against a different parent than the one presented, and the delegation is rejected.

The verifier confirms the delegation's own signature over its domain-prefixed preimage, resolving the signing key against `trustedKeySets` and confirming the key is not revoked.

The verifier confirms scope narrowing: each scope dimension (tools, budget ceiling, action count, expiry) is checked to be equal to or more restrictive than the parent's, with any expansion producing `DELEGATION_SCOPE_VIOLATION`.

The verifier confirms the single-hop constraint: a chain deeper than one hop produces `DELEGATION_SINGLE_HOP`.

The verifier consumes the delegation's replay identifier through the replay store, in the same manner as the authorization's `auth_id`, so that a delegation cannot be replayed for multiple executions. The reference implementation consumes both the parent authorization's `auth_id` and the delegation's identifier, ensuring that neither the parent nor the delegation can be independently replayed.

Only when every check — parent validity, parent binding, delegation signature, scope narrowing, single-hop, and replay consumption — passes is the delegated execution permitted. The delegation verification is exercised by the delegation conformance vectors and the cross-adapter delegation guard tests, which confirm that scope violations, expired parents, broken parent bindings, and over-deep chains are all rejected.

### 7.6 Relationship to the capability model

`DelegationV1` is the protocol's expression of the object-capability principle (§4.1) at the delegation layer. The parent authorization is a capability; the delegation is an attenuated capability derived from it by introduction. The delegatee receives authority only through the delegation, which it could not have fabricated, and that authority is strictly bounded by the parent's.

The difference from a classical capability, as with `AuthorizationV1` itself (§4.1), is the binding to computational context. A classical attenuated capability narrows a standing right. A `DelegationV1` narrows an authorization that was itself bound to a specific intent, state, and policy. The delegated authority is therefore doubly specific: it is bounded both by the narrowing scope of the delegation and by the context-binding of the parent authorization it derives from. A delegatee acting under a `DelegationV1` is authorized for a narrowed scope, against the specific state the parent was evaluated against, within the parent's validity window — a tighter envelope than either a standing capability or an unbound delegation would provide.

With the two decision artifacts specified — `AuthorizationV1` in Section 6 and `DelegationV1` here — the next section describes the enforcement architecture that verifies them: the policy enforcement point, `OxDeAIGuard`, and the sequential verification pipeline that realizes the fail-closed boundary.

---

## 8. The Policy Enforcement Point: OxDeAIGuard

The policy enforcement point (PEP) is the component that verifies authorization artifacts and gates execution. It is where the protocol's guarantees become operational: the artifacts specified in Sections 6 and 7 are inert data until a PEP verifies them and either permits or refuses execution. This section specifies the PEP architecture as realized in the reference implementation, `OxDeAIGuard` — its structural placement, its sequential verification pipeline, the state-commit interaction, and the fail-closed properties that the pipeline guarantees.

The PEP is described here at the level of architecture and behavior. The exact API surface is documented in the reference implementation; the conformance vectors that verify the PEP's behavior are catalogued in Appendix C. The goal of this section is to specify the PEP precisely enough that an independent implementation in another language would produce a PEP with identical observable behavior.

### 8.1 Structural placement

The PEP realizes the non-bypassability invariant (§5.3) structurally rather than through runtime permission checks. The mechanism is the higher-order-function discipline: the PEP wraps the execution function and exposes only the wrapped form to the proposing component.

In the reference implementation, the guard is constructed around an execution function and returns a guarded closure:

```
const guarded = guard(action, execute);
// The proposing component holds `guarded`, never `execute` directly.
// Reaching `execute` is possible only through `guarded`,
// which performs verification before forwarding.
```

The proposing component receives `guarded`. It does not receive `execute`. The only path to `execute` is through `guarded`, and `guarded` performs the full verification pipeline before forwarding to `execute`. There is no parameter, flag, or alternate entry point that reaches `execute` while skipping verification. This is the structural expression of "execution is unreachable unless authorization is verified."

This placement is an architectural constraint that the deployment must honor. The protocol provides the guarded closure; it cannot force the deployment to actually route execution through it. A deployment that constructs the guard but then also retains and uses a direct reference to `execute` has bypassed the PEP at the architecture level, outside anything the protocol can detect (§3.5, §3.7). The protocol's non-bypassability guarantee holds for execution that goes through the guard; it is the deployment's responsibility to ensure that all execution does.

The guard validates its own configuration at construction. A guard constructed without the required configuration — in strict mode, without `trustedKeySets`; in a state-verifying profile, without a `computeStateHash` or state-access configuration — fails at construction rather than at first use. This moves configuration errors to the earliest possible point, so that a misconfigured guard cannot be constructed and then silently admit executions.

### 8.2 The sequential verification pipeline

When the guarded closure is invoked with a proposed action and the accompanying authorization artifact, the PEP executes a sequential verification pipeline. Each step is a check that can fail; any failure throws before the execution boundary is reached, and no subsequent step or the execution itself runs. The pipeline is fail-closed in the strict sense: there is no step whose failure produces a degraded-but-permitted outcome (G6).

The pipeline proceeds in the following order. The ordering is part of the specification, because some checks depend on earlier ones having passed, and because the order determines which error is reported when multiple conditions would fail.

First, the engine decision is checked. If the decision is not ALLOW, the pipeline throws (`OxDeAIDenyError`) before any further processing. A non-ALLOW decision is the engine's refusal, and the PEP enforces it immediately.

Second, the presence and structural validity of the authorization artifact are checked. An ALLOW decision without an accompanying valid authorization artifact, or with an artifact missing required fields, throws (`OxDeAIAuthorizationError`). The PEP does not proceed on a decision that lacks the artifact that proves it.

Third, in a delegation case, the delegation scope is checked. The guard validates the delegation's scope against the parent scope (§7.3) before chain verification, with a missing or malformed parent scope failing closed.

Fourth, the signature is verified. The artifact's signature is checked against the public key resolved from `trustedKeySets` by the artifact's `kid`, over the reconstructed preimage (§6.4). In strict mode, an absent `trustedKeySets` produces `TRUSTED_KEYSETS_REQUIRED` here. A key not present in `trustedKeySets` produces `AUTH_KID_UNKNOWN`; a key present but revoked produces a key-inactive failure; a signature that does not verify produces `AUTH_SIGNATURE_INVALID`; an algorithm identifier not matching case-exactly produces `AUTH_ALG_UNSUPPORTED`.

Fifth, the issuer and audience bindings are checked. An issuer not matching the verifier's expectation produces `AUTH_ISSUER_MISMATCH`; an audience not matching produces `AUTH_AUDIENCE_MISMATCH`.

Sixth, the policy binding is checked where a policy identity is expected, confirming the artifact's `policy_id` matches the expected policy.

Seventh, the expiry is checked. Applying the strict zero-tolerance model and the `expiry`/`expires_at` precedence rule (§6.5), an artifact whose effective expiry is at or before the verifier's observed time produces `AUTH_EXPIRED`.

Eighth, the intent binding is checked. The PEP recomputes `intent_hash` over the canonical serialization of the proposed action and compares it against the artifact's `intent_hash`. A mismatch indicates the artifact authorizes a different action than the one being executed, and the pipeline throws.

Ninth, in Profile C, the state binding is checked. The PEP obtains the live state through the configured state access, computes its hash via the configured `computeStateHash`, and compares it against the artifact's `state_hash`. A mismatch produces a state-binding failure; if `computeStateHash` itself throws, the guard catches the exception and throws, failing closed. A mismatch between the strategy the engine used and the strategy the PEP uses produces a deterministic failure rather than a silent divergence.

Tenth, the replay check is performed. The PEP consumes the artifact's `auth_id` (and, in a delegation case, the delegation's replay identifier) through the `ReplayStore`. A second presentation of an already-consumed identifier produces `AUTH_REPLAY`. If the replay store is unavailable, the guard catches the store exception and throws, failing closed (§8.4).

Only after every check has passed does the pipeline reach the state-commit and execution steps (§8.3). The complete set of failure modes is verified by the Guard PEP Conformance vectors (GPC series, Appendix C), which confirm that each failure condition blocks the execution boundary, the state commit, and any pre-execution hook.

### 8.3 State commit and execution

When all verification steps pass, the PEP proceeds to commit the next state and then permit execution. The ordering of these two operations is significant.

In a state-managing deployment, the engine's decision is accompanied by a next state — the state that results from the authorized action being accounted for (budget decremented, velocity counter advanced, concurrency slot consumed). The PEP commits this next state through a compare-and-set (CAS) operation before execution proceeds. The CAS operation confirms that the state has not been modified by a concurrent operation since the authorization was evaluated; if the version expected by the commit does not match the current version, the commit fails and the PEP throws (`OxDeAIConflictError`), refusing execution.

The state commit occurring before execution is a deliberate ordering. It ensures that the accounting for an action is durably recorded before the action's side effects occur, so that a concurrent action cannot be authorized against stale state in the window between this action's authorization and its execution. The CAS semantics make the commit atomic with respect to concurrent commits: two actions racing to consume the same budget or the same concurrency slot cannot both succeed, because the second CAS will observe the version advanced by the first and fail.

An optional pre-execution hook may run after all checks pass and after the state commit, immediately before execution. This hook is a deployment extension point; it runs only when execution is about to proceed, never on a refused action. An optional decision hook may run to record the decision for audit; exceptions from this audit hook are isolated so that an audit-logging failure does not itself block an otherwise-authorized execution, though the decision has already been verified and committed at that point.

Execution proceeds only after the state commit succeeds. If execution itself fails — the underlying operation errors — that failure is the execution's, not the PEP's; the PEP's responsibility ends at admitting the verified, committed action to execution. The accounting has been committed; a deployment requiring compensation for failed-but-authorized actions handles that at the application layer, as the protocol governs admission rather than execution outcome.

### 8.4 Fail-closed properties

The PEP's fail-closed behavior rests on a set of properties that the pipeline structure guarantees. We state them explicitly because fail-closed enforcement (G6) is the property most easily eroded by well-intentioned error handling that converts a failure into a degraded success.

Verification failures throw before the execution boundary. Every check in the pipeline (§8.2) that can fail does so by throwing, and the throw propagates out of the guarded closure before `execute` is reached. There is no catch within the pipeline that converts a verification failure into a permitted execution.

Configuration errors throw rather than defaulting permissively. The absence of `trustedKeySets` in strict mode produces `TRUSTED_KEYSETS_REQUIRED` rather than disabling signature verification. The absence of required state configuration in a state-verifying profile fails at construction. Misconfiguration produces refusal, not silent permission.

Replay store unavailability throws. The `ReplayStore` contract specifies that store exceptions must propagate as verification failures. The guard catches store exceptions and throws `OxDeAIAuthorizationError` rather than proceeding without replay protection. A PEP that cannot confirm an artifact has not been replayed refuses the artifact.

State-hash computation failure throws. If the configured `computeStateHash` throws — because the state is malformed, the strategy is misconfigured, or any other reason — the guard catches the exception and throws rather than proceeding without state verification.

Clock unavailability is precluded by explicit time injection. In strict mode, the verifier requires the observed time to be passed explicitly (`opts.now`) rather than read implicitly from the system clock. This removes an implicit entropy source and ensures that expiry evaluation is deterministic and testable; it also means a deployment cannot accidentally evaluate expiry against an unintended clock.

These properties are not assumed; they are verified. The GPC conformance vectors exercise each failure mode — kill-switch denial, invalid signature, audience mismatch, expiry, state-hash mismatch, replay, CAS conflict, missing artifact, missing required fields — and confirm in each case that the execution boundary, the state commit, and the pre-execution hook are all blocked. The property tests further confirm, across arbitrary proposed-action inputs, that a non-ALLOW decision always prevents both execution and state commit, and that a successful ALLOW always commits state before execution.

### 8.5 The PEP as the operational locus of the protocol

The PEP is where the protocol's separation of concerns (§5.1) is enforced. The policy engine produces decisions; the PEP enforces them; the artifacts carry the decisions between them. The PEP does not re-make the engine's decision — it does not re-evaluate the policy — it verifies that the artifact the engine produced is valid, properly bound, unexpired, unreplayed, and (in Profile C) consistent with the live state, and then it admits or refuses execution accordingly.

This division is what allows the PEP to be simple, auditable, and uniform across deployments. The PEP's logic is the verification pipeline and the fail-closed guarantees; it does not contain policy-specific reasoning, which lives in the engine. A reviewer auditing the PEP audits a fixed verification pipeline, not a deployment-specific policy. The policy varies; the enforcement is uniform. This uniformity is what makes the PEP's behavior specifiable by conformance vectors that hold across all deployments regardless of their policies.

The next section specifies the verification model that the PEP relies on and that is also exposed independently of the PEP — the stateless verification surface that allows artifacts to be verified offline, after the fact, by any party holding the public keys, without access to the running system.

---

## 9. The Verification Model

The PEP described in Section 8 performs verification inline, at the execution boundary, as part of admitting or refusing an action. But the protocol's verification logic is also exposed as a set of stateless primitives that can be invoked independently of the PEP — offline, after the fact, by any party holding the relevant public keys, without access to the running system. This section specifies that stateless verification surface, the result model it returns, and the offline-verifiability property that it establishes.

The distinction between inline enforcement and offline verification is central to the protocol's audit posture. The PEP verifies in order to gate execution. The stateless verifiers verify in order to establish, after the fact, that a decision was valid — for an auditor reconstructing what happened, for a relying party confirming an artifact before acting on it, or for an independent implementation confirming cross-implementation agreement (Section 10). The same verification logic serves both, but the stateless surface makes the logic available outside the execution path.

### 9.1 Stateless verification primitives

The protocol exposes a set of verification primitives, each a pure function of its inputs and the verifier configuration, with no dependence on running-system state beyond what is passed in. The reference implementation names them as follows; an independent implementation would expose equivalent functions.

`verifyAuthorization` verifies an `AuthorizationV1` artifact: signature validity against the resolved key, algorithm match, issuer and audience binding, expiry, and (given the proposed action) intent binding. It does not, by itself, consume the `auth_id` against a replay store — replay consumption is a stateful operation belonging to the PEP, not the stateless verifier. The stateless verifier confirms the artifact's cryptographic and binding validity; the PEP adds the stateful replay consumption.

`verifyDelegationChain` verifies a `DelegationV1` against its parent `AuthorizationV1`: parent validity, parent binding (`parent_auth_hash` recomputation), delegation signature, scope narrowing, and the single-hop constraint (Section 7). Like `verifyAuthorization`, it performs the stateless checks; replay consumption is the PEP's stateful addition.

`verifySnapshot` verifies a canonical state snapshot: that it decodes correctly, that its format version is recognized, and that its policy binding matches the expected policy. This allows a party to confirm that a state snapshot is well-formed and bound to the expected policy without access to the engine that produced it.

`verifyAuditEvents` verifies a sequence of audit events: that the hash chain is intact (each event's hash correctly incorporates the previous), that the policy binding holds, and that timestamps are non-decreasing. It recomputes the audit head hash offline from the provided events, allowing an auditor to confirm that an audit trace has not been tampered with — that no event has been inserted, removed, or modified — without trusting the system that produced the trace.

`verifyEnvelope` verifies a `VerificationEnvelopeV1`, the portable artifact that combines a snapshot, a sequence of audit events, and the policy identity. It confirms the envelope's structural integrity and, in strict mode, returns a positive verdict only when the audit trace includes at least one state checkpoint anchoring the trace to a concrete state. This makes the envelope a self-contained, portable evidence artifact: a party holding the envelope and the issuer's public key can confirm the recorded sequence of governance events independently.

Each primitive is stateless in the precise sense that its output is determined entirely by its inputs and the verifier configuration. It reads no global state, consults no clock implicitly (time is passed explicitly where needed), and mutates nothing. This statelessness is what makes the verifiers reproducible: the same inputs produce the same verdict on any conformant implementation, at any time, in any process (G5).

### 9.2 The result model

Every verification primitive returns a result in a uniform schema, `VerificationResult`, carrying one of three status values: `ok`, `invalid`, or `inconclusive`. The trichotomy is deliberate and the distinction between the three is semantically significant.

`ok` means the verification succeeded: the artifact is valid, properly bound, and (where applicable) unexpired, against the provided configuration. An `ok` verdict is a positive statement that the checked properties hold.

`invalid` means the verification failed in a way that constitutes a definite negative: the signature did not verify, the artifact was expired, a binding did not match, the algorithm was unsupported, the scope was violated. An `invalid` verdict is a positive statement that a checked property does not hold. It is a determinate refusal, not an absence of information.

`inconclusive` means the verification could not reach a determinate verdict given the inputs provided. The canonical case is strict-mode verification of an audit trace or envelope that lacks the anchoring evidence (a state checkpoint) required to reach a positive verdict: the verifier cannot say `ok` because the anchor is absent, but it also cannot say `invalid` because nothing was found to be wrong — the evidence is simply insufficient. `inconclusive` is the verifier declining to overstate its knowledge.

This trichotomy matters for the protocol's fail-closed posture. A binary ok/invalid model would force `inconclusive` cases into one of the two definite verdicts, and either choice would be wrong: treating insufficient evidence as `ok` would be fail-open (asserting validity that was not established), while treating it as `invalid` would be inaccurate (asserting a defect that was not found). The third value lets the verifier report exactly what it knows — that it could not establish validity — and lets the relying party decide how to treat insufficient evidence. In an enforcement context, `inconclusive` is treated as non-`ok` and therefore as a refusal (fail-closed); in an audit context, `inconclusive` is a signal that the evidence provided is insufficient and more is needed.

The result also carries the specific reason for an `invalid` or `inconclusive` verdict, drawn from the protocol's error code taxonomy (Appendix D). Violations are reported in a deterministic order, so that an artifact with multiple defects produces the same reported reason across implementations rather than reporting whichever defect a given implementation happened to check first. This deterministic violation ordering is part of what makes the verification reproducible (G5): two implementations verifying the same defective artifact agree not only that it is `invalid` but on why.

### 9.3 Offline verifiability

The defining property of the stateless verification surface is offline verifiability: an artifact can be verified by a party with no access to the system that produced it, no network connection to the issuer, and no shared state with the policy engine — holding only the artifact, the relevant public keys, and (where the verification requires it) the proposed action or live state.

This property establishes the replayability invariant (I5). A governance decision captured in an `AuthorizationV1` is reproducible from committed evidence: a verifier operating only from the public artifact and the issuer's public key arrives at the same verdict the PEP arrived at when it admitted the action. The verification does not re-run the policy engine's decision logic — it does not re-evaluate the policy — it confirms that the artifact the engine produced is valid. This is a weaker and more precise claim than "the auditor can reproduce the decision": the auditor reproduces the *verification* of the decision, confirming that the recorded decision was validly issued, bound, and unexpired.

Offline verifiability has concrete consequences for the protocol's audit posture. An auditor reviewing a system weeks after the fact, holding the archived artifacts and the issuer's public keys, can confirm: that each recorded authorization was validly signed by a trusted key; that each was bound to the specific action it authorized (given the recorded action); that each was unexpired at issuance; that the audit trace's hash chain is intact and no events were inserted, removed, or modified; and that the envelope's recorded sequence of events is internally consistent. The auditor confirms all of this without trusting the running system, without contacting the issuer, and without access to the engine's internal state. The evidence is self-contained.

This is the distinction the protocol draws between having a governance policy and being able to prove that an action was governed. A system that merely has a policy can assert, after the fact, that it followed the policy. A system that produces offline-verifiable artifacts can demonstrate, from committed evidence that the asserting party cannot have forged without a trusted key, that a specific action was authorized by a specific evaluation, bound to a specific context, within a specific validity window. The proof is in the artifacts, not in the trust placed in the system that produced them.

### 9.4 The relationship between stateless verification and the PEP

The stateless verifiers and the PEP share verification logic but differ in two respects: the stateful additions the PEP makes, and the purpose each serves.

The PEP adds stateful operations that the stateless verifiers deliberately omit. Replay consumption — recording that an `auth_id` has been used — is stateful and belongs to the PEP, because it mutates the replay store. State commit via CAS is stateful and belongs to the PEP. The stateless verifiers confirm the cryptographic and binding validity that does not require mutation; the PEP wraps them with the stateful operations that gate execution. This division means the stateless verifiers can be invoked freely, idempotently, without side effects, by any party — while the stateful operations that must occur exactly once per execution are confined to the PEP.

The purposes differ accordingly. The PEP verifies in order to decide admission, once, at the execution boundary, with the stateful consequences that admission entails. The stateless verifiers verify in order to establish validity, repeatably, anywhere, without consequence beyond the verdict they return. An auditor invokes the stateless verifiers; a relying party confirming an artifact before acting invokes them; an independent implementation confirming conformance invokes them (Section 10). The PEP is invoked once per execution; the stateless verifiers are invoked whenever validity needs to be established.

This separation is what allows the protocol's verification to be both an enforcement mechanism and an audit mechanism with the same underlying logic. The logic that gates execution in real time is the same logic that, exposed statelessly, lets an auditor confirm months later that the gating was valid. The next section describes how this shared verification logic is held to a single specification across independent implementations — the conformance methodology that establishes that the TypeScript, Go, and Python implementations of these verifiers agree byte-for-byte.

---

## 10. Conformance and Cross-Implementation Reproducibility

The protocol's claims to determinism (G5) and the supporting invariant of replayability (I5) are not self-evident. A specification can describe deterministic behavior; whether independent implementations actually produce identical results is an empirical question that a specification alone cannot answer. This section describes the conformance methodology by which OxDeAI establishes, as a mechanically verifiable fact, that independently written implementations agree byte-for-byte on the protocol's behavior.

The methodology rests on two components: a suite of portable conformance vectors that define expected behavior independently of any implementation, and a set of independently written language implementations that each verify the vectors. The agreement of these implementations on the vectors is the evidence. We describe both components, the specific proof points that anchor cross-language agreement, the current coverage, and — with deliberate care — the limits of what the conformance suite establishes.

### 10.1 Why conformance matters for this protocol

Most authorization systems are single implementations. A system verifies its own artifacts using its own code; the question of whether a *different* implementation would agree does not arise, because there is no different implementation. For such systems, internal test coverage suffices: the implementation is correct if it behaves as its authors intended.

A protocol intended to be implemented by multiple independent parties faces a stronger requirement. If the protocol is to be a genuine interoperability standard — if an artifact produced by one party's implementation is to be verifiable by another party's implementation — then the implementations must agree not approximately but exactly. A signature is computed over specific bytes; if two implementations serialize the same logical artifact to different bytes, one will produce a signature the other rejects. Byte-level agreement is not a nicety for an authorization protocol; it is the precondition for interoperability.

This requirement is most acute at the canonicalization layer. The protocol's signatures and hashes are computed over canonical serializations (§6.4, Appendix B). If two implementations canonicalize the same input differently — ordering keys differently, normalizing Unicode differently, encoding numbers differently — they compute different preimages and disagree on every signature and hash. The conformance methodology therefore concentrates on establishing that canonicalization, and the verification logic built on it, is byte-identical across implementations.

This is the property that distinguishes a protocol from a product. A product's audit trail is verifiable by the product. A protocol's artifacts are verifiable by anyone who implements the protocol correctly — and "correctly" is defined by agreement with the conformance vectors, not by agreement with any particular implementation, including the reference one.

### 10.2 The portable conformance vector suite

The conformance vectors are data files, independent of any implementation, that specify expected behavior. Each vector describes an input — a canonical serialization to be hashed, an artifact to be verified, a key lifecycle scenario to be evaluated — and the expected output: the expected hash, the expected verification verdict, the expected error code. A vector is a claim about behavior that any implementation can be checked against.

The vectors are organized by the protocol surface they exercise. The canonicalization vectors specify the canonical serialization of inputs covering key ordering, Unicode normalization, numeric encoding, duplicate-key rejection, and unsupported-type rejection. The authorization vectors specify verification verdicts for `AuthorizationV1` artifacts across both encodings, covering valid acceptance, tampered-signature rejection, unknown-key rejection, audience mismatch, expiry, the `expiry`/`expires_at` precedence rule, intent binding, and the algorithm case-exactness rule. The key-lifecycle vectors specify verdicts across key status (active, retired, revoked) and validity windows (`not_before`, `not_after`). The Profile C vectors specify state-hash verification semantics across the verification modes, including the Encoding-B signature path. The SignedKRLV1 vectors specify revocation-list verification across valid, expired, malformed, and version-regression cases. The delegation vectors specify chain verification, scope narrowing, and the single-hop constraint.

Each vector is portable in the precise sense that it carries everything needed to check it — the input, the expected output, and any fixture key material — in a form that any implementation in any language can load and evaluate. The vectors are not tied to the reference implementation's internal representations; they are external specifications of behavior. An implementation that did not exist when a vector was written can be checked against it without modification to the vector.

### 10.3 Independently written implementations

The conformance vectors define expected behavior; the implementations that verify them provide the evidence of agreement. The protocol currently has three language implementations of the verification logic: a TypeScript reference implementation, a Go harness, and a Python harness.

These implementations are independent of one another at the code level. The Go harness does not call into the TypeScript reference; it implements canonicalization-v1, Ed25519 verification, and the protocol's verification logic natively in Go, using Go's standard-library cryptographic primitives. The Python harness likewise implements the verification logic natively, using Python's standard library and platform cryptographic libraries, with no runtime dependency on the TypeScript or Go implementations. Each harness loads the same portable vectors and evaluates them with its own independent implementation.

We are careful about the word "independent" here. The three implementations are independent of each other in the sense that each is a separate body of code that implements the protocol from the specification, not by calling another implementation. They are not, however, independent of the project: all three are currently project-maintained, written by the same author or under the same project's direction. This is a meaningful limitation on the strength of the cross-implementation evidence, and we state it plainly. Genuine third-party independent implementations — written by parties with no connection to the project, from the specification alone — would provide stronger evidence of the specification's completeness and unambiguity than project-maintained implementations can. The conformance methodology is designed to make such third-party implementation possible (the vectors and specification are public and self-contained); the appearance of third-party implementations is a goal, not a present fact.

What the three project-maintained implementations do establish is that the protocol's behavior is reproducible across genuinely different codebases, languages, and cryptographic libraries — that the specification is concrete enough to implement consistently in TypeScript, Go, and Python, using three different cryptographic stacks, and reach byte-identical results. This is weaker than third-party independence but stronger than single-implementation self-testing.

### 10.4 Byte-equivalence proof points

The clearest evidence the conformance methodology produces is a set of byte-equivalence proof points: specific artifacts whose verification across all three implementations demonstrates that the implementations compute identical preimage bytes from identical inputs.

The canonical example is a `SignedKRLV1` artifact with duplicate revoked key identifiers, carrying a specific Ed25519 signature. This single artifact serves as a cross-language byte-equivalence anchor: the TypeScript, Go, and Python implementations each independently canonicalize the artifact's signing payload, compute the preimage bytes, and verify the signature against those bytes. The signature verifies identically in all three. Because Ed25519 verification of a given signature against a given public key succeeds only if the message bytes are exactly correct, the fact that the same signature verifies in all three implementations is proof that all three computed identical preimage bytes — that their canonicalization agreed byte-for-byte. A single byte of difference in any implementation's canonicalization would cause that implementation's verification to fail.

A second proof point is provided by the Profile C Encoding-B artifacts, which exercise the non-domain-prefixed signing path (§6.4) with base64url encoding. These artifacts establish byte-equivalence on the Encoding-B preimage construction specifically, confirming that the two encodings' distinct preimage rules are reproduced identically across implementations. An implementation that handled the Encoding-A domain prefix correctly but the Encoding-B non-prefixed path incorrectly would fail these vectors while passing the Encoding-A ones.

These proof points are not assertions in the paper; they are mechanically verified on every run of the conformance suite. The claim "the implementations agree byte-for-byte on this artifact" is not something the reader must take on trust — it is re-established every time the suite runs, in continuous integration, across all three implementations. The proof is reproducible by anyone who clones the repository and runs the suite.

### 10.5 Current coverage

The conformance suite currently comprises 265 assertions: 209 in the TypeScript reference implementation, 28 in the Go harness, and 28 in the Python harness. The TypeScript assertions cover the full verification surface — authorization verification across both encodings, key lifecycle, delegation, audit chains, envelopes, Profile C state verification, and the SignedKRLV1 path. The Go and Python harnesses each cover canonicalization, the eight Profile C state-verification modes including the Encoding-B path, and the nine SignedKRLV1 vectors, providing cross-language verification of the surfaces where byte-equivalence is most critical.

The coverage is uneven by design and by stage. The TypeScript reference implementation covers the broadest surface because it is the reference; the Go and Python harnesses concentrate on the canonicalization, Profile C, and SignedKRLV1 surfaces where cross-language agreement provides the most valuable evidence. Some surfaces are verified in TypeScript but do not yet have cross-language coverage: the authorization-verification harness integration in Go and Python, for instance, is identified in the protocol audit as a future item. The intent-binding portable vector exists with independent hash derivation, but the Go and Python authorization-verification harness integration that would exercise it cross-language is not yet implemented.

We state this coverage precisely rather than rounding it up to a claim of complete cross-language coverage. The Profile C and SignedKRLV1 surfaces have full cross-language coverage; the broader authorization-verification surface has cross-language coverage on canonicalization (which underlies all of it) but not yet on every verification verdict. The conformance methodology is sound and the most critical surfaces are covered cross-language; the coverage is not yet complete across every surface, and the gaps are documented rather than obscured.

### 10.6 What conformance does and does not establish

The conformance suite establishes a specific, bounded claim, and the discipline of the methodology requires stating both what it establishes and what it does not.

What it establishes: that the protocol's behavior on the covered surfaces is reproducible byte-for-byte across three implementations in three languages using three cryptographic stacks. That canonicalization-v1 is concrete enough to implement consistently across these implementations. That the verification verdicts on the covered vectors agree across implementations, including the deterministic ordering of reported violations. That the byte-equivalence proof points verify identically across all three implementations on every run. Collectively, this is concrete evidence for the determinism goal (G5) and the replayability invariant (I5) on the covered surfaces.

What it does not establish: that the implementations agree on surfaces not covered by vectors. Determinism is verified for what the vectors exercise; surfaces without vectors — certain canonicalization edge cases for unusual inputs, the cross-language authorization-verification verdicts not yet harnessed — are not verified to agree, and the suite makes no claim about them. The suite cannot prove the absence of divergence on untested inputs; it can only demonstrate agreement on tested ones. This residual is bounded by the suite's coverage and reduced with each vector added, but it is not zero, and the methodology does not pretend otherwise.

Nor does the conformance suite establish that the protocol is *secure*. Conformance is agreement with the specification; it is not a security proof. An implementation can be perfectly conformant and still be deployed insecurely (§3.7), and the specification itself could in principle contain a flaw that all conformant implementations would faithfully reproduce. Conformance establishes interoperability and reproducibility; it does not substitute for the independent security review that the protocol has not yet undergone (§13).

Nor, finally, does the current suite establish third-party independent implementability in the strongest sense. As stated in §10.3, the three implementations are project-maintained. That the protocol *can* be implemented from its public specification by a third party is a design goal supported by the public, self-contained vectors and specification; that it *has* been so implemented is not yet a fact. The strongest form of cross-implementation evidence — agreement between the project's implementation and a genuinely external one — awaits external adoption.

The conformance methodology is, within these bounds, the protocol's strongest evidence for its determinism and reproducibility claims. It transforms "the protocol is deterministic" from an assertion into a reproducible demonstration on the covered surfaces. The next section describes how this verifiable protocol composes with external governance providers through the interoperability profiles, including a deployed integration that exercises the protocol's cross-encoding support in practice.

---

## 11. Interoperability Profiles

The protocol defines three interoperability profiles that govern how an authorization is produced and how thoroughly the enforcement boundary verifies it. The profiles allow the protocol to serve both deployments where the policy engine and PEP are the same OxDeAI implementation and deployments where an external governance provider produces the decision that the OxDeAI boundary enforces. This section specifies the three profiles, the trust separation that governs external-provider integration, and a deployed integration that exercises the cross-provider path in practice.

The profiles are not different protocols; they are different configurations of the same protocol, distinguished by the source of the authorization and the depth of state verification at the boundary. An artifact verified under any profile is the same `AuthorizationV1` specified in Section 6; the profiles differ in how the artifact arrives and what the PEP checks.

### 11.1 The three profiles

*Profile A (core-native).* The policy engine and the PEP are both OxDeAI implementations. The engine evaluates the proposed action, produces an `AuthorizationV1` in Encoding A (the core-native encoding, §6.3), signs it with an OxDeAI signing key, and the PEP verifies it. This is the baseline profile: the full decision-to-enforcement flow within a single OxDeAI deployment. The state binding is signed and tamper-evident, but the PEP does not perform live-state re-verification beyond confirming the signed `state_hash`.

*Profile B (external provider, wire-compatible).* An external governance provider produces a decision that an adapter translates into an `AuthorizationV1`, typically in Encoding B (the external-provider-compatible encoding, §6.3). The external provider signs a receipt with its own key; the adapter constructs an `AuthorizationV1` and signs it with an OxDeAI-trusted key. The PEP verifies the `AuthorizationV1` against its `trustedKeySets` as in Profile A. The distinguishing feature is the trust separation (§11.2): the external provider's receipt-signing key and the OxDeAI signing key are distinct trust domains, and only the OxDeAI-trusted key produces an artifact the PEP accepts.

*Profile C (full semantic state verification).* The PEP performs live-state re-verification at enforcement time. In addition to verifying the signed `state_hash` (as in all profiles), the PEP obtains the live state through its configured state access, computes the state hash via the configured `computeStateHash`, and compares it against the authorization's `state_hash` (§8.2 step nine). This detects state that has changed between authorization and enforcement. Profile C is the strongest verification posture and the one to which the state-provider trust boundary (§13) most directly applies, because it is the profile that consumes live state at the enforcement point.

The profiles compose with the encodings but are not identical to them. Profile A typically uses Encoding A and Profile B typically uses Encoding B, reflecting their origins, but the profile (how the artifact is produced and verified) and the encoding (how the artifact is serialized) are distinct dimensions. The conformance suite covers Profile C across both encodings, including the Encoding-B state-verification path (§10.4).

### 11.2 Trust separation in external-provider integration

The central design concern in Profile B is preventing an external provider from breaching the OxDeAI trust boundary. An external governance provider participates in the decision, but it must not be able to produce an `AuthorizationV1` that the PEP accepts directly — because if it could, the external provider's key compromise would directly compromise the OxDeAI enforcement boundary, and the trust configuration at the PEP would no longer be the sole determinant of which authorizations are accepted (§5.4).

The protocol enforces this through key-domain separation. The external provider signs its governance receipt with its own key. This receipt is evidence of the external provider's decision, signed in the external provider's trust domain. An adapter consumes the receipt, verifies it against the external provider's key, and — if the receipt is valid — constructs an `AuthorizationV1` that it signs with an OxDeAI signing key, a key present in the PEP's `trustedKeySets`. The PEP verifies the `AuthorizationV1` against `trustedKeySets` exactly as it does in Profile A; it does not verify the external provider's receipt directly, and the external provider's key is not in the PEP's `trustedKeySets`.

The consequence is a clean trust boundary. The PEP trusts the adapter's OxDeAI-signed `AuthorizationV1`, not the external provider's receipt. The adapter is the bridge between the two trust domains, and it is the adapter — signing with an OxDeAI-trusted key — that takes responsibility for the translation. An external provider whose key is compromised can produce forged receipts, but those forged receipts do not directly produce PEP-accepted authorizations; they would have to pass through the adapter, which is a distinct component under the deploying party's control. The conformance suite includes vectors that verify this separation: an artifact signed by an OxDeAI key in `trustedKeySets` is accepted, while the same artifact carrying a provider receipt key absent from `trustedKeySets` is rejected with an unknown-key error.

This separation realizes, for the external-provider case, the principle stated throughout: validity is cryptographic, trust is explicit (§5.4). An external provider's receipt may be cryptographically valid in the external provider's domain, but it is not trusted by the OxDeAI PEP, because the PEP's trust is defined by its `trustedKeySets`, which contains the OxDeAI signing key and not the external provider's receipt key.

### 11.3 A deployed integration: the Sift adapter

The external-provider profile is not hypothetical. The protocol's `@oxdeai/sift` adapter integrates Sift, an external governance provider, with the OxDeAI enforcement boundary. We describe this integration as a worked example of Profile B, because it exercises the trust separation, the two-encoding accommodation, and the production-versus-enforcement layering in a concrete deployment.

The integration arose from a technical request: Sift, as an external governance provider producing signed decision receipts, sought integration with an execution-time enforcement boundary. The integration is purely technical; no commercial relationship, funding, or contractual arrangement is involved. The collaboration produced the adapter and, in the process, surfaced several protocol-level alignment issues that were resolved in the protocol's specifications rather than in Sift-specific workarounds.

The adapter operates as Profile B specifies. It verifies Sift receipts locally — confirming the Ed25519 signature against Sift's receipt key, with no remote dependency on Sift at verification time — and constructs an `AuthorizationV1` with explicit bindings: the authorization's `auth_id` is bound to the receipt's server-side nonce (a unique-per-decision value, exactly the property `auth_id` requires); the `policy_id` is bound to the receipt's matched policy; and the `intent_hash` and `state_hash` are computed over canonical serializations of the proposed action and state. The adapter then signs the constructed `AuthorizationV1` with an OxDeAI key, and the OxDeAI PEP verifies it. Sift's receipt key and the OxDeAI signing key are distinct, as Profile B requires; the PEP trusts the OxDeAI-signed authorization, not the Sift receipt directly.

The integration exercised the protocol's two-encoding support directly. Sift's wire format used the lowercase `ed25519` algorithm identifier and the `expires_at` temporal field — Encoding B's conventions (§6.3). The OxDeAI core verifier expected the `Ed25519` identifier and the `expiry` field — Encoding A's conventions. Rather than forcing Sift to re-sign in Encoding A or building a one-off compatibility shim, the protocol specified both encodings precisely, with the `expiry`/`expires_at` precedence rule and the case-exact algorithm matching, so that an Encoding-B artifact from the Sift adapter is directly verifiable by the OxDeAI core without a translation layer. The alignment issues that surfaced during integration — the algorithm-identifier casing and the temporal-field naming — became specified protocol features with conformance vectors locking the behavior, rather than remaining integration-specific accommodations. This is the conservative-protocol discipline (§5.6, the audit methodology) applied to integration: an integration request that reveals an ambiguity is resolved by specifying the ambiguity away for all implementers, not by patching the specific integration.

The integration also clarified the layering. Sift functions as a decision layer — it produces a governance decision, informed by its own risk assessment and policy evaluation. OxDeAI functions as the execution-time enforcement boundary — it takes the decision, expressed as a verified `AuthorizationV1`, and enforces it fail-closed at the execution point. The two layers are complementary: the decision layer decides, the enforcement boundary enforces, and the `AuthorizationV1` is the artifact that carries the decision across the boundary. This layering — an external decision layer above the OxDeAI enforcement boundary — is the general pattern Profile B supports, with Sift as the first deployed instance.

### 11.4 The non-authoritative metadata pattern

A distinct integration pattern, complementary to Profile B, governs external systems that attach contextual information to OxDeAI-governed actions without participating in the authorization decision. Where Profile B integrates an external system that *produces* the decision, the non-authoritative metadata pattern integrates an external system that *annotates* an action — attaching routing evidence, provenance attestations, observability data, or audit context — without influencing whether the action is authorized.

The pattern's defining rule is isolation from the authorization decision. External metadata may be attached to an action, but it must satisfy three conditions: it must be cryptographically isolated from the `AuthorizationV1`, appearing in no field that influences the PEP's verdict; it must not condition the PEP's verification pipeline, which proceeds identically whether or not the metadata is present; and it must follow its own versioned serialization, independent of canonicalization-v1, so that external metadata schemas evolve without affecting the protocol's verification surfaces.

The test that distinguishes authoritative from non-authoritative integration is precise: can the metadata, through any path, cause the PEP to produce a different ALLOW/non-ALLOW verdict than it would without the metadata? If yes, the metadata is authoritative and must go through the policy engine — it is part of the decision, and it must be bound into the authorization the engine signs. If no, the metadata is non-authoritative and may be attached externally using the isolation pattern. This test draws the boundary that the protocol's authority path defines: routing, observability, and audit systems may propose, explain, and annotate; only the policy engine decides; only the PEP enforces.

This pattern allows rich external context — routing evidence that explains why an action was proposed, provenance data that records its origin, cost-attribution metadata for accounting — to accompany an action without creating a side channel through which an external actor could influence authorization. The metadata is evidence; the `AuthorizationV1` is authority. The two are kept structurally distinct, so that the integrity of the authorization decision does not depend on the integrity of the external metadata.

### 11.5 Profiles as a spectrum of integration

The three profiles and the metadata pattern form a spectrum of how external systems relate to the OxDeAI boundary. At one end, Profile A is fully self-contained: OxDeAI produces and enforces its own decisions. Profile B admits an external decision layer, with the trust separation ensuring the external provider informs but does not breach the enforcement boundary. The non-authoritative metadata pattern admits external annotation without any authority over the decision. Profile C, orthogonal to the production question, deepens the enforcement-side verification by re-checking live state.

What is constant across the spectrum is the authority path. In every configuration, the policy engine (whether OxDeAI's own or an external provider's, bridged through an adapter) decides; the `AuthorizationV1` carries the decision; the PEP enforces it fail-closed; and external systems that are not the policy engine cannot alter the verdict. The profiles vary the source of the decision and the depth of verification; they do not vary the principle that authorization is decided by a trusted issuer, carried in a verifiable artifact, and enforced at a non-bypassable boundary.

This integration flexibility, bounded by the constant authority path, is what allows OxDeAI to serve as an enforcement boundary beneath heterogeneous decision layers — its own engine, external governance providers, risk-scoring systems — while preserving the deterministic, verifiable, fail-closed properties that the protocol guarantees regardless of where the decision originates. The next section returns to the six security goals defined in Section 2 and maps each to the specific mechanisms, across all the profiles, that realize it.

---

## 12. Security Goals Realized

Section 2 defined six security goals (G1–G6). The intervening sections specified the protocol mechanisms. This section maps each goal to the mechanisms that realize it and the conformance evidence that verifies it, so that each goal can be traced from statement to realization to verification. Where a goal's realization is bounded by a residual, the residual is named and the relevant deployment obligation identified.

The mapping is intended to be auditable. A reviewer should be able to take any goal, follow it to the mechanisms claimed to realize it, and check those mechanisms against the specification and the conformance suite. Goals that depend on deployment configuration to hold are marked as such, because a goal realized only under correct configuration is realized conditionally, and the condition is part of the honest claim.

### 12.1 G1: Authorization authenticity

*Goal:* An authorization artifact accepted by a conformant PEP was produced by an issuer holding a private key that the PEP's verifier has been explicitly configured to trust.

*Realization:* Authenticity is established by the conjunction of three mechanisms. The Ed25519 signature over the domain-prefixed canonical preimage (§6.4) ensures that only a holder of the signing private key could have produced the artifact. The `trustedKeySets` configuration at the verifier (§5.4, §8.2 step four) defines which keys are trusted, so that a valid signature from an untrusted key is rejected (`AUTH_KID_UNKNOWN`). The key revocation list ensures that a key present in `trustedKeySets` but revoked is rejected, so that authenticity reflects current trust, not merely configured trust. All three conditions are necessary: a signature valid against a trusted, unrevoked key.

*Verification:* The authorization signature vectors verify acceptance of valid signatures and rejection of tampered signatures, unknown keys, and unsupported algorithms. The key-lifecycle vectors verify rejection of revoked and window-expired keys. The Profile B trust-separation vectors verify that a key absent from `trustedKeySets` is rejected even when the signature is otherwise valid.

*Residual:* Authenticity is bounded by signing-key custody. A compromised signing key produces artifacts indistinguishable from legitimate ones until the key is revoked, and revocation propagation is bounded by the KRL polling interval and signing latency (§3.5, §3.8). The protocol provides revocation as the response to compromise; it does not provide compromise detection or custody, which are deployment obligations.

### 12.2 G2: Authorization integrity

*Goal:* An authorization artifact cannot be modified after signing without invalidating the signature, regardless of which fields are modified.

*Realization:* Integrity follows from the signature covering the canonical serialization of the entire signed artifact (§6.4). Because the signature is computed over the canonical preimage, any modification to any signed field, to field ordering, or to encoding produces a different preimage and thus signature verification failure. The canonical serialization (canonicalization-v1) makes the preimage deterministic, so that the verifier reconstructs the same preimage the signer used, and any divergence introduced by tampering is detected.

*Verification:* The signature vectors verify that a tampered field invalidates the signature. The canonicalization vectors verify that the serialization is deterministic across the covered inputs, which is the precondition for the verifier reconstructing the signer's preimage. The cross-language byte-equivalence proof points (§10.4) verify that the preimage reconstruction is byte-identical across implementations, so that integrity verification does not depend on implementation-specific serialization.

*Residual:* Integrity verification depends on canonicalization being byte-identical across the signer's and verifier's implementations. The conformance suite detects canonicalization divergence on covered inputs; it cannot prove the absence of divergence on uncovered inputs (§10.6). An implementation bug producing divergent canonicalization on an uncovered input could, in principle, cause an artifact to verify in one implementation and fail in another. This residual is bounded by conformance coverage.

### 12.3 G3: Replay resistance

*Goal:* An authorization artifact accepted once by a conformant PEP cannot be accepted a second time by a conformant deployment with durable replay state.

*Realization:* Each artifact carries a unique `auth_id` (§6.2). The PEP consumes the `auth_id` through the `ReplayStore` interface (§8.2 step ten), which implements atomic single-use semantics: a second presentation of an already-consumed identifier is rejected (`AUTH_REPLAY`). The atomicity of consumption — provided by the backing store's compare-and-set or equivalent linearizable write — ensures that two concurrent presentations of the same artifact cannot both succeed. Delegation replay is handled correspondingly, with both the parent `auth_id` and the delegation identifier consumed (§7.5).

*Verification:* The replay vector verifies that a second presentation of a consumed `auth_id` is rejected. The PEP conformance vectors verify that replay-store unavailability causes verification failure rather than permissive acceptance, realizing the fail-closed behavior on which the guarantee depends.

*Residual:* Replay resistance is conditional on durable replay-store configuration (RT-TRUST-3, §3.8). The default in-memory store provides replay resistance only within a single process and loses state on restart; multi-process deployments using the in-memory default lose replay coherence across instances. The protocol specifies the replay-store contract but does not enforce the choice of backing store at the wire level, and it does not detect a misconfigured deployment. The guarantee holds for deployments with durable replay state; the deployment obligation to configure such state is part of the honest claim.

### 12.4 G4: Delegation non-expansion

*Goal:* A delegation artifact cannot grant a delegatee any authority that the delegating authorization did not itself possess.

*Realization:* Non-expansion is enforced by the scope-narrowing verification (§7.3). The delegation's `parent_auth_hash` binds it to a specific parent authorization (§7.2), and the verifier checks each scope dimension — tool allowlist, budget ceiling, action count, expiry — to be equal to or more restrictive than the parent's, rejecting any expansion (`DELEGATION_SCOPE_VIOLATION`). The parent scope is supplied as an explicit typed field and structurally validated before chain verification, failing closed on a missing or malformed parent scope (§7.3). The single-hop constraint (§7.4) bounds delegation to the case the verification fully covers.

*Verification:* The delegation vectors verify scope-narrowing enforcement across the scope dimensions, rejection of scope violations, rejection of delegations bound to an invalid or mismatched parent, and rejection of chains deeper than one hop. The cross-adapter delegation guard tests verify that these rejections hold at the enforcement boundary.

*Residual:* Non-expansion is verified for single-hop delegation. Multi-hop delegation is specified but not yet verified with chains deeper than two, and the current verifier rejects deeper chains rather than verifying them (§7.4). Deployments requiring deeper delegation compose single-hop delegations through application logic, with each hop independently verified against its immediate parent.

### 12.5 G5: Deterministic verification

*Goal:* Two conformant implementations, given the same authorization artifact and the same verifier configuration, produce identical verification verdicts.

*Realization:* Determinism follows from three properties. The canonical serialization is deterministic (canonicalization-v1, Appendix B). Ed25519 verification is deterministic by construction. The verifier's decision is a pure function of the artifact, the configuration, and the explicitly injected observed time (§8.4, the explicit `opts.now` precluding implicit clock reads). The strict zero-tolerance expiry model (§6.5) avoids a configurable parameter that could produce divergent verdicts. The deterministic ordering of reported violations (§9.2) ensures that implementations agree not only on the verdict but on the reported reason.

*Verification:* This is the goal the conformance methodology most directly addresses (Section 10). The portable vectors define expected verdicts independently of any implementation; the three language implementations each verify the vectors; the byte-equivalence proof points demonstrate identical preimage computation across implementations. The clock-semantics vectors verify identical expiry behavior across implementations, including the boundary cases and the verifier-clock-behind case.

*Residual:* Determinism is verified for the surfaces covered by conformance vectors (§10.6). Surfaces without cross-language vectors are not verified to agree, and the suite cannot prove the absence of divergence on uncovered inputs. The residual is bounded by coverage and reduced with each vector added. The three implementations are project-maintained, so the evidence is reproducibility across codebases and languages rather than third-party independent agreement (§10.3).

### 12.6 G6: Fail-closed enforcement

*Goal:* Any verification failure, configuration ambiguity, or absence of authorization produces non-execution. There is no execution path through partial verification or graceful degradation.

*Realization:* Fail-closed enforcement is realized by the PEP's sequential pipeline structure (§8.2, §8.4). Every check that can fail does so by throwing before the execution boundary is reached, with no catch converting a failure into a permitted execution. Configuration errors throw rather than defaulting permissively: an absent `trustedKeySets` in strict mode produces `TRUSTED_KEYSETS_REQUIRED`; required state configuration absent in a state-verifying profile fails at construction. Replay-store unavailability and state-hash computation failure both throw rather than proceeding without the corresponding check. The KRL `signed_required` mode rejects unsigned revocation lists before verification proceeds. The structural placement of the PEP as a wrapping closure (§8.1) ensures the execution function is unreachable except through the verification pipeline.

*Verification:* The PEP conformance vectors exercise each failure mode — denial, invalid signature, audience mismatch, expiry, state-hash mismatch, replay, CAS conflict, missing artifact, missing fields — and confirm in each case that the execution boundary, the state commit, and the pre-execution hook are all blocked. The property tests confirm, across arbitrary proposed-action inputs, that a non-ALLOW decision always prevents both execution and state commit.

*Residual:* Fail-closed enforcement is as strong as the deployment's configuration and architecture. The KRL `signed_preferred` default accepts unsigned fallback during transport failures (RT-TRUST-2, §3.8), retaining transport-trust-only semantics for unsigned cases until the default migrates to `signed_required`. And the structural non-bypassability of the PEP holds only for execution actually routed through the guard; a deployment that retains a direct reference to the execution function bypasses the PEP outside anything the protocol can detect (§8.1). These are deployment obligations: configure `signed_required` where cryptographic KRL verification is required, and ensure all execution is routed through the guard.

### 12.7 Summary of the mapping

The table below summarizes the goal-to-mechanism-to-residual mapping. It is a navigational aid; the authoritative statements are in the subsections above and the sections they reference.

| Goal | Primary mechanisms | Principal residual |
|------|-------------------|-------------------|
| G1 Authenticity | Ed25519 signature; `trustedKeySets`; KRL | Signing-key custody |
| G2 Integrity | Signature over canonical preimage; canonicalization-v1 | Canonicalization coverage |
| G3 Replay resistance | Unique `auth_id`; atomic `ReplayStore` consumption | Durable store configuration |
| G4 Delegation non-expansion | `parent_auth_hash` binding; scope-narrowing verification | Single-hop only (current version) |
| G5 Deterministic verification | Canonicalization; pure verification function; conformance suite | Coverage; project-maintained implementations |
| G6 Fail-closed enforcement | Sequential throwing pipeline; structural PEP placement | Default KRL mode; PEP placement |

Two observations follow from the mapping. First, every goal is realized by specific, verifiable mechanisms rather than by assertion, and every goal's realization is verified by conformance vectors or property tests. This is the traceability that the goal-driven structure was intended to provide: a reviewer can follow each goal to its mechanisms and to the evidence that the mechanisms work.

Second, every goal is bounded by a residual, and the residuals divide into two kinds. Some are deployment obligations — configurations the deployment must adopt for the goal to hold fully (durable replay store for G3, `signed_required` mode and correct PEP placement for G6). Others are bounds on the evidence — the conformance coverage that bounds G2 and G5, the single-hop limitation that bounds G4, the project-maintained nature of the implementations that bounds the independence claim for G5. Stating both kinds explicitly is the difference between claiming the goals are achieved and claiming they are achieved under stated conditions with stated evidence. The protocol makes the latter claim. The next section develops the residuals that bound these goals into a full account of the protocol's limitations.

---

## 13. Limitations

A protocol's limitations are as much a part of its specification as its mechanisms. A deployment evaluating whether OxDeAI fits its requirements needs to know not only what the protocol guarantees but what it does not, under what conditions the guarantees hold, and which problems it leaves to the deployment or to future work. This section states the protocol's limitations systematically: the residual trust assumptions, the operational risks, and the capabilities not yet built.

We state these as plainly as the contributions. A limitations section that minimizes its subject is less useful than one that states limitations clearly enough that a deployment can decide whether they matter for its case. The most significant limitation — the state provider trust boundary — is treated first and at length, because it is the one most likely to be missed and most consequential when it is.

### 13.1 The state provider trust boundary (RT-TRUST-1)

The protocol's most significant structural limitation concerns the integrity of state. In Profile C (§11.1), the PEP verifies that the live state hashes to the same value committed in the authorization: it computes `computeStateHash(liveState)` and compares it against the authorization's `state_hash`. This verification proves hash consistency between the authorization artifact and the state object the PEP was given. It does not prove that the state object is honest, current, or derived from a compliant source of truth.

The gap is precise. The PEP obtains the live state through a configured state-access interface (`getState`). The state object that this interface returns is trusted input to the PEP. A state provider that is compromised, misconfigured, or non-compliant can return a manufactured state object whose hash matches a valid authorization's `state_hash`, and the PEP's verification will pass. The PEP verifies the hash; it cannot verify the provenance of the object that produced the hash. A sophisticated adversary who controls the state provider and can construct a state object matching a valid authorization's committed hash defeats the state binding at the PEP layer, and the protocol cannot detect this.

This is not a flaw to be fixed by a protocol change; it is a structural boundary. The protocol operates at the point where state is presented for verification. It cannot reach behind that point to verify that the presenting system is honest, any more than a signature verifier can verify that the signing system was not compromised when it signed. The boundary is intrinsic to the protocol's position in the architecture: it verifies artifacts and the consistency of state against them; it does not own or operate the state provider.

The protocol's response to this limitation is to specify, rather than to enforce, what a compliant state provider must satisfy. The state-provider-requirements specification defines minimum integrity requirements for a compliant state provider: read consistency and compare-and-set semantics so that concurrent mutations are detected; state provenance with monotonic versioning so that mutation history is reconstructable; write access control so that only authorized paths mutate state; audit emission so that mutations are recorded; replay and rollback expectations so that old state is not served as current; and compromise indicators that a deployment can monitor. The specification defines what compliance means; it provides the criteria against which a deployment's state provider can be evaluated.

But compliance is a deployment responsibility, not a protocol-layer guarantee. The protocol cannot verify, at the wire level, that a deployment's state provider satisfies these requirements. A deployment that configures a compliant state provider mitigates RT-TRUST-1 to the extent the requirements address it; a deployment that configures a non-compliant or compromised provider retains the full residual risk. The protocol moves RT-TRUST-1 from "no requirements exist" to "requirements are specified and deployment compliance is the operator's responsibility." It does not close the residual, and we do not claim it does.

Even a fully compliant state provider does not eliminate every risk in this area. A hash collision against SHA-256, though computationally infeasible, is a theoretical residual. An insider at the state provider with legitimate write access who manufactures state within normal operational bounds — producing valid version tokens, plausible mutation history, and correct audit entries — may not be detectable by the compromise indicators, because the manufactured state is, by construction, operationally indistinguishable from legitimate state. And a future cryptographic compromise of the state hash function would weaken the binding proportionally. These named residuals persist beyond compliance and are documented as such.

The honest characterization is this: OxDeAI's state binding proves that the state presented at enforcement is consistent with the state committed at authorization, under the assumption that the state provider is honest. The assumption is necessary; the protocol cannot discharge it. Deployments for which this assumption is unacceptable — where the state provider cannot be trusted even under the compliance requirements — are deployments for which OxDeAI's Profile C state binding provides hash-consistency assurance but not state-source assurance, and they should understand the distinction before relying on it.

### 13.2 KRL transport integrity in the default mode (RT-TRUST-2)

The protocol supports three modes for key revocation list integrity (§8.4, §11). The `signed_required` mode cryptographically verifies every revocation list, closing the transport-integrity gap: a revocation list must be a signed `SignedKRLV1` artifact verified before any revocation data is accepted. The `signed_preferred` mode, which is the current default, verifies signed revocation lists when present but falls back to transport trust for unsigned lists. The `unsigned_legacy` mode, deprecated, accepts revocation lists on transport trust only.

The limitation is in the default. A deployment running the `signed_preferred` default, when it encounters an unsigned revocation list — for instance, during a transport failure or against a revocation source that does not yet sign its lists — falls back to accepting that list on transport trust (typically HTTPS) rather than on cryptographic verification. In this fallback case, an adversary positioned to manipulate the transport could, in principle, suppress revocations, causing the verifier to continue accepting a key that should have been revoked.

The mitigation is available and specified: a deployment requiring cryptographic revocation integrity configures `signed_required` mode, which refuses unsigned lists entirely. The supporting mechanisms — a persistent watermark store that prevents revocation-list version regression across restarts, and a last-known-good cache that closes the cold-start window without trusting unverified data — are specified and available for deployments that configure them. The limitation is that the protective configuration is not the default; the default favors availability (accepting an unsigned list rather than failing) over strict integrity (refusing it).

This is tracked for change. The protocol's migration path moves the default to `signed_required` in a future version, with `unsigned_legacy` removed in the same change. Until that migration, the limitation stands: deployments that do not explicitly configure `signed_required` retain transport-trust semantics for the unsigned-fallback case, and the deployment obligation is to configure `signed_required` where cryptographic revocation integrity is required.

### 13.3 Replay store durability (RT-TRUST-3)

The replay resistance guarantee (G3) is conditional on durable replay-store configuration (§12.3). The protocol's default in-memory replay store provides replay resistance only within a single process and loses its state on restart. A deployment running multiple PEP instances, or a single instance that restarts, using the in-memory default has a replay window: across instances, replay coherence is lost entirely; across a restart, the replay state is lost until repopulated.

The mitigation is to configure a durable, atomic replay store — the protocol's `ReplayStore` contract is satisfied by backing stores such as Redis with SET NX, PostgreSQL with serializable isolation, or DynamoDB with conditional writes, each providing the atomic single-use semantics the guarantee requires. The limitation is that the protocol does not enforce this configuration at the wire level and does not detect a misconfigured deployment: a deployment that uses the in-memory default in a multi-process or restart-resilient context degrades silently to weaker replay semantics, with no protocol-layer warning. The deployment obligation is to configure durable replay storage where the deployment's process model requires it, and the protocol audit identifies the addition of a configuration-level warning for this misconfiguration as follow-up work.

### 13.4 Non-bypassability is bounded to the operating layer

The non-bypassability property (§5.3, §8.1) holds at the level of the language runtime in which the PEP operates. The structural placement of the PEP as a wrapping closure ensures that, within that runtime, the execution function is unreachable except through the verification pipeline. This property does not extend below the runtime.

A fully compromised host process that can manipulate memory directly, an operating-system-level adversary, or a hardware attack can circumvent the PEP regardless of its structural placement, because these adversaries operate beneath the layer at which the structural guarantee holds. The protocol does not provide hardware-bound enforcement, secure-enclave isolation, or operating-system-level process isolation. Deployments requiring these must compose OxDeAI with the corresponding isolation mechanisms; the protocol's non-bypassability is a property within its operating layer, not below it.

There is also a deployment-level bypass that the protocol cannot prevent: a deployment that constructs the guard but retains and uses a direct reference to the execution function has bypassed the PEP architecturally (§8.1). The protocol provides the guarded closure and the structural guarantee that the closure cannot be circumvented; it cannot force the deployment to route all execution through the closure. Ensuring that the PEP is actually in the execution path of every action is a deployment responsibility.

### 13.5 Cryptographic and temporal assumptions

The protocol uses Ed25519 and SHA-256. Both are pre-quantum cryptographic primitives. A sufficiently capable quantum adversary running Shor's algorithm could compute private keys from public keys and forge Ed25519 signatures; Grover's algorithm reduces SHA-256's effective security against a quantum adversary, though less severely. The protocol does not currently address post-quantum migration. This is a shared limitation with most contemporary cryptographic protocols rather than an OxDeAI-specific one, and it is identified as future work (§15); for the present threat environment, in which cryptographically relevant quantum computers do not exist, the primitives provide their classical security.

The protocol's expiry model depends on clock synchronization (§6.5, §3.7). The strict zero-tolerance expiry evaluation uses the verifier's observed time as the reference; significant clock skew between issuer and verifier can cause valid artifacts to be rejected or, where the verifier's clock is behind, expired artifacts to be accepted within the skew window. The protocol assumes NTP or equivalent synchronization and does not enforce clock integrity. Clock synchronization is a deployment obligation.

### 13.6 Capabilities not yet built

Several capabilities are specified or anticipated but not yet implemented, and a deployment should not assume their availability.

An HTTP PEP middleware — a ready-to-deploy enforcement boundary for HTTP-based execution paths — is planned but not yet implemented. The current PEP is the higher-order-function guard; deployments enforcing at an HTTP boundary currently wire the guard into their own HTTP handling rather than dropping in a provided middleware.

A structured decision-event schema for observability is not yet specified. The PEP provides a decision hook that emits per-decision events, but the event format is not yet a stable, versioned schema. Observability tooling that depends on a stable event format cannot yet be built against a specified contract; the schema's specification is identified as follow-up work.

Multi-hop delegation is specified but not verified with chains deeper than two hops, and the current verifier rejects deeper chains (§7.4, §12.4). Deployments requiring deeper delegation compose single-hop delegations through application logic.

Operator-facing failure playbooks — runbooks mapping the protocol's failure modes to operational responses — are not yet written, though the threat model and the key-custody and replay-store guidance documents cover adjacent ground. A unified deployment checklist covering all the protocol's deployment obligations in one place does not yet exist; the obligations are documented across the threat model, the state-provider requirements, and the per-area guidance, but not consolidated.

### 13.7 The limitation that bounds all others: no independent security review

The protocol has not undergone independent security review by a third party. Every analysis in this paper — the threat model, the security goals, the mechanism-to-goal mapping, the residuals — is the work of the protocol's author and the internal protocol audit. Internal analysis, however disciplined, is not a substitute for review by parties who did not design the protocol and who approach it adversarially and without the author's assumptions.

This bounds every other claim in the paper. A security goal claimed to be realized by a mechanism is realized to the best of the author's analysis; an independent reviewer might identify a gap the author did not see. A residual claimed to be the only residual in an area might be joined by others a reviewer would surface. The conformance suite verifies agreement with the specification, but it cannot verify that the specification is itself free of security flaws (§10.6).

This is stated not as a disclaimer but as the most important limitation in the paper. The appropriate posture toward a security protocol that has not been independently reviewed is provisional: its claims are credible to the extent that its author's analysis is sound and its mechanisms are verifiable, but they have not been subjected to the adversarial scrutiny that independent review provides. The protocol is at the stage where its design is articulated and its behavior is verifiable, and the next step in establishing its security claims is independent review — which is identified as the immediate priority in future work (§15). A deployment evaluating OxDeAI for a security-critical context should weigh the absence of independent review accordingly, and should consider commissioning its own review for high-assurance use.

### 13.8 Reading the limitations together

The limitations divide into three kinds, and distinguishing them clarifies what each means for a deployment.

The structural limitations — RT-TRUST-1 most significantly, and the bounds on non-bypassability — are intrinsic to the protocol's position in the architecture. They cannot be closed by a protocol change; they are boundaries of what a protocol at this layer can verify. A deployment addresses them by satisfying the deployment-side requirements (compliant state provider, isolation mechanisms) and by understanding what remains assumed even then.

The default-configuration limitations — RT-TRUST-2's `signed_preferred` default, RT-TRUST-3's in-memory default — are limitations of the current defaults, not of the protocol's capabilities. The protective configurations exist and are specified; the limitation is that they are not yet default. A deployment addresses these by explicit configuration, and the protocol's migration path addresses them by changing the defaults.

The not-yet-built limitations — the HTTP middleware, the event schema, multi-hop delegation, the consolidated deployment checklist, and most importantly the independent security review — are matters of stage rather than of design. They represent work identified and not yet done, and they are the substance of the future work the next-but-one section describes.

A deployment evaluating OxDeAI should read these limitations as the conditions under which the protocol's guarantees hold and the boundaries beyond which they do not. The protocol's value is real within these bounds; stating the bounds precisely is what allows a deployment to determine whether its requirements fall within them. The next section steps back from the protocol's specifics to consider its relationship to the broader category of execution-time authorization systems, and the convergent independent design that aligned OxDeAI with a framework formalized separately.

---

## 14. Convergence with the Execution-Time Authorization Framework

OxDeAI was developed as a concrete protocol, not as an implementation of a framework. Yet its architecture aligns closely with a framework for execution-time authorization that was formalized independently and published after OxDeAI's core design was established. This section examines that convergence: the framework's invariants, OxDeAI's alignment with each, the argument that the convergence is independent rather than derivative, the one design choice where OxDeAI's path through the framework's space is worth examining in detail, and the discipline OxDeAI maintains in referencing the framework.

The convergence matters for two reasons. It locates OxDeAI within a recognized category, giving readers familiar with the framework a vocabulary for OxDeAI's design. And the independence of the convergence is itself evidence: when two efforts arrive at the same structure without coordination, the structure is more likely to reflect something necessary about the problem than the preferences of either designer.

### 14.1 The framework and its invariants

Meyman [Meyman 2026] formalizes execution-time authorization as an architectural category defined by six invariants. A system qualifies as an execution-time authorization implementation, in the framework's terms, if it satisfies all six. We summarized these invariants in Section 2 as the basis for OxDeAI's security goals; here we restate them as the framework defines them and map OxDeAI's mechanisms to each.

The six invariants are: I1, determinism — authorization outcomes are fully determined by inputs, identical across implementations and executions; I2, fail-closed enforcement — any verification failure or ambiguity produces non-execution; I3, non-bypassability — the enforcement boundary cannot be circumvented by actors within the runtime; I4, decision-artifact completeness — the decision is captured in a verifiable artifact carrying full decision context; I5, replayability — governance decisions are independently reproducible from committed evidence; I6, time-bounded evaluation without fail-open — evaluation is bounded in time, and expiry produces non-execution.

These invariants and the security goals of Section 2 are related but not identical. The invariants characterize membership in the category; the goals state what OxDeAI is designed to provide. They overlap substantially — both concern determinism, fail-closed behavior, and verifiable artifacts — but the goals include protocol-specific commitments (authenticity via explicit trust configuration, delegation non-expansion) that the framework's invariants do not enumerate, and the invariants frame the properties at the level of the category rather than of a specific protocol. We use the invariant labels as the shared category vocabulary while the goals remain OxDeAI's own statement of its design.

### 14.2 Invariant-by-invariant alignment

*I1, determinism.* OxDeAI's canonicalization-v1 (§6.4, Appendix B) defines a deterministic serialization, and the verifier's decision is a pure function of the artifact, configuration, and explicitly injected time (§8.4). The conformance methodology (Section 10) provides empirical evidence of determinism across implementations, with the byte-equivalence proof points demonstrating identical computation. This is the alignment with the strongest evidence behind it: I1 is not merely claimed but mechanically demonstrated on the covered surfaces.

*I2, fail-closed enforcement.* OxDeAI's PEP pipeline (§8.2, §8.4) throws on any verification failure before the execution boundary, with no degradation path, and configuration errors produce explicit failure rather than permissive defaults. This realizes G6 and aligns with I2. The alignment is bounded by the same residual that bounds G6: the `signed_preferred` KRL default and the deployment obligation of correct PEP placement (§13.2, §13.4).

*I3, non-bypassability.* OxDeAI's structural PEP placement (§5.3, §8.1) makes the execution function reachable only through the verification pipeline, within the operating layer. This aligns with I3, bounded by the same limitation: non-bypassability holds within the runtime, not below it, and not against a deployment that fails to route execution through the guard (§13.4).

*I4, decision-artifact completeness.* OxDeAI's `AuthorizationV1` (§6) carries the full decision context — the bindings, identity, validity, and cryptographic material — in a self-contained, independently verifiable form, with the public-artifact projection (§6.4) ensuring the signed surface depends only on normative fields reproducible without engine internals. This aligns directly with I4. The audit chain and envelope (§9) extend the completeness to the sequence of governance events.

*I5, replayability.* OxDeAI's stateless verification surface (§9) and the offline-verifiability property establish that a verifier operating from public artifacts reaches the same verdict the PEP reached. The conformance vectors are themselves an instance of replayability: the protocol's behavior is reproducible from committed evidence by any implementation. This aligns with I5, with the precise scope noted in §9.3 — the auditor reproduces the verification of the decision, not the decision itself.

*I6, time-bounded evaluation without fail-open.* OxDeAI's strict zero-tolerance expiry (§6.5), with no grace period and no fail-open path at expiry, aligns directly with I6. The `issued_at`-not-enforced choice and the deployment obligation of clock synchronization are the bounds, both stated in §6.5 and §13.5.

The alignment is complete across the six invariants in the sense that OxDeAI has a mechanism for each, and the mechanisms are those the preceding sections specified. We do not claim formal conformance to the framework — no formal conformance process exists, and the framework defines a category rather than a certification — but the invariant-by-invariant mapping shows that OxDeAI's design satisfies each invariant as the framework states it, within the residuals the limitations section names.

### 14.3 The argument for independent convergence

OxDeAI's core architecture — canonicalization-v1, `AuthorizationV1`, the PEP boundary, `DelegationV1`, the cross-language conformance suite, the external-provider integration — was developed before the framework's publication. The alignment described in §14.2 is therefore convergent: two efforts arriving at structurally similar conclusions, not one implementing the other.

The case for independence rests on chronology and on the nature of the alignment. The chronology is that OxDeAI's design predates the framework's February 2026 publication; the protocol's artifacts, the canonicalization specification, and the conformance approach were established before the framework was available to implement. The nature of the alignment is that it is structural rather than terminological: OxDeAI did not adopt the framework's vocabulary, its invariant names, or its system-specific terminology (§14.5); it arrived at mechanisms that satisfy the invariants while describing them in its own terms developed independently.

Why would two independent efforts converge? Because the problem constrains the solution space. A system that must enforce a verifiable, non-bypassable, fail-closed boundary between a decision and its actuation is led toward a recognizable set of choices: a canonical serialization, because verification across parties requires byte-agreement; signed decision artifacts, because the decision must be verifiable without trusting the decider's runtime; replay protection, because a single decision should authorize a single action; time-bounded validity, because an authorization that never expires is a standing grant rather than a decision; offline verifiability, because audit requires reproducing the verdict from evidence. These are not arbitrary design preferences; they are close to forced by the requirements. Two designers who take the requirements seriously will land in similar territory.

This is why the convergence is evidence rather than coincidence. If OxDeAI had been built to the framework's specification, its alignment would demonstrate only that the author can follow a specification. Because it was built independently, its alignment demonstrates that the framework's invariants capture something real about the problem — that they are the properties the problem demands, not one team's stylistic choices. The convergence validates the framework as much as the framework contextualizes OxDeAI. Each independently arrived-at instance of a structure is evidence that the structure is necessary; OxDeAI is such an instance.

We state this carefully to avoid overclaiming in the other direction. Independent convergence is evidence that the invariants are well-chosen; it is not proof that they are complete or that no alternative architecture could satisfy the underlying requirements differently. The convergence shows that two efforts found the same region of the solution space; it does not show that the region is the only viable one. The honest claim is that the alignment is genuine, the development independent, and the convergence informative — not that convergence settles every question about how execution-time authorization should be built.

### 14.4 One design choice examined: the binary gate and escalation

The framework discusses, beyond the six invariants, the treatment of cases where a governance system cannot reach a binary decision and must hand off to a higher-level process — escalation, in the framework's terms, sometimes expressed as an ABSTAIN-with-escalation verdict. OxDeAI's treatment of this case is a design choice worth examining, because it is the point where OxDeAI's path through the category's design space is most clearly a choice rather than a forced move.

OxDeAI uses a binary execution gate (§5.6, §6.2). The authorization decision relevant to execution is ALLOW or non-ALLOW; there is no ABSTAIN verdict at the protocol layer. This is deliberate, and the rationale follows from the invariants themselves. Introducing an ABSTAIN verdict at the protocol level would make the authorization outcome depend on policy state in a way that varies by deployment — whether a given input produces ABSTAIN or a binary outcome would become a function of deployment-specific policy, undermining the determinism the protocol requires of its verdict (I1). And an ABSTAIN verdict, if mishandled by the layer that consumes it, could create a path to execution through unresolved authorization — precisely the fail-closed failure (I2) the protocol exists to prevent.

OxDeAI's resolution is to separate decision authority from workflow continuation. The decision authority — ALLOW or non-ALLOW — belongs to the protocol layer and is deterministic and verifiable. The workflow continuation — what happens when the answer is non-ALLOW, whether the action is terminally refused, escalated to a human, retried with narrowed parameters, or routed elsewhere — belongs to the orchestration layer above the protocol. OxDeAI does not preclude escalation; it locates escalation at the orchestration layer, where it belongs, rather than at the protocol layer, where it would compromise the determinism and fail-closed properties of the verdict. An orchestration system consuming OxDeAI's non-ALLOW signal may implement any escalation behavior it chooses; the protocol guarantees only that, until the orchestration layer resolves the matter, execution has not occurred.

This is consistent with the framework's concern that enforcement boundaries be non-bypassable: a first-class ABSTAIN verdict mishandled by orchestration is a bypass risk, and OxDeAI's binary gate removes that risk from the protocol layer by not introducing the verdict there. The framework raises escalation as a consideration; OxDeAI's answer is to keep the protocol's verdict binary and deterministic and to place escalation where it cannot compromise the verdict. We note this as a design choice rather than a forced move because a different protocol in the same category could reasonably make ABSTAIN first-class and manage the determinism and bypass concerns through other means; OxDeAI's choice reflects its priority on keeping the protocol-layer verdict maximally simple and verifiable. Future versions may revisit this if escalation patterns prove to need first-class protocol support (§15).

### 14.5 Discipline in referencing the framework

OxDeAI references the framework as a category vocabulary and as the source of the invariant structure, with attribution, under the framework paper's license. It does not adopt the framework's system-specific terminology. OxDeAI's components retain their own names — `AuthorizationV1`, `DelegationV1`, `SignedKRLV1`, `OxDeAIGuard`, canonicalization-v1 — which are the canonical references for OxDeAI throughout. Where the framework or any specific execution-time authorization system uses proprietary names for its mechanisms, OxDeAI does not adopt those names, and this paper does not use them.

This discipline serves two purposes. It keeps OxDeAI's identity its own: the protocol is described in its own terms, and a reader encounters OxDeAI's vocabulary, not a borrowed one. And it maintains a clean separation between the category (which is a shared intellectual space that the framework named and that OxDeAI occupies) and any specific system within it (whose particular terminology and implementation are that system's own). OxDeAI uses the category name and the invariant labels as shared vocabulary; it does not represent itself as derived from, affiliated with, or conformant to any specific system within the category.

The independent-development statement that accompanies this discipline — that OxDeAI's architecture was developed independently and predates the framework's publication — is part of the protocol's standing record and is maintained as accurate. The convergence is genuine and the framework is properly credited; the independence is real and stated; and OxDeAI's vocabulary remains its own. This is the posture appropriate to a protocol that converges with a framework without deriving from it.

### 14.6 What the convergence establishes

The convergence with the execution-time authorization framework establishes that OxDeAI is a member of a recognized category, satisfying the category's defining invariants through independently developed mechanisms. It gives readers a vocabulary for OxDeAI's design and locates the protocol in a space that the framework has mapped. And it provides evidence — through the independence of the convergence — that the invariants the protocol satisfies are properties the problem demands rather than choices the author preferred.

What the convergence does not establish is any claim of formal conformance, certification, or affiliation, none of which exist, and none of which the protocol claims. The framework defines a category; OxDeAI is a concrete protocol within it; the relationship is membership and convergence, not derivation or certification. The protocol stands on its own specification, its own mechanisms, and its own conformance evidence; the framework provides context and a vocabulary, and the convergence provides a particular kind of validation, but neither is load-bearing for the protocol's own claims. OxDeAI would be the same protocol, with the same guarantees and the same limitations, whether or not the framework existed; the framework helps locate and contextualize it, and the convergence helps validate the invariants both share.

The final section of the body turns from contextualizing the protocol to the work ahead: the future directions, beginning with the independent security review that §13.7 identified as the most important next step.

---

## 15. Future Work

The protocol is at a stage where its design is articulated, its behavior is verifiable, and its limitations are named. The work ahead falls into three horizons: the immediate priority of independent security review, the near-term protocol and tooling work that the limitations identify, and the longer-horizon questions that adoption and the evolution of the category will raise. We describe these as directions, not as a schedule; the protocol's development follows the discipline of specifying and verifying each step before claiming it, and the order in which these directions are pursued depends on adoption signals and review outcomes rather than on a fixed timeline.

### 15.1 The immediate priority: independent security review

The most important next step is independent security review by a third party, for the reasons §13.7 develops: every analysis in this paper is the author's own, and internal analysis is not a substitute for adversarial scrutiny by parties who did not design the protocol. Until such review occurs, the protocol's security claims are credible to the extent the author's analysis is sound and the mechanisms are verifiable, but they have not been tested against the assumptions an independent reviewer would challenge.

The form of review most appropriate to the protocol's current state is a cryptographic and protocol review targeting the specification artifacts and the verification model: the authorization and delegation artifacts, the canonicalization specification, the signed revocation list, the state-provider trust boundary, and the conformance approach. The review's value would be in identifying gaps the internal analysis missed, challenging the residuals the limitations section names, and subjecting the threat model to scrutiny from outside the author's frame. The protocol is structured to make such review tractable: the specification is complete enough to review, the conformance suite provides verifiable behavior to check against, and the limitations are stated rather than hidden, so a reviewer begins from an honest account rather than discovering the residuals themselves.

This priority is stated first because it bounds the others. There is little value in extending the protocol's surface — new profiles, new delegation depth, new middleware — before the existing surface has been independently reviewed, because extension before review compounds unreviewed design. The conservative path is to subject the current, well-specified surface to review, address what the review surfaces, and extend from a reviewed foundation.

### 15.2 Near-term protocol and tooling work

Several directions follow directly from the limitations (§13) and are near-term in the sense that the work is scoped and the path is clear, pending the prioritization that review outcomes will inform.

*Migrating the KRL default to `signed_required`.* The current `signed_preferred` default retains transport-trust semantics for unsigned-fallback cases (§13.2). The migration moves the default to `signed_required` and removes the deprecated `unsigned_legacy` mode, closing the transport-integrity residual at the default level rather than only for deployments that explicitly opt in. Because this is a breaking change to default behavior, it belongs to a major protocol version with a documented migration path, and the deprecation trajectory for `unsigned_legacy` is already in place.

*Extending cross-language conformance coverage.* The conformance suite covers the canonicalization, Profile C, and SignedKRLV1 surfaces cross-language, but the authorization-verification verdicts are not yet harnessed in Go and Python (§10.5). Extending the Go and Python harnesses to cover the full authorization-verification surface would close the gap between cross-language canonicalization coverage (which underlies everything) and cross-language verdict coverage (which is currently TypeScript-complete but not yet cross-language-complete on every verdict). This strengthens the determinism evidence (G5) on the surfaces not yet covered.

*Multi-hop delegation.* The current protocol supports single-hop delegation and rejects deeper chains (§7.4, §12.4). Extending to verified multi-hop delegation requires specifying the chain-narrowing semantics across hops, verifying the chain end-to-end, and adding conformance vectors for chains deeper than two. The conservative posture is to extend only after the single-hop case has accumulated deployment experience, so that multi-hop is built on a foundation that practice has exercised.

*An HTTP PEP middleware.* The current PEP is the higher-order-function guard; a ready-to-deploy HTTP middleware (§13.6) would lower the integration cost for deployments enforcing at an HTTP boundary, providing a drop-in enforcement boundary rather than requiring each deployment to wire the guard into its own HTTP handling.

*A structured decision-event schema.* The PEP emits per-decision events through a hook, but the event format is not yet a stable versioned schema (§13.6). Specifying this schema would allow observability tooling to be built against a stable contract, addressing the monitoring gap the production-readiness analysis identifies.

*A configuration-level warning for replay-store misconfiguration.* The in-memory replay store degrades silently to weaker semantics in multi-process or restart-resilient deployments (§13.3). A configuration-level signal that warns when a non-durable store is used in a context that requires durability would surface the misconfiguration that the protocol currently cannot detect.

These directions are scoped by the limitations that motivate them. None requires reconceiving the protocol; each extends or hardens a surface the current design already establishes.

### 15.3 Longer-horizon directions

Several directions are longer-horizon, either because they depend on adoption that has not yet occurred or because they address questions the category itself has not settled.

*Third-party independent implementation.* The conformance suite's strongest possible evidence — agreement between the project's implementations and a genuinely external one — awaits external adoption (§10.3). The protocol is designed to make third-party implementation tractable: the specification and vectors are public and self-contained. But the appearance of a third-party implementation is a function of adoption, not of the project's own effort, and it is therefore a longer-horizon direction. When it occurs, it would convert the cross-implementation evidence from reproducibility-across-project-maintained-implementations to reproducibility-including-independent-parties, materially strengthening the determinism claim.

*Formal verification.* The protocol's invariants are verified by conformance vectors and property tests, not by formal proof (§7.3 of the audit's standardization assessment notes this as out of scope for the current version). Formal verification of the core invariants — a machine-checked proof that the verification logic enforces the fail-closed property, for instance — would provide a stronger assurance than testing for deployments requiring it, such as those subject to regulatory certification. This is longer-horizon both because it is substantial work and because its value is highest for a class of high-assurance deployments that the protocol may or may not serve.

*Semantic stability of state representations.* The state binding hashes a state snapshot (§5.5); it does not address whether the state's semantic interpretation is stable across policy versions or schema changes. A state that hashes consistently but is interpreted differently under a changed policy version is a subtlety the current hash-based binding does not capture. Addressing semantic stability — ensuring that a state binding remains meaningful across the evolution of the policy that interprets it — is a longer-horizon refinement that the category as a whole has not settled.

*Post-quantum migration.* The protocol uses Ed25519 and SHA-256 (§13.5). A migration to post-quantum signature schemes would be required if cryptographically relevant quantum computers emerge. The protocol's signature surface is well-isolated, which would make the migration tractable when warranted, but the migration is longer-horizon because the threat is not present and the post-quantum signature standards are still settling. The direction is noted so that the protocol's eventual evolution toward post-quantum primitives is anticipated rather than retrofitted.

*Hardware-bound enforcement.* The protocol's non-bypassability holds within its operating layer, not below it (§13.4). Composing the protocol with hardware security modules, secure enclaves, or operating-system-level isolation — for deployments requiring assurance below the runtime layer — is a longer-horizon direction that would extend the protocol's enforcement guarantees into territory the software layer alone cannot reach. This is composition rather than protocol change: the protocol would remain as specified, deployed within a stronger isolation boundary that the protocol does not itself provide.

### 15.4 The path established

The directions in this section share a common discipline, the same one that produced the current protocol: specify before implementing, verify before claiming, name residuals rather than eliding them, and extend from a reviewed and exercised foundation rather than ahead of one. The immediate priority — independent security review — exemplifies the discipline: it subjects the current surface to scrutiny before that surface is extended, so that extension builds on reviewed ground.

This discipline determines the order more than any timeline does. The protocol advances by establishing each property solidly before claiming the next, and the future work is the continuation of that pattern: review the current surface, harden the defaults and close the coverage gaps the limitations name, and consider the longer-horizon extensions as adoption and review inform which of them the protocol's users actually need. The protocol's value at each stage is what has been specified and verified, not what is planned; the future work describes the directions that value may extend in, under the same conservative discipline that produced the value already established.

---

That concludes the body of the paper. The preceding sections specified a deterministic execution authorization protocol — its decision artifacts, its enforcement architecture, its verification model, its conformance methodology, and its interoperability profiles — established its security goals and mapped each to verifiable mechanisms, named its limitations and residual trust assumptions without minimizing them, located it within the execution-time authorization category through independent convergence, and described the work ahead. The appendices that follow provide the complete artifact specifications, the canonicalization grammar, the error code taxonomy, and the conformance vector catalog that an independent implementer would require.

---


# Appendices and References

> **Reconciliation note (remove before publication).** The appendices below
> contain exact field names, encodings, signature values, vector identifiers,
> and error codes. Every concrete value must be reconciled against the live
> repository before publication: the type definitions in `@oxdeai/core`, the
> conformance vector files under `docs/spec/test-vectors/` and
> `packages/conformance/vectors/`, the harness assertion counts, the
> `SignedKRLV1` and `AuthorizationV1` specifications under `docs/spec/`, and the
> error-code constants in the implementation. Where a value is reproduced from
> the body or from the working specifications, it is marked **[verify]**.
> Truncated signatures are marked **[full value required]** — an appendix must
> carry the complete value, never an ellipsis, because the surrounding claim is
> mechanical verifiability.

---

## Appendix A: Protocol Artifact Field Catalog

This appendix catalogs the fields of the three signed protocol artifacts. For
each field it gives the semantic role, whether the field is required, and notes
on encoding where the two wire encodings (Appendix A.4) differ. The authoritative
field definitions are the type declarations in the reference implementation;
this catalog is a reference companion and must be reconciled against those
declarations **[verify]**.

### A.1 AuthorizationV1

The central decision artifact (body §6). Fields are listed in semantic groups,
not in serialization order; the canonical serialization order is determined by
canonicalization-v1 (Appendix B), which sorts keys by UTF-8 byte order.

**Decision**

| Field | Required | Role |
|-------|----------|------|
| `decision` | yes | The verdict. The execution-relevant value is `ALLOW`; any other value, or any verification failure, produces non-execution (body §6.2). No `ABSTAIN` value is defined (body §14.4). |

**Identity**

| Field | Required | Role |
|-------|----------|------|
| `issuer` | yes | Identifies the issuing policy engine. Checked against verifier expectation; mismatch → `AUTH_ISSUER_MISMATCH`. |
| `audience` | yes | Identifies the intended verifier/enforcement context. Mismatch → `AUTH_AUDIENCE_MISMATCH`. |

**Binding**

| Field | Required | Role |
|-------|----------|------|
| `intent_hash` | yes | `SHA-256(canonicalize(proposed_action))`. Recomputed and compared by the verifier; mismatch → non-execution (body §6.4). |
| `state_hash` | yes | Canonical hash of the policy state snapshot evaluated. Signed in all profiles; re-verified against live state in Profile C (body §6.4, §11.1). |
| `policy_id` | yes | Content hash of the policy configuration. Identifies policy; does NOT authenticate issuer (body §5.4). |

**Uniqueness**

| Field | Required | Role |
|-------|----------|------|
| `auth_id` | yes | Unique single-use identifier. Consumed via the replay store; second presentation → `AUTH_REPLAY` (body §6.2, §8.2). |
| `nonce` | optional | Present in the type. In the current version replay protection is enforced via `auth_id`, not via a separately verified `nonce`; noted as a partial element in the protocol audit. **[verify intended status]** |

**Temporal**

| Field | Required | Role |
|-------|----------|------|
| `issued_at` | yes | Issuance timestamp. Informational; NOT enforced as a lower bound (body §6.5). |
| `expiry` | yes (Enc. A) | Upper bound of validity. Strict zero-tolerance: valid iff `now < expiry` (body §6.5). |
| `expires_at` | yes (Enc. B) | Encoding-B name for the temporal upper bound. When both `expiry` and `expires_at` are present, `expiry` takes precedence (body §6.3). |

**Cryptographic**

| Field | Required | Role |
|-------|----------|------|
| `alg` | yes | Signature algorithm identifier. Matched case-exactly: `Ed25519` (Enc. A) or `ed25519` (Enc. B). `EdDSA`/`ED25519` → `AUTH_ALG_UNSUPPORTED` (body §6.3). |
| `kid` | yes | Signing-key identifier. Resolves the public key from `trustedKeySets`. Treated as opaque. |
| `signature` | yes | Ed25519 signature over the signing preimage (Appendix A.4). base64 (Enc. A) / base64url-no-padding (Enc. B). |
| `capability` | optional | Optional capability designation. See reference implementation for current semantics. **[verify]** |

**Engine-internal fields (NOT part of the public artifact).** The public
projection (`toPublicAuthorizationV1`, body §6.4) strips engine-internal fields
before any signing or hashing surface. The following are examples of fields the
projection removes; they MUST NOT appear in the signed preimage and MUST NOT be
relied upon by a verifier: `authorization_id`, `engine_signature`,
`state_snapshot_hash`, `policy_version`, `expires_at` where used as an
engine-internal legacy alias. **[verify exact list against `toPublicAuthorizationV1`]**

### A.2 DelegationV1

The scoped-delegation artifact (body §7). A `DelegationV1` is meaningful only in
relation to a presented parent `AuthorizationV1`.

| Field | Required | Role |
|-------|----------|------|
| `parent_auth_hash` | yes | `SHA-256(canonicalize(toPublicAuthorizationV1(parent)))`. Binds the delegation to one specific parent (body §7.2). Mismatch with presented parent → rejection. |
| `scope` | yes | The narrowed authority. Each dimension must be ≤ the parent's; expansion → `DELEGATION_SCOPE_VIOLATION` (body §7.3). |
| `scope.tools` | yes | Permitted tool allowlist; must be a subset of the parent's. |
| `scope.max_amount` | yes | Budget ceiling; must not exceed the parent's. **[verify field name]** |
| `scope.max_actions` | optional | Action-count ceiling; must not exceed the parent's. **[verify field name and required status]** |
| `scope.expiry` | yes | Delegation expiry; must not extend beyond the parent's. |
| `alg` | yes | Signature algorithm identifier (as A.1). |
| `kid` | yes | Signing-key identifier (as A.1). |
| `signature` | yes | Ed25519 signature over the domain-prefixed delegation preimage (prefix `OXDEAI_DELEGATION_V1\n`, Appendix A.4). |

Additional delegation identity/uniqueness fields (e.g., a delegation identifier
consumed for replay, body §7.5) follow the reference implementation. **[verify
exact field names for the delegation replay identifier]**

The single-hop constraint (body §7.4) is a verification rule, not a field: a
chain deeper than one hop → `DELEGATION_SINGLE_HOP`.

### A.3 SignedKRLV1

The signed key revocation list (body §8.4, §11). A provider-neutral protocol
artifact carrying revoked key identifiers, verified before revocation data is
accepted in `signed_required` mode.

| Field | Required | Role |
|-------|----------|------|
| `revoked_kids` | yes | The set of revoked key identifiers. Duplicate entries are tolerated in verification (see the duplicate-kids byte-equivalence vector, Appendix C.3). **[verify field name]** |
| `krl_version` | yes | Monotonic version/watermark. A decrease → `KRL_VERSION_REGRESSION`. **[verify field name]** |
| `not_after` | yes | Expiry of the revocation list. `now >= not_after` → `KRL_EXPIRED`. **[verify field name]** |
| `alg` | yes | Signature algorithm identifier. |
| `kid` | yes | Signing-key identifier for the KRL signer. |
| `signature` | yes | Ed25519 signature over the domain-prefixed KRL preimage (prefix `OXDEAI_KRL_V1\n`). |

KRL verification reason codes are catalogued in Appendix D. Note the ownership
split (body, audit P1-4): some reason codes are produced by the adapter/mode
logic and some are passed through from the core verifier.

### A.4 Wire encodings and the signing preimage

Two encodings of `AuthorizationV1` (body §6.3). Both encode the same logical
artifact.

**Encoding A (core-native).**
- `alg` literal: `Ed25519` (matched case-exactly).
- Temporal upper-bound field: `expiry`.
- Signature encoding: base64.
- Signing preimage: domain-prefixed. Preimage bytes =
  `"OXDEAI_AUTH_V1\n"` ++ `canonicalize(signed_fields)`.

**Encoding B (external-provider-compatible).**
- `alg` literal: `ed25519` (lowercase, matched case-exactly).
- Temporal upper-bound field: `expires_at`.
- Signature and public-key encoding: base64url, no padding (`=` stripped).
- Public keys: raw 32-byte Ed25519, no DER/PEM/JWK wrapper.
- Signing preimage: NOT domain-prefixed. Preimage bytes =
  `canonicalize(signing_payload)`.

**Domain-separation prefixes** (Encoding A and the other signed artifacts):

| Artifact | Prefix |
|----------|--------|
| `AuthorizationV1` (Enc. A) | `OXDEAI_AUTH_V1\n` |
| `DelegationV1` | `OXDEAI_DELEGATION_V1\n` |
| `SignedKRLV1` | `OXDEAI_KRL_V1\n` |

**Precedence rule.** When both `expiry` and `expires_at` are present, `expiry`
governs. An artifact with expired `expiry` and valid `expires_at` is rejected as
expired (vector `auth-expiry-wins-over-expires-at`, Appendix C).

---

## Appendix B: canonicalization-v1

The deterministic serialization over which all signatures and hashes are
computed (body §6.4, §10). The byte-exactness of this procedure across
implementations is the precondition for cross-implementation verification
(body §10.1). The authoritative specification is
`docs/spec/core/canonicalization-v1.md`; this appendix summarizes the rules
**[verify against the specification]**.

### B.1 Serialization rules

A conforming canonicalization of a value produces UTF-8 bytes according to the
following rules:

1. **Object key ordering.** Object keys are sorted by UTF-8 byte order
   (lexicographic over the UTF-8 encoding of the key), not by code point and not
   by locale. Key insertion order does not affect output.

2. **Unicode normalization.** String values and keys are normalized to NFC
   (Normalization Form C) before serialization.

3. **Numeric encoding.** Only safe integers are permitted. Floating-point values
   are rejected (`FLOAT_NOT_ALLOWED`). Integers outside the safe-integer range
   are rejected (`UNSAFE_INTEGER_NUMBER`); large integers are represented via the
   bigint mechanism the specification defines. **[verify exact numeric rules and
   error names]**

4. **Duplicate key rejection.** An object containing duplicate keys is rejected
   (`DUPLICATE_KEY`). This prevents serialization ambiguity from repeated keys.

5. **Unsupported type rejection.** Values of unsupported types — `undefined`,
   functions, symbols — are rejected (`UNSUPPORTED_TYPE`).

6. **No insignificant whitespace.** The canonical form contains no insignificant
   whitespace; the serialization is the compact form (equivalent to JSON with
   sorted keys and `(",", ":")` separators, over UTF-8, no trailing newline).

### B.2 Hashing

Canonical hashing computes `SHA-256` over the canonical UTF-8 bytes. The
`intent_hash`, `state_hash`, `policy_id`, and `parent_auth_hash` are all
SHA-256 over the canonicalization of their respective inputs (body §6.4, §7.2).

### B.3 Grammar (informative)

The following grammar is an informative summary of the value space
canonicalization-v1 accepts. It is not a substitute for the normative
specification **[verify / replace with the normative grammar]**.

```
value      := object | array | string | integer | boolean | null
object     := "{" [ member ( "," member )* ] "}"      ; keys UTF-8 byte-sorted, unique
member     := string ":" value
array      := "[" [ value ( "," value )* ] "]"         ; order preserved
string     := <NFC-normalized UTF-8, JSON-escaped>
integer    := <safe integer; floats rejected>
boolean    := "true" | "false"
null       := "null"
```

### B.4 Cross-language note

canonicalization-v1 is implemented independently in TypeScript
(`packages/core/src/crypto/hashes.ts`), Go
(`go-harness/canonicalization_verify.go`), and Python
(`python-harness/verify_canonicalization_vectors.py`) **[verify paths]**. The
canonicalization vectors (Appendix C.1) verify byte-agreement across these
implementations on the covered inputs.

---

## Appendix C: Conformance Vector Catalog

This appendix catalogs the conformance vectors by surface (body §10). The
catalog is a reference to the vector suite, not a substitute for it; the
authoritative vectors are the data files in the repository, and the assertion
counts and vector identifiers below must be reconciled against them
**[verify all counts and identifiers]**.

The current suite comprises **265 assertions [verify]**: 209 TypeScript, 28 Go,
28 Python (body §10.5). Coverage is full cross-language on canonicalization,
Profile C, and SignedKRLV1; TypeScript-complete with partial cross-language
coverage on the broader authorization-verification surface (body §10.5).

### C.1 Canonicalization vectors

File: `docs/spec/test-vectors/canonicalization-v1.json` **[verify path]**.
Approximately **11 vectors [verify]**. Cover: object-key ordering, key-order
invariance of hashes, NFC normalization, safe-integer encoding, float rejection,
duplicate-key rejection, unsupported-type rejection.

Representative identifiers (illustrative — **[verify exact IDs]**):
`v1-object-key-ordering` … `i4-float-timestamp-rejected`.

### C.2 Authorization vectors

File: `docs/spec/test-vectors/authorization-v1.json` and the TypeScript
authorization-signature/verification vector sets **[verify paths]**.
Approximately **12 portable `authorization-v1.json` vectors [verify]** plus the
broader TypeScript authorization vector sets.

Covered cases include:

| Vector (illustrative) | Property verified |
|-----------------------|-------------------|
| `authorization-sig-001` | Encoding A valid signature accepted |
| `authorization-sig-010` | Encoding B valid signature accepted |
| `authorization-sig-002` | Tampered signature → `AUTH_SIGNATURE_INVALID` |
| `authorization-sig-003` | Wrong kid → `AUTH_KID_UNKNOWN` |
| `authorization-sig-005` | Audience mismatch → `AUTH_AUDIENCE_MISMATCH` |
| `authorization-sig-004` | Issuer mismatch → `AUTH_ISSUER_MISMATCH` |
| `authorization-sig-007` | Expired → `AUTH_EXPIRED` |
| `authorization-sig-008` | Replay → `AUTH_REPLAY` |
| `authorization-sig-009`, `-011`, `-012` | Algorithm rejection (`EdDSA`/`ED25519`/unsupported) → `AUTH_ALG_UNSUPPORTED` |
| `auth-expiry-wins-over-expires-at` | `expiry`/`expires_at` precedence (expired `expiry` + valid `expires_at` → expired) |
| `auth-intent-mismatch`, `auth-intent-action-match-1` | Intent binding via independent `intent_hash` derivation from `proposed_action` |
| `pb-trust-oxdeai-key-allow` | Profile B: OxDeAI key in `trustedKeySets` → ALLOW |
| `pb-trust-provider-key-rejected` | Profile B: provider receipt key absent from `trustedKeySets` → `AUTH_KID_UNKNOWN` |

**[verify every identifier and the expected error string against the suite]**

### C.3 Clock-semantics vectors

File: `docs/spec/test-vectors/clock-semantics-verification.json` **[verify]**.
Approximately **5 vectors / 10 assertions [verify]**.

| Vector (illustrative) | Property verified |
|-----------------------|-------------------|
| `clock-001` | Last valid second (`now = expiry - 1`) → ok |
| `clock-002` | One past expiry (`now = expiry + 1`) → `AUTH_EXPIRED` |
| `clock-003` | Verifier clock behind `issued_at` → still accepted (`issued_at` not a lower bound) |
| `clock-004`, `clock-005` | Encoding-B variants of the boundary conditions |

**[verify identifiers]**

### C.4 Key-lifecycle vectors

File: `docs/spec/test-vectors/key-lifecycle-verification.json` **[verify]**.
Approximately **10 vectors / 20 assertions [verify]**. Cover key status
(active, retired, revoked), `not_before` and `not_after` windows, revocation
overriding a valid time window, and wrong-kid-known-issuer.

| Vector (illustrative) | Property verified |
|-----------------------|-------------------|
| `key-lifecycle-002` | Revoked key → rejected |
| `key-lifecycle-003` | Future `not_before` → inactive |
| `key-lifecycle-004`, `-006`, `-008` | Expired `not_after` windows → inactive |
| `key-lifecycle-007` | Retired key within dual-sign overlap window → ok |
| `key-lifecycle-009` | Revocation overrides valid time window |

**[verify identifiers]**

### C.5 Profile C state-verification vectors

File: `docs/spec/test-vectors/profile-c-state-verification.json` **[verify]**.
**8 modes (001–008) [verify]**, validated cross-language in Go and Python
(body §10.5). Modes 001–005 cover state-hash semantics; modes 006–008 cover the
Encoding-B path with independent Ed25519 signature verification (no domain
prefix; base64url).

| Mode | Property verified |
|------|-------------------|
| `profile-c-001` … `-005` | State-hash verification semantics, including strategy-mismatch deterministic failure (`-003`) |
| `profile-c-006` … `-008` | Encoding-B Profile C: independent Encoding-B signature verification + state-hash comparison |

**[verify mode identifiers and the Encoding-B signature value in C.7]**

### C.6 SignedKRLV1 vectors

File: `docs/spec/test-vectors/signed-krl-v1.json` **[verify]**.
**9 vectors [verify]**, validated cross-language in Go and Python.

| Vector (illustrative) | Property verified |
|-----------------------|-------------------|
| `KRL_SIGNED_VALID` | Valid signed KRL accepted |
| `KRL_SIGNED_EXPIRED` | `now >= not_after` → `KRL_EXPIRED` |
| `KRL_VERSION_REGRESSION` | Version decrease → `KRL_VERSION_REGRESSION` |
| `KRL_DUPLICATE_REVOKED_KIDS` | Duplicate revoked kids; serves as the cross-language byte-equivalence anchor (C.7) |
| (malformed / unsupported-alg / unknown-signing-kid / inactive-signing-key variants) | Corresponding reason codes (Appendix D) |

**[verify the full set of 9 identifiers]**

### C.7 Byte-equivalence proof points

The proof points (body §10.4) are specific signature values that verify
identically across TypeScript, Go, and Python, demonstrating byte-identical
preimage computation.

**Duplicate-kids SignedKRLV1 signature (`KRL_DUPLICATE_REVOKED_KIDS`):**

```
+mwEd2QP5+tx6pCKAiF8BKzMAHf1c28mcTQF575pDn/DwgRiJ+PkYnv+sasIdgj1S7E9mSZZK1pOTP43nlnsDA==
```

**[verify — full value required; confirm exact bytes against the suite]**

**Profile C Encoding-B artifact signature (modes 006–008):**

```
jMyip7h-GMgl2nV_q8Cz-MuqbD4vgba6vseRejY13e-w8WZeW7UU7ft58JHJFJR0fyZ3NGXvjJBGeKSSJLThCA
```

**[verify — full value required; this is the base64url-no-padding Encoding-B
signature; confirm exact bytes against the suite]**

Both values are re-verified on every run of the conformance suite across all
three implementations; their identical verification is the mechanical proof of
byte-equivalent canonicalization (body §10.4).

### C.8 Guard PEP conformance (GPC) and property tests

The PEP conformance vectors (GPC series) and the property-based determinism
tests verify the enforcement behavior (body §8.4). These are implementation
tests in the reference implementation rather than portable cross-language
vectors **[verify location and naming]**.

GPC series (illustrative): GPC-1 … GPC-11, each confirming that a specific
failure mode (kill-switch denial, invalid signature, audience mismatch, expiry,
state-hash mismatch, replay, CAS conflict, missing artifact, missing required
fields) blocks the execution boundary, the state commit, and the pre-execution
hook.

Property tests (illustrative): determinism invariants I1–I6 / D-1–D-6, the
delegation-chain property tests, and the cross-adapter validation tests
**[verify identifiers and counts]**.

---

## Appendix D: Error Code Taxonomy

The verification primitives and the PEP report failures via specific reason
codes, returned in the `VerificationResult` (body §9.2) and reported in a
deterministic order (body §9.2). The codes below are grouped by surface. The
authoritative set is the error-code constants in the implementation; this
taxonomy must be reconciled against them **[verify every code string]**.

### D.1 Authorization verification

| Code | Meaning |
|------|---------|
| `AUTH_SIGNATURE_INVALID` | Signature did not verify against the resolved key. |
| `AUTH_KID_UNKNOWN` | Signing key not present in `trustedKeySets`. |
| `AUTH_ALG_UNSUPPORTED` | Algorithm identifier not an accepted case-exact literal. |
| `AUTH_KEY_INACTIVE` | Resolved key present but revoked or outside its validity window. **[verify exact code]** |
| `AUTH_ISSUER_MISMATCH` | Issuer does not match verifier expectation. |
| `AUTH_AUDIENCE_MISMATCH` | Audience does not match verifier configuration. |
| `AUTH_EXPIRED` | Observed time at or past effective expiry. |
| `AUTH_REPLAY` | `auth_id` already consumed. |
| `TRUSTED_KEYSETS_REQUIRED` | Strict mode with no `trustedKeySets` configured. |
| (intent-mismatch code) | Recomputed `intent_hash` ≠ artifact `intent_hash`. **[verify exact code name]** |
| (policy-id-mismatch code) | `policy_id` ≠ expected policy. **[verify exact code name]** |

### D.2 Canonicalization

| Code | Meaning |
|------|---------|
| `DUPLICATE_KEY` | Object contains duplicate keys. |
| `FLOAT_NOT_ALLOWED` | Floating-point value encountered. |
| `UNSAFE_INTEGER_NUMBER` | Integer outside the safe range without the bigint mechanism. **[verify]** |
| `UNSUPPORTED_TYPE` | Value of unsupported type (`undefined`, function, symbol). |

### D.3 Delegation

| Code | Meaning |
|------|---------|
| `DELEGATION_SCOPE_VIOLATION` | Delegation scope expands the parent's on some dimension. |
| `DELEGATION_SINGLE_HOP` | Delegation chain deeper than one hop. |
| (parent-binding-mismatch code) | Recomputed `parent_auth_hash` ≠ presented parent. **[verify exact code name]** |

### D.4 SignedKRLV1

Reason-code ownership is split (body §8.4, audit P1-4): some codes are produced
by the adapter/mode logic (Sift-local), others are passed through from the core
verifier as opaque strings.

**Core verifier (passed through):**

| Code | Meaning |
|------|---------|
| `KRL_MALFORMED` | KRL structurally invalid. |
| `KRL_SIG_INVALID` | KRL signature did not verify. |
| `KRL_EXPIRED` | `now >= not_after`. |
| `KRL_UNSUPPORTED_ALG` | KRL algorithm not supported. |
| `KRL_UNKNOWN_SIGNING_KID` | KRL signing key unknown. |
| `KRL_SIGNING_KEY_INACTIVE` | KRL signing key inactive. |
| `KRL_VERSION_REGRESSION` | KRL version decreased. |

**Adapter/mode logic (provider-local):**

| Code | Meaning |
|------|---------|
| `KRL_UNSIGNED_IN_SIGNED_REQUIRED` | Unsigned KRL presented in `signed_required` mode. |
| `KRL_MISSING_VERIFY_CALLBACK` | Signed KRL with no `verifyKrl` callback configured. |
| `KRL_VERIFY_CALLBACK_ERROR` | The `verifyKrl` callback threw. |
| `KRL_VERIFY_RESULT_INCOMPLETE` | The `verifyKrl` callback returned an incomplete result. |

**[verify all KRL code strings and the ownership split against the implementation]**

### D.5 PEP enforcement (exceptions)

The PEP signals enforcement failures by throwing rather than by returning a
result (body §8). Illustrative exception types **[verify names]**:

| Exception | Condition |
|-----------|-----------|
| `OxDeAIDenyError` | Engine decision is not ALLOW. |
| `OxDeAIAuthorizationError` | Verification failure (missing artifact, failed check, replay-store unavailable, state-hash computation failure). |
| `OxDeAIConflictError` | CAS version conflict on state commit. |

---

## References

> **Reconciliation note (remove before publication).** The reference list below
> assembles the author-year citations used in the body into full entries. Verify
> each entry's exact title, venue, year, and identifier before publication. The
> Meyman entry's DOI is reproduced from the alignment work and must be confirmed.
> Add or remove entries to match the final body text after the external-review
> pass.

[Anderson 2008] Anderson, R. *Security Engineering: A Guide to Building
Dependable Distributed Systems.* 2nd ed. Wiley, 2008.

[Bernstein et al. 2012] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., and
Yang, B.-Y. "High-speed high-security signatures." *Journal of Cryptographic
Engineering* 2(2), 2012, pp. 77–89. (Ed25519.)

[Birgisson et al. 2014] Birgisson, A., Politz, J. G., Erlingsson, Ú., Taly, A.,
Vrable, M., and Lentczner, M. "Macaroons: Cookies with Contextual Caveats for
Decentralized Authorization in the Cloud." *Network and Distributed System
Security Symposium (NDSS)*, 2014.

[biscuit-auth] Biscuit Authorization. Specification and reference
implementation. https://www.biscuitsec.org/ **[verify citation form and access
date]**

[Dennis and Van Horn 1966] Dennis, J. B., and Van Horn, E. C. "Programming
Semantics for Multiprogrammed Computations." *Communications of the ACM* 9(3),
1966, pp. 143–155.

[FIPS 180-4] National Institute of Standards and Technology. *Secure Hash
Standard (SHS).* FIPS PUB 180-4, 2015. (SHA-256.)

[Hardt 2012] Hardt, D., ed. "The OAuth 2.0 Authorization Framework." RFC 6749,
IETF, 2012.

[Jones 2015] Jones, M., Bradley, J., and Sakimura, N. "JSON Web Token (JWT)."
RFC 7519, IETF, 2015.

[Levy 1984] Levy, H. M. *Capability-Based Computer Systems.* Digital Press,
1984.

[Meyman 2026] Meyman, E. "Execution-Time Authorization for AI Agents: A Formal
Framework for Deterministic Governance Boundaries." FERZ, Inc., February 2026.
DOI: 10.5281/zenodo.18764561. Licensed CC-BY-4.0. **[verify DOI, exact title,
and date]**

[Miller 2006] Miller, M. S. *Robust Composition: Towards a Unified Approach to
Access Control and Concurrency Control.* PhD thesis, Johns Hopkins University,
2006. (Object-capability model.)

[RFC 8032] Josefsson, S., and Liusvaara, I. "Edwards-Curve Digital Signature
Algorithm (EdDSA)." RFC 8032, IETF, 2017.

[W3C VC] World Wide Web Consortium. *Verifiable Credentials Data Model.* W3C
Recommendation. **[verify version and year used]**

---
