# OxDeAI Alignment with AARM (Autonomous Action Runtime Management)

**Document type:** Standardization positioning artifact
**Status:** Working draft
**Scope:** Conceptual alignment mapping only - no protocol changes, no code changes, no conformance vector changes
**Related documents:** `docs/standardization/execution-time-authorization-alignment.md`, `docs/audits/protocol-audit-post-interoperability.md`

---

## 1. Purpose and Scope

This document positions OxDeAI relative to AARM's conformance requirements as specified in:

> Errico, H. "Autonomous Action Runtime Management (AARM): A System Specification for Securing AI-Driven Actions at Runtime." arXiv:2602.09433, February 2026.

Cited throughout as [Errico 2026], with section references matching the paper's own numbering (e.g., [Errico 2026, §VII-B1]).

AARM organizes its conformance surface into nine requirements: six Core requirements (R1-R6, all MUST) and three Extended requirements (R7-R9, all SHOULD) [Errico 2026, §VII-A]. This document maps OxDeAI's architecture and artifacts against each of the nine, following the same per-requirement structure, status vocabulary, and evidentiary discipline as `execution-time-authorization-alignment.md`.

**What this document is:**

- A mapping artifact for standardization positioning
- An explicit record of which OxDeAI protocol components address which AARM requirements
- An honest account of which AARM requirements OxDeAI does not attempt to satisfy, and why
- A structural note on where OxDeAI's scope could participate in a larger AARM-conformant deployment

**What this document is not:**

- A conformance claim against AARM
- A roadmap toward AARM conformance
- A protocol change, a code change, or a conformance vector change
- A marketing document

Every status below is backed by a specific AARM section citation, an OxDeAI code path or spec section, or an issue number. Where a requirement is not satisfied, the residual is named explicitly rather than folded into a qualified "partial" claim without explanation.

---

## 2. Institutional Context

AARM and OxDeAI currently occupy different institutional positions, and this document does not treat that difference as evidence for or against either system's technical merit. AARM is governed by a CSA (Cloud Security Alliance) Technical Working Group, has a published conformance process [Errico 2026, §VII], is documented in an arXiv-published companion paper, and maintains an active implementer/builder registry. OxDeAI has none of these: it has no external governance body, no published third-party conformance process, and has not undergone independent security review (tracked in issue #139, referenced in `docs/whitepaper/oxdeai-deterministic-execution-authorization.md` §13.7). These are stated as facts about institutional status, not as a ranking of technical quality. AARM's builder/registry count is not used anywhere in this document as evidence for a technical claim; it has no bearing on whether a given requirement is satisfied by a given code path.

---

## 3. Requirement-by-Requirement Mapping

| Requirement | Level | OxDeAI status | Evidence |
|---|---|---|---|
| R1: Pre-Execution Interception | MUST | Satisfied | §3.1 |
| R2: Context Accumulation | MUST | Out of Scope by Design | §3.2 |
| R3: Policy Evaluation with Intent Alignment | MUST | Out of Scope by Design | §3.3 |
| R4: Authorization Decisions | MUST | Out of Scope by Design | §3.4 |
| R5: Tamper-Evident Receipts | MUST | Partially Satisfied | §3.5 |
| R6: Identity Binding | MUST | Partially Satisfied | §3.6 |
| R7: Semantic Distance Tracking | SHOULD | Out of Scope by Design | §3.7 |
| R8: Telemetry Export | SHOULD | Partially Satisfied | §3.8 |
| R9: Least Privilege Enforcement | SHOULD | Satisfied | §3.9 |

### 3.1 R1: Pre-Execution Interception (MUST)

**AARM requirement:** "All actions must be intercepted before execution." [Errico 2026, §VII-B1]

**OxDeAI status: Satisfied.** `OxDeAIGuard` (`packages/guard/src/guard.ts`) is a higher-order function that wraps `execute()`; the guarded action is only reachable via the returned closure, and every verification step (ALLOW decision, `AuthorizationV1` validity, state hash match, intent hash match, replay check, audience match, issuer match) must pass before `execute()` is called. This is the same structural mechanism documented as ETA I3 (non-bypassability) in `docs/standardization/execution-time-authorization-alignment.md` §3.3, and is verified by the GPC (Guard PEP Conformance) property tests in `packages/guard/src/test/guard.pep-conformance.test.ts`. As with the ETA mapping, this claim is bounded to the TypeScript/Node.js process layer; OxDeAI makes no hardware- or OS-level interception claim.

### 3.2 R2: Context Accumulation (MUST)

**AARM requirement:** actions are evaluated "against accumulated session state including prior operations and data accessed" [Errico 2026, §VII-B2, §IV-C].

**OxDeAI status: Out of Scope by Design.** OxDeAI's verification primitives are, by design, pure functions of an artifact and explicit inputs, with "no dependence on running-system state beyond what is passed in" (whitepaper §9.1). This statelessness is the mechanism behind G5 (deterministic verification): "two conformant implementations, given the same authorization artifact and the same verifier configuration, produce identical verification verdicts" (whitepaper §2, G5). An accumulated-session-state evaluator is necessarily stateful across a sequence of prior actions, which is incompatible with a verification model whose determinism guarantee depends on having no implicit dependence on accumulated runtime state. OxDeAI's replay tracking (`auth_id` consumption in `ReplayStore`) is a narrow, single-use check, not the general session-context accumulator AARM specifies, and is explicitly carved out of the stateless verification surface for this reason (whitepaper §9.1: "replay consumption is a stateful operation belonging to the PEP, not the stateless verifier").

### 3.3 R3: Policy Evaluation with Intent Alignment (MUST)

**AARM requirement:** policy assessment considering "both static rules and contextual alignment with user intent" [Errico 2026, §VII-B3].

**OxDeAI status: Out of Scope by Design.** OxDeAI's `PolicyEngine` evaluates a deterministic rule set (kill-switch, allowlist, budget, per-action cap, velocity, concurrency, recursion-depth checks — see `ReasonCode` in `packages/core/src/types/policy.ts`) against a canonically hashed intent and state. It does not perform "contextual alignment with user intent" in AARM's sense, which is a semantic judgment about whether an action is faithful to an underlying goal rather than a check against explicit, canonicalizable rules. Introducing such a judgment into the verification path would reintroduce the same determinism conflict named in §3.2: canonicalization-v1 requires a serialization procedure with no ambiguous or non-reproducible inputs (`docs/spec/core/canonicalization-v1.md`), and a semantic intent-alignment judgment is not, in general, byte-reproducible across independent implementations in the way G5 requires.

### 3.4 R4: Authorization Decisions (MUST)

**AARM requirement:** the system must enforce one of five outcomes — ALLOW, DENY, MODIFY, STEP_UP, DEFER [Errico 2026, §VII-B4].

**OxDeAI status: Out of Scope by Design.** OxDeAI's `Decision` type (`packages/core/src/types/policy.ts:6-9`) is exactly `"ALLOW" | "DENY"` — a binary gate, not a five-outcome decision space. This is a deliberate design choice, discussed at length in `docs/standardization/execution-time-authorization-alignment.md` §4 in the context of the ETA framework's ABSTAIN-with-escalation verdict: OxDeAI keeps the protocol-layer verdict narrow and deterministic (ALLOW or non-ALLOW), and treats everything a richer outcome space would otherwise encode — parameter modification, step-up approval, deferral — as an orchestration-layer concern above the PEP. AARM's MODIFY outcome overlaps with structured argument provenance, tracked independently in issue #217; AARM's STEP_UP and DEFER outcomes overlap with approval/workflow semantics, tracked independently in issue #218. Neither #217 nor #218 proposes adding outcomes to `AuthorizationV1.decision`; both describe orchestration- or provenance-layer work that sits above the current binary artifact. A five-outcome decision space is incompatible with a verification model whose determinism guarantee (G5) depends on the verdict being a pure function of canonicalizable inputs — MODIFY, STEP_UP, and DEFER each presuppose state or workflow context beyond what the stateless verifier evaluates (§3.2, §3.3).

### 3.5 R5: Tamper-Evident Receipts (MUST)

**AARM requirement:** "every action, its accumulated context, the policy decision, and the execution outcome must be recorded in tamper-evident receipts" [Errico 2026, §VII-B5].

**OxDeAI status: Partially Satisfied.** The policy-decision component is covered: `AuthorizationV1` (`docs/spec/artifacts/authorization-v1.md`) is a signed, tamper-evident artifact binding a decision to a specific `intent_hash` and `state_hash`, and `HashChainedLog` (`packages/core/src/audit/HashChainedLog.ts`) provides a tamper-evident chain of `INTENT_RECEIVED`, `DECISION`, and `STATE_CHECKPOINT` events, each entry's SHA-256 hash binding to the previous entry's hash (`computeNextHash()`). A separate Ed25519 signing mechanism, `VerificationEnvelopeV1` (`packages/core/src/verification/envelope.ts`, `signEnvelopeEd25519()`), exists in code but is listed as pending specification (`docs/protocol/overview.md` §"VerificationEnvelopeV1"); this document does not assert that `HashChainedLog` output is routed through it. Two components of AARM's R5 are not covered: "accumulated context" is not recorded, consistent with the R2 residual (§3.2); and the **execution outcome** specifically is not yet bound into a receipt artifact. `ExecutionReceiptV1` — the artifact that would carry execution-outcome attestation — is listed as **Planned**, not yet specified or implemented (`README.md` protocol status table; `docs/protocol/overview.md` line 43: "*(planned; not specified in this document)* Execution attestation binding receipt to a verified authorization"). No `context` field has been defined for it because the artifact itself does not yet exist as a spec. This is a genuine gap against R5 as written, not a naming difference: AARM requires the execution outcome be recorded, and OxDeAI's current signed artifacts stop at the authorization decision, before execution occurs.

### 3.6 R6: Identity Binding (MUST)

**AARM requirement:** "actions must be bound to identities at all layers — human principal, service account, agent session, and role/privilege scope" [Errico 2026, §VII-B6], formally defined as four layers in [Errico 2026, §IV-A2]: human principal, service identity, agent/session identity (merged as a single layer, not split into separate agent and session layers), and role/privilege scope.

**OxDeAI status: Partially Satisfied.** `DelegationV1`'s `delegator`/`delegatee` fields (`docs/spec/artifacts/delegation-v1.md` §2) each carry a single principal identity string, and `AuthorizationV1`'s `issuer`/`audience` fields bind a decision to issuer and audience identities. Read against AARM's own §IV-A2 model — which merges agent and session into one identity layer rather than treating them as two — `delegator`/`delegatee` and `issuer`/`audience` are a plausible fit for AARM's merged agent/session layer; there is no separate "session identity" field to be missing, because AARM does not require one as distinct from agent identity. Role/privilege scope is represented by `DelegationV1`'s `scope` object (tools, `max_amount`, `max_actions`, `max_depth`; §4.1 Scope Narrowing); `verifyDelegationChain()` checks effective declared scope non-expansion against an explicit caller-supplied `parentScope`, with the runtime limitation described in §3.9. What is **not** covered is the human-principal layer: OxDeAI's identity fields are proposer-supplied strings, not the output of an authenticated-principal-to-agent-identity binding. This is precisely the gap the Tier 1 evaluator-input-provenance ADR addresses and does not yet close — `docs/architecture/decisions/tier1-evaluator-input-provenance.md` states that "an explicit proposer claim that conflicts with the mapping fails closed rather than being silently overwritten" is future secure-path work, governed by open issue #197, with credential provenance and scope tracked independently in issue #216. Neither issue is closed as of this writing.

### 3.7 R7: Semantic Distance Tracking (SHOULD)

**AARM requirement:** implementations "SHOULD compute semantic distance using embedding-based similarity between the original user request and the current action" [Errico 2026, §VII-C1, §IV-C1].

**OxDeAI status: Out of Scope by Design.** Two things bound this status. First, R7 is an Extended (SHOULD) requirement — AARM itself does not require semantic-distance tracking for Core conformance (R1-R6) [Errico 2026, §VII-A]. Second, and independent of conformance level, OxDeAI's determinism guarantee is structurally incompatible with embedding-based evaluation as AARM specifies it: canonicalization-v1 requires "only integers in the safe IEEE-754 range" and states floats "MUST be rejected" (`docs/spec/core/canonicalization-v1.md` line 71, error code `FLOAT_NOT_ALLOWED`). Embedding vectors are float arrays. A verification surface that computed or consumed embedding-based similarity scores could not pass through canonicalization-v1 without either violating the float-rejection rule or introducing a parallel, non-canonicalized data path — either of which would break the byte-equivalence property that G5 and the cross-language conformance suite depend on.

### 3.8 R8: Telemetry Export (SHOULD)

**AARM requirement:** telemetry export "enabling visibility and incident investigation" [Errico 2026, §VII-C2].

**OxDeAI status: Partially Satisfied.** `HashChainedLog` emits structured, tamper-evident audit events (`INTENT_RECEIVED`, `DECISION`, `STATE_CHECKPOINT`) that support incident investigation and are independently verifiable via `verifyAuditEvents()` (whitepaper §9.1). No dedicated telemetry-export interface, wire format, or integration with an external observability system (e.g., OpenTelemetry, a SIEM export format) is specified anywhere in the current spec set — a repository-wide search for telemetry/OpenTelemetry references in `docs/` and `packages/` returns no matches. The audit log is queryable and verifiable, but it is not, today, an export mechanism in the sense AARM's R8 describes.

### 3.9 R9: Least Privilege Enforcement (SHOULD)

**AARM requirement:** "least privilege enforcement through operation-specific credential scoping" [Errico 2026, §VII-C3].

**OxDeAI status: Satisfied.** With an explicit caller-supplied `parentScope`, `verifyDelegationChain()` checks non-expansion of the effective declared scope across tools, `max_amount`, `max_actions`, and `max_depth`, as required by `DelegationV1` §4.1 (Scope Narrowing); violations produce `DELEGATION_SCOPE_VIOLATION`. `max_actions` participates in inheritance and narrowing; the current implementation does not count or consume delegated actions against it at runtime. Verification proves narrowing against the supplied `parentScope`, without independently establishing that it represents an external authoritative grant. This is the mechanism behind G4 (delegation non-expansion) in the whitepaper (§2, G4) and is verified by the delegation property-based test suite (`docs/testing/delegation-pbt.md`). This directly satisfies AARM's operation-specific credential-scoping requirement for the delegation path; it does not, on its own, address broader credential-provenance questions (issuer key custody, credential issuance scope) tracked separately in issue #216.

---

## 4. Architecture Positioning

AARM defines four reference implementation architectures with distinct trust properties: Protocol Gateway, SDK Instrumentation, Kernel/eBPF Monitor, and Architecture D, Vendor Integration [Errico 2026, §VI]. Architecture D requires "vendors to implement AARM controls within their service," with vendors exposing action decisions to customers and customers deploying AARM policy-evaluation components against those exposed decisions [Errico 2026, §VI-D2-D4].

OxDeAI's scope — a PEP that intercepts execution (R1, §3.1), a scoped delegation/credential mechanism (R9, §3.9), and a signed decision artifact plus tamper-evident audit chain (R5, partially, §3.5) — is structurally the kind of component Architecture D's "customer implementation" side describes: a policy-evaluation and decision-artifact layer that a vendor's exposed action-decision surface could sit in front of, or that could sit behind a vendor's exposed decision surface.

This is a structural observation about where OxDeAI's scope intersects AARM's architecture model, stated for positioning purposes only. **No integration between OxDeAI and any AARM Architecture D vendor exists today, and no partnership is claimed.** Whether OxDeAI's R1/R5/R6-relevant components could participate in an Architecture D deployment is unverified and would require an actual integration to establish, not this document.

---

## 5. Residual Trust Corroboration

<!-- Blocked on #197. Do not draft until #197 (evaluator input
provenance) closes. See whitepaper §3.2/§3.8 for the parallel
pending edit. Content will state whether AARM's own treatment of
policy-engine/context-accumulator as Trusted-without-verification
[Errico 2026, §V-E] and its identification of "federated receipt
verification" as an open research direction [Errico 2026, §VIII-C]
corroborates RT-TRUST-1 as a structural property of the problem
rather than an OxDeAI-specific gap — but only once #197's actual
resolution is known, since the comparison's content depends on
what #197 ships. -->

---

## 6. Closing Note

This document was written to give OxDeAI's standardization positioning a second reference point beyond the ETA framework mapping (`execution-time-authorization-alignment.md`), using AARM's nine-requirement conformance structure as the comparison basis. It should be re-read for rhetorical inflation with the same separation discipline noted in the ETA alignment document.

What remains open: R5 is partially satisfied pending `ExecutionReceiptV1`, which is currently Planned and unscheduled; R6 is partially satisfied pending resolution of issue #197 (Tier 1 evaluator-input provenance), with issue #216 tracking an adjacent, independently scoped credential-provenance gap, and issues #217/#218 tracking the argument-provenance and approval-workflow gaps named in the R4 mapping; R8 has no dedicated export mechanism; and §5 of this document is explicitly withheld pending #197.

This document should be revisited when any of the following occurs: issue #197 closes; `ExecutionReceiptV1` ships a specification (at which point §3.5 and §5 both require re-drafting); AARM publishes a version of its specification beyond the one cited here (arXiv:2602.09433, February 2026); or the independent security review tracked in issue #139 completes.
