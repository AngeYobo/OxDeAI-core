# OxDeAI 2.0 OpenZeppelin Review Scope

**Status:** Draft — prepared for review scheduling, not yet frozen.
**Authored against:** `700b7b13ae13740aaeb2e0df1ae187f30087b6b5` (informational reference only; this is *not* `S_freeze` — see §2).
**Related:** [#254](https://github.com/oxdeai/oxdeai/issues/254) (release gates), `docs/audits/protocol-audit-post-interoperability.md` (prior internal audit, dated 2026-06-04, predates the Tier 1 secure-guard work described here), `docs/audits/2.0-residual-scope.md` (companion residual-risk document).

---

## 1. Review objective

The primary review question is:

> **Does "no valid authorization → no execution through the reviewed enforcement boundary" hold under the documented trust and deployment assumptions?**

This is a scoped question, not an open-ended audit. The reviewer is asked to evaluate this invariant specifically for the enforcement paths named in §3–§4, under the trust assumptions stated in §6, at the exact commit frozen as `S_freeze` (§2).

This review is **not**:

- a generic review of all present or future OxDeAI capabilities,
- a review of the adapter frameworks (LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, OpenClaw) themselves, only of how OxDeAI's own adapter packages configure the guard,
- a standardization or AARM-conformance review,
- a review of the website, documentation site, or non-security package tooling (`@oxdeai/cli`),
- a review of features that do not exist in the codebase at `S_freeze` (see §8).

---

## 2. Review provenance model

| Term | Definition |
|---|---|
| `S_freeze` | The exact Git commit SHA reviewed initially. **To be frozen before review** — not yet assigned. |
| `S_fix` | The remediation-only commit prepared after the reviewer delivers findings against `S_freeze`. **To be frozen after remediation** — not yet assigned. |

Rules governing this model:

- The initial review applies to `S_freeze` and only `S_freeze`.
- Remediation verification applies to `git diff S_freeze..S_fix` — the reviewer re-examines the diff, not the whole tree again, unless the diff's scope requires broader re-reading.
- Published OxDeAI 2.0 npm artifacts **MUST** be built from `S_fix`, not from any unreviewed commit that lands after it.
- Any code change merged after `S_fix` is **outside** the reviewed release boundary unless it is explicitly submitted for a follow-up review. This applies even to changes that look purely cosmetic.
- Package/tarball hashes for the candidate 2.0 artifacts (produced via `pnpm pack` per `docs/release/RELEASING.md` and `docs/release/release-checklist.md`) **MUST** be recorded alongside `S_freeze` and again alongside `S_fix`, so the artifact a reviewer signed off on can be distinguished from any other build claiming the same version number. This directly addresses the version-integrity problem already identified in [#254](https://github.com/oxdeai/oxdeai/issues/254): package.json version strings have previously been reused across non-identical trees (e.g., `@oxdeai/guard` was labeled `1.0.3` in Git while npm's last published artifact was `1.0.1`, and `1.0.2`/`1.0.3` were tagged but never published — see `packages/guard/CHANGELOG.md`).

**Neither `S_freeze` nor `S_fix` is assigned as of this document's authoring.** Do not treat the "Authored against" SHA above as either — it is provided only so a reader can independently verify the repository state this scope document was written from.

---

## 3. In-scope security properties

### Authorization artifact issuance and verification

- `AuthorizationV1` — `packages/core/src/types/authorization.ts`, `docs/spec/artifacts/authorization-v1.md`
- `DelegationV1` — `packages/core/src/types/delegation.ts`, `docs/spec/artifacts/delegation-v1.md`
- `SignedKRLV1`, where relevant to a deployment's key-revocation posture — `packages/core/src/verification/verifySignedKrl.ts`, `docs/spec/artifacts/signed-krl-v1.md`
- Canonicalization — `packages/core/src/crypto/hashes.ts`, `docs/spec/core/canonicalization-v1.md`
- Signature verification (Ed25519, Encoding A/B) — `packages/core/src/crypto/signatures.ts`, `packages/core/src/verification/verifyAuthorization.ts`
- Intent binding (`intent_hash`) — `packages/guard/src/guard.ts` (hash-binding step), `packages/guard/src/test/guard.intent-binding.test.ts`
- Audience binding (`expectedAudience`) — `packages/guard/src/types.ts`, `packages/guard/src/guard.ts`
- Expiry/freshness — `packages/core/src/verification/verifyAuthorization.ts`, `docs/spec/artifacts/authorization-v1.md §17` (clock-semantics)
- Revocation — `packages/core/src/verification/verifySignedKrl.ts`, key lifecycle (`keyIsActiveAt`) in `packages/core/src/crypto/signatures.ts`
- Replay protection — see dedicated subsection below

### Trusted time

- Trusted evaluation time as an explicit, required, never-defaulted argument to `PolicyEngine.evaluatePure` — `packages/core/src/policy/PolicyEngine.ts`, `packages/core/src/policy/verifyTrustedTime.ts`, `docs/spec/core/trusted-time-v1.md`
- Intent freshness bounds (`maxClockSkewSeconds`, `maxIntentAgeSeconds`, `RECOMMENDED_TRUSTED_TIME_PROFILE`) — `packages/core/src/policy/trustedTimeProfile.ts`, `packages/core/src/policy/trustedTimeValidation.ts`
- The reviewer should confirm that no policy module derives a security decision from attacker-controlled `intent.timestamp` in place of the trusted `evaluationTime` argument. This was the subject of a prior internal repro harness; see `scripts/security/repro-policy-boundary-attacks.ts` for the specific attack shapes already tested against (attacks C, K, J, I).

### Policy evaluation

- `PolicyEngine` — `packages/core/src/policy/PolicyEngine.ts` and its modules under `packages/core/src/policy/modules/` (`KillSwitchModule`, `AllowlistModule`, `ReplayModule`, `RecursionDepthModule`, `ConcurrencyModule`, `ToolAmplificationModule`, `BudgetModule`, `VelocityModule`)
- Fail-closed behavior on malformed engine output — **[#247](https://github.com/oxdeai/oxdeai/issues/247) MUST land before `S_freeze` is assigned.** #247 reports that a malformed `DENY` result missing `reasons` can currently surface as a raw `TypeError` rather than a structured engine-contract violation; the issue itself states execution still fails closed in that case, so this is a robustness/classification gap, not a bypass — but it is treated as a pre-freeze prerequisite rather than a residual that may remain open at `S_freeze`. Once #247 lands, the relevant build, test, security, packaging, and external-consumer gates (§9, `docs/release/release-checklist.md`) **MUST** be rerun before `S_freeze` is assigned, since the fix touches the guard's DENY-handling path exercised by those gates. The reviewer's task is not to verify that #247 is resolved in the abstract, but to verify the exact malformed-output fail-closed semantics actually present in the code at `S_freeze`.
- Deterministic policy evaluation — `packages/core/src/test/property.decision.test.ts`, `packages/core/src/test/canonicalization.property.test.ts`
- State version/CAS semantics — see Replay/state subsection

### Enforcement boundary

- `OxDeAIGuard` — `packages/guard/src/guard.ts` (the lower-level entry point; still a legitimate integration surface, see §7 of `docs/audits/2.0-residual-scope.md`)
- `createSecureGuard` — `packages/guard/src/secureGuard.ts` (the Tier 1 hardened entry point)
- `createTrustedExecutionContext` — `packages/guard/src/trustedContext.ts`
- Trusted/proposer provenance reconciliation — `packages/guard/src/provenance.ts` (`reconcileWithTrustedContext`, `ClaimProvenance`, `ProvenanceRecord`)
- Explicit tenancy posture — `SecureGuardOptions.tenancy` in `packages/guard/src/secureGuard.ts`
- Trusted identity/agent binding — the `agent_id`/`depth`/`tool`/`principal_id`/`tenant_id`/`adapter_id`/`route_classification` fields reconciled in `packages/guard/src/provenance.ts`
- Audience and key trust configuration — `expectedAudience`, `trustedKeySets` in `packages/guard/src/types.ts` and `packages/guard/src/guard.ts`
- `onDecision` — `packages/guard/src/types.ts` (`OxDeAIGuardConfig.onDecision`)
- `onBoundaryEvent` — `packages/guard/src/boundaryEvent.ts`, `packages/guard/src/types.ts`. This is a newly-added (2.0) audit stream, disjoint from `onDecision` by construction; the reviewer should confirm no rejection is silently reported on neither stream.
- No execution after guard rejection — `packages/guard/src/test/guard.test.ts`, `packages/guard/src/test/guard.boundary.test.ts`, `packages/guard/src/test/guard.boundary-audit.test.ts`

### Replay/state

- `ReplayStore` interface and implementations — `packages/guard/src/replayStore.ts` (in-memory), `packages/guard/src/replayStore.redis.ts` (Redis, `SET NX EX` atomicity)
- State hash/version handling — `packages/core/src/policy/PolicyEngine.ts` (`computeStateHash`), `packages/guard/src/types.ts` (`VersionedState`, `StateVersion`)
- CAS conflict behavior — `packages/guard/src/test/guard.cas.test.ts`, `OxDeAIConflictError` in `packages/guard/src/errors.ts`
- State authority assumptions — this is a named residual, not an in-scope guarantee. See §6 and `docs/spec/state-provider-requirements.md`. **The reviewer is not being asked to verify that any particular deployment's state provider is authoritative** — only that the guard correctly detects and fails closed on hash mismatch and CAS conflict for whatever state it is given.

### Verification surface

- `verifyEnvelope` — `packages/core/src/verification/verifyEnvelope.ts`
- Strict verification behavior (`mode: "strict"`, `trustedKeySets` requirement, `TRUSTED_KEYSETS_REQUIRED`) — `packages/core/src/verification/verifyAuthorization.ts`, `packages/core/src/verification/createVerifier.ts`
- Relevant SDK/conformance surfaces — `packages/sdk/src/` (guard/verification convenience wrappers), `packages/conformance/src/validate.ts` and its vector sets under `packages/conformance/vectors/`

### Adapters

Review the five framework adapter packages (`packages/langgraph`, `packages/crewai`, `packages/autogen`, `packages/openai-agents`, `packages/openclaw`) **only** for:

- Correct guard configuration forwarding — each adapter's `src/adapter.ts` should delegate all authorization logic to `@oxdeai/guard`'s `OxDeAIGuard` without reimplementing any policy or verification logic. Confirm no adapter contains its own `verifyAuthorization` call, its own replay logic, or its own signature check.
- Dependency compatibility — each adapter's packed `package.json` should declare `@oxdeai/core`/`@oxdeai/guard` as resolvable semver ranges, not `workspace:*` (see §11 packaging notes; this was a real historical defect in the published 1.0.x line for all five adapters, corrected as part of the pre-freeze work under [#254](https://github.com/oxdeai/oxdeai/issues/254)/#256).
- Audience/replay/state configuration — confirm each adapter forwards `expectedAudience`, `replayStore`, `onBoundaryEvent`, and `computeStateHash` through to the underlying guard rather than dropping them.
- Declared provenance/trust profile — each adapter's `README.md` now carries a "Trust profile" section (added as part of the pre-freeze work) stating that agent identity is deployment-fixed (`config.agentId`), not proposer-controlled, but that tool identity and recursion depth are **not** established from a `TrustedExecutionContext` on the adapter path. The reviewer should confirm this stated profile matches what the adapter code actually does.
- Whether adapter documentation accurately scopes what is trusted vs. declared — see the "Trust profile" sections referenced above, e.g. `packages/langgraph/README.md`.

**Adapters are not presumed to establish authenticated Tier 1 provenance, and none of them currently do.** No adapter constructs a `TrustedExecutionContext` or calls `createSecureGuard`. This is a documented, intentional posture (see `docs/audits/2.0-residual-scope.md` §7), not an oversight to be flagged as a finding by itself. The reviewer should flag it as a finding only if adapter documentation or the public website overstates what the adapter path provides relative to what the code does.

---

## 4. Primary packages/files

### Primary security-review files

```
packages/core/src/policy/PolicyEngine.ts
packages/core/src/policy/trustedTimeProfile.ts
packages/core/src/policy/trustedTimeValidation.ts
packages/core/src/policy/verifyTrustedTime.ts
packages/core/src/policy/modules/KillSwitchModule.ts
packages/core/src/policy/modules/AllowlistModule.ts
packages/core/src/policy/modules/ReplayModule.ts
packages/core/src/policy/modules/RecursionDepthModule.ts
packages/core/src/policy/modules/ConcurrencyModule.ts
packages/core/src/policy/modules/ToolAmplificationModule.ts
packages/core/src/policy/modules/BudgetModule.ts
packages/core/src/policy/modules/VelocityModule.ts
packages/core/src/verification/verifyAuthorization.ts
packages/core/src/verification/verifyEnvelope.ts
packages/core/src/verification/verifyDelegation.ts
packages/core/src/verification/verifySignedKrl.ts
packages/core/src/verification/createVerifier.ts
packages/core/src/crypto/hashes.ts
packages/core/src/crypto/signatures.ts
packages/core/src/crypto/sign.ts
packages/core/src/crypto/verify.ts
packages/core/src/delegation/createDelegation.ts
packages/core/src/audit/HashChainedLog.ts
packages/core/src/types/authorization.ts
packages/core/src/types/delegation.ts
packages/core/src/types/keyset.ts
packages/core/src/types/signed-krl.ts
packages/core/src/types/intent.ts
packages/core/src/types/state.ts
packages/guard/src/guard.ts
packages/guard/src/secureGuard.ts
packages/guard/src/trustedContext.ts
packages/guard/src/provenance.ts
packages/guard/src/boundaryEvent.ts
packages/guard/src/errors.ts
packages/guard/src/types.ts
packages/guard/src/normalizeAction.ts
packages/guard/src/replayStore.ts
packages/guard/src/replayStore.redis.ts
```

### Supporting specification/documentation files

```
docs/spec/core/canonicalization-v1.md
docs/spec/core/trusted-time-v1.md
docs/spec/core/eta-core-v1.md
docs/spec/artifacts/authorization-v1.md
docs/spec/artifacts/delegation-v1.md
docs/spec/artifacts/signed-krl-v1.md
docs/spec/enforcement/pep-gateway-v1.md
docs/spec/verification/verification-v1.md
docs/spec/interoperability/external-provider-profile.md
docs/spec/state-provider-requirements.md
docs/security/SECURITY.md
docs/security/threat-model.md
docs/architecture/threat-model-external-providers.md
docs/architecture/key-custody-and-rotation.md
docs/architecture/replay-store-ttl-alignment.md
docs/architecture/pep-production-guide.md
docs/architecture/decisions/tier1-evaluator-input-provenance.md
docs/audits/protocol-audit-post-interoperability.md
docs/audits/2.0-residual-scope.md
```

### Conformance/test evidence

```
packages/conformance/vectors/*.json
packages/conformance/src/validate.ts
docs/spec/test-vectors/*.json
go-harness/*.go
python-harness/*.py
packages/guard/src/test/guard.provenance.test.ts
packages/guard/src/test/guard.boundary-audit.test.ts
packages/guard/src/test/guard.delegation.test.ts
packages/guard/src/test/guard.delegation.matrix.test.ts
packages/guard/src/test/guard.delegation.property.test.ts
packages/guard/src/test/guard.state-binding.test.ts
packages/guard/src/test/guard.cas.test.ts
packages/guard/src/test/guard.toctou.test.ts
packages/guard/src/test/guard.replay-store.test.ts
packages/guard/src/test/guard.replay-store.redis.test.ts
packages/guard/src/test/guard.intent-binding.test.ts
packages/core/src/test/toctou.test.ts
packages/core/src/test/trusted-time-integration.test.ts
packages/core/src/test/verify.authorization.test.ts
packages/core/src/test/delegation.matrix.test.ts
scripts/security/repro-policy-boundary-attacks.ts
```

### Adapter review files

```
packages/langgraph/src/adapter.ts
packages/langgraph/src/types.ts
packages/langgraph/README.md
packages/langgraph/src/test/adapter.test.ts
packages/crewai/src/adapter.ts
packages/crewai/src/types.ts
packages/crewai/README.md
packages/crewai/src/test/adapter.test.ts
packages/autogen/src/adapter.ts
packages/autogen/src/types.ts
packages/autogen/README.md
packages/autogen/src/test/adapter.test.ts
packages/openai-agents/src/adapter.ts
packages/openai-agents/src/types.ts
packages/openai-agents/README.md
packages/openai-agents/src/test/adapter.test.ts
packages/openclaw/src/adapter.ts
packages/openclaw/src/types.ts
packages/openclaw/README.md
packages/openclaw/src/test/adapter.test.ts
packages/compat/src/test/cross-adapter.test.ts
```

No `examples/*` demo scripts are listed as primary review files — they are reproduction aids (§9) and are explicitly out of scope as a review target per §8.

---

## 5. Threat model

| Attack | Attacker capability assumed | Trusted component relied on to resist it |
|---|---|---|
| Proposer-controlled identity/context substitution | Full control over `ProposedAction`/`Intent` fields, including `agent_id`, `depth`, `tool` | `createTrustedExecutionContext` + `reconcileWithTrustedContext`, on the secure-guard path only |
| Intent tampering (post-authorization) | Ability to modify the intent between authorization issuance and execution | Intent-hash binding at guard step (`intentHash(intent)` vs. `authorization.intent_hash`) |
| Audience confusion | Ability to present an authorization issued for a different audience/agent | `expectedAudience` check in `OxDeAIGuardConfig` / `AUTH_AUDIENCE_MISMATCH` |
| Replay | Ability to resubmit a previously-consumed `auth_id` or `delegation_id` | `ReplayStore.consumeAuthId`/`consumeDelegationId`, fail-closed on store unavailability |
| Stale/future-dated intent manipulation | Full control over `intent.timestamp` | Trusted `evaluationTime` argument, `maxClockSkewSeconds`/`maxIntentAgeSeconds` |
| Key/trust-anchor confusion | Ability to sign with an arbitrary key not in `trustedKeySets` | `trustedKeySets` requirement, `TRUSTED_KEYSETS_REQUIRED`/`AUTH_KID_UNKNOWN` fail-closed behavior |
| Delegation misuse (scope widening, expiry extension) | Control over a child agent's delegation request | `verifyDelegationChain`, `parentScope` required-field validation, `isValidDelegationScope` |
| Revoked authorization acceptance | Possession of a validly-signed but revoked key/artifact | `keyIsActiveAt`, `SignedKRLV1`/`verifySignedKrl` where a KRL is configured |
| State race / stale-state authorization | Ability to race a concurrent state mutation against the CAS window | `setState(nextState, expectedVersion)` CAS contract, `OxDeAIConflictError` |
| Malformed decision output | A compromised or buggy `PolicyEngine` returning an ill-formed `DENY`/`ALLOW` result | Guard-side validation of engine output before constructing `OxDeAIDenyError`/issuing execution. [#247](https://github.com/oxdeai/oxdeai/issues/247) is a pre-freeze prerequisite (§3), not an open residual; the reviewer verifies the exact malformed-output fail-closed semantics present in the implementation at `S_freeze` |
| Bypass of guard/enforcement path | Ability to call the protected action through any code path that does not invoke the guard | **Not a protocol-level guarantee.** Non-bypassability holds only for execution paths actually routed through the reviewed enforcement boundary — see §6 and `docs/audits/2.0-residual-scope.md` §9 |
| Mismatch between action reviewed and action executed | A protected executor that performs a different operation than the one named in the authorized intent | Adapter/executor responsibility; the guard authorizes an `Intent`, not the executor's actual side effect — see residual scope §9 |

**Trusted components** for this threat model: the authenticating PEP process, the guard library itself (`@oxdeai/guard`), the configured `trustedKeySets` and the key custody process that provisions them, the authorization signer, and the protected execution path once selected. **Untrusted / attacker-reachable**: the proposer, the agent runtime, the orchestrator, and (per the ADR's stated threat model in `docs/architecture/decisions/tier1-evaluator-input-provenance.md`) potentially the state and policy configuration sources unless a deployment specifically hardens them per `docs/spec/state-provider-requirements.md`.

---

## 6. Trust assumptions

- The enforcement boundary/operator, not the protocol, is responsible for providing trusted identity/context inputs to `createTrustedExecutionContext`. The brand it applies is **misuse resistance, not authentication** (`packages/guard/src/trustedContext.ts`): it proves a context object was constructed by this function, not that the underlying caller was actually authenticated.
- Trusted keys/trust anchors (`trustedKeySets`) are assumed to be provisioned correctly by the deployment; the protocol enforces that they are configured (fail-closed if not) but cannot verify that the *right* keys were chosen.
- The authoritative state source behind `getState()`/`setState()` is a deployment responsibility unless the deployment separately satisfies `docs/spec/state-provider-requirements.md`. The protocol enforces hash-consistency and CAS version-conflict detection; it does not authenticate the state provider itself. See `docs/audits/2.0-residual-scope.md` §3.
- A cryptographic signature over an artifact proves origin (relative to `trustedKeySets`) and integrity. It does **not** prove that the underlying claim is true, current, or authoritative — this is stated explicitly and normatively in `docs/security/SECURITY.md §7`: *"Verification does NOT ensure: that the policy was correct or legitimate, that the state was legitimate, that the issuer is globally authoritative."*
- Correct placement of the guard/PEP — i.e., that the protected action has no reachable code path that bypasses `OxDeAIGuard`/`createSecureGuard` — is a deployment architecture requirement, not something the protocol can enforce from inside the library. The `examples/non-bypassable-demo` demonstrates one concrete pattern (a shared-secret bearer token gating the protected upstream), not a universal guarantee.
- External side effects performed inside the protected `execute()` callback may require the executor to apply its own resource-native atomic version check (e.g., HTTP `If-Match`, a database row version, a transactional write) if the side effect's own correctness depends on the resource not having changed between authorization and execution. OxDeAI's own state CAS protects only its own policy-state transition, not an arbitrary external resource — see [#253](https://github.com/oxdeai/oxdeai/issues/253) and `docs/audits/2.0-residual-scope.md` §4.

---

## 7. Known residuals acknowledged before review

The following are **known, previously-documented design or implementation residuals** — not hidden acceptance criteria the reviewer is expected to discover independently, and not issues this engagement is scoped to resolve.

- **[#197](https://github.com/oxdeai/oxdeai/issues/197)** — Tier 1 evaluator-input provenance. The self-declared-field half (`agent_id`, `depth`, `tool` when a trusted route premise exists) is addressed by `createSecureGuard`/`createTrustedExecutionContext`/`reconcileWithTrustedContext`. The state-source-authority half is not: a compliant `getState()` implementation is a deployment responsibility (`docs/spec/state-provider-requirements.md`), and the protocol cannot detect a compromised state provider that returns manufactured-but-hash-consistent state. Open at the time of authoring.
- **[#253](https://github.com/oxdeai/oxdeai/issues/253)** — Resource-side TOCTOU preconditions. OxDeAI's own CAS closes the race on its own policy state; it does not automatically serialize mutation of an external resource the protected executor touches. Design-only issue, open at the time of authoring.
- **[#238](https://github.com/oxdeai/oxdeai/issues/238)** — Post-execution-start audit semantics. If the protected `execute()` callback throws after authorization/CAS succeed, the current guard produces neither an `onDecision` record nor an `onBoundaryEvent` for that specific failure — a real gap in audit-trail completeness for that one lifecycle state. Design-only issue, open at the time of authoring.
- **[#245](https://github.com/oxdeai/oxdeai/issues/245)** — Human-approval action binding for fresh resubmission. No approval workflow exists in the shipped `PolicyEngine` today; this issue is explicitly gated "do not implement yet" pending resolution of the Tier 1 authoritative approval-state question this engagement does not need to resolve. Open at the time of authoring.
- **Secondary cluster — policy-expressiveness gaps**, all P2, all open at the time of authoring, all pre-dating and independent of the Tier 1 secure-guard work: [#214](https://github.com/oxdeai/oxdeai/issues/214) (no default-deny tool allowlist axis), [#216](https://github.com/oxdeai/oxdeai/issues/216) (no credential provenance/scope binding), [#217](https://github.com/oxdeai/oxdeai/issues/217) (argument provenance not expressible beyond an opaque `metadata_hash`), [#218](https://github.com/oxdeai/oxdeai/issues/218) (no approval-state workflow concept), [#219](https://github.com/oxdeai/oxdeai/issues/219) (per-tenant limits are a naming convention, not a verified property). These bound what the policy model can express; they do not describe a bypass of what it currently does enforce.

See `docs/audits/2.0-residual-scope.md` for the full residual-risk treatment of each of these.

---

## 8. Explicit out of scope

- Future `ExecutionReceiptV1` work, if not implemented at `S_freeze` (planned per `ROADMAP.md` v4.x; also the subject of the separate, purely-decisional [#249](https://github.com/oxdeai/oxdeai/issues/249) RATS/EAT/COSE compatibility analysis, which explicitly states it proposes no protocol change).
- STEP_UP / human-approval binding from [#245](https://github.com/oxdeai/oxdeai/issues/245).
- Resource-native TOCTOU protection where the external resource offers no atomic precondition mechanism of its own — see [#253](https://github.com/oxdeai/oxdeai/issues/253).
- Post-execution-start audit semantics from [#238](https://github.com/oxdeai/oxdeai/issues/238), if still unresolved at `S_freeze`.
- Future Tier 2 state/provenance work (an authoritative `StateProvider`/`PolicyProvider` abstraction beyond the current `getState`/`setState` CAS contract) — described as future work in `docs/architecture/decisions/tier1-evaluator-input-provenance.md`, not implemented.
- Future instruction/proposal provenance work — [#251](https://github.com/oxdeai/oxdeai/issues/251), a decision-record-only issue explicitly proposing no protocol field or mechanism.
- New adapters not present in the repository at `S_freeze`.
- Unrelated product/UI/business logic, including the public website (`website/index.html`).
- Unpublished roadmap features generally — see `ROADMAP.md` "Planned" and "Planned Later" milestones (v2.7 onward), none of which are implementation claims for this review.

---

## 9. Review evidence

The following should be provided to the reviewer:

- Exact `S_freeze` SHA (to be assigned).
- Release-candidate package versions for all ten publishable packages (`@oxdeai/core`, `@oxdeai/guard`, `@oxdeai/sdk`, `@oxdeai/conformance`, `@oxdeai/cli`, and the five adapters).
- Packed tarballs (`pnpm pack` output) for each publishable package, built from `S_freeze`.
- Tarball integrity hashes (`npm pack`/`pnpm pack` shasum output) for each of the above.
- Test commands and results: `pnpm test` (root), `pnpm -C packages/conformance validate`, `pnpm -C packages/guard test`, `pnpm -C packages/core test`, `node scripts/security/repro-policy-boundary-attacks.ts`.
- Conformance results: current counts and pass/fail status for the TypeScript, Go, and Python conformance harnesses (`packages/conformance/vectors/*.json`, `go-harness/`, `python-harness/`).
- `release-preflight` results for each package (`node scripts/release-preflight.mjs --package <name> --check-npm`).
- Architecture/security docs listed in §4.
- This scope document and its companion, `docs/audits/2.0-residual-scope.md`.
- Reproduction instructions for the critical invariants — see `examples/non-bypassable-demo/README.md` for the ALLOW/DENY/REPLAY/BYPASS reproduction, and `scripts/security/repro-policy-boundary-attacks.ts` for the self-declared-identity/depth/tool provenance-conflict reproductions.

---

## 10. Remediation and fix-review requirement

This engagement **MUST** include, in order:

1. Initial review of `S_freeze`.
2. Remediation-only changes made in response to findings, producing `S_fix`.
3. Reviewer verification of `git diff S_freeze..S_fix` — confirming that the diff addresses the findings it claims to address and introduces no new regressions in the reviewed surface.
4. Explicit confirmation, in writing, of which findings are resolved and which remain unresolved (with severity and rationale) **before** any 2.0 artifact built from `S_fix` is published.

A generic "audit completed" statement without a stated `S_freeze` SHA, a stated `S_fix` SHA, and an explicit resolved/unresolved finding list is not an acceptable engagement output for this review.

---

## 11. Allowed public claims after review

Any public claim referencing this review MUST include:

- The exact reviewed SHA (`S_freeze`).
- The exact fix-reviewed SHA (`S_fix`), if remediation occurred.
- The review date and the reviewing firm/individual.

The following claims are **not** permitted based on this review alone:

- A generic "OxDeAI is audited" statement detached from a specific version/SHA.
- Any claim of complete AARM Core conformance — this review does not establish that, and none of the current documentation (`docs/standardization/execution-time-authorization-alignment.md`, `docs/audits/protocol-audit-post-interoperability.md §7.6`) claims standard-adoption readiness today.
- A claim that the review covers versions published after `S_fix` without a stated follow-up review.
- A claim that adapters were reviewed for authenticated Tier 1 provenance guarantees they do not implement (see §3, §7).
