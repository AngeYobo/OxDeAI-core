# Claim mapping audit (schema v2)

#290 review update: the Profile-C docs representation is authoritative and the
package representation is its deterministic projection, not independent corpus
evidence. PROFILE-C-001 retains its original evidence/levels and adds a forbidden
inference from projection equality to independent evidence. CANON-ESC-001 remains
unresolved/deferred; current eight cases do not require an escaping resolution.
See [corpus authority](../../conformance/corpus-authority.md) and the live registry.


Review snapshot. Run `pnpm verify:spec-claims` for live counts. Locks are contextual records, not additional normative requirements.

```text
OxDeAI Spec-to-Code Claim Verification

Registered records: 29
Normative claim records (curated, not exhaustive): 26
Contextual corpus locks (not executable requirements): 3
Traceability (requirements only; references validated; evidence NOT executed by this command):
 implementation mapped: 20/26
 executable evidence mapped: 20/26
 integration evidence: 12/12 required
 negative evidence: 18/18 required
 security-critical with negative evidence: 18/25
 portable conformance evidence: 5/19 applicable

Independent dimensions and evidence capabilities (curated scope, not proof or current execution results):
 CANON-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, CONFORMANCE_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 CANON-002 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED, CONFORMANCE_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 CANON-003 [requirement; normative=specified; evidence=gap; scope=in-scope; portable] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-ARTIFACT-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-VERIFY-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-VERIFY-002 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-VERIFY-003 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-BIND-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; implementation-specific] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-TIME-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-TRUST-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; implementation-specific] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 AUTH-REPLAY-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; implementation-specific] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 TRUSTED-TIME-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 TRUSTED-TIME-002 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 DELEGATION-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 DELEGATION-002 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 DELEGATION-003 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 SIGNED-KRL-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED, CONFORMANCE_TESTED
  Depends on RT-TRUST-2 (conditional-mitigation; context only): Artifact verification alone does not close the deployment KRL residual.
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER KRL_SIGNATURE_VALID -> KRL_DEPLOYMENT_RESIDUAL_CLOSED: Required deployment configuration and persistent stores are not established by artifact vectors.
 SIGNED-KRL-002 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, ADVERSARIAL_TESTED, CONFORMANCE_TESTED
  Depends on RT-TRUST-2 (conditional-mitigation; context only): Artifact verification alone does not close the deployment KRL residual.
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER KRL_SIGNATURE_VALID -> KRL_DEPLOYMENT_RESIDUAL_CLOSED: Required deployment configuration and persistent stores are not established by artifact vectors.
 PROFILE-C-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED, CONFORMANCE_TESTED
  Depends on RT-TRUST-1 (trust-premise; context only): State-hash consistency does not establish state-provider integrity.
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER STATE_HASH_MATCH -> STATE_SOURCE_TRUSTED: Honest, current, authoritative state is a deployment premise.
 PEP-ENFORCE-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; implementation-specific] TRACEABLE, TESTED, INTEGRATION_TESTED, ADVERSARIAL_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 PEP-DEPLOY-001 [requirement; normative=specified; evidence=gap; scope=deployment; deployment-assumption] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 STATE-TRUST-001 [requirement; normative=specified; evidence=gap; scope=deployment; deployment-assumption] NO EXECUTABLE MAPPING
  Depends on RT-TRUST-1 (trust-premise; context only): State-hash consistency does not establish state-provider integrity.
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER STATE_HASH_MATCH -> STATE_SOURCE_TRUSTED: Honest, current, authoritative state is a deployment premise.
 VERIFY-ORDER-001 [requirement; normative=ambiguous; evidence=gap; scope=in-scope; portable] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 DELEGATION-AUDIT-001 [requirement; normative=specified; evidence=gap; scope=in-scope; implementation-specific] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 ETA-SIGNING-001 [requirement; normative=ambiguous; evidence=gap; scope=in-scope; portable] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 ETA-DETERMINISM-001 [requirement; normative=specified; evidence=mapped; scope=in-scope; portable] TRACEABLE, TESTED, INTEGRATION_TESTED
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
 CANON-ESC-001 [corpus-lock; normative=unresolved; evidence=unassessed; scope=deferred; documentation-only] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER SELECTED_CANONICALIZATION_VECTORS_PASS -> CANON_ESC_LOCK_RESOLVED: Existing vectors do not resolve an undefined corpus lock.
 RT-TRUST-1 [corpus-lock; normative=non-normative; evidence=unassessed; scope=deployment; documentation-only] NO EXECUTABLE MAPPING
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER STATE_HASH_MATCH -> STATE_SOURCE_TRUSTED: Matching state can be manufactured by a compromised provider.
 RT-TRUST-2 [corpus-lock; normative=non-normative; evidence=unassessed; scope=conditional; documentation-only] NO EXECUTABLE MAPPING
  Applies when (all conditions; NOT evaluated): krlMode=signed_required, verifyKrl=configured, KrlWatermarkStore=configured, SignedKrlCache=configured
  DO NOT INFER STRUCTURAL_PASS -> SEMANTIC_PROOF: Reference consistency does not prove the claimed semantics.
  DO NOT INFER TESTED -> WHOLE_PROTOCOL_CONFORMANCE: Selected executable cases do not establish whole-protocol conformance.
  DO NOT INFER KRL_SIGNATURE_VALID -> KRL_DEPLOYMENT_RESIDUAL_CLOSED: Signature verification does not establish integrity mode, callback, durable watermark or signed cache configuration.

Issues:
 unmapped claims: 6
 ambiguous claims: 2
 maintainer decisions pending (advisory): 9
 stale implementation refs: 0
 stale evidence refs: 0
 missing required evidence: 0
 REVIEW CANON-001: Only object ordering is claimed; NFC normalization and collision rejection need separate claims. Negative cases are not required for this ordering-only claim.
 REVIEW CANON-003: Core canonicalJson receives objects, after raw duplicate keys may be lost. NFC collision detection is not evidence of duplicate-key-aware raw JSON parsing.
 REVIEW PEP-DEPLOY-001: Deployment topology and upstream access control must be independently evidenced. Gateway tests cannot prove arbitrary deployment non-bypassability.
 REVIEW STATE-TRUST-001: Provider honesty/coherence is an external deployment obligation. Hash equality and CAS tests do not demonstrate it for a deployed provider.
 REVIEW VERIFY-ORDER-001: Verification §5 puts signature before expiry; AuthorizationV1 §10 puts expiry before signature. Core collects/sorts violations. No claim of satisfying both incompatible sequences.
 REVIEW DELEGATION-AUDIT-001: No direct mapping found for required DELEGATION_EXECUTION/DELEGATION_DENIED hash-chained events. Guard boundary event callbacks alone are not evidence of this contract.
 REVIEW ETA-SIGNING-001: ETA excludes entire signature field; AuthorizationV1 §5 retains nested alg/kid and defines encoding-specific prefix. Normative docs vectors use another verifier/preimage; do not equate corpora.
 REVIEW ETA-DETERMINISM-001: Inputs include trusted evaluationTime and fixed configuration per trusted-time profile. This selected test does not prove all decision modules deterministic.
 REVIEW CANON-ESC-001: CANON-ESC-001 was requested for registration by the maintainer; no existing repository definition of this identifier was found. This source is context only. Exact escaping/corpus-lock meaning and disposition require a maintainer decision; no new serialization rule is asserted.
 REVIEW RT-TRUST-1: The residual is not closed. Minimum state-provider requirements exist, but provider compliance and integrity remain deployment responsibilities. This lock is an audit observation, not another executable protocol requirement.
 REVIEW RT-TRUST-2: Conditional closure is documented for configured deployments, not established here. Compatibility modes retain residual risk. Applicability conditions describe the documented closure context; the checker never evaluates a deployment or declares this lock closed.

Mapped ≠ demonstrated. Tested ≠ portable conformance tested. Signature validity ≠ trusted premises.
Structural PASS is not semantic proof or whole-protocol conformance. Dependencies and pending decisions do not close locks.
See docs/verification/spec-claims/README.md for corpus boundaries and maintainer findings.
RESULT: PASS (structural verification only)
```

## CANON-001 — Canonical object key ordering

Source (normative): [docs/spec/core/canonicalization-v1.md](../../../docs/spec/core/canonicalization-v1.md), 6. Serialization Rules (normative) (normative-statement).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Only object ordering is claimed; NFC normalization and collision rejection need separate claims. Negative cases are not required for this ordering-only claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/crypto/hashes.ts](../../../packages/core/src/crypto/hashes.ts) — `canonicalizeToJson`

Evidence:

- [packages/core/src/test/canonicalization.property.test.ts](../../../packages/core/src/test/canonicalization.property.test.ts) — `C-P2: canonical output is invariant to object key insertion order at every nesting level` (unit; negative=false; portable=false). Core canonicalization property test for the selected serialization rule. Runner: `pnpm -C packages/core test` (TypeScript).
- [docs/spec/test-vectors/canonicalization-v1.json](../../../docs/spec/test-vectors/canonicalization-v1.json) — `v1-object-key-ordering` (cross-runtime; negative=false; portable=true). Exact sorted canonical JSON and SHA-256; Python independent implementation. Runner: `pnpm test:vectors:py` (Python).

## CANON-002 — Reject floating point numbers

Source (normative): [docs/spec/core/canonicalization-v1.md](../../../docs/spec/core/canonicalization-v1.md), 6. Serialization Rules (normative) (MUST).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/crypto/hashes.ts](../../../packages/core/src/crypto/hashes.ts) — `canonicalizeToJson`

Evidence:

- [packages/core/src/test/canonicalization.property.test.ts](../../../packages/core/src/test/canonicalization.property.test.ts) — `C-P6: floats, NaN, and ±Infinity are always rejected with FLOAT_NOT_ALLOWED` (unit; negative=true; portable=false). Core canonicalization property test for the selected serialization rule. Runner: `pnpm -C packages/core test` (TypeScript).
- [docs/spec/test-vectors/canonicalization-v1.json](../../../docs/spec/test-vectors/canonicalization-v1.json) — `i1-float-rejected` (cross-runtime; negative=true; portable=true). Float rejection and expected error code. Runner: `pnpm test:vectors:py` (Python).

## CANON-003 — Reject duplicate keys at raw input parsing

Source (normative): [docs/spec/core/canonicalization-v1.md](../../../docs/spec/core/canonicalization-v1.md), 5. Input Parsing Requirements (MUST).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: specified. Evidence: gap. Scope: in-scope. Maintainer decision required: true.

Scope notes: Core canonicalJson receives objects, after raw duplicate keys may be lost. NFC collision detection is not evidence of duplicate-key-aware raw JSON parsing.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## AUTH-ARTIFACT-001 — Reject decisions other than ALLOW

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), 4. Canonical Semantic Model (MUST).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`

Evidence:

- [packages/conformance/vectors/authorization-verification.json](../../../packages/conformance/vectors/authorization-verification.json) — `authorization-verify-004` (vector; negative=true; portable=false). Non-ALLOW decision rejected with AUTH_DECISION_INVALID. Runner: `pnpm -C packages/conformance validate` (TypeScript).

## AUTH-VERIFY-001 — Reject invalid Ed25519 signatures

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), 8. Signature Requirements (MUST).

Type: requirement. Category: VERIFY. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`

Evidence:

- [packages/conformance/vectors/authorization-signature-verification.json](../../../packages/conformance/vectors/authorization-signature-verification.json) — `authorization-sig-002` (vector; negative=true; portable=false). Corrupted signature fails verification. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-1 tampered signature: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Guard blocks execute on corrupted signature. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-VERIFY-002 — Issuer-scoped trusted key resolution

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), 8. Signature Requirements (MUST).

Type: requirement. Category: TRUST. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: expectedIssuer is meaningful when independently established. Scalar expectations are not inherently defective; this claim does not prove provenance of configuration.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`

Evidence:

- [packages/conformance/vectors/authorization-signature-verification.json](../../../packages/conformance/vectors/authorization-signature-verification.json) — `authorization-sig-004` (vector; negative=true; portable=false). Wrong issuer yields issuer mismatch and unknown key. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-2 unknown issuer: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Unknown issuer signed with separate key cannot execute. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-VERIFY-003 — Audience matches execution boundary

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), audience (MUST).

Type: requirement. Category: VERIFY. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`
- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`

Evidence:

- [packages/conformance/vectors/authorization-signature-verification.json](../../../packages/conformance/vectors/authorization-signature-verification.json) — `authorization-sig-005` (vector; negative=true; portable=false). Wrong expected audience rejects. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-3 wrong audience: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Wrong audience blocks callback execution. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-BIND-001 — Intent hash exactly matches requested action

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), intent_hash (MUST).

Type: requirement. Category: ENFORCEMENT. Classification: implementation-specific.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Guard integration checks normalized action binding. Pure verifyAuthorization does not recompute the requested action; no portable vector is asserted here.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`
- [packages/core/src/crypto/hashes.ts](../../../packages/core/src/crypto/hashes.ts) — `intentHash`

Evidence:

- [packages/guard/src/test/guard.intent-binding.test.ts](../../../packages/guard/src/test/guard.intent-binding.test.ts) — `IB-2 wrong intent_hash in auth: OxDeAIAuthorizationError thrown, execute blocked` (integration; negative=true; portable=false). Authorization for action A cannot execute action B. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-TIME-001 — Strict expiry at now greater than or equal to expiry

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), expiry / expires_at (MUST).

Type: requirement. Category: TIME. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`

Evidence:

- [packages/conformance/vectors/authorization-verification.json](../../../packages/conformance/vectors/authorization-verification.json) — `authorization-verify-002` (vector; negative=true; portable=false). now equals expiry returns AUTH_EXPIRED. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-4 expired auth: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Expired signed authorization cannot execute. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-TRUST-001 — Missing strict trust configuration fails closed

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), Strict mode (MUST).

Type: requirement. Category: TRUST. Classification: implementation-specific.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence is guard configuration enforcement. It does not establish honesty of supplied keys or policy premises.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyAuthorization.ts](../../../packages/core/src/verification/verifyAuthorization.ts) — `verifyAuthorization`
- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`

Evidence:

- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-5 missing trustedKeySets: OxDeAIGuardConfigurationError thrown at construction` (integration; negative=true; portable=false). Guard construction rejects missing trustedKeySets. Runner: `pnpm -C packages/guard test` (TypeScript).

## AUTH-REPLAY-001 — Reused auth_id cannot execute

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), 11. Replay Protection (MUST).

Type: requirement. Category: REPLAY. Classification: implementation-specific.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: In-memory/shared-store integration scope only; not proof of distributed durable replay storage.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`
- [packages/guard/src/replayStore.ts](../../../packages/guard/src/replayStore.ts) — `createInMemoryReplayStore`

Evidence:

- [packages/guard/src/test/guard.replay-store.test.ts](../../../packages/guard/src/test/guard.replay-store.test.ts) — `RS-1 default store: auth_id replay blocked on second call to same guard instance` (integration; negative=true; portable=false). Second use blocked; exactly one execution. Runner: `pnpm -C packages/guard test` (TypeScript).
- [packages/guard/src/test/guard.replay-store.test.ts](../../../packages/guard/src/test/guard.replay-store.test.ts) — `RS-3 shared store: auth_id replay blocked across two distinct guard instances` (integration; negative=true; portable=false). Shared store blocks replay across guard instances. Runner: `pnpm -C packages/guard test` (TypeScript).

## TRUSTED-TIME-001 — Issuance uses trusted evaluation time

Source (normative): [docs/spec/core/trusted-time-v1.md](../../../docs/spec/core/trusted-time-v1.md), 4. Consistency Invariants (MUST).

Type: requirement. Category: TIME. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/policy/PolicyEngine.ts](../../../packages/core/src/policy/PolicyEngine.ts) — `PolicyEngine`

Evidence:

- [packages/core/src/test/trusted-time-integration.test.ts](../../../packages/core/src/test/trusted-time-integration.test.ts) — `issuance tripwire: issued_at and expiry derive from evaluationTime, not intent.timestamp` (integration; negative=true; portable=false). Future-side freshness-valid intent does not drive issuance or expiry. Runner: `pnpm -C packages/core test` (TypeScript).

## TRUSTED-TIME-002 — Reject future freshness violations

Source (normative): [docs/spec/core/trusted-time-v1.md](../../../docs/spec/core/trusted-time-v1.md), 6. Freshness Semantics (Future and Stale) (normative-statement).

Type: requirement. Category: TIME. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/policy/verifyTrustedTime.ts](../../../packages/core/src/policy/verifyTrustedTime.ts) — `verifyTrustedTime`
- [packages/core/src/policy/PolicyEngine.ts](../../../packages/core/src/policy/PolicyEngine.ts) — `PolicyEngine`

Evidence:

- [packages/core/src/test/trusted-time-integration.test.ts](../../../packages/core/src/test/trusted-time-integration.test.ts) — `future-dated intent → exactly DENY/INTENT_FRESHNESS_FUTURE` (integration; negative=true; portable=false). Future timestamp yields exactly DENY/INTENT_FRESHNESS_FUTURE. Runner: `pnpm -C packages/core test` (TypeScript).

## DELEGATION-001 — Child tools cannot widen supplied parentScope

Source (normative): [docs/spec/artifacts/delegation-v1.md](../../../docs/spec/artifacts/delegation-v1.md), 4.1 Scope Narrowing (MUST).

Type: requirement. Category: DELEGATION. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Narrowing is relative to caller-supplied parentScope; no evidence that the scope originated from an authoritative external grant.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyDelegation.ts](../../../packages/core/src/verification/verifyDelegation.ts) — `verifyDelegation`

Evidence:

- [packages/conformance/vectors/delegation-verification.json](../../../packages/conformance/vectors/delegation-verification.json) — `delegation-verify-005` (vector; negative=true; portable=false). Tool outside caller-supplied parent scope rejected. Runner: `pnpm -C packages/conformance validate` (TypeScript).

## DELEGATION-002 — Reject delegation as parent (single hop)

Source (normative): [docs/spec/artifacts/delegation-v1.md](../../../docs/spec/artifacts/delegation-v1.md), 4.4 Single-Hop Enforcement (MUST NOT).

Type: requirement. Category: DELEGATION. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyDelegation.ts](../../../packages/core/src/verification/verifyDelegation.ts) — `verifyDelegationChain`

Evidence:

- [packages/conformance/vectors/delegation-chain-verification.json](../../../packages/conformance/vectors/delegation-chain-verification.json) — `delegation-chain-006` (vector; negative=true; portable=false). Delegation parent rejected as multihop. Runner: `pnpm -C packages/conformance validate` (TypeScript).

## DELEGATION-003 — Delegation policy equals parent policy

Source (normative): [docs/spec/artifacts/delegation-v1.md](../../../docs/spec/artifacts/delegation-v1.md), 4.1 Scope Narrowing (MUST).

Type: requirement. Category: DELEGATION. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: This binds two artifacts. It does not prove that an issuer is independently authorized for that policy. Generic expectedPolicyId remains valid when independently configured.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/verification/verifyDelegation.ts](../../../packages/core/src/verification/verifyDelegation.ts) — `verifyDelegationChain`

Evidence:

- [packages/conformance/vectors/delegation-chain-verification.json](../../../packages/conformance/vectors/delegation-chain-verification.json) — `delegation-chain-007` (vector; negative=true; portable=false). Child-parent policy mismatch rejected. Runner: `pnpm -C packages/conformance validate` (TypeScript).

## SIGNED-KRL-001 — Duplicate revoked kids rejected

Source (normative): [docs/spec/artifacts/signed-krl-v1.md](../../../docs/spec/artifacts/signed-krl-v1.md), 9. `revoked_kids` deduplication (MUST).

Type: requirement. Category: TRUST. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Dependency: RT-TRUST-2 (conditional-mitigation). Artifact verification alone does not close the deployment KRL residual.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: KRL_SIGNATURE_VALID → KRL_DEPLOYMENT_RESIDUAL_CLOSED. Required deployment configuration and persistent stores are not established by artifact vectors.

Implementation:

- [packages/core/src/verification/verifySignedKrl.ts](../../../packages/core/src/verification/verifySignedKrl.ts) — `verifySignedKrl`

Evidence:

- [packages/conformance/vectors/signed-krl-verification.json](../../../packages/conformance/vectors/signed-krl-verification.json) — `krl-005` (vector; negative=true; portable=false). Duplicate revoked kid entries rejected. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [docs/spec/test-vectors/signed-krl-v1.json](../../../docs/spec/test-vectors/signed-krl-v1.json) — `KRL_DUPLICATE_REVOKED_KIDS` (cross-runtime; negative=true; portable=true). Independent Python duplicate-entry rejection. Runner: `pnpm test:vectors:py` (Python).

## SIGNED-KRL-002 — Invalid KRL signature rejected

Source (normative): [docs/spec/artifacts/signed-krl-v1.md](../../../docs/spec/artifacts/signed-krl-v1.md), 10. Reason codes (normative-statement).

Type: requirement. Category: VERIFY. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Evidence demonstrates the selected cases only; review semantic adequacy when changing this claim.

Dependency: RT-TRUST-2 (conditional-mitigation). Artifact verification alone does not close the deployment KRL residual.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: KRL_SIGNATURE_VALID → KRL_DEPLOYMENT_RESIDUAL_CLOSED. Required deployment configuration and persistent stores are not established by artifact vectors.

Implementation:

- [packages/core/src/verification/verifySignedKrl.ts](../../../packages/core/src/verification/verifySignedKrl.ts) — `verifySignedKrl`

Evidence:

- [packages/conformance/vectors/signed-krl-verification.json](../../../packages/conformance/vectors/signed-krl-verification.json) — `krl-002` (vector; negative=true; portable=false). Tampered signature rejected. Runner: `pnpm -C packages/conformance validate` (TypeScript).
- [docs/spec/test-vectors/signed-krl-v1.json](../../../docs/spec/test-vectors/signed-krl-v1.json) — `KRL_SIGNED_INVALID_SIG` (cross-runtime; negative=true; portable=true). Independent Python Ed25519 verification rejects tampering. Runner: `pnpm test:vectors:py` (Python).

## PROFILE-C-001 — Live-state hash must match committed state hash

Source (normative): [docs/spec/interoperability/external-provider-profile.md](../../../docs/spec/interoperability/external-provider-profile.md), 2.3.2 Additional Verifier Requirements (beyond Profile B) (normative-statement).

Type: requirement. Category: STATE. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Portable evidence covers hash comparison only. Guard integration covers callback blocking separately. Neither establishes current or honest state.

Dependency: RT-TRUST-1 (trust-premise). State-hash consistency does not establish state-provider integrity.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: STATE_HASH_MATCH → STATE_SOURCE_TRUSTED. Honest, current, authoritative state is a deployment premise.

Implementation:

- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`

Evidence:

- [packages/guard/src/test/guard.state-binding.test.ts](../../../packages/guard/src/test/guard.state-binding.test.ts) — `SB-2 mismatched state_hash: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Mismatched state hash blocks execute. Runner: `pnpm -C packages/guard test` (TypeScript).
- [docs/spec/test-vectors/profile-c-state-verification.json](../../../docs/spec/test-vectors/profile-c-state-verification.json) — `profile-c-002` (cross-runtime; negative=true; portable=true). Portable hash comparison mismatch, not execution or provider honesty. Runner: `pnpm test:vectors:py` (Python).

## PEP-ENFORCE-001 — Invalid authorization prevents execution

Source (normative): [docs/spec/artifacts/authorization-v1.md](../../../docs/spec/artifacts/authorization-v1.md), 1. Purpose (MUST NOT).

Type: requirement. Category: ENFORCEMENT. Classification: implementation-specific.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Selected guard rejection case only. Does not prove every possible execution path is non-bypassable.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/guard/src/guard.ts](../../../packages/guard/src/guard.ts) — `OxDeAIGuard`

Evidence:

- [packages/guard/src/test/guard.authorization.test.ts](../../../packages/guard/src/test/guard.authorization.test.ts) — `A-1 tampered signature: execute is blocked and OxDeAIAuthorizationError is thrown` (integration; negative=true; portable=false). Invalid signature prevents execute callback. Runner: `pnpm -C packages/guard test` (TypeScript).

## PEP-DEPLOY-001 — Gateway is sole execution boundary

Source (normative): [docs/spec/enforcement/pep-gateway-v1.md](../../../docs/spec/enforcement/pep-gateway-v1.md), 4.1 Execution Boundary (MUST).

Type: requirement. Category: TRUST. Classification: deployment-assumption.

Normative: specified. Evidence: gap. Scope: deployment. Maintainer decision required: true.

Scope notes: Deployment topology and upstream access control must be independently evidenced. Gateway tests cannot prove arbitrary deployment non-bypassability.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## STATE-TRUST-001 — State provider serves coherent view

Source (normative): [docs/spec/state-provider-requirements.md](../../../docs/spec/state-provider-requirements.md), 2.1 Requirement (MUST).

Type: requirement. Category: STATE. Classification: deployment-assumption.

Normative: specified. Evidence: gap. Scope: deployment. Maintainer decision required: true.

Scope notes: Provider honesty/coherence is an external deployment obligation. Hash equality and CAS tests do not demonstrate it for a deployed provider.

Dependency: RT-TRUST-1 (trust-premise). State-hash consistency does not establish state-provider integrity.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: STATE_HASH_MATCH → STATE_SOURCE_TRUSTED. Honest, current, authoritative state is a deployment premise.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## VERIFY-ORDER-001 — Normative verification ordering

Source (normative): [docs/spec/verification/verification-v1.md](../../../docs/spec/verification/verification-v1.md), 9. Determinism and Ordering (MUST).

Type: requirement. Category: VERIFY. Classification: portable.

Normative: ambiguous. Evidence: gap. Scope: in-scope. Maintainer decision required: true.

Scope notes: Verification §5 puts signature before expiry; AuthorizationV1 §10 puts expiry before signature. Core collects/sorts violations. No claim of satisfying both incompatible sequences.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## DELEGATION-AUDIT-001 — PEP delegation events included in hash-chained audit log

Source (normative): [docs/spec/artifacts/delegation-v1.md](../../../docs/spec/artifacts/delegation-v1.md), 7. Audit Event (MUST).

Type: requirement. Category: AUDIT. Classification: implementation-specific.

Normative: specified. Evidence: gap. Scope: in-scope. Maintainer decision required: true.

Scope notes: No direct mapping found for required DELEGATION_EXECUTION/DELEGATION_DENIED hash-chained events. Guard boundary event callbacks alone are not evidence of this contract.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## ETA-SIGNING-001 — ETA signing payload excludes entire signature field

Source (normative): [docs/spec/core/eta-core-v1.md](../../../docs/spec/core/eta-core-v1.md), 5. Authorization Artifact (AuthorizationV1) (MUST).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: ambiguous. Evidence: gap. Scope: in-scope. Maintainer decision required: true.

Scope notes: ETA excludes entire signature field; AuthorizationV1 §5 retains nested alg/kid and defines encoding-specific prefix. Normative docs vectors use another verifier/preimage; do not equate corpora.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## ETA-DETERMINISM-001 — Identical trusted inputs produce deterministic signed authorizations

Source (normative): [docs/spec/core/eta-core-v1.md](../../../docs/spec/core/eta-core-v1.md), Requirements (MUST).

Type: requirement. Category: ARTIFACT. Classification: portable.

Normative: specified. Evidence: mapped. Scope: in-scope. Maintainer decision required: false.

Scope notes: Inputs include trusted evaluationTime and fixed configuration per trusted-time profile. This selected test does not prove all decision modules deterministic.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Implementation:

- [packages/core/src/policy/PolicyEngine.ts](../../../packages/core/src/policy/PolicyEngine.ts) — `PolicyEngine`

Evidence:

- [packages/core/src/test/authorization.trusted-time-issuance.test.ts](../../../packages/core/src/test/authorization.trusted-time-issuance.test.ts) — `identical trusted inputs produce deterministic Ed25519 authorizations` (integration; negative=false; portable=false). Repeated trusted inputs produce identical Ed25519 authorization objects. Runner: `pnpm -C packages/core test` (TypeScript).

## CANON-ESC-001 — Unresolved canonicalization corpus lock (maintainer-supplied identifier)

Source (context): [docs/spec/core/canonicalization-v1.md](../../../docs/spec/core/canonicalization-v1.md), 6. Serialization Rules (normative) (not-applicable).

Type: corpus-lock. Category: ARTIFACT. Classification: documentation-only.

Normative: unresolved. Evidence: unassessed. Scope: deferred. Maintainer decision required: true.

Scope notes: CANON-ESC-001 was requested for registration by the maintainer; no existing repository definition of this identifier was found. This source is context only. Exact escaping/corpus-lock meaning and disposition require a maintainer decision; no new serialization rule is asserted.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: SELECTED_CANONICALIZATION_VECTORS_PASS → CANON_ESC_LOCK_RESOLVED. Existing vectors do not resolve an undefined corpus lock.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## RT-TRUST-1 — State provider integrity residual

Source (context): [docs/audits/protocol-audit-post-interoperability.md](../../../docs/audits/protocol-audit-post-interoperability.md), 5.3 Residual Trust Risks (not-applicable).

Type: corpus-lock. Category: TRUST. Classification: documentation-only.

Normative: non-normative. Evidence: unassessed. Scope: deployment. Maintainer decision required: true.

Scope notes: The residual is not closed. Minimum state-provider requirements exist, but provider compliance and integrity remain deployment responsibilities. This lock is an audit observation, not another executable protocol requirement.

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: STATE_HASH_MATCH → STATE_SOURCE_TRUSTED. Matching state can be manufactured by a compromised provider.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.

## RT-TRUST-2 — Conditional KRL transport-integrity residual

Source (context): [docs/spec/interoperability/external-provider-profile.md](../../../docs/spec/interoperability/external-provider-profile.md), 2.2.5 KRL Integrity at Profile B (not-applicable).

Type: corpus-lock. Category: TRUST. Classification: documentation-only.

Normative: non-normative. Evidence: unassessed. Scope: conditional. Maintainer decision required: true.

Scope notes: Conditional closure is documented for configured deployments, not established here. Compatibility modes retain residual risk. Applicability conditions describe the documented closure context; the checker never evaluates a deployment or declares this lock closed.

Contextual all-of conditions (not evaluated): [{"setting":"krlMode","equals":"signed_required"},{"setting":"verifyKrl","equals":"configured"},{"setting":"KrlWatermarkStore","equals":"configured"},{"setting":"SignedKrlCache","equals":"configured"}]

Forbidden inference: STRUCTURAL_PASS → SEMANTIC_PROOF. Reference consistency does not prove the claimed semantics.

Forbidden inference: TESTED → WHOLE_PROTOCOL_CONFORMANCE. Selected executable cases do not establish whole-protocol conformance.

Forbidden inference: KRL_SIGNATURE_VALID → KRL_DEPLOYMENT_RESIDUAL_CLOSED. Signature verification does not establish integrity mode, callback, durable watermark or signed cache configuration.

Implementation:

- No direct executable mapping claimed.

Evidence:

- No executable evidence claimed.
