# OxDeAI Specification (v1.0.2)

This document is a protocol-grade specification aligned to shipped OxDeAI v1.0.2 behavior.

- Normative protocol text is in [`protocol/protocol.md`](./protocol/protocol.md).
- This document is a complete implementation-facing companion for builders and auditors.
- If this document conflicts with the normative protocol file, the normative protocol file wins.

## 1. Scope and Non-Goals

### 1.1 Scope

OxDeAI defines deterministic, pre-execution economic containment for autonomous systems.

A compliant implementation MUST evaluate `(intent, state)` and produce deterministic policy artifacts:

- decision (`ALLOW` or `DENY`)
- authorization (only on `ALLOW`)
- state transition
- append-only audit events
- stateless verification outputs

### 1.2 Non-Goals

OxDeAI does not attempt to solve:

- general observability/monitoring platforms
- semantic safety or content safety of model outputs
- identity, transport, or settlement network security by itself

## 2. Terminology Glossary

- Intent: Requested action plus policy-relevant fields.
- State: Economic policy state used during evaluation.
- PolicyEngine: Deterministic evaluator over `(intent, state)`.
- CanonicalState: Canonical snapshot object used for portable state exchange.
- Snapshot bytes: Canonical UTF-8 bytes of `CanonicalState`.
- Authorization: Allow artifact bound to intent hash, state hash, policy version, and expiry.
- AuditEvent: One event in the append-only audit stream.
- Audit head hash: Deterministic chain tip computed from ordered events.
- STATE_CHECKPOINT: Audit event carrying `stateHash` for strict anchoring.
- VerificationEnvelopeV1: Portable artifact containing snapshot and audit events.
- VerificationResult: Unified verifier output (`ok | invalid | inconclusive`).

## 3. Artifact Model

## 3.1 Intent

Intent fields are defined by the public `Intent` type in `@oxdeai/core`.
For hash binding, implementations MUST follow the binding projection behavior of the shipped runtime:

- `signature` MUST be excluded from `intent_hash`.
- unknown non-binding fields MUST NOT affect `intent_hash`.
- canonical JSON MUST be used before hashing.

Minimal example:

```json
{
  "intent_id": "intent-1",
  "agent_id": "agent-1",
  "action_type": "PROVISION",
  "amount": "320",
  "target": "us-east-1",
  "timestamp": 1772718102,
  "metadata_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "nonce": "1",
  "signature": "placeholder"
}
```

## 3.2 Policy State and CanonicalState

Runtime policy state contains module slices (budget, velocity, replay, concurrency, recursion, kill switch, allowlists, tool limits).
Portable snapshots are represented as:

- `formatVersion: 1`
- `engineVersion: string`
- `policyId: string`
- `modules: Record<string, unknown>`

Minimal `CanonicalState` example:

```json
{
  "formatVersion": 1,
  "engineVersion": "1.0.2",
  "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de",
  "modules": {
    "BudgetModule": {
      "budget_limit": { "agent-1": "1000000" },
      "spent_in_period": { "agent-1": "320" }
    }
  }
}
```

## 3.3 Canonical Snapshot Encoding (`formatVersion = 1`)

Snapshot bytes MUST be canonical UTF-8 JSON bytes of `CanonicalState`.

Canonical JSON requirements:

- object keys sorted lexicographically
- arrays preserved in given order
- `undefined` normalized to `null` where applicable
- bigint-like values represented as base-10 strings in canonical JSON paths
- non-finite numbers rejected

## 3.4 Authorization Artifact (Current v1.0.2 Behavior)

The authorization object emitted on `ALLOW` includes:

- `authorization_id`
- `intent_hash`
- `policy_version`
- `state_snapshot_hash`
- `decision` (`ALLOW`)
- `expires_at`
- `engine_signature`

Signature scheme in v1.0.2 is symmetric-key HMAC (implementation profile in `@oxdeai/core`).
Public-key non-forgeable signatures are not part of v1.0.2 protocol requirements.

Minimal authorization example:

```json
{
  "authorization_id": "19e9022f6bc34e77489c3c480629ae41a68f17c8b42685c482ae060755b800ef",
  "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
  "policy_version": "v1",
  "state_snapshot_hash": "8e0d8542b8c9b02fdd9862d720f4755ff3ae04bd51fae5fb58dae7089ddf1beb",
  "decision": "ALLOW",
  "expires_at": 1772718222,
  "engine_signature": "hex-hmac"
}
```

## 3.5 Audit Events and Chain Rules

Audit events are typed JSON objects (`INTENT_RECEIVED`, `DECISION`, `AUTH_EMITTED`, `EXECUTION_ATTESTED`, `STATE_CHECKPOINT`).

Event normalization for hashing MUST include:

- `policyId: event.policyId ?? null`
- canonical JSON encoding

Reference chain in the engine log (`HashChainedLog`) uses:

- initial previous hash `"GENESIS"`
- `next = sha256(prev + "\n" + canonicalEventBytes)`

`verifyAuditEvents` computes a deterministic `auditHeadHash` by replaying the provided event list and applying its shipped chain routine.
Timestamps MUST be non-decreasing.

Minimal audit excerpt:

```json
[
  {
    "type": "INTENT_RECEIVED",
    "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
    "agent_id": "agent-1",
    "timestamp": 1772718102,
    "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de"
  },
  {
    "type": "STATE_CHECKPOINT",
    "stateHash": "30a1b0957089e6cc9e43afd0a71ad9a02389afc59657dafb66d5768c62987c75",
    "timestamp": 1772718102,
    "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de"
  }
]
```

## 3.6 Verification Envelope

`VerificationEnvelopeV1` logical structure:

- `formatVersion: 1`
- `snapshot: Uint8Array` (canonical snapshot bytes)
- `events: AuditEntry[]`

Wire encoding in v1.0.2 uses canonical JSON with:

- `formatVersion: 1`
- `snapshot: "<base64>"`
- `events: [...]`

Minimal wire JSON example:

```json
{
  "formatVersion": 1,
  "snapshot": "eyJmb3JtYXRWZXJzaW9uIjoxLCJlbmdpbmVWZXJzaW9uIjoiMS4wLjIiLCJwb2xpY3lJZCI6Ii4uLiIsIm1vZHVsZXMiOnt9fQ==",
  "events": []
}
```

## 4. Determinism Requirements

Compliant implementations MUST satisfy:

- same input intent/state/config => same decision and artifacts
- canonical serialization for all hashed artifacts
- deterministic ordering of module and verification outputs
- no hidden entropy in policy-critical logic

Strict no-entropy rule:

- policy-critical paths MUST NOT depend on randomness
- policy-critical paths MUST NOT depend on ambient wall clock where deterministic input is required
- verification functions MUST be pure (no I/O, clocks, randomness, env reads)

## 5. Verification Surface

## 5.1 Functions

Stateless verification API:

- `verifySnapshot(snapshotBytes, opts?)`
- `verifyAuditEvents(events, opts?)`
- `verifyEnvelope(envelopeBytes, opts?)`

## 5.2 `VerificationResult`

All three verifiers return:

- `ok: boolean`
- `status: "ok" | "invalid" | "inconclusive"`
- `violations: VerificationViolation[]`
- optional `policyId`, `stateHash`, `auditHeadHash`

## 5.3 Status Semantics

- `ok`: artifact verifies under selected mode.
- `invalid`: malformed or inconsistent artifact(s).
- `inconclusive`: valid enough to parse/replay but insufficient strict anchoring evidence.

## 5.4 Deterministic Violation Ordering

Violations MUST be sorted deterministically by:

1. `code` (lexicographic)
2. `index` (ascending, default 0 when absent)

## 5.5 Strict vs Best-Effort

`verifyAuditEvents` and `verifyEnvelope` accept mode:

- `strict` (default): missing state anchor causes `inconclusive`
- `best-effort`: missing state anchor does not block `ok` if no invalid violations exist

## 6. Replay Verification and State Anchors

`STATE_CHECKPOINT` with `stateHash` is the strict replay anchor in v1.0.2 verifier behavior.

Rules:

- strict mode MUST return `inconclusive` when no valid state checkpoint is present
- strict mode MUST NOT silently upgrade unanchored traces to `ok`
- best-effort MAY return `ok` without anchors when no invalid violations exist

## 7. Security Model and Threat Analysis

## 7.1 Covered Threats

- replay/duplicate intent processing (nonce/state replay modules)
- tampered audit order/content (hash chain replay)
- policy identity mismatch (`policyId` checks)
- non-monotonic event time ordering

## 7.2 Forgery Risk in v1.0.2

Authorization proof is symmetric-key HMAC in the reference profile.
This means verification trust is scoped to parties sharing key custody policy.
Cross-party non-forgeable public verification is not a v1.0.2 guarantee.

## 7.3 Operational Guidance (Non-Protocol)

- store signing keys in KMS/HSM-backed controls
- rotate keys with overlap windows
- keep key-to-environment/tenant isolation strict
- treat `invalid` and (in strict environments) `inconclusive` as fail-closed outcomes

## 8. Backward Compatibility and Evolution

## 8.1 `formatVersion` Rules

- `formatVersion = 1` is stable for v1.0.x.
- any incompatible wire/schema change MUST use a new formatVersion and major protocol release.

## 8.2 `policyId` Expectations

`policyId` binds artifacts to a policy configuration profile.
When policy logic/config changes in a way that changes policy identity, outputs SHOULD reflect a new `policyId`.

## 8.3 Violation Code Evolution

Existing violation code semantics MUST remain stable in `1.0.x`.
Adding new codes MAY be done in backward-compatible releases if:

- existing codes are unchanged
- deterministic ordering rules remain unchanged
- consumers can still parse known codes safely

Removing or repurposing existing codes is a breaking change.

## 9. Conformance

Conformance vectors in `@oxdeai/conformance` are the executable behavioral contract for v1.0.2 profile.

Current assertion categories include:

- intent hashing invariants
- authorization payload/signature outputs
- snapshot encoding and state hash outputs
- audit chain recomputation invariants
- envelope verification status/field propagation/violations

A conformant implementation MUST reproduce expected outputs for the published vector set for its targeted protocol version.

## 10. Relying Party (PEP) Contract

This section defines how an external Policy Enforcement Point (PEP), tool gateway, or provider MUST gate execution.

Two verification paths are distinct:

- Authorization pre-exec verification (capability-token style gate)
- Envelope post-exec verification (audit-grade verification evidence)

## 10.1 Authorization Pre-Execution Verification

Before executing any side effect, a relying party MUST verify authorization validity against the intended execution input.

Required checks:

1. Signature validity  
The relying party MUST validate the authorization signature using the configured v1.0.2 trust profile (shared-secret/HMAC profile in the reference implementation).

2. TTL / expiry  
The relying party MUST reject authorization when `now > expires_at`.

3. Intent binding  
The relying party MUST recompute expected `intent_hash` from the execution intent binding fields and require equality with `authorization.intent_hash`.

4. Policy identity binding  
The relying party SHOULD require policy identity consistency with its expected environment profile.  
In v1.0.2 artifacts this is primarily enforced via policy version/state binding checks and runtime policy identity configuration.

5. Decision binding  
The relying party MUST require `decision == "ALLOW"` in the authorization artifact.

If any required check fails, execution MUST be denied (fail closed).

## 10.2 Envelope Post-Execution Verification

Envelope verification is not a pre-execution capability check by itself.  
It is an audit-grade integrity proof over snapshot + audit stream.

A relying party/auditor verifying envelope evidence MUST:

1. Run `verifyEnvelope(envelopeBytes, opts?)`.
2. Require `status == "ok"` for strict pass outcomes.
3. Treat `status == "invalid"` as failed evidence.
4. Treat `status == "inconclusive"` as non-pass under strict compliance policy.

Required consistency checks (performed by verifier surface):

- snapshot integrity (`verifySnapshot`)
- audit integrity and ordering (`verifyAuditEvents`)
- policy identity consistency between snapshot and audit (`policyId` checks)
- deterministic violation ordering in output

## 10.3 Strict State-Anchor Constraints

When strict mode is selected:

- missing `STATE_CHECKPOINT` anchor MUST produce `inconclusive`
- relying parties requiring strict evidence MUST reject `inconclusive` for final settlement/compliance acceptance

Best-effort mode MAY be used for diagnostics, but MUST NOT be treated as strict proof in systems that require anchored replay evidence.

## 11. Future Work (Explicitly Non-v1.0.2)

- Non-forgeable verification profile (public-key signatures) targeted for v1.2.
- Design note: see [`docs/NON_FORGEABLE_VERIFICATION.md`](./docs/NON_FORGEABLE_VERIFICATION.md).
- Extended multi-party verification metadata profiles.
- Additional cross-runtime conformance vectors.

## Appendix A. Implementation Notes

- Reference implementation: `@oxdeai/core` (TypeScript).
- Companion packages:
  - `@oxdeai/sdk` (integration helpers)
  - `@oxdeai/conformance` (vectors + validator)
- Production users SHOULD pin compatible package versions and validate against frozen vectors.
