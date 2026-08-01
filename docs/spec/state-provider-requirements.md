# OxDeAI State Provider Requirements

**Version:** v1.0  
**Status:** Normative (Specification)  
**Category:** Deployment Compliance  
**Related:** `docs/spec/enforcement/pep-gateway-v1.md`, `docs/spec/interoperability/external-provider-profile.md`, `docs/audits/protocol-audit-post-interoperability.md`

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, **MAY**, and **RECOMMENDED** in this document are to be interpreted as described in RFC 2119.

---

## 1. Trust Boundary

### 1.1 What OxDeAI verifies

`OxDeAIGuard` calls `config.getState()` to obtain the live state object at enforcement time. It verifies:

```
computeStateHash(liveState) === authorization.state_hash
```

This proves that the state object returned by `getState()` is hash-consistent with the `state_hash` committed in the `AuthorizationV1` artifact at authorization time.

### 1.2 What OxDeAI does not verify

OxDeAI does not verify:

- That `getState()` serves state from an honest, authoritative source
- That the state object was not manufactured to produce a matching hash
- That the state source has not been rolled back to an earlier version
- That the state provider is not experiencing split-brain or replica inconsistency
- That the state was not mutated by an unauthorized actor between authorization and enforcement

These are deployment-level properties. A compromised or non-compliant state provider can return a manufactured state object whose hash matches a valid authorization, allowing the guard's semantic check to pass against a dishonest state source. **The protocol cannot detect this at the PEP layer.**

### 1.3 The deployment trust contract

`getState()` is trusted input to the guard. A deployment that configures a non-compliant state provider retains the RT-TRUST-1 residual risk: the guard's state-hash verification proves hash consistency between the authorization artifact and the live state object, but does not prove that the state object is honest, current, or derived from a compliant source of truth.

This specification defines minimum integrity requirements that a state provider must satisfy for a deployment to be considered compliant with the OxDeAI state provider trust boundary. Compliance is a deployment responsibility; the protocol cannot enforce it at the wire level.

### 1.4 Profile-specific applicability

#### Profile C (Full semantic state verification)

Deployments using `OxDeAIGuard` with live-state re-verification via `computeStateHash` are **Profile C** deployments. In Profile C, `getState()` is called at enforcement time and the result is directly used for the authorization decision. **State provider integrity requirements in this specification are minimum compliance requirements for Profile C deployments.** A Profile C deployment that cannot demonstrate state provider compliance cannot honestly claim that its authorization decisions are semantically bound to an honest state.

#### Profile A and Profile B

Profile A (Core-native AuthorizationV1) and Profile B (External provider wire-compatible) do not perform live-state re-verification at the gateway level. `state_hash` is protected by Ed25519 signature integrity - tampering `state_hash` produces `AUTH_SIGNATURE_INVALID`. There is no `getState()` call in the enforcement path.

**For Profile A/B deployments, the requirements in this specification are best-practice guidance unless the deployment introduces state-dependent enforcement equivalent to Profile C** (e.g., an adapter that re-fetches live state and re-computes a hash for comparison with the authorization artifact).

---

## 2. Read Consistency

### 2.1 Requirement

A compliant state provider MUST serve a coherent state view to `getState()`.

Specifically:

- The state object returned by `getState()` for a given authorization context MUST reflect the same logical state that the policy engine evaluated when producing the `AuthorizationV1` artifact, unless an authorized state mutation has occurred between authorization and enforcement.
- The state provider MUST support compare-and-set (CAS) or an equivalent linearizable write mechanism so that concurrent state mutations can be detected atomically at the time `setState(nextState, expectedVersion)` is called.
- The `StateVersion` token returned by `getState()` MUST NOT be null or undefined. A missing version token causes the guard to fail closed.
- The state provider MUST NOT return a version token that has been decremented or reset to a prior value unless an authorized rollback/restore event has occurred and been audited.

### 2.2 Concurrent mutation

The guard enforces that the version read by `getState()` matches the version expected by `setState()`. If a concurrent modification advances the version between the `getState()` call and the `setState()` call, `setState()` MUST return `false` and the guard throws `OxDeAIConflictError`, blocking execution.

The state store backing `getState()` and `setState()` MUST provide atomicity guarantees sufficient to make this detection reliable. Implementations SHOULD use database-level CAS, optimistic locking, or conditional write operations.

Trusted-time velocity accounting does not replace this requirement. Although
velocity window progression is derived exclusively from the trusted
`evaluation_time` defined in `docs/spec/core/trusted-time-v1.md` §7, concurrent
evaluators can still read the same counter and each attempt to consume the same
remaining slot. The provider MUST serialize those updates or reject all but one
through atomic compare-and-set. Distributed PEP clocks SHOULD be synchronized
and non-decreasing; a clock behind a persisted velocity `window_start` causes a
fail-closed `STATE_INVALID` decision.

The same requirements apply to trusted-time tool-call windows. Persisted
`tool_limits.calls` timestamps and pruning are driven only by
`evaluation_time`; caller-controlled `intent.timestamp` is non-authoritative.
Concurrent evaluators can still race to consume the same remaining tool quota,
so providers MUST serialize or reject conflicting updates. An evaluation clock
behind a persisted call timestamp fails closed with `STATE_INVALID`.

### 2.3 Stale replica reads

For Profile C deployments, `getState()` MUST read from the authoritative replica of the state store, not from a potentially stale secondary replica. Reading from a lagging replica can produce a hash that matches an old authorization but not the current authoritative state.

### 2.4 Deployment mapping

Compliant deployments may satisfy read consistency requirements through existing relational databases with serializable isolation, distributed key-value stores configured for strong consistency, or append-only state stores where each committed state is addressable by a stable version identifier. No custom state-provider system is required.

---

## 3. State Provenance

### 3.1 Source-of-truth declaration

A compliant state provider MUST be able to identify the authoritative backing storage whose state is served to both the policy engine and the PEP. This declaration does not require cryptographic proof; it is an architectural statement that must be documented and reviewable.

### 3.2 State versioning

The state provider MUST associate each state snapshot with a version identifier that:

- Advances monotonically within the operational lifecycle of the deployment (each successful mutation produces a strictly newer version)
- Is retained in audit records alongside the mutation that produced it
- Is unique per mutation event

Version identifiers MUST NOT be reused for different state contents.

### 3.3 Mutation history

A compliant state provider MUST be able to produce evidence that allows an auditor to reconstruct which state version was in effect at any given point in time. This does not require a full event sourcing system - a versioned snapshot store with monotonically advancing version identifiers, or an append-only log of state deltas, both satisfy this requirement.

### 3.4 Mutation attribution

Where the source or actor triggering a state mutation is identifiable, the state provider SHOULD record actor attribution alongside the mutation event. For mutations triggered by `setState()` from the guard, the corresponding `auth_id` of the authorizing `AuthorizationV1` SHOULD be retained in the mutation record.

### 3.5 Deployment mapping

Compliant deployments may satisfy provenance requirements through existing infrastructure such as database row versioning (e.g., PostgreSQL `xmin` or application-managed version columns), CDC (change data capture) streams that capture each state mutation with a timestamp and actor, append-only Kafka topics, or Git-based state stores with immutable commit history. No custom state-provider system is required.

---

## 4. Write Access Control

### 4.1 Controlled mutation authority

The set of entities permitted to mutate state MUST be explicitly controlled, authenticated, and auditable. The specific mechanism - role-based access control, capability tokens, service account restrictions, or database-level permissions - is deployment-specific. The deployment MUST document which identities hold write authority.

### 4.2 Agent isolation

Agents that consume state through the OxDeAI execution boundary MUST NOT hold credentials that allow them to directly mutate the backing state store by any path that bypasses the policy engine's `nextState` mechanism. The write path used by the guard's `setState()` MUST be the authoritative mutation path for policy-governed state changes.

### 4.3 Administrative and debug writes

Out-of-band state mutations - including administrative overrides, debugging modifications, and disaster-recovery restores - MUST be auditable. Such writes MUST produce audit events that are distinguishable from guard-mediated writes. Administrative write authority MUST be separate from agent-level authority.

### 4.4 Unauthorized write handling

Attempts to mutate state by entities without write authority MUST fail closed (rejected, not silently ignored). Failed write attempts MUST produce an audit event with sufficient context to identify the requestor and the attempted operation.

### 4.5 Deployment mapping

Compliant deployments may satisfy write access control requirements through existing IAM systems (AWS IAM, GCP IAM, Azure RBAC), Kubernetes RBAC for service accounts, database-level row security or schema permissions, or network-level service mesh policies that restrict which services may reach the state store write path. No custom access control system is required, provided the existing system prevents unauthorized state mutations and produces auditable records.

---

## 5. Audit Emission

### 5.1 Required audit events

A compliant state provider MUST be able to produce records for the following event classes:

| Event class | Requirement |
|-------------|-------------|
| State mutation (successful) | MUST |
| State mutation (failed / rejected) | MUST |
| Administrative override / out-of-band write | MUST |
| Rollback or restore event | MUST |

### 5.2 Recommended audit events

The following event classes SHOULD be produced where technically feasible:

| Event class | Requirement |
|-------------|-------------|
| State read for authorization (policy engine evaluation) | SHOULD |
| State read for enforcement (guard's `getState()` call) | SHOULD |
| Version conflict / CAS failure | SHOULD |

### 5.3 Minimum event fields

Each audit event SHOULD include at minimum:

- Event type (mutation, read, conflict, rollback, override)
- State version identifier before and after (where applicable)
- Timestamp (UTC, monotonic or wall-clock with NTP-synchronized source)
- Actor / source identifier (where identifiable)
- Outcome (success, failure, rejection)

### 5.4 OxDeAI ingestion in v1

OxDeAI v1 does not specify an ingestion protocol for state provider audit events. This specification defines what compliant deployments must be able to produce and retain. Future versions of the protocol may define structured event schemas that state providers can emit and OxDeAI tooling can consume.

### 5.5 Retention

State provider audit records MUST be retained for a period sufficient for post-hoc incident review. As a minimum baseline, records SHOULD be retained for a period not less than the longest `AuthorizationV1` expiry window used in the deployment, plus an operational buffer appropriate to the deployment's incident response SLA.

### 5.6 Deployment mapping

Compliant deployments may satisfy audit emission requirements through existing database transaction logs, application-level event emission to Kafka or equivalent durable message buses, cloud-native audit log services (e.g., AWS CloudTrail, GCP Cloud Audit Logs, Azure Monitor), or structured application logging with sufficient retention guarantees. No custom audit infrastructure is required, provided the records are retained and reviewable.

---

## 6. Replay and Rollback Expectations

### 6.1 Version monotonicity

State version identifiers MUST advance monotonically with each successful mutation. A decreasing version value MUST be treated as a rollback indicator and MUST produce an alert or audit event.

### 6.2 Rollback events

When state is restored to an earlier version - whether for disaster recovery, testing, or administrative purposes - the rollback event MUST:

- Produce an audit record identifying the source version, the target version, the actor, the timestamp, and the authorization for the rollback
- Be distinguishable in the audit log from normal state mutations

### 6.3 Old state not served as current

A compliant state provider MUST NOT serve an old state snapshot as the current state unless a rollback event has been explicitly authorized, audited, and recorded. Serving stale state that produces a hash match against an expired or superseded authorization without a corresponding rollback event is non-compliant.

### 6.4 Interaction with authorization expiry

State rollback can create a window where a non-expired `AuthorizationV1` might be evaluated against a rolled-back state snapshot. The `auth_id` replay check mitigates this at the authorization level for previously-consumed tokens, but authorizations that have not yet been consumed may be affected by rollback. Deployments performing state rollbacks SHOULD evaluate whether concurrent or pending authorizations remain valid against the restored state.

### 6.5 Deployment mapping

Compliant deployments may satisfy rollback expectations through existing database point-in-time recovery procedures with mandatory audit entries, change management processes that require authorization records for state restores, or infrastructure-as-code pipelines where state changes produce immutable audit trails. No custom rollback mechanism is required, provided rollback events are authorized, audited, and distinguishable from normal mutations.

---

## 7. Compromise Indicators

The following observable patterns indicate state provider compromise or non-compliance. Deployments SHOULD implement monitoring and alerting for these patterns.

### 7.1 High-priority indicators (MUST alert)

| Indicator | Notes |
|-----------|-------|
| `state_hash` matches an authorization but mutation history cannot explain the match | Strongest indicator of manufactured state; requires forensic review |
| Policy engine and PEP observe divergent states for the same version | Indicates split-brain or replica inconsistency |
| State version decreases unexpectedly | Rollback indicator |
| Administrative write performed without corresponding authorized rollback or maintenance event | Indicates unauthorized out-of-band modification |
| Rollback or restore performed without an audit record | Unauthorized state manipulation |

### 7.2 Anomaly indicators (SHOULD alert)

| Indicator | Notes |
|-----------|-------|
| Repeated CAS conflicts for the same agent or resource | May indicate racing writes or adversarial concurrent submission |
| State reads without corresponding audit records | May indicate audit bypass or logging failure |
| State mutation without identifiable actor | May indicate audit configuration failure |

### 7.3 Deployment-specific indicators (MAY alert)

| Indicator | Notes |
|-----------|-------|
| Impossible state transitions (e.g., budget decreases without corresponding authorized spend, velocity counters reset without period rollover) | Requires knowledge of policy semantics; thresholds are deployment-specific |
| State read timestamp gaps (extended periods without audit records corresponding to guard activity) | Deployment-specific; indicates possible stale-read or audit bypass |

### 7.4 Deployment mapping

Compliant deployments may satisfy compromise detection requirements through existing monitoring infrastructure such as SIEM systems ingesting state store audit logs, database anomaly detection, or custom alerting pipelines configured to detect the indicators listed in §7.1. Automated alerting for §7.1 indicators is strongly recommended for production deployments operating under Profile C.

---

## 8. Compliance Evidence

Integrators claiming state-provider compliance MUST be able to provide the following evidence on request:

### 8.1 Required evidence

| Evidence | Description |
|----------|-------------|
| Architecture description | Identifies the authoritative state source, the read/write paths, and how they relate to `getState()` and `setState()` in the guard configuration |
| Source-of-truth declaration | Names the backing storage system and its consistency model |
| Access-control model | Documents which identities hold write authority and how that authority is enforced |
| Mutation authorization rules | Describes which actors may trigger state mutations, under what conditions, and through what paths |
| State versioning model | Describes how version identifiers are assigned, how monotonicity is enforced, and how mutation history is retained |
| Audit event schema | Describes what events are produced, their fields, and how they are retained |
| Rollback policy | Describes the procedure for authorized state restores, including audit requirements |

### 8.2 Recommended evidence

| Evidence | Description |
|----------|-------------|
| Operational runbook | Incident response procedures for state provider compromise or anomaly |
| Evidence retention policy | Retention duration and access controls for audit records |
| Monitoring and alerting plan | Maps compromise indicators from §7 to specific alerts or dashboards |
| CAS configuration documentation | Confirms that the backing store provides linearizable or serializable write semantics |

---

## 9. Non-Goals and Residuals

This specification explicitly does not:

- **Cryptographically prove state-source honesty.** The protocol verifies hash binding, not state-source integrity. A sophisticated adversary who constructs state matching a valid authorization hash without triggering any observable indicators is not detectable at the PEP layer.
- **Implement a state provider.** This specification defines requirements; it does not provide a reference implementation or mandate a specific database, event store, or infrastructure component.
- **Require a specific backend.** Any storage system that satisfies the requirements in §2–§8 is compliant, regardless of vendor or technology.
- **Make RT-TRUST-1 disappear for non-compliant deployments.** The RT-TRUST-1 residual exists precisely because OxDeAI cannot verify state-source compliance at the protocol layer. Deployments that do not satisfy these requirements retain the full RT-TRUST-1 risk.
- **Make OxDeAI standard-adoption-ready by itself.** RT-TRUST-1 specified with residual is progress; it is not the same as RT-TRUST-1 closed. Independent security review and other open prerequisites remain.
- **Change `AuthorizationV1`, `DelegationV1`, `SignedKRLV1`, or `canonicalization-v1`.** These protocol artifacts are unchanged.
- **Change OxDeAI runtime behavior.** `getState()` continues to be trusted input to the guard. This specification does not change how the guard processes the state object.

### 9.1 Named residuals

Even a fully compliant state provider (satisfying all requirements in this specification) does not eliminate the following risks:

- **Hash collision:** An adversary who can produce a state object whose canonical hash matches a valid `state_hash` would pass the guard's check. This is computationally infeasible with SHA-256 but remains a theoretical residual.
- **Insider threat at the state provider:** An authorized actor with write access who manufactures state within normal operational bounds (producing valid version tokens, plausible mutation history, correct audit entries) may not be detectable by the indicators in §7.
- **Cryptographic compromise of the state hash function:** If `computeStateHash` is weakened by a future cryptographic vulnerability, state binding guarantees weaken proportionally. This is not OxDeAI-specific.

---

## 10. Relationship to Other Specifications

| Specification | Relationship |
|--------------|-------------|
| `docs/spec/enforcement/pep-gateway-v1.md` | The PEP gateway spec defines the enforcement boundary; this specification defines what the state provider behind `getState()` must satisfy |
| `docs/spec/interoperability/external-provider-profile.md §2.3` | Profile C adds live-state re-verification; state provider requirements are minimum compliance for Profile C |
| `docs/audits/protocol-audit-post-interoperability.md` RT-TRUST-1 | This specification moves RT-TRUST-1 from RISK to SPECIFIED WITH RESIDUAL |
| `docs/standardization/execution-time-authorization-alignment.md §7.1` | ETA §10.1 (policy composability) maps to RT-TRUST-1 / P2-4; this specification is the concrete closure of P2-4 |
| `packages/guard/src/types.ts` | `OxDeAIGuardConfig.getState` and `.setState` define the interface; this specification defines the integrity requirements for compliant implementations |
| `packages/guard/src/test/guard.state-binding.test.ts` | SB-1 through SB-13 verify hash-binding behavior at the protocol layer; this specification defines deployment requirements beyond what the protocol layer verifies |

---

*This specification was added to close audit item P2-4 (Specify state provider trust boundary). It moves RT-TRUST-1 from RISK to SPECIFIED WITH RESIDUAL. State-source compliance remains a deployment responsibility.*
