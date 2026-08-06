# Tier 1 Evaluator-Input Provenance Boundary

## Status

**Accepted:** 2026-08-06  
**Governing issue:** [#197](https://github.com/oxdeai/oxdeai/issues/197)  
**Dependent follow-ups:** [#214](https://github.com/oxdeai/oxdeai/issues/214), [#219](https://github.com/oxdeai/oxdeai/issues/219)  
**Independently tracked:** [#215](https://github.com/oxdeai/oxdeai/issues/215), [#216](https://github.com/oxdeai/oxdeai/issues/216), [#217](https://github.com/oxdeai/oxdeai/issues/217), [#218](https://github.com/oxdeai/oxdeai/issues/218)

This record accepts an architecture. It does not define a final public API or
implement the secure execution path.

## Context

The current authorization pipeline cryptographically binds an authorization to
the intent, state snapshot, and policy identifier that the issuer used. Valid
hashes and signatures establish integrity and internal consistency. They do not
independently establish the provenance or authority of those inputs.

In particular, a valid authorization does not by itself prove:

- that state came from an authoritative provider, was fresh, or was its latest
  version;
- the identity of the state provider or that compare-and-set (CAS) later
  succeeded;
- that policy configuration came from an authoritative source;
- the identity of the caller or a binding between that principal and
  `intent.agent_id`;
- that depth reflects the real execution chain;
- that tool, adapter, action classification, or tenant identity came from the
  protected execution route;
- argument provenance; or
- that the adapter selected during authorization is the adapter that executed.

A proposer-controlled claim does not become authoritative merely because it is
hashed or included in a signed artifact. Similarly, `state_hash` establishes
binding to a supplied snapshot; it does not authenticate the snapshot's source.
CAS detects conflicting state transitions; it does not authenticate a state
provider.

The threat model permits compromise of the proposer, agent runtime, or
orchestrator. The intended Tier 1 trust boundary consists of the authenticated
PEP, guard, configured state and policy providers, authorization signer and
verifier, trusted adapter route, and protected execution path. Compromise of
one of those trusted components remains a deployment risk.

Current runtime surfaces do not yet implement this complete boundary:

- direct `PolicyEngine.evaluatePure()` accepts caller-supplied intent, state,
  and `evaluationTime`, while policy configuration belongs to the caller-created
  engine;
- `OxDeAIGuard` obtains `{ state, version }` through configured `getState()` and
  performs `setState(nextState, version)` before its standard execution
  callback, but has no provider identifier or authenticated principal context;
- the SDK `StateAdapter` has unversioned `load()` and `save()` operations;
- the generic PEP gateway verifies an already-issued authorization and invokes
  a configured upstream executor, but does not establish evaluator-input
  provenance; and
- the LGF/Frappe example fixes adapter selection and isolates upstream
  credentials in server configuration, but request identity fields are not an
  authenticated principal.

The normative [State Provider Requirements](../../spec/state-provider-requirements.md)
define Profile C provider and CAS obligations. The
[Policy and State Modeling Guidance](../../integrations/policy-state-modeling.md)
explains current modeling limitations. This decision adds neither a state
protocol nor a cryptographic provider-attestation mechanism.

## Problem Statement

A compromised component must not be able to choose both the requested action
and the supposedly trusted state, policy, identity, routing, or execution
context used to authorize it.

The security reproduction cases expose the boundary:

- **G:** self-declared recursion depth can select a less restrictive result;
- **H:** `tool_call` is already non-load-bearing in tool-limit enforcement and
  must remain so;
- **L:** self-declared `agent_id` can select another agent's privilege profile;
- **M:** self-declared tool names can select unconfigured or differently
  configured quota buckets.

Trusted routing addresses the provenance part of M. Default-deny behavior for a
legitimately routed but unconfigured tool is the separate policy-model change
tracked by #214.

## Decision

OxDeAI will introduce a dedicated secure guard/PEP execution path. Existing
low-level behavior will not silently acquire different inputs or semantics.

The secure path has this ordered flow:

1. The PEP authenticates the caller or execution principal.
2. The PEP creates trusted server-side execution context.
3. The guard maps the principal to effective agent and tenant identities.
4. The guard rejects proposer claims that conflict with trusted context.
5. The guard selects state and policy providers from protected configuration.
6. The guard reads authoritative versioned state, then validates provider
   identity and any expected version supplied by the proposer.
7. The guard loads authoritative policy configuration and derives or verifies
   the effective `policy_id`.
8. Trusted routing or execution context supplies adapter identity, tool,
   security-relevant action classification, recursion depth, tenant namespace,
   and `evaluationTime`.
9. The guard constructs the effective intent from the proposal and trusted
   context.
10. The existing pure `PolicyEngine` evaluates that effective intent against
    the independently obtained state and policy.
11. The existing evaluation path computes `intent_hash`, `state_hash`, and
    `policy_id` and issues the unchanged authorization.
12. The guard verifies the authorization as required by the secure path.
13. The guard commits `nextState` using the exact version read, through CAS or
    an equivalent atomic conflict-rejection mechanism.
14. Only after CAS succeeds does the guard invoke the same trusted adapter that
    was selected before authorization.

This decision belongs primarily at the PEP/guard boundary, before
`PolicyEngine.evaluatePure()`. `TrustedExecutionContext` remains outside core
`PolicyEvaluationContext` in the first implementation.

`AuthorizationV1`, `DelegationV1`, `SignedKRLV1`, and `canonicalization-v1`
remain unchanged in Tier 1.

## Trust Boundaries

| Component | Responsibility and permitted trust | Must not trust or permit |
|---|---|---|
| Proposer | Supplies action claims and, where supported, a scoped state reference and expected version | Cannot supply authoritative state, policy, provider identity, principal, route, depth, tenant, or clock input |
| Authenticated transport | Establishes an authenticated session or caller credential and protects its delivery to the PEP | Request JSON is not authenticated context merely because it arrived over the transport |
| PEP | Authenticates the principal, captures trusted time, resolves protected routing, and creates server-side context | Must not copy identity or route authority from unauthenticated proposal fields |
| Guard | Merges proposal and trusted context, rejects conflicts, selects providers, evaluates, verifies, commits through CAS, and gates execution | Must not treat hashes, arbitrary `policyId`, or lookup success as proof of provenance |
| StateProvider | Returns state and a genuine version for an authorized scoped reference and performs atomic CAS | Must not be selected by a proposer; a version token is not provider authentication |
| PolicyProvider | Returns the configured policy for the authenticated deployment, tenant, and route context | Must not accept proposal-supplied policy as authoritative |
| `PolicyEngine` | Deterministically evaluates the effective intent, state, policy, and trusted `evaluationTime`; computes existing bindings | Does not authenticate callers, providers, or adapters by itself |
| Authorization signer | Signs the authorization produced for the evaluated inputs | Signature integrity does not establish input provenance independently |
| Authorization verifier | Verifies signature, issuer, audience, time, hashes, and other required artifact constraints | Must not infer provider authority or CAS success from a valid artifact |
| Adapter registry | Maps a protected route to stable adapter and tool identities | A proposer cannot freely rename or replace a route identity |
| Execution adapter | Executes the exact authorized operation with protected credentials | Must not substitute arguments, tool identity, or downstream route after authorization |
| Protected upstream | Accepts execution only through the intended protected adapter/PEP path | Must not expose a bypass that accepts direct proposer invocation |

## Trusted Execution Context

The secure path carries server-created execution context conceptually similar
to the following:

```ts
// Illustrative only: not an approved public TypeScript API.
interface TrustedExecutionContext {
  principalId: string;
  tenantId?: string;
  agentId: string;
  adapterId: string;
  tool?: string;
  depth: number;
  evaluationTime: number;
}
```

The context is created server-side and must not be accepted directly from
request JSON. The exact interface and construction rules belong to a follow-up
implementation issue. In the first implementation it remains a guard/PEP
concern, outside core `PolicyEvaluationContext` and outside canonical protocol
artifacts.

## Principal Binding

Authentication occurs before guard evaluation. The PEP produces an
authenticated, deployment-local principal identifier and passes it to the guard
through server-side context. Deployments may use mTLS, OAuth/OIDC, a trusted
gateway identity, or an authenticated session; this ADR does not mandate one
technology or make the resulting identifier protocol-portable.

The guard maps that principal to effective `agent_id`. An explicit proposer
claim that conflicts with the mapping fails closed rather than being silently
overwritten. Whether a missing claim is filled from context or rejected is part
of the future secure-path contract. Direct self-declaration is never sufficient
authority.

Rejection happens before evaluation, authorization issuance, state mutation,
or execution.

## Authoritative State

For the secure path:

- the guard selects the StateProvider from protected configuration;
- the proposer cannot select provider identity;
- a proposer may submit a scoped reference and expected version;
- the provider returns authoritative state and its version;
- the guard validates provider identity and expected version before evaluation;
- the existing core path computes `state_hash` from that returned snapshot;
- the exact version read is used for the state transition; and
- CAS conflict prevents execution.

These properties remain distinct:

| Property | Tier 1 source |
|---|---|
| Snapshot integrity or consistency | `state_hash` binds the authorization to the evaluated snapshot |
| Provider authority | Guard-selected and deployment-authenticated provider |
| Freshness | Provider consistency guarantees and version policy |
| Version consistency | Validated version returned with the read |
| Atomic transition | Exact-version CAS or equivalent conflict rejection |
| Authorization binding | Existing signed authorization fields and verification |

A matching `state_hash` does not prove that the provider was authoritative or
the snapshot latest. Successful CAS does not authenticate the provider. This
ADR does not prescribe the final StateProvider TypeScript interface.

## Authoritative Policy

The guard selects a PolicyProvider from protected configuration. The proposer
does not supply authoritative policy configuration and cannot establish policy
authority by supplying an arbitrary `policyId`.

The effective `policy_id` is computed from, or verified against, the policy
returned by the authoritative source. Policy reference, loading, versioning,
caching, and update semantics remain implementation work.

## Trusted Routing and Execution Context

- `tool` is derived from trusted adapter routing or validated against an
  authoritative closed mapping.
- Adapter identity is fixed before authorization, and the same adapter performs
  execution afterward.
- Security-relevant action classification is derived from trusted routing or
  checked against the actual operation about to execute.
- Recursion depth is derived from the trusted execution chain, not accepted as
  authoritative from `intent.depth`.
- Tenant namespace is derived from authenticated identity and protected
  configuration. Encoding a tenant in `agent_id` is only a naming convention.
- `evaluationTime` comes from the trusted PEP/guard clock path described by the
  normative [Trusted Time specification](../../spec/core/trusted-time-v1.md).
- `tool_call` is derived where useful or retained only as a non-load-bearing
  compatibility claim. It cannot determine whether tool enforcement applies.

Conflicting proposal claims fail closed. Hashing the conflict does not make the
proposal authoritative.

## State Transition and Execution Ordering

The secure path preserves this mandatory order:

```text
authenticate
→ resolve trusted context
→ read authoritative state and policy
→ evaluate
→ verify
→ CAS
→ execute
```

Execution does not occur when authentication or principal mapping fails, a
proposal conflicts with trusted context, provider identity or expected version
mismatches, policy source mismatches, evaluation denies, authorization
verification fails, CAS conflicts, or the adapter route changes.

## Secure and Legacy Profiles

### Secure Tier 1 path

The secure path combines an authenticated principal, server-created trusted
execution context, guard-selected authoritative providers, atomic CAS, and a
fixed adapter route. Only that path, or an integration independently enforcing
the same boundary, may claim the provenance guarantees recorded here.

### Legacy or low-level path

Direct `PolicyEngine` use and integrations that accept caller-supplied state or
configuration remain lower-level paths. They may be appropriate where the
caller and its inputs are already inside a trusted deployment boundary, but do
not by themselves provide Tier 1 evaluator-input provenance.

This ADR neither deprecates nor removes existing paths. It requires secure and
legacy guarantees to be described separately.

## Alternatives Considered

### Intent signatures

An intent signature can identify a registered proposer and protect proposal
integrity. It does not establish authoritative state, policy, route, honest
depth, or the proposer's entitlement to an `agent_id`. Making it load-bearing
would also require key registration, rotation, revocation, and delegation rules.
It is not selected for Tier 1.

### Signed state attestations and provider-issued state tokens

These could make provider identity and snapshot claims portable, but require
provider key registration, rotation, revocation, token semantics, and freshness
rules. They still need atomic transition handling and do not solve policy,
principal, and routing provenance. They are possible Tier 2 work.

### Proof-carrying state

Proofs could support stronger state claims but introduce proof formats,
verification rules, operational cost, and compatibility work disproportionate
to the immediate reference path. They are deferred Tier 2 research.

### Signed execution-context envelopes

A signed context could portably bind principal and routing claims, but would be
a new artifact with issuer trust, key lifecycle, versioning, and canonicalization
requirements. Local authenticated PEP-to-guard context is sufficient for the
Tier 1 reference boundary. A portable envelope is deferred.

### New `AuthorizationV1` fields

Additional fields would require artifact and verifier compatibility decisions
and still would not make a compromised source authoritative. Tier 1 retains the
existing artifact.

### Move provenance into core `PolicyEvaluationContext`

This would expand a public core input without itself authenticating the values.
Enforcing provenance at the PEP/guard boundary keeps deployment authentication
outside the deterministic evaluator. The first implementation therefore leaves
core `PolicyEvaluationContext` unchanged.

### Silently change existing guard behavior

Making existing callbacks acquire new meanings could break deployments and
allow legacy integrations to appear provenance-safe without satisfying the new
requirements. A dedicated secure path makes the guarantees explicit.

## Consequences

### Benefits

- The authoritative boundary is explicit and reviewable.
- A proposer cannot select both the action and the trusted premises.
- Deployment-specific authentication remains outside canonical artifacts.
- Core protocol artifacts and canonicalization remain stable.
- Pure policy evaluation remains deterministic.
- CAS and execution ordering remain explicit.
- Implementation can be divided into narrow changes.

### Costs and trade-offs

- A secure guard API and provider abstractions are required.
- Secure deployments require authenticated PEP transport and protected
  principal mapping.
- Adapter registries need stable route, tool, and adapter identities.
- SDK and existing integrations require migration or explicit legacy
  classification.
- Mixed-version deployment needs operational controls.
- Integration and conformance coverage must expand.
- Direct callers cannot claim Tier 1 without independently enforcing equivalent
  controls.

## Compatibility

| Surface | Expected impact |
|---|---|
| Core `PolicyEngine` | No expected semantic change for Tier 1 |
| `PolicyEvaluationContext` | Remains unchanged in the first implementation |
| `Intent` and `State` | No artifact/schema change decided here; secure construction and provider interfaces require later API review |
| `AuthorizationV1` | No change |
| `DelegationV1` and `SignedKRLV1` | No change |
| `canonicalization-v1` | No change |
| Guard | Likely new public secure-path and trusted-context APIs |
| SDK | Needs a versioned/CAS secure integration profile or explicit legacy classification |
| PEP request handling | Requires authenticated, server-side context rather than trusting request identity fields |
| State providers | Need provider identity, versioned reads, and atomic conflict rejection; exact API unresolved |
| Policy providers | New authoritative loading abstraction likely; exact API unresolved |
| Adapters | Need stable trusted route metadata and execution-route continuity |
| Conformance | New provenance and ordering tests; no canonical artifact-vector change expected |

Public guard and provider additions require API review during implementation.
This ADR does not approve a particular interface shape.

## Migration Strategy

1. Merge this ADR.
2. Define the dedicated secure guard context and entry point.
3. Add authenticated principal-to-`agent_id` binding.
4. Add authoritative versioned state and policy providers.
5. Add trusted adapter/tool routing and trusted recursion-depth derivation.
6. Add CAS and execution-order conformance coverage.
7. Bind authenticated tenant namespace to state and policy selection.
8. Migrate SDK and PEP integrations to the secure profile.
9. Explicitly classify remaining integrations as secure or legacy.
10. Address dependent policy work in #214 and tenant enforcement in #219.

Secure and legacy guards must not silently share semantic assumptions.
Deployments that currently submit complete state objects must migrate to
guard-side authoritative reads or remain legacy. State and policy provider
selection must be protected from proposer influence. A rolling deployment must
not advertise Tier 1 while requests can reach older guards that interpret the
same inputs as self-declared. Secure profiles require authenticated transport.

## Reason-Code Implications

The current public reason registry does not precisely classify every new
boundary failure. Later implementation work must decide how to represent:

- principal mismatch;
- state-provider identity mismatch;
- expected-version mismatch;
- policy-source mismatch;
- trusted tool or adapter-route mismatch;
- depth mismatch; and
- tenant mismatch.

The decision may use guard-layer structured errors, public policy reason codes,
conformance-visible enforcement errors, or a deliberate combination. This ADR
does not invent names or modify the registry.

## Related Issues

- [#197](https://github.com/oxdeai/oxdeai/issues/197) governs this provenance
  architecture and remains open for implementation.
- [#214](https://github.com/oxdeai/oxdeai/issues/214) is dependent: default-deny
  tool policy requires trusted tool identity, then a separate schema and policy
  decision.
- [#219](https://github.com/oxdeai/oxdeai/issues/219) is dependent:
  authenticated tenant identity must bind state and policy namespaces.
- [#215](https://github.com/oxdeai/oxdeai/issues/215) is independent action-type
  extensibility work.
- [#216](https://github.com/oxdeai/oxdeai/issues/216) independently tracks
  credential provenance and scope.
- [#217](https://github.com/oxdeai/oxdeai/issues/217) independently tracks
  structured argument provenance.
- [#218](https://github.com/oxdeai/oxdeai/issues/218) independently tracks
  approval and workflow state.
- [#166](https://github.com/oxdeai/oxdeai/issues/166) produced the policy/state
  modeling guidance that exposed these boundaries.
- [#139](https://github.com/oxdeai/oxdeai/issues/139) provides related external
  review and standardization context.

This ADR does not claim that #163 is resolved.

## Follow-up Implementation Issues

| Title | Dependency | Invariant | Affected layer |
|---|---|---|---|
| Secure guard `TrustedExecutionContext` | This ADR | Trusted context is created server-side and cannot be supplied as request JSON | Guard and PEP |
| Bind authenticated principal to `agent_id` | Trusted context | Effective agent identity follows authenticated principal; conflicts fail closed | PEP and guard |
| Authoritative versioned StateProvider | Secure guard entry point | Proposer cannot supply authoritative state or select its provider; exact-version conflict prevents execution | Guard, providers, SDK |
| Authoritative PolicyProvider | Secure guard entry point | Proposer cannot establish policy authority through configuration or `policyId` | Guard and policy integration |
| Trusted tool and adapter routing | Trusted context | Policy tool identity and executing adapter come from one protected route | PEP, guard, adapters |
| Trusted recursion-depth derivation | Trusted context | Effective depth comes from the protected execution chain | Guard and integrations |
| `tool_call` compatibility hardening | Trusted routing | Proposer-controlled `tool_call` never decides whether enforcement applies | Core regression coverage and guard |
| Tenant namespace binding | Principal binding and providers | Authenticated tenant identity selects both state and policy namespaces | PEP, guard, providers |
| Provenance conformance vectors | Relevant secure-path changes | Forged claims and provider/version conflicts fail before mutation or execution | Conformance and guard |
| Security reproduction updates | Principal, depth, and routing changes | Cases G, H, L, and M demonstrate the enforced boundary | Security scripts |
| SDK and deployment migration guidance | Stable secure APIs | Integrations cannot conflate low-level and Tier 1 guarantees | SDK and documentation |

## Non-goals

This ADR does not:

- implement the secure path or close #197;
- define a final public TypeScript interface;
- add authentication middleware or mandate OAuth, mTLS, SPIFFE, or another
  identity technology;
- define a proof format, signed state attestation, provider token, or signed
  execution-context artifact;
- modify `AuthorizationV1`, `DelegationV1`, `SignedKRLV1`, or canonicalization;
- define credential provenance or structured argument provenance;
- define approval workflows or make `ActionType` extensible;
- implement default-deny tool allowlists or tenant enforcement; or
- change existing policy semantics.

## Decision Validation

An implementation satisfies this decision only when:

- no proposer-controlled field is authoritative solely because it is hashed or
  signed;
- secure state and policy come from guard-selected authoritative providers;
- authenticated principal controls effective `agent_id`;
- tool, adapter, depth, tenant namespace, and `evaluationTime` have trusted
  sources;
- conflicting claims fail closed before issuance, mutation, or execution;
- exact-version CAS precedes protected execution;
- the adapter selected before authorization is the adapter that executes;
- secure and legacy guarantees are not conflated; and
- existing protocol artifacts and canonicalization remain unchanged.

