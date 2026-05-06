# Infrastructure Provisioning Control with OxDeAI

## Status

Non-normative (developer documentation)






## Scenario Summary

An agent runtime is allowed to trigger infrastructure operations such as provisioning a cloud instance or initiating a deployment step. These actions create real external effects and are often expensive, slow to reverse, or operationally sensitive.

OxDeAI sits between the runtime and the infrastructure provider as a deterministic authorization boundary. Each provisioning attempt is normalized into intent, evaluated against current policy state, and either authorized or refused before the provider-facing action is executed.

## Problem / Failure Mode

Infrastructure control paths are vulnerable to failure modes that monitoring alone does not prevent:

- repeated instance creation caused by retries or loops
- provisioning into the wrong environment or resource scope
- unsafe reasoning that continues to propose real infrastructure changes
- side effects triggered after policy state has already reached its intended limit

The failure is not merely a bad plan. The failure is that a real provider action crosses the execution boundary when it should have been blocked before execution.

## Architecture

```text
Runtime / Agent
   ↓
Adapter normalization
   ↓
Intent + State
   ↓
OxDeAI PDP
   ↓
AuthorizationV1 on ALLOW
   ↓
PEP verifyAuthorization
   ↓
Cloud / Infrastructure provider
   ↓
Audit events + snapshot
   ↓
Verification envelope
```

In the repository, the maintained demos model this with deterministic GPU provisioning intents. The pattern generalizes to infrastructure operations such as instance creation, environment-scoped deployment, or other provider-bound actions.

## Controls Applied

Typical control concepts for this case include:

- allowed action types
- allowed assets or resource classes
- allowed target scopes or regions
- per-operation authorization at the provisioning boundary
- total budget or allowance constraints
- explicit refusal of out-of-scope or exhausted operations

These controls are implemented as policy decisions over normalized intent and current state, not as new protocol features.

## Authorization Flow

1. The runtime proposes a provisioning action.
2. The adapter normalizes the action into deterministic intent.
3. Current policy state is provided, including budget, scope, or operational flags.
4. The OxDeAI PDP evaluates the proposed action against `(intent, state, policy)`.
5. On `ALLOW`, `AuthorizationV1` may be emitted.
6. The PEP verifies authorization before calling the infrastructure provider.
7. Decision and execution or refusal are recorded in audit events.
8. Snapshot plus audit events may be packaged into a verification envelope and checked with `verifyEnvelope()`.

## Failure Mode Prevented

OxDeAI prevents a real infrastructure action from reaching the provider when policy no longer permits it.

In the shared provisioning scenario, the first two provisioning attempts are authorized and the third is denied. The prevented failure is the third side effect: without the authorization boundary, the runtime could have created one more external resource after the intended limit had been reached.

This also helps contain duplicate side effects from retries or repeated reasoning when the current state no longer permits another provisioning action.

## Verification Evidence

The evidence path is the standard OxDeAI evidence path:

- the snapshot captures the evaluated provisioning state after authorized actions
- the audit chain records the proposed provisioning intents, decisions, and authorization emission on allowed actions
- the denied provisioning attempt remains visible as a refusal in the audit path
- the verification envelope packages snapshot plus audit evidence for offline verification

That lets an integrator or reviewer reason about:

- which provisioning state was evaluated
- which provisioning attempts were allowed
- which provisioning attempt was refused
- whether the packaged evidence remains structurally consistent under `verifyEnvelope()`

In the maintained demos, the expected semantic result is:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

This is conservative evidence, not a claim of provider-side attestation. It confirms the OxDeAI-side decision, state, and evidence path are internally consistent and verifiable.

## Integration Notes

- Put normalization at the infrastructure action boundary, where raw runtime proposals become stable intent.
- Put the PEP immediately before the provider call so `DENY` cannot fall through to execution.
- On `DENY`, return an explicit refusal path to the runtime and record it audibly in the audit path.
- Keep target scopes and resource identities stable in normalized intent so policy and evidence remain comparable.
- If the same operation can be proposed by multiple runtimes, make equivalent provisioning requests normalize to equivalent intents.

## Related Repo References

- [`examples/openai-tools`](../../examples/openai-tools)
- [`examples/openclaw`](../../examples/openclaw)
- [`docs/integrations/openclaw.md`](../integrations/openclaw.md)
- [`docs/integrations/shared-demo-scenario.md`](../integrations/shared-demo-scenario.md)
- [`docs/adapters/adapter-verification.md`](../adapters/adapter-verification.md)
- [`docs/adapter-contract.md`](../adapters/adapter-contract.md)
- [`docs/pep-production-guide.md`](../architecture/pep-production-guide.md)
- [`SPEC.md`](../../SPEC.md)
- [`ROADMAP.md`](../../ROADMAP.md)
