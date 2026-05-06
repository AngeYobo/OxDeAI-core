# API Cost Containment with OxDeAI

## Status

Non-normative (developer documentation)






## Scenario Summary

An agent runtime is allowed to call external APIs through a tool or adapter boundary. Each request is individually reasonable, but repeated calls can accumulate cost quickly under retries, loops, or overly persistent planning behavior.

OxDeAI sits at the execution boundary between the runtime and the external API call. Each proposed call is normalized into intent, evaluated against current policy state, and either authorized or refused before the side effect occurs.

## Problem / Failure Mode

Without a pre-execution authorization boundary, API usage often becomes visible only after cost has already accrued. Common failure modes include:

- repeated paid API calls in a planning loop
- retries that continue after remaining allowance is exhausted
- a tool repeatedly calling the same expensive endpoint because the runtime still considers it plausible
- operators noticing the overrun only through delayed billing or monitoring

Prompt filtering or response shaping does not stop a runtime that continues to propose economically valid-looking external calls.

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
External API call
   ↓
Audit events + snapshot
   ↓
Verification envelope
```

In the repository examples, this pattern is represented by the shared budget scenario across maintained adapters, with the OpenAI tools demo as the reference function-call style boundary.

## Controls Applied

Typical control concepts for this case include:

- total budget cap for the agent or period
- per-action cost cap
- action count or rate constraints
- restricted target scopes for billable APIs
- explicit deny on exhausted allowance

These are policy controls expressed through the existing `(intent, state, policy)` evaluation model.

## Authorization Flow

1. The runtime proposes an external API call.
2. The adapter normalizes that proposal into deterministic intent.
3. Current policy state is supplied, including remaining allowance or counters.
4. The OxDeAI PDP evaluates the proposed action against `(intent, state, policy)`.
5. On `ALLOW`, `AuthorizationV1` may be emitted.
6. The PEP verifies authorization before the API call is executed.
7. Decision and execution or refusal are recorded in audit events.
8. Snapshot plus audit events may be packaged into a verification envelope and checked with `verifyEnvelope()`.

## Failure Mode Prevented

OxDeAI prevents additional chargeable API calls from crossing the execution boundary after the permitted allowance has been consumed.

In practical terms, this prevents a runtime from continuing to spend against an external API because the tool path remains reachable. The denied call does not execute when the PEP is wired correctly.

OxDeAI does not predict future spend. It bounds permitted execution one action at a time through deterministic authorization at the action boundary.

## Verification Evidence

The evidence path remains the standard OxDeAI path:

- the snapshot captures the evaluated policy state, including the state after allowed actions
- the audit chain records proposed intents, decisions, authorization emission on `ALLOW`, and the refused path on `DENY`
- the verification envelope packages snapshot plus audit evidence for stateless verification

An integrator or relying party can use that evidence to reason about:

- which policy state was evaluated
- which actions were authorized
- which action was refused
- whether the packaged evidence is structurally consistent

In the maintained demos, the expected semantic result is:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

That means the envelope is internally consistent under the chosen verification mode, and the audit plus snapshot evidence are sufficient for offline reasoning about the bounded execution path.

## Integration Notes

- Normalize API/tool requests before policy evaluation, not after execution.
- Keep the PEP directly on the side-effect path so the external API call is unreachable on `DENY`.
- On `DENY`, return an explicit refusal to the runtime and do not attempt a degraded execution path.
- Keep policy state transitions deterministic so evidence remains reproducible across reruns of the same scenario.
- If multiple frameworks call the same API surface, ensure equivalent external calls normalize to equivalent intents.

## Related Repo References

- [`examples/openai-tools`](../../examples/openai-tools)
- [`docs/integrations/openai-tools.md`](../integrations/openai-tools.md)
- [`docs/integrations/shared-demo-scenario.md`](../integrations/shared-demo-scenario.md)
- [`docs/adapters/adapter-verification.md`](../adapters/adapter-verification.md)
- [`docs/adapter-contract.md`](../adapters/adapter-contract.md)
- [`docs/pep-production-guide.md`](../architecture/pep-production-guide.md)
- [`SPEC.md`](../../SPEC.md)
- [`ROADMAP.md`](../../ROADMAP.md)
