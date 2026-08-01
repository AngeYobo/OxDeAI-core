# Shared Demo Scenario

## Status

Non-normative (developer documentation)






This document defines the canonical cross-adapter demo scenario for maintained OxDeAI integrations.

It is a reproducibility contract for adapter demos.
It is not a protocol artifact and does not change protocol semantics, authorization artifacts, audit formats, or verification APIs.

## Purpose

The shared scenario gives maintainers and third-party integrators one framework-neutral validation path for adapter demos.

Each maintained adapter demo MUST show the same decision sequence and the same verification outcome:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

## Policy Assumptions

The canonical scenario uses a simple deterministic budget model.

The initial policy state assumes:

- total budget or allowance is sufficient for two low-cost actions
- the first action consumes part of that allowance
- the second action consumes the remaining allowance
- the third action exceeds the remaining allowance and is denied

This repository expresses that model as a fixed-cost GPU provisioning scenario:

- action cost: `500`
- initial budget: `1000`
- first action: allowed
- second action: allowed
- third action: denied with budget exhausted

## Shared Action Sequence

Raw action payloads MAY differ by adapter.
Their normalized intent meaning MUST remain equivalent.

The canonical sequence is:

1. propose one low-cost action within policy
2. propose a second equivalent low-cost action within the remaining allowance
3. propose a third equivalent action after allowance is exhausted

In the maintained repository demos, the equivalent normalized meaning is:

1. provision `a100` in `us-east-1`
2. provision `a100` in `us-east-1`
3. provision `a100` in `us-east-1`

## Expected Decisions

The expected authorization sequence is:

1. `ALLOW`
2. `ALLOW`
3. `DENY`

The third action MUST be denied before external execution.

## Expected Audit And Evidence Outcome

The demo SHOULD emit audit evidence that makes the sequence understandable without re-running the runtime:

- first authorization and execution path recorded
- second authorization and execution path recorded
- third proposal and refusal path recorded
- state snapshot captured for verification
- verification envelope packaged from snapshot plus audit evidence

The exact raw runtime events MAY differ.
The evidence MUST remain sufficient to reproduce the same OxDeAI boundary outcome.

## Expected Verification Outcome

The resulting envelope verification outcome is:

`verifyEnvelope() => ok`

This demonstrates that:

- the adapter preserved deterministic intent normalization
- authorization gating remained consistent
- refusal remained explicit
- audit and snapshot evidence were sufficient for offline verification

## Concurrent Variant: Compare-And-Set On The Budget Counter

The sequence above is single-threaded: each proposal is evaluated and committed
before the next is built. Deployments are not, and the budget counter is where
that difference shows first.

This variant is optional for adapter demos. It exists because the canonical
scenario already contains everything needed to exercise it: a counter with room
for exactly two actions.

### Scenario

Two evaluators read the same state and each propose the second low-cost action:

1. both read state at the same `StateVersion`, with one action's worth of
   allowance remaining
2. both evaluate, and both receive `ALLOW` with a proposed next state
3. both attempt to commit

### Expected Outcome

Exactly one commit succeeds.

- the first `setState(nextState, expectedVersion)` MUST return `true`
- the second MUST return `false`, because the persisted version no longer
  matches the version it read
- the losing evaluator's guard MUST raise `OxDeAIConflictError`, and its tool
  MUST NOT execute

The budget MUST NOT be double-spent. After the exchange, exactly one of the two
proposals has consumed allowance, and a subsequent equivalent proposal is denied
as in the canonical sequence.

### Why This Belongs In The Shared Scenario

Both evaluators received `ALLOW`. The decision was correct in each case, against
the state each of them read. What separates the two outcomes is not policy but
the atomicity of the commit, which is why the state provider requirements make
compare-and-set a provider obligation rather than an engine one - see
[State Provider Requirements](../spec/state-provider-requirements.md) §2.2.

This also demonstrates the distinction between the two state checks: the
`state_hash` binding answers whether the live state is the one the authorization
was minted against, while the `StateVersion` token answers whether anyone
advanced it between read and write. A demo that only exercises the first will
not show this failure mode at all.

## Reproducibility Guidance

Adapters MAY differ in:

- raw action shape
- framework control flow
- local logging format

Adapters MUST preserve:

- equivalent normalized intent semantics
- equivalent policy state progression
- equivalent decision outcomes
- verifiable envelope evidence

Maintained demos do not need byte-identical console output.
They do need an obviously comparable result:

- decision 1: `ALLOW`
- decision 2: `ALLOW`
- decision 3: `DENY`
- envelope verification: `ok`
