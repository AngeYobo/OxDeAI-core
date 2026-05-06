# AutoGen Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets AutoGen-style multi-message and tool-execution flows.
OxDeAI sits between the runtime’s proposed action and the actual side effect boundary.

```text
framework runtime
    ↓
adapter normalization
    ↓
intent + state
    ↓
OxDeAI PDP
    ↓
AuthorizationV1
    ↓
PEP verifyAuthorization
    ↓
tool execution
```

## Install

Install workspace dependencies:

```bash
pnpm install
```

Relevant packages:

- `@oxdeai/core`
- optionally `@oxdeai/sdk`
- AutoGen runtime dependencies used by the host integration

## Minimal Quickstart

Run the AutoGen-shaped example:

```bash
pnpm -C examples/autogen start
```

Repository example:

- [`examples/autogen`](../../examples/autogen)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

## Adapter Responsibilities

For this integration, the adapter:

- normalizes message-to-tool or action proposals into intent
- provides current policy state
- invokes OxDeAI evaluation
- enforces `verifyAuthorization(...)` before execution
- emits audit events for authorization and execution/refusal outcomes

Adapters are integration components.
They are not part of the protocol.

## Production PEP Wiring

Production flow:

```text
runtime proposes action
adapter normalizes proposal
OxDeAI PDP evaluates policy
AuthorizationV1 returned on ALLOW
PEP verifies authorization
external side effect executes
```

Production rules:

- authorization verification MUST occur before side effects
- `DENY` MUST produce an explicit refusal path
- execution outcomes SHOULD emit audit events
- authorization artifacts SHOULD remain verifiable offline

## Shared Demo Scenario

This integration implements the canonical shared scenario described in [`shared-demo-scenario.md`](./shared-demo-scenario.md).

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Raw action form differs by runtime.
For this adapter, the raw proposal surface is a message-to-tool or action dispatch boundary.

## Validation

Local validation command:

```bash
pnpm -C examples/autogen validate
```

Example directory:

- [`examples/autogen`](../../examples/autogen)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- AutoGen integrations often normalize at the message-to-tool execution boundary.
- The adapter SHOULD keep action normalization deterministic despite message-level orchestration.
- Multi-agent orchestration changes runtime behavior, not the OxDeAI protocol contract.
