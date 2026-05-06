# OpenAI Agents SDK Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets OpenAI Agents SDK-shaped runtimes.
OxDeAI sits between agent-proposed actions and the side effect boundary.

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
- optionally `@oxdeai/sdk` for production guard wiring
- OpenAI Agents SDK dependencies used by the host runtime

## Minimal Quickstart

Run the repository example:

```bash
pnpm -C examples/openai-agents-sdk start
```

Repository example:

- [`examples/openai-agents-sdk`](../../examples/openai-agents-sdk)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

The example shows the adapter normalizing agent SDK actions into intent, evaluating policy, and enforcing authorization before execution.

## Adapter Responsibilities

For this integration, the adapter:

- converts agent SDK action proposals into deterministic intent
- supplies current policy state
- invokes OxDeAI evaluation
- gates execution with `verifyAuthorization(...)`
- emits audit evidence for later envelope verification

Adapters are integration components.
They are not part of the protocol.

## Production PEP Wiring

Production flow:

```text
agent runtime proposes action
adapter normalizes proposal
OxDeAI PDP evaluates policy
AuthorizationV1 returned on ALLOW
PEP verifies authorization
tool or external side effect executes
```

Production rules:

- authorization verification MUST happen before side effects
- `DENY` MUST remain explicit and observable
- execution/refusal outcomes SHOULD emit audit events
- authorization and envelope artifacts SHOULD remain verifiable offline

## Shared Demo Scenario

This integration implements the canonical shared scenario described in [`shared-demo-scenario.md`](./shared-demo-scenario.md).

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Raw action form differs by runtime.
For this adapter, the raw proposal surface is an OpenAI Agents SDK action dispatch.

## Validation

Local validation command:

```bash
pnpm -C examples/openai-agents-sdk validate
```

Example directory:

- [`examples/openai-agents-sdk`](../../examples/openai-agents-sdk)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- The adapter boundary typically sits around tool-call dispatch.
- Normalization focuses on stable action type, target, and binding fields.
- This integration should remain comparable to the reference OpenAI tools boundary.
