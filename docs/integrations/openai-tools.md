# OpenAI Tools Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets OpenAI tools or function-call style runtimes.
OxDeAI sits at the execution authorization boundary between proposed tool calls and actual tool execution.

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

For the repository example, the relevant package is:

- `@oxdeai/core`

Production integrations will typically use:

- `@oxdeai/core`
- `@oxdeai/sdk` for guard-oriented wiring
- runtime-specific tool/function call dependencies

## Minimal Quickstart

Run the minimal reference demo:

```bash
pnpm -C examples/openai-tools start
```

Repository example:

- [`examples/openai-tools`](../../examples/openai-tools)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

This demonstrates:

1. the runtime proposes a tool action
2. the adapter normalizes it into intent
3. OxDeAI evaluates policy
4. authorization is required before execution
5. the third action is refused before the tool runs

## Adapter Responsibilities

For this integration, the adapter:

- normalizes proposed tool calls into intent
- provides current policy state
- invokes OxDeAI policy evaluation
- enforces `verifyAuthorization(...)` before execution
- emits audit evidence for later verification

Adapters are integration components.
They are not part of the protocol.

## Production PEP Wiring

Production flow:

```text
runtime proposes action
adapter normalizes action
OxDeAI PDP evaluates policy
AuthorizationV1 returned on ALLOW
PEP verifies authorization
external side effect executed
```

Production rules:

- authorization verification MUST occur before side effects
- `DENY` MUST produce an explicit refusal path
- execution outcomes SHOULD emit audit events
- authorization artifacts SHOULD remain verifiable offline

See:

- [`docs/adapter-contract.md`](../adapter-contract.md)
- [`docs/pep-production-guide.md`](../pep-production-guide.md)

## Shared Demo Scenario

This integration implements the canonical shared scenario described in [`shared-demo-scenario.md`](./shared-demo-scenario.md).

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Raw action form differs by runtime.
For this adapter, the raw proposal surface is an OpenAI tool or function call.

## Validation

Local validation command:

```bash
pnpm -C examples/openai-tools validate
```

Example directory:

- [`examples/openai-tools`](../../examples/openai-tools)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- This is the reference function/tool-call boundary demo in the repository.
- Tool-call normalization is the primary adapter responsibility.
- The adapter MUST ensure equivalent tool proposals map to equivalent intents.
