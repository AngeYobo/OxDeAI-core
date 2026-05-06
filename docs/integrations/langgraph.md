# LangGraph Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets LangGraph-style workflow execution.
OxDeAI sits below the graph node proposal layer and above actual tool execution.

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
- `@oxdeai/langgraph` (thin adapter binding)
- `@oxdeai/guard` (universal PEP - delegated to by `@oxdeai/langgraph`)

## Minimal Quickstart

Run the LangGraph example:

```bash
pnpm -C examples/langgraph start
```

Repository example:

- [`examples/langgraph`](../../examples/langgraph)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

The workflow node proposes actions; the adapter normalizes them into intent before OxDeAI evaluation.

## Adapter Responsibilities

The `@oxdeai/langgraph` package is a **thin binding only**. It:

- injects `agentId` from config into every tool call (LangGraph tool calls carry no agent identity)
- maps `toolCall.id` → `context.intent_id`
- passes the resulting `ProposedAction` to `@oxdeai/guard`

Everything else - policy evaluation, authorization verification, state persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

Adapters are integration components.
They are not part of the protocol.

## Production PEP Wiring

Production flow:

```text
workflow node proposes action
adapter normalizes action
OxDeAI PDP evaluates policy
AuthorizationV1 returned on ALLOW
PEP verifies authorization
external side effect executes
```

Production rules:

- authorization verification MUST occur before side effects
- `DENY` MUST yield an explicit refusal path
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
For this adapter, the raw proposal surface is a LangGraph workflow or node dispatch.

## Validation

Local validation command:

```bash
pnpm -C examples/langgraph validate
```

Example directory:

- [`examples/langgraph`](../../examples/langgraph)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- LangGraph normalization typically happens at the node or tool-dispatch boundary.
- Equivalent workflow proposals SHOULD map to equivalent intents.
- Graph orchestration changes adapter code, not OxDeAI protocol semantics.
