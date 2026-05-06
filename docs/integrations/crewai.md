# CrewAI Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets CrewAI-shaped task and tool execution flows.
OxDeAI sits at the boundary between task-proposed actions and tool execution.

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
- CrewAI runtime dependencies used by the host integration

## Minimal Quickstart

Run the CrewAI-shaped example:

```bash
pnpm -C examples/crewai start
```

Repository example:

- [`examples/crewai`](../../examples/crewai)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

## Adapter Responsibilities

For this integration, the adapter:

- normalizes task or tool proposals into intent
- provides current policy state
- invokes OxDeAI evaluation
- enforces `verifyAuthorization(...)` before execution
- emits audit events for decisions and outcomes

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
external side effect executes
```

Production rules:

- authorization verification MUST occur before side effects
- `DENY` MUST remain explicit
- execution/refusal outcomes SHOULD emit audit events
- verification artifacts SHOULD remain usable offline

## Shared Demo Scenario

This integration implements the canonical shared scenario described in [`shared-demo-scenario.md`](./shared-demo-scenario.md).

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Raw action form differs by runtime.
For this adapter, the raw proposal surface is a CrewAI task or tool handoff.

## Validation

Local validation command:

```bash
pnpm -C examples/crewai validate
```

Example directory:

- [`examples/crewai`](../../examples/crewai)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- CrewAI integrations usually normalize at the task-to-tool boundary.
- Normalization SHOULD preserve stable action type, target, and resource identity.
- Adapter behavior should remain comparable to other tool-oriented integrations.
