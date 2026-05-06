# OpenClaw Integration

## Status

Non-normative (developer documentation)






## Overview

This integration kit targets OpenClaw-shaped command execution runtimes.
OxDeAI sits between proposed command execution and the external side effect boundary.

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
- OpenClaw runtime dependencies used by the host integration

## Minimal Quickstart

Run the OpenClaw-shaped example:

```bash
pnpm -C examples/openclaw start
```

Repository example:

- [`examples/openclaw`](../../examples/openclaw)

Expected sequence:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

## Adapter Responsibilities

For this integration, the adapter:

- normalizes command-style runtime actions into intent
- provides current policy state
- invokes OxDeAI evaluation
- enforces `verifyAuthorization(...)` before execution
- emits audit events for decision and execution/refusal outcomes

Adapters are integration components.
They are not part of the protocol.

## Production PEP Wiring

Production flow:

```text
runtime proposes command
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
For this adapter, the raw proposal surface is a command-style execution request.

## Validation

Local validation command:

```bash
pnpm -C examples/openclaw validate
```

Example directory:

- [`examples/openclaw`](../../examples/openclaw)

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Boundary expectation:
- the denied third action does not execute
- missing authorization fails closed before execution

## Integration Notes

- OpenClaw is the closest command-execution shaped adapter in the repository.
- Command execution proposals still require deterministic normalization into intent.
- The adapter boundary is where raw command surfaces become verifiable OxDeAI authorization decisions.
