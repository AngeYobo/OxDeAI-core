# OxDeAI Demo - LangGraph Integration Boundary

This example mirrors [`examples/openai-tools`](../openai-tools) as closely as possible.

The key difference is proposal source:

- `openai-tools`: tool calls are proposed in an OpenAI-tools style loop
- `langgraph`: tool calls are proposed by a LangGraph workflow node

In both cases, OxDeAI remains the economic authorization boundary below the framework.

---

## What this demo shows

LangGraph proposes GPU provisioning three times. OxDeAI policy allows exactly two.

```text
Call 1: provision_gpu(a100, us-east-1) -> ALLOW  (500 spent,  500 remaining)
Call 2: provision_gpu(a100, us-east-1) -> ALLOW  (1000 spent,   0 remaining)
Call 3: provision_gpu(a100, us-east-1) -> DENY   (BUDGET_EXCEEDED - tool never called)
```

At the end, snapshot + audit events are packed into a verification envelope and checked with `verifyEnvelope(...)`.

---

## Architecture

```text
LangGraph (graph.ts)
  -> proposes tool actions
  -> @oxdeai/langgraph (pep.ts)     ← thin adapter, no security logic
  -> @oxdeai/guard                   ← universal PEP / authorization boundary
  -> Tool Execution (only if Authorization is valid)
```

Expanded:

```text
LangGraph workflow node
  -> proposed provision_gpu(asset, region)
  -> createLangGraphGuard (pep.ts)
      -> maps LangGraphToolCall -> ProposedAction
      -> OxDeAIGuard -> evaluatePure(intent, state, evaluationTime)
          -> DENY  => OxDeAIDenyError, no execution
          -> ALLOW => Authorization required + verified
  -> execute() called only after authorization check
  -> state commit via nextState
  -> audit chain + envelope + verifyEnvelope()
```

The PEP contains no authorization logic. All security decisions live in `@oxdeai/guard`.

---

## Run

Prerequisites: install workspace deps from repo root (`pnpm install`), then:

```bash
cd examples/langgraph
pnpm build
node dist/run.js
```

## Shared Demo Scenario

This example implements the canonical cross-adapter scenario in [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).

Expected visible outcome:

- decision 1: `ALLOW`
- decision 2: `ALLOW`
- decision 3: `DENY`
- envelope verification: `ok`

---

## Expected output (compact)

```text
LangGraph workflow
  proposed tool calls: 3

Call 1 -> ALLOW -> EXECUTED
Call 2 -> ALLOW -> EXECUTED
Call 3 -> DENY  -> NOT EXECUTED

verifyEnvelope (strict mode): status=ok
```

---

## Why the third action is denied

Policy budget is fixed at 1000 minor units.
Each `a100/us-east-1` provisioning intent costs 500.

- Call 1 consumes 500
- Call 2 consumes 500
- Call 3 exceeds budget and is denied before execution

This keeps framework orchestration separate from authorization enforcement.
