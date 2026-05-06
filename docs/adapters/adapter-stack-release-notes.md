# Adapter Stack Release Notes

## Status

Non-normative (developer documentation)

Historical release note. This file is not current release policy and must not be used as a release runbook. Current release policy is package-scoped and lives in [`docs/release/RELEASE.md`](../release/RELEASE.md).






## Release Status

Complete (v1.4)

The OxDeAI adapter stack is complete. All maintained runtime adapters have been implemented, tested, and validated.

## What is complete

### Universal PEP package

- `@oxdeai/guard` - `OxDeAIGuard(config)` factory; all authorization logic lives here

### Runtime adapter packages (5 adapters)

| Package | Runtime | Status |
|---|---|---|
| `@oxdeai/langgraph` | LangGraph | complete - tests pass |
| `@oxdeai/openai-agents` | OpenAI Agents SDK | complete - tests pass |
| `@oxdeai/crewai` | CrewAI | complete - tests pass |
| `@oxdeai/autogen` | AutoGen | complete - tests pass |
| `@oxdeai/openclaw` | OpenClaw | complete - tests pass |

### Examples (5 adapters + reference)

| Example | Adapter used |
|---|---|
| `examples/openai-tools` | direct `@oxdeai/core` (reference boundary demo) |
| `examples/langgraph` | `@oxdeai/langgraph` |
| `examples/openai-agents-sdk` | `@oxdeai/openai-agents` |
| `examples/crewai` | `@oxdeai/crewai` |
| `examples/autogen` | `@oxdeai/autogen` |
| `examples/openclaw` | `@oxdeai/openclaw` |

All examples produce the deterministic shared scenario:
- `ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`

## Architecture invariants upheld

- No adapter package contains authorization logic
- All adapters delegate to `@oxdeai/guard`
- All adapters inject `agentId` (tool calls carry no agent identity)
- All adapters re-export `OxDeAIDenyError`, `OxDeAIAuthorizationError`, `OxDeAINormalizationError`
- All adapters support `mapActionToIntent`, `beforeExecute`, `onDecision`, `strict`
- Fail-closed: `ALLOW` without authorization artifact throws `OxDeAIAuthorizationError`

## Validation

Run full adapter validation:

```bash
# Build all packages
pnpm build

# Run all adapter tests
pnpm --filter "@oxdeai/guard" test
pnpm --filter "@oxdeai/langgraph" test
pnpm --filter "@oxdeai/openai-agents" test
pnpm --filter "@oxdeai/crewai" test
pnpm --filter "@oxdeai/autogen" test
pnpm --filter "@oxdeai/openclaw" test

# Run all examples
pnpm -C examples/openai-tools start
pnpm -C examples/langgraph start
pnpm -C examples/openai-agents-sdk start
pnpm -C examples/crewai start
pnpm -C examples/autogen start
pnpm -C examples/openclaw start

# Cross-adapter validation
node scripts/validate-adapters.mjs
```

## References

- [Adapter stack architecture](../integrations/adapter-stack.md)
- [Adapter reference architecture](./adapter-reference-architecture.md)
- [Shared demo scenario](../integrations/shared-demo-scenario.md)
- [Adapter validation](adapter-verification.md)
