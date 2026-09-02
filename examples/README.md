# Examples

Reference integrations and usage examples for OxDeAI.

## Included

- `gpu-guard` - deterministic GPU provisioning guard with audit chain
- `langgraph` - LangGraph integration demo with OxDeAI PDP/PEP guard boundary
- `openai-tools` - OpenAI tools/runtime integration demo with matching policy scenario
- `crewai` - CrewAI-shaped integration demo with shared ALLOW/ALLOW/DENY scenario
- `openai-agents-sdk` - OpenAI Agents SDK-shaped integration demo with shared boundary contract
- `autogen` - AutoGen-shaped integration demo with shared boundary contract
- `openclaw` - OpenClaw-shaped integration demo with the canonical authorization boundary flow
- `rust-verifier` - reference-only Rust verifier skeleton (`AuthorizationV1` fail-closed path)
- `agentgram-demo` - deterministic execution boundary for Agentgram actions using the OxDeAI SDK
- `delegation` - `DelegationV1` demo: a parent agent delegates strictly narrowed authority to a child agent
- `execution-boundary-demo` - two-panel UI contrasting an unprotected path against the OxDeAI-guarded path
- `lgf-frappe-pep` - minimal OxDeAI PEP for the LGF-managed Frappe Helpdesk proof of concept
- `non-bypassable-demo` - canonical `Agent -> PEP Gateway -> Protected Upstream` demo: the agent process has no direct call path to the protected upstream
- `sift` - end-to-end demo tracing the integration path from a Sift governance receipt to OxDeAI execution authorization
- `sift-boundary-demo` - terminal demo of Sift-to-OxDeAI execution-boundary enforcement across 4 scenarios
- `reference-sift-oxdeai` - reference implementation of Sift-to-OxDeAI integration with execution-boundary enforcement

## Known-broken at HEAD

The runtime fixes for these are tracked and handled separately from documentation
changes. Do not treat them as verified until fixed.

- `delegation-demo`: `OxDeAIGuard` construction in `src/scenario.ts` omits the
  now-required `trustedKeySets`. Both `pnpm start` and `pnpm terminal` currently
  throw `OxDeAIGuardConfigurationError` on invocation.
- `non-bypassable-openclaw`: `agent.mjs` builds an unsigned, structurally
  incomplete `AuthorizationV1` fixture instead of reusing
  `non-bypassable-demo/auth-fixture.mjs`'s signed fixture. The documented
  ALLOW / DENY_HASH_MISMATCH / REPLAY scenarios do not currently produce the
  documented outcomes.

`non-bypassable-demo` is the canonical, currently-working non-bypassability
example and is unaffected by the above.
