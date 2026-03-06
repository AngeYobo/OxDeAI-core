# OxDeAI Demo — OpenAI Tools Pattern

Demonstrates the OxDeAI **pre-execution economic boundary** in practice.

An agent plans three tool calls. OxDeAI evaluates each intent before any tool executes.
If the policy denies an intent, the tool call is blocked — not monitored after the fact, blocked.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Agent                            │
│   "I want to call web.search for $0.10"                 │
└────────────────────┬────────────────────────────────────┘
                     │ PlannedCall
                     ▼
┌─────────────────────────────────────────────────────────┐
│              PEP — Policy Enforcement Point             │  pep.ts
│                                                         │
│  1. builds Intent from planned call                     │
│  2. asks PDP: is this allowed?                          │
│  3. if DENY → abort, tool never called                  │
│  4. if ALLOW → verify Authorization is present          │
│  5. execute tool only after Authorization confirmed     │
└────────────┬────────────────────────────────────────────┘
             │ Intent
             ▼
┌─────────────────────────────────────────────────────────┐
│              PDP — Policy Decision Point                │  policy.ts
│                                                         │
│  PolicyEngine.evaluatePure(intent, state)               │
│                                                         │
│  Modules checked:                                       │
│    KillSwitch · Budget · PerActionCap · Velocity        │
│    Replay · Concurrency · Recursion · ToolAmplification │
│                                                         │
│  Returns: ALLOW + Authorization + nextState             │
│        or DENY + reasons                                │
└─────────────────────────────────────────────────────────┘
```

**PDP** = evaluates policy, issues authorizations, owns state transitions.  
**PEP** = enforces the authorization requirement at execution time. Thin by design.

---

## What This Demo Shows

| Step | What happens |
|---|---|
| Intent built | agent_id, tool, amount, nonce, timestamp |
| `evaluatePure` called | deterministic policy evaluation, pre-execution |
| DENY path | tool call is blocked, state unchanged |
| ALLOW path | Authorization issued with `expires_at` and HMAC signature |
| Tool executes | only after Authorization confirmed by PEP |
| Audit events logged | INTENT_RECEIVED → DECISION → AUTH_EMITTED |
| Envelope produced | snapshot + audit events bundled |
| `verifyEnvelope` called | independent offline verification, strict mode |

---

## Run

**Prerequisites:** built monorepo (`pnpm build` from root).

```bash
# From monorepo root:
cd examples/openai-tools

# Allow path — all 3 tool calls succeed
pnpm start

# Deny path — budget exhausted, 3rd call blocked
pnpm start:deny
```

No paid API calls. All tool execution is mocked. The economic boundary is real.

---

## Expected output (allow path)

```
╔══════════════════════════════════════════════════════════════════╗
║  OxDeAI Demo — OpenAI Tools Pattern                              ║
║  Mode: NORMAL BUDGET (allow path)                                ║
╚══════════════════════════════════════════════════════════════════╝

Policy:  budget=5000000μ$  spent=0μ$  remaining=5000000μ$
         max_per_action=2000000μ$

── Agent tool calls ────────────────────────────────────────────────

→ INTENT  tool=web.search  amount=100000μ$  nonce=1
✓ ALLOWED  auth_id=...  expires=...
⚙  EXECUTE  web.search({"query":"current GPU spot prices us-east-1"})
   RESULT   ✓ [MOCK] Search results for: "current GPU spot prices us-east-1"

→ INTENT  tool=openai.responses  amount=500000μ$  nonce=2
✓ ALLOWED  auth_id=...  expires=...
⚙  EXECUTE  openai.responses(...)
   RESULT   ✓ [MOCK] LLM response to: ...

→ INTENT  tool=data.fetch  amount=1000000μ$  nonce=3
✓ ALLOWED  auth_id=...  expires=...
⚙  EXECUTE  data.fetch(...)
   RESULT   ✓ [MOCK] Fetched dataset ...

── Summary ──────────────────────────────────────────────────────────
   Executed: 3  Denied: 0

── Verification envelope ──────────────────────────────────────────
   status:        ok
   violations:    none

✓ Envelope verified. Execution history is tamper-evident and auditable.
```

## Expected output (deny path)

Same as above except the third call:
```
→ INTENT  tool=data.fetch  amount=1000000μ$  nonce=3
✗ DENIED  reasons: per_action_cap_exceeded
   Executed: 2  Denied: 1
```

---

## Key invariants demonstrated

- **Pre-execution**: `evaluatePure` is called before any tool runs. No post-hoc monitoring.
- **Fail-closed**: DENY → no tool call, no state mutation, no side effects.
- **Authorization binding**: PEP checks for Authorization before executing. ALLOW without Authorization throws.
- **State commitment**: `nextState` from PDP committed only after successful execution.
- **Audit chain**: every evaluation emits ordered, hash-chained events.
- **Verifiable envelope**: third party can verify execution history without running the engine.

---

## Extending this demo

**Add a real OpenAI tool call:**
Replace the mock in `TOOL_REGISTRY` with an actual `fetch` to the OpenAI API.
The PEP boundary and authorization check are unchanged.

**Add more policy modules:**
Adjust `makeNormalState()` in `policy.ts` to tune budget, velocity, or recursion limits.

**Test tamper detection:**
Modify an audit event after recording it, then call `verifyEnvelope` — it will return `invalid`.