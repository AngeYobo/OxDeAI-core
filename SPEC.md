# OxDeAI-core Specification v0.1

## 1. Overview

OxDeAI-core is a deterministic economic guardrails engine for autonomous systems and AI agents.

The engine evaluates:

    evaluate(intent, state) -> decision

decision ∈ { ALLOW, DENY }

Evaluation is deterministic.

---

## 2. Fail-Closed Semantics

If state is malformed or incomplete:

    decision = DENY (STATE_INVALID)

The engine MUST never ALLOW under uncertainty.

---

## 3. Normative Predicates (evaluated on PRE-STATE)

All predicates below are evaluated against the **pre-evaluation state** (snapshot at function entry).

An intent MAY be ALLOWED iff ALL predicates hold:

P-KILL:
    global_kill == false
    agent_kill == false

P-ALLOWLIST:
    action_type ∈ allowed_action_types
    asset ∈ allowed_assets
    target ∈ allowed_targets

P-CAP:
    amount ≤ max_amount_per_action

P-BUDGET:
    spent_pre + amount ≤ budget_limit

P-VELOCITY:
    if within_window(pre_state):
        count_pre + 1 ≤ max_actions

P-REPLAY:
    nonce not previously seen (pre_state)

---

## 4. State Update Semantics

State updates are applied **only if decision = ALLOW**.

After an ALLOW decision, the implementation MAY update internal counters, such as:

- spent_in_period[agent] := spent_pre + amount
- velocity.counters[agent] := (window_start, count_pre + 1) or reset window if expired
- replay protection store: mark (agent_id, nonce) as seen

After a DENY decision, the implementation MUST NOT apply economic state increments
(spent/counters). (Audit logging is allowed.)

---

## 5. Meta-Invariant

ALLOW ⇒ all normative predicates hold (on PRE-STATE).

This property is enforced through fuzz + meta-property testing.

---

## 6. Authorization

If decision = ALLOW:

authorization = HMAC_SHA256(engine_secret, canonical_intent)

Verification must be constant-time.

---

## 7. Audit Log

Each evaluation result is appended to a hash chain:

hash_n = SHA256(hash_(n-1) || decision_payload)

Any tampering invalidates the chain.

---

## 8. Determinism

Given identical (intent, pre-state):

    evaluate() MUST return identical decision and reason codes.

No randomness is permitted inside the engine.

---

Spec Version: 0.1
Status: Deterministic, invariant-driven.
