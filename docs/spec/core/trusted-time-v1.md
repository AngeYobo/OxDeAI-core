
# Trusted-Time Authorization - Core Profile v1

This document defines the normative **trusted-time** rules for Execution-Time
Authorization (ETA). It is a strict extension of `eta-core-v1.md`: it constrains
which clock an evaluator may rely on when a decision depends on time.

It defines the specification only. Verifier wiring (`verifyTrustedTime`), engine
integration, and conformance vectors are out of scope for this document and are
introduced by separate, independently reviewed changes.

---

## 1. Purpose

An `Intent` may carry an agent-supplied timestamp. An attacker who controls the
agent controls that value. Any time-dependent authorization decision that trusts
it — issuance, expiry, replay retention, or velocity accounting — is
attacker-influenced.

Trusted-time authorization removes that influence by separating two clocks and
restricting the untrusted one to a single, bounded purpose.

---

## 2. Two-Clock Trust Model

An evaluation reasons over two distinct time sources:

- **`intent.timestamp`** — an agent-supplied value on the `Intent` (unix
  seconds). It is an **untrusted freshness claim**. It is attacker-controllable
  and MUST NOT drive issuance, expiry, replay retention, or velocity accounting.
- **`evaluation_time`** — the **trusted PEP clock** read at the moment of
  evaluation (unix seconds). It is the sole authority for `issued_at`, expiry
  derivation, replay-window retention/eviction, and velocity windows.

`intent.timestamp` is admissible for exactly one purpose: a bounded **freshness**
check against `evaluation_time` (§6). Every other time-dependent decision MUST
key off `evaluation_time` only.

---

## 3. Evaluation Contract

The evaluation is:

```
evaluate(intent, state, evaluation_time) → { decision, status, issued_at?, expiry?, violations[] }
```

- `decision` ∈ { `ALLOW`, `DENY` }.
- `status`: `ok` on `ALLOW`; a denial status otherwise.
- On **`ALLOW`**: `issued_at` and `expiry` MUST be present and derived per §5.
- On **`DENY`**: `issued_at` and `expiry` MUST be absent — no authorization is
  minted for a denied intent — and `violations[]` MUST carry one or more reason
  codes (§7).
- Evaluation MUST be a pure function of `(intent, state, evaluation_time)`. It
  MUST NOT read an ambient clock inside the evaluation; `evaluation_time` is the
  only time input.

How `evaluation_time` is threaded into the existing evaluation pipeline (an
explicit third parameter, a decision context, or a PEP-level pre-gate) is an
implementation concern for a later change and is not fixed by this profile.

---

## 4. Consistency Invariants

A conformant trusted-time evaluation MUST hold all four invariants:

1. **Skew is freshness-only.** Skew tolerance applies only to the
   `intent.timestamp` freshness claim (§6); it MUST NOT widen expiry or any
   other window.
2. **Trusted issuance.** `issued_at` MUST be minted from trusted time:
   `issued_at = evaluation_time`.
3. **Trusted, bounded expiry.** `expiry` MUST be derived from trusted time and a
   bounded TTL: `expiry = evaluation_time + min(maxTtlSeconds, requested_ttl)`.
   Absent an optional `requested_ttl`, `expiry = evaluation_time + maxTtlSeconds`.
4. **Enforcement stays zero-tolerance.** Trusted-time *mints* the expiry;
   downstream expiry verification remains zero-tolerance (`now < expiry`),
   unchanged from `eta-core-v1`. This profile does not relax enforcement.

---

## 5. Configuration

| field | meaning | requirement |
|---|---|---|
| `maxClockSkewSeconds` | max `intent.timestamp − evaluation_time` tolerated as fresh (future side) | REQUIRED |
| `maxIntentAgeSeconds` | max `evaluation_time − intent.timestamp` tolerated as fresh (stale side) | REQUIRED |
| `replayWindowSeconds` | nonce retention window, keyed to `evaluation_time` | REQUIRED |
| `maxTtlSeconds` | upper bound on the minted expiry TTL | REQUIRED |
| `velocity.maxActions`, `velocity.windowSeconds` | actions per trusted-time window | profile-defined |

- **REQUIRED** fields MUST be present for a conformant trusted-time evaluation.
- **profile-defined** fields MAY be set or omitted by a profile, which MUST
  document its default when omitted.

---

## 6. Freshness Semantics (Future and Stale)

Let `Δ = intent.timestamp − evaluation_time`. The freshness gate is evaluated
**before** replay and velocity (§7 ordering), and is the only gate that reads
`intent.timestamp`.

- **Future-dated.** `Δ > maxClockSkewSeconds` → `DENY`, no authorization minted.
- **Stale.** `−Δ > maxIntentAgeSeconds` → `DENY`, no authorization minted.
- **Fresh.** Otherwise the gate passes and evaluation proceeds. Issuance still
  derives entirely from `evaluation_time` (§4).

Because freshness precedes replay and velocity, an intent that would *also* fail
one of those gates MUST still deny with the freshness reason when it is
future-dated or stale — the freshness decision is reached first.

---

## 7. Replay and Velocity (Trusted-Clock)

Replay and velocity MUST key off `evaluation_time` only.

- **Replay.** A nonce's retention/eviction MUST be computed against
  `evaluation_time`. A future-dated `intent.timestamp` MUST NOT evict a nonce
  still inside `[seen_at, seen_at + replayWindowSeconds)`. Reuse of a retained
  nonce → `DENY`.
- **Velocity.** The action window is
  `[window_start, window_start + velocity.windowSeconds)` in `evaluation_time`.
  A future-dated intent MUST NOT reset or advance it. Exceeding `maxActions`
  within the trusted window → `DENY`.

The honest path MUST remain admissible: a distinct, unused nonce inside the
retention window, and a velocity window that legitimately reset because
*trusted* time advanced, are both `ALLOW` (subject to the rest of the policy).

**Evaluation order (normative):** freshness (§6) → replay → velocity.

---

## 8. Reason-Code Mapping

Codes are mapped against the existing `ReasonCode` set in
`packages/core/src/types/policy.ts`. Reuse is preferred where the semantics
match; additions are **proposed and subject to review**.

| condition | code | status |
|---|---|---|
| retained-nonce reuse (§7) | `REPLAY_NONCE` | **reuse** — existing code |
| velocity window exceeded (§7) | `VELOCITY_EXCEEDED` | **reuse** — existing code |
| minted authorization later expired (downstream enforcement, §4.4) | `AUTH_EXPIRED` | **reuse** — existing code |
| intent future-dated beyond skew (§6) | `INTENT_FRESHNESS_FUTURE` | **proposed addition** |
| intent staler than `maxIntentAgeSeconds` (§6) | `INTENT_STALE` | **proposed addition** |

Notes for review:

- The enum has **no intent-freshness code today**. `AUTH_EXPIRED` is the
  expiry of an already-issued authorization (a different lifecycle stage), and
  `STATE_INVALID` is malformed state (a different meaning), so neither fits the
  freshness gate. The freshness direction genuinely needs new code(s).
- Open naming question: two self-describing codes (`INTENT_FRESHNESS_FUTURE`,
  `INTENT_STALE`, as above) versus one parametrized `INTENT_FRESHNESS_*` code
  carrying the direction. This profile lists two so each violation is
  self-describing, but the enum is the maintainers' to decide.
- `REPLAY_DETECTED` also exists, if a future revision wants to distinguish
  nonce-reuse from broader replay detection.

No code is final until the enum change is reviewed and merged separately.

---

## 9. Out of Scope

This document specifies rules only. The following are explicitly deferred to
separate, independently reviewed changes and MUST NOT be inferred from this
profile:

- `verifyTrustedTime` verifier wiring
- engine / runtime integration of `evaluation_time`
- conformance vectors, including the stale-intent negative/positive pair
- key distribution, delegation, and orchestration (already out of scope per
  `eta-core-v1`)

---

## 10. Conformance

An implementation is trusted-time-conformant if:

- no time-dependent decision relies on `intent.timestamp` except the bounded
  freshness gate (§6);
- `issued_at` and `expiry` are minted from `evaluation_time` under the §4
  invariants;
- replay and velocity key off `evaluation_time` only (§7);
- the evaluation order is freshness → replay → velocity (§7);
- denials mint no authorization and carry a reason code (§3, §8).

Conformance MUST be verifiable via test vectors (introduced separately).

---
