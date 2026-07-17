// SPDX-License-Identifier: Apache-2.0
import type { PolicyResult } from "../types/policy.js";

/**
 * Inputs to {@link verifyTrustedTime}.
 *
 * `evaluationTime` MUST be supplied by a trusted caller — the PEP's own
 * clock, sampled once per evaluation (docs/spec/core/trusted-time-v1.md
 * §2.1). This module never reads an ambient clock; passing an untrusted or
 * attacker-influenced `evaluationTime` defeats the entire trusted-time
 * model. `intentTimestamp` is the opposite trust class: an agent-supplied,
 * attacker-controllable freshness claim, admissible for this bounded check
 * only (spec §2, §6).
 *
 * @public
 */
export type VerifyTrustedTimeInput = {
  /** Agent-supplied `Intent.timestamp` (unix seconds). Untrusted freshness claim. */
  intentTimestamp: number;
  /** Trusted PEP clock (unix seconds), sampled once per evaluation by the caller. */
  evaluationTime: number;
  /** Max seconds `intentTimestamp` may lead `evaluationTime` and still be fresh (spec §5). */
  maxClockSkewSeconds: number;
  /** Max seconds `intentTimestamp` may lag `evaluationTime` and still be fresh (spec §5). */
  maxIntentAgeSeconds: number;
};

/**
 * Protocol numeric domain (spec §5.1): finite, non-negative, safe-integer
 * unix-seconds / duration-seconds values only. NaN, Infinity, non-integers,
 * negatives, and unsafe magnitudes are all rejected — never coerced.
 */
function isProtocolSeconds(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/**
 * Pure, deterministic freshness gate for the trusted-time profile
 * (docs/spec/core/trusted-time-v1.md §6).
 *
 * Compares the untrusted `intentTimestamp` freshness claim against the
 * trusted `evaluationTime` and the two bounded tolerances. Both boundaries
 * are inclusive — a delta exactly equal to a tolerance is fresh; only a
 * delta strictly beyond it denies (spec §6).
 *
 * This function is side-effect-free: it performs no I/O, reads no ambient
 * clock (`Date.now()` or otherwise), derives no trust from
 * `intentTimestamp`, and does not mutate its input or any external state.
 * It returns the standard `PolicyResult` shape (spec §3) — `ALLOW` with
 * empty reasons, or `DENY` with one `ReasonCode` — introducing no parallel
 * result format.
 *
 * This function is standalone: it is not wired into `PolicyEngine`, does
 * not read or write `State`, and does not evaluate replay, velocity, or any
 * other gate. Wiring it into the evaluation pipeline is a separate,
 * independently reviewed change (spec §9).
 *
 * A malformed `intentTimestamp` (NaN, Infinity, non-integer, negative, or
 * unsafe magnitude) is the one attacker-reachable invalid input; it fails
 * closed with `STATE_INVALID` per spec §5.1/§6, without being compared
 * against the boundaries.
 *
 * `evaluationTime`, `maxClockSkewSeconds`, and `maxIntentAgeSeconds` are
 * trusted-caller / configuration inputs, not attacker-reachable data. A
 * malformed value among them is a caller precondition violation — per spec
 * §5.1 ("malformed configuration MUST cause the implementation to refuse to
 * evaluate") this function throws rather than returning a policy decision,
 * so the failure cannot be mistaken for a data-driven `DENY`.
 *
 * @public
 */
export function verifyTrustedTime(input: VerifyTrustedTimeInput): PolicyResult {
  const { intentTimestamp, evaluationTime, maxClockSkewSeconds, maxIntentAgeSeconds } = input;

  if (!isProtocolSeconds(evaluationTime)) {
    throw new Error(
      "verifyTrustedTime: evaluationTime must be a finite, non-negative safe integer (unix seconds)"
    );
  }
  if (!isProtocolSeconds(maxClockSkewSeconds)) {
    throw new Error(
      "verifyTrustedTime: maxClockSkewSeconds must be a finite, non-negative safe integer"
    );
  }
  if (!isProtocolSeconds(maxIntentAgeSeconds)) {
    throw new Error(
      "verifyTrustedTime: maxIntentAgeSeconds must be a finite, non-negative safe integer"
    );
  }

  if (!isProtocolSeconds(intentTimestamp)) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const delta = intentTimestamp - evaluationTime;

  if (delta > maxClockSkewSeconds) {
    return { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] };
  }
  if (-delta > maxIntentAgeSeconds) {
    return { decision: "DENY", reasons: ["INTENT_STALE"] };
  }

  return { decision: "ALLOW", reasons: [] };
}
