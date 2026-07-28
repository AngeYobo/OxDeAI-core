// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "./intent.js";
import type { ModuleStateCodec, State } from "./state.js";

/** @public */
export const Decision = {
  ALLOW: "ALLOW",
  DENY: "DENY"
} as const;

/** @public */
export type Decision = (typeof Decision)[keyof typeof Decision];

/** @public */
export const ReasonCode = {
  KILL_SWITCH: "KILL_SWITCH",
  ALLOWLIST_ACTION: "ALLOWLIST_ACTION",
  ALLOWLIST_ASSET: "ALLOWLIST_ASSET",
  ALLOWLIST_TARGET: "ALLOWLIST_TARGET",
  POLICY_VERSION_MISMATCH: "POLICY_VERSION_MISMATCH",
  STATE_INVALID: "STATE_INVALID",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
  PER_ACTION_CAP_EXCEEDED: "PER_ACTION_CAP_EXCEEDED",
  VELOCITY_EXCEEDED: "VELOCITY_EXCEEDED",
  CONCURRENCY_LIMIT_EXCEEDED: "CONCURRENCY_LIMIT_EXCEEDED",
  RECURSION_DEPTH_EXCEEDED: "RECURSION_DEPTH_EXCEEDED",
  REPLAY_NONCE: "REPLAY_NONCE",
  REPLAY_DETECTED: "REPLAY_DETECTED",
  AUTH_EXPIRED: "AUTH_EXPIRED",
  AUTH_SIGNATURE_INVALID: "AUTH_SIGNATURE_INVALID",
  AUTH_INTENT_MISMATCH: "AUTH_INTENT_MISMATCH",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  CONCURRENCY_RELEASE_INVALID: "CONCURRENCY_RELEASE_INVALID",
  TOOL_CALL_LIMIT_EXCEEDED: "TOOL_CALL_LIMIT_EXCEEDED",
  INTENT_FRESHNESS_FUTURE: "INTENT_FRESHNESS_FUTURE",
  INTENT_STALE: "INTENT_STALE",
} as const;

/** @public */
export type ReasonCode = (typeof ReasonCode)[keyof typeof ReasonCode];

/** @public */
export type PolicyResult =
  | { decision: "ALLOW"; reasons: []; stateDelta?: Partial<State> }
  | { decision: "DENY"; reasons: ReasonCode[] };

/**
 * Trusted evaluator inputs handed to every policy module.
 *
 * This is a single extensible context object rather than a positional
 * parameter list: later trusted-evaluator work adds *fields* here instead of
 * widening `PolicyModule.evaluate` again for each new input.
 *
 * `evaluationTime` is the trusted PEP clock (unix seconds), sampled once per
 * evaluation and threaded down from `PolicyEngine.evaluatePure`. It is already
 * validated by `assertProtocolSeconds` before any module runs, and it is NOT
 * `intent.timestamp` — that value is attacker-controlled.
 *
 * @public
 */
export interface PolicyEvaluationContext {
  evaluationTime: number;
}

/** @public */
export interface PolicyModule {
  id: string;
  evaluate(intent: Intent, state: State, context: PolicyEvaluationContext): PolicyResult;
  codec: ModuleStateCodec;
}

// Backward-compatible alias for older imports.
/** @public */
export type ModuleResult = PolicyResult;

/** @public */
export type PolicyId = string;
