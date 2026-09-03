// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyEvaluationContext, PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

/**
 * Enforces a fixed-window action limit using trusted evaluation time.
 * This is not a rolling or sliding-window limiter.
 *
 * @public
 */
export function VelocityModule(
  intent: Intent,
  state: State,
  context: PolicyEvaluationContext,
): PolicyResult {
  const cfg = state.velocity?.config;
  if (
    !cfg ||
    typeof state.velocity.counters !== "object" ||
    state.velocity.counters === null ||
    Array.isArray(state.velocity.counters) ||
    !Number.isSafeInteger(cfg.window_seconds) ||
    cfg.window_seconds <= 0 ||
    !Number.isSafeInteger(cfg.max_actions) ||
    cfg.max_actions < 0
  ) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const agent = intent.agent_id;
  const now = context.evaluationTime;

  const c = state.velocity.counters[agent];
  if (
    c !== undefined &&
    (
      typeof c !== "object" ||
      c === null ||
      !Number.isSafeInteger(c.window_start) ||
      c.window_start < 0 ||
      !Number.isSafeInteger(c.count) ||
      c.count < 0 ||
      now < c.window_start
    )
  ) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  let nextCounter: { window_start: number; count: number };

  // Subtraction is safe after the backward-clock check because both operands
  // are non-negative safe integers and now >= window_start.
  if (!c || now - c.window_start >= cfg.window_seconds) {
    if (cfg.max_actions < 1) {
      return { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] };
    }
    nextCounter = { window_start: now, count: 1 };
  } else {
    // Refuse before incrementing. Because count < max_actions and max_actions
    // is a safe integer, count + 1 also remains a safe integer.
    if (c.count >= cfg.max_actions) {
      return { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] };
    }
    nextCounter = { window_start: c.window_start, count: c.count + 1 };
  }

  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      velocity: {
        ...state.velocity,
        counters: {
          ...state.velocity.counters,
          [agent]: nextCounter
        }
      }
    }
  };
}

/** @public */
export const VelocityModuleCodec = statelessModuleCodec("VelocityModule");
