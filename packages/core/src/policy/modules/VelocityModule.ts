import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

export function VelocityModule(intent: Intent, state: State): PolicyResult {
  const cfg = state.velocity?.config;
  if (!cfg || typeof cfg.window_seconds !== "number" || typeof cfg.max_actions !== "number") {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const agent = intent.agent_id;
  const now = intent.timestamp;

  const c = state.velocity.counters[agent];
  const windowExpired = !c || now >= c.window_start + cfg.window_seconds;

  const nextCounter = windowExpired
    ? { window_start: now, count: 1 }
    : { window_start: c.window_start, count: c.count + 1 };

  if (nextCounter.count > cfg.max_actions) {
    return { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] };
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

export const VelocityModuleCodec = statelessModuleCodec("VelocityModule");
