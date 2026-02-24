import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";

export function VelocityModule(intent: Intent, state: State): PolicyResult {
  const cfg = state.velocity.config;
  const c = state.velocity.counters[intent.agent_id];
  const now = intent.timestamp;

  if (!c) return { decision: "ALLOW", reasons: [] };

  const windowEnd = c.window_start + cfg.window_seconds;

  // If window elapsed, allow (engine will reset on commit)
  if (now >= windowEnd) return { decision: "ALLOW", reasons: [] };

  if (c.count + 1 > cfg.max_actions) return { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] };

  return { decision: "ALLOW", reasons: [] };
}