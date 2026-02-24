import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";

export function BudgetModule(intent: Intent, state: State): PolicyResult {
  const limit = state.budget.budget_limit[intent.agent_id];
  const spent = state.budget.spent_in_period[intent.agent_id] ?? 0n;

  // Fail-closed if budget not configured
  if (limit === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  // INV-2 per-action cap
  const cap = state.max_amount_per_action[intent.agent_id];
  if (cap === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };
  if (intent.amount > cap) return { decision: "DENY", reasons: ["PER_ACTION_CAP_EXCEEDED"] };

  // INV-1 budget hard cap
  if (spent + intent.amount > limit) return { decision: "DENY", reasons: ["BUDGET_EXCEEDED"] };

  return { decision: "ALLOW", reasons: [] };
}