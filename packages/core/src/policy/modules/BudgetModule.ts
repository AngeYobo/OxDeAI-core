import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";


export function BudgetModule(intent: Intent, state: State): PolicyResult {
  const limit = state.budget.budget_limit[intent.agent_id];
  const spent = state.budget.spent_in_period[intent.agent_id] ?? 0n;

  if (limit === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const cap = state.max_amount_per_action[intent.agent_id];
  if (cap === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };
  if (intent.amount > cap) return { decision: "DENY", reasons: ["PER_ACTION_CAP_EXCEEDED"] };

  if (spent + intent.amount > limit) return { decision: "DENY", reasons: ["BUDGET_EXCEEDED"] };

  // Proposed delta (no mutation)
  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      budget: {
        ...state.budget,
        spent_in_period: {
          ...state.budget.spent_in_period,
          [intent.agent_id]: spent + intent.amount
        }
      }
    }
  };
}

export const BudgetModuleCodec = statelessModuleCodec("BudgetModule");
