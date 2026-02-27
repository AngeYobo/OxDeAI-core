import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

export function RecursionDepthModule(intent: Intent, state: State): PolicyResult {
  const agent = intent.agent_id;

  const max = state.recursion?.max_depth?.[agent];
  if (max === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const depth = intent.depth ?? 0;
  if (depth > max) {
    return { decision: "DENY", reasons: ["RECURSION_DEPTH_EXCEEDED"] };
  }

  return { decision: "ALLOW", reasons: [] };
}

export const RecursionDepthModuleCodec = statelessModuleCodec("RecursionDepthModule");
