import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

export function KillSwitchModule(intent: Intent, state: State): PolicyResult {
  if (state.kill_switch.global) return { decision: "DENY", reasons: ["KILL_SWITCH"] };
  if (state.kill_switch.agents[intent.agent_id] === true) {
    return { decision: "DENY", reasons: ["KILL_SWITCH"] };
  }
  return { decision: "ALLOW", reasons: [] };
}

export const KillSwitchModuleCodec = statelessModuleCodec("KillSwitchModule");
