import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult, ReasonCode } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

export function AllowlistModule(intent: Intent, state: State): PolicyResult {
  const reasons: ReasonCode[] = [];
  const al = state.allowlists;

  if (al.action_types && !al.action_types.includes(intent.action_type)) {
    reasons.push("ALLOWLIST_ACTION");
  }
  if (al.assets && intent.asset && !al.assets.includes(intent.asset)) {
    reasons.push("ALLOWLIST_ASSET");
  }
  if (al.targets && !al.targets.includes(intent.target)) {
    reasons.push("ALLOWLIST_TARGET");
  }

  return reasons.length ? { decision: "DENY", reasons } : { decision: "ALLOW", reasons: [] };
}

export const AllowlistModuleCodec = statelessModuleCodec("AllowlistModule");
