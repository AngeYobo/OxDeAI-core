import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult, ReasonCode } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

/** @public */
export function AllowlistModule(intent: Intent, state: State): PolicyResult {
  const reasons: ReasonCode[] = [];
  const al = state.allowlists;

  if (al.action_types && al.action_types.length > 0 && !al.action_types.includes(intent.action_type)) {
    reasons.push("ALLOWLIST_ACTION");
  }
  if (al.assets && al.assets.length > 0 && intent.asset && !al.assets.includes(intent.asset)) {
    reasons.push("ALLOWLIST_ASSET");
  }
  if (al.targets && al.targets.length > 0 && !al.targets.includes(intent.target)) {
    reasons.push("ALLOWLIST_TARGET");
  }

  return reasons.length ? { decision: "DENY", reasons } : { decision: "ALLOW", reasons: [] };
}

/** @public */
export const AllowlistModuleCodec = statelessModuleCodec("AllowlistModule");
