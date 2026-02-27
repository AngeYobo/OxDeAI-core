import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

function nonceKey(intent: Intent): string {
  // keep consistent formatting across versions
  return intent.nonce.toString();
}

export function ReplayModule(intent: Intent, state: State): PolicyResult {
  const agent = intent.agent_id;

  const cfg = state.replay;
  if (!cfg || typeof cfg.window_seconds !== "number" || typeof cfg.max_nonces_per_agent !== "number") {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const now = intent.timestamp;
  const windowStart = now - cfg.window_seconds;

  const list = state.replay.nonces[agent] ?? [];

  // prune deterministically
  const pruned = list.filter((x) => x.ts >= windowStart);

  const n = nonceKey(intent);
  if (pruned.some((x) => x.nonce === n)) {
    return { decision: "DENY", reasons: ["REPLAY_NONCE"] };
  }

  const next = [...pruned, { nonce: n, ts: now }];

  // cap size
  const capped =
    next.length <= cfg.max_nonces_per_agent ? next : next.slice(next.length - cfg.max_nonces_per_agent);

  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      replay: {
        ...state.replay,
        nonces: {
          ...state.replay.nonces,
          [agent]: capped
        }
      }
    }
  };
}

export const ReplayModuleCodec = statelessModuleCodec("ReplayModule");
