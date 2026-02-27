import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

export function ConcurrencyModule(intent: Intent, state: State): PolicyResult {
  const agent = intent.agent_id;
  const t = intent.type ?? "EXECUTE";

  const max = state.concurrency?.max_concurrent?.[agent];
  if (max === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const active = state.concurrency.active?.[agent] ?? 0;

  // --- RELEASE path ---
  if (t === "RELEASE") {
    const authId = intent.authorization_id;
    if (!authId) return { decision: "DENY", reasons: ["CONCURRENCY_RELEASE_INVALID"] };

    const activeAuths = state.concurrency.active_auths?.[agent] ?? {};
    if (!activeAuths[authId]) {
      return { decision: "DENY", reasons: ["CONCURRENCY_RELEASE_INVALID"] };
    }

    // remove auth + decrement active (never below 0)
    const { [authId]: _, ...rest } = activeAuths;
    const nextActive = active > 0 ? active - 1 : 0;

    return {
      decision: "ALLOW",
      reasons: [],
      stateDelta: {
        concurrency: {
          ...state.concurrency,
          active: {
            ...state.concurrency.active,
            [agent]: nextActive
          },
          active_auths: {
            ...state.concurrency.active_auths,
            [agent]: rest
          }
        }
      }
    };
  }

  // --- EXECUTE path ---
  if (active >= max) {
    return { decision: "DENY", reasons: ["CONCURRENCY_LIMIT_EXCEEDED"] };
  }

  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      concurrency: {
        ...state.concurrency,
        active: {
          ...state.concurrency.active,
          [agent]: active + 1
        }
      }
    }
  };
}

export const ConcurrencyModuleCodec = statelessModuleCodec("ConcurrencyModule");
