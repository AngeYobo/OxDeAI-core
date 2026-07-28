// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyEvaluationContext, PolicyResult } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

function nonceKey(intent: Intent): string {
  // keep consistent formatting across versions
  return intent.nonce.toString();
}

/**
 * Replay-window eviction is driven exclusively by the trusted evaluation
 * clock (`context.evaluationTime`), never by `intent.timestamp`,
 * `issued_at`, `expiry`, or an ambient `Date.now()`.
 *
 * `intent.timestamp` is attacker-controlled, and sourcing the window from it
 * is a replay bypass. Entries are retained while `entry.ts >= windowStart`,
 * so POSTdating an intent pushes `windowStart` forward, prunes the caller's
 * own previously recorded nonce, and lets the replay through. (Backdating
 * moves `windowStart` earlier and therefore retains more; it is not an
 * eviction bypass, though it does inflate replay-state pressure.)
 *
 * Persisted-state compatibility (no migration, self-healing):
 *  - legacy replay entries may have been stamped from `intent.timestamp`;
 *  - they are interpreted as existing persisted timestamps, without conversion;
 *  - all new entries are stamped from `evaluationTime`;
 *  - pruning is driven exclusively by `evaluationTime`;
 *  - no persisted-state schema migration or version bump is required;
 *  - legacy entries self-heal as they expire under the trusted evaluation
 *    clock. The transition completes within one replay retention window plus
 *    the maximum positive legacy timestamp skew permitted by the freshness
 *    policy — a legacy entry may have been stamped from an `intent.timestamp`
 *    running ahead of trusted time by up to the configured future-skew
 *    tolerance, so it survives that much longer than the window alone.
 *
 * This is safe because the trusted-time freshness gate in
 * `PolicyEngine.evaluatePure` already bounds how far `intent.timestamp` may
 * deviate from `evaluationTime`, which is what makes that overhang finite.
 *
 * @public
 */
export function ReplayModule(
  intent: Intent,
  state: State,
  context: PolicyEvaluationContext,
): PolicyResult {
  const agent = intent.agent_id;

  const cfg = state.replay;
  if (!cfg || typeof cfg.window_seconds !== "number" || typeof cfg.max_nonces_per_agent !== "number") {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const now = context.evaluationTime;
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

/** @public */
export const ReplayModuleCodec = statelessModuleCodec("ReplayModule");
