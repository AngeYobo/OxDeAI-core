// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyEvaluationContext, PolicyResult } from "../../types/policy.js";
import { isProtocolSeconds } from "../trustedTimeValidation.js";
import { statelessModuleCodec } from "./_codec.js";

/**
 * The resulting `concurrency.active_auths[agent]` map for one evaluation,
 * plus the accounting needed to keep the scalar `active` counter consistent
 * with it.
 *
 * @public
 */
export interface ConcurrencyLeaseTransition {
  /** The agent's lease map after reclamation and, for a valid RELEASE, removal. */
  auths: Record<string, { expires_at: number }>;
  /**
   * Number of entries removed: expired leases, plus the released lease when
   * the intent is a RELEASE naming a live lease.
   */
  removed: number;
  /** True when a RELEASE names a lease that is not live at `evaluationTime`. */
  releaseInvalid: boolean;
}

/**
 * computeConcurrencyLeases - the concurrency lease decision for one evaluation.
 *
 * A lease is expired, and therefore reclaimable, when
 *
 *   evaluationTime >= expires_at
 *
 * This is the same strict zero-tolerance boundary AuthorizationV1 uses: at the
 * exact `expires_at` the lease is no longer live and may be reclaimed.
 *
 * Returns `null` when any of the agent's resident leases carries a malformed
 * `expires_at` (missing, non-finite, non-integer, or negative), so callers fail
 * closed with `STATE_INVALID`. No "maximum plausible TTL" ceiling is applied -
 * clock-regression handling must not depend on an implicit deployment
 * assumption, and no such ceiling is an authoritative policy input today.
 *
 * Only the acting agent's leases are read. Another agent's corrupt entry cannot
 * deny this agent, which keeps one malformed leaf from bricking every agent
 * sharing the state.
 *
 * This is the single definition of the reclamation decision. `PolicyEngine`
 * calls it with the same `(intent, state, evaluationTime)` to materialize
 * `auths` as a replacement assignment, because a module `stateDelta` is
 * deep-merged and so cannot express key removal on its own.
 *
 * @public
 */
export function computeConcurrencyLeases(
  intent: Intent,
  state: State,
  evaluationTime: number
): ConcurrencyLeaseTransition | null {
  const agent = intent.agent_id;
  const resident = state.concurrency?.active_auths?.[agent] ?? {};

  const auths: Record<string, { expires_at: number }> = {};
  let removed = 0;

  for (const authId of Object.keys(resident)) {
    const lease = resident[authId];
    if (!lease || !isProtocolSeconds(lease.expires_at)) return null;

    if (evaluationTime >= lease.expires_at) {
      removed += 1;
      continue;
    }
    auths[authId] = lease;
  }

  if ((intent.type ?? "EXECUTE") !== "RELEASE") {
    return { auths, removed, releaseInvalid: false };
  }

  // A RELEASE naming a lease that is absent - fabricated, already released, or
  // already reclaimed as expired - is a deterministic DENY. Unknown RELEASE
  // operations are deliberately not idempotent: making them so would require a
  // separately authenticated tombstone, or equivalent evidence that the lease
  // once existed, which v1 does not have.
  const authId = intent.authorization_id;
  if (!authId || !auths[authId]) {
    return { auths, removed, releaseInvalid: true };
  }

  const { [authId]: _released, ...rest } = auths;
  return { auths: rest, removed: removed + 1, releaseInvalid: false };
}

/** @public */
export function ConcurrencyModule(
  intent: Intent,
  state: State,
  context: PolicyEvaluationContext
): PolicyResult {
  const agent = intent.agent_id;
  const t = intent.type ?? "EXECUTE";

  const max = state.concurrency?.max_concurrent?.[agent];
  if (max === undefined) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  const active = state.concurrency.active?.[agent] ?? 0;

  const leases = computeConcurrencyLeases(intent, state, context.evaluationTime);
  if (leases === null) return { decision: "DENY", reasons: ["STATE_INVALID"] };

  // Reclaiming N expired leases decrements `active` by exactly N, floored at
  // zero. The counter is decremented rather than recomputed from the map size:
  // a deployment that tracks `active` without populating `active_auths` keeps
  // its existing accounting, so reclamation cannot silently release capacity
  // that was never lease-tracked.
  const activeAfterReclaim = Math.max(0, active - leases.removed);

  // --- RELEASE path ---
  if (t === "RELEASE") {
    if (leases.releaseInvalid) {
      return { decision: "DENY", reasons: ["CONCURRENCY_RELEASE_INVALID"] };
    }

    return {
      decision: "ALLOW",
      reasons: [],
      stateDelta: {
        concurrency: {
          ...state.concurrency,
          active: {
            ...state.concurrency.active,
            [agent]: activeAfterReclaim
          },
          active_auths: {
            ...state.concurrency.active_auths,
            [agent]: leases.auths
          }
        }
      }
    };
  }

  // --- EXECUTE path ---
  // The limit is checked against the post-reclamation count, so leases whose
  // holder never sent a RELEASE stop consuming capacity once they expire.
  if (activeAfterReclaim >= max) {
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
          [agent]: activeAfterReclaim + 1
        },
        active_auths: {
          ...state.concurrency.active_auths,
          [agent]: leases.auths
        }
      }
    }
  };
}

/** @public */
export const ConcurrencyModuleCodec = statelessModuleCodec("ConcurrencyModule");
