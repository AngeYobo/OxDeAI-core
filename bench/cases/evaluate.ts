import { createFixtureSet } from "../fixtures";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { State } from "@oxdeai/core";

export const name = "evaluate";

function cloneState(state: State): State {
  return {
    ...state,
    budget: {
      budget_limit: { ...state.budget.budget_limit },
      spent_in_period: { ...state.budget.spent_in_period },
    },
    replay: { ...state.replay, nonces: { ...(state.replay.nonces ?? {}) } },
    velocity: { ...state.velocity, counters: { ...(state.velocity.counters ?? {}) } },
    concurrency: {
      ...state.concurrency,
      active: { ...(state.concurrency.active ?? {}) },
      active_auths: { ...(state.concurrency.active_auths ?? {}) },
    },
  };
}

export function create(seed: number): () => unknown {
  const fixtures = createFixtureSet(seed);
  const fx = fixtures.complex;
  const engine = new PolicyEngine({
    policy_version: fx.policy.version,
    engine_secret: "bench-hmac-secret",
    authorization_ttl_seconds: 120,
    authorization_issuer: "bench-issuer",
    authorization_audience: "bench-rp",
    policyId: fx.policy.id,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
  const baseState = cloneState(fx.state);

  return () => {
    const out = engine.evaluatePure(fx.intent, cloneState(baseState), fx.intent.timestamp);
    if (out.decision === "ALLOW") {
      return out.authorization.authorization_id;
    }
    return out.decision;
  };

}
