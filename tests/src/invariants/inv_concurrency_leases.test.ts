import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { State } from "@oxdeai/core";
import { makeIntent } from "../helpers/intent.js";
import { makeState } from "../helpers/state.js";

const T0 = 1_700_000_000;
const TTL = 60;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function baseState(maxConcurrent: number): State {
  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });
  state.concurrency = {
    max_concurrent: { "agent-1": maxConcurrent },
    active: {},
    active_auths: {}
  };
  return state;
}

function execIntent(nonce: bigint, timestamp: number) {
  return makeIntent({
    intent_id: `intent-${nonce}`,
    nonce,
    amount: 1_000n,
    asset: "USDC",
    target: "merchant",
    timestamp
  });
}

function leases(state: State): Record<string, { expires_at: number }> {
  return state.concurrency.active_auths["agent-1"] ?? {};
}

/**
 * INV-ConcurrencyLeases (oxdeai/oxdeai#227)
 *
 * After any successful transition, no lease that has been released or reclaimed
 * may remain resident in `concurrency.active_auths`, and the scalar `active`
 * counter must not contradict the resulting map.
 *
 * This is the invariant the reclamation change exists to establish: before it,
 * a module `stateDelta` could not express key removal, so entries accumulated
 * on both the RELEASE path and the expiry path.
 */
test("INV-ConcurrencyLeases: successful transitions leave no released or reclaimed lease resident", () => {
  const engine = makeEngine();
  let state = baseState(4);

  // Drive a mixed sequence of EXECUTE and RELEASE across advancing time, so
  // both removal paths — explicit release and expiry-driven reclamation — are
  // exercised against the same accumulating state.
  const issued: Array<{ authId: string; expires_at: number }> = [];
  let nonce = 1n;

  for (let step = 0; step < 3; step++) {
    const at = T0 + step * 10;
    const out = engine.evaluatePure(execIntent(nonce++, at), state, at);
    assert.equal(out.decision, "ALLOW", `EXECUTE ${step} must ALLOW`);
    if (out.decision !== "ALLOW") throw new Error("expected ALLOW");
    state = out.nextState;
    issued.push({ authId: out.authorization.auth_id, expires_at: out.authorization.expiry });
  }

  // Release the first lease explicitly, well before it expires.
  const releasedId = issued[0].authId;
  const releaseAt = T0 + 30;
  const released = engine.evaluatePure(
    { ...execIntent(nonce++, releaseAt), type: "RELEASE", authorization_id: releasedId },
    state,
    releaseAt
  );
  assert.equal(released.decision, "ALLOW", "RELEASE of a live lease must ALLOW");
  if (released.decision !== "ALLOW") throw new Error("expected ALLOW");
  state = released.nextState;

  assert.ok(
    !(releasedId in leases(state)),
    "a released lease must not remain resident after a successful transition"
  );
  assert.equal(
    state.concurrency.active["agent-1"],
    Object.keys(leases(state)).length,
    "active must agree with the resulting lease map"
  );

  // Advance past every remaining lease's expiry and drive one more successful
  // transition. Everything issued above is now reclaimable.
  const afterAll = Math.max(...issued.map((i) => i.expires_at));
  const final = engine.evaluatePure(execIntent(nonce++, afterAll), state, afterAll);
  assert.equal(final.decision, "ALLOW", "capacity must be available once leases expire");
  if (final.decision !== "ALLOW") throw new Error("expected ALLOW");
  state = final.nextState;

  const resident = leases(state);
  for (const { authId } of issued) {
    assert.ok(
      !(authId in resident),
      `reclaimed lease ${authId.slice(0, 8)}… must not remain resident`
    );
  }
  assert.deepEqual(
    Object.keys(resident),
    [final.authorization.auth_id],
    "only the lease issued by the final transition may remain"
  );
  assert.equal(
    state.concurrency.active["agent-1"],
    Object.keys(resident).length,
    "active must agree with the resulting lease map"
  );
});

/**
 * The limit must be enforced against live leases only. An agent saturated
 * purely by leases nobody released regains capacity at expiry, and an agent
 * saturated by live leases does not.
 */
test("INV-ConcurrencyLeases: expired leases stop consuming capacity, live ones do not", () => {
  const engine = makeEngine();
  let state = baseState(1);

  const first = engine.evaluatePure(execIntent(1n, T0), state, T0);
  assert.equal(first.decision, "ALLOW");
  if (first.decision !== "ALLOW") throw new Error("expected ALLOW");
  state = first.nextState;

  // Still live: the single slot is genuinely occupied.
  const blocked = engine.evaluatePure(execIntent(2n, T0 + 1), state, T0 + 1);
  assert.equal(blocked.decision, "DENY", "a live lease must still occupy the slot");
  assert.ok(blocked.decision === "DENY" && blocked.reasons.includes("CONCURRENCY_LIMIT_EXCEEDED"));

  // At exactly expires_at the lease is no longer live and the slot returns.
  const atExpiry = first.authorization.expiry;
  const recovered = engine.evaluatePure(execIntent(3n, atExpiry), state, atExpiry);
  assert.equal(recovered.decision, "ALLOW", "at expires_at the slot must be reclaimable");
  if (recovered.decision !== "ALLOW") throw new Error("expected ALLOW");

  assert.deepEqual(
    Object.keys(leases(recovered.nextState)),
    [recovered.authorization.auth_id],
    "the abandoned lease must be gone, replaced by the newly issued one"
  );
  assert.equal(recovered.nextState.concurrency.active["agent-1"], 1);
});
