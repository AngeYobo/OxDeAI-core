import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

/**
 * Fuzz configuration
 * Default: 300
 * Override: FUZZ_ITERS=2000 pnpm test
 */
const DEFAULT_ITERS = 300;
const MAX_ITERS = 50_000;

function getIterations(): number {
  const raw = process.env.FUZZ_ITERS;
  if (!raw) return DEFAULT_ITERS;

  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_ITERS;

  return Math.min(Math.floor(n), MAX_ITERS);
}

const ITERS = getIterations();

if (!process.env.__FUZZ_LOGGED) {
  process.env.__FUZZ_LOGGED = "1";
  console.log(`[fuzz] FUZZ_ITERS=`);
}

// Deterministic PRNG (LCG)
function lcg(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (1664525 * s + 1013904223) >>> 0;
    return s;
  };
}

function randInt(r: () => number, min: number, max: number): number {
  const x = r();
  return min + (x % (max - min + 1));
}

test(`FUZZ(${ITERS}): budget & per-action cap consistency`, () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "fuzz-secret",
    authorization_ttl_seconds: 60
  });

  const r = lcg(0xC0FFEE);
  const now = 1_000_000;

  for (let i = 0; i < ITERS; i++) {
    const limit = BigInt(randInt(r, 1, 50)) * 1_000_000n;
    const spent = BigInt(randInt(r, 0, 50)) * 1_000_000n;
    const cap = BigInt(randInt(r, 1, 50)) * 1_000_000n;
    const amount = BigInt(randInt(r, 0, 60)) * 1_000_000n;

    const intent: Intent = {
      intent_id: `i-${i}`,
      agent_id: "agent-A",
      action_type: "PAYMENT",
      amount,
      asset: "USDC",
      target: "merchant",
      timestamp: now,
      metadata_hash: "0x" + "0".repeat(64),
      nonce: BigInt(i + 1),
      signature: "sig"
    };

    const state: State = {
      policy_version: "0.1.0",
      period_id: "p1",
      kill_switch: { global: false, agents: {} },
      allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
      budget: { budget_limit: { "agent-A": limit }, spent_in_period: { "agent-A": spent } },
      max_amount_per_action: { "agent-A": cap },
      velocity: { config: { window_seconds: 60, max_actions: 1000 }, counters: {} }
    };

    const out = engine.evaluate(intent, state);

    const capViolated = amount > cap;
    const budgetViolated = spent + amount > limit;

    if (capViolated) {
      assert.equal(out.decision, "DENY", `cap violation i=${i}`);
      assert.ok(out.reasons.includes("PER_ACTION_CAP_EXCEEDED"));
    } else if (budgetViolated) {
      assert.equal(out.decision, "DENY", `budget violation i=${i}`);
      assert.ok(out.reasons.includes("BUDGET_EXCEEDED"));
    }
  }
});

test(`FUZZ(${ITERS}): velocity window edge cases`, () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "fuzz-secret-2",
    authorization_ttl_seconds: 60
  });

  const r = lcg(0xBADC0DE);
  const window = 60;

  for (let i = 0; i < ITERS; i++) {
    const maxActions = randInt(r, 1, 10);
    const count = randInt(r, 0, 12);

    const windowStart = 10_000;
    const insideTs = windowStart + randInt(r, 0, window - 1);
    const boundaryTs = windowStart + window;

    const mkState = (ts: number): State => ({
      policy_version: "0.1.0",
      period_id: "p1",
      kill_switch: { global: false, agents: {} },
      allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
      budget: { budget_limit: { "agent-A": 1_000_000_000n }, spent_in_period: { "agent-A": 0n } },
      max_amount_per_action: { "agent-A": 1_000_000_000n },
      velocity: {
        config: { window_seconds: window, max_actions: maxActions },
        counters: { "agent-A": { window_start: windowStart, count } }
      }
    });

    const mkIntent = (nonce: bigint, ts: number): Intent => ({
      intent_id: `v-${i}-${ts}`,
      agent_id: "agent-A",
      action_type: "PAYMENT",
      amount: 1_000_000n,
      asset: "USDC",
      target: "merchant",
      timestamp: ts,
      metadata_hash: "0x" + "0".repeat(64),
      nonce,
      signature: "sig"
    });

    // Inside window
    {
      const state = mkState(insideTs);
      const out = engine.evaluate(mkIntent(BigInt(10_000 + i), insideTs), state);
      const shouldDeny = count + 1 > maxActions;

      if (shouldDeny) {
        assert.equal(out.decision, "DENY", `velocity violation i=${i}`);
        assert.ok(out.reasons.includes("VELOCITY_EXCEEDED"));
      }
    }

    // Boundary reset
    {
      const state = mkState(boundaryTs);
      const out = engine.evaluate(mkIntent(BigInt(20_000 + i), boundaryTs), state);
      assert.equal(out.decision, "ALLOW", `boundary reset failed i=${i}`);
    }
  }
});
