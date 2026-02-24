import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State, ActionType } from "@oxdeai/core";

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

// Deterministic PRNG (LCG)
function lcg(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (1664525 * s + 1013904223) >>> 0;
    return s;
  };
}
function randInt(r: () => number, min: number, max: number): number {
  return min + (r() % (max - min + 1));
}
function pick<T>(r: () => number, arr: readonly T[]): T {
  return arr[randInt(r, 0, arr.length - 1)];
}

/**
 * SPEC PREDICATES (evaluated on PRE-STATE)
 */
function predicatesHold(intent: Intent, state: State): { ok: boolean; failures: string[] } {
  const failures: string[] = [];
  const agent = intent.agent_id;

  const al = state.allowlists;
  if (!al || !al.action_types || !al.assets || !al.targets) {
    return { ok: false, failures: ["P-STATE: malformed allowlists"] };
  }

  // P-KILL
  if (state.kill_switch.global === true) failures.push("P-KILL global");
  if (state.kill_switch.agents[agent] === true) failures.push("P-KILL agent");

  // P-ALLOWLIST
  if (!al.action_types.includes(intent.action_type)) failures.push("P-ALLOWLIST action_type");
  if (intent.asset && !al.assets.includes(intent.asset)) failures.push("P-ALLOWLIST asset");
  if (!al.targets.includes(intent.target)) failures.push("P-ALLOWLIST target");

  // P-CAP
  const cap = state.max_amount_per_action[agent];
  if (cap === undefined) failures.push("P-STATE missing cap");
  else if (intent.amount > cap) failures.push("P-CAP");

  // P-BUDGET (pre-state)
  const limit = state.budget.budget_limit[agent];
  const spent = state.budget.spent_in_period[agent] ?? 0n;
  if (limit === undefined) failures.push("P-STATE missing budget");
  else if (spent + intent.amount > limit) failures.push("P-BUDGET");

  // P-VELOCITY (pre-state)
  const cfg = state.velocity.config;
  const c = state.velocity.counters[agent];
  if (c) {
    const inWindow = intent.timestamp < c.window_start + cfg.window_seconds;
    if (inWindow && c.count + 1 > cfg.max_actions) failures.push("P-VELOCITY");
  }

  return { ok: failures.length === 0, failures };
}

test(`META(${ITERS}): ALLOW implies predicates hold (on pre-state)`, () => {
  const engine = new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "meta-secret",
    authorization_ttl_seconds: 60
  });

  const r = lcg(0xA110FFEE);
  const window = 60;

  const ACTIONS: readonly ActionType[] = ["PAYMENT"];
  const ASSETS = ["USDC", "ETH"] as const;
  const TARGETS = ["merchant", "svc:cloud", "svc:gpu"] as const;

  for (let i = 0; i < ITERS; i++) {
    const now = 10_000 + randInt(r, 0, 10_000);

    const limit = BigInt(randInt(r, 1, 100)) * 1_000_000n;
    const spent = BigInt(randInt(r, 0, 100)) * 1_000_000n;
    const cap = BigInt(randInt(r, 1, 100)) * 1_000_000n;
    const amount = BigInt(randInt(r, 0, 120)) * 1_000_000n;

    const maxActions = randInt(r, 1, 10);
    const count = randInt(r, 0, 12);

    const windowStart = now - randInt(r, 0, 2 * window);
    const hasCounter = randInt(r, 0, 1) === 1;

    const intent: Intent = {
      intent_id: `meta-${i}`,
      agent_id: "agent-A",
      action_type: pick(r, ACTIONS),
      amount,
      asset: pick(r, ASSETS),
      target: pick(r, TARGETS),
      timestamp: now,
      metadata_hash: "0x" + "0".repeat(64),
      nonce: BigInt(2_000_000 + i), // avoid replay in this test
      signature: "sig"
    };

    const state: State = {
      policy_version: "0.1.0",
      period_id: "p1",
      kill_switch: { global: false, agents: {} },
      allowlists: {
        action_types: ["PAYMENT"],
        assets: ["USDC", "ETH"],
        targets: ["merchant", "svc:cloud", "svc:gpu"]
      },
      budget: {
        budget_limit: { "agent-A": limit },
        spent_in_period: { "agent-A": spent }
      },
      max_amount_per_action: { "agent-A": cap },
      velocity: {
        config: { window_seconds: window, max_actions: maxActions },
        counters: hasCounter ? { "agent-A": { window_start: windowStart, count } } : {}
      }
    };

    // Snapshot PRE-STATE because engine.evaluate mutates state
    const preState: State = structuredClone(state);

    const out = engine.evaluate(intent, state);

    if (out.decision === "ALLOW") {
      const chk = predicatesHold(intent, preState);
      assert.equal(chk.ok, true, `ALLOW violated spec (pre-state): ${chk.failures.join(" | ")}`);
    }
  }
});
