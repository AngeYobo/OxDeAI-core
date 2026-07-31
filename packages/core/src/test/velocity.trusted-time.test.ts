// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { VelocityModule } from "../policy/modules/VelocityModule.js";
import type { Intent } from "../types/intent.js";
import type { PolicyResult } from "../types/policy.js";
import type { State } from "../types/state.js";

const AGENT = "agent-velocity";
const T0 = 1_730_000_000;
const WINDOW = 60;

function intentAt(timestamp: number, nonce = 1n): Intent {
  return {
    intent_id: `velocity-${nonce}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    type: "EXECUTE",
    amount: 1n,
    asset: "USDC",
    target: "merchant",
    timestamp,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "sig",
    tool: "pay",
    tool_call: true,
    depth: 0,
  };
}

function velocityState(
  counter?: { window_start: number; count: number },
  config: { window_seconds: number; max_actions: number } = {
    window_seconds: WINDOW,
    max_actions: 1,
  },
): State {
  return {
    velocity: {
      config,
      counters: counter ? { [AGENT]: counter } : {},
    },
  } as unknown as State;
}

function counterFrom(result: PolicyResult): { window_start: number; count: number } {
  assert.equal(result.decision, "ALLOW");
  const counter = result.stateDelta?.velocity?.counters[AGENT];
  assert.ok(counter);
  return counter;
}

function fullState(counter?: { window_start: number; count: number }): State {
  return {
    policy_version: "velocity-trusted-time-v1",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant"] },
    budget: { budget_limit: { [AGENT]: 1_000n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 1_000n },
    velocity: {
      config: { window_seconds: WINDOW, max_actions: 1 },
      counters: counter ? { [AGENT]: counter } : {},
    },
    replay: { window_seconds: 600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: {
      max_concurrent: { [AGENT]: 10 },
      active: {},
      active_auths: {},
    },
    recursion: { max_depth: { [AGENT]: 10 } },
    tool_limits: {
      window_seconds: 600,
      max_calls: { [AGENT]: 100 },
      calls: {},
    },
  };
}

function engine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "velocity-trusted-time-v1",
    engine_secret: "velocity-trusted-time-test-secret-32-bytes",
    maxClockSkewSeconds: 30,
    maxIntentAgeSeconds: 300,
  });
}

test("#192 first window starts at evaluationTime, not a distinct fresh intent.timestamp", () => {
  const intent = intentAt(T0 + 10);
  const result = VelocityModule(intent, velocityState(), { evaluationTime: T0 });
  assert.deepEqual(counterFrom(result), { window_start: T0, count: 1 });
  assert.notEqual(counterFrom(result).window_start, intent.timestamp);
});

test("#192 exhausted active window denies without consuming quota or mutating state", () => {
  const state = velocityState({ window_start: T0, count: 1 });
  const before = structuredClone(state);
  const result = VelocityModule(intentAt(T0 + 10), state, { evaluationTime: T0 });
  assert.deepEqual(result, { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] });
  assert.deepEqual(state, before);
});

for (const [label, evaluationTime, decision] of [
  ["just before", T0 + WINDOW - 1, "DENY"],
  ["at", T0 + WINDOW, "ALLOW"],
  ["just after", T0 + WINDOW + 1, "ALLOW"],
] as const) {
  test(`#192 trusted reset ${label} the exact boundary`, () => {
    const result = VelocityModule(
      intentAt(T0 + 5),
      velocityState({ window_start: T0, count: 1 }),
      { evaluationTime },
    );
    assert.equal(result.decision, decision);
    if (result.decision === "ALLOW") {
      assert.deepEqual(counterFrom(result), { window_start: evaluationTime, count: 1 });
    }
  });
}

test("#192 freshness-valid intent timestamps do not affect velocity decisions or state", () => {
  const timestamps = [T0 - 300, T0, T0 + 30];
  const results = timestamps.map((timestamp) =>
    VelocityModule(
      intentAt(timestamp),
      velocityState({ window_start: T0 - 10, count: 1 }),
      { evaluationTime: T0 },
    ),
  );
  assert.deepEqual(results[1], results[0]);
  assert.deepEqual(results[2], results[0]);
});

test("#192 future dating inside the freshness band cannot reset an exhausted trusted window", () => {
  let state = velocityState();
  const first = VelocityModule(intentAt(T0 - 300, 1n), state, { evaluationTime: T0 });
  assert.equal(first.decision, "ALLOW");
  state = { ...state, ...first.stateDelta };

  for (const [timestamp, nonce] of [[T0, 2n], [T0 + 30, 3n]] as const) {
    const result = VelocityModule(intentAt(timestamp, nonce), state, { evaluationTime: T0 });
    assert.deepEqual(result, { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] });
  }
});

test("#192 only evaluationTime crossing the boundary resets the window", () => {
  const state = velocityState({ window_start: T0, count: 1 });
  const before = VelocityModule(intentAt(T0 + 30), state, { evaluationTime: T0 + WINDOW - 1 });
  const exact = VelocityModule(intentAt(T0 - 30), state, { evaluationTime: T0 + WINDOW });
  const after = VelocityModule(intentAt(T0), state, { evaluationTime: T0 + WINDOW + 1 });
  assert.equal(before.decision, "DENY");
  assert.deepEqual(counterFrom(exact), { window_start: T0 + WINDOW, count: 1 });
  assert.deepEqual(counterFrom(after), { window_start: T0 + WINDOW + 1, count: 1 });
});

test("#192 backward evaluationTime fails closed without state mutation or quota grant", () => {
  const state = velocityState({ window_start: T0, count: 0 });
  const before = structuredClone(state);
  const result = VelocityModule(intentAt(T0), state, { evaluationTime: T0 - 1 });
  assert.deepEqual(result, { decision: "DENY", reasons: ["STATE_INVALID"] });
  assert.deepEqual(state, before);
});

test("#192 malformed velocity counter and configuration matrix fails closed", () => {
  const malformed: State[] = [
    velocityState({ window_start: -1, count: 0 }),
    velocityState({ window_start: 1.5, count: 0 }),
    velocityState({ window_start: NaN, count: 0 }),
    velocityState({ window_start: Infinity, count: 0 }),
    velocityState({ window_start: Number.MAX_SAFE_INTEGER + 1, count: 0 }),
    velocityState({ window_start: T0, count: -1 }),
    velocityState({ window_start: T0, count: 1.5 }),
    velocityState({ window_start: T0, count: NaN }),
    velocityState({ window_start: T0, count: Infinity }),
    velocityState({ window_start: T0, count: Number.MAX_SAFE_INTEGER + 1 }),
    velocityState(undefined, { window_seconds: 0, max_actions: 1 }),
    velocityState(undefined, { window_seconds: -1, max_actions: 1 }),
    velocityState(undefined, { window_seconds: 1.5, max_actions: 1 }),
    velocityState(undefined, { window_seconds: NaN, max_actions: 1 }),
    velocityState(undefined, { window_seconds: Infinity, max_actions: 1 }),
    velocityState(undefined, { window_seconds: Number.MAX_SAFE_INTEGER + 1, max_actions: 1 }),
    velocityState(undefined, { window_seconds: 60, max_actions: -1 }),
    velocityState(undefined, { window_seconds: 60, max_actions: 1.5 }),
    velocityState(undefined, { window_seconds: 60, max_actions: NaN }),
    velocityState(undefined, { window_seconds: 60, max_actions: Infinity }),
    velocityState(undefined, { window_seconds: 60, max_actions: Number.MAX_SAFE_INTEGER + 1 }),
    velocityState(undefined, {
      window_seconds: "60" as unknown as number,
      max_actions: 1,
    }),
    velocityState(undefined, {
      window_seconds: null as unknown as number,
      max_actions: 1,
    }),
    velocityState(undefined, {
      window_seconds: 60,
      max_actions: "1" as unknown as number,
    }),
    velocityState(undefined, {
      window_seconds: 60,
      max_actions: null as unknown as number,
    }),
    velocityState({
      window_start: "1730000000" as unknown as number,
      count: 0,
    }),
    velocityState({
      window_start: T0,
      count: "0" as unknown as number,
    }),
    { velocity: { config: { window_seconds: 60, max_actions: 1 }, counters: { [AGENT]: null } } } as unknown as State,
    { velocity: { config: { window_seconds: 60, max_actions: 1 } } } as unknown as State,
  ];

  for (const state of malformed) {
    const result = VelocityModule(intentAt(T0), state, { evaluationTime: T0 });
    assert.deepEqual(result, { decision: "DENY", reasons: ["STATE_INVALID"] });
  }
});

test("#192 freshness denial occurs before velocity and leaves caller state unchanged", () => {
  const state = fullState();
  const before = structuredClone(state);
  const result = engine().evaluatePure(intentAt(T0 + 31), state, T0);
  assert.deepEqual(result, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
  assert.deepEqual(state, before);
  assert.deepEqual(state.velocity.counters, {});
});

test("#192 identical inputs are deterministic and caller intent/state remain immutable", () => {
  const intent = intentAt(T0 - 10);
  const state = velocityState({ window_start: T0 - 20, count: 0 });
  const intentBefore = structuredClone(intent);
  const stateBefore = structuredClone(state);
  const first = VelocityModule(intent, state, { evaluationTime: T0 });
  const second = VelocityModule(intent, state, { evaluationTime: T0 });
  assert.deepEqual(first, second);
  assert.deepEqual(intent, intentBefore);
  assert.deepEqual(state, stateBefore);
});

test("#192 property: freshness-valid intent timestamps are velocity-noninterfering", () => {
  fc.assert(fc.property(
    fc.integer({ min: T0 - 300, max: T0 + 30 }),
    fc.integer({ min: T0 - 300, max: T0 + 30 }),
    (t1, t2) => {
      const state = velocityState({ window_start: T0 - 10, count: 0 }, {
        window_seconds: WINDOW,
        max_actions: 3,
      });
      assert.deepEqual(
        VelocityModule(intentAt(t1), state, { evaluationTime: T0 }),
        VelocityModule(intentAt(t2), state, { evaluationTime: T0 }),
      );
    },
  ));
});

test("#192 property: no intent timestamp can prematurely reset an exhausted active window", () => {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 3_600 }),
    fc.integer({ min: 0, max: 30 }),
    (windowSeconds, elapsed) => {
      fc.pre(elapsed < windowSeconds);
      const state = velocityState({ window_start: T0, count: 1 }, {
        window_seconds: windowSeconds,
        max_actions: 1,
      });
      const result = VelocityModule(intentAt(T0 + 30), state, { evaluationTime: T0 + elapsed });
      assert.deepEqual(result, { decision: "DENY", reasons: ["VELOCITY_EXCEEDED"] });
    },
  ));
});

test("#192 property: trusted resets use evaluationTime and window starts progress monotonically", () => {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 3_600 }),
    fc.integer({ min: 0, max: 30 }),
    (windowSeconds, extra) => {
      const evaluationTime = T0 + windowSeconds + extra;
      const result = VelocityModule(
        intentAt(T0 - 30),
        velocityState({ window_start: T0, count: 1 }, {
          window_seconds: windowSeconds,
          max_actions: 1,
        }),
        { evaluationTime },
      );
      assert.deepEqual(counterFrom(result), { window_start: evaluationTime, count: 1 });
      assert.ok(counterFrom(result).window_start >= T0);
    },
  ));
});

test("#192 active window denies at MAX_SAFE_INTEGER without unsafe increment", () => {
  const state = velocityState(
    {
      window_start: T0,
      count: Number.MAX_SAFE_INTEGER,
    },
    {
      window_seconds: WINDOW,
      max_actions: Number.MAX_SAFE_INTEGER,
    },
  );

  const before = structuredClone(state);
  const result = VelocityModule(intentAt(T0), state, { evaluationTime: T0 });

  assert.deepEqual(result, {
    decision: "DENY",
    reasons: ["VELOCITY_EXCEEDED"],
  });
  assert.deepEqual(state, before);
});
