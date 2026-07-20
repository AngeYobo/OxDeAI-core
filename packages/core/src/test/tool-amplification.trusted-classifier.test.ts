// SPDX-License-Identifier: Apache-2.0
/**
 * Regression coverage for the trusted tool-call classifier
 * (isRateLimitedToolCall in ToolAmplificationModule.ts).
 *
 * Prior to this fix, ToolAmplificationModule gated entirely on the
 * self-declared, agent-controlled `intent.tool_call` boolean: an agent could
 * omit or falsify it to bypass the tool-call limit while requesting the same
 * executable action. Classification is now derived from the EXECUTE
 * discriminator plus policy-controlled `state.tool_limits`, resolved via
 * `intent.tool` used only as a lookup key. `intent.tool_call` must not
 * influence the outcome at all.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";

const AGENT = "agent-1";
const TOOL = "search";
const BASE_TS = 1_800_000_000;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-test",
    engine_secret: "x".repeat(32),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(overrides?: (s: State) => void): State {
  const s: State = {
    policy_version: "v1-test",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["wallet", "tool"], targets: ["user_1", "tool_1"] },
    budget: { budget_limit: { [AGENT]: 1_000_000_000n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 1_000_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 1000 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 1000 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 1 }, calls: {} },
  };
  overrides?.(s);
  return s;
}

function makeIntent(overrides?: Partial<Intent>): Intent {
  return {
    intent_id: `intent-${Math.random().toString(16).slice(2)}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    amount: 100n,
    asset: "wallet",
    target: "user_1",
    timestamp: BASE_TS,
    metadata_hash: "00",
    nonce: 1n,
    signature: "placeholder",
    depth: 0,
    ...overrides,
  } as Intent;
}

// 1-3: same tool, same limit, each self-declared tool_call variant must be
// enforced identically (first ALLOW, second DENY with TOOL_CALL_LIMIT_EXCEEDED).
for (const [label, tool_call] of [
  ["true", true],
  ["false", false],
  ["omitted", undefined],
] as const) {
  test(`tool-call limit enforced identically when tool_call is ${label}`, () => {
    const engine = makeEngine();
    let state = makeState();

    const first = engine.evaluatePure(
      makeIntent({ tool: TOOL, tool_call, nonce: 1n, timestamp: BASE_TS }),
      state,
      BASE_TS,
    );
    assert.equal(first.decision, "ALLOW");
    assert.ok(first.decision === "ALLOW" && first.nextState);
    state = (first as Extract<typeof first, { decision: "ALLOW" }>).nextState;

    const second = engine.evaluatePure(
      makeIntent({ tool: TOOL, tool_call, nonce: 2n, timestamp: BASE_TS }),
      state,
      BASE_TS,
    );
    assert.equal(second.decision, "DENY");
    assert.deepEqual(second.reasons, ["TOOL_CALL_LIMIT_EXCEEDED"]);
  });
}

// 4: mixed sequence must consume ONE shared budget — not per-variant fixtures.
test("mixed tool_call sequence (omitted -> false -> true) shares one budget", () => {
  const engine = makeEngine();
  let state = makeState();

  const omitted = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 10n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(omitted.decision, "ALLOW");
  assert.ok(omitted.decision === "ALLOW");
  state = omitted.nextState;

  const declaredFalse = engine.evaluatePure(
    makeIntent({ tool: TOOL, tool_call: false, nonce: 11n, timestamp: BASE_TS }),
    state,
    BASE_TS,
  );
  assert.equal(declaredFalse.decision, "DENY");
  assert.deepEqual(declaredFalse.reasons, ["TOOL_CALL_LIMIT_EXCEEDED"]);

  const declaredTrue = engine.evaluatePure(
    makeIntent({ tool: TOOL, tool_call: true, nonce: 12n, timestamp: BASE_TS }),
    state,
    BASE_TS,
  );
  assert.equal(declaredTrue.decision, "DENY");
  assert.deepEqual(declaredTrue.reasons, ["TOOL_CALL_LIMIT_EXCEEDED"]);
});

// 5: exact configured limit boundary.
test("exact configured limit boundary: N ALLOW then DENY on N+1", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 3;
  });

  const outcomes: string[] = [];
  for (let i = 0; i < 4; i++) {
    const out = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: BigInt(20 + i), timestamp: BASE_TS }), state, BASE_TS);
    outcomes.push(out.decision);
    if (out.decision === "ALLOW") state = out.nextState;
  }
  assert.deepEqual(outcomes, ["ALLOW", "ALLOW", "ALLOW", "DENY"]);
});

// 6: non-tool action (no `tool` field) is never charged against the tool budget.
test("non-tool action is not charged against the tool-call budget", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1;
  });

  for (let i = 0; i < 5; i++) {
    const out = engine.evaluatePure(makeIntent({ nonce: BigInt(30 + i), timestamp: BASE_TS }), state, BASE_TS);
    assert.equal(out.decision, "ALLOW", `call ${i} should not be tool-limited`);
    state = out.nextState;
  }
  assert.deepEqual(state.tool_limits.calls[AGENT] ?? [], []);
});

// 7: configured tool (explicit per-tool cap) vs unconfigured tool (no
// per-tool entry, falls back to the agent's aggregate cap). `max_calls[agent]`
// is a mandatory per-agent leaf (validateNumericLeaves) so every EXECUTE
// intent naming a tool is still subject to *some* enforcement; the per-tool
// registry only tightens the threshold for tools it explicitly names.
test("configured tool gets its explicit per-tool cap; unconfigured tool falls back to the aggregate cap", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 100;
    s.tool_limits.max_calls_by_tool = { [AGENT]: { [TOOL]: 1 } };
  });

  const firstConfigured = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 40n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(firstConfigured.decision, "ALLOW");
  assert.ok(firstConfigured.decision === "ALLOW");
  state = firstConfigured.nextState;

  const secondConfigured = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 41n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(secondConfigured.decision, "DENY", "per-tool cap of 1 should already be exhausted");
  assert.deepEqual(secondConfigured.reasons, ["TOOL_CALL_LIMIT_EXCEEDED"]);

  const unconfiguredTool = engine.evaluatePure(
    makeIntent({ tool: "unlisted_tool", nonce: 42n, timestamp: BASE_TS }),
    state,
    BASE_TS,
  );
  assert.equal(unconfiguredTool.decision, "ALLOW", "no per-tool cap for this name, aggregate cap (100) not yet reached");
});

test("agent with a configured tool cap has calls enforced regardless of tool_call", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1;
  });

  const first = engine.evaluatePure(makeIntent({ tool: TOOL, tool_call: false, nonce: 41n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(first.decision, "ALLOW");
  assert.ok(first.decision === "ALLOW");
  state = first.nextState;

  const second = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 42n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(second.decision, "DENY");
  assert.deepEqual(second.reasons, ["TOOL_CALL_LIMIT_EXCEEDED"]);
});

// 8: malformed/ambiguous tool identifiers fail closed or are safely excluded.
test("empty-string tool is not classified as a tool call (excluded, not charged)", () => {
  const engine = makeEngine();
  const state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1;
  });

  const out = engine.evaluatePure(makeIntent({ tool: "", tool_call: true, nonce: 50n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(out.decision, "ALLOW");
});

test("classified tool call with malformed tool_limits state fails closed", () => {
  const engine = makeEngine();
  const state = makeState((s) => {
    // Classification resolves true (max_calls[AGENT] configured), but the
    // enforcement data itself is malformed -> must fail closed.
    (s.tool_limits as unknown as { window_seconds: unknown }).window_seconds = "not-a-number";
  });

  const out = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 51n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

// 9: window reset keyed off intent.timestamp (pre-existing window semantics,
// unchanged by this fix), with evaluationTime kept consistent to stay fresh.
test("tool-call window resets once elapsed time exceeds window_seconds", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.window_seconds = 60;
    s.tool_limits.max_calls[AGENT] = 1;
  });

  const first = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 60n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(first.decision, "ALLOW");
  assert.ok(first.decision === "ALLOW");
  state = first.nextState;

  const withinWindow = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 61n, timestamp: BASE_TS + 30 }), state, BASE_TS + 30);
  assert.equal(withinWindow.decision, "DENY");

  const afterWindow = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 62n, timestamp: BASE_TS + 61 }), state, BASE_TS + 61);
  assert.equal(afterWindow.decision, "ALLOW");
});

// 10: deterministic repeated evaluation.
test("classification and decision are deterministic for identical inputs", () => {
  const state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1;
  });
  const intent = makeIntent({ tool: TOOL, nonce: 70n, timestamp: BASE_TS });

  const out1 = makeEngine().evaluatePure(intent, state, BASE_TS);
  const out2 = makeEngine().evaluatePure(intent, state, BASE_TS);

  assert.equal(out1.decision, out2.decision);
  assert.deepEqual(out1.reasons, out2.reasons);
});

// 11: audit reason-code consistency — the audit trail reflects the trusted
// classification outcome, not the agent's tool_call claim.
test("audit trail records TOOL_CALL_LIMIT_EXCEEDED without referencing tool_call", () => {
  const engine = makeEngine();
  let state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1;
  });

  const first = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 80n, timestamp: BASE_TS }), state, BASE_TS);
  assert.ok(first.decision === "ALLOW");
  state = first.nextState;

  const second = engine.evaluatePure(makeIntent({ tool: TOOL, tool_call: false, nonce: 81n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(second.decision, "DENY");

  const events = engine.audit.snapshot() as Array<{ type: string; reasons?: string[] }>;
  const denyEvents = events.filter((e) => e.reasons?.includes("TOOL_CALL_LIMIT_EXCEEDED"));
  assert.ok(denyEvents.length > 0, "expected an audit event carrying TOOL_CALL_LIMIT_EXCEEDED");
});

// 12: replay and velocity still run in their existing order/precedence,
// unaffected by tool-call classification.
test("replay detection still precedes tool-limit accounting for tool intents", () => {
  const engine = makeEngine();
  const state = makeState((s) => {
    s.tool_limits.max_calls[AGENT] = 1000;
  });

  const intent = makeIntent({ tool: TOOL, nonce: 90n, timestamp: BASE_TS });
  const first = engine.evaluatePure(intent, state, BASE_TS);
  assert.equal(first.decision, "ALLOW");
  assert.ok(first.decision === "ALLOW");

  const replay = engine.evaluatePure(intent, first.nextState, BASE_TS);
  assert.equal(replay.decision, "DENY");
  assert.ok(
    replay.reasons.includes("REPLAY_NONCE") || replay.reasons.includes("REPLAY_DETECTED"),
    `expected a replay reason, got ${JSON.stringify(replay.reasons)}`,
  );
});

test("velocity limit still enforced independently of tool-call classification", () => {
  const engine = makeEngine();
  const state = makeState((s) => {
    s.velocity.config.max_actions = 1;
    s.tool_limits.max_calls[AGENT] = 1000;
  });

  const first = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 91n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(first.decision, "ALLOW");
  assert.ok(first.decision === "ALLOW");

  const second = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 92n, timestamp: BASE_TS }), first.nextState, BASE_TS);
  assert.equal(second.decision, "DENY");
  assert.deepEqual(second.reasons, ["VELOCITY_EXCEEDED"]);
});

test("kill-switch still fail-fasts before tool-limit accounting runs", () => {
  const engine = makeEngine();
  const state = makeState((s) => {
    s.kill_switch.agents[AGENT] = true;
    s.tool_limits.max_calls[AGENT] = 1000;
  });

  const out = engine.evaluatePure(makeIntent({ tool: TOOL, nonce: 93n, timestamp: BASE_TS }), state, BASE_TS);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["KILL_SWITCH"]);
});
