// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { MODULE_CODECS } from "../policy/modules/registry.js";
import { encodeCanonicalState, decodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import type { Intent, ActionType } from "../types/intent.js";
import type { CanonicalState, State, ToolLimitsState } from "../types/state.js";

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "50");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260303");
const ONLY_SEED = process.env.PBT_ONLY_SEED ? Number(process.env.PBT_ONLY_SEED) : undefined;

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[randInt(rng, 0, values.length - 1)];
}

function shuffle<T>(rng: () => number, input: readonly T[]): T[] {
  const out = [...input];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randInt(rng, 0, i);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function shuffleObjectKeys<T>(rng: () => number, record: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const key of shuffle(rng, Object.keys(record))) {
    out[key] = record[key];
  }
  return out;
}

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v0.6-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 120,
    deny_mode: "fail-fast",
    strictDeterminism: true
  });
}

function randomActionType(rng: () => number): ActionType {
  return pick(rng, ["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"] as const);
}

function genAgents(rng: () => number): string[] {
  const n = randInt(rng, 2, 5);
  const agents = ["agent-1"];
  for (let i = 2; i <= n; i++) agents.push(`agent-${i}`);
  return agents;
}

function genState(seed: number): State {
  const rng = mulberry32(seed);
  const agents = genAgents(rng);

  const budget_limit: Record<string, bigint> = {};
  const spent_in_period: Record<string, bigint> = {};
  const max_amount_per_action: Record<string, bigint> = {};
  const velocityCounters: State["velocity"]["counters"] = {};
  const replayNonces: State["replay"]["nonces"] = {};
  const maxConcurrent: Record<string, number> = {};
  const active: Record<string, number> = {};
  const activeAuths: Record<string, Record<string, { expires_at: number }>> = {};
  const maxDepth: Record<string, number> = {};
  const toolMaxCalls: Record<string, number> = {};
  const toolCalls: NonNullable<ToolLimitsState["calls"]> = {};
  const toolMaxByTool: NonNullable<ToolLimitsState["max_calls_by_tool"]> = {};
  const killAgents: Record<string, boolean> = {};

  for (const agent of agents) {
    const limit = BigInt(randInt(rng, 20_000, 200_000));
    const spent = BigInt(randInt(rng, 0, Number(limit / 4n)));
    budget_limit[agent] = limit;
    spent_in_period[agent] = spent;
    max_amount_per_action[agent] = BigInt(randInt(rng, 500, 5_000));

    const counterCount = randInt(rng, 0, 8);
    if (counterCount > 0) {
      velocityCounters[agent] = {
        window_start: 1_700_000_000 - randInt(rng, 0, 500),
        count: counterCount
      };
    }

    const seenReplay = new Set<string>();
    const replayCount = randInt(rng, 0, 5);
    const entries: Array<{ nonce: string; ts: number }> = [];
    while (entries.length < replayCount) {
      const ts = 1_700_000_000 - randInt(rng, 0, 1000);
      const nonce = String(randInt(rng, 1, 10_000));
      const key = `${ts}:${nonce}`;
      if (seenReplay.has(key)) continue;
      seenReplay.add(key);
      entries.push({ nonce, ts });
    }
    replayNonces[agent] = entries;

    const max = randInt(rng, 1, 5);
    const act = randInt(rng, 0, max);
    maxConcurrent[agent] = max;
    active[agent] = act;
    const auths: Record<string, { expires_at: number }> = {};
    for (let i = 0; i < act; i++) {
      auths[`auth-${agent}-${i}`] = { expires_at: 1_700_000_000 + randInt(rng, 1, 5000) };
    }
    activeAuths[agent] = auths;

    maxDepth[agent] = randInt(rng, 0, 5);

    toolMaxCalls[agent] = randInt(rng, 2, 20);
    const c: Array<{ ts: number; tool?: string }> = [];
    for (let i = 0; i < randInt(rng, 0, 4); i++) {
      c.push({
        ts: 1_700_000_000 - randInt(rng, 0, 400),
        tool: rng() > 0.4 ? pick(rng, ["openai.responses", "stripe.charge", "aws.ec2.runInstances"]) : undefined
      });
    }
    toolCalls[agent] = c;

    toolMaxByTool[agent] = {
      "openai.responses": randInt(rng, 1, toolMaxCalls[agent]),
      "stripe.charge": randInt(rng, 1, toolMaxCalls[agent])
    };

    killAgents[agent] = rng() > 0.92;
  }

  const allowAction: ActionType[] =
    rng() > 0.4 ? shuffle(rng, ["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"] as const) : [];
  const allowAssets = rng() > 0.6 ? shuffle(rng, ["USD", "USDC", "ETH", "BTC", "USD"]) : [];
  const allowTargets = rng() > 0.6 ? shuffle(rng, ["merchant-a", "merchant-b", "merchant-c", "merchant-a"]) : [];

  return {
    policy_version: "v0.6-test",
    period_id: `period-${seed}`,
    kill_switch: {
      global: false,
      agents: killAgents
    },
    allowlists: {
      action_types: allowAction,
      assets: allowAssets,
      targets: allowTargets
    },
    budget: {
      budget_limit,
      spent_in_period
    },
    max_amount_per_action,
    velocity: {
      config: {
        window_seconds: randInt(rng, 10, 120),
        max_actions: randInt(rng, 1, 20)
      },
      counters: velocityCounters
    },
    replay: {
      window_seconds: randInt(rng, 30, 2000),
      max_nonces_per_agent: randInt(rng, 2, 20),
      nonces: replayNonces
    },
    concurrency: {
      max_concurrent: maxConcurrent,
      active,
      active_auths: activeAuths
    },
    recursion: {
      max_depth: maxDepth
    },
    tool_limits: {
      window_seconds: randInt(rng, 10, 600),
      max_calls: toolMaxCalls,
      max_calls_by_tool: toolMaxByTool,
      calls: toolCalls
    }
  };
}

type IntentOp = {
  type: "EXECUTE" | "RELEASE";
  agent_id: string;
  action_type: ActionType;
  amount: bigint;
  target: string;
  asset?: string;
  depth: number;
  tool_call?: boolean;
  tool?: string;
};

function genIntentOps(seed: number, state: State): IntentOp[] {
  const rng = mulberry32(seed ^ 0x9e3779b9);
  const agents = Object.keys(state.budget.budget_limit).sort();
  const ops: IntentOp[] = [];
  const n = randInt(rng, 8, 18);
  for (let i = 0; i < n; i++) {
    const agent = pick(rng, agents);
    const type = rng() > 0.75 ? "RELEASE" : "EXECUTE";
    ops.push({
      type,
      agent_id: agent,
      action_type: randomActionType(rng),
      amount: BigInt(randInt(rng, 1, 250)),
      target: pick(rng, ["merchant-a", "merchant-b", "merchant-c", "merchant-d"]),
      asset: rng() > 0.5 ? pick(rng, ["USD", "USDC", "ETH"]) : undefined,
      depth: randInt(rng, 0, 3),
      tool_call: rng() > 0.45,
      tool: rng() > 0.5 ? pick(rng, ["openai.responses", "stripe.charge", "aws.ec2.runInstances"]) : undefined
    });
  }
  return ops;
}

function buildEquivalentState(seed: number, state: State): State {
  const rng = mulberry32(seed ^ 0x85ebca6b);

  return {
    policy_version: state.policy_version,
    period_id: state.period_id,
    kill_switch: {
      global: state.kill_switch.global,
      agents: shuffleObjectKeys(rng, state.kill_switch.agents)
    },
    allowlists: {
      action_types: state.allowlists.action_types ? shuffle(rng, state.allowlists.action_types) : undefined,
      assets: state.allowlists.assets ? shuffle(rng, state.allowlists.assets) : undefined,
      targets: state.allowlists.targets ? shuffle(rng, state.allowlists.targets) : undefined
    },
    budget: {
      budget_limit: shuffleObjectKeys(rng, state.budget.budget_limit),
      spent_in_period: shuffleObjectKeys(rng, state.budget.spent_in_period)
    },
    max_amount_per_action: shuffleObjectKeys(rng, state.max_amount_per_action),
    velocity: {
      config: { ...state.velocity.config },
      counters: shuffleObjectKeys(rng, state.velocity.counters)
    },
    replay: {
      window_seconds: state.replay.window_seconds,
      max_nonces_per_agent: state.replay.max_nonces_per_agent,
      nonces: Object.fromEntries(
        shuffle(rng, Object.keys(state.replay.nonces)).map((agent) => [agent, shuffle(rng, state.replay.nonces[agent] ?? [])])
      )
    },
    concurrency: {
      max_concurrent: shuffleObjectKeys(rng, state.concurrency.max_concurrent),
      active: shuffleObjectKeys(rng, state.concurrency.active),
      active_auths: Object.fromEntries(
        shuffle(rng, Object.keys(state.concurrency.active_auths)).map((agent) => [
          agent,
          shuffleObjectKeys(rng, state.concurrency.active_auths[agent] ?? {})
        ])
      )
    },
    recursion: {
      max_depth: shuffleObjectKeys(rng, state.recursion.max_depth)
    },
    tool_limits: {
      window_seconds: state.tool_limits!.window_seconds,
      max_calls: shuffleObjectKeys(rng, state.tool_limits!.max_calls),
      max_calls_by_tool: Object.fromEntries(
        shuffle(rng, Object.keys(state.tool_limits!.max_calls_by_tool ?? {})).map((agent) => [
          agent,
          shuffleObjectKeys(rng, state.tool_limits!.max_calls_by_tool?.[agent] ?? {})
        ])
      ),
      calls: Object.fromEntries(
        shuffle(rng, Object.keys(state.tool_limits!.calls)).map((agent) => [
          agent,
          shuffle(rng, state.tool_limits!.calls[agent] ?? [])
        ])
      )
    }
  };
}

function runIntentOps(engine: PolicyEngine, initial: State, ops: IntentOp[], seed: number): {
  decisions: Array<"ALLOW" | "DENY">;
  finalState: State;
} {
  let state = structuredClone(initial);
  const decisions: Array<"ALLOW" | "DENY"> = [];
  const authsByAgent: Record<string, string[]> = {};
  let nonce = 10_000n;

  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    const ts = 1_700_100_000 + i;

    const baseIntent = {
      intent_id: `intent-${seed}-${i}`,
      agent_id: op.agent_id,
      action_type: op.action_type,
      amount: op.amount,
      asset: op.asset,
      target: op.target,
      timestamp: ts,
      metadata_hash: `0x${(seed + i).toString(16).padStart(8, "0")}`,
      nonce,
      signature: "sig",
      depth: op.depth,
      tool_call: op.tool_call,
      tool: op.tool
    };

    let intent: Intent;
    if (op.type === "RELEASE") {
      const queue = authsByAgent[op.agent_id] ?? [];
      const authorization_id = queue.shift();
      if (authorization_id) {
        authsByAgent[op.agent_id] = queue;
        intent = { ...baseIntent, type: "RELEASE", authorization_id };
      } else {
        intent = { ...baseIntent, type: "EXECUTE" };
      }
    } else {
      intent = { ...baseIntent, type: "EXECUTE" };
    }

    nonce += 1n;
    const out = engine.evaluatePure(intent, state, { mode: "fail-fast" });
    decisions.push(out.decision);

    if (out.decision === "ALLOW") {
      state = out.nextState;
      if (intent.type !== "RELEASE") {
        const queue = authsByAgent[intent.agent_id] ?? [];
        queue.push(out.authorization.auth_id);
        authsByAgent[intent.agent_id] = queue;
      }
    }
  }

  return { decisions, finalState: state };
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertThrowsWithSeed(seed: number, fn: () => unknown, detail: string): void {
  assert.throws(fn, `seed=${seed} ${detail}`);
}

function mutateSnapshot(snapshot: CanonicalState): CanonicalState {
  return {
    formatVersion: snapshot.formatVersion,
    engineVersion: snapshot.engineVersion,
    policyId: snapshot.policyId,
    modules: structuredClone(snapshot.modules)
  };
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

test("I1 canonical hashing ignores key insertion order", () => {
  for (const seed of seeds()) {
    const engine = makeEngine();
    const s = genState(seed);
    const s2 = buildEquivalentState(seed, s);

    assert.equal(
      engine.computeStateHash(s),
      engine.computeStateHash(s2),
      `seed=${seed} engine state hash mismatch for equivalent insertion order`
    );

    for (const moduleId of Object.keys(MODULE_CODECS).sort()) {
      const codec = MODULE_CODECS[moduleId];
      assert.equal(
        codec.stateHash(s),
        codec.stateHash(s2),
        `seed=${seed} module=${moduleId} state hash mismatch for equivalent insertion order`
      );
    }
  }
});

test("I2 snapshot roundtrip is idempotent", () => {
  for (const seed of seeds()) {
    const engine = makeEngine();
    const state = genState(seed);
    const baseline = genState(seed + 10_000);

    const originalStateHash = engine.computeStateHash(state);
    const snap1 = engine.exportState(state);
    const bytes1 = encodeCanonicalState(snap1);
    const snap2 = decodeCanonicalState(bytes1);

    const fresh = makeEngine();
    fresh.importState(baseline, snap2);
    const snap3 = fresh.exportState(baseline);
    const bytes3 = encodeCanonicalState(snap3);

    assert.equal(
      sha256(bytes1),
      sha256(bytes3),
      `seed=${seed} encoded snapshot hash mismatch after roundtrip`
    );

    assert.equal(
      originalStateHash,
      fresh.computeStateHash(baseline),
      `seed=${seed} state hash mismatch after snapshot roundtrip`
    );
  }
});

test("I3 decision equivalence across import/export", () => {
  for (const seed of seeds()) {
    const state = genState(seed);
    const ops = genIntentOps(seed, state);

    const liveEngine = makeEngine();
    const live = runIntentOps(liveEngine, state, ops, seed);

    const importedEngine = makeEngine();
    const snap = importedEngine.exportState(state);
    const encoded = encodeCanonicalState(snap);
    const decoded = decodeCanonicalState(encoded);
    const importedStart = genState(seed + 50_000);
    importedEngine.importState(importedStart, decoded);

    const imported = runIntentOps(importedEngine, importedStart, ops, seed);

    assert.deepEqual(
      live.decisions,
      imported.decisions,
      `seed=${seed} decision sequence mismatch after import/export`
    );
    // NOTE: final state hashes are intentionally NOT compared here.
    // Since state_hash now binds to the evaluation-time input state
    // (computeStateHashFor(inputState)), runs starting from different initial
    // states (live=state, imported=importedStart) produce different
    // authorization_ids → different active_auths keys → different final state
    // hashes. Decision equivalence (above) is the correct invariant to check.
  }
});

test("I4 deserializer rejects malformed payloads", () => {
  for (const seed of seeds()) {
    const engine = makeEngine();
    const state = genState(seed);
    const snap = engine.exportState(state);

    assertThrowsWithSeed(
      seed,
      () => decodeCanonicalState(new TextEncoder().encode(JSON.stringify({ ...snap, formatVersion: 2 }))),
      "expected bad formatVersion to throw"
    );

    assertThrowsWithSeed(
      seed,
      () => decodeCanonicalState(new TextEncoder().encode(JSON.stringify({ ...snap, modules: "bad" }))),
      "expected non-object modules to throw"
    );

    assertThrowsWithSeed(
      seed,
      () => decodeCanonicalState(new TextEncoder().encode(JSON.stringify({ ...snap, policyId: 99 }))),
      "expected non-string policyId to throw"
    );

    const replayBad = mutateSnapshot(snap);
    replayBad.modules.ReplayModule = {
      window_seconds: 60,
      max_nonces_per_agent: 10,
      nonces: {
        "agent-1": [
          { nonce: "x", ts: 10 },
          { nonce: "x", ts: 10 }
        ]
      }
    };
    assertThrowsWithSeed(seed, () => makeEngine().importState(genState(seed + 1), replayBad), "expected duplicate replay nonce to throw");

    const budgetBad = mutateSnapshot(snap);
    budgetBad.modules.BudgetModule = {
      budget_limit: { "agent-1": "-10x" },
      spent_in_period: { "agent-1": "1" },
      max_amount_per_action: { "agent-1": "2" }
    };
    assertThrowsWithSeed(seed, () => makeEngine().importState(genState(seed + 2), budgetBad), "expected invalid bigint string to throw");

    const velocityBad = mutateSnapshot(snap);
    velocityBad.modules.VelocityModule = {
      config: { window_seconds: 0, max_actions: 3 },
      counters: { "agent-1": { window_start: 10, count: -1 } }
    };
    assertThrowsWithSeed(seed, () => makeEngine().importState(genState(seed + 3), velocityBad), "expected invalid negative/non-positive velocity values to throw");
  }
});
