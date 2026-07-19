// SPDX-License-Identifier: Apache-2.0
// packages/core/src/test/property.decision.test.ts
//
// Property-based invariants for the PolicyEngine decision path.
//
// Invariants:
//   D-1  evaluatePure is deterministic for equivalent inputs
//   D-2  evaluatePure does not mutate the input state
//   D-3  evaluatePure is stable across structuredClone variants
//   D-4  Key-order insensitivity propagates to decisions, not only hashes
//   D-6  strictDeterminism enforces explicit inputs and stays stable
//
// D-5 (cross-process decision determinism) lives in cross_process.test.ts.
//
// Seed control:
//   PBT_CASES  number of seeds to run (default 50)
//   PBT_SEED   override base seed      (default 20260303)
//   PBT_ONLY_SEED  run exactly one seed (for focused repro)

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { Intent, ActionType } from "../types/intent.js";
import type { State, ToolLimitsState } from "../types/state.js";
import type { Authorization } from "../types/authorization.js";

const DEFAULT_CASES = Number(process.env["PBT_CASES"] ?? "50");
const BASE_SEED = Number(process.env["PBT_SEED"] ?? "20260303");
const ONLY_SEED = process.env["PBT_ONLY_SEED"] ? Number(process.env["PBT_ONLY_SEED"]) : undefined;

// ── PRNG (mulberry32, identical to property.test.ts) ──────────────────────

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

// ── Engine factory ────────────────────────────────────────────────────────

const POLICY_VERSION = "v0.6-test";

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY_VERSION,
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 120,
    deny_mode: "fail-fast",
    strictDeterminism: true,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── State generator (mirrors property.test.ts genState exactly) ──────────

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
    policy_version: POLICY_VERSION,
    period_id: `period-${seed}`,
    kill_switch: { global: false, agents: killAgents },
    allowlists: { action_types: allowAction, assets: allowAssets, targets: allowTargets },
    budget: { budget_limit, spent_in_period },
    max_amount_per_action,
    velocity: {
      config: { window_seconds: randInt(rng, 10, 120), max_actions: randInt(rng, 1, 20) },
      counters: velocityCounters
    },
    replay: {
      window_seconds: randInt(rng, 30, 2000),
      max_nonces_per_agent: randInt(rng, 2, 20),
      nonces: replayNonces
    },
    concurrency: { max_concurrent: maxConcurrent, active, active_auths: activeAuths },
    recursion: { max_depth: maxDepth },
    tool_limits: {
      window_seconds: randInt(rng, 10, 600),
      max_calls: toolMaxCalls,
      max_calls_by_tool: toolMaxByTool,
      calls: toolCalls
    }
  };
}

// ── Intent op types and generators ───────────────────────────────────────

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
      action_type: pick(rng, ["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"] as const),
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

// Build a concrete Intent from an IntentOp (always EXECUTE; RELEASE needs auth context).
function buildExecIntent(op: IntentOp, seed: number, idx: number, nonce: bigint): Intent {
  return {
    intent_id: `intent-${seed}-${idx}`,
    agent_id: op.agent_id,
    action_type: op.action_type,
    amount: op.amount,
    asset: op.asset,
    target: op.target,
    timestamp: 1_700_100_000 + idx,
    metadata_hash: `0x${(seed + idx).toString(16).padStart(8, "0")}`,
    nonce,
    signature: "sig",
    depth: op.depth,
    tool_call: op.tool_call,
    tool: op.tool,
    type: "EXECUTE"
  } as Intent;
}

// Build equivalent state with shuffled object-key insertion order.
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
        shuffle(rng, Object.keys(state.replay.nonces)).map((a) => [
          a,
          shuffle(rng, state.replay.nonces[a] ?? [])
        ])
      )
    },
    concurrency: {
      max_concurrent: shuffleObjectKeys(rng, state.concurrency.max_concurrent),
      active: shuffleObjectKeys(rng, state.concurrency.active),
      active_auths: Object.fromEntries(
        shuffle(rng, Object.keys(state.concurrency.active_auths)).map((a) => [
          a,
          shuffleObjectKeys(rng, state.concurrency.active_auths[a] ?? {})
        ])
      )
    },
    recursion: { max_depth: shuffleObjectKeys(rng, state.recursion.max_depth) },
    tool_limits: {
      window_seconds: state.tool_limits!.window_seconds,
      max_calls: shuffleObjectKeys(rng, state.tool_limits!.max_calls),
      max_calls_by_tool: Object.fromEntries(
        shuffle(rng, Object.keys(state.tool_limits!.max_calls_by_tool ?? {})).map((a) => [
          a,
          shuffleObjectKeys(rng, state.tool_limits!.max_calls_by_tool?.[a] ?? {})
        ])
      ),
      calls: Object.fromEntries(
        shuffle(rng, Object.keys(state.tool_limits!.calls)).map((a) => [
          a,
          shuffle(rng, state.tool_limits!.calls[a] ?? [])
        ])
      )
    }
  };
}

// Run a full intent-op sequence, building RELEASE intents from prior auth IDs.
function runIntentOps(
  engine: PolicyEngine,
  initial: State,
  ops: IntentOp[],
  seed: number
): { decisions: Array<"ALLOW" | "DENY">; finalState: State; auditHeadHash: string } {
  let state = structuredClone(initial);
  const decisions: Array<"ALLOW" | "DENY"> = [];
  const authsByAgent: Record<string, string[]> = {};
  let nonce = 10_000n;

  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    const baseIntent = {
      intent_id: `intent-${seed}-${i}`,
      agent_id: op.agent_id,
      action_type: op.action_type,
      amount: op.amount,
      asset: op.asset,
      target: op.target,
      timestamp: 1_700_100_000 + i,
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
    const out = engine.evaluatePure(intent, state, intent.timestamp, { mode: "fail-fast" });
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
  return { decisions, finalState: state, auditHeadHash: engine.audit.headHash() };
}

// ── Tests ─────────────────────────────────────────────────────────────────

test("D-1 evaluatePure is deterministic for equivalent inputs", () => {
  for (const seed of seeds()) {
    const engine = makeEngine();
    const state = genState(seed);
    const op = genIntentOps(seed, state).find((o) => o.type === "EXECUTE");
    if (!op) continue;

    const intent = buildExecIntent(op, seed, 0, 1_000n);

    const out1 = engine.evaluatePure(intent, structuredClone(state), intent.timestamp, { mode: "fail-fast" });
    const out2 = engine.evaluatePure(intent, structuredClone(state), intent.timestamp, { mode: "fail-fast" });

    assert.equal(out1.decision, out2.decision, `seed=${seed} decision mismatch`);
    assert.deepEqual(out1.reasons ?? [], out2.reasons ?? [], `seed=${seed} reasons mismatch`);

    if (out1.decision === "ALLOW" && out2.decision === "ALLOW") {
      // All stable fields of the authorization must be identical.
      assert.equal(out1.authorization.auth_id, out2.authorization.auth_id,
        `seed=${seed} auth_id mismatch`);
      assert.equal(out1.authorization.intent_hash, out2.authorization.intent_hash,
        `seed=${seed} intent_hash mismatch`);
      assert.equal(out1.authorization.state_hash, out2.authorization.state_hash,
        `seed=${seed} state_hash mismatch`);
      assert.equal(out1.authorization.issued_at, out2.authorization.issued_at,
        `seed=${seed} issued_at mismatch`);
      assert.equal(out1.authorization.expiry, out2.authorization.expiry,
        `seed=${seed} expiry mismatch`);
      assert.equal(out1.authorization.decision, out2.authorization.decision,
        `seed=${seed} authorization.decision mismatch`);
      // nextState must hash identically.
      assert.equal(
        engine.computeStateHash(out1.nextState),
        engine.computeStateHash(out2.nextState),
        `seed=${seed} nextState hash mismatch`
      );
    }
  }
});

test("D-2 evaluatePure does not mutate the input state", () => {
  // deepMerge creates new object copies at every touched path, so passing a
  // state reference directly must leave the original fully unchanged.
  for (const seed of seeds()) {
    const engine = makeEngine();
    const state = genState(seed);
    const op = genIntentOps(seed, state).find((o) => o.type === "EXECUTE");
    if (!op) continue;

    const intent = buildExecIntent(op, seed, 0, 2_000n);

    // Capture a deterministic fingerprint of the state before evaluation.
    const preHash = engine.computeStateHash(state);

    // Pass state directly - the implementation must not mutate it.
    engine.evaluatePure(intent, state, intent.timestamp, { mode: "fail-fast" });

    const postHash = engine.computeStateHash(state);
    assert.equal(preHash, postHash,
      `seed=${seed} evaluatePure mutated the input state`);
  }
});

test("D-3 cross-clone determinism: structuredClone inputs yield identical outputs", () => {
  // Two independent structuredClone copies of the same logical state must
  // produce identical evaluation outputs - ruling out any residual aliasing
  // between the cloned copy and the engine's internal working state.
  for (const seed of seeds()) {
    const engine = makeEngine();
    const state = genState(seed);
    const op = genIntentOps(seed, state).find((o) => o.type === "EXECUTE");
    if (!op) continue;

    const intent = buildExecIntent(op, seed, 0, 3_000n);

    const cloneA = structuredClone(state);
    const cloneB = structuredClone(state);

    // Verify the clones are equal but not the same reference.
    assert.deepEqual(cloneA, cloneB,
      `seed=${seed} structuredClone produced non-equal copies`);
    assert.notStrictEqual(cloneA, cloneB,
      `seed=${seed} structuredClone must return new objects`);

    const outA = engine.evaluatePure(intent, cloneA, intent.timestamp, { mode: "fail-fast" });
    const outB = engine.evaluatePure(intent, cloneB, intent.timestamp, { mode: "fail-fast" });

    assert.equal(outA.decision, outB.decision,
      `seed=${seed} cross-clone decision mismatch`);

    if (outA.decision === "ALLOW" && outB.decision === "ALLOW") {
      assert.equal(outA.authorization.auth_id, outB.authorization.auth_id,
        `seed=${seed} cross-clone auth_id mismatch`);
      assert.equal(outA.authorization.state_hash, outB.authorization.state_hash,
        `seed=${seed} cross-clone state_hash mismatch`);
      assert.equal(
        engine.computeStateHash(outA.nextState),
        engine.computeStateHash(outB.nextState),
        `seed=${seed} cross-clone nextState hash mismatch`
      );
    }
  }
});

test("D-4 key order does not affect decision output", () => {
  // buildEquivalentState shuffles the insertion order of every object key
  // while preserving logical equality. The decision sequence, final state hash,
  // and audit head hash must be identical to the unshuffled baseline.
  for (const seed of seeds()) {
    const state = genState(seed);
    const shuffled = buildEquivalentState(seed, state);
    const ops = genIntentOps(seed, state);

    const r1 = runIntentOps(makeEngine(), state, ops, seed);
    const r2 = runIntentOps(makeEngine(), shuffled, ops, seed);

    assert.deepEqual(r1.decisions, r2.decisions,
      `seed=${seed} key order affected the decision sequence`);

    assert.equal(
      makeEngine().computeStateHash(r1.finalState),
      makeEngine().computeStateHash(r2.finalState),
      `seed=${seed} key order affected the final state hash`
    );

    assert.equal(r1.auditHeadHash, r2.auditHeadHash,
      `seed=${seed} key order affected the audit head hash`);
  }
});

test("D-6 strict mode: verifyAuthorization requires explicit now", () => {
  // With strictDeterminism: true, calling verifyAuthorization() without an
  // explicit `now` must throw instead of falling back to Date.now().
  for (const seed of seeds()) {
    const engine = makeEngine(); // strictDeterminism: true
    const state = genState(seed);
    const op = genIntentOps(seed, state).find((o) => o.type === "EXECUTE");
    if (!op) continue;

    const intent = buildExecIntent(op, seed, 0, 4_000n);
    const out = engine.evaluatePure(intent, structuredClone(state), intent.timestamp, { mode: "fail-fast" });
    if (out.decision !== "ALLOW") continue;

    const { authorization } = out;
    const explicitNow = intent.timestamp; // well within the 120 s TTL

    // Without `now` in strict mode: the implementation's inner strictDeterminism
    // throw is caught by the outer try/catch in verifyAuthorization and converted
    // to { valid: false, reason: "INTERNAL_ERROR" }.  The result must not be valid.
    // Cast as Authorization: runtime object has all legacy fields even though
    // the TypeScript type was narrowed to AuthorizationV1 at the evaluatePure boundary.
    const noNowResult = engine.verifyAuthorization(intent, authorization as Authorization, state);
    assert.ok(!noNowResult.valid,
      `seed=${seed} expected invalid result when now is omitted in strict mode`);
    assert.equal(noNowResult.reason, "INTERNAL_ERROR",
      `seed=${seed} expected INTERNAL_ERROR when now is omitted in strict mode`);

    // With explicit `now`: must succeed and be stable across repeated calls.
    const r1 = engine.verifyAuthorization(intent, authorization as Authorization, state, explicitNow);
    const r2 = engine.verifyAuthorization(intent, authorization as Authorization, state, explicitNow);
    assert.deepEqual(r1, r2,
      `seed=${seed} verifyAuthorization not stable with the same explicit now`);
    assert.ok(r1.valid,
      `seed=${seed} expected valid=true with explicit now within TTL`);
  }
});

test("D-6 strict mode: evaluatePure uses intent.timestamp, not Date.now()", () => {
  // evaluatePure must derive issued_at from intent.timestamp, never from
  // Date.now(). Two calls with the same intent must produce the same issued_at
  // and the same auth_id even when the wall clock advances between calls.
  for (const seed of seeds()) {
    const engine = makeEngine(); // strictDeterminism: true
    const state = genState(seed);
    const op = genIntentOps(seed, state).find((o) => o.type === "EXECUTE");
    if (!op) continue;

    const intent = buildExecIntent(op, seed, 0, 5_000n);

    const out1 = engine.evaluatePure(intent, structuredClone(state), intent.timestamp, { mode: "fail-fast" });
    const out2 = engine.evaluatePure(intent, structuredClone(state), intent.timestamp, { mode: "fail-fast" });

    assert.equal(out1.decision, out2.decision,
      `seed=${seed} strict mode evaluatePure decision not stable`);

    if (out1.decision === "ALLOW" && out2.decision === "ALLOW") {
      assert.equal(out1.authorization.issued_at, intent.timestamp,
        `seed=${seed} issued_at must equal intent.timestamp, not Date.now()`);
      assert.equal(out1.authorization.issued_at, out2.authorization.issued_at,
        `seed=${seed} issued_at not stable across calls`);
      assert.equal(out1.authorization.auth_id, out2.authorization.auth_id,
        `seed=${seed} auth_id not stable across calls`);
    }
  }
});

test("D-7 audit head hash is deterministic across independent engine instances", () => {
  // Two freshly-created engines that process the same intent sequence against
  // the same initial state must produce identical audit.headHash() values.
  // This verifies that all audit event fields - policyId, timestamps, hashes -
  // are derived solely from the inputs and not from any per-instance entropy.
  for (const seed of seeds()) {
    const state = genState(seed);
    const ops = genIntentOps(seed, state);

    const r1 = runIntentOps(makeEngine(), state, ops, seed);
    const r2 = runIntentOps(makeEngine(), state, ops, seed);

    assert.deepEqual(r1.decisions, r2.decisions,
      `seed=${seed} D-7 decision sequences diverged between instances`);
    assert.equal(r1.auditHeadHash, r2.auditHeadHash,
      `seed=${seed} D-7 audit head hash mismatch between independent engine instances`);
  }
});

test("D-8 computePolicyId is stable for fixed engine configuration", () => {
  // computePolicyId() must return the same string on every call for a given
  // engine instance, and across independently-constructed engines with the
  // same options. It must change when any option that participates in the
  // policy identity changes.
  for (const seed of seeds()) {
    const e1 = makeEngine();
    const e2 = makeEngine();

    // Stable within a single instance.
    const id1a = e1.computePolicyId();
    const id1b = e1.computePolicyId();
    assert.equal(id1a, id1b,
      `seed=${seed} D-8 computePolicyId not stable within the same instance`);

    // Stable across independently-constructed instances with identical opts.
    assert.equal(id1a, e2.computePolicyId(),
      `seed=${seed} D-8 computePolicyId differs across equivalent engine instances`);

    // Changes when a policy-identity-bearing option changes.
    const eDiffTtl = new PolicyEngine({
      policy_version: POLICY_VERSION,
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_ttl_seconds: 999,   // differs from makeEngine() (120)
      deny_mode: "fail-fast",
      strictDeterminism: true,
      ...RECOMMENDED_TRUSTED_TIME_PROFILE
    });
    assert.notEqual(id1a, eDiffTtl.computePolicyId(),
      `seed=${seed} D-8 computePolicyId did not change when ttl changed`);

    const eDiffVersion = new PolicyEngine({
      policy_version: "v0.6-test-alt",  // differs from POLICY_VERSION
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_ttl_seconds: 120,
      deny_mode: "fail-fast",
      strictDeterminism: true,
      ...RECOMMENDED_TRUSTED_TIME_PROFILE
    });
    assert.notEqual(id1a, eDiffVersion.computePolicyId(),
      `seed=${seed} D-8 computePolicyId did not change when policy_version changed`);
  }
});
