import {
  encodeCanonicalState,
  encodeEnvelope,
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  verifySnapshot,
} from "@oxdeai/core";
import type { AuthorizationV1, Intent, State } from "@oxdeai/core";
import type { KeySet } from "@oxdeai/core";

export const BENCHMARK_ENVELOPE_KEY_SET: KeySet = {
  issuer: "bench-envelope-issuer",
  version: "1",
  keys: [
    {
      kid: "bench-envelope-key",
      alg: "Ed25519",
      public_key:
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAWiMMGTYK7zzHwZXLzDpCshxAH6Lgx8gVsJaixePuY7g=\n-----END PUBLIC KEY-----",
    },
  ],
};

export type FixtureProfile = "minimal" | "complex" | "adversarial";

type BenchFixture = {
  profile: FixtureProfile;
  policy: { id: string; version: string };
  intent: Intent;
  state: State;
  auth: AuthorizationV1;
  envelopeBytes: Uint8Array;
};

function seeded(seed: number): () => number {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 0x100000000;
  };
}

function deepCloneState(state: State): State {
  const nonces: Record<string, Array<{ nonce: string; ts: number }>> = {};
  for (const [agent, values] of Object.entries(state.replay.nonces ?? {})) {
    nonces[agent] = values.map((v) => ({ nonce: String(v.nonce), ts: v.ts }));
  }
  const toolLimits = state.tool_limits
    ? {
        window_seconds: state.tool_limits.window_seconds,
        max_calls: { ...state.tool_limits.max_calls },
        max_calls_by_tool: { ...(state.tool_limits.max_calls_by_tool ?? {}) },
        calls: { ...(state.tool_limits.calls ?? {}) },
      }
    : undefined;

  return {
    ...state,
    kill_switch: { ...state.kill_switch, agents: { ...(state.kill_switch.agents ?? {}) } },
    allowlists: {
      action_types: [...(state.allowlists.action_types ?? [])],
      assets: [...(state.allowlists.assets ?? [])],
      targets: [...(state.allowlists.targets ?? [])],
    },
    budget: {
      budget_limit: { ...state.budget.budget_limit },
      spent_in_period: { ...state.budget.spent_in_period },
    },
    max_amount_per_action: { ...state.max_amount_per_action },
    velocity: {
      config: { ...state.velocity.config },
      counters: { ...(state.velocity.counters ?? {}) },
    },
    replay: {
      ...state.replay,
      nonces,
    },
    concurrency: {
      max_concurrent: { ...state.concurrency.max_concurrent },
      active: { ...(state.concurrency.active ?? {}) },
      active_auths: { ...(state.concurrency.active_auths ?? {}) },
    },
    recursion: {
      max_depth: { ...state.recursion.max_depth },
    },
    ...(toolLimits ? { tool_limits: toolLimits } : {}),
  };
}

function makeEngine(policyId: string, policyVersion: string): PolicyEngine {
  return new PolicyEngine({
    policy_version: policyVersion,
    engine_secret: "benchmark-only-hmac-secret-at-least-32-chars",
    authorization_ttl_seconds: 120,
    authorization_issuer: "bench-issuer",
    authorization_audience: "bench-rp",
    policyId,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(profile: FixtureProfile, seed: number): State {
  const rnd = seeded(seed);
  const baseBudget = profile === "minimal" ? 50_000n : profile === "complex" ? 1_000_000n : 5_000_000n;
  const replayWindow = profile === "adversarial" ? 120 : 3600;
  const maxDepth = profile === "minimal" ? 4 : 12;
  const velocityMax = profile === "adversarial" ? 5_000 : 1_000;
  const states: State = {
    policy_version: `bench-${profile}-v1`,
    period_id: `bench-period-${profile}`,
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PAYMENT", "PURCHASE", "PROVISION"],
      assets: ["USDC", "USD", "EUR"],
      targets: ["merchant-1", "merchant-2", "merchant-3"],
    },
    budget: {
      budget_limit: { "agent-1": baseBudget },
      spent_in_period: { "agent-1": BigInt(Math.floor(rnd() * 1000)) },
    },
    max_amount_per_action: { "agent-1": profile === "minimal" ? 2000n : 10000n },
    velocity: {
      config: { window_seconds: 60, max_actions: velocityMax },
      counters: {},
    },
    replay: { window_seconds: replayWindow, max_nonces_per_agent: 1024, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 100 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": maxDepth } },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 1000 },
      max_calls_by_tool: {},
      calls: {},
    },
  };

  if (profile !== "minimal") {
    if (states.allowlists.targets) {
      states.allowlists.targets.push("merchant-4", "merchant-5");
    }
    states.velocity.counters["agent-1"] = { window_start: 1700000000, count: Math.floor(rnd() * 200) };
  }
  if (profile === "adversarial") {
    states.replay.nonces["agent-1"] = [{ nonce: "99", ts: 1700000000 }];
    states.concurrency.active["agent-1"] = 3;
  }
  return states;
}

function makeIntent(profile: FixtureProfile, seed: number): Intent {
  const rnd = seeded(seed ^ 0x9e3779b9);
  const baseAmount = profile === "minimal" ? 500n : profile === "complex" ? 1500n : 2000n;
  return {
    intent_id: `bench-${profile}-intent-${Math.floor(rnd() * 10_000)}`,
    agent_id: "agent-1",
    action_type: profile === "adversarial" ? "PURCHASE" : "PAYMENT",
    type: "EXECUTE",
    nonce: BigInt(Math.floor(rnd() * 10_000) + 1),
    amount: baseAmount,
    target: profile === "minimal" ? "merchant-1" : "merchant-3",
    timestamp: 1_700_000_000 + Math.floor(rnd() * 10),
    metadata_hash: "a".repeat(64),
    signature: "bench-signature",
    depth: profile === "minimal" ? 0 : 1,
    tool_call: profile !== "minimal",
    tool: profile === "minimal" ? undefined : "settle_invoice",
  } as Intent;
}

function makeEnvelope(policyId: string, state: State, nowTs: number): Uint8Array {
  const snapshot = encodeCanonicalState({
    formatVersion: 1,
    engineVersion: "bench-engine",
    policyId,
    modules: state as unknown as Record<string, unknown>,
  });
  const snapshotResult = verifySnapshot(snapshot, { expectedPolicyId: policyId });
  if (!snapshotResult.stateHash) throw new Error("fixture envelope failed to compute stateHash");
  return encodeEnvelope({
    formatVersion: 1,
    snapshot,
    events: [
      { type: "INTENT_RECEIVED", timestamp: nowTs, policyId, intent_hash: "h".repeat(64), agent_id: "agent-1" },
      {
        type: "DECISION",
        timestamp: nowTs + 1,
        policyId,
        policy_version: state.policy_version,
        intent_hash: "h".repeat(64),
        decision: "ALLOW",
        reasons: [],
      },
      { type: "STATE_CHECKPOINT", timestamp: nowTs + 2, policyId, stateHash: snapshotResult.stateHash },
    ],
  } as any);
}

function makeFixture(profile: FixtureProfile, seed: number): BenchFixture {
  const policy = { id: "0123456789abcdef".repeat(4), version: `bench-${profile}-v1` };
  const engine = makeEngine(policy.id, policy.version);
  const state = makeState(profile, seed);
  const intent = makeIntent(profile, seed);
  const out = engine.evaluatePure(intent, deepCloneState(state), intent.timestamp);
  if (out.decision !== "ALLOW" || !out.authorization) {
    throw new Error(`fixture ${profile}: expected ALLOW authorization`);
  }
  return {
    profile,
    policy,
    intent,
    state,
    auth: out.authorization,
    envelopeBytes: makeEnvelope(policy.id, state, 1_700_000_000),
  };
}

export type FixtureSet = {
  seed: number;
  minimal: BenchFixture;
  complex: BenchFixture;
  adversarial: BenchFixture;
};

export function createFixtureSet(seed: number): FixtureSet {
  return {
    seed,
    minimal: makeFixture("minimal", seed + 11),
    complex: makeFixture("complex", seed + 17),
    adversarial: makeFixture("adversarial", seed + 23),
  };
}

export function makeDeterministicToolExecutor() {
  let acc = 0x811c9dc5 >>> 0;
  const scratch = new Uint32Array(16);
  const ring = new Uint16Array(32);
  return (actionType: string, target: string, costMinorUnits: number): number => {
    // Deterministic runtime-like work: JSON serialization + stable hash + in-memory transform.
    const payloadObj = {
      actionType,
      target,
      amountMinor: costMinorUnits,
      version: "v1",
      route: "dispatch",
      shape: "tool-call",
    };
    const payload = JSON.stringify(payloadObj);
    let h = acc;
    for (let round = 0; round < 16; round++) {
      for (let i = 0; i < payload.length; i++) {
        h ^= payload.charCodeAt(i) + round;
        h = Math.imul(h, 16777619) >>> 0; // FNV-1a style mix.
        scratch[i & 15] = (scratch[i & 15] + h + i + round) >>> 0;
        ring[(i + round) & 31] = (ring[(i + round) & 31] + (h & 0xffff)) & 0xffff;
      }
    }
    for (let i = 0; i < scratch.length; i++) {
      h ^= scratch[i] + i;
      h = Math.imul(h ^ (h >>> 13), 0x5bd1e995) >>> 0;
    }
    for (let i = 0; i < ring.length; i++) {
      h ^= ring[i] + i * 17;
      h = Math.imul(h ^ (h >>> 11), 0x27d4eb2d) >>> 0;
    }
    acc = (h ^ (h >>> 15)) >>> 0;
    return acc;
  };
}

export type ProtectedPathFixture = {
  policyId: string;
  engine: PolicyEngine;
  intent: Intent;
  state: State;
  auth: AuthorizationV1;
  envelopeBytes: Uint8Array;
  toolExecute: (actionType: string, target: string, costMinorUnits: number) => number;
};

export function createProtectedPathFixture(seed: number): ProtectedPathFixture {
  const fx = createFixtureSet(seed).complex;
  const engine = makeEngine(fx.policy.id, fx.policy.version);
  return {
    policyId: fx.policy.id,
    engine,
    intent: fx.intent,
    state: deepCloneState(fx.state),
    auth: fx.auth,
    envelopeBytes: fx.envelopeBytes,
    toolExecute: makeDeterministicToolExecutor(),
  };
}
