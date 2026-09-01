// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based tests for @oxdeai/guard.
 *
 * Uses the same seeded-PRNG approach as packages/core/src/test/property.test.ts:
 *   - mulberry32 PRNG, fully deterministic given a seed
 *   - PBT_CASES env var controls iteration count (default 100)
 *   - PBT_SEED   env var overrides the base seed
 *   - PBT_ONLY_SEED env var runs a single seed for focused debugging
 *
 * Test IDs follow the convention G-N (Normalizer) and G-G (Guard).
 */

import test from "node:test";
import assert from "node:assert/strict";

import type { Authorization, Intent, PolicyEngine, State } from "@oxdeai/core";
import { stateSnapshotHash, intentHash } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";

import { defaultNormalizeAction } from "../normalizeAction.js";
import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAINormalizationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

// ── PRNG (identical to core property.test.ts) ─────────────────────────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "100");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260315");
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

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── generators ────────────────────────────────────────────────────────────────

const ALPHANUMS = "abcdefghijklmnopqrstuvwxyz0123456789_-";
const ACTION_KEYWORDS = [
  "provision", "payment", "purchase", "onchain", "transfer",
  "gpu", "vm", "storage", "buy", "send", "swap", "mint", "chain",
  "blockchain", "subscribe", "order",
];
const VALID_ACTION_TYPES = ["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"] as const;

const BASE_TRUST = { trustedKeySets: [TEST_KEYSET], expectedAudience: "aud-test" };

function genAlphaStr(rng: () => number, minLen: number, maxLen: number): string {
  const len = randInt(rng, minLen, maxLen);
  return Array.from({ length: len }, () => ALPHANUMS[randInt(rng, 0, ALPHANUMS.length - 1)]).join("");
}

/** Generates a random scalar value for use as an args field. */
function genScalar(rng: () => number): unknown {
  const kind = randInt(rng, 0, 4);
  switch (kind) {
    case 0: return randInt(rng, -1_000_000, 1_000_000);
    case 1: return genAlphaStr(rng, 1, 12);
    case 2: return rng() > 0.5;
    case 3: return null;
    default: return 0;
  }
}

function genArgs(rng: () => number, maxKeys: number): Record<string, unknown> {
  const count = randInt(rng, 0, maxKeys);
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < count; i++) {
    obj[genAlphaStr(rng, 2, 8)] = genScalar(rng);
  }
  return obj;
}

function shuffleObjectKeys(rng: () => number, obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of shuffle(rng, Object.keys(obj))) result[key] = obj[key];
  return result;
}

/** Generates a valid ProposedAction (agent_id always present). */
function genAction(rng: () => number): ProposedAction {
  const hasResourceType = rng() > 0.5;
  const hasCost = rng() > 0.3;
  const hasTimestamp = rng() > 0.4;
  const hasTarget = rng() > 0.5;
  const hasIntentId = rng() > 0.5;
  const hasNonce = rng() > 0.4;

  const nonceVariant = randInt(rng, 0, 2);
  const nonce: unknown =
    nonceVariant === 0 ? BigInt(randInt(rng, 0, 999_999))
    : nonceVariant === 1 ? randInt(rng, 0, 999_999)
    : undefined;

  // Mix keyword-containing names with pure random ones so inferActionType
  // exercises all branches across the run.
  const useKeyword = rng() > 0.4;
  const name = useKeyword
    ? `${pick(rng, ACTION_KEYWORDS)}_${genAlphaStr(rng, 2, 8)}`
    : genAlphaStr(rng, 3, 16);

  return {
    name,
    args: genArgs(rng, 5),
    resourceType: hasResourceType ? pick(rng, ACTION_KEYWORDS) : undefined,
    estimatedCost: hasCost ? rng() * 10_000 : undefined,
    timestampSeconds: hasTimestamp ? 1_700_000_000 + randInt(rng, 0, 1_000_000) : undefined,
    context: {
      agent_id: `agent-${randInt(rng, 1, 50)}`,
      target: hasTarget ? genAlphaStr(rng, 3, 15) : undefined,
      intent_id: hasIntentId ? genAlphaStr(rng, 10, 20) : undefined,
      nonce,
    },
  };
}

/** Same as genAction but always omits agent_id. */
function genActionNoAgentId(rng: () => number): ProposedAction {
  const action = genAction(rng);
  const { agent_id: _omit, ...contextWithout } = action.context ?? {};
  return { ...action, context: contextWithout };
}

/** Generates a non-negative estimatedCost. */
function genNonNegativeCost(rng: () => number): number {
  return rng() * 50_000; // [0, 50000)
}

/** Generates an invalid estimatedCost (negative or non-finite). */
function genInvalidCost(rng: () => number): number {
  return pick(rng, [-1, -0.001, -9999, -Infinity, Infinity, NaN]);
}

// ── mock engine factories ─────────────────────────────────────────────────────

// Signed but long-expired — strict verifier will reject with AUTH_EXPIRED.
const EXPIRED_STUB_AUTH = signAuth({ auth_id: "stub-expired", issued_at: 1_000, expiry: 2_000 }) as unknown as Authorization;

function makeDenyEngine(): PolicyEngine {
  return {
    evaluatePure: () => ({ decision: "DENY" as const, reasons: ["KILL_SWITCH_GLOBAL"] }),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

function makeAllowEngine(state: State, nextState?: State): PolicyEngine {
  return {
    evaluatePure: (intent: Intent, s: State) => {
      const auth = signAuth({
        auth_id: "stub-valid",
        state_hash: stateSnapshotHash(s),
        intent_hash: intentHash(intent),
      }) as unknown as Authorization;
      return {
        decision: "ALLOW" as const,
        reasons: [] as [],
        authorization: auth,
        nextState: nextState ?? state,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

function makeAllowEngineNoAuth(nextState: State): PolicyEngine {
  return {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: undefined as unknown as Authorization,
      nextState,
    }),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

function makeAuthFailEngine(nextState: State): PolicyEngine {
  return {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: EXPIRED_STUB_AUTH,
      nextState,
    }),
  } as unknown as PolicyEngine;
}

function makePermissiveState(agentId: string): State {
  return buildState({
    agent_id: agentId,
    allow_action_types: ["PROVISION", "PAYMENT", "PURCHASE", "ONCHAIN_TX"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 10_000,
    max_concurrent: 64,
  });
}

// ── N1: normalizer output shape invariants ────────────────────────────────────

test("N1 defaultNormalizeAction always produces a well-formed Intent for any valid ProposedAction", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const intent = defaultNormalizeAction(action);

    assert.equal(typeof intent.intent_id, "string", `seed=${seed} intent_id must be string`);
    assert.ok(intent.intent_id.length > 0, `seed=${seed} intent_id must be non-empty`);

    assert.equal(typeof intent.agent_id, "string", `seed=${seed} agent_id must be string`);
    assert.ok(intent.agent_id.length > 0, `seed=${seed} agent_id must be non-empty`);

    assert.ok(
      (VALID_ACTION_TYPES as readonly string[]).includes(intent.action_type),
      `seed=${seed} action_type "${intent.action_type}" is not one of the 4 valid values`
    );

    assert.equal(typeof intent.amount, "bigint", `seed=${seed} amount must be bigint`);
    assert.ok(intent.amount >= 0n, `seed=${seed} amount must be non-negative`);

    assert.equal(typeof intent.target, "string", `seed=${seed} target must be string`);
    assert.ok(intent.target.length > 0, `seed=${seed} target must be non-empty`);

    assert.equal(typeof intent.timestamp, "number", `seed=${seed} timestamp must be number`);
    assert.ok(Number.isInteger(intent.timestamp), `seed=${seed} timestamp must be integer`);
    assert.ok(intent.timestamp > 0, `seed=${seed} timestamp must be positive`);

    assert.equal(typeof intent.metadata_hash, "string", `seed=${seed} metadata_hash must be string`);
    assert.equal(intent.metadata_hash.length, 64, `seed=${seed} metadata_hash must be 64 hex chars`);
    assert.ok(/^[0-9a-f]{64}$/.test(intent.metadata_hash), `seed=${seed} metadata_hash must be lowercase hex`);

    assert.equal(typeof intent.nonce, "bigint", `seed=${seed} nonce must be bigint`);

    assert.equal(intent.type, "EXECUTE", `seed=${seed} default type must be EXECUTE`);
  }
});

// ── N2: metadata_hash is stable under args key reordering ────────────────────

test("N2 metadata_hash is identical regardless of args key insertion order", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);

    const shuffledAction: ProposedAction = {
      ...action,
      args: shuffleObjectKeys(mulberry32(seed ^ 0xdeadbeef), action.args),
    };

    const h1 = defaultNormalizeAction(action).metadata_hash;
    const h2 = defaultNormalizeAction(shuffledAction).metadata_hash;

    assert.equal(h1, h2, `seed=${seed} metadata_hash must be invariant to key order`);
  }
});

// ── N3: missing agent_id always throws OxDeAINormalizationError ───────────────

test("N3 defaultNormalizeAction always throws OxDeAINormalizationError when agent_id is absent", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genActionNoAgentId(rng);

    assert.throws(
      () => defaultNormalizeAction(action),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAINormalizationError,
          `seed=${seed} expected OxDeAINormalizationError, got ${Object.prototype.toString.call(err)}`
        );
        assert.ok(
          err.message.includes("agent_id"),
          `seed=${seed} error message should mention agent_id`
        );
        return true;
      },
      `seed=${seed}`
    );
  }
});

// ── N4: action_type is always one of the 4 legal values ──────────────────────

test("N4 action_type is always a valid ActionType for any name or resourceType string", () => {
  // Generate diverse name strings: random, keyword-containing, mixed-case, with
  // separators — all must map to one of the 4 canonical values.
  const extraNames = [
    "x", "a1", "z".repeat(50), "PAY", "PROVISION_THING",
    "buy_tokens_onchain", "send_payment_via_blockchain",
    "subscribe_to_gpu_pool", "random_unknown_action",
    "transfer_onchain", "mint_nft", "swap_eth_usdc",
    "onchain_transfer", "blockchain_payment", "chain_send",
  ];

  for (const seed of seeds()) {
    const rng = mulberry32(seed);

    // Seeded random name
    const action = genAction(rng);
    const intent = defaultNormalizeAction(action);
    assert.ok(
      (VALID_ACTION_TYPES as readonly string[]).includes(intent.action_type),
      `seed=${seed} name="${action.name}" resourceType="${action.resourceType}" → invalid action_type "${intent.action_type}"`
    );
  }

  // Fixed edge cases
  for (const name of extraNames) {
    const action: ProposedAction = { name, args: {}, context: { agent_id: "a" } };
    const intent = defaultNormalizeAction(action);
    assert.ok(
      (VALID_ACTION_TYPES as readonly string[]).includes(intent.action_type),
      `name="${name}" → invalid action_type "${intent.action_type}"`
    );
  }
});

// ── N5: amount = round(estimatedCost × 1_000_000) for any non-negative cost ──

test("N5 amount equals round(estimatedCost × 1_000_000) for any non-negative finite cost", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const cost = genNonNegativeCost(rng);
    const action: ProposedAction = {
      name: "op",
      args: {},
      estimatedCost: cost,
      context: { agent_id: "agent-x" },
    };

    const intent = defaultNormalizeAction(action);
    const expected = BigInt(Math.round(cost * 1_000_000));

    assert.equal(
      intent.amount,
      expected,
      `seed=${seed} cost=${cost} expected amount=${expected} got ${intent.amount}`
    );
  }
});

// ── N6: invalid estimatedCost always throws ───────────────────────────────────

test("N6 defaultNormalizeAction always throws OxDeAINormalizationError for invalid estimatedCost", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const cost = genInvalidCost(rng);
    const action: ProposedAction = {
      name: "op",
      args: {},
      estimatedCost: cost,
      context: { agent_id: "agent-x" },
    };

    assert.throws(
      () => defaultNormalizeAction(action),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAINormalizationError,
          `seed=${seed} cost=${cost} expected OxDeAINormalizationError, got ${Object.prototype.toString.call(err)}`
        );
        return true;
      },
      `seed=${seed} cost=${cost}`
    );
  }
});

// ── N7: agent_id always propagates into intent ────────────────────────────────

test("N7 agent_id in context always equals agent_id in the produced Intent", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const intent = defaultNormalizeAction(action);
    assert.equal(
      intent.agent_id,
      action.context!.agent_id,
      `seed=${seed} intent.agent_id should match context.agent_id`
    );
  }
});

// ── N8: target defaults to action.name when context.target is absent ──────────

test("N8 target falls back to action.name when context.target is absent", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const base = genAction(rng);
    // Explicitly remove context.target
    const { target: _omit, ...contextWithout } = base.context ?? {};
    const action: ProposedAction = { ...base, context: contextWithout };

    const intent = defaultNormalizeAction(action);
    assert.equal(intent.target, action.name, `seed=${seed} target should equal action.name`);
  }
});

// ── G1: DENY always blocks execute and setState ───────────────────────────────

test("G1 engine DENY always prevents execute() and setState() for any ProposedAction", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;

    let executeCalled = false;
    let setStateCalled = false;

    let currentVersion = 0;
    const config: OxDeAIGuardConfig = {
      engine: makeDenyEngine(),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { setStateCalled = true; if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      ...BASE_TRUST,
    };

    const guard = OxDeAIGuard(config);

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(err instanceof OxDeAIDenyError, `seed=${seed} expected OxDeAIDenyError`);
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called on DENY`);
    assert.ok(!setStateCalled, `seed=${seed} setState must not be called on DENY`);
  }
});

// ── G2: missing agent_id always blocks execute ────────────────────────────────

test("G2 missing agent_id always prevents execute() for any ProposedAction", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genActionNoAgentId(rng);
    const state = makePermissiveState("fallback-agent");
    let currentState = state;
    let executeCalled = false;

    let currentVersion = 0;
    const config: OxDeAIGuardConfig = {
      engine: makeAllowEngine(currentState),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      ...BASE_TRUST,
    };

    const guard = OxDeAIGuard(config);

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAINormalizationError,
          `seed=${seed} expected OxDeAINormalizationError, got ${Object.prototype.toString.call(err)}`
        );
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called when normalization fails`);
  }
});

// ── G3: ALLOW without authorization always blocks execute ─────────────────────

test("G3 ALLOW without authorization artifact always prevents execute() for any ProposedAction", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;
    let executeCalled = false;

    let currentVersion = 0;
    const config: OxDeAIGuardConfig = {
      engine: makeAllowEngineNoAuth(currentState),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      ...BASE_TRUST,
    };

    const guard = OxDeAIGuard(config);

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAIAuthorizationError,
          `seed=${seed} expected OxDeAIAuthorizationError, got ${Object.prototype.toString.call(err)}`
        );
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called without authorization`);
  }
});

// ── G4: failed verifyAuthorization always blocks execute ──────────────────────

test("G4 failed verifyAuthorization always prevents execute() for any ProposedAction", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;
    let executeCalled = false;

    let currentVersion = 0;
    const config: OxDeAIGuardConfig = {
      engine: makeAuthFailEngine(currentState),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      ...BASE_TRUST,
    };

    const guard = OxDeAIGuard(config);

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAIAuthorizationError,
          `seed=${seed} expected OxDeAIAuthorizationError`
        );
        assert.ok(
          err.message.includes("AUTH_EXPIRED"),
          `seed=${seed} error message should include the verification failure reason`
        );
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called when verifyAuthorization fails`);
  }
});

// ── G5: ALLOW always calls setState then execute ──────────────────────────────

test("G5 successful ALLOW always calls setState() before execute() and returns result for any ProposedAction", async () => {
  const SENTINEL = Symbol("execution-result");

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;
    let currentVersion = 0;

    let executeCalled = false;
    let setStateCalled = false;
    const callOrder: string[] = [];

    const config: OxDeAIGuardConfig = {
      engine: makeAllowEngine(currentState),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => {
        callOrder.push("setState");
        setStateCalled = true;
        if (v !== currentVersion) return false;
        currentState = s;
        currentVersion++;
        return true;
      },
      ...BASE_TRUST,
    };

    const guard = OxDeAIGuard(config);
    const result = await guard(action, async () => {
      callOrder.push("execute");
      executeCalled = true;
      return SENTINEL;
    });

    assert.ok(executeCalled, `seed=${seed} execute must be called on ALLOW`);
    assert.ok(setStateCalled, `seed=${seed} setState must be called on ALLOW`);
    assert.equal(result, SENTINEL, `seed=${seed} guard must return the execute() result`);

    // setState (CAS commit) must happen before execute
    assert.equal(callOrder[0], "setState", `seed=${seed} setState must be called before execute`);
    assert.equal(callOrder[1], "execute", `seed=${seed} execute must be called after setState`);
  }
});

// ── G6: onDecision always fires with correct decision value ───────────────────

test("G6 onDecision always receives correct decision value for any outcome", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;

    // DENY path
    let denyDecision: string | undefined;
    let denyVersion = 0;
    await assert.rejects(
      () => OxDeAIGuard({
        engine: makeDenyEngine(),
        getState: () => ({ state: currentState, version: denyVersion }),
        setState: (s, v) => { if (v !== denyVersion) return false; currentState = s; denyVersion++; return true; },
        onDecision: ({ decision }) => { denyDecision = decision; },
        ...BASE_TRUST,
      })(action, async () => {}),
      OxDeAIDenyError
    );
    assert.equal(denyDecision, "DENY", `seed=${seed} onDecision must receive DENY`);

    // ALLOW path
    let allowDecision: string | undefined;
    let allowVersion = 0;
    await OxDeAIGuard({
      engine: makeAllowEngine(currentState),
      getState: () => ({ state: currentState, version: allowVersion }),
      setState: (s, v) => { if (v !== allowVersion) return false; currentState = s; allowVersion++; return true; },
      onDecision: ({ decision }) => { allowDecision = decision; },
      ...BASE_TRUST,
    })(action, async () => {});
    assert.equal(allowDecision, "ALLOW", `seed=${seed} onDecision must receive ALLOW`);
  }
});

// ── G7: onDecision errors never propagate ────────────────────────────────────

test("G7 onDecision hook errors never surface to the caller for any ProposedAction", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;

    let currentVersion = 0;
    const guard = OxDeAIGuard({
      engine: makeAllowEngine(currentState),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      onDecision: () => { throw new Error(`seed=${seed} hook explosion`); },
      ...BASE_TRUST,
    });

    // Must not throw despite the hook error
    await guard(action, async () => "ok");
  }
});

// ── generators: malformed / valid DENY reasons (#247) ─────────────────────────

/** Generates an arbitrary value that is never a valid `string[]` reasons array. */
function genMalformedReasons(rng: () => number): unknown {
  const kind = pick(rng, ["undefined", "null", "scalar", "object", "mixed-array"] as const);
  switch (kind) {
    case "undefined": return undefined;
    case "null": return null;
    case "scalar": return genScalar(rng);
    case "object": return genArgs(rng, 3);
    default: {
      // Guaranteed at least one non-string element, mixed in among zero or
      // more strings at a random position, so the array can never happen to
      // be all-strings by chance.
      const strCount = randInt(rng, 0, 3);
      const arr: unknown[] = Array.from({ length: strCount }, () => genAlphaStr(rng, 1, 8));
      const badElement = pick(rng, [42, true, null, {}, undefined] as const);
      arr.splice(randInt(rng, 0, arr.length), 0, badElement);
      return arr;
    }
  }
}

function genValidReasons(rng: () => number): string[] {
  const count = randInt(rng, 1, 4);
  return Array.from({ length: count }, () => genAlphaStr(rng, 3, 20).toUpperCase());
}

function makeMalformedDenyEngine(reasons: unknown): PolicyEngine {
  return { evaluatePure: () => ({ decision: "DENY" as const, reasons }) } as unknown as PolicyEngine;
}

function makeReasonsDenyEngine(reasons: string[]): PolicyEngine {
  return { evaluatePure: () => ({ decision: "DENY" as const, reasons }) } as unknown as PolicyEngine;
}

// ── G8: malformed DENY reasons always fail closed as an engine-contract violation (#247) ──

test("G8 malformed DENY reasons always fail closed as OxDeAIAuthorizationError, never execute, never onDecision", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;
    let currentVersion = 0;
    let executeCalled = false;
    let onDecisionCalled = false;

    const malformed = genMalformedReasons(rng);

    const guard = OxDeAIGuard({
      engine: makeMalformedDenyEngine(malformed),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      onDecision: () => { onDecisionCalled = true; },
      ...BASE_TRUST,
    });

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(
          err instanceof OxDeAIAuthorizationError,
          `seed=${seed} reasons=${JSON.stringify(malformed)} expected OxDeAIAuthorizationError, got ${Object.prototype.toString.call(err)}`
        );
        assert.ok(
          !(err instanceof OxDeAIDenyError),
          `seed=${seed} reasons=${JSON.stringify(malformed)} malformed DENY must never surface as OxDeAIDenyError`
        );
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called for malformed DENY reasons`);
    assert.ok(!onDecisionCalled, `seed=${seed} onDecision must not fire for malformed DENY reasons`);
  }
});

// ── G9: valid string[] DENY reasons still follow the normal DENY path (control) ──

test("G9 valid string[] DENY reasons always follow the normal DENY path (control)", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const action = genAction(rng);
    const agentId = action.context?.agent_id as string;
    const state = makePermissiveState(agentId);
    let currentState = state;
    let currentVersion = 0;
    let executeCalled = false;
    let capturedDecision: string | undefined;
    let capturedReasons: readonly string[] | undefined;

    const validReasons = genValidReasons(rng);

    const guard = OxDeAIGuard({
      engine: makeReasonsDenyEngine(validReasons),
      getState: () => ({ state: currentState, version: currentVersion }),
      setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
      onDecision: ({ decision, reasons }) => { capturedDecision = decision; capturedReasons = reasons; },
      ...BASE_TRUST,
    });

    await assert.rejects(
      () => guard(action, async () => { executeCalled = true; }),
      (err: unknown) => {
        assert.ok(err instanceof OxDeAIDenyError, `seed=${seed} expected OxDeAIDenyError`);
        assert.deepEqual(err.reasons, validReasons, `seed=${seed} reasons must pass through unchanged`);
        return true;
      },
      `seed=${seed}`
    );

    assert.ok(!executeCalled, `seed=${seed} execute must not be called on DENY`);
    assert.equal(capturedDecision, "DENY", `seed=${seed} onDecision must fire with DENY`);
    assert.deepEqual(capturedReasons, validReasons, `seed=${seed} onDecision must receive the same reasons`);
  }
});
