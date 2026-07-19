// SPDX-License-Identifier: Apache-2.0
// packages/guard/src/test/guard.toctou.test.ts
//
// Guard-level TOCTOU and enforcement-boundary tests.
//
// Scenarios:
//   G-1  Sequential guard calls advance state → nonce replay blocked through PEP
//   G-2  Budget exhaustion → subsequent guard call denied
//   G-3  Reverification requirement: every guard call re-evaluates policy;
//        possessing a prior valid artifact does not grant access after state changes

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { TEST_KEYSET, TEST_KEYPAIR } from "./helpers/fixtures.js";
import { OxDeAIDenyError } from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const AGENT_ID = "agent-guard-toctou";
const T0 = Math.floor(Date.now() / 1000);

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret:  "guard-toctou-secret-32-bytes-ok!",
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: "aud-test",
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

/** Return a config backed by a mutable state variable.
 *  getState / setState close over the same reference. */
function makeStatefulConfig(
  engine: PolicyEngine,
  initialState: State,
  overrides: Partial<OxDeAIGuardConfig> = {}
): OxDeAIGuardConfig {
  let current = initialState;
  let version = 0;
  return {
    engine,
    getState: () => ({ state: current, version }),
    setState: (s, v) => { if (v !== version) return false; current = s; version++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

function makeAction(nonce: bigint, estimatedCost = 0): ProposedAction {
  return {
    name:           "provision_gpu",
    args:           { asset: "a100" },
    estimatedCost,
    resourceType:   "gpu",
    timestampSeconds: T0,
    context: {
      agent_id: AGENT_ID,
      target:   "gpu-pool",
      nonce,          // fixed nonce so the second call can replay it
      intent_id: `intent-${nonce.toString()}`,
    },
  };
}

// ── G-1: nonce replay blocked through PEP ────────────────────────────────────

test("G-1 sequential guard calls: state advances → nonce replay denied", async () => {
  const engine = makeEngine();
  const initial = buildState({
    agent_id:             AGENT_ID,
    allow_action_types:   ["PROVISION"],
    budget_limit:         1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent:       16,
  });

  const config = makeStatefulConfig(engine, initial);
  const guard  = OxDeAIGuard(config);

  const action = makeAction(999n);

  // First call: ALLOW, setState called, nonce recorded in state.
  let firstExecuted = false;
  await guard(action, async () => { firstExecuted = true; });
  assert.ok(firstExecuted, "first call must execute");

  // Second call with the same nonce against the advanced state: must DENY.
  let secondExecuted = false;
  await assert.rejects(
    () => guard(action, async () => { secondExecuted = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDenyError,
        `expected OxDeAIDenyError on replay, got: ${err}`);
      assert.ok(
        err.reasons.some((r) => r.includes("REPLAY")),
        `expected REPLAY reason, got: ${JSON.stringify(err.reasons)}`
      );
      return true;
    }
  );
  assert.ok(!secondExecuted, "second call with replayed nonce must not execute");
});

// ── G-2: budget exhaustion → subsequent call denied ──────────────────────────

test("G-2 budget exhaustion: spent budget blocks next guard call", async () => {
  const engine = makeEngine();

  // Budget of 2 units total; each call spends 1 unit (estimatedCost = 1e-6 → 1n).
  const initial = buildState({
    agent_id:             AGENT_ID,
    allow_action_types:   ["PROVISION"],
    budget_limit:         2n,            // 2 micro-units
    max_amount_per_action: 2n,
    velocity_max_actions: 1000,
    max_concurrent:       16,
  });

  const config = makeStatefulConfig(engine, initial);
  const guard  = OxDeAIGuard(config);

  // First call spends 1 unit (estimatedCost = 1e-6).
  let firstExecuted = false;
  await guard(makeAction(100n, 0.000001), async () => { firstExecuted = true; });
  assert.ok(firstExecuted, "first call must execute within budget");

  // Second call spends another unit — total becomes 2 which equals the limit.
  // (budget_limit = 2n, after first call spent_in_period = 1n, amount = 1n → 1+1 = 2 ≤ 2 → ALLOW)
  let secondExecuted = false;
  await guard(makeAction(101n, 0.000001), async () => { secondExecuted = true; });
  assert.ok(secondExecuted, "second call must execute at budget limit");

  // Third call would exceed the budget (2+1 = 3 > 2) → DENY.
  let thirdExecuted = false;
  await assert.rejects(
    () => guard(makeAction(102n, 0.000001), async () => { thirdExecuted = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDenyError,
        `expected OxDeAIDenyError when budget exhausted, got: ${err}`);
      assert.ok(
        err.reasons.some((r) => r.includes("BUDGET")),
        `expected BUDGET reason, got: ${JSON.stringify(err.reasons)}`
      );
      return true;
    }
  );
  assert.ok(!thirdExecuted, "third call must not execute when budget is exhausted");
});

// ── G-3: reverification requirement ──────────────────────────────────────────

test("G-3 reverification: state mutated between calls → policy re-evaluated each time", async () => {
  // Demonstrate that a guard call does not rely on a cached authorization from
  // a prior run. The guard always re-evaluates (getState → evaluatePure →
  // verifyAuthorization → execute). Even if you hold a valid auth artifact
  // from a previous call, you cannot inject it to bypass the guard.
  //
  // The observable proof: after the kill switch is engaged mid-run, a
  // subsequent guard call is denied — showing the guard checks live state,
  // not a stale artifact.

  const engine = makeEngine();
  const initial = buildState({
    agent_id:             AGENT_ID,
    allow_action_types:   ["PROVISION"],
    budget_limit:         1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent:       16,
  });

  let current = initial;
  let version = 0;
  const config: OxDeAIGuardConfig = {
    engine,
    getState: () => ({ state: current, version }),
    setState: (s, v) => { if (v !== version) return false; current = s; version++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);

  // First call succeeds and advances state.
  await guard(makeAction(200n), async () => {});

  // External mutation: engage kill switch on the shared state reference.
  current = { ...current, kill_switch: { global: true, agents: {} } };

  // Second call reads the live state (kill switch engaged) → must DENY.
  let secondExecuted = false;
  await assert.rejects(
    () => guard(makeAction(201n), async () => { secondExecuted = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDenyError,
        `expected OxDeAIDenyError after kill switch, got: ${err}`);
      assert.ok(
        err.reasons.some((r) => r.includes("KILL_SWITCH")),
        `expected KILL_SWITCH reason, got: ${JSON.stringify(err.reasons)}`
      );
      return true;
    }
  );
  assert.ok(!secondExecuted,
    "second call must not execute when kill switch is engaged on live state");
});
