// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import { verifySnapshot } from "../verification/verifySnapshot.js";
import type { State } from "../types/state.js";

function baseState(): State {
  return {
    policy_version: "v0.9-test",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-1": 10_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 5_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 100 },
      counters: {}
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 2 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 3 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 10 },
      calls: {}
    }
  };
}

function buildSnapshotBytes() {
  const engine = new PolicyEngine({
    policy_version: "v0.9-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const snapshot = engine.exportState(baseState());
  return { engine, snapshot, bytes: encodeCanonicalState(snapshot) };
}

test("verifySnapshot ok on encoded canonical snapshot", () => {
  const { engine, bytes } = buildSnapshotBytes();

  const out = verifySnapshot(bytes);
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
  assert.equal(out.policyId, engine.computePolicyId());
  assert.ok(typeof out.stateHash === "string" && out.stateHash.length === 64);
});

test("verifySnapshot detects policy mismatch", () => {
  const { bytes } = buildSnapshotBytes();

  const out = verifySnapshot(bytes, { expectedPolicyId: "deadbeef" });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "POLICY_ID_MISMATCH"));
});

test("verifySnapshot fails on corrupt bytes", () => {
  const out = verifySnapshot(new Uint8Array([1, 2, 3]));
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "SNAPSHOT_CORRUPT"));
});

test("verifySnapshot fails on unsupported formatVersion", () => {
  const { snapshot } = buildSnapshotBytes();
  const bad = {
    ...snapshot,
    formatVersion: 2
  };
  const bytes = new TextEncoder().encode(JSON.stringify(bad));

  const out = verifySnapshot(bytes);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "SNAPSHOT_CORRUPT"));
});

test("verifySnapshot fails on malformed modules", () => {
  const { snapshot } = buildSnapshotBytes();
  const bad = {
    ...snapshot,
    modules: "bad"
  };
  const bytes = new TextEncoder().encode(JSON.stringify(bad));

  const out = verifySnapshot(bytes);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "SNAPSHOT_CORRUPT"));
});
