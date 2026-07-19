// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import { verifySnapshot } from "../verification/verifySnapshot.js";
import { verifyAuditEvents } from "../verification/verifyAuditEvents.js";
import { encodeEnvelope } from "../verification/envelope.js";
import { verifyEnvelope } from "../verification/verifyEnvelope.js";
import type { AuditEntry } from "../audit/AuditLog.js";
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

function makeEngine() {
  return new PolicyEngine({
    policy_version: "v0.9-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function makeEvents(policyId: string, withCheckpoint = false): AuditEntry[] {
  const events: AuditEntry[] = [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-1",
      agent_id: "agent-1",
      timestamp: 100,
      policyId
    },
    {
      type: "DECISION",
      intent_hash: "ih-1",
      decision: "ALLOW",
      reasons: [],
      policy_version: "v0.9-test",
      timestamp: 101,
      policyId
    }
  ];
  if (withCheckpoint) {
    events.push({
      type: "STATE_CHECKPOINT",
      stateHash: "a".repeat(64),
      timestamp: 102,
      policyId
    });
  }
  return events;
}

test("snapshot verifier returns unified structure", () => {
  const engine = makeEngine();
  const bytes = encodeCanonicalState(engine.exportState(baseState()));

  const result = verifySnapshot(bytes);
  assert.equal(typeof result.ok, "boolean");
  assert.ok(result.status === "ok" || result.status === "invalid" || result.status === "inconclusive");
  assert.ok(Array.isArray(result.violations));
  assert.equal(result.status, "ok");
});

test("audit verifier returns unified structure", () => {
  const result = verifyAuditEvents(makeEvents("policy-A", true), { mode: "strict" });
  assert.equal(typeof result.ok, "boolean");
  assert.equal(result.status, "ok");
  assert.ok(Array.isArray(result.violations));
  assert.ok(typeof result.auditHeadHash === "string" && result.auditHeadHash.length === 64);
});

test("envelope verifier returns unified structure with propagated hashes", () => {
  const engine = makeEngine();
  const policyId = engine.computePolicyId();
  const snapshotBytes = encodeCanonicalState(engine.exportState(baseState()));
  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: makeEvents(policyId, true)
  });

  const result = verifyEnvelope(envelopeBytes, { mode: "best-effort" });
  assert.equal(result.ok, true);
  assert.equal(result.status, "ok");
  assert.equal(result.policyId, policyId);
  assert.ok(typeof result.stateHash === "string" && result.stateHash.length === 64);
  assert.ok(typeof result.auditHeadHash === "string" && result.auditHeadHash.length === 64);
});

test("deterministic violation ordering", () => {
  const events: AuditEntry[] = [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-1",
      agent_id: "agent-1",
      timestamp: 100,
      policyId: "p2"
    },
    {
      type: "DECISION",
      intent_hash: "ih-1",
      decision: "ALLOW",
      reasons: [],
      policy_version: "v0.9-test",
      timestamp: 99,
      policyId: "p1"
    }
  ];

  const result = verifyAuditEvents(events, { mode: "best-effort" });
  assert.equal(result.status, "invalid");
  const sorted = [...result.violations].sort(
    (a, b) => a.code.localeCompare(b.code) || ((a.index ?? 0) - (b.index ?? 0))
  );
  assert.deepEqual(result.violations, sorted);
});
