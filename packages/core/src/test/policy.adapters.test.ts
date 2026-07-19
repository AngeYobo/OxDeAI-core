// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { InMemoryAuditSink } from "../adapters/InMemory.js";
import type { AuditEvent } from "../audit/AuditLog.js";
import type { AuditSink } from "../adapters/types.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";

function makeState(): State {
  return {
    policy_version: "v0.6-test",
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
      max_nonces_per_agent: 128,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 4 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 3 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 100 },
      calls: {}
    }
  };
}

function makeIntent(nonce: bigint): Intent {
  return {
    intent_id: `intent-${nonce.toString()}`,
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: 10n,
    target: "merchant-a",
    timestamp: 1_700_000_000 + Number(nonce),
    metadata_hash: "0x01",
    nonce,
    signature: "sig",
    type: "EXECUTE",
    depth: 0
  };
}

class AsyncAuditSink implements AuditSink {
  public readonly events: AuditEvent[] = [];

  append(event: AuditEvent): Promise<void> {
    return Promise.resolve().then(() => {
      this.events.push(structuredClone(event));
    });
  }
}

test("audit sink receives events in-order", async () => {
  const sink = new InMemoryAuditSink();
  const engine = new PolicyEngine({
    policy_version: "v0.6-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    auditSink: sink,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const out = engine.evaluatePure(makeIntent(1n), makeState(), 1_700_000_001, { mode: "fail-fast" });
  assert.equal(out.decision, "ALLOW");

  await engine.flushAudit();

  const emitted = engine.audit.snapshot().map((e) => e.type);
  const mirrored = sink.drain().map((e) => e.type);
  assert.deepEqual(mirrored, emitted);
});

test("async audit sink preserves event order after flush", async () => {
  const sink = new AsyncAuditSink();
  const engine = new PolicyEngine({
    policy_version: "v0.6-test",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    auditSink: sink,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  const s0 = makeState();
  const r1 = engine.evaluatePure(makeIntent(11n), s0, 1_700_000_011, { mode: "fail-fast" });
  assert.equal(r1.decision, "ALLOW");
  const r2 = engine.evaluatePure(makeIntent(12n), r1.nextState, 1_700_000_012, { mode: "fail-fast" });
  assert.equal(r2.decision, "ALLOW");

  await engine.flushAudit();

  const emitted = engine.audit.snapshot().map((e) => e.type);
  const mirrored = sink.events.map((e) => e.type);
  assert.deepEqual(mirrored, emitted);
});
