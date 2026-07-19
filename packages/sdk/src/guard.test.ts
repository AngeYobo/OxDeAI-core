// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";

import { InMemoryAuditAdapter, InMemoryStateAdapter } from "./adapters.js";
import { buildIntent, buildState } from "./builders.js";
import { createGuard } from "./guard.js";

function makeEngine() {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    authorization_issuer: "issuer-A",
    authorization_audience: "rp-A",
    policyId: "a".repeat(64),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeAllowState() {
  return buildState({
    policy_version: "v1",
    agent_id: "agent-1",
    allow_action_types: ["PROVISION"],
    allow_targets: ["us-east-1"],
    budget_limit: 1_000n,
    spent_in_period: 0n,
    max_amount_per_action: 500n,
  });
}

test("guard executes callback on ALLOW", async () => {
  const engine = makeEngine();
  const stateAdapter = new InMemoryStateAdapter(makeAllowState());
  const auditAdapter = new InMemoryAuditAdapter();
  const guard = createGuard({
    engine,
    stateAdapter,
    auditAdapter,
    clock: { now: () => 1_770_000_000 },
  });

  let called = 0;
  const result = await guard(
    buildIntent({
      intent_id: "intent-allow-1",
      agent_id: "agent-1",
      action_type: "PROVISION",
      amount: 500n,
      target: "us-east-1",
      nonce: 1n,
    }),
    async () => {
      called++;
      return "ok";
    }
  );

  assert.equal(called, 1);
  assert.equal(result.executed, true);
  assert.equal(result.output.decision, "ALLOW");
  if (result.executed) assert.equal(result.executionResult, "ok");
  assert.ok(auditAdapter.snapshot().length > 0);
});

test("guard does not execute callback on DENY", async () => {
  const engine = makeEngine();
  const stateAdapter = new InMemoryStateAdapter(makeAllowState());
  const guard = createGuard({
    engine,
    stateAdapter,
    clock: { now: () => 1_770_000_000 },
  });

  let called = 0;
  const result = await guard(
    buildIntent({
      intent_id: "intent-deny-1",
      agent_id: "agent-1",
      action_type: "PROVISION",
      amount: 900n,
      target: "us-east-1",
      nonce: 2n,
    }),
    async () => {
      called++;
      return "should-not-run";
    }
  );

  assert.equal(called, 0);
  assert.equal(result.executed, false);
  assert.equal(result.output.decision, "DENY");
});

test("guard enforces authorization verification at callback boundary", async () => {
  const engine = makeEngine();
  const original = engine.verifyAuthorization.bind(engine);
  (engine as any).verifyAuthorization = () => ({ valid: false, reason: "forced-test-failure" });

  const stateAdapter = new InMemoryStateAdapter(makeAllowState());
  const guard = createGuard({
    engine,
    stateAdapter,
    clock: { now: () => 1_770_000_000 },
  });

  let called = 0;
  const result = await guard(
    buildIntent({
      intent_id: "intent-allow-auth-check",
      agent_id: "agent-1",
      action_type: "PROVISION",
      amount: 500n,
      target: "us-east-1",
      nonce: 3n,
    }),
    async () => {
      called++;
      return "should-not-run";
    }
  );

  assert.equal(called, 0);
  assert.equal(result.executed, false);
  assert.equal(result.output.decision, "DENY");
  assert.ok(result.output.reasons.some((r) => r.startsWith("AUTH_INVALID:")));

  (engine as any).verifyAuthorization = original;
});

test("guard output is deterministic for equivalent inputs", async () => {
  const intent = buildIntent({
    intent_id: "intent-deterministic-1",
    agent_id: "agent-1",
    action_type: "PROVISION",
    amount: 500n,
    target: "us-east-1",
    nonce: 10n,
    timestamp: 1_770_000_000,
  });

  const g1 = createGuard({
    engine: makeEngine(),
    stateAdapter: new InMemoryStateAdapter(makeAllowState()),
    clock: { now: () => 1_770_000_000 },
  });
  const g2 = createGuard({
    engine: makeEngine(),
    stateAdapter: new InMemoryStateAdapter(makeAllowState()),
    clock: { now: () => 1_770_000_000 },
  });

  const r1 = await g1(intent, async () => "ok");
  const r2 = await g2(intent, async () => "ok");

  assert.equal(r1.output.decision, "ALLOW");
  assert.equal(r2.output.decision, "ALLOW");
  if (r1.output.decision === "ALLOW" && r2.output.decision === "ALLOW") {
    assert.equal(r1.output.authorization.auth_id, r2.output.authorization.auth_id);
    assert.equal(r1.output.authorization.state_hash, r2.output.authorization.state_hash);
    assert.equal(r1.output.authorization.intent_hash, r2.output.authorization.intent_hash);
  }
});
