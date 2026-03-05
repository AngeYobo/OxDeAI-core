import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "@oxdeai/core";

import { InMemoryAuditAdapter, InMemoryStateAdapter } from "./adapters.js";
import { buildIntent, buildState } from "./builders.js";
import { OxDeAIClient } from "./client.js";

test("builder helpers create engine-compatible intent/state", () => {
  const state = buildState({
    policy_version: "v1",
    agent_id: "agent-1",
    allow_action_types: ["PROVISION"],
    allow_targets: ["us-east-1"]
  });
  const intent = buildIntent({
    intent_id: "intent-1",
    agent_id: "agent-1",
    action_type: "PROVISION",
    amount: 100n,
    target: "us-east-1",
    nonce: 1n,
    timestamp: 1_770_000_000
  });

  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "dev-secret",
    authorization_ttl_seconds: 60
  });
  const out = engine.evaluatePure(intent, state, { mode: "fail-fast" });
  assert.equal(out.decision, "ALLOW");
});

test("OxDeAIClient evaluate+persist+verify flow", async () => {
  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "dev-secret",
    authorization_ttl_seconds: 60
  });
  const stateAdapter = new InMemoryStateAdapter(
    buildState({
      policy_version: "v1",
      agent_id: "agent-1",
      allow_action_types: ["PROVISION"],
      allow_targets: ["us-east-1"]
    })
  );
  const auditAdapter = new InMemoryAuditAdapter();
  const client = new OxDeAIClient({
    engine,
    stateAdapter,
    auditAdapter,
    clock: { now: () => 1_770_000_000 }
  });

  const intent = buildIntent({
    intent_id: "intent-2",
    agent_id: "agent-1",
    action_type: "PROVISION",
    amount: 320n,
    target: "us-east-1",
    nonce: 2n
  });
  const res = await client.evaluateAndCommit(intent);

  assert.equal(res.output.decision, "ALLOW");
  if (res.output.decision !== "ALLOW") return;
  assert.ok(res.auditEvents.length >= 3);
  assert.equal(auditAdapter.snapshot().length, res.auditEvents.length);

  const auth = await client.verifyAuthorization(
    { ...intent, timestamp: 1_770_000_000 },
    res.output.authorization
  );
  assert.equal(auth.valid, true);

  const verify = await client.verifyCurrentArtifacts({ mode: "best-effort" });
  assert.equal(verify.snapshot.status, "ok");
  assert.equal(verify.audit.status, "ok");
  assert.equal(verify.envelope.status, "ok");
});
