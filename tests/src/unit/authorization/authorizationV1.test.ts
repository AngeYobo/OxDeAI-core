import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, verifyAuthorization } from "@oxdeai/core";
import { makeIntent } from "../../helpers/intent.js";
import { makeState } from "../../helpers/state.js";

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "unit-secret",
    authorization_ttl_seconds: 60,
    authorization_issuer: "issuer-A",
    authorization_audience: "rp-A",
    policyId: "a".repeat(64)
  });
}

function allowOutput() {
  const engine = makeEngine();
  const intent = makeIntent({
    nonce: 1n,
    amount: 1_000_000n,
    asset: "USDC",
    target: "t1",
    timestamp: 1000
  });
  const state = makeState({
    policy_version: "0.1.0",
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["t1"] },
    budget: { budget_limit: { "agent-1": 10_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 5_000_000n }
  });

  const out = engine.evaluatePure(intent, state);
  if (out.decision !== "ALLOW") {
    throw new Error(`expected ALLOW, got DENY: ${out.reasons.join(",")}`);
  }
  return { out, intent };
}

test("creation emits AuthorizationV1 fields on ALLOW", () => {
  const { out } = allowOutput();
  const auth = out.authorization;

  assert.equal(auth.decision, "ALLOW");
  assert.ok(typeof auth.auth_id === "string" && auth.auth_id.length > 0);
  assert.equal(auth.auth_id, auth.authorization_id);
  assert.equal(auth.issuer, "issuer-A");
  assert.equal(auth.audience, "rp-A");
  assert.equal(auth.state_hash, auth.state_snapshot_hash);
  assert.equal(auth.policy_id, "a".repeat(64));
  assert.equal(auth.expiry, auth.expires_at);
  assert.equal(auth.issued_at, 1000);
});

test("verification success", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, {
    now: 1010,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    expectedPolicyId: "a".repeat(64),
    consumedAuthIds: []
  });

  assert.equal(result.status, "ok");
  assert.equal(result.ok, true);
  assert.deepEqual(result.violations, []);
});

test("expiry failure", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, { now: auth.expiry });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_EXPIRED"));
});

test("replay protection (simulated consumed id)", () => {
  const { out } = allowOutput();
  const auth = out.authorization;
  const result = verifyAuthorization(auth, { now: 1010, consumedAuthIds: [auth.auth_id] });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_REPLAY"));
});

test("issuer mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedIssuer: "issuer-B" });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_ISSUER_MISMATCH"));
});

test("audience mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedAudience: "rp-B" });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_AUDIENCE_MISMATCH"));
});

test("policy mismatch", () => {
  const { out } = allowOutput();
  const result = verifyAuthorization(out.authorization, { now: 1010, expectedPolicyId: "b".repeat(64) });
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "AUTH_POLICY_ID_MISMATCH"));
});
