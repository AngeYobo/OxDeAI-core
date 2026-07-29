// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";

import { InMemoryAuditAdapter, InMemoryStateAdapter } from "./adapters.js";
import { buildIntent, buildState } from "./builders.js";
import { OxDeAIClient } from "./client.js";
import { createGuard } from "./guard.js";

/**
 * Records the time argument the SDK hands to the engine, then delegates to the real
 * implementation so behaviour is unchanged. This is what lets the tests below assert
 * the verifier-time *argument* directly rather than inferring it from a verdict.
 */
class SpyEngine extends PolicyEngine {
  readonly evaluateTimes: number[] = [];
  readonly verifyTimes: Array<number | undefined> = [];

  override evaluatePure(
    ...args: Parameters<PolicyEngine["evaluatePure"]>
  ): ReturnType<PolicyEngine["evaluatePure"]> {
    this.evaluateTimes.push(args[2]);
    return super.evaluatePure(...args);
  }

  override verifyAuthorization(
    ...args: Parameters<PolicyEngine["verifyAuthorization"]>
  ): ReturnType<PolicyEngine["verifyAuthorization"]> {
    this.verifyTimes.push(args[3]);
    return super.verifyAuthorization(...args);
  }
}

function spyEngine() {
  return new SpyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function testState() {
  return buildState({
    policy_version: "v1",
    agent_id: "agent-1",
    allow_action_types: ["PROVISION"],
    allow_targets: ["us-east-1"]
  });
}

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
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const out = engine.evaluatePure(intent, state, intent.timestamp, { mode: "fail-fast" });
  assert.equal(out.decision, "ALLOW");
});

test("OxDeAIClient evaluate+persist+verify flow", async () => {
  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
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

test("client verification expires an authorization on the trusted clock, not intent.timestamp", async () => {
  const EVALUATION_TIME = 1_770_000_000;
  let trustedNow = EVALUATION_TIME;

  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const client = new OxDeAIClient({
    engine,
    stateAdapter: new InMemoryStateAdapter(
      buildState({
        policy_version: "v1",
        agent_id: "agent-1",
        allow_action_types: ["PROVISION"],
        allow_targets: ["us-east-1"]
      })
    ),
    clock: { now: () => trustedNow }
  });

  const fields = {
    intent_id: "intent-195",
    agent_id: "agent-1",
    action_type: "PROVISION" as const,
    amount: 100n,
    target: "us-east-1",
    nonce: 1n
  };
  const res = await client.evaluateAndCommit(buildIntent(fields));
  assert.equal(res.output.decision, "ALLOW");
  if (res.output.decision !== "ALLOW") return;

  // The intent exactly as evaluated: evaluateAndCommit filled `timestamp` from the
  // clock, so this reproduces the intent the authorization is hash-bound to.
  const issuedIntent = buildIntent({ ...fields, timestamp: EVALUATION_TIME });
  const expiry = Number(res.output.authorization.expiry);
  assert.ok(expiry > EVALUATION_TIME);

  trustedNow = expiry - 1;
  assert.deepEqual(await client.verifyAuthorization(issuedIntent, res.output.authorization), {
    valid: true
  });

  // Only the trusted clock moves past expiry; the intent is byte-identical. Reading
  // verifier time from intent.timestamp would pin it at the intent's own value and
  // accept this authorization forever.
  trustedNow = expiry + 1;
  assert.deepEqual(await client.verifyAuthorization(issuedIntent, res.output.authorization), {
    valid: false,
    reason: "AUTH_EXPIRED"
  });
});

test("client forwards the trusted verification time to the engine verifier", async () => {
  const CLOCK_T = 1_770_000_000;
  const EXPLICIT_T = 1_770_000_042;
  const engine = spyEngine();
  const client = new OxDeAIClient({
    engine,
    stateAdapter: new InMemoryStateAdapter(testState()),
    clock: { now: () => CLOCK_T }
  });

  const fields = {
    intent_id: "intent-195-spy",
    agent_id: "agent-1",
    action_type: "PROVISION" as const,
    amount: 100n,
    target: "us-east-1",
    nonce: 1n
  };
  const res = await client.evaluateAndCommit(buildIntent(fields));
  assert.equal(res.output.decision, "ALLOW");
  if (res.output.decision !== "ALLOW") return;
  const authorization = res.output.authorization;
  engine.verifyTimes.length = 0;

  // Without an explicit time, the trusted clock is what reaches the engine.
  await client.verifyAuthorization(buildIntent({ ...fields, timestamp: CLOCK_T }), authorization);
  assert.deepEqual(engine.verifyTimes, [CLOCK_T]);

  // An explicit verificationTime takes precedence over the clock.
  await client.verifyAuthorization(buildIntent({ ...fields, timestamp: CLOCK_T }), authorization, {
    verificationTime: EXPLICIT_T
  });
  assert.deepEqual(engine.verifyTimes, [CLOCK_T, EXPLICIT_T]);

  // Varying only intent.timestamp must not move the verifier-time argument. These
  // calls fail the intent-hash check, which is irrelevant here: the assertion is on
  // what the SDK passed, not on the verdict it got back.
  for (const timestamp of [CLOCK_T - 120, CLOCK_T + 120, CLOCK_T + 240]) {
    await client.verifyAuthorization(buildIntent({ ...fields, timestamp }), authorization);
  }
  assert.deepEqual(engine.verifyTimes, [CLOCK_T, EXPLICIT_T, CLOCK_T, CLOCK_T, CLOCK_T]);
});

test("guard forwards its single evaluationTime sample to the engine verifier", async () => {
  const CLOCK_T = 1_770_000_000;
  const INTENT_T = CLOCK_T + 200;
  const engine = spyEngine();
  const guard = createGuard({
    engine,
    stateAdapter: new InMemoryStateAdapter(testState()),
    clock: { now: () => CLOCK_T }
  });

  const result = await guard(
    buildIntent({
      intent_id: "intent-195-guard-spy",
      agent_id: "agent-1",
      action_type: "PROVISION",
      amount: 100n,
      target: "us-east-1",
      nonce: 1n,
      timestamp: INTENT_T
    }),
    async () => "executed"
  );
  assert.equal(result.output.decision, "ALLOW");

  // One clock sample, used for evaluation and for verification, and not the intent's
  // own timestamp even though the intent carries a different one.
  assert.deepEqual(engine.evaluateTimes, [CLOCK_T]);
  assert.deepEqual(engine.verifyTimes, [CLOCK_T]);
  assert.notEqual(CLOCK_T, INTENT_T);
});

test("expired authorizations are rejected on the trusted clock regardless of intent timestamp", async () => {
  const EVALUATION_TIME = 1_770_000_000;

  // Issues one authorization at a caller-chosen intent timestamp. The trusted clock is
  // pinned to EVALUATION_TIME in every case, so the only thing that varies is the
  // intent's own claimed timestamp — which the trusted-time profile permits within ±300s.
  async function issueAt(intentTimestamp: number) {
    const engine = new PolicyEngine({
      policy_version: "v1",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_ttl_seconds: 60,
      ...RECOMMENDED_TRUSTED_TIME_PROFILE
    });
    let trustedNow = EVALUATION_TIME;
    const client = new OxDeAIClient({
      engine,
      stateAdapter: new InMemoryStateAdapter(
        buildState({
          policy_version: "v1",
          agent_id: "agent-1",
          allow_action_types: ["PROVISION"],
          allow_targets: ["us-east-1"]
        })
      ),
      clock: { now: () => trustedNow }
    });
    const fields = {
      intent_id: "intent-195-indep",
      agent_id: "agent-1",
      action_type: "PROVISION" as const,
      amount: 100n,
      target: "us-east-1",
      nonce: 1n,
      timestamp: intentTimestamp
    };
    const res = await client.evaluateAndCommit(buildIntent(fields));
    assert.equal(res.output.decision, "ALLOW");
    if (res.output.decision !== "ALLOW") throw new Error("expected ALLOW");
    const authorization = res.output.authorization;
    return {
      authorization,
      verifyAt: (t: number) => {
        trustedNow = t;
        return client.verifyAuthorization(buildIntent(fields), authorization);
      }
    };
  }

  // Two authorizations whose intents differ only in `timestamp`, 190s apart.
  const early = await issueAt(EVALUATION_TIME + 10);
  const late = await issueAt(EVALUATION_TIME + 200);

  // Deadlines are read from the artifacts rather than asserted, so this test makes no
  // claim about whether expiry is derived from intent.timestamp or evaluation_time and
  // stays valid when that changes.
  const TRUSTED =
    Math.max(Number(early.authorization.expiry), Number(late.authorization.expiry)) + 1;

  // A single trusted verification time, past both deadlines. Both must be rejected,
  // and identically — the verdict follows the trusted clock, not how recent each
  // intent claims to be.
  const earlyResult = await early.verifyAt(TRUSTED);
  const lateResult = await late.verifyAt(TRUSTED);
  assert.deepEqual(earlyResult, lateResult);
  assert.deepEqual(earlyResult, { valid: false, reason: "AUTH_EXPIRED" });
});
