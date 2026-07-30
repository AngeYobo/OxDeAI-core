// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import fc from "fast-check";

import { PolicyEngine, type EngineOptions } from "../policy/PolicyEngine.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";
const EVALUATION_TIME = 1_730_000_000;
const TTL = 60;
const SECRET = "trusted-issuance-test-secret-32chars!!";
const AGENT = "agent-1";
const TEST_PRIVATE_KEY_PEM = generateKeyPairSync("ed25519").privateKey.export({
  type: "pkcs8",
  format: "pem",
}).toString();

function makeEngine(overrides: Partial<EngineOptions> = {}): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1-issuance",
    engine_secret: SECRET,
    authorization_ttl_seconds: TTL,
    maxClockSkewSeconds: 300,
    maxIntentAgeSeconds: 300,
    ...overrides,
  });
}

function makeState(overrides: Partial<State> = {}): State {
  return {
    policy_version: "v1-issuance",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PAYMENT"],
      assets: ["wallet"],
      targets: ["merchant-1"],
    },
    budget: {
      budget_limit: { [AGENT]: 1_000_000n },
      spent_in_period: { [AGENT]: 0n },
    },
    max_amount_per_action: { [AGENT]: 1_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 100 }, calls: {} },
    ...overrides,
  };
}

function makeIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intent_id: "intent-1",
    agent_id: AGENT,
    action_type: "PAYMENT",
    amount: 100n,
    asset: "wallet",
    target: "merchant-1",
    timestamp: EVALUATION_TIME,
    metadata_hash: "0".repeat(64),
    nonce: 1n,
    signature: "sig",
    depth: 0,
    type: "EXECUTE",
    ...overrides,
  } as Intent;
}

function issue(
  engine: PolicyEngine,
  intent: Intent,
  state = makeState(),
  evaluationTime = EVALUATION_TIME,
) {
  const out = engine.evaluatePure(intent, state, evaluationTime);
  assert.equal(out.decision, "ALLOW");
  if (out.decision !== "ALLOW") throw new Error("expected ALLOW");
  return out;
}

test("trusted issuance covers intent timestamps before, equal to, and after evaluationTime", () => {
  for (const [index, intentTimestamp] of [
    EVALUATION_TIME - 300,
    EVALUATION_TIME,
    EVALUATION_TIME + 300,
  ].entries()) {
    const out = issue(
      makeEngine(),
      makeIntent({ intent_id: `intent-${index}`, nonce: BigInt(index + 1), timestamp: intentTimestamp }),
    );
    assert.equal(out.authorization.issued_at, EVALUATION_TIME);
    assert.equal(out.authorization.expiry, EVALUATION_TIME + TTL);
    assert.equal(out.authorization.expiry - out.authorization.issued_at, TTL);
  }
});

test("freshness-valid intent.timestamp changes cannot shift the issued validity window", () => {
  const earlier = issue(makeEngine(), makeIntent({ timestamp: EVALUATION_TIME - 20 }));
  const later = issue(makeEngine(), makeIntent({ timestamp: EVALUATION_TIME + 20 }));

  assert.deepEqual(
    [earlier.authorization.issued_at, earlier.authorization.expiry],
    [later.authorization.issued_at, later.authorization.expiry],
  );
  assert.notEqual(earlier.authorization.intent_hash, later.authorization.intent_hash);
  assert.notEqual(earlier.authorization.auth_id, later.authorization.auth_id);
  assert.notEqual(earlier.authorization.signature, later.authorization.signature);
});

test("changing only evaluationTime shifts issued_at and expiry by the same amount", () => {
  const intent = makeIntent({ timestamp: EVALUATION_TIME });
  const first = issue(makeEngine(), intent, makeState(), EVALUATION_TIME);
  const second = issue(makeEngine(), intent, makeState(), EVALUATION_TIME + 10);

  assert.equal(second.authorization.issued_at - first.authorization.issued_at, 10);
  assert.equal(second.authorization.expiry - first.authorization.expiry, 10);
  assert.equal(first.authorization.expiry - first.authorization.issued_at, TTL);
  assert.equal(second.authorization.expiry - second.authorization.issued_at, TTL);
});

test("undefined TTL uses the existing 60-second default and no other invalid value does", () => {
  const defaultEngine = makeEngine({ authorization_ttl_seconds: undefined });
  const out = issue(defaultEngine, makeIntent());
  assert.equal(out.authorization.expiry - out.authorization.issued_at, 60);

  const invalidTtls: unknown[] = [
    null,
    "60",
    NaN,
    Infinity,
    -Infinity,
    1.5,
    0,
    -1,
    Number.MAX_SAFE_INTEGER + 1,
  ];
  for (const ttl of invalidTtls) {
    assert.throws(
      () => makeEngine({ authorization_ttl_seconds: ttl as number }),
      /authorization_ttl_seconds/,
      `TTL ${String(ttl)} must be rejected rather than defaulted or coerced`,
    );
  }
});

test("unsafe expiry arithmetic rejects before audit, authorization construction, or signing", () => {
  const engine = makeEngine({
    authorization_signing_alg: "Ed25519",
    authorization_private_key_pem: undefined,
  });
  const evaluationTime = Number.MAX_SAFE_INTEGER - TTL + 1;

  assert.throws(
    () =>
      engine.evaluatePure(
        makeIntent({ timestamp: evaluationTime }),
        makeState(),
        evaluationTime,
      ),
    /safe integer/,
  );
  assert.deepEqual(engine.audit.snapshot(), []);
});

test("freshness denial produces no authorization and does not reach signing", () => {
  const engine = makeEngine({
    authorization_signing_alg: "Ed25519",
    authorization_private_key_pem: undefined,
  });
  const out = engine.evaluatePure(
    makeIntent({ timestamp: EVALUATION_TIME + 301 }),
    makeState(),
    EVALUATION_TIME,
  );
  assert.deepEqual(out, {
    decision: "DENY",
    reasons: ["INTENT_FRESHNESS_FUTURE"],
  });
});

test("EXECUTE and RELEASE share trusted-time issuance", () => {
  const execute = issue(
    makeEngine(),
    makeIntent({ type: "EXECUTE", nonce: 10n, timestamp: EVALUATION_TIME - 1 }),
  );
  assert.equal(execute.authorization.issued_at, EVALUATION_TIME);
  assert.equal(
    execute.nextState.concurrency.active_auths[AGENT]?.[execute.authorization.auth_id]?.expires_at,
    EVALUATION_TIME + TTL,
  );

  const releasedId = "existing-authorization";
  const releaseState = makeState({
    concurrency: {
      max_concurrent: { [AGENT]: 10 },
      active: { [AGENT]: 1 },
      active_auths: {
        [AGENT]: { [releasedId]: { expires_at: EVALUATION_TIME + 600 } },
      },
    },
  });
  const release = issue(
    makeEngine(),
    makeIntent({
      type: "RELEASE",
      authorization_id: releasedId,
      nonce: 11n,
      timestamp: EVALUATION_TIME + 1,
    }),
    releaseState,
  );
  assert.equal(release.authorization.issued_at, EVALUATION_TIME);
  assert.equal(release.authorization.expiry, EVALUATION_TIME + TTL);
});

test("expiry remains an exclusive upper bound", () => {
  const out = issue(makeEngine(), makeIntent());
  const common = {
    expectedIssuer: out.authorization.issuer,
    expectedAudience: out.authorization.audience,
    expectedPolicyId: out.authorization.policy_id,
    legacyHmacSecret: SECRET,
  };

  assert.equal(
    verifyAuthorization(out.authorization, {
      ...common,
      now: out.authorization.expiry - 1,
    }).status,
    "ok",
  );
  assert.equal(
    verifyAuthorization(out.authorization, {
      ...common,
      now: out.authorization.expiry,
    }).status,
    "invalid",
  );
});

test("identical trusted inputs produce deterministic Ed25519 authorizations", () => {
  const options = {
    authorization_signing_alg: "Ed25519" as const,
    authorization_signing_kid: "test-key",
    authorization_private_key_pem: TEST_PRIVATE_KEY_PEM,
  };
  const first = issue(makeEngine(options), makeIntent());
  const second = issue(makeEngine(options), makeIntent());

  assert.deepEqual(first.authorization, second.authorization);
  assert.equal(first.authorization.issued_at, EVALUATION_TIME);
  assert.equal(first.authorization.expiry, EVALUATION_TIME + TTL);
});

test("property: every successful authorization has a safe trusted-time fixed-TTL window", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1_000_000, max: 2_000_000_000 }),
      fc.integer({ min: -300, max: 300 }),
      fc.integer({ min: 1, max: 1_000_000 }),
      (evaluationTime, offset, nonce) => {
        const out = issue(
          makeEngine(),
          makeIntent({
            intent_id: `intent-${nonce}`,
            nonce: BigInt(nonce),
            timestamp: evaluationTime + offset,
          }),
          makeState(),
          evaluationTime,
        );
        assert.equal(out.authorization.issued_at, evaluationTime);
        assert.equal(out.authorization.expiry - out.authorization.issued_at, TTL);
        assert.ok(Number.isFinite(out.authorization.issued_at));
        assert.ok(Number.isSafeInteger(out.authorization.issued_at));
        assert.ok(Number.isFinite(out.authorization.expiry));
        assert.ok(Number.isSafeInteger(out.authorization.expiry));
      },
    ),
  );
});

test("property: freshness-valid intent timestamps do not affect the issued window", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1_000_000, max: 2_000_000_000 }),
      fc.integer({ min: -300, max: 300 }),
      fc.integer({ min: -300, max: 300 }),
      (evaluationTime, firstOffset, secondOffset) => {
        const first = issue(
          makeEngine(),
          makeIntent({ timestamp: evaluationTime + firstOffset }),
          makeState(),
          evaluationTime,
        );
        const second = issue(
          makeEngine(),
          makeIntent({ timestamp: evaluationTime + secondOffset }),
          makeState(),
          evaluationTime,
        );
        assert.deepEqual(
          [first.authorization.issued_at, first.authorization.expiry],
          [second.authorization.issued_at, second.authorization.expiry],
        );
      },
    ),
  );
});

test("property: freshness denial never includes an authorization", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1_000_000, max: 2_000_000_000 }),
      fc.boolean(),
      (evaluationTime, future) => {
        const timestamp = future ? evaluationTime + 301 : evaluationTime - 301;
        const out = makeEngine().evaluatePure(
          makeIntent({ timestamp }),
          makeState(),
          evaluationTime,
        );
        assert.equal(out.decision, "DENY");
        assert.equal("authorization" in out, false);
      },
    ),
  );
});

test("property: nondecreasing trusted evaluation times produce nondecreasing issued_at", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1_000_000, max: 2_000_000_000 }),
      fc.integer({ min: 0, max: 300 }),
      (firstEvaluationTime, delta) => {
        const intent = makeIntent({ timestamp: firstEvaluationTime });
        const first = issue(
          makeEngine(),
          intent,
          makeState(),
          firstEvaluationTime,
        );
        const second = issue(
          makeEngine(),
          intent,
          makeState(),
          firstEvaluationTime + delta,
        );
        assert.ok(second.authorization.issued_at >= first.authorization.issued_at);
      },
    ),
  );
});
