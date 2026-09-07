// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { sha256HexFromJson } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import {
  createPepGatewayExecutor,
  protectUpstreamExecution,
  INTERNAL_EXECUTOR_TOKEN_HEADER,
} from "../gateway.js";
import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";

const AUDIENCE = "gateway-test-audience";
/** Default fixture policy_id; see signAuth() in helpers/fixtures.ts. */
const POLICY_ID = "p".repeat(64);
/** #301: one explicit pair, never issuers x policies. */
const AUTHORITIES = [{ issuer: TEST_KEYSET.issuer, policyId: POLICY_ID }] as const;
const TOKEN = "internal-token-for-tests";
const ACTION = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

function makeAuth(overrides: Partial<AuthorizationV1> = {}): AuthorizationV1 {
  return signAuth({
    auth_id: `gateway-auth-${Date.now()}-${Math.random()}`,
    audience: AUDIENCE,
    intent_hash: sha256HexFromJson(ACTION),
    ...overrides,
  });
}

test("gateway valid AuthorizationV1 forwards with internal capability and executes", async () => {
  let upstreamCalled = false;
  const seenHeaders: Record<string, string>[] = [];
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async (_action, headers) => {
      upstreamCalled = true;
      seenHeaders.push(headers);
      return { status: 200, body: { ok: true, executed: true } };
    },
  });

  const result = await gateway({ action: ACTION, authorization: makeAuth() });

  assert.equal(result.status, 200);
  assert.equal(result.body.executed, true);
  assert.equal(upstreamCalled, true);
  assert.equal(seenHeaders[0]?.[INTERNAL_EXECUTOR_TOKEN_HEADER], TOKEN);
});

test("gateway missing AuthorizationV1 denies without upstream call", async () => {
  let upstreamCalled = false;
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      upstreamCalled = true;
      return { status: 200, body: {} };
    },
  });

  const result = await gateway({ action: ACTION });

  assert.equal(result.status, 403);
  assert.equal(result.body.decision, "DENY");
  assert.equal(result.body.executed, false);
  assert.equal(result.upstreamCalled, false);
  assert.equal(upstreamCalled, false);
});

test("gateway malformed request denies without upstream call", async () => {
  let upstreamCalled = false;
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      upstreamCalled = true;
      return { status: 200, body: {} };
    },
  });

  const result = await gateway(null);

  assert.equal(result.status, 403);
  assert.equal(result.body.decision, "DENY");
  assert.equal(result.body.executed, false);
  assert.equal(result.body.reason, "INVALID_REQUEST");
  assert.equal(result.upstreamCalled, false);
  assert.equal(upstreamCalled, false);
});

test("gateway invalid signature denies without upstream call", async () => {
  let upstreamCalled = false;
  const auth = makeAuth();
  auth.signature = "not-a-valid-signature";
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      upstreamCalled = true;
      return { status: 200, body: {} };
    },
  });

  const result = await gateway({ action: ACTION, authorization: auth });

  assert.equal(result.status, 403);
  assert.match(result.body.reason ?? "", /AUTH_SIGNATURE_INVALID|AUTH_SIGNATURE/);
  assert.equal(result.body.executed, false);
  assert.equal(upstreamCalled, false);
});

test("gateway intent mismatch denies without upstream call", async () => {
  let upstreamCalled = false;
  const auth = makeAuth({ intent_hash: "d".repeat(64) });
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      upstreamCalled = true;
      return { status: 200, body: {} };
    },
  });

  const result = await gateway({ action: ACTION, authorization: auth });

  assert.equal(result.status, 403);
  assert.equal(result.body.reason, "INTENT_HASH_MISMATCH");
  assert.equal(result.body.executed, false);
  assert.equal(upstreamCalled, false);
});

test("gateway auth_id replay denies second submission without upstream call", async () => {
  let upstreamCalls = 0;
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => {
      upstreamCalls += 1;
      return { status: 200, body: { ok: true } };
    },
  });
  const auth = makeAuth({ auth_id: "gateway-replay-auth" });

  const first = await gateway({ action: ACTION, authorization: auth });
  const second = await gateway({ action: ACTION, authorization: auth });

  assert.equal(first.status, 200);
  assert.equal(second.status, 403);
  assert.equal(second.body.reason, "AUTH_REPLAY");
  assert.equal(second.body.executed, false);
  assert.equal(upstreamCalls, 1);
});

test("protected upstream denies direct bypass without internal token", async () => {
  let executed = false;
  const direct = await protectUpstreamExecution(ACTION.params, {}, {
    expectedToken: TOKEN,
    execute: async () => {
      executed = true;
      return { ok: true };
    },
  });

  assert.equal(direct.status, 403);
  assert.equal(direct.executed, false);
  assert.equal(executed, false);
});

test("protected upstream denies direct bypass with invalid internal token", async () => {
  let executed = false;
  const direct = await protectUpstreamExecution(
    ACTION.params,
    { [INTERNAL_EXECUTOR_TOKEN_HEADER]: "wrong-token" },
    {
      expectedToken: TOKEN,
      execute: async () => {
        executed = true;
        return { ok: true };
      },
    }
  );

  assert.equal(direct.status, 403);
  assert.equal(direct.executed, false);
  assert.equal(executed, false);
});

test("protected upstream executes only with valid internal token", async () => {
  const result = await protectUpstreamExecution(
    ACTION.params,
    { [INTERNAL_EXECUTOR_TOKEN_HEADER]: TOKEN },
    {
      expectedToken: TOKEN,
      execute: async () => ({ ok: true, executed: true }),
    }
  );

  assert.equal(result.status, 200);
  assert.equal(result.executed, true);
});

test("gateway maps upstream error to 502 and never reports executed=true", async () => {
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    executeUpstream: async () => ({ status: 500, body: { error: "boom", executed: false } }),
  });

  const result = await gateway({ action: ACTION, authorization: makeAuth() });

  assert.equal(result.status, 502);
  assert.equal(result.body.reason, "UPSTREAM_ERROR");
  assert.notEqual(result.body.executed, true);
});

test("gateway maps upstream timeout to 504 and never reports executed=true", async () => {
  const gateway = createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: AUTHORITIES,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: TOKEN,
    timeoutMs: 10,
    executeUpstream: async () => new Promise((resolve) => setTimeout(() => resolve({ status: 200, body: {} }), 100)),
  });

  const result = await gateway({ action: ACTION, authorization: makeAuth() });

  assert.equal(result.status, 504);
  assert.equal(result.body.reason, "UPSTREAM_TIMEOUT");
  assert.notEqual(result.body.executed, true);
});
