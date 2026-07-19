// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import type { Authorization } from "@oxdeai/core";
import { InMemoryAuditAdapter, InMemoryStateAdapter, buildIntent } from "@oxdeai/sdk";

import { createAgentgramGuard, toTarget, toIntentInput } from "./adapter.js";
import { makeLiveEngine, makeLiveState } from "./policy-live.js";
import { AGENTGRAM_INTENTS } from "./intents.js";

// ── Fixtures ───────────────────────────────────────────────────────────────────

const AGENT_ID      = "test-agent";
const TARGET_AGENT  = "target-agent";
const POST_ID       = "post-001";
// createAgentgramGuard has no clock override — it always uses the SDK's
// default Date.now()-based clock for the trusted-time freshness gate's
// evaluationTime (see #184). NOW must therefore be real-time-derived, not a
// fixed historical constant, or every guard() call below would be denied
// with INTENT_STALE before reaching the property under test.
const NOW           = Math.floor(Date.now() / 1000);
const TEST_SECRET   = "test-secret-must-be-at-least-32-chars!!";

function makeGuard(postIds: string[] = [POST_ID]) {
  return createAgentgramGuard({
    engine:       makeLiveEngine(TEST_SECRET),
    agentId:      AGENT_ID,
    stateAdapter: new InMemoryStateAdapter(
      makeLiveState({ agentId: AGENT_ID, targetAgentName: TARGET_AGENT, postIds })
    ),
    auditAdapter: new InMemoryAuditAdapter(),
  });
}

// ── 1. Target mapping ──────────────────────────────────────────────────────────

test("toTarget: read_home -> agentgram:/home", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 1n }),
    "agentgram:/home"
  );
});

test("toTarget: read_feed -> agentgram:/feed", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.READ_FEED, nonce: 1n }),
    "agentgram:/feed"
  );
});

test("toTarget: post_like -> agentgram:/posts/{postId}/like", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.POST_LIKE, postId: "p-42", nonce: 1n }),
    "agentgram:/posts/p-42/like"
  );
});

test("toTarget: comment_create -> agentgram:/posts/{postId}/comments", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.COMMENT_CREATE, postId: "p-42", content: "nice", nonce: 1n }),
    "agentgram:/posts/p-42/comments"
  );
});

test("toTarget: register_agent -> agentgram:/agents/register", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.REGISTER_AGENT, agentName: "bot", description: "A bot", nonce: 1n }),
    "agentgram:/agents/register"
  );
});

test("toTarget: fetch_memory -> agentgram:/memories/{agentName}", () => {
  assert.equal(
    toTarget({ tool: AGENTGRAM_INTENTS.FETCH_MEMORY, agentName: "alice", nonce: 1n }),
    "agentgram:/memories/alice"
  );
});

// ── 2. Intent input mapping ────────────────────────────────────────────────────

test("toIntentInput: action_type is PROVISION", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 5n, timestampSeconds: NOW },
    AGENT_ID
  );
  assert.equal(input.action_type, "PROVISION");
});

test("toIntentInput: amount is 0n", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 5n, timestampSeconds: NOW },
    AGENT_ID
  );
  assert.equal(input.amount, 0n);
});

test("toIntentInput: tool_call is true", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 5n, timestampSeconds: NOW },
    AGENT_ID
  );
  assert.equal(input.tool_call, true);
});

test("toIntentInput: agent_id is passed through", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 5n, timestampSeconds: NOW },
    AGENT_ID
  );
  assert.equal(input.agent_id, AGENT_ID);
});

test("toIntentInput: nonce is preserved", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 42n, timestampSeconds: NOW },
    AGENT_ID
  );
  assert.equal(input.nonce, 42n);
});

test("toIntentInput: timestamp is preserved", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 5n, timestampSeconds: 1234567890 },
    AGENT_ID
  );
  assert.equal(input.timestamp, 1234567890);
});

test("toIntentInput: target matches action", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: "p-99", nonce: 1n },
    AGENT_ID
  );
  assert.equal(input.target, "agentgram:/posts/p-99/like");
});

test("toIntentInput: intent_id encodes tool and nonce", () => {
  const input = toIntentInput(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 7n },
    AGENT_ID
  );
  assert.equal(input.intent_id, `agentgram-${AGENTGRAM_INTENTS.READ_HOME}-7`);
});

// ── 3. Guard ALLOW tests ───────────────────────────────────────────────────────

test("guard: ALLOW read_home when target is allowed", async () => {
  const guard = makeGuard();
  let called = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 1n, timestampSeconds: NOW },
    async () => { called++; return "ok"; }
  );
  assert.equal(called, 1);
});

test("guard: ALLOW read_feed when target is allowed", async () => {
  const guard = makeGuard();
  let called = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.READ_FEED, nonce: 1n, timestampSeconds: NOW },
    async () => { called++; return "ok"; }
  );
  assert.equal(called, 1);
});

test("guard: ALLOW like_post when postId is in allowlist", async () => {
  const guard = makeGuard([POST_ID]);
  let called = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: POST_ID, nonce: 1n, timestampSeconds: NOW },
    async () => { called++; return "ok"; }
  );
  assert.equal(called, 1);
});

test("guard: ALLOW comment_post when postId is in allowlist", async () => {
  const guard = makeGuard([POST_ID]);
  let called = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.COMMENT_CREATE, postId: POST_ID, content: "Great post!", nonce: 1n, timestampSeconds: NOW },
    async () => { called++; return "ok"; }
  );
  assert.equal(called, 1);
});

test("guard: ALLOW fetch_memory when target agent is allowed", async () => {
  const guard = makeGuard();
  let called = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.FETCH_MEMORY, agentName: TARGET_AGENT, nonce: 1n, timestampSeconds: NOW },
    async () => { called++; return "ok"; }
  );
  assert.equal(called, 1);
});

// ── 4. Guard DENY tests ────────────────────────────────────────────────────────

test("guard: DENY replay nonce reuse", async () => {
  const guard = makeGuard();

  await guard(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 999n, timestampSeconds: NOW },
    async () => "first"
  );

  await assert.rejects(
    guard(
      { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 999n, timestampSeconds: NOW },
      async () => "replay"
    ),
    /DENY/
  );
});

test("guard: DENY like_post when postId is not in allowlist", async () => {
  const guard = makeGuard([POST_ID]);
  await assert.rejects(
    guard(
      { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: "invalid-post-id", nonce: 1n, timestampSeconds: NOW },
      async () => "should-not-run"
    ),
    /DENY/
  );
});

// ── 5. Execution boundary ──────────────────────────────────────────────────────

test("execution boundary: callback called exactly once on ALLOW", async () => {
  const guard = makeGuard();
  let calls = 0;
  await guard(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 100n, timestampSeconds: NOW },
    async () => { calls++; return "done"; }
  );
  assert.equal(calls, 1);
});

test("execution boundary: callback not called on DENY", async () => {
  const guard = makeGuard([]); // empty postIds → no post targets in allowlist
  let calls = 0;
  try {
    await guard(
      { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: POST_ID, nonce: 1n, timestampSeconds: NOW },
      async () => { calls++; return "ok"; }
    );
  } catch {
    // expected DENY
  }
  assert.equal(calls, 0);

});

test("does not call Agentgram API when DENY", async () => {
  const guard = makeGuard([]);
  let called = false;

  try {
    await guard(
      {
        tool: AGENTGRAM_INTENTS.POST_LIKE,
        postId: "invalid",
        nonce: 2n,
        timestampSeconds: NOW
      },
      async () => {
        called = true;
        return {};
      }
    );

    assert.fail("Expected DENY but got ALLOW");
  } catch (err) {
    assert.match(String(err), /DENY/);
  }

  assert.equal(called, false);
});

test("same input → same decision", async () => {
  const guard = makeGuard([POST_ID]);

  const action = {
    tool: AGENTGRAM_INTENTS.POST_LIKE,
    postId: POST_ID,
    nonce: 1n
  };

  const r1 = await guard(action, async () => "ok");
  const r2 = await guard({ ...action, nonce: 2n }, async () => "ok");

  assert.equal(r1, "ok");
  assert.equal(r2, "ok");
});

test("decision stable across state rebuild", async () => {
  const guard1 = makeGuard([POST_ID]);
  const guard2 = makeGuard([POST_ID]);

  const action = {
    tool: AGENTGRAM_INTENTS.POST_LIKE,
    postId: POST_ID,
    nonce: 1n
  };

  await guard1(action, async () => "ok");
  await guard2({ ...action, nonce: 2n }, async () => "ok");
});

test("decision can be verified independently", async () => {
  const engine = makeLiveEngine(TEST_SECRET);

  const state = makeLiveState({
    agentId: AGENT_ID,
    targetAgentName: TARGET_AGENT,
    postIds: [POST_ID]
  });

  const intent = buildIntent(
    toIntentInput(
      {
        tool: AGENTGRAM_INTENTS.POST_LIKE,
        postId: POST_ID,
        nonce: 123n,
        timestampSeconds: NOW
      },
      AGENT_ID
    )
  );

  const result = engine.evaluatePure(intent, state, intent.timestamp);

  assert.equal(result.decision, "ALLOW");
  assert.ok(result.authorization, "expected authorization on ALLOW");
  assert.ok(result.nextState, "expected nextState on ALLOW");

  // Cast as Authorization: runtime object retains internal engine fields even
  // though the TypeScript type was narrowed to AuthorizationV1 at evaluatePure boundary.
  const verification = engine.verifyAuthorization(
    intent,
    result.authorization! as Authorization,
    result.nextState!,
    intent.timestamp
  );

  assert.equal(verification.valid, true);
});

test("tampered intent fails verification", async () => {
  const engine = makeLiveEngine(TEST_SECRET);

  const state = makeLiveState({
    agentId: AGENT_ID,
    targetAgentName: TARGET_AGENT,
    postIds: [POST_ID]
  });

  const intent = buildIntent(
    toIntentInput(
      {
        tool: AGENTGRAM_INTENTS.POST_LIKE,
        postId: POST_ID,
        nonce: 124n,
        timestampSeconds: NOW
      },
      AGENT_ID
    )
  );

  const result = engine.evaluatePure(intent, state, intent.timestamp);

  assert.equal(result.decision, "ALLOW");
  assert.ok(result.authorization);
  assert.ok(result.nextState);

  const tamperedIntent = {
    ...intent,
    target: "agentgram:/posts/evil/like"
  };

  // Cast as Authorization: same rationale as above — internal HMAC verification.
  const verification = engine.verifyAuthorization(
    tamperedIntent,
    result.authorization! as Authorization,
    result.nextState!,
    intent.timestamp
  );

  assert.equal(verification.valid, false);
});
