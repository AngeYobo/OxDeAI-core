// SPDX-License-Identifier: Apache-2.0
/**
 * replay.trusted-time.test.ts
 *
 * #191: replay-window eviction is driven exclusively by the trusted
 * evaluation clock, never by `intent.timestamp` / `issued_at` / `expiry` /
 * an ambient `Date.now()`.
 *
 * The tests below pin three things separately, because they can regress
 * independently:
 *
 *  1. WINDOW  — `windowStart` is derived from `evaluationTime`.
 *  2. STAMP   — newly recorded nonces carry `evaluationTime`.
 *  3. COMPAT  — legacy entries stamped from `intent.timestamp` are read as
 *               persisted values without conversion, and age out against the
 *               trusted clock (the self-healing, no-migration path).
 *
 * Note on direction: retention is `entry.ts >= windowStart`, so POSTdating an
 * intent is the eviction bypass — it moves `windowStart` forward and prunes
 * entries. Backdating retains more. Any test meant to demonstrate the fix must
 * postdate where it asserts eviction is prevented, and backdate where it
 * asserts pruning still happens; using the other direction yields a test that
 * passes against the intent-clock implementation too and proves nothing.
 *
 * Every fixture keeps `intent.timestamp` numerically distinct from
 * `evaluationTime`, so a module that reads the wrong clock cannot
 * accidentally pass. A test that used the same value for both would be
 * vacuous here.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { ReplayModule } from "../policy/modules/ReplayModule.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { PolicyResult } from "../types/policy.js";

const AGENT = "agent-1";

/** Trusted clock. Intent timestamps below are deliberately offset from this. */
const EVAL_NOW = 1_730_000_000;
const WINDOW = 3_600;

function intentAt(timestamp: number, nonce: bigint): Intent {
  return {
    intent_id: `intent-${nonce.toString()}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    asset: "USDC",
    amount: 1n,
    target: "user_1",
    timestamp,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "sig",
    tool: "pay",
    tool_call: true,
    depth: 0,
  };
}

function stateWithNonces(
  entries: Array<{ nonce: string; ts: number }>,
  windowSeconds: number = WINDOW,
): State {
  return {
    policy_version: "v1-replay-tt",
    replay: {
      window_seconds: windowSeconds,
      max_nonces_per_agent: 256,
      nonces: { [AGENT]: entries },
    },
  } as unknown as State;
}

/** Read back the nonce list a module ALLOW produced. */
function nonces(result: PolicyResult): Array<{ nonce: string; ts: number }> {
  assert.equal(result.decision, "ALLOW");
  const delta = (result as Extract<PolicyResult, { decision: "ALLOW" }>).stateDelta;
  assert.ok(delta?.replay, "ALLOW result must carry a replay stateDelta");
  return delta.replay.nonces[AGENT] ?? [];
}

// ── 1. WINDOW: eviction follows the trusted clock ────────────────────────────

test("#191 replay window: an entry outside the trusted window is pruned even when intent.timestamp would retain it", () => {
  // Entry is 2h old relative to the trusted clock → outside a 1h window.
  const stale = { nonce: "900", ts: EVAL_NOW - 2 * WINDOW };

  // BACKdated: retention is `entry.ts >= windowStart`, so an earlier
  // intent.timestamp yields an EARLIER windowStart and retains MORE. Here
  // windowStart would be EVAL_NOW - 3*WINDOW, which keeps the stale entry —
  // so the assertion below fails under the intent-clock implementation.
  const intent = intentAt(EVAL_NOW - 2 * WINDOW, 1n);

  const out = ReplayModule(intent, stateWithNonces([stale]), { evaluationTime: EVAL_NOW });

  const kept = nonces(out).map((e) => e.nonce);
  assert.ok(!kept.includes("900"), "stale entry must be pruned against evaluationTime, not intent.timestamp");
});

test("#191 replay window: an entry inside the trusted window is retained even when intent.timestamp would evict it", () => {
  // Entry is 10 minutes old on the trusted clock → comfortably inside.
  const fresh = { nonce: "901", ts: EVAL_NOW - 600 };

  // A postdated intent that would push windowStart past the entry.
  const intent = intentAt(EVAL_NOW + 2 * WINDOW, 2n);

  const out = ReplayModule(intent, stateWithNonces([fresh]), { evaluationTime: EVAL_NOW });

  const kept = nonces(out).map((e) => e.nonce);
  assert.ok(kept.includes("901"), "fresh entry must survive: retention is trusted-clock driven");
});

test("#191 replay window: a postdated intent cannot evict its previously recorded nonce", () => {
  // The attack the trusted clock closes. Pruning keeps `entry.ts >= windowStart`,
  // so POSTdating is the eviction direction: a later intent.timestamp pushes
  // windowStart forward past the recorded entry, prunes it, and lets the replay
  // through. Under the intent-clock implementation windowStart would be
  // EVAL_NOW + WINDOW, which drops nonce 42 and returns ALLOW.
  const recorded = { nonce: "42", ts: EVAL_NOW - 60 };
  const postdated = intentAt(EVAL_NOW + 2 * WINDOW, 42n);

  const out = ReplayModule(postdated, stateWithNonces([recorded]), { evaluationTime: EVAL_NOW });

  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["REPLAY_NONCE"]);
});

// ── 2. STAMP: new entries carry the trusted clock ────────────────────────────

test("#191 nonce stamping: a newly recorded nonce is stamped with evaluationTime, not intent.timestamp", () => {
  const intentTs = EVAL_NOW - 120; // inside freshness bounds, but distinct
  const out = ReplayModule(intentAt(intentTs, 7n), stateWithNonces([]), { evaluationTime: EVAL_NOW });

  const list = nonces(out);
  assert.equal(list.length, 1);
  assert.equal(list[0]!.nonce, "7");
  assert.equal(list[0]!.ts, EVAL_NOW, "new entries must be stamped from the trusted clock");
  assert.notEqual(list[0]!.ts, intentTs);
});

// ── 3. COMPAT: legacy entries, no migration, self-healing ────────────────────

test("#191 compat: legacy entries stamped from intent.timestamp are read as-is, without conversion", () => {
  // Written by a pre-#191 engine from intent.timestamp, skewed behind the
  // trusted clock but still inside the retention window.
  const legacy = { nonce: "1001", ts: EVAL_NOW - 30 };

  const out = ReplayModule(intentAt(EVAL_NOW - 5, 2002n), stateWithNonces([legacy]), {
    evaluationTime: EVAL_NOW,
  });

  const list = nonces(out);
  const survived = list.find((e) => e.nonce === "1001");
  assert.ok(survived, "legacy entry must be retained while inside the window");
  assert.equal(survived.ts, EVAL_NOW - 30, "legacy ts must be preserved verbatim — no rewrite, no migration");
});

test("#191 compat: a legacy nonce still inside the window is honoured and blocks its own replay", () => {
  const legacy = { nonce: "1001", ts: EVAL_NOW - 30 };
  const out = ReplayModule(intentAt(EVAL_NOW - 5, 1001n), stateWithNonces([legacy]), {
    evaluationTime: EVAL_NOW,
  });

  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["REPLAY_NONCE"]);
});

test("#191 compat: after one retention window every surviving entry carries a trusted-time stamp", () => {
  const legacy = [
    { nonce: "1", ts: EVAL_NOW - 10 },
    { nonce: "2", ts: EVAL_NOW - 20 },
  ];

  // Advance the trusted clock past one full retention window. Legacy entries
  // age out on their persisted timestamps; the new entry is trusted-stamped.
  const later = EVAL_NOW + WINDOW + 1;
  const out = ReplayModule(intentAt(later - 5, 3n), stateWithNonces(legacy), { evaluationTime: later });

  const list = nonces(out);
  assert.deepEqual(
    list.map((e) => e.nonce),
    ["3"],
    "legacy entries must age out against the trusted clock",
  );
  assert.equal(list[0]!.ts, later);
});

// ── 4. Unchanged behaviour that must not regress ─────────────────────────────

test("#191 replay: malformed replay config still denies with STATE_INVALID", () => {
  const bad = { policy_version: "v1-replay-tt", replay: { nonces: {} } } as unknown as State;
  const out = ReplayModule(intentAt(EVAL_NOW, 1n), bad, { evaluationTime: EVAL_NOW });

  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.reasons, ["STATE_INVALID"]);
});

// ── 5. Properties: replay monotonicity (mirrors the velocity/tool-window ────
//    trusted-time property tests in style and scope)
//
// `ReplayModule` never reads `intent.timestamp` at all — only
// `context.evaluationTime` and `intent.nonce`/`agent_id`. The properties below
// generalize the fixed WINDOW/STAMP examples above into arbitrary-input
// sweeps, so a future change that starts consulting `intent.timestamp` (the
// exact regression #191 closed) is caught regardless of which specific
// window/offset values a fixed example happens to use.
//
// Scope note: `max_nonces_per_agent` is held at its existing fixed value (256,
// via `stateWithNonces`) throughout. Capacity-based list-size eviction is a
// separate, pre-existing resource bound with no dedicated coverage anywhere in
// this file today; generalizing that is out of scope for this pass and is not
// asserted one way or the other here.

test("#191 property: any intent.timestamp yields the identical decision for a given (nonce, state, evaluationTime)", () => {
  fc.assert(fc.property(
    fc.integer({ min: EVAL_NOW - 10 * WINDOW, max: EVAL_NOW + 10 * WINDOW }),
    fc.integer({ min: EVAL_NOW - 10 * WINDOW, max: EVAL_NOW + 10 * WINDOW }),
    (t1, t2) => {
      const state = stateWithNonces([{ nonce: "500", ts: EVAL_NOW - 60 }]);
      assert.deepEqual(
        ReplayModule(intentAt(t1, 500n), state, { evaluationTime: EVAL_NOW }),
        ReplayModule(intentAt(t2, 500n), state, { evaluationTime: EVAL_NOW }),
      );
    },
  ));
});

test("#191 property: no intent.timestamp can evict a recorded nonce still inside the trusted window", () => {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 100_000 }),
    fc.integer({ min: 0, max: 100_000 }),
    fc.integer({ min: -10_000_000, max: 10_000_000 }),
    (windowSeconds, elapsed, tsOffset) => {
      fc.pre(elapsed < windowSeconds); // still inside the trusted window at evaluationTime
      const recordedAt = EVAL_NOW;
      const evaluationTime = recordedAt + elapsed;
      const state = stateWithNonces([{ nonce: "77", ts: recordedAt }], windowSeconds);

      // Attacker-controlled offset applied to the trusted evaluation time —
      // arbitrarily postdated or backdated, and never bounded by a freshness
      // gate here (that gate lives upstream in PolicyEngine.evaluatePure).
      const attackerTimestamp = evaluationTime + tsOffset;
      const out = ReplayModule(intentAt(attackerTimestamp, 77n), state, { evaluationTime });

      assert.deepEqual(out, { decision: "DENY", reasons: ["REPLAY_NONCE"] });
    },
  ));
});

test("#191 property: activity under other nonces cannot make a consumed nonce valid again", () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 50 }), // intervening distinct-nonce calls, well under max_nonces_per_agent (256)
    fc.integer({ min: 0, max: WINDOW - 1 }), // elapsed time, still inside the trusted window
    (interveningCount, elapsed) => {
      let entries: Array<{ nonce: string; ts: number }> = [];

      const first = ReplayModule(intentAt(EVAL_NOW, 999n), stateWithNonces(entries), { evaluationTime: EVAL_NOW });
      assert.equal(first.decision, "ALLOW", "setup: the target nonce must be consumable once");
      entries = nonces(first);

      let evalTime = EVAL_NOW;
      for (let i = 0; i < interveningCount; i++) {
        evalTime += 1;
        const step = ReplayModule(
          intentAt(evalTime, BigInt(2000 + i)),
          stateWithNonces(entries),
          { evaluationTime: evalTime },
        );
        assert.equal(step.decision, "ALLOW", `setup: intervening activity #${i} must itself be consumable`);
        entries = nonces(step);
      }

      const finalEvalTime = EVAL_NOW + elapsed;
      const replay = ReplayModule(
        intentAt(finalEvalTime, 999n),
        stateWithNonces(entries),
        { evaluationTime: finalEvalTime },
      );

      assert.deepEqual(
        replay,
        { decision: "DENY", reasons: ["REPLAY_NONCE"] },
        `interveningCount=${interveningCount} elapsed=${elapsed}`,
      );
    },
  ));
});
