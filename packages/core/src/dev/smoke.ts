// packages/core/src/dev/smoke.ts
import { PolicyEngine } from "../policy/PolicyEngine.js"; // adjust path if needed
import { intentHash } from "../crypto/hashes.js";
import { ReplayEngine } from "../replay/ReplayEngine.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import type { ReasonCode } from "../types/policy.js";

(() => {
  const base: any = { type: "TOOL_CALL", tool: "x", params: { a: 1 }, nonce: "n1" };
  const withSig = { ...base, signature: "0xdeadbeef" };
  if (intentHash(base) !== intentHash(withSig)) {
    throw new Error("regression: intentHash must ignore signature");
  }
})();

function baseState(): State {
  return {
    policy_version: "v0.2",
    period_id: "2026-02",

    kill_switch: { global: false, agents: {} },

    allowlists: {},

    budget: {
      budget_limit: { "agent-1": 10_000n },
      spent_in_period: { "agent-1": 0n }
    },

    max_amount_per_action: { "agent-1": 9_999n },

    velocity: {
      config: { window_seconds: 60, max_actions: 100 },
      counters: {}
    },

    // NEW
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {}
    },

    // NEW
    concurrency: {
      max_concurrent: { "agent-1": 2 },
      active: {},
      active_auths: {}
    },

    // NEW
    recursion: {
      max_depth: { "agent-1": 2 }
    },

    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 2 },
      calls: {}
    }
  };
}

function intentBase(overrides?: Partial<Intent>): Intent {
  return {
    agent_id: "agent-1",
    nonce: 1n,
    amount: 1n,
    timestamp: 1700000000,
    depth: 0,
    ...(overrides ?? {})
  } as Intent;
}

type EvaluatePureResult = ReturnType<PolicyEngine["evaluatePure"]>;
type AllowResult = Extract<EvaluatePureResult, { decision: "ALLOW" }>;
type DenyResult = Extract<EvaluatePureResult, { decision: "DENY" }>;

function mustAllow(out: EvaluatePureResult): asserts out is AllowResult {
  if (out.decision !== "ALLOW") {
    throw new Error(`Expected ALLOW, got DENY: ${out.reasons.join(",")}`);
  }
}

function mustDeny(out: EvaluatePureResult): asserts out is DenyResult {
  if (out.decision !== "DENY") {
    throw new Error("Expected DENY, got ALLOW");
  }
}

function mustIncludeReason(out: DenyResult, reason: ReasonCode) {
  if (!out.reasons.includes(reason)) {
    throw new Error(`Expected reasons to include ${reason}, got: ${out.reasons.join(",")}`);
  }
}

async function main() {
  const engine = new PolicyEngine({
    policy_version: "v0.2",
    engine_secret: "dev-secret",
    authorization_ttl_seconds: 60,
    deny_mode: "fail-fast"
  });

  // ---- Test 1: Replay ----
  {
    const state = baseState();
    const intent = intentBase({ nonce: 42n });

    const r1 = engine.evaluatePure(intent, state, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(intent, r1.nextState, { mode: "fail-fast" });
    mustDeny(r2);
    mustIncludeReason(r2, "REPLAY_NONCE");

    console.log("- Replay test passed");
  }

  // ---- Test 2: Recursion depth ----
  {
    const state = baseState();
    const intent = intentBase({ nonce: 43n, depth: 999 });

    const r = engine.evaluatePure(intent, state, { mode: "fail-fast" });
    mustDeny(r);
    mustIncludeReason(r, "RECURSION_DEPTH_EXCEEDED");

    console.log("- Recursion depth test passed");
  }

  // ---- Test 3: Concurrency (no release) ----
  {
    const state = baseState();

    const i1 = intentBase({ nonce: 100n });
    const r1 = engine.evaluatePure(i1, state, { mode: "fail-fast" });
    mustAllow(r1);

    const i2 = intentBase({ nonce: 101n });
    const r2 = engine.evaluatePure(i2, r1.nextState, { mode: "fail-fast" });
    mustAllow(r2);

    const i3 = intentBase({ nonce: 102n });
    const r3 = engine.evaluatePure(i3, r2.nextState, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "CONCURRENCY_LIMIT_EXCEEDED");

    console.log("- Concurrency test passed");
  }

  // ---- Test 4: Release bound to authorization_id ----
  {
    const state = baseState();

    // EXECUTE twice -> should ALLOW, active=2
    const r1 = engine.evaluatePure(intentBase({ nonce: 200n, type: "EXECUTE" }), state, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(intentBase({ nonce: 201n, type: "EXECUTE" }), r1.nextState, { mode: "fail-fast" });
    mustAllow(r2);

    // Third EXECUTE -> DENY
    const r3 = engine.evaluatePure(intentBase({ nonce: 202n, type: "EXECUTE" }), r2.nextState, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "CONCURRENCY_LIMIT_EXCEEDED");

    // RELEASE with invalid auth -> DENY
    const badRel = engine.evaluatePure(
      intentBase({ nonce: 203n, type: "RELEASE", authorization_id: "not-a-real-auth" }),
      r2.nextState,
      { mode: "fail-fast" }
    );
    mustDeny(badRel);
    mustIncludeReason(badRel, "CONCURRENCY_RELEASE_INVALID");

    // RELEASE with real auth -> ALLOW (free one slot)
    const rel = engine.evaluatePure(
      intentBase({ nonce: 204n, type: "RELEASE", authorization_id: r2.authorization.authorization_id }),
      r2.nextState,
      { mode: "fail-fast" }
    );
    mustAllow(rel);

    // Now EXECUTE should ALLOW again (slot freed)
    const r4 = engine.evaluatePure(intentBase({ nonce: 205n, type: "EXECUTE" }), rel.nextState, { mode: "fail-fast" });
    mustAllow(r4);

    console.log("- Release binding test passed");
  }

  // ---- Test 5: Tool amplification cap ----
  {
    const seed = baseState();
    const state = {
      ...seed,
      concurrency: {
        ...seed.concurrency,
        max_concurrent: { "agent-1": 10 }
      }
    };

    const mk = (nonce: bigint) =>
      intentBase({
        nonce,
        type: "EXECUTE",
        tool_call: true,
        tool: "openai.responses"
      });

    const r1 = engine.evaluatePure(mk(300n), state, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(mk(301n), r1.nextState, { mode: "fail-fast" });
    mustAllow(r2);

    // third call in same window should DENY (max_calls = 2)
    const r3 = engine.evaluatePure(mk(302n), r2.nextState, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "TOOL_CALL_LIMIT_EXCEEDED");

    console.log("- Tool amplification test passed");
  }

  // ---- Snapshot determinism smoke (manual) ----
  {
    const state = baseState();
    const snap1 = engine.exportState(state);
    const hash1 = engine.computeStateHash(state);

    const clone = structuredClone(state);
    engine.importState(clone, snap1);
    const hash2 = engine.computeStateHash(clone);

    console.log(hash1 === hash2);
  }

  // ---- Replay equivalence smoke (audit-level invariants) ----
  {
    const events = engine.audit.snapshot();
    const replay = ReplayEngine.replay(events, { policyId: engine.computePolicyId() });
    console.log(replay.invariantViolations.length === 0);
  }

  // ---- Deterministic rebuild fingerprint ----
  {
    const policyId = engine.computePolicyId();
    const stateHash = engine.computeStateHash(baseState());
    const auditHeadHash = engine.audit.headHash();
    console.log(`DETERMINISM policyId=${policyId}`);
    console.log(`DETERMINISM stateHash=${stateHash}`);
    console.log(`DETERMINISM auditHeadHash=${auditHeadHash}`);
  }
  

  console.log("🎉 All smoke tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
