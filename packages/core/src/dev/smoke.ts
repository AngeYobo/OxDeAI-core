// SPDX-License-Identifier: Apache-2.0
// packages/core/src/dev/smoke.ts
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { PolicyEngine } from "../policy/PolicyEngine.js"; // adjust path if needed
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import { intentHash } from "../crypto/hashes.js";
import { ReplayEngine } from "../replay/ReplayEngine.js";
import { decodeCanonicalState, encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
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

// Every intent in this smoke run uses timestamp 1700000000; evaluationTime
// matches it exactly so freshness is always fresh (delta = 0) and every
// other decision/hash in this file stays byte-identical to before trusted-time
// integration.
const EVAL_TIME = 1700000000;

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

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function main() {
  const engine = new PolicyEngine({
    policy_version: "v0.2",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    deny_mode: "fail-fast",
    checkpoint_every_n_events: 2,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });

  // ---- Test 1: Replay ----
  {
    const state = baseState();
    const intent = intentBase({ nonce: 42n });

    const r1 = engine.evaluatePure(intent, state, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(intent, r1.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustDeny(r2);
    mustIncludeReason(r2, "REPLAY_NONCE");

    console.log("- Replay test passed");
  }

  // ---- Test 2: Recursion depth ----
  {
    const state = baseState();
    const intent = intentBase({ nonce: 43n, depth: 999 });

    const r = engine.evaluatePure(intent, state, EVAL_TIME, { mode: "fail-fast" });
    mustDeny(r);
    mustIncludeReason(r, "RECURSION_DEPTH_EXCEEDED");

    console.log("- Recursion depth test passed");
  }

  // ---- Test 3: Concurrency (no release) ----
  {
    const state = baseState();

    const i1 = intentBase({ nonce: 100n });
    const r1 = engine.evaluatePure(i1, state, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r1);

    const i2 = intentBase({ nonce: 101n });
    const r2 = engine.evaluatePure(i2, r1.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r2);

    const i3 = intentBase({ nonce: 102n });
    const r3 = engine.evaluatePure(i3, r2.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "CONCURRENCY_LIMIT_EXCEEDED");

    console.log("- Concurrency test passed");
  }

  // ---- Test 4: Release bound to authorization_id ----
  {
    const state = baseState();

    // EXECUTE twice -> should ALLOW, active=2
    const r1 = engine.evaluatePure(intentBase({ nonce: 200n, type: "EXECUTE" }), state, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(intentBase({ nonce: 201n, type: "EXECUTE" }), r1.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r2);

    // Third EXECUTE -> DENY
    const r3 = engine.evaluatePure(intentBase({ nonce: 202n, type: "EXECUTE" }), r2.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "CONCURRENCY_LIMIT_EXCEEDED");

    // RELEASE with invalid auth -> DENY
    const badRel = engine.evaluatePure(
      intentBase({ nonce: 203n, type: "RELEASE", authorization_id: "not-a-real-auth" }),
      r2.nextState,
      EVAL_TIME, { mode: "fail-fast" }
    );
    mustDeny(badRel);
    mustIncludeReason(badRel, "CONCURRENCY_RELEASE_INVALID");

    // RELEASE with real auth -> ALLOW (free one slot)
    const rel = engine.evaluatePure(
      intentBase({ nonce: 204n, type: "RELEASE", authorization_id: r2.authorization.auth_id }),
      r2.nextState,
      EVAL_TIME, { mode: "fail-fast" }
    );
    mustAllow(rel);

    // Now EXECUTE should ALLOW again (slot freed)
    const r4 = engine.evaluatePure(intentBase({ nonce: 205n, type: "EXECUTE" }), rel.nextState, EVAL_TIME, { mode: "fail-fast" });
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

    const r1 = engine.evaluatePure(mk(300n), state, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r1);

    const r2 = engine.evaluatePure(mk(301n), r1.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustAllow(r2);

    // third call in same window should DENY (max_calls = 2)
    const r3 = engine.evaluatePure(mk(302n), r2.nextState, EVAL_TIME, { mode: "fail-fast" });
    mustDeny(r3);
    mustIncludeReason(r3, "TOOL_CALL_LIMIT_EXCEEDED");

    console.log("- Tool amplification test passed");
  }

  // ---- Snapshot roundtrip invariant ----
  {
    const state = baseState();
    const originalStateHash = engine.computeStateHash(state);
    const snap = engine.exportState(state);
    const encoded = encodeCanonicalState(snap);
    const decoded = decodeCanonicalState(encoded);

    const clone = structuredClone(state);
    engine.importState(clone, decoded);
    const afterHash = engine.computeStateHash(clone);
    assert(originalStateHash === afterHash, "snapshot roundtrip hash must match");

    const snapshotHash = createHash("sha256").update(encoded).digest("hex");
    console.log(`DETERMINISM snapshotHash=${snapshotHash}`);
  }

  // ---- Decision equivalence before/after import ----
  {
    const sequence = [
      intentBase({ nonce: 500n, type: "EXECUTE", tool_call: true, tool: "openai.responses" }),
      intentBase({ nonce: 501n, type: "EXECUTE", tool_call: true, tool: "openai.responses" })
    ];

    const liveStart = baseState();
    let liveState = liveStart;
    const liveDecisions: Array<"ALLOW" | "DENY"> = [];
    for (const i of sequence) {
      const out = engine.evaluatePure(i, liveState, EVAL_TIME, { mode: "fail-fast" });
      liveDecisions.push(out.decision);
      if (out.decision === "ALLOW") liveState = out.nextState;
    }
    const liveHash = engine.computeStateHash(liveState);

    const importedStart = baseState();
    const snap = engine.exportState(importedStart);
    const encoded = encodeCanonicalState(snap);
    const decoded = decodeCanonicalState(encoded);
    engine.importState(importedStart, decoded);

    let importedState = importedStart;
    const importedDecisions: Array<"ALLOW" | "DENY"> = [];
    for (const i of sequence) {
      const out = engine.evaluatePure(i, importedState, EVAL_TIME, { mode: "fail-fast" });
      importedDecisions.push(out.decision);
      if (out.decision === "ALLOW") importedState = out.nextState;
    }
    const importedHash = engine.computeStateHash(importedState);

    assert(
      liveDecisions.join(",") === importedDecisions.join(","),
      "decision sequence must match before/after import"
    );
    assert(liveHash === importedHash, "final state hash must match before/after import");
  }

  // ---- Replay equivalence smoke (audit-level invariants) ----
  {
    const events = engine.audit.snapshot();
    assert(events.some((e) => e.type === "STATE_CHECKPOINT"), "at least one STATE_CHECKPOINT must be emitted");

    const replay = ReplayEngine.replay(events, { policyId: engine.computePolicyId() });
    assert(replay.invariantViolations.length === 0, "audit replay invariants must hold");

    const strict = ReplayEngine.verify(events);
    assert(strict.ok === true, "strict replay verify must pass with checkpoints");
  }

  // ---- Deterministic rebuild fingerprint ----
  let determinism: { policyId: string; stateHash: string; auditHeadHash: string } | undefined;
  {
    const policyId = engine.computePolicyId();
    const stateHash = engine.computeStateHash(baseState());
    const auditHeadHash = engine.audit.headHash();
    determinism = { policyId, stateHash, auditHeadHash };
    console.log(`DETERMINISM policyId=${policyId}`);
    console.log(`DETERMINISM stateHash=${stateHash}`);
    console.log(`DETERMINISM auditHeadHash=${auditHeadHash}`);
  }
  if (process.env["OXDEAI_SMOKE_OUT"] && determinism) {
    await writeFile(process.env["OXDEAI_SMOKE_OUT"], JSON.stringify(determinism), "utf8");
  }
  

  console.log("🎉 All smoke tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
