import { PolicyEngine } from "../../packages/core/src/policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../../packages/core/src/policy/trustedTimeProfile.js";
import type { EvaluatePureOutput } from "../../packages/core/src/policy/PolicyEngine.js";
import type { State } from "../../packages/core/src/types/state.js";
import type { Intent } from "../../packages/core/src/types/intent.js";

const AGENT = "agent-1";
const POLICY_VERSION = "v1-test";
const SECRET = "x".repeat(32);
const BASE_TS = 1_751_970_000;
const FUTURE_TS = BASE_TS + 100 * 365 * 24 * 60 * 60;

// evaluatePure()'s real return type: authorization/nextState only exist on
// the ALLOW branch, so callers must narrow on `decision` before reading them.
type Outcome = EvaluatePureOutput;

function engine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY_VERSION,
    engine_secret: SECRET,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

// Fixed trusted "now" for every attack below — deliberately NOT derived from
// each attack's (attacker-controlled) intent.timestamp. This is the two-clock
// model itself: attacks that future-date intent.timestamp are now expected to
// be caught by the freshness gate (INTENT_FRESHNESS_FUTURE) before they ever
// reach replay/velocity/tool-window logic. Attacks C, K3, J, and I probe
// exactly this boundary and are expected to flip from VULNERABLE to
// RESISTED/FIXED now that freshness is wired in ahead of those gates.
const EVAL_TIME = BASE_TS;

function baseState(overrides?: (s: State) => void): State {
  const s: State = {
    policy_version: POLICY_VERSION,
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      // Tool calls are signaled via intent.tool_call, not a dedicated
      // ActionType — "PAYMENT" covers both plain and tool-call intents below.
      action_types: ["PAYMENT"],
      assets: ["wallet", "tool"],
      targets: ["user_1", "tool_1"],
    },
    budget: {
      budget_limit: { [AGENT]: 1_000_000_000n },
      spent_in_period: { [AGENT]: 0n },
    },
    max_amount_per_action: { [AGENT]: 1_000_000_000n },
    velocity: {
      config: { window_seconds: 3600, max_actions: 1 },
      counters: {},
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {},
    },
    concurrency: {
      max_concurrent: { [AGENT]: 1000 },
      active: {},
      active_auths: {},
    },
    recursion: {
      max_depth: { [AGENT]: 1 },
    },
    tool_limits: {
      window_seconds: 3600,
      max_calls: { [AGENT]: 1 },
      calls: {},
    },
  };

  overrides?.(s);
  return s;
}

function intent(overrides?: Partial<Intent>): Intent {
  return {
    intent_id: `intent-${Math.random().toString(16).slice(2)}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    amount: 100n,
    asset: "wallet",
    target: "user_1",
    timestamp: BASE_TS,
    metadata_hash: "00",
    nonce: 1n,
    signature: "placeholder",
    depth: 0,
    ...overrides,
  } as Intent;
}

function print(name: string, out: Outcome): void {
  console.log(`\n=== ${name} ===`);
  console.log("decision:", out.decision);
  console.log("reasons:", JSON.stringify(out.reasons ?? []));
  if (out.decision === "ALLOW") {
    console.log("issued_at:", out.authorization.issued_at);
    console.log("expiry:", out.authorization.expiry);
  }
}

function assertSignal(name: string, condition: boolean, vulnerable: string, resisted: string): void {
  if (condition) {
    console.log(`SECURITY SIGNAL: ${vulnerable}`);
  } else {
    console.log(`RESISTED / FIXED: ${resisted}`);
  }
}

/**
 * F — per-agent kill-switch type confusion.
 *
 * Expected vulnerable behavior:
 *   kill_switch.agents[agent] = 1
 *   decision = ALLOW
 *
 * Expected fixed behavior:
 *   decision = DENY
 *   reasons = ["STATE_INVALID"]
 */
function attackF_killSwitchTypeConfusion(): void {
  const s = baseState((st) => {
    (st.kill_switch.agents as Record<string, unknown>)[AGENT] = 1;
    st.velocity.config.max_actions = 1000;
  });

  const out = engine().evaluatePure(intent(), s, EVAL_TIME);
  print("F: kill_switch.agents[agent] = 1", out);

  assertSignal(
    "F",
    out.decision === "ALLOW",
    "VULNERABLE: truthy non-boolean per-agent kill-switch produced ALLOW",
    "per-agent kill-switch type confusion rejected or denied",
  );
}

/**
 * C — future-dated intent creates future-dated authorization.
 *
 * Expected vulnerable behavior:
 *   issued_at = future timestamp
 *   expiry = future timestamp + ttl
 *   decision = ALLOW
 *
 * This does not prove verifier behavior alone; it proves the engine emits auths
 * based on attacker-controlled intent.timestamp.
 */
function attackC_futureDatedAuthorization(): void {
  const s = baseState((st) => {
    st.velocity.config.max_actions = 1000;
  });

  const out = engine().evaluatePure(
    intent({
      timestamp: FUTURE_TS,
      nonce: 2n,
    }),
    s,
    EVAL_TIME,
  );

  print("C: future-dated intent timestamp", out);

  const expiry = out.decision === "ALLOW" ? out.authorization.expiry : undefined;
  assertSignal(
    "C",
    out.decision === "ALLOW" && typeof expiry === "number" && expiry > BASE_TS + 99 * 365 * 24 * 60 * 60,
    "VULNERABLE: engine emitted far-future authorization from intent.timestamp",
    "future-dated authorization rejected or bounded",
  );
}

/**
 * K — replay bypass by future-dating the replay attempt.
 *
 * Expected vulnerable behavior:
 *   first use nonce 7 at BASE_TS => ALLOW
 *   immediate reuse nonce 7 at BASE_TS => DENY
 *   future-dated reuse nonce 7 beyond replay window => ALLOW
 */
function attackK_replayFutureDating(): void {
  const e = engine();
  let s = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.max_calls[AGENT] = 1000;
  });

  const first = e.evaluatePure(intent({ nonce: 7n, timestamp: BASE_TS }), s, EVAL_TIME);
  if (first.decision === "ALLOW") s = first.nextState;

  const immediateReplay = e.evaluatePure(intent({ nonce: 7n, timestamp: BASE_TS }), s, EVAL_TIME);
  const futureReplay = e.evaluatePure(intent({ nonce: 7n, timestamp: BASE_TS + 7200 }), s, EVAL_TIME);

  print("K1: nonce 7 first use", first);
  print("K2: nonce 7 immediate replay", immediateReplay);
  print("K3: nonce 7 future-dated replay", futureReplay);

  assertSignal(
    "K",
    first.decision === "ALLOW" &&
      immediateReplay.decision === "DENY" &&
      futureReplay.decision === "ALLOW",
    "VULNERABLE: replay protection bypassed by attacker-controlled future timestamp",
    "future-dated replay rejected",
  );
}

/**
 * J — velocity window bypass by future-dating every action.
 *
 * Expected vulnerable behavior:
 *   max_actions = 1
 *   5 sequential actions with timestamps beyond window
 *   all ALLOW
 */
function attackJ_velocityFutureDating(): void {
  const e = engine();
  let s = baseState((st) => {
    st.velocity.config.window_seconds = 3600;
    st.velocity.config.max_actions = 1;
    st.tool_limits.max_calls[AGENT] = 1000;
  });

  const outs: Outcome[] = [];

  for (let i = 0; i < 5; i++) {
    const out = e.evaluatePure(
      intent({
        nonce: BigInt(100 + i),
        timestamp: BASE_TS + i * 7200,
      }),
      s,
      EVAL_TIME,
    );
    outs.push(out);
    if (out.decision === "ALLOW") s = out.nextState;
  }

  console.log("\n=== J: velocity future-dating ===");
  console.log("decisions:", outs.map((o) => o.decision).join(", "));
  console.log("reasons:", outs.map((o) => JSON.stringify(o.reasons ?? [])).join(" | "));

  assertSignal(
    "J",
    outs.every((o) => o.decision === "ALLOW"),
    "VULNERABLE: velocity limit reset by attacker-controlled future timestamps",
    "velocity future-dating rejected or bounded",
  );
}

/**
 * I — tool-amplification window bypass by future-dating tool calls.
 *
 * Expected vulnerable behavior:
 *   max_calls = 1
 *   5 tool calls with timestamps beyond window
 *   all ALLOW
 */
function attackI_toolWindowFutureDating(): void {
  const e = engine();
  let s = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.window_seconds = 3600;
    st.tool_limits.max_calls[AGENT] = 1;
  });

  const outs: Outcome[] = [];

  for (let i = 0; i < 5; i++) {
    const out = e.evaluatePure(
      intent({
        intent_id: `tool-${i}`,
        asset: "tool",
        target: "tool_1",
        nonce: BigInt(200 + i),
        timestamp: BASE_TS + i * 7200,
        tool_call: true,
      }),
      s,
      EVAL_TIME,
    );
    outs.push(out);
    if (out.decision === "ALLOW") s = out.nextState;
  }

  console.log("\n=== I: tool limit future-dating ===");
  console.log("decisions:", outs.map((o) => o.decision).join(", "));
  console.log("reasons:", outs.map((o) => JSON.stringify(o.reasons ?? [])).join(" | "));

  assertSignal(
    "I",
    outs.every((o) => o.decision === "ALLOW"),
    "VULNERABLE: tool-call limit reset by attacker-controlled future timestamps",
    "tool future-dating rejected or bounded",
  );
}

/**
 * H — tool-amplification opt-in bypass.
 *
 * Expected vulnerable behavior:
 *   max_calls = 1
 *   tool_call omitted
 *   5 tool-like actions ALLOW
 *
 * Control:
 *   tool_call = true
 *   only first ALLOW, rest DENY
 */
function attackH_toolCallOptIn(): void {
  const e1 = engine();
  let s1 = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.max_calls[AGENT] = 1;
  });

  const omitted: Outcome[] = [];

  for (let i = 0; i < 5; i++) {
    const out = e1.evaluatePure(
      intent({
        intent_id: `tool-omitted-${i}`,
        asset: "tool",
        target: "tool_1",
        nonce: BigInt(300 + i),
        timestamp: BASE_TS,
        // tool_call intentionally omitted
      }),
      s1,
      EVAL_TIME,
    );
    omitted.push(out);
    if (out.decision === "ALLOW") s1 = out.nextState;
  }

  const e2 = engine();
  let s2 = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.max_calls[AGENT] = 1;
  });

  const explicit: Outcome[] = [];

  for (let i = 0; i < 5; i++) {
    const out = e2.evaluatePure(
      intent({
        intent_id: `tool-explicit-${i}`,
        asset: "tool",
        target: "tool_1",
        nonce: BigInt(400 + i),
        timestamp: BASE_TS,
        tool_call: true,
      }),
      s2,
      EVAL_TIME,
    );
    explicit.push(out);
    if (out.decision === "ALLOW") s2 = out.nextState;
  }

  console.log("\n=== H: tool_call opt-in bypass ===");
  console.log("tool_call omitted:", omitted.map((o) => o.decision).join(", "));
  console.log("tool_call true   :", explicit.map((o) => o.decision).join(", "));

  assertSignal(
    "H",
    omitted.every((o) => o.decision === "ALLOW") &&
      explicit.filter((o) => o.decision === "ALLOW").length === 1,
    "VULNERABLE: omitting self-declared tool_call bypasses tool limit",
    "tool limit enforced even when tool_call is omitted",
  );
}

/**
 * G — recursion depth self-declared.
 *
 * Expected vulnerable behavior:
 *   depth = 99 => DENY
 *   same intent shape with depth = 0 => ALLOW
 */
function attackG_depthSelfDeclared(): void {
  const s = baseState((st) => {
    st.velocity.config.max_actions = 1000;
  });

  const highDepth = engine().evaluatePure(intent({ depth: 99, nonce: 500n }), s, EVAL_TIME);
  const lowDepth = engine().evaluatePure(intent({ depth: 0, nonce: 501n }), s, EVAL_TIME);

  print("G1: depth = 99", highDepth);
  print("G2: depth = 0", lowDepth);

  assertSignal(
    "G",
    highDepth.decision === "DENY" && lowDepth.decision === "ALLOW",
    "VULNERABLE DESIGN: recursion guard depends on self-declared intent.depth",
    "depth cannot be bypassed by self-declaration",
  );
}

function main(): void {
  console.log("\nOxDeAI policy-boundary attack repro harness");
  console.log("Repo-local only. Do not run against production systems.\n");

  attackF_killSwitchTypeConfusion();
  attackC_futureDatedAuthorization();
  attackK_replayFutureDating();
  attackJ_velocityFutureDating();
  attackI_toolWindowFutureDating();
  attackH_toolCallOptIn();
  attackG_depthSelfDeclared();

  console.log("\nDone.");
}

main();
