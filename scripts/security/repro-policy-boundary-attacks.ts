import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine } from "../../packages/core/src/policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../../packages/core/src/policy/trustedTimeProfile.js";
import type { EvaluatePureOutput } from "../../packages/core/src/policy/PolicyEngine.js";
import type { State } from "../../packages/core/src/types/state.js";
import type { Intent } from "../../packages/core/src/types/intent.js";
// The Tier 1 secure-guard package (@oxdeai/guard) is built against the
// published `@oxdeai/core` (dist) types, which are a separate nominal type
// from the `../../packages/core/src/...` PolicyEngine imported above (private
// field identity differs across declarations even when structurally
// identical). The engine handed to createSecureGuard()'s config must
// therefore come from the same "@oxdeai/core" resolution the guard package
// itself uses — everything else in this file keeps using the legacy-profile
// src imports unchanged.
import { PolicyEngine as CorePolicyEngine } from "@oxdeai/core";
import type { KeySet } from "@oxdeai/core";
import { buildState } from "../../packages/sdk/src/index.js";
import {
  createSecureGuard,
  createTrustedExecutionContext,
  OxDeAIProvenanceConflictError,
} from "../../packages/guard/src/index.js";
import type {
  SecureGuardOptions,
  ProposedAction,
  OxDeAIGuardConfig,
  GuardDecisionRecord,
} from "../../packages/guard/src/index.js";

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
// model itself: attacks that grossly future-date intent.timestamp are expected
// to be caught by freshness before later policy modules. Attack J deliberately
// stays inside the valid freshness band so it proves velocity itself is driven
// by evaluationTime; the other future-dating cases continue to probe the
// freshness boundary.
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

// ── Fixtures for identity/label-substitution attacks (L, M) ────────────────
const LOW_AGENT = "agent-low";
const HIGH_AGENT = "agent-high";
const CAPPED_TOOL = "search";

// Two configured agents: a restrictive one and a permissive one. L probes an
// intent that self-declares HIGH_AGENT to inherit the permissive caps.
function twoAgentState(): State {
  const s = baseState();
  s.budget.budget_limit = { [LOW_AGENT]: 100n, [HIGH_AGENT]: 1_000_000_000n };
  s.budget.spent_in_period = { [LOW_AGENT]: 0n, [HIGH_AGENT]: 0n };
  s.max_amount_per_action = { [LOW_AGENT]: 100n, [HIGH_AGENT]: 1_000_000_000n };
  s.velocity.config.max_actions = 1000;
  s.concurrency.max_concurrent = { [LOW_AGENT]: 1000, [HIGH_AGENT]: 1000 };
  s.recursion.max_depth = { [LOW_AGENT]: 1, [HIGH_AGENT]: 1 };
  s.tool_limits.max_calls = { [LOW_AGENT]: 1000, [HIGH_AGENT]: 1000 };
  return s;
}

// Per-tool cap on CAPPED_TOOL only; every other gate relaxed so M isolates the
// per-tool accounting path.
function perToolCapState(): State {
  const s = baseState();
  s.budget.budget_limit = { [LOW_AGENT]: 1_000_000n };
  s.budget.spent_in_period = { [LOW_AGENT]: 0n };
  s.max_amount_per_action = { [LOW_AGENT]: 1_000_000n };
  s.velocity.config.max_actions = 1000;
  s.concurrency.max_concurrent = { [LOW_AGENT]: 1000 };
  s.recursion.max_depth = { [LOW_AGENT]: 1000 };
  s.tool_limits.max_calls = { [LOW_AGENT]: 100 };
  s.tool_limits.max_calls_by_tool = { [LOW_AGENT]: { [CAPPED_TOOL]: 1 } };
  return s;
}

function toolIntent(nonce: number): Partial<Intent> {
  return {
    intent_id: `tool-${nonce}`,
    agent_id: LOW_AGENT,
    asset: "tool",
    target: "tool_1",
    nonce: BigInt(nonce),
    timestamp: BASE_TS,
    tool_call: true,
  };
}

// Direct engine.evaluatePure() calls below carry no Tier 1 provenance
// guarantee — every intent field (agent_id, depth, tool, ...) is exactly the
// self-declared value the "attacker" supplied, with no trusted execution
// context in the loop. This is the profile every pre-#234 caller runs under,
// and it remains a first-class supported path (OxDeAIGuard has no such
// guarantee either); the label makes that boundary explicit rather than
// changing what these cases mean.
const LEGACY_PROFILE_LABEL = "LEGACY PROFILE";

// Structured pass/fail state for CI. Only invariants that are expected to
// hold today (Tier 1 secure-profile protections, plus the legacy attacks
// that are already fixed) are pushed here on violation. Intentional
// legacy-profile residuals (G/L/M) are logged for diagnostics only and never
// push a failure — see the individual call sites below.
const failures: string[] = [];

function print(name: string, out: Outcome): void {
  console.log(`\n=== [${LEGACY_PROFILE_LABEL}] ${name} ===`);
  console.log("decision:", out.decision);
  console.log("reasons:", JSON.stringify(out.reasons ?? []));
  if (out.decision === "ALLOW") {
    console.log("issued_at:", out.authorization.issued_at);
    console.log("expiry:", out.authorization.expiry);
  }
}

// `blocking: true` marks a case where `condition` (vulnerable/signal
// detected) must NOT hold today; a regression pushes a CI failure. Omitted
// (or false) for cases that are intentionally still reproducible (legacy
// G/L/M) — those remain diagnostic-only, matching the requirement that
// expected legacy-profile residuals must not fail CI.
function assertSignal(
  name: string,
  condition: boolean,
  vulnerable: string,
  resisted: string,
  opts?: { blocking?: boolean },
): void {
  if (condition) {
    console.log(`[${LEGACY_PROFILE_LABEL}] SECURITY SIGNAL: ${vulnerable}`);
    if (opts?.blocking) {
      failures.push(`${name}: ${vulnerable}`);
    }
  } else {
    console.log(`[${LEGACY_PROFILE_LABEL}] RESISTED / FIXED: ${resisted}`);
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
    { blocking: true },
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
    { blocking: true },
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
    { blocking: true },
  );
}

/**
 * J — velocity window bypass by varying caller time inside the freshness band.
 *
 * Expected vulnerable behavior:
 *   max_actions = 1
 *   sequential actions vary freshness-valid intent timestamps
 *   all ALLOW
 *
 * Expected fixed behavior:
 *   first ALLOW, all later actions VELOCITY_EXCEEDED while evaluationTime
 *   remains inside the same trusted window.
 */
function attackJ_velocityFutureDating(): void {
  const e = engine();
  let s = baseState((st) => {
    // Each attacker timestamp step is larger than this window, while all
    // timestamps remain inside the ±300-second freshness band.
    st.velocity.config.window_seconds = 100;
    st.velocity.config.max_actions = 1;
    st.tool_limits.max_calls[AGENT] = 1000;
  });

  const outs: Outcome[] = [];
  const freshnessValidOffsets = [-300, -150, 0, 150, 300];

  for (let i = 0; i < 5; i++) {
    const out = e.evaluatePure(
      intent({
        nonce: BigInt(100 + i),
        timestamp: BASE_TS + freshnessValidOffsets[i]!,
      }),
      s,
      EVAL_TIME,
    );
    outs.push(out);
    if (out.decision === "ALLOW") s = out.nextState;
  }

  console.log("\n=== J: velocity timestamp noninterference ===");
  console.log("decisions:", outs.map((o) => o.decision).join(", "));
  console.log("reasons:", outs.map((o) => JSON.stringify(o.reasons ?? [])).join(" | "));

  assertSignal(
    "J",
    outs.every((o) => o.decision === "ALLOW"),
    "VULNERABLE: velocity limit reset by attacker-controlled future timestamps",
    "freshness-valid caller timestamps cannot reset trusted velocity quota",
    { blocking: true },
  );
}

/**
 * I — tool-amplification window resistance to caller timestamp changes.
 *
 * Caller timestamps stay inside the freshness-valid band. Trusted evaluation
 * time remains fixed for three calls, then reaches the exact boundary.
 */
function attackI_toolWindowFutureDating(): void {
  const e = engine();
  let s = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.window_seconds = 3600;
    st.tool_limits.max_calls[AGENT] = 1;
  });

  const cases = [
    { timestamp: BASE_TS, evaluationTime: EVAL_TIME },
    { timestamp: BASE_TS + 300, evaluationTime: EVAL_TIME },
    { timestamp: BASE_TS - 300, evaluationTime: EVAL_TIME },
    { timestamp: BASE_TS + 3600, evaluationTime: EVAL_TIME + 3600 },
  ];
  const outs: Outcome[] = [];

  for (const [i, attack] of cases.entries()) {
    const out = e.evaluatePure(
      intent({
        intent_id: `tool-${i}`,
        asset: "tool",
        target: "tool_1",
        nonce: BigInt(200 + i),
        timestamp: attack.timestamp,
        tool: "search",
        tool_call: true,
      }),
      s,
      attack.evaluationTime,
    );
    outs.push(out);
    if (out.decision === "ALLOW") s = out.nextState;
  }

  console.log("\n=== I: tool limit future-dating ===");
  console.log("decisions:", outs.map((o) => o.decision).join(", "));
  console.log("reasons:", outs.map((o) => JSON.stringify(o.reasons ?? [])).join(" | "));

  assertSignal(
    "I",
    !(outs[0]?.decision === "ALLOW" &&
      outs[1]?.decision === "DENY" && outs[1].reasons.includes("TOOL_CALL_LIMIT_EXCEEDED") &&
      outs[2]?.decision === "DENY" && outs[2].reasons.includes("TOOL_CALL_LIMIT_EXCEEDED") &&
      outs[3]?.decision === "ALLOW"),
    "VULNERABLE: tool-call limit reset by attacker-controlled future timestamps",
    "caller timestamps cannot reset quota; trusted exact-boundary progression can",
    { blocking: true },
  );
}

/**
 * H — tool-amplification opt-in bypass.
 *
 * Classification is now derived from the trusted action discriminator
 * (EXECUTE) plus a policy-configured tool in state.tool_limits, resolved via
 * intent.tool as a lookup key — never from the self-declared intent.tool_call
 * boolean (see isRateLimitedToolCall in ToolAmplificationModule.ts). All
 * three intents below name the same policy-configured tool and therefore
 * MUST receive identical tool-limit treatment regardless of tool_call.
 *
 * Originally vulnerable behavior:
 *   max_calls = 1
 *   tool_call omitted
 *   5 tool-like actions ALLOW
 *
 * Control (always enforced, before and after the fix):
 *   tool_call = true
 *   only first ALLOW, rest DENY
 *
 * Fixed behavior additionally requires the omitted/false variants to be
 * denied identically to the control, AND a mixed omitted -> false -> true
 * sequence to consume one shared budget (limit = 1): only the first call
 * ALLOWs, the rest DENY with TOOL_CALL_LIMIT_EXCEEDED.
 */
function attackH_toolCallOptIn(): void {
  const TOOL = "search";

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
        tool: TOOL,
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
        tool: TOOL,
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

  const e3 = engine();
  let s3 = baseState((st) => {
    st.velocity.config.max_actions = 1000;
    st.tool_limits.max_calls[AGENT] = 1;
  });

  const mixedVariants: Array<{ tool_call?: boolean }> = [{ tool_call: undefined }, { tool_call: false }, { tool_call: true }];
  const mixed: Outcome[] = [];

  for (let i = 0; i < mixedVariants.length; i++) {
    const out = e3.evaluatePure(
      intent({
        intent_id: `tool-mixed-${i}`,
        asset: "tool",
        target: "tool_1",
        tool: TOOL,
        nonce: BigInt(800 + i),
        timestamp: BASE_TS,
        tool_call: mixedVariants[i]!.tool_call,
      }),
      s3,
      EVAL_TIME,
    );
    mixed.push(out);
    if (out.decision === "ALLOW") s3 = out.nextState;
  }

  console.log("\n=== H: tool_call opt-in bypass ===");
  console.log("tool_call omitted:", omitted.map((o) => o.decision).join(", "));
  console.log("tool_call true   :", explicit.map((o) => o.decision).join(", "));
  console.log("mixed omitted->false->true:", mixed.map((o) => o.decision).join(", "));

  const omittedBypassed = omitted.every((o) => o.decision === "ALLOW");
  const controlEnforced = explicit.filter((o) => o.decision === "ALLOW").length === 1;
  const mixedSharesOneBudget =
    mixed[0]!.decision === "ALLOW" && mixed[1]!.decision === "DENY" && mixed[2]!.decision === "DENY";

  assertSignal(
    "H",
    omittedBypassed || !controlEnforced || !mixedSharesOneBudget,
    "VULNERABLE: omitting or falsifying self-declared tool_call bypasses tool limit",
    "tool limit enforced identically regardless of tool_call value or presence",
    { blocking: true },
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

/**
 * L — per-agent limit evasion by self-declared identity.
 *
 * agent_id is the trust anchor every per-agent gate keys off (budget,
 * velocity, replay, concurrency, recursion, tool limits, kill-switch), yet it
 * is an unauthenticated attacker-controlled intent field. An agent bound to a
 * restrictive profile can inherit a more permissive agent's limits simply by
 * naming it. Same family as G/H: a self-declared field gates a security
 * decision without independent provenance.
 *
 * Note: substituting an *unconfigured* agent_id fails closed (STATE_INVALID),
 * so this probes the more dangerous case — substituting a *known, more
 * privileged* agent, which is indistinguishable from a legitimate request for
 * that agent.
 *
 * Expected vulnerable behavior:
 *   amount above the caller's own per-action cap => DENY as self
 *   identical amount declared under a higher-limit agent => ALLOW
 *
 * Expected fixed behavior (design change, out of scope for trusted-time):
 *   engine binds decisions to an authenticated principal, not intent.agent_id;
 *   the substituted-identity request cannot inherit foreign limits.
 */
function attackL_agentIdentitySubstitution(): void {
  const restrictedAmount = 1_000n;

  const asSelf = engine().evaluatePure(
    intent({ agent_id: LOW_AGENT, amount: restrictedAmount, nonce: 600n }),
    twoAgentState(),
    EVAL_TIME,
  );
  const asPrivileged = engine().evaluatePure(
    intent({ agent_id: HIGH_AGENT, amount: restrictedAmount, nonce: 601n }),
    twoAgentState(),
    EVAL_TIME,
  );

  print(`L1: amount ${restrictedAmount} as '${LOW_AGENT}' (cap 100)`, asSelf);
  print(`L2: amount ${restrictedAmount} as '${HIGH_AGENT}' (cap 1e9)`, asPrivileged);

  assertSignal(
    "L",
    asSelf.decision === "DENY" && asPrivileged.decision === "ALLOW",
    "VULNERABLE: per-agent limits inherited by self-declaring a more privileged agent_id",
    "decisions bound to authenticated principal, not self-declared agent_id",
  );
}

/**
 * M — per-tool cap evasion by self-declared tool name.
 *
 * ToolAmplificationModule enforces a per-tool cap only when
 * max_calls_by_tool[agent][intent.tool] is configured. intent.tool is
 * attacker-controlled, so spreading calls across freshly-invented tool names
 * falls through to the aggregate cap only, defeating any per-tool cap. Sibling
 * of H (there the whole module is skipped by omitting tool_call; here one
 * specific cap is dodged by renaming the tool).
 *
 * Setup isolates the per-tool cap: aggregate tool cap, budget, velocity and
 * concurrency are all raised so only the per-tool "search" cap can bite.
 *
 * Expected vulnerable behavior:
 *   second call to capped tool "search" => DENY TOOL_CALL_LIMIT_EXCEEDED
 *   call to unlisted tool "search_v2"   => ALLOW
 *
 * Expected fixed behavior:
 *   per-tool accounting cannot be escaped by an unconfigured tool name
 *   (e.g. default-deny unknown tools, or an aggregate that ignores tool label).
 */
function attackM_toolNameSelfDeclared(): void {
  const e = engine();
  let s = perToolCapState();

  const first = e.evaluatePure(
    intent({ ...toolIntent(700), tool: CAPPED_TOOL }),
    s,
    EVAL_TIME,
  );
  if (first.decision === "ALLOW") s = first.nextState;

  const sameTool = e.evaluatePure(
    intent({ ...toolIntent(701), tool: CAPPED_TOOL }),
    s,
    EVAL_TIME,
  );
  const renamedTool = e.evaluatePure(
    intent({ ...toolIntent(702), tool: `${CAPPED_TOOL}_v2` }),
    s,
    EVAL_TIME,
  );

  print(`M1: first '${CAPPED_TOOL}' (per-tool cap 1)`, first);
  print(`M2: second '${CAPPED_TOOL}'`, sameTool);
  print(`M3: renamed '${CAPPED_TOOL}_v2' (no per-tool cap)`, renamedTool);

  assertSignal(
    "M",
    first.decision === "ALLOW" &&
      sameTool.decision === "DENY" &&
      renamedTool.decision === "ALLOW",
    "VULNERABLE: per-tool cap bypassed by self-declaring an unlisted tool name",
    "per-tool accounting resistant to attacker-chosen tool labels",
  );
}

// ── Tier 1 secure-profile fixtures (#234) ───────────────────────────────────
//
// These cases run through createSecureGuard(), not engine.evaluatePure()
// directly. A TrustedExecutionContext supplies authoritative premises
// (agentId, depth, optionally tool); the secure guard reconciles those
// against the proposer's declared claims BEFORE evaluation, authorization
// issuance, state mutation or execution. A conflict raises
// OxDeAIProvenanceConflictError and the shared enforcement body (state read,
// PolicyEngine.evaluatePure, authorization verification, replay, CAS,
// execution) is never reached.
//
// This does NOT prove the guard authenticates the caller or derives the
// principal-to-agent mapping — createTrustedExecutionContext() is called
// directly here, the same way a PEP would call it after its own
// authentication step. What this proves is narrower and still load-bearing:
// once an authoritative premise IS supplied through trusted context, the
// proposer's self-declared claim cannot override it.
const TIER1_PROFILE_LABEL = "TIER 1 SECURE PROFILE";

const SECURE_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const SECURE_KEYSET: KeySet = {
  issuer: "repro-secure-issuer",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: SECURE_KEYPAIR.publicKey.toString() }],
};

const SECURE_AUDIENCE = "repro-secure-audience";
const SECURE_TOOL_TARGET = "tool_1";

const SINGLE_TENANT: SecureGuardOptions = { tenancy: "single-tenant" };

function secureEngine(): CorePolicyEngine {
  return new CorePolicyEngine({
    policy_version: POLICY_VERSION,
    engine_secret: SECRET,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: SECURE_KEYSET.issuer,
    authorization_audience: SECURE_AUDIENCE,
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: SECURE_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

// Deployment-level state store backing the secure guard's shared enforcement
// body. Only reached on the ALLOW path (M-secure without a trusted tool
// premise) — the conflict cases below never get this far.
function makeSecureGuardConfig(
  agentId: string,
  onDecision?: (record: GuardDecisionRecord) => void,
): OxDeAIGuardConfig {
  let currentState: State = buildState({
    agent_id: agentId,
    policy_version: POLICY_VERSION,
    allow_action_types: ["PROVISION"],
    allow_assets: [],
    allow_targets: [SECURE_TOOL_TARGET],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 1000,
    max_depth: 1000,
    tool_max_calls: 1000,
  });
  let currentVersion = 0;

  return {
    engine: secureEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => {
      if (v !== currentVersion) return false;
      currentState = s;
      currentVersion++;
      return true;
    },
    trustedKeySets: [SECURE_KEYSET],
    expectedAudience: SECURE_AUDIENCE,
    ...(onDecision ? { onDecision } : {}),
  };
}

// Proposer-controlled action. `context` is where a proposer's declared
// claims live (agent_id / depth / tool) — the same field the reconciliation
// table reads from.
function secureAction(context: Record<string, unknown>): ProposedAction {
  return {
    name: "provision_gpu",
    args: {},
    estimatedCost: 0,
    resourceType: "gpu",
    context: { target: SECURE_TOOL_TARGET, ...context },
  };
}

/**
 * Shared runner for the three provenance-conflict cases (G/L/M-with-tool):
 * construct the trusted context, run the secure guard, and confirm the
 * conflict is deterministic, names exactly the expected field, and never
 * reaches the protected execute() callback.
 */
async function runProvenanceConflictCase(
  name: string,
  trustedContext: ReturnType<typeof createTrustedExecutionContext>,
  stateAgentId: string,
  action: ProposedAction,
  expectedField: string,
  resistedMessage: string,
): Promise<void> {
  console.log(`\n=== [${TIER1_PROFILE_LABEL}] ${name} ===`);

  const secureGuard = createSecureGuard(makeSecureGuardConfig(stateAgentId), SINGLE_TENANT);

  let executed = false;
  let caught: unknown;
  try {
    await secureGuard(trustedContext, action, async () => {
      executed = true;
      return "should-not-execute";
    });
  } catch (err) {
    caught = err;
  }

  const conflictError = caught instanceof OxDeAIProvenanceConflictError ? caught : undefined;
  const fields = conflictError?.fields ?? [];

  console.log("error:", conflictError ? conflictError.constructor.name : String(caught));
  console.log("conflicting fields:", JSON.stringify(fields));
  console.log("provenance:", conflictError ? JSON.stringify(conflictError.provenance) : "n/a");
  console.log("execute callback invoked:", executed);

  const resisted =
    conflictError !== undefined &&
    fields.length === 1 &&
    fields[0] === expectedField &&
    !executed;

  if (resisted) {
    console.log(`[${TIER1_PROFILE_LABEL}] RESISTED / FIXED: ${resistedMessage}`);
  } else {
    console.log(
      `[${TIER1_PROFILE_LABEL}] SECURITY SIGNAL: expected a deterministic OxDeAIProvenanceConflictError ` +
        `on '${expectedField}' with the protected execute() callback never invoked, but did not observe it.`,
    );
    failures.push(`${name}: expected a deterministic provenance conflict on '${expectedField}'`);
  }
}

/**
 * G-secure — recursion depth provenance conflict.
 *
 * Trusted execution context supplies depth = 99 (derived from the real
 * protected execution chain). The proposer separately claims depth = 0 in
 * action.context. Sibling of legacy attack G: same self-declared-depth
 * shape, but now with a trusted premise in the loop to conflict against.
 */
async function attackGSecure_depthProvenanceConflict(): Promise<void> {
  const trustedContext = createTrustedExecutionContext({
    principalId: "principal-g-secure",
    agentId: AGENT,
    adapterId: "adapter-secure",
    depth: 99,
  });

  await runProvenanceConflictCase(
    "G-secure: trusted depth=99, proposer claims depth=0",
    trustedContext,
    AGENT,
    secureAction({ agent_id: AGENT, depth: 0 }),
    "depth",
    "trusted depth cannot be lowered by proposer claim",
  );
}

/**
 * L-secure — agent identity provenance conflict.
 *
 * Trusted execution context supplies agentId = 'agent-low'. The proposer
 * separately claims agent_id = 'agent-high' in action.context, mirroring
 * legacy attack L's privileged-identity substitution. This proves only that
 * a proposer claim cannot override an already-supplied trusted agentId — not
 * that the guard authenticates the caller or derives agent_id itself.
 */
async function attackLSecure_agentIdentityProvenanceConflict(): Promise<void> {
  const trustedContext = createTrustedExecutionContext({
    principalId: "principal-l-secure",
    agentId: LOW_AGENT,
    adapterId: "adapter-secure",
    depth: 0,
  });

  await runProvenanceConflictCase(
    `L-secure: trusted agentId='${LOW_AGENT}', proposer claims agent_id='${HIGH_AGENT}'`,
    trustedContext,
    LOW_AGENT,
    secureAction({ agent_id: HIGH_AGENT, depth: 0 }),
    "agent_id",
    "trusted agent identity cannot be replaced by proposer claim",
  );
}

/**
 * M-secure (trusted tool present) — tool identity provenance conflict.
 *
 * Trusted execution context supplies tool = 'search', derived from the
 * trusted route. The proposer separately claims tool = 'search_v2',
 * mirroring legacy attack M's tool-rename bypass. Closed ONLY because this
 * route happens to supply an authoritative tool identity — see the
 * no-trusted-tool case below for the route that does not.
 */
async function attackMSecure_toolProvenanceConflict(): Promise<void> {
  const trustedContext = createTrustedExecutionContext({
    principalId: "principal-m-secure",
    agentId: AGENT,
    adapterId: "adapter-secure",
    depth: 0,
    tool: CAPPED_TOOL,
  });

  await runProvenanceConflictCase(
    `M-secure (trusted tool): trusted tool='${CAPPED_TOOL}', proposer claims tool='${CAPPED_TOOL}_v2'`,
    trustedContext,
    AGENT,
    secureAction({ agent_id: AGENT, depth: 0, tool: `${CAPPED_TOOL}_v2` }),
    "tool",
    "trusted tool identity rejects proposer rename",
  );
}

/**
 * M-secure (no trusted tool) — residual, not globally fixed.
 *
 * Trusted execution context intentionally carries no `tool` (this route has
 * no authoritative tool identity to supply — `tool` is optional on
 * TrustedExecutionContext for exactly this reason). The proposer's tool
 * claim has nothing to conflict against, so reconciliation cannot reject it:
 * it is retained and recorded as `"unverified"`, evaluation proceeds, and the
 * protected execute() callback DOES run. This is the case the task
 * description requires we not mis-report as closed — M is closed only for
 * routes that supply an authoritative tool identity (see the case above).
 */
async function attackMSecure_toolUnverifiedWithoutRoutePremise(): Promise<void> {
  const trustedContext = createTrustedExecutionContext({
    principalId: "principal-m-secure-unverified",
    agentId: AGENT,
    adapterId: "adapter-secure",
    depth: 0,
    // Deliberately no `tool` — this route has no authoritative tool identity.
  });

  console.log(`\n=== [${TIER1_PROFILE_LABEL}] M-secure (no trusted tool): proposer claims tool='${CAPPED_TOOL}_v2' ===`);

  const records: GuardDecisionRecord[] = [];
  const secureGuard = createSecureGuard(
    makeSecureGuardConfig(AGENT, (record) => {
      records.push(record);
    }),
    SINGLE_TENANT,
  );

  let executed = false;
  let caught: unknown;
  try {
    await secureGuard(
      trustedContext,
      secureAction({ agent_id: AGENT, depth: 0, tool: `${CAPPED_TOOL}_v2` }),
      async () => {
        executed = true;
        return "executed";
      },
    );
  } catch (err) {
    caught = err;
  }

  const provenance = records[0]?.provenance;
  const toolOutcome = provenance?.["tool"];

  console.log("decision:", records[0]?.decision);
  console.log("provenance:", JSON.stringify(provenance ?? {}));
  console.log("execute callback invoked:", executed);
  console.log("thrown error:", caught ? String(caught) : "none");

  const isResidualUnverified = toolOutcome === "unverified" && executed && caught === undefined;

  if (isResidualUnverified) {
    console.log(
      `[${TIER1_PROFILE_LABEL}] RESIDUAL / UNVERIFIED: proposer tool claim has no authoritative tool premise on this route`,
    );
  } else if (toolOutcome === "matched") {
    console.log(
      `[${TIER1_PROFILE_LABEL}] SECURITY SIGNAL: proposer tool claim was recorded as 'matched' with no trusted tool ` +
        `premise to match against — this misreports an unverified claim as verified.`,
    );
    failures.push(
      "M-secure (no trusted tool): proposer tool claim misreported as 'matched' with no trusted tool premise",
    );
  } else {
    console.log(
      `[${TIER1_PROFILE_LABEL}] SECURITY SIGNAL: expected provenance.tool === 'unverified' with execution proceeding, ` +
        `observed tool='${String(toolOutcome)}', executed=${executed}, error=${caught ? String(caught) : "none"}.`,
    );
    failures.push(
      `M-secure (no trusted tool): expected residual/unverified state, observed tool='${String(toolOutcome)}', ` +
        `executed=${executed}, error=${caught ? String(caught) : "none"}`,
    );
  }
}

async function main(): Promise<void> {
  console.log("\nOxDeAI policy-boundary attack repro harness");
  console.log("Repo-local only. Do not run against production systems.\n");

  attackF_killSwitchTypeConfusion();
  attackC_futureDatedAuthorization();
  attackK_replayFutureDating();
  attackJ_velocityFutureDating();
  attackI_toolWindowFutureDating();
  attackH_toolCallOptIn();
  attackG_depthSelfDeclared();
  attackL_agentIdentitySubstitution();
  attackM_toolNameSelfDeclared();

  // Tier 1 secure-profile cases (#234). These run through createSecureGuard()
  // rather than engine.evaluatePure() directly — see the section above for
  // why each is not a claim that the corresponding legacy attack is globally
  // closed.
  await attackGSecure_depthProvenanceConflict();
  await attackLSecure_agentIdentityProvenanceConflict();
  await attackMSecure_toolProvenanceConflict();
  await attackMSecure_toolUnverifiedWithoutRoutePremise();

  console.log("\nDone.");

  if (failures.length > 0) {
    console.error(`\n${failures.length} required policy-boundary invariant(s) failed:`);
    for (const f of failures) console.error(` - ${f}`);
    process.exitCode = 1;
  } else {
    console.log("\nAll required policy-boundary invariants held.");
  }
}

main();
