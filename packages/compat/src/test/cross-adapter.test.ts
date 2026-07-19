// SPDX-License-Identifier: Apache-2.0
/**
 * Cross-adapter invariant tests for OxDeAI.
 *
 * Validates the core protocol invariant across LangGraph, OpenAI Agents SDK,
 * and CrewAI adapters:
 *
 *   Same normalized intent + same policy state + same policy configuration
 *   => same authorization decision
 *   => same semantic normalization evidence (action_type, amount, metadata_hash)
 *
 * Value:
 *   This test protects against "adapter drift" - where framework-specific
 *   wrappers accidentally change protocol behavior. Each adapter translates
 *   its framework-native tool call to a ProposedAction using different field
 *   names (LangGraph/CrewAI use `args`, OpenAI Agents uses `input`; LangGraph/
 *   CrewAI use `id`, OpenAI Agents uses `call_id`). Despite these surface
 *   differences, OxDeAI semantics must remain identical - every adapter MUST
 *   produce the same authorization outcome for the same conceptual action.
 *
 * Why shared mutable state is forbidden (I6 - Evaluation Isolation):
 *   PolicyEngine.evaluatePure accumulates module deltas via deepMerge, which
 *   is a shallow copy at the top level: nested objects (budget, replay, etc.)
 *   are mutated in place. If getState returns the same object reference to
 *   multiple concurrent callers, the first caller's deepMerge corrupts the
 *   state observed by subsequent callers, producing non-deterministic DENY
 *   outcomes for inputs that should ALLOW. Each adapter invocation MUST
 *   receive a structuredClone of the shared state constant.
 *
 * Why adapter drift is a protocol risk:
 *   OxDeAI is adapter-agnostic by design: any framework that can produce a
 *   ProposedAction with the correct fields must produce the same protocol
 *   outcome as any other. If an adapter mis-maps a field (e.g. "input" vs
 *   "args", estimatedCost ignored, agentId not threaded), the downstream
 *   intent will differ from the other adapters - same conceptual action, but
 *   different policy outcome. This breaks the portability claim and silently
 *   weakens authorization enforcement for users of that adapter.
 *
 * Test structure:
 *   - CORPUS TESTS:         five deterministic cases with known expected outcomes.
 *   - CAP CORPUS TESTS:     two boundary cases for per-action cap enforcement.
 *   - PBT SWEEP:            seeded variation across tool names and estimated costs.
 *   - NONCE REPLAY TEST:    same nonce as pre-recorded state → REPLAY_NONCE across all adapters.
 *   - CONCURRENT ISOLATION: N parallel calls per adapter - proves state isolation
 *                           prevents budget bleed across concurrent evaluations.
 *
 * Invariants asserted per case (see assertCrossAdapterEquivalence):
 *   1. decision:       all adapters produce the same ALLOW / DENY
 *   2. action_type:    normalization infers the same canonical action type
 *   3. amount:         estimatedCost maps to the same fixed-point bigint
 *   4. metadata_hash:  SHA-256 of canonical args is identical across adapters
 *   5. timestamp:      pinned timestamp is preserved through all normalizers
 *   6. agent_id:       injected agentId is correctly threaded through all paths
 *   7. denial reasons: on DENY, all adapters report the same violation strings
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Intent, KeySet, State } from "@oxdeai/core";
import {
  defaultNormalizeAction,
  OxDeAIDenyError,
} from "@oxdeai/guard";
import type { GuardDecisionRecord, OxDeAIGuardConfig, ProposedAction } from "@oxdeai/guard";
import { buildState } from "@oxdeai/sdk";

import { createLangGraphGuard } from "@oxdeai/langgraph";
import type { LangGraphToolCall } from "@oxdeai/langgraph";

import { createOpenAIAgentsGuard } from "@oxdeai/openai-agents";
import type { OpenAIAgentsToolCall } from "@oxdeai/openai-agents";

import { createCrewAIGuard } from "@oxdeai/crewai";
import type { CrewAIToolCall } from "@oxdeai/crewai";

// ── PRNG (same pattern as all other PBT tests in this repo) ──────────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "50");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260319");
const ONLY_SEED = process.env.PBT_ONLY_SEED ? Number(process.env.PBT_ONLY_SEED) : undefined;

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[randInt(rng, 0, values.length - 1)];
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── Ed25519 test fixture ──────────────────────────────────────────────────────

const TEST_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding:  { format: "pem", type: "spki" },
});

const TEST_KEYSET: KeySet = {
  issuer: "test-issuer",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: TEST_KEYPAIR.publicKey.toString() }],
};

// ── Shared policy infrastructure ──────────────────────────────────────────────

const AGENT_ID = "cross-adapter-agent";

// Current unix timestamp injected into every tool call so the timestamp field
// in the normalized intent is deterministic and comparable, and auth tokens
// are not expired.
const T_FIXED = Math.floor(Date.now() / 1000);

// One engine instance shared across all adapters in every test. Using the same
// engine ensures policy_version, engine_secret, and all policy module configs
// are identical - the decision boundary is the same for every adapter.
const ENGINE = new PolicyEngine({
  policy_version: "v1-cross-adapter",
  engine_secret: "cross-adapter-test-secret-32-chars!",
  authorization_signing_alg: "Ed25519",
  authorization_signing_kid: "k1",
  authorization_issuer: TEST_KEYSET.issuer,
  authorization_audience: AGENT_ID,
  authorization_ttl_seconds: 600,
  authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
  ...RECOMMENDED_TRUSTED_TIME_PROFILE,
});

// Policy state: only PROVISION-type actions are allowed, budget is generous so
// it never constrains the corpus cases. Each adapter invocation clones this
// state (structuredClone) rather than sharing the reference - see I6.
const POLICY_STATE = buildState({
  agent_id: AGENT_ID,
  policy_version: "v1-cross-adapter",
  allow_action_types: ["PROVISION"],
  budget_limit: 10_000_000_000n,
  max_amount_per_action: 10_000_000_000n,
  velocity_max_actions: 1000,
  max_concurrent: 16,
});

// ── Per-action cap policy infrastructure ──────────────────────────────────────
//
// Used by the cap boundary corpus (see CAP_CORPUS below).
// max_amount_per_action is tight (500 units = 500_000_000 micro-units) so that
// a tool call with estimatedCost=500 hits the boundary exactly, and one with
// estimatedCost=501 exceeds it.

const CAP_ENGINE = new PolicyEngine({
  policy_version: "v1-cross-adapter-cap",
  engine_secret: "cross-adapter-cap-secret-32-chars!!",
  authorization_signing_alg: "Ed25519",
  authorization_signing_kid: "k1",
  authorization_issuer: TEST_KEYSET.issuer,
  authorization_audience: AGENT_ID,
  authorization_ttl_seconds: 600,
  authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
  ...RECOMMENDED_TRUSTED_TIME_PROFILE,
});

// 500 units in fixed-point micro-units (1 unit = 1_000_000 micro-units).
const CAP_AMOUNT = 500_000_000n;

const CAP_STATE = buildState({
  agent_id: AGENT_ID,
  policy_version: "v1-cross-adapter-cap",
  allow_action_types: ["PROVISION"],
  budget_limit: 10_000_000_000n,
  max_amount_per_action: CAP_AMOUNT,
  velocity_max_actions: 1000,
  max_concurrent: 16,
});

// ── Nonce replay state infrastructure ─────────────────────────────────────────
//
// REPLAY_STATE is POLICY_STATE with PINNED_NONCE already recorded in the
// per-agent nonce log. Any evaluation that presents the same nonce at T_FIXED
// will be rejected by ReplayModule with REPLAY_NONCE.
//
// Why this test exists:
//   All three adapters must agree on REPLAY_NONCE when replaying the same
//   nonce. If an adapter fails to thread the nonce through its normalizer,
//   it would produce a different (random) nonce and incorrectly ALLOW the
//   action. This test proves that the nonce channel is not broken by any
//   adapter's field mapping.

const PINNED_NONCE = 0xc0ffee_abcdef_1234n;

const REPLAY_STATE: State = {
  ...structuredClone(POLICY_STATE),
  replay: {
    ...POLICY_STATE.replay,
    // Pre-record PINNED_NONCE at T_FIXED. ReplayModule keeps nonces within a
    // window of `window_seconds` (default 3600). Since intent.timestamp is
    // also T_FIXED, the nonce falls within the window and triggers REPLAY_NONCE.
    nonces: {
      [AGENT_ID]: [{ nonce: PINNED_NONCE.toString(), ts: T_FIXED }],
    },
  },
};

// ── Concurrent isolation state infrastructure ──────────────────────────────────
//
// A deliberately tight-budget state for the concurrent isolation test.
// The invariant under test (I6):
//   With structuredClone isolation, 30 concurrent calls each starting from
//   spent=0 all ALLOW (5 units << 100-unit budget).
//   Without isolation (the former bug), deepMerge would mutate the shared
//   state's budget.spent_in_period in place: after 20 calls accumulate
//   100_000_000n (= 100 units), calls 21–30 would DENY with BUDGET_EXCEEDED.
//
// budget_limit    = 100 units  = 100_000_000n micro-units
// cost per call   =   5 units  =   5_000_000n micro-units
// calls to exhaust = 100 / 5   = 20 calls
// total parallel  = 3 adapters × 10 iterations = 30 calls
// → With shared state: calls 21–30 would DENY (100 < 150).
// → With isolated state: all 30 ALLOW (5 ≤ 100 each).

const CONCURRENCY_ENGINE = new PolicyEngine({
  policy_version: "v1-cross-adapter-concurrency",
  engine_secret: "cross-adapter-concurrency-32chars!",
  authorization_signing_alg: "Ed25519",
  authorization_signing_kid: "k1",
  authorization_issuer: TEST_KEYSET.issuer,
  authorization_audience: AGENT_ID,
  authorization_ttl_seconds: 600,
  authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
  ...RECOMMENDED_TRUSTED_TIME_PROFILE,
});

const ISOLATED_BUDGET = 100_000_000n; // 100 units

const CONCURRENCY_STATE = buildState({
  agent_id: AGENT_ID,
  policy_version: "v1-cross-adapter-concurrency",
  allow_action_types: ["PROVISION"],
  budget_limit: ISOLATED_BUDGET,
  max_amount_per_action: ISOLATED_BUDGET,  // cap is non-binding; budget is the active constraint
  velocity_max_actions: 1000,
  max_concurrent: 100,                     // high enough to not constrain the 30 concurrent calls
});

// ── Action corpus types ───────────────────────────────────────────────────────
//
// A "conceptual action" is adapter-neutral: it captures the semantic intent
// without any framework-specific field names. Each adapter runner below
// translates it into the right tool call shape.

type ConceptualAction = {
  /** Stable identifier used in assertion messages and as the pinned call ID. */
  id: string;
  toolName: string;
  args: Record<string, unknown>;
  estimatedCost: number;
  resourceType?: string;
  /** Ground-truth expected outcome for this case given POLICY_STATE. */
  expectedDecision: "ALLOW" | "DENY";
  /** Expected action_type after inference from toolName / resourceType. Omit in PBT paths. */
  expectedActionType?: "PROVISION" | "PAYMENT" | "PURCHASE" | "ONCHAIN_TX";
};

// ── Normalizer capture ────────────────────────────────────────────────────────
//
// Wraps a base normalizer (defaultNormalizeAction by default) so we can record
// what the normalizer produced for each adapter call. Using this wrapper as
// mapActionToIntent does NOT change behavior - the guard receives the same
// Intent. It only lets us compare the intermediate normalization evidence
// across adapters.
//
// The optional `base` parameter allows tests that need to pin specific intent
// fields (e.g. nonce for replay tests) to supply a custom base normalizer
// without breaking the capture contract.

type NormalizerCapture = {
  mapActionToIntent: (action: ProposedAction) => Intent;
  getCapture: () => Intent;
};

function makeNormalizerCapture(
  base: (action: ProposedAction) => Intent = defaultNormalizeAction
): NormalizerCapture {
  let captured: Intent | undefined;
  return {
    mapActionToIntent(action: ProposedAction): Intent {
      const intent = base(action);
      captured = intent;
      return intent;
    },
    getCapture(): Intent {
      assert.ok(captured !== undefined, "normalizer was never called - guard did not reach normalization");
      return captured;
    },
  };
}

// Returns a base normalizer that pins the nonce to a fixed bigint value.
// All other fields are delegated to defaultNormalizeAction.
// Used by the nonce replay test so that every adapter presents the same nonce
// that is already recorded in REPLAY_STATE.nonces.
function withFixedNonce(nonce: bigint): (action: ProposedAction) => Intent {
  return (action: ProposedAction): Intent => {
    const intent = defaultNormalizeAction(action);
    return { ...intent, nonce };
  };
}

// ── Adapter result type ───────────────────────────────────────────────────────

type AdapterResult = {
  adapterName: string;
  decision: "ALLOW" | "DENY";
  reasons: readonly string[];
  intent: Intent;
};

// ── Runner options ────────────────────────────────────────────────────────────
//
// Passed to each per-adapter runner to override the default engine, state, or
// base normalizer. Defaults to ENGINE, structuredClone(POLICY_STATE), and
// defaultNormalizeAction respectively.

type RunnerOptions = {
  /** PolicyEngine to use. Defaults to ENGINE. */
  engine?: PolicyEngine;
  /**
   * State factory called once per guard invocation.
   *
   * MUST return an isolated state snapshot - do NOT return the same mutable
   * object reference across invocations. Use structuredClone(STATE) or
   * equivalent. Violating this causes cross-call state mutation (I6).
   *
   * Defaults to () => structuredClone(POLICY_STATE).
   */
  getState?: OxDeAIGuardConfig["getState"];
  /**
   * Base normalizer applied before capture-wrapping. Use this to pin fields
   * (e.g. nonce) that the adapter's framework-native tool call cannot carry
   * directly. Defaults to defaultNormalizeAction.
   */
  baseNormalizer?: (action: ProposedAction) => Intent;
};

// ── Per-adapter runners ───────────────────────────────────────────────────────

async function runLangGraph(ca: ConceptualAction, opts: RunnerOptions = {}): Promise<AdapterResult> {
  const norm = makeNormalizerCapture(opts.baseNormalizer);
  let record: GuardDecisionRecord | undefined;

  const guard = createLangGraphGuard({
    engine: opts.engine ?? ENGINE,
    getState: opts.getState ?? (() => ({ state: structuredClone(POLICY_STATE), version: 0 })),
    setState: () => true,
    agentId: AGENT_ID,
    mapActionToIntent: norm.mapActionToIntent,
    onDecision: r => { record = r; },
    trustedKeySets: [TEST_KEYSET],
  });

  // LangGraph field mapping: toolCall.args → ProposedAction.args
  //                          toolCall.id   → context.intent_id
  const toolCall: LangGraphToolCall = {
    name: ca.toolName,
    args: ca.args,
    id: `pinned-${ca.id}`,
    estimatedCost: ca.estimatedCost,
    resourceType: ca.resourceType,
    timestampSeconds: T_FIXED,
  };

  try {
    await guard(toolCall, async () => {});
  } catch (err) {
    if (!(err instanceof OxDeAIDenyError)) throw err;
  }

  assert.ok(record !== undefined, "LangGraph: onDecision was not called");
  return {
    adapterName: "LangGraph",
    decision: record.decision,
    reasons: record.reasons ?? [],
    intent: norm.getCapture(),
  };
}

async function runOpenAIAgents(ca: ConceptualAction, opts: RunnerOptions = {}): Promise<AdapterResult> {
  const norm = makeNormalizerCapture(opts.baseNormalizer);
  let record: GuardDecisionRecord | undefined;

  const guard = createOpenAIAgentsGuard({
    engine: opts.engine ?? ENGINE,
    getState: opts.getState ?? (() => ({ state: structuredClone(POLICY_STATE), version: 0 })),
    setState: () => true,
    agentId: AGENT_ID,
    mapActionToIntent: norm.mapActionToIntent,
    onDecision: r => { record = r; },
    trustedKeySets: [TEST_KEYSET],
  });

  // OpenAI Agents SDK field mapping: toolCall.input    → ProposedAction.args
  //                                  toolCall.call_id  → context.intent_id
  // These are the key surface differences from LangGraph and CrewAI.
  const toolCall: OpenAIAgentsToolCall = {
    name: ca.toolName,
    input: ca.args,             // ← "input" not "args"
    call_id: `pinned-${ca.id}`, // ← "call_id" not "id"
    estimatedCost: ca.estimatedCost,
    resourceType: ca.resourceType,
    timestampSeconds: T_FIXED,
  };

  try {
    await guard(toolCall, async () => {});
  } catch (err) {
    if (!(err instanceof OxDeAIDenyError)) throw err;
  }

  assert.ok(record !== undefined, "OpenAI Agents: onDecision was not called");
  return {
    adapterName: "OpenAI Agents",
    decision: record.decision,
    reasons: record.reasons ?? [],
    intent: norm.getCapture(),
  };
}

async function runCrewAI(ca: ConceptualAction, opts: RunnerOptions = {}): Promise<AdapterResult> {
  const norm = makeNormalizerCapture(opts.baseNormalizer);
  let record: GuardDecisionRecord | undefined;

  const guard = createCrewAIGuard({
    engine: opts.engine ?? ENGINE,
    getState: opts.getState ?? (() => ({ state: structuredClone(POLICY_STATE), version: 0 })),
    setState: () => true,
    agentId: AGENT_ID,
    mapActionToIntent: norm.mapActionToIntent,
    onDecision: r => { record = r; },
    trustedKeySets: [TEST_KEYSET],
  });

  // CrewAI field mapping: toolCall.args → ProposedAction.args
  //                       toolCall.id   → context.intent_id
  // Same surface as LangGraph - CrewAI and LangGraph are structurally identical
  // at the ProposedAction boundary, but they are independent adapter packages.
  const toolCall: CrewAIToolCall = {
    name: ca.toolName,
    args: ca.args,
    id: `pinned-${ca.id}`,
    estimatedCost: ca.estimatedCost,
    resourceType: ca.resourceType,
    timestampSeconds: T_FIXED,
  };

  try {
    await guard(toolCall, async () => {});
  } catch (err) {
    if (!(err instanceof OxDeAIDenyError)) throw err;
  }

  assert.ok(record !== undefined, "CrewAI: onDecision was not called");
  return {
    adapterName: "CrewAI",
    decision: record.decision,
    reasons: record.reasons ?? [],
    intent: norm.getCapture(),
  };
}

// Convenience: run all three adapters with the same options and return results
// as a fixed-length tuple. All runners are launched concurrently; each receives
// an isolated state snapshot via opts.getState.
async function runAllAdapters(
  ca: ConceptualAction,
  opts: RunnerOptions = {}
): Promise<[AdapterResult, AdapterResult, AdapterResult]> {
  return Promise.all([
    runLangGraph(ca, opts),
    runOpenAIAgents(ca, opts),
    runCrewAI(ca, opts),
  ]);
}

// ── Cross-adapter equivalence assertions ──────────────────────────────────────
//
// These are the invariants that must hold across ALL adapters for ANY
// conceptual action. They are checked in priority order - decision is the most
// critical invariant; the others verify that the normalization path is
// semantically equivalent, not just coincidentally producing the same outcome.

function assertCrossAdapterEquivalence(
  results: AdapterResult[],
  ca: ConceptualAction,
  label: string
): void {
  const [first, ...rest] = results;

  // Invariant 1: decision - the primary protocol invariant.
  // Every adapter must produce the same ALLOW / DENY for the same conceptual action.
  for (const r of rest) {
    assert.equal(
      r.decision,
      first.decision,
      `[${label}] decision mismatch: ${first.adapterName}=${first.decision} vs ${r.adapterName}=${r.decision}`
    );
  }

  // Invariant 2: decision must match the expected outcome for this case.
  if (ca.expectedDecision !== undefined) {
    assert.equal(
      first.decision,
      ca.expectedDecision,
      `[${label}] all adapters agreed on "${first.decision}" but corpus expects "${ca.expectedDecision}"`
    );
  }

  // Invariant 3: action_type - must be inferred identically from toolName+resourceType.
  for (const r of rest) {
    assert.equal(
      r.intent.action_type,
      first.intent.action_type,
      `[${label}] action_type mismatch: ${first.adapterName}="${first.intent.action_type}" vs ${r.adapterName}="${r.intent.action_type}"`
    );
  }
  if (ca.expectedActionType !== undefined) {
    assert.equal(
      first.intent.action_type,
      ca.expectedActionType,
      `[${label}] action_type was "${first.intent.action_type}" but corpus expects "${ca.expectedActionType}"`
    );
  }

  // Invariant 4: metadata_hash - SHA-256 of canonical(args).
  // LangGraph/CrewAI receive args as toolCall.args; OpenAI receives them as
  // toolCall.input. After adapter mapping both arrive as ProposedAction.args
  // with identical content. The default normalizer's hashArgs() must produce
  // the same hex digest for all three.
  for (const r of rest) {
    assert.equal(
      r.intent.metadata_hash,
      first.intent.metadata_hash,
      `[${label}] metadata_hash mismatch: ${first.adapterName} vs ${r.adapterName} - ` +
      `args content diverged during adapter normalization`
    );
  }

  // Invariant 5: amount - BigInt(Math.round(estimatedCost * 1_000_000)).
  // Must be identical regardless of which adapter path produced the ProposedAction.
  for (const r of rest) {
    assert.equal(
      r.intent.amount,
      first.intent.amount,
      `[${label}] amount mismatch: ${first.adapterName}=${first.intent.amount} vs ${r.adapterName}=${r.intent.amount}`
    );
  }

  // Invariant 6: timestamp - the pinned T_FIXED value must survive all adapters.
  for (const r of rest) {
    assert.equal(
      r.intent.timestamp,
      first.intent.timestamp,
      `[${label}] timestamp mismatch: ${first.adapterName}=${first.intent.timestamp} vs ${r.adapterName}=${r.intent.timestamp}`
    );
  }

  // Invariant 7: agent_id - injected via config.agentId, must be threaded
  // identically by every adapter into context.agent_id → intent.agent_id.
  for (const r of rest) {
    assert.equal(
      r.intent.agent_id,
      first.intent.agent_id,
      `[${label}] agent_id mismatch: ${first.adapterName}="${first.intent.agent_id}" vs ${r.adapterName}="${r.intent.agent_id}"`
    );
  }
  assert.equal(
    first.intent.agent_id,
    AGENT_ID,
    `[${label}] agent_id was "${first.intent.agent_id}" but expected "${AGENT_ID}"`
  );

  // Invariant 8: denial reasons - on DENY, every adapter must surface the same
  // violation strings. The engine decision is deterministic given the same
  // intent + state, so violation messages must be identical.
  if (first.decision === "DENY") {
    const firstReasonsSorted = [...first.reasons].sort();
    for (const r of rest) {
      assert.deepEqual(
        [...r.reasons].sort(),
        firstReasonsSorted,
        `[${label}] DENY reasons mismatch: ${first.adapterName} vs ${r.adapterName}`
      );
    }
  }
}

// Assert that every result in `results` contains `reasonCode` in its reasons.
// Used after assertCrossAdapterEquivalence to pin the specific violation class.
function assertAllReasonsInclude(
  results: AdapterResult[],
  reasonCode: string,
  label: string
): void {
  for (const r of results) {
    assert.ok(
      r.reasons.includes(reasonCode),
      `[${label}] ${r.adapterName}: expected "${reasonCode}" in reasons, got: [${r.reasons.join(", ")}]`
    );
  }
}

// ── CORPUS TESTS: deterministic cases ────────────────────────────────────────

// Tool names are chosen to exercise every inferActionType branch:
//   "provision*"       → PROVISION  (safe default for infrastructure)
//   "send_payment"     → PAYMENT    (contains "send" + "pay")
//   "buy_storage"      → PURCHASE   (contains "buy")
//   "onchain_transfer" → ONCHAIN_TX (contains "onchain")
const ACTION_CORPUS: ConceptualAction[] = [
  {
    id: "provision-zero-cost",
    toolName: "provision_gpu",
    args: { tier: "standard", region: "us-east-1" },
    estimatedCost: 0,
    expectedDecision: "ALLOW",
    expectedActionType: "PROVISION",
  },
  {
    id: "provision-nonzero-cost",
    toolName: "provision_vm",
    args: { cores: 4, memory_gb: 16 },
    estimatedCost: 10,
    expectedDecision: "ALLOW",
    expectedActionType: "PROVISION",
  },
  {
    id: "payment-not-in-allowlist",
    toolName: "send_payment",
    args: { to: "recipient-wallet", amount: 100 },
    estimatedCost: 100,
    expectedDecision: "DENY",
    expectedActionType: "PAYMENT",
  },
  {
    id: "purchase-not-in-allowlist",
    toolName: "buy_storage",
    args: { size_gb: 500 },
    estimatedCost: 50,
    expectedDecision: "DENY",
    expectedActionType: "PURCHASE",
  },
  {
    id: "onchain-not-in-allowlist",
    toolName: "onchain_transfer",
    args: { to: "0xdeadbeef", wei: "1000000000000000000" },
    estimatedCost: 0,
    expectedDecision: "DENY",
    expectedActionType: "ONCHAIN_TX",
  },
];

for (const ca of ACTION_CORPUS) {
  test(`cross-adapter corpus: "${ca.id}" → ${ca.expectedDecision} across LangGraph / OpenAI Agents / CrewAI`, async () => {
    const results = await runAllAdapters(ca);
    assertCrossAdapterEquivalence(results, ca, ca.id);
  });
}

// ── CAP CORPUS TESTS: per-action cap boundary ─────────────────────────────────
//
// Verifies that BudgetModule's per-action cap (PER_ACTION_CAP_EXCEEDED) fires
// consistently across all adapters when estimatedCost exceeds the cap.
//
// CAP_STATE.max_amount_per_action = 500_000_000n (= 500 units).
// estimatedCost=500 → amount=500_000_000n = cap → ALLOW (not strictly greater).
// estimatedCost=501 → amount=501_000_000n > cap → DENY (PER_ACTION_CAP_EXCEEDED).
//
// Human-review note: BudgetModule denies when intent.amount > cap, not >=.
// The boundary is inclusive-allow: cost exactly equal to cap passes.

const CAP_CORPUS: ConceptualAction[] = [
  {
    id: "amount-at-cap",
    toolName: "provision_gpu",
    args: { tier: "high-mem" },
    estimatedCost: 500,
    expectedDecision: "ALLOW",
    expectedActionType: "PROVISION",
  },
  {
    id: "amount-exceeds-cap",
    toolName: "provision_gpu",
    args: { tier: "high-mem" },
    estimatedCost: 501,
    expectedDecision: "DENY",
    expectedActionType: "PROVISION",
  },
];

const capOpts: RunnerOptions = {
  engine: CAP_ENGINE,
  getState: () => ({ state: structuredClone(CAP_STATE), version: 0 }),
};

for (const ca of CAP_CORPUS) {
  test(`cross-adapter cap corpus: "${ca.id}" → ${ca.expectedDecision} across LangGraph / OpenAI Agents / CrewAI`, async () => {
    const results = await runAllAdapters(ca, capOpts);
    assertCrossAdapterEquivalence(results, ca, ca.id);

    // Pin the specific violation class - all adapters must agree on the cause.
    if (ca.expectedDecision === "DENY") {
      assertAllReasonsInclude(results, "PER_ACTION_CAP_EXCEEDED", ca.id);
    }
  });
}

// ── PBT SWEEP: seeded variation ───────────────────────────────────────────────
//
// Randomly varies tool name and estimatedCost across seeds. The expected
// decision is determined by whether the tool name falls into the PROVISION
// category (allowed) or any other category (denied by the allowlist module).
//
// This supplements the corpus tests by covering a wider range of (name, cost)
// combinations and asserting only the cross-adapter equivalence invariant
// (not an expected value), since random tools may or may not be known.
//
// Note: Because nonce is random and not pinned, the intent hash (which
// includes nonce) is NOT compared here. The invariant holds at the decision
// and evidence level (action_type, metadata_hash, amount, timestamp, agent_id).

// Tools that infer PROVISION → ALLOW given POLICY_STATE.
const PROVISION_TOOLS = [
  "provision_gpu",
  "provision_vm",
  "provision_cluster",
  "provision_storage",
] as const;

// Tools that infer a non-PROVISION type → DENY given POLICY_STATE.
const NON_PROVISION_TOOLS = [
  "send_payment",
  "buy_storage",
  "onchain_transfer",
  "mint_nft",
] as const;

const PBT_TOOL_POOL = [...PROVISION_TOOLS, ...NON_PROVISION_TOOLS] as const;

test("cross-adapter PBT: seeded variation → same decision + evidence across all adapters", async () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);

    const toolName = pick(rng, PBT_TOOL_POOL);
    const estimatedCost = randInt(rng, 0, 500);
    const argValue = randInt(rng, 1, 9999);

    // Expected decision is deterministic: PROVISION tools are allowed,
    // non-PROVISION tools are denied by the allowlist policy.
    const expectedDecision: "ALLOW" | "DENY" =
      (PROVISION_TOOLS as readonly string[]).includes(toolName) ? "ALLOW" : "DENY";

    const ca: ConceptualAction = {
      id: `pbt-seed-${seed}`,
      toolName,
      args: { value: argValue, region: "us-east-1" },
      estimatedCost,
      expectedDecision,
      // expectedActionType intentionally omitted - PBT only asserts cross-adapter equivalence.
    };

    const results = await runAllAdapters(ca);

    // In PBT we assert cross-adapter equivalence (invariants 1, 3–8) and that
    // the decision matches the known expected value (invariant 2).
    assertCrossAdapterEquivalence(
      results,
      ca,
      `pbt seed=${seed} tool=${toolName} cost=${estimatedCost}`
    );
  }
});

// ── NONCE REPLAY TEST ─────────────────────────────────────────────────────────
//
// All three adapters must agree that a nonce which already appears in the
// replay window produces REPLAY_NONCE, regardless of framework field mapping.
//
// Setup:
//   REPLAY_STATE has PINNED_NONCE pre-recorded at T_FIXED.
//   withFixedNonce(PINNED_NONCE) overrides the normalizer so every adapter
//   produces an intent carrying that exact nonce, not a random one.
//
// Why this matters for adapter portability:
//   If an adapter fails to thread its tool-call fields through to the
//   ProposedAction correctly, the normalizer might receive a different action
//   structure and produce a different (random) nonce. That adapter would then
//   incorrectly ALLOW the replay while the others correctly DENY. This test
//   surfaces that class of adapter drift.
//
// Adapter limitation note:
//   The nonce is not a first-class field in any adapter's tool-call type.
//   It must be injected via a custom mapActionToIntent (baseNormalizer here).
//   This is intentional: nonce management is a protocol concern, not a
//   framework concern. All adapters support mapActionToIntent overrides.

test("cross-adapter replay: same nonce as pre-recorded state → REPLAY_NONCE across all adapters", async () => {
  const ca: ConceptualAction = {
    id: "nonce-replay",
    toolName: "provision_gpu",
    args: { region: "us-east-1" },
    estimatedCost: 0,
    expectedDecision: "DENY",
  };

  const replayOpts: RunnerOptions = {
    engine: ENGINE,
    getState: () => ({ state: structuredClone(REPLAY_STATE), version: 0 }),
    baseNormalizer: withFixedNonce(PINNED_NONCE),
  };

  const results = await runAllAdapters(ca, replayOpts);

  // All adapters must agree: DENY with REPLAY_NONCE.
  assertCrossAdapterEquivalence(results, ca, "nonce-replay");
  assertAllReasonsInclude(results, "REPLAY_NONCE", "nonce-replay");
});

// ── CONCURRENT ISOLATION TEST ─────────────────────────────────────────────────
//
// Proves I6 (Evaluation Isolation): with structuredClone isolation, N parallel
// calls per adapter all ALLOW even though their combined cost would exhaust the
// budget if state were shared.
//
// Parameters (see CONCURRENCY_STATE definition above for the full derivation):
//   N_PER_ADAPTER = 10  →  30 total concurrent calls across 3 adapters
//   COST_PER_CALL = 5   →  5_000_000n micro-units per call
//   ISOLATED_BUDGET     →  100_000_000n micro-units = 100 units
//
//   Combined cost if accumulated: 30 × 5 = 150 units > 100-unit budget.
//   Per-call cost with isolation: 5 units ≤ 100-unit budget → ALLOW every time.
//
// Regression:
//   The former bug (structuredClone absent) caused later calls to observe
//   the budget already partially spent by earlier callers, producing spurious
//   BUDGET_EXCEEDED denials. This test would have caught that regression.

test("cross-adapter concurrent isolation: 30 parallel calls all ALLOW with isolated state (I6)", async () => {
  const N_PER_ADAPTER = 10;
  const COST_PER_CALL = 5;

  const concOpts: RunnerOptions = {
    engine: CONCURRENCY_ENGINE,
    getState: () => ({ state: structuredClone(CONCURRENCY_STATE), version: 0 }),
  };

  const ca: ConceptualAction = {
    id: "concurrent-isolation",
    toolName: "provision_gpu",
    args: { region: "us-east-1" },
    estimatedCost: COST_PER_CALL,
    expectedDecision: "ALLOW",
  };

  // Launch N_PER_ADAPTER × 3 calls concurrently. Each adapter runner calls
  // getState() once, which returns a fresh structuredClone. If getState
  // returned the same reference instead, deepMerge inside evaluatePure would
  // mutate the shared state's budget.spent_in_period, and calls beyond the
  // 20th would DENY with BUDGET_EXCEEDED.
  const tasks: Promise<AdapterResult>[] = [];
  for (let i = 0; i < N_PER_ADAPTER; i++) {
    tasks.push(
      runLangGraph(ca, concOpts),
      runOpenAIAgents(ca, concOpts),
      runCrewAI(ca, concOpts),
    );
  }

  const results = await Promise.all(tasks);

  for (let i = 0; i < results.length; i++) {
    assert.equal(
      results[i].decision,
      "ALLOW",
      `concurrent call ${i} (${results[i].adapterName}) got DENY ` +
      `[${results[i].reasons.join(", ")}]: state isolation failure - ` +
      `all ${results.length} calls must ALLOW when state is correctly isolated`
    );
  }
});
