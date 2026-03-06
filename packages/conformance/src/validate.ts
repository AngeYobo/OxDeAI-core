import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  encodeCanonicalState,
  encodeEnvelope,
  PolicyEngine,
  sha256HexFromJson,
  verifyAuthorization,
  verifyAuditEvents,
  verifyEnvelope,
  verifySnapshot
} from "@oxdeai/core";
import type { AuthorizationV1, Intent, State, VerificationResult } from "@oxdeai/core";

type JsonRecord = Record<string, unknown>;

type AuthorizationLike = {
  auth_id: string;
  issuer: string;
  audience: string;
  intent_hash: string;
  state_hash: string;
  policy_id: string;
  decision: "ALLOW" | "DENY";
  issued_at: number;
  expiry: number;
  state_snapshot_hash: string;
  expires_at: number;
  engine_signature: string;
};

type EnvelopeEvent = Parameters<typeof encodeEnvelope>[0]["events"][number];

type ConformanceAdapter = {
  name: string;
  canonicalJson(value: unknown): string;
  intentHash(intent: Intent): string;
  evaluateAuthorization(intent: Intent): { authorization: AuthorizationLike; policyId: string };
  encodeSnapshot(state: State): { bytes: Uint8Array; policyId: string };
  verifySnapshot(bytes: Uint8Array, expectedPolicyId?: string): VerificationResult;
  verifyAuditEvents(
    events: unknown[],
    opts?: { expectedPolicyId?: string; mode?: "strict" | "best-effort"; requireStateAnchors?: boolean }
  ): VerificationResult;
  verifyEnvelope(bytes: Uint8Array, opts?: { expectedPolicyId?: string; mode?: "strict" | "best-effort" }): VerificationResult;
  verifyAuthorization(auth: AuthorizationV1, opts?: {
    now?: number;
    expectedIssuer?: string;
    expectedAudience?: string;
    expectedPolicyId?: string;
    consumedAuthIds?: readonly string[];
  }): VerificationResult;
};

const CORE_ENGINE_SECRET = "test-secret";
const CORE_POLICY_ID = "a".repeat(64);
const INTENT_BINDING_FIELDS = [
  "intent_id",
  "agent_id",
  "action_type",
  "depth",
  "amount",
  "asset",
  "target",
  "timestamp",
  "metadata_hash",
  "nonce",
  "type",
  "authorization_id",
  "tool",
  "tool_call"
] as const;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: CORE_ENGINE_SECRET,
    authorization_ttl_seconds: 60,
    policyId: CORE_POLICY_ID
  });
}

function makeBaseState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-1": 5_000_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 2_000_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 10 },
      counters: {}
    },
    replay: {
      window_seconds: 300,
      max_nonces_per_agent: 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 3 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 5 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 50 },
      calls: {}
    }
  };
}

function asRecord(value: unknown): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("expected object");
  }
  return value as JsonRecord;
}

function parseIntent(input: unknown): Intent {
  const r = asRecord(input);
  const maybeType = r.type;
  const type = maybeType === "RELEASE" ? "RELEASE" : "EXECUTE";

  const base = {
    intent_id: String(r.intent_id),
    agent_id: String(r.agent_id),
    action_type: String(r.action_type) as Intent["action_type"],
    amount: BigInt(String(r.amount)),
    asset: r.asset === undefined ? undefined : String(r.asset),
    target: String(r.target),
    timestamp: Number(r.timestamp),
    metadata_hash: String(r.metadata_hash),
    nonce: BigInt(String(r.nonce)),
    signature: String(r.signature),
    depth: r.depth === undefined ? undefined : Number(r.depth),
    tool: r.tool === undefined ? undefined : String(r.tool),
    tool_call: r.tool_call === undefined ? undefined : Boolean(r.tool_call)
  };

  if (type === "RELEASE") {
    return {
      ...base,
      type: "RELEASE",
      authorization_id: String(r.authorization_id)
    };
  }

  return {
    ...base,
    type: "EXECUTE",
    authorization_id: r.authorization_id === undefined ? undefined : String(r.authorization_id)
  };
}

function parseState(input: unknown): State {
  const r = asRecord(input);
  const budget = asRecord(r.budget);
  const budget_limit = asRecord(budget.budget_limit);
  const spent_in_period = asRecord(budget.spent_in_period);

  const max_amount_per_action = asRecord(r.max_amount_per_action);

  const toBigintRecord = (rec: JsonRecord): Record<string, bigint> => {
    const out: Record<string, bigint> = {};
    for (const [k, v] of Object.entries(rec)) out[k] = BigInt(String(v));
    return out;
  };

  const state = makeBaseState();
  state.policy_version = String(r.policy_version);
  state.period_id = String(r.period_id);

  state.kill_switch = {
    global: Boolean(asRecord(r.kill_switch).global),
    agents: asRecord(asRecord(r.kill_switch).agents) as Record<string, boolean>
  };
  state.allowlists = asRecord(r.allowlists) as State["allowlists"];
  state.budget = {
    budget_limit: toBigintRecord(budget_limit),
    spent_in_period: toBigintRecord(spent_in_period)
  };
  state.max_amount_per_action = toBigintRecord(max_amount_per_action);
  state.velocity = asRecord(r.velocity) as State["velocity"];
  state.replay = asRecord(r.replay) as State["replay"];
  state.concurrency = asRecord(r.concurrency) as State["concurrency"];
  state.recursion = asRecord(r.recursion) as State["recursion"];
  state.tool_limits = asRecord(r.tool_limits) as State["tool_limits"];

  return state;
}

function b64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function hexSha256Utf8(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

const coreAdapter: ConformanceAdapter = {
  name: "@oxdeai/core",
  canonicalJson,
  intentHash(intent: Intent): string {
    const src = intent as unknown as Record<string, unknown>;
    const binding: Record<string, unknown> = {};
    for (const key of INTENT_BINDING_FIELDS) {
      const value = src[key];
      if (value !== undefined) binding[key] = value;
    }
    return sha256HexFromJson(binding);
  },
  evaluateAuthorization(intent: Intent) {
    const engine = makeEngine();
    const out = engine.evaluatePure(intent, makeBaseState());
    if (out.decision !== "ALLOW") {
      throw new Error(`expected ALLOW, got DENY: ${out.reasons.join(",")}`);
    }
    return { authorization: out.authorization, policyId: engine.computePolicyId() };
  },
  encodeSnapshot(state: State) {
    const engine = makeEngine();
    const snapshot = engine.exportState(state);
    return { bytes: encodeCanonicalState(snapshot), policyId: engine.computePolicyId() };
  },
  verifySnapshot(bytes: Uint8Array, expectedPolicyId?: string): VerificationResult {
    return verifySnapshot(bytes, expectedPolicyId ? { expectedPolicyId } : undefined);
  },
  verifyAuditEvents(events, opts) {
    return verifyAuditEvents(events as any, opts);
  },
  verifyEnvelope,
  verifyAuthorization
};

function loadJson<T>(name: string): T {
  const p = resolve(process.cwd(), "vectors", name);
  return JSON.parse(readFileSync(p, "utf8")) as T;
}

type VectorFile = { version: string; vectors: Array<JsonRecord> };

type CheckCtx = {
  failures: string[];
  passed: number;
};

function pass(ctx: CheckCtx, msg: string): void {
  ctx.passed += 1;
  console.log(`PASS ${msg}`);
}

function fail(ctx: CheckCtx, msg: string): void {
  ctx.failures.push(msg);
  console.error(`FAIL ${msg}`);
}

function eq(ctx: CheckCtx, label: string, actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(ctx, `${label}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  } else {
    pass(ctx, label);
  }
}

function validateIntentHashVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("intent-hash.json");
  const vectors = file.vectors;
  const hashes: Record<string, string> = {};

  for (const v of vectors) {
    const id = String(v.id);
    const intent = parseIntent(v.input);
    const got = adapter.intentHash(intent);
    const want = String(asRecord(v.expected).hash);
    hashes[id] = got;
    eq(ctx, `${id} hash`, got, want);
  }

  eq(ctx, "intent-hash-002 invariant", hashes["intent-hash-002"], hashes["intent-hash-001"]);
  eq(ctx, "intent-hash-003 invariant", hashes["intent-hash-003"], hashes["intent-hash-001"]);
}

function validateAuthorizationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("authorization-payload.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const intent = parseIntent(v.input);
    const { authorization, policyId } = adapter.evaluateAuthorization(intent);
    const expected = asRecord(v.expected);

    eq(ctx, `${id} intent_hash`, authorization.intent_hash, String(expected.intent_hash));
    if (expected.state_hash !== undefined) {
      eq(ctx, `${id} state_hash`, authorization.state_snapshot_hash, String(expected.state_hash));
    }
    eq(ctx, `${id} expires_at`, authorization.expires_at, Number(expected.expires_at));

    const payload = adapter.canonicalJson({
      expires_at: authorization.expires_at,
      intent_hash: authorization.intent_hash,
      policy_id: policyId,
      state_hash: authorization.state_snapshot_hash
    });
    eq(ctx, `${id} canonical_signing_payload`, payload, String(expected.canonical_signing_payload));
    eq(ctx, `${id} signature`, authorization.engine_signature, String(expected.signature));
  }
}

function validateAuthorizationVerificationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("authorization-verification.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const auth = asRecord(input.auth) as AuthorizationV1;
    const opts = (input.opts ? asRecord(input.opts) : {}) as {
      now?: number;
      expectedIssuer?: string;
      expectedAudience?: string;
      expectedPolicyId?: string;
      consumedAuthIds?: readonly string[];
    };
    const expected = asRecord(v.expected);
    const got = adapter.verifyAuthorization(auth, opts);

    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function validateSnapshotVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("snapshot-hash.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const expected = asRecord(v.expected);

    if (v.input_state !== undefined) {
      const state = parseState(v.input_state);
      const { bytes, policyId } = adapter.encodeSnapshot(state);
      const out = adapter.verifySnapshot(bytes, policyId);
      if (out.status !== "ok" || !out.stateHash) {
        fail(ctx, `${id} verifySnapshot expected ok`);
        continue;
      }
      eq(ctx, `${id} snapshot_base64`, Buffer.from(bytes).toString("base64"), String(expected.snapshot_base64));
      eq(ctx, `${id} state_hash`, out.stateHash, String(expected.state_hash));
    } else {
      const bytes = b64ToBytes(String(v.input_snapshot_base64));
      const out = adapter.verifySnapshot(bytes, CORE_POLICY_ID);
      if (out.status !== "ok" || !out.stateHash) {
        fail(ctx, `${id} verifySnapshot expected ok`);
        continue;
      }
      eq(ctx, `${id} state_hash`, out.stateHash, String(expected.state_hash));
    }
  }
}

function validateAuditChainVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("audit-chain.json");
  const [v1, v2, v3, v4] = file.vectors;

  const genesis = hexSha256Utf8(String(v1.input));
  eq(ctx, "audit-chain-001 genesis", genesis, String(asRecord(v1.expected).genesis_hex));

  const i2 = asRecord(v2.input);
  const e0 = i2.event_0;
  const head1 = hexSha256Utf8(`${String(i2.head_0)}\n${adapter.canonicalJson(e0)}`);
  eq(ctx, "audit-chain-002 head_1", head1, String(asRecord(v2.expected).head_1));

  const i3 = asRecord(v3.input);
  const events = (i3.events as unknown[]) ?? [];
  let head = String(i3.genesis);
  const heads: string[] = [];
  for (const ev of events) {
    head = hexSha256Utf8(`${head}\n${adapter.canonicalJson(ev)}`);
    heads.push(head);
  }
  const e3 = asRecord(v3.expected);
  eq(ctx, "audit-chain-003 head_1", heads[0], String(e3.head_1));
  eq(ctx, "audit-chain-003 head_2", heads[1], String(e3.head_2));
  eq(ctx, "audit-chain-003 head_3", heads[2], String(e3.head_3));

  const i4 = asRecord(v4.input);
  const mut = i4.mutated_event_0;
  const mutHead1 = hexSha256Utf8(`${String(i4.head_0)}\n${adapter.canonicalJson(mut)}`);
  const e4 = asRecord(v4.expected);
  eq(ctx, "audit-chain-004 original_head_1", String(e4.original_head_1), String(e4.original_head_1));
  eq(ctx, "audit-chain-004 mutated_head_1", mutHead1, String(e4.mutated_head_1));
  eq(ctx, "audit-chain-004 must differ", mutHead1 !== String(e4.original_head_1), true);
}

function buildEnvelopeCases(adapter: ConformanceAdapter): Array<{ status: string; violations: unknown[]; policyId?: string; stateHash?: string; auditHeadHash?: string }> {
  const engine = makeEngine();
  const state = makeBaseState();
  const intent = parseIntent({
    intent_id: "intent-300",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: "1000000",
    target: "merchant-1",
    timestamp: 1730000000,
    metadata_hash: "0".repeat(64),
    nonce: "300",
    signature: "sig-placeholder",
    depth: 0,
    tool: "openai.responses",
    tool_call: true,
    type: "EXECUTE"
  });

  const out = engine.evaluatePure(intent, state);
  if (out.decision !== "ALLOW") throw new Error("expected ALLOW for envelope cases");

  const events = engine.audit.snapshot();
  const snapshotBytes = encodeCanonicalState(engine.exportState(state));
  const snap = adapter.verifySnapshot(snapshotBytes, engine.computePolicyId());
  if (snap.status !== "ok" || !snap.stateHash) throw new Error("failed to build envelope cases");

  const valid = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const withCheckpointEvents: EnvelopeEvent[] = [
    ...events,
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: snap.stateHash,
      timestamp: intent.timestamp,
      policyId: engine.computePolicyId()
    }
  ];
  const withCheckpoint = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: withCheckpointEvents
  });
  const mismatchedEvents: EnvelopeEvent[] = events.map((e) => ({
    ...e,
    policyId: "c".repeat(64)
  }));
  const mismatched = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: mismatchedEvents
  });
  const corrupt = new Uint8Array([1, 2, 3, 4, 5]);

  return [
    adapter.verifyEnvelope(withCheckpoint, { expectedPolicyId: engine.computePolicyId(), mode: "strict" }),
    adapter.verifyEnvelope(valid, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(mismatched, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(corrupt, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(valid, { expectedPolicyId: engine.computePolicyId(), mode: "strict" })
  ];
}

function validateEnvelopeVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("envelope-verification.json");
  const actual = buildEnvelopeCases(adapter);

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];

    eq(ctx, `${id} status`, got.status, String(expected.status));
    if (expected.policyId !== undefined) eq(ctx, `${id} policyId`, got.policyId, String(expected.policyId));
    if (expected.stateHash !== undefined) eq(ctx, `${id} stateHash`, got.stateHash, String(expected.stateHash));
    if (expected.auditHeadHash !== undefined) eq(ctx, `${id} auditHeadHash`, got.auditHeadHash, String(expected.auditHeadHash));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function buildAuditVerificationCases(
  adapter: ConformanceAdapter
): Array<{ status: string; violations: unknown[] }> {
  const expectedPolicyId = "a".repeat(64);
  const mismatchPolicyId = "b".repeat(64);
  const altPolicyId = "c".repeat(64);

  const policyMismatch = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "11".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { expectedPolicyId, mode: "best-effort" }
  );

  const nonMonotonic = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "22".repeat(32),
        agent_id: "agent-1",
        timestamp: 200,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "22".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: expectedPolicyId
      }
    ],
    { mode: "best-effort" }
  );

  const mixedPolicy = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "33".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "33".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { mode: "best-effort" }
  );

  const strictMissingAnchor = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "44".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "44".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: expectedPolicyId
      }
    ],
    { mode: "strict" }
  );

  const orderingCase = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "55".repeat(32),
        agent_id: "agent-1",
        timestamp: 300,
        policyId: altPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "55".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { expectedPolicyId, mode: "strict" }
  );

  return [policyMismatch, nonMonotonic, mixedPolicy, strictMissingAnchor, orderingCase];
}

function validateAuditVerificationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("audit-verification.json");
  const actual = buildAuditVerificationCases(adapter);

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function main(): void {
  const ctx: CheckCtx = { failures: [], passed: 0 };
  const adapter = coreAdapter;

  console.log(`Running conformance validation with ${adapter.name}`);

  validateIntentHashVectors(ctx, adapter);
  validateAuthorizationVectors(ctx, adapter);
  validateAuthorizationVerificationVectors(ctx, adapter);
  validateSnapshotVectors(ctx, adapter);
  validateAuditChainVectors(ctx, adapter);
  validateAuditVerificationVectors(ctx, adapter);
  validateEnvelopeVectors(ctx, adapter);

  if (ctx.failures.length > 0) {
    console.error(`\nConformance failed: ${ctx.failures.length} assertion(s)`);
    process.exit(1);
  }

  console.log(`\nConformance passed: ${ctx.passed} assertions`);
}

main();
