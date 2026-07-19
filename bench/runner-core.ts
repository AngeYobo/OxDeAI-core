import { Worker } from "node:worker_threads";
import type { BenchmarkConfig, ScenarioName } from "./config.js";
import { computeLatencyStats, median, measureIterations, type LatencyStats } from "./metrics.js";

export type ScenarioHandle = {
  scenario: ScenarioName;
  label: string;
  mode?: "strict" | "best-effort";
  work: () => unknown;
};

export type ScenarioRun = {
  scenario: ScenarioName;
  label: string;
  workers: number;
  iterations: number;
  warmupIterations: number;
  runs: number;
  stats: LatencyStats;
  status: "OK" | "NOISY" | "EXTREMELY_NOISY";
  outlierDetected: boolean;
  annotations: string[];
  sink: number;
  perRun: LatencyStats[];
};

type WorkerResult = { samplesNs: number[]; elapsedNs: number; sink: number };

function warmup(work: () => unknown, iterations: number): number {
  let sink = 0;
  for (let i = 0; i < iterations; i++) {
    const out = work();
    if (typeof out === "number") sink ^= out | 0;
    else if (typeof out === "string") sink ^= out.length;
    else if (out && typeof out === "object") sink ^= Object.keys(out as Record<string, unknown>).length;
  }
  return sink;
}

function aggregateStats(runs: LatencyStats[]): LatencyStats {
  return {
    count: Math.round(median(runs.map((r) => r.count))),
    min: median(runs.map((r) => r.min)),
    max: median(runs.map((r) => r.max)),
    mean: median(runs.map((r) => r.mean)),
    stddev: median(runs.map((r) => r.stddev)),
    p50: median(runs.map((r) => r.p50)),
    p95: median(runs.map((r) => r.p95)),
    p99: median(runs.map((r) => r.p99)),
    p999: median(runs.map((r) => r.p999)),
    opsPerSec: median(runs.map((r) => r.opsPerSec)),
    cv: median(runs.map((r) => r.cv)),
  };
}

function classifyNoise(cv: number): "OK" | "NOISY" | "EXTREMELY_NOISY" {
  if (cv <= 1.0) return "OK";
  if (cv <= 5.0) return "NOISY";
  return "EXTREMELY_NOISY";
}

const WORKER_CODE = `
const { parentPort, workerData } = require("node:worker_threads");

function seeded(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    return (x >>> 0) / 0x100000000;
  };
}
function makeState() {
  return {
    policy_version: "bench-complex-v1",
    period_id: "bench-period",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT","TRANSFER"], assets: ["USDC"], targets: ["merchant-3"] },
    budget: { budget_limit: { "agent-1": 1000000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 10000n },
    velocity: { config: { window_seconds: 60, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 1024, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 100 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 12 } },
    tool_limits: { window_seconds: 60, max_calls: { "agent-1": 1000 }, max_calls_by_tool: {}, calls: {} },
  };
}
function makeIntent(seed) {
  const rnd = seeded(seed);
  return {
    intent_id: "bench-worker-intent-" + Math.floor(rnd() * 10000),
    agent_id: "agent-1",
    action_type: "PAYMENT",
    type: "EXECUTE",
    nonce: 1n + BigInt(Math.floor(rnd() * 1000)),
    amount: 1500n,
    target: "merchant-3",
    timestamp: 1700000000,
    metadata_hash: "a".repeat(64),
    signature: "bench",
    depth: 1,
    tool_call: true,
    tool: "settle_invoice",
  };
}
function makeSyntheticToolExecutor() {
  let acc = 0x811c9dc5 >>> 0;
  const scratch = new Uint32Array(16);
  const ring = new Uint16Array(32);
  return (actionType, target, amount) => {
    const payload = JSON.stringify({
      actionType,
      target,
      amountMinor: amount,
      version: "v1",
      route: "dispatch",
      shape: "tool-call",
    });
    let h = acc;
    for (let round = 0; round < 16; round++) {
      for (let i = 0; i < payload.length; i++) {
        h ^= payload.charCodeAt(i) + round;
        h = Math.imul(h, 16777619) >>> 0;
        scratch[i & 15] = (scratch[i & 15] + h + i + round) >>> 0;
        ring[(i + round) & 31] = (ring[(i + round) & 31] + (h & 0xffff)) & 0xffff;
      }
    }
    for (let i = 0; i < scratch.length; i++) {
      h ^= scratch[i] + i;
      h = Math.imul(h ^ (h >>> 13), 0x5bd1e995) >>> 0;
    }
    for (let i = 0; i < ring.length; i++) {
      h ^= ring[i] + i * 17;
      h = Math.imul(h ^ (h >>> 11), 0x27d4eb2d) >>> 0;
    }
    acc = (h ^ (h >>> 15)) >>> 0;
    return acc;
  };
}
async function main() {
  const core = await import("@oxdeai/core");
  const { scenario, mode, seed, warmup, iterations } = workerData;
  const policyId = "0123456789abcdef".repeat(4);
  const engine = new core.PolicyEngine({
    policy_version: "bench-complex-v1",
    engine_secret: "bench-hmac-secret",
    authorization_ttl_seconds: 120,
    authorization_issuer: "bench-issuer",
    authorization_audience: "bench-rp",
    policyId,
    ...core.RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
  const intent = makeIntent(seed);
  const state = makeState();
  const allow = engine.evaluatePure(intent, state, 1700000000);
  const auth = allow.authorization;
  const snapshot = core.encodeCanonicalState({
    formatVersion: 1,
    engineVersion: "bench-engine",
    policyId,
    modules: state,
  });
  const snapVr = core.verifySnapshot(snapshot, { expectedPolicyId: policyId });
  const envelope = core.encodeEnvelope({
    formatVersion: 1,
    snapshot,
    events: [
      { type: "INTENT_RECEIVED", timestamp: 1700000000, policyId, intent_hash: "h".repeat(64), agent_id: "agent-1" },
      { type: "DECISION", timestamp: 1700000001, policyId, intent_hash: "h".repeat(64), decision: "ALLOW", reasons: [] },
      { type: "STATE_CHECKPOINT", timestamp: 1700000002, policyId, stateHash: snapVr.stateHash },
    ],
  });
  const runTool = makeSyntheticToolExecutor();
  const actionType = intent.action_type;
  const target = intent.target;
  const amount = Number(intent.amount);
  let work;
  if (scenario === "baselinePath") {
    work = () => {
      return runTool(actionType, target, amount);
    };
  } else if (scenario === "protectedPath") {
    const authOpts = {
      now: 1700000000,
      expectedIssuer: "bench-issuer",
      expectedAudience: "bench-rp",
      expectedPolicyId: policyId,
      consumedAuthIds: [],
      requireSignatureVerification: true,
      legacyHmacSecret: "bench-hmac-secret",
    };
    work = () => {
      const decision = engine.evaluatePure(intent, makeState(), 1700000000);
      if (decision.decision !== "ALLOW") return 0;
      const authVr = core.verifyAuthorization(auth, authOpts);
      if (authVr.status !== "ok") return 0;
      const envVr = core.verifyEnvelope(envelope, { mode, expectedPolicyId: policyId, requireSignatureVerification: false, now: 1700000000 });
      if (envVr.status !== "ok" && envVr.status !== "inconclusive") return 0;
      return runTool(actionType, target, amount);
    };
  } else if (scenario === "evaluate") {
    work = () => engine.evaluatePure(intent, makeState(), 1700000000);
  } else if (scenario === "verifyAuthorization") {
    const opts = {
      now: 1700000000,
      expectedIssuer: "bench-issuer",
      expectedAudience: "bench-rp",
      expectedPolicyId: policyId,
      consumedAuthIds: [],
      requireSignatureVerification: true,
      legacyHmacSecret: "bench-hmac-secret",
    };
    work = () => core.verifyAuthorization(auth, opts);
  } else {
    work = () => core.verifyEnvelope(envelope, { mode, expectedPolicyId: policyId, requireSignatureVerification: false, now: 1700000000 });
  }
  let sink = 0;
  for (let i = 0; i < warmup; i++) {
    const out = work();
    if (out && typeof out === "object") sink ^= Object.keys(out).length;
  }
  const samplesNs = new Array(iterations);
  const allStart = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const s = process.hrtime.bigint();
    const out = work();
    const e = process.hrtime.bigint();
    samplesNs[i] = Number(e - s);
    if (out && typeof out === "object") sink ^= Object.keys(out).length;
  }
  const elapsedNs = Number(process.hrtime.bigint() - allStart);
  parentPort.postMessage({ samplesNs, elapsedNs, sink });
}
main().catch((err) => { throw err; });
`;

async function runSingleAttempt(scenario: ScenarioHandle, config: BenchmarkConfig): Promise<{ stats: LatencyStats; sink: number }> {
  const warmupIterations = Math.max(10_000, config.warmupIterations);
  const iterations = Math.max(100_000, config.iterations);
  let sink = warmup(scenario.work, warmupIterations);
  const measured = measureIterations(iterations, scenario.work);
  sink ^= measured.sink;
  return { stats: computeLatencyStats(measured.samplesNs, measured.elapsedNs), sink };
}

async function runWorkersAttempt(
  scenario: ScenarioHandle,
  config: BenchmarkConfig,
  workers: number
): Promise<{ stats: LatencyStats; sink: number }> {
  const warmupIterations = Math.max(10_000, config.warmupIterations);
  const iterations = Math.max(100_000, config.iterations);
  const perWorkerWarmup = Math.ceil(warmupIterations / workers);
  const perWorkerIterations = Math.ceil(iterations / workers);
  const wallStart = process.hrtime.bigint();

  const tasks: Array<Promise<WorkerResult>> = [];
  for (let i = 0; i < workers; i++) {
    tasks.push(
      new Promise((resolve, reject) => {
        const worker = new Worker(WORKER_CODE, {
          eval: true,
          workerData: {
            scenario: scenario.scenario,
            mode: scenario.mode ?? "best-effort",
            seed: config.seed + i,
            warmup: perWorkerWarmup,
            iterations: perWorkerIterations,
          },
        });
        worker.on("message", (msg) => resolve(msg as WorkerResult));
        worker.on("error", reject);
        worker.on("exit", (code) => {
          if (code !== 0) reject(new Error(`worker exited with code ${code}`));
        });
      })
    );
  }
  const chunks = await Promise.all(tasks);
  const allSamples = new Float64Array(chunks.reduce((s, c) => s + c.samplesNs.length, 0));
  let sink = 0;
  let offset = 0;
  for (const c of chunks) {
    allSamples.set(c.samplesNs, offset);
    offset += c.samplesNs.length;
    sink ^= c.sink;
  }
  const wallElapsedNs = Number(process.hrtime.bigint() - wallStart);
  return { stats: computeLatencyStats(allSamples, wallElapsedNs), sink };
}

export async function runScenario(scenario: ScenarioHandle, config: BenchmarkConfig, workers: number): Promise<ScenarioRun> {
  const perRun: LatencyStats[] = [];
  let sink = 0;
  let outlierDetected = false;
  const annotations = new Set<string>();
  for (let i = 0; i < config.runs; i++) {
    const out = workers === 1 ? await runSingleAttempt(scenario, config) : await runWorkersAttempt(scenario, config, workers);
    perRun.push(out.stats);
    sink ^= out.sink;
    const extremeSpike = out.stats.p50 > 0 && out.stats.max > out.stats.p50 * 100;
    if (extremeSpike) {
      outlierDetected = true;
      annotations.add("OUTLIER_DETECTED");
    }
  }

  const stats = aggregateStats(perRun);
  return {
    scenario: scenario.scenario,
    label: scenario.label,
    workers,
    iterations: Math.max(100_000, config.iterations),
    warmupIterations: Math.max(10_000, config.warmupIterations),
    runs: config.runs,
    stats,
    status: classifyNoise(stats.cv),
    outlierDetected,
    annotations: [...annotations],
    sink,
    perRun,
  };
}
