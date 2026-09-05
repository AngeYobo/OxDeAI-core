# OxDeAI Benchmark Announcement

## Status

Non-normative (developer documentation)

Announcement draft. This file is not current release policy and must not be used as a release runbook. Current release policy is package-scoped and lives in [`docs/release/RELEASE.md`](./RELEASE.md).






OxDeAI includes a reproducible benchmark suite for measuring the runtime cost
of its authorization boundary. The current-HEAD run contains noise and outlier
warnings and does not support a stable numeric headline. Exact observations,
provenance, and limitations are recorded in
[`bench/BENCHMARK_SUMMARY.md`](../../bench/BENCHMARK_SUMMARY.md).

## Why this benchmark exists

For an agent runtime, the relevant engineering question is not whether a verifier is fast in isolation. The relevant question is whether a pre-execution authorization boundary can be enforced without materially changing runtime behavior.

OxDeAI is designed around that boundary:

- the runtime proposes an action
- OxDeAI evaluates policy deterministically
- an authorization artifact is emitted only on `ALLOW`
- the relying party verifies authorization before the side effect executes

That gives a fail-closed execution model for actions such as:

- tool calls
- external API calls
- payments
- provisioning operations

The benchmark exists to measure the practical cost of that boundary.

## What the suite measures

The benchmark reports four main scenarios:

- `evaluate`
- `verifyEnvelope`
- `baselinePath`
- `protectedPath`

These are the most useful scenarios for adoption decisions:

- `evaluate` isolates policy decision cost
- `verifyEnvelope` isolates envelope verification cost
- `baselinePath` provides a no-authorization comparison path
- `protectedPath` shows the actual inline cost of enforcing the boundary

`verifyAuthorization` is still measured in the suite, but it is treated as a secondary diagnostic result because its standalone latency is often close to the measurement noise floor relative to the end-to-end protected path.

## Latest measured result

The current run is a host-specific observation rather than a publication-ready
performance range. It uses five repetitions, 100,000 measured samples and
10,000 warmup invocations per repetition, 1 and 4 workers, and both envelope
modes. See the benchmark summary for the exact environment, p50/p95/p99 values,
and harness classifications.

## Interpretation

The benchmark does not show that authorization is “free,” nor does it establish
a universal bound. It measures a synthetic protected path on one host.

In deployments dominated by model calls, network I/O, database operations,
queueing, or external tool execution, teams can compare the measured local
authorization cost against those downstream latency budgets. This benchmark
does not measure that comparison directly.

This makes the benchmark useful for comparative systems testing, but whether
the measured cost is acceptable depends on the deployment workload and latency
budget.

## Reproducibility

The benchmark is included in the repository and is intended to be rerun.

Run the full suite locally with:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both
```

Important caveats:

- results depend on CPU, runtime, and scheduler behavior
- WSL, VMs, laptops, and shared hosts usually increase noise
- absolute overhead in microseconds is the primary metric
- p50 and mean are the clearest indicators of steady-state inline cost

For a full run-specific write-up, see [`bench/BENCHMARK_SUMMARY.md`](../../bench/BENCHMARK_SUMMARY.md).

## Short developer-facing copies

### X / Twitter

OxDeAI includes a reproducible protected-minus-baseline benchmark. The current
host-specific run is noisy, so consult the run report rather than quoting a
stable overhead range.

That path includes deterministic policy evaluation plus authorization/envelope
checks before synthetic tool work. The report records its host-specific cost
without asserting a universal bound.

Reproducible locally:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both
```

Repo: `github.com/oxdeai/oxdeai-core`

### Hacker News

OxDeAI is an authorization boundary for agent runtimes.

The model is simple: the runtime proposes an action, OxDeAI evaluates policy deterministically, emits an authorization on `ALLOW`, and the relying party verifies that authorization before any side effect executes. The goal is fail-closed execution control for tool calls, payments, provisioning, and similar agent actions.

We added a reproducible benchmark suite to measure the practical cost of that
boundary. It measures `evaluate`, `verifyAuthorization`, `verifyEnvelope`, and
baseline versus protected synthetic execution directly. The current run is
host-specific and noisy, so it is reported with exact classifications rather
than promoted as a stable range.

The result is not zero cost. For network- or model-bound runtimes it may be
small relative to downstream work, but that comparison is workload-dependent
and is not measured by this synthetic benchmark.

Important details:

- measured under Node.js on Linux/WSL2
- 100k iterations, 10k warmup, 5 runs
- concurrency 1 and 4 workers
- results depend on hardware/runtime
- benchmark is meant to be rerun, not treated as a universal constant

The repo includes the benchmark harness and a run-specific summary so the
methodology and reported observations can be inspected or reproduced.

### Reddit

OxDeAI is a deterministic authorization layer for agent actions.

We benchmarked a synthetic protected execution path containing policy
evaluation, authorization verification, envelope verification, and deterministic
in-memory tool work. The current host-specific result is noisy and is not a
stable overhead claim.

The microbenchmark measures the local cost of placing a fail-closed
authorization boundary in front of synthetic agent actions. Whether that cost
is acceptable is workload-dependent. Relevant applications include:

- tool execution
- external API calls
- payments
- provisioning flows

The benchmark is reproducible from the repo and reports `evaluate`, `verifyEnvelope`, `baselinePath`, and `protectedPath` separately.

### Developer summary

For an agent runtime, the relevant question is usually not whether authorization is fast in the abstract. The relevant question is whether a pre-execution policy boundary can be enforced without materially changing end-to-end runtime behavior.

The current OxDeAI measurement does not establish end-to-end impact for an
agent runtime. It measures deterministic in-memory work rather than HTTP
requests, model calls, database writes, queues, or external tool execution.
Teams should compare the protected-minus-baseline cost with their own workload
and latency budget.

That overhead buys a specific property: deterministic fail-closed execution control. The runtime can require a valid authorization artifact before the tool call happens, rather than relying on post-fact logging or heuristic filtering.

The benchmark is structured to make engineering review easier:

- `evaluate` isolates policy decision cost
- `verifyEnvelope` isolates verification artifact cost
- `baselinePath` gives a no-authorization comparison path
- `protectedPath` shows the actual inline cost of gating execution

These measurements are host-specific inline-overhead observations, not a
promise that every environment will see the same number. Teams should rerun the
benchmark on their own hardware and compare absolute microsecond overhead in a
controlled way.

### Quickstart example

```bash
pnpm add @oxdeai/core
```

```ts
import { PolicyEngine } from "@oxdeai/core";

const engine = new PolicyEngine({
  policy_version: "1.0.0",
  engine_secret: "replace-with-a-real-secret",
  authorization_ttl_seconds: 60,
  authorization_issuer: "your-pdp",
  authorization_audience: "your-relying-party",
  policyId: "a".repeat(64),
});

const intent = {
  intent_id: "intent-001",
  agent_id: "agent-1",
  action_type: "PAYMENT",
  type: "EXECUTE",
  nonce: 1n,
  amount: 1000n,
  target: "merchant-1",
  timestamp: Math.floor(Date.now() / 1000),
  metadata_hash: "b".repeat(64),
  signature: "app-signature",
  depth: 0,
  tool_call: true,
};

const state = {
  policy_version: "1.0.0",
  period_id: "period-2026-03",
  kill_switch: { global: false, agents: {} },
  allowlists: {
    action_types: ["PAYMENT"],
    assets: [],
    targets: ["merchant-1"],
  },
  budget: {
    budget_limit: { "agent-1": 10_000n },
    spent_in_period: { "agent-1": 0n },
  },
  max_amount_per_action: { "agent-1": 2_000n },
  velocity: {
    config: { window_seconds: 60, max_actions: 100 },
    counters: {},
  },
  replay: {
    window_seconds: 3600,
    max_nonces_per_agent: 1024,
    nonces: {},
  },
  concurrency: {
    max_concurrent: { "agent-1": 10 },
    active: {},
    active_auths: {},
  },
  recursion: {
    max_depth: { "agent-1": 4 },
  },
  tool_limits: {
    window_seconds: 60,
    max_calls: { "agent-1": 100 },
    max_calls_by_tool: {},
    calls: {},
  },
};

const result = engine.evaluatePure(intent, state);

if (result.decision === "ALLOW") {
  console.log("authorized");
  console.log(result.authorization);
} else {
  console.log("denied");
  console.log(result.reasons);
}
```
