# OxDeAI Benchmark Suite

## Executive Summary

The current-HEAD full-suite run is recorded in
[`BENCHMARK_SUMMARY.md`](./BENCHMARK_SUMMARY.md), including commit, environment,
command, repeated-run percentiles, and noise classifications.

That run does not support a stable numeric overhead claim: relevant scenarios
contain noise or outlier warnings, and results are specific to the measured
host, runtime, fixture, and code revision. Use the suite to measure a deployment
candidate on comparable hardware rather than treating one run as a universal
runtime guarantee.

## Overview

The OxDeAI benchmark suite measures the performance characteristics of the OxDeAI authorization primitives.

Repo note: `bench/node_modules` is vendored to keep chart/canvas bindings stable for offline graph generation. If you need to trim the repo, delete that folder and run `pnpm -C bench install` to restore it.

The benchmark evaluates the latency and throughput of the deterministic authorization boundary used in agent execution environments.

Measured primitives:

- `evaluate()`
- `verifyAuthorization()`
- `verifyEnvelope()`

Primary benchmark scenarios:

- `evaluate`
- `verifyEnvelope`
- `baselinePath`
- `protectedPath`

Execution path scenarios:

- `baselinePath`
- `protectedPath`

The protected path is a synthetic execution flow containing OxDeAI
authorization checks and deterministic in-memory tool work. It is not an
end-to-end agent, model, network, or application benchmark.

## Benchmark Goals

The benchmark suite is designed to answer:

1. How expensive is OxDeAI policy evaluation?
2. How expensive is authorization verification?
3. How expensive is envelope verification?
4. What is the incremental cost of OxDeAI authorization in this synthetic execution path?

The most important measurement is:

`protectedPath - baselinePath`

which represents the incremental authorization overhead.

`verifyAuthorization` remains a separate diagnostic, while public
interpretation focuses on the complete protected-minus-baseline path.

## Why This Matters

Agent runtimes already spend time on orchestration, serialization, and tool execution overhead. OxDeAI should be evaluated as incremental boundary cost, not as isolated micro-function speed.

This suite measures the additional latency introduced by running the protected execution path versus a baseline runtime path.

The suite measures pre-execution authorization cost; whether that cost is
acceptable depends on the deployment workload and latency budget.

## Benchmark Methodology

The benchmark follows common systems benchmarking practices.

### Warmup phase

The runtime is warmed up before measurement to allow:

- JIT optimization
- memory allocation stabilization
- cache warming

### Measurement phase

Each scenario runs for a fixed number of iterations.

Timing is captured using:

`process.hrtime.bigint()`

which provides nanosecond resolution.

Samples are stored in nanoseconds and reported in milliseconds.

For documentation and interpretation, the project also reports the main
results in microseconds so absolute deltas remain easy to compare.

### Multiple runs

Each scenario can be executed multiple times (`--runs=N`) to reduce variance.

### Statistical metrics

Results include:

- p50 latency
- p95 latency
- p99 latency
- mean latency
- standard deviation
- coefficient of variation
- throughput (operations/sec)

Runs may be marked:

- `OK`
- `NOISY`
- `EXTREMELY_NOISY`

depending on the coefficient of variation.

## Benchmark Scenarios

### evaluate

Measures pure policy evaluation latency.

### verifyAuthorization

Measures the cost of verifying a cryptographic authorization artifact.

The benchmark fixture uses the reference shared-secret trust profile emitted by the bench
`PolicyEngine`, so `verifyAuthorization()` is run with `requireSignatureVerification: true`
and the benchmark HMAC secret. This avoids measuring the non-cryptographic fast path where
only field/binding checks are evaluated.

### verifyEnvelope

Measures verification of execution envelopes.

The current fixture envelope is unsigned. The benchmark supplies a valid
trusted key set for both modes but sets `requireSignatureVerification: false`,
so this scenario includes snapshot and audit-envelope verification but not
Ed25519 envelope-signature verification.

Supported modes:

- `best-effort`
- `strict`

### baselinePath

Synthetic execution path representing agent runtime work without OxDeAI.

The path performs deterministic synthetic tool execution.

No authorization checks occur.

### protectedPath

Execution path including OxDeAI authorization.

`evaluate -> verifyAuthorization -> verifyEnvelope -> tool execution`

The same synthetic tool execution is performed as in `baselinePath`.

This allows a clean comparison.

## Running the Benchmark

Install dependencies:

```bash
pnpm install
```

Run full benchmark:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4
```

Baseline only:

```bash
pnpm -C bench run run -- --scenario=baselinePath
```

Protected path:

```bash
pnpm -C bench run run -- --scenario=protectedPath --envelopeMode=both
```

## CLI Parameters

Parameter | Meaning
---|---
scenario | which scenario to run
runs | number of repeated runs
iterations | iterations per run
warmup | warmup iterations
concurrency | number of workers
envelopeMode | strict / best-effort / both

## Benchmark Output

Generated report files:

```text
bench/outputs/latest.json
bench/outputs/run-<timestamp>.json
```

JSON output includes:

- machine metadata
- Node.js version
- CPU information
- benchmark configuration
- per-scenario latency percentiles
- throughput
- noise classification

## Interpreting Results

The most meaningful metric is the absolute latency overhead between:

`protectedPath - baselinePath`

Percentage overhead may be misleading when the baseline path is extremely small.

Therefore absolute microsecond overhead should be considered the primary metric.

The current run contains noise and outlier warnings and therefore does not
support a stable external numeric claim. See
[`BENCHMARK_SUMMARY.md`](./BENCHMARK_SUMMARY.md) for the exact observations and
their classifications.

## Result Interpretation

Primary interpretation should focus on:

- baseline execution latency
- protected execution latency
- absolute authorization overhead

The benchmark is designed to emphasize absolute latency overhead in microseconds, not percentage overhead.

When baseline latency is very small, percentage deltas can become unstable and
visually misleading. Absolute deltas remain host- and workload-specific.

## How To Compare Across Machines

For cross-machine comparisons:

- compare absolute overhead first (microseconds), not only `ops/sec`
- compare `p50` / `p95` / `p99`, not only mean latency
- expect more jitter on laptops, WSL, VMs, and shared hosts
- use repeated single-worker runs for cleaner local interpretation (for example `--stabilityMode --runs=5`)

## Limitations

Benchmark results depend on:

- CPU
- Node.js runtime
- operating system
- virtualization environments

Results produced under WSL or VM environments may exhibit higher noise.

For best reproducibility, run on bare metal with minimal background load.
