# OxDeAI Current-HEAD Benchmark Summary

**Status:** Non-normative, host-specific benchmark evidence. Repeated clean-worktree
measurements on this host show a consistent protected-path p50 around 0.5-0.55 ms.
Tail latency and several component scenarios still contain noise and outlier
warnings, so these results are not a universal runtime guarantee.

## Provenance

- Git commit: `b2bcfcf603aefcd60ea0cbcd3b406b59cf77933d`
- Worktree at measurement: clean
- Timestamp: `2026-09-05T05:57:46.478Z`
- CPU: Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz
- Logical cores: 4
- Node.js: `v23.3.0`
- pnpm: `9.12.2`
- OS: Linux `6.6.87.2-microsoft-standard-WSL2` x64
- Environment: WSL2

The benchmark compatibility patch replaces the obsolete 17-character fixture
secret with a benchmark-only value satisfying the current PolicyEngine minimum,
supplies the now-required `policy_version` on the fixture's `DECISION` audit
event, and supplies a benchmark-only trusted key set to envelope verification.
Production validation and verification semantics are unchanged.

An earlier post-secret-fix run was rejected as evidence after an explicit
status preflight showed that its envelope fixture returned `invalid` and the
protected callback exited before synthetic tool work. None of that run's
latencies are used here. After correcting the benchmark-only envelope fixture,
the preflight returned `ALLOW`, authorization `ok`, and envelope `ok` for both
modes before the benchmark evidence was collected.

## Command and methodology

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both --output-dir=/tmp/oxdeai-bench-b2bcfcf-final-clean
````

* Seed: `20260310`
* Repetitions: 5 per scenario, worker count, and envelope mode
* Warmup: 10,000 invocations per repetition
* Measured samples: 100,000 per repetition
* Workers: 1 and 4
* Envelope modes: `best-effort` and `strict`
* Clock: `process.hrtime.bigint()` around each invocation
* Aggregation: the reported statistics are the median of the five per-run
  statistics; samples are not averaged together to hide noisy runs
* Four-worker mode divides the warmup and measured invocation totals across
  four worker threads, then combines their samples for each repetition
* Noise classification: `OK` for coefficient of variation (CV) at most 1.0,
  `NOISY` for CV at most 5.0, and `EXTREMELY_NOISY` above 5.0
* Outlier annotation: emitted when any repetition has `max > 100 × p50`

## Exact measured paths

`baselinePath` performs deterministic synthetic tool work only.

`protectedPath` performs:

```text
PolicyEngine.evaluatePure
  -> verifyAuthorization
  -> verifyEnvelope
  -> the same deterministic synthetic tool work as baselinePath
```

Authorization verification is included. The fixture uses the engine's
shared-secret HMAC authorization profile and calls `verifyAuthorization()` with
`requireSignatureVerification: true` and the matching benchmark-only HMAC
secret.

Envelope verification is also included. Both envelope modes receive a valid
trusted key set, but the fixture envelope is unsigned and the benchmark sets
`requireSignatureVerification: false`. These results therefore include
snapshot and audit-envelope verification, but not Ed25519 envelope-signature
verification.

The benchmark does not execute a model call, network request, database
operation, queue, or application tool. It is not an end-to-end agent-latency
benchmark.

## Results

All values below are medians across five runs, in microseconds.

| Scenario                        | Workers |    p50 |     p95 |     p99 |   mean | Harness status             |
| ------------------------------- | ------: | -----: | ------: | ------: | -----: | -------------------------- |
| `baselinePath`                  |       1 |   7.40 |    7.80 |   22.00 |   7.92 | `OK + OUTLIER_DETECTED`    |
| `protectedPath` (`best-effort`) |       1 | 548.20 |  737.70 | 2756.21 | 623.86 | `OK + OUTLIER_DETECTED`    |
| `protectedPath` (`strict`)      |       1 | 554.40 |  747.80 | 3102.31 | 641.59 | `OK + OUTLIER_DETECTED`    |
| `baselinePath`                  |       4 |  18.90 |   21.00 |   35.50 |  18.73 | `NOISY + OUTLIER_DETECTED` |
| `protectedPath` (`best-effort`) |       4 | 557.80 | 1075.31 | 3187.85 | 669.81 | `OK`                       |
| `protectedPath` (`strict`)      |       4 | 560.00 | 1181.43 | 2840.81 | 661.92 | `OK`                       |

Absolute overhead is computed as the independently aggregated
`protectedPath - baselinePath` percentiles:

| Mode          | Workers |   Δp50 |    Δp95 |    Δp99 |  Δmean |
| ------------- | ------: | -----: | ------: | ------: | -----: |
| `best-effort` |       1 | 540.80 |  729.90 | 2734.21 | 615.94 |
| `strict`      |       1 | 547.00 |  740.00 | 3080.31 | 633.67 |
| `best-effort` |       4 | 538.90 | 1054.31 | 3152.35 | 651.08 |
| `strict`      |       4 | 541.10 | 1160.43 | 2805.31 | 643.19 |

## Stability assessment

Across repeated clean-worktree runs on this host, the protected-path median
remains comparatively stable. In the latest run, all four protected-path
configurations are classified `OK`, with p50 overhead between 538.90 µs and
547.00 µs across one- and four-worker configurations.

The benchmark still contains important sources of variability. Several component
scenarios remain `NOISY`, the four-worker baseline is `NOISY`, and one-worker
protected-path runs contain outlier warnings. Tail latency is therefore less
stable than the median.

The current evidence supports a host-specific observation of approximately
0.5-0.55 ms p50 protected-path overhead on this machine and runtime. It does
not establish a universal OxDeAI latency guarantee.

## Reproduction and limitations

Run the exact command above on an otherwise idle host and retain all five
repetitions, including noisy or unfavorable results. Compare raw scenario
latencies and absolute deltas; percentage deltas are misleading when the
synthetic baseline is very small.

Important limitations:

* Results are specific to this CPU, Node version, WSL2 kernel, code revision,
  fixture, and scenario order.
* The synthetic tool workload cannot establish that authorization overhead is
  negligible relative to a deployment's model, network, or application work.
* Envelope signature verification is disabled, so these figures do not include
  Ed25519 envelope-signature verification.
* Percentile deltas subtract independently aggregated percentiles; they are not
  a distribution of paired per-invocation latency differences.
* Tail latency remains sensitive to runtime and scheduler noise even though the
  protected-path median is comparatively stable.
* The worker implementation does not currently dispatch `verifyDelegation`
  separately, so multi-worker delegation-labeled rows from `--scenario=all`
  are not delegation evidence. This does not affect the explicit baseline and
  protected worker branches used for the overhead table.
