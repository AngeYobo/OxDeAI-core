# OxDeAI Current-HEAD Benchmark Summary

**Status:** Non-normative, host-specific observation. The run contains noise
and outlier warnings and does not support a stable or universal overhead claim.

## Provenance

- Git commit: `ef00d4c2a71fc63e74287b626be4cac7f3491647`
- Worktree at measurement: dirty
- Dirty paths at measurement: `.gitignore`, `bench/cases/evaluate.ts`,
  `bench/cases/protectedPath.ts`, `bench/cases/verifyAuthorization.ts`,
  `bench/cases/verifyEnvelope.ts`, `bench/fixtures.ts`, and
  `bench/runner-core.ts`; the `.gitignore` change was pre-existing and unrelated
- Timestamp: `2026-09-04T14:59:46.749Z`
- CPU: Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz
- Logical cores: 4
- Node.js: `v23.3.0`
- pnpm: `9.12.2`
- OS: Linux `6.6.87.2-microsoft-standard-WSL2` x64
- Environment: WSL2
- Generated JSON SHA-256:
  `a03efd0eeef231585e571c41ed56a2e672d87a8a652a64c32378a4c78165e9f5`

The benchmark compatibility patch replaces the obsolete 17-character fixture
secret with a 44-character benchmark-only value, supplies the now-required
`policy_version` on the fixture's `DECISION` audit event, and supplies a
benchmark-only trusted key set to envelope verification. Production validation
and verification semantics are unchanged.

An earlier post-secret-fix run was rejected as evidence after an explicit
status preflight showed that its envelope fixture returned `invalid` and the
protected callback exited before synthetic tool work. None of that run's
latencies are used here. After correcting the benchmark-only envelope fixture,
the preflight returned `ALLOW` / authorization `ok` / envelope `ok` for both
modes before the run reported below was started.

## Command and methodology

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both --output-dir=/tmp/oxdeai-bench-ef00d4c-valid
```

- Seed: `20260310`
- Repetitions: 5 per scenario, worker count, and envelope mode
- Warmup: 10,000 invocations per repetition
- Measured samples: 100,000 per repetition
- Workers: 1 and 4
- Envelope modes: `best-effort` and `strict`
- Clock: `process.hrtime.bigint()` around each invocation
- Aggregation: the reported statistics are the median of the five per-run
  statistics; samples are not averaged together to hide noisy runs
- Four-worker mode divides the warmup and measured invocation totals across
  four worker threads, then combines their samples for each repetition
- Noise classification: `OK` for coefficient of variation (CV) at most 1.0,
  `NOISY` for CV at most 5.0, and `EXTREMELY_NOISY` above 5.0
- Outlier annotation: emitted when any repetition has `max > 100 × p50`

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

| Scenario | Workers | p50 | p95 | p99 | mean | Harness status |
|---|---:|---:|---:|---:|---:|---|
| `baselinePath` | 1 | 7.700 | 8.800 | 26.200 | 10.140 | `EXTREMELY_NOISY + OUTLIER_DETECTED` |
| `protectedPath` (`best-effort`) | 1 | 608.402 | 1846.107 | 5013.036 | 848.773 | `NOISY + OUTLIER_DETECTED` |
| `protectedPath` (`strict`) | 1 | 573.502 | 1086.004 | 3953.917 | 731.352 | `OK + OUTLIER_DETECTED` |
| `baselinePath` | 4 | 18.900 | 27.700 | 104.800 | 27.029 | `EXTREMELY_NOISY + OUTLIER_DETECTED` |
| `protectedPath` (`best-effort`) | 4 | 583.703 | 1933.808 | 5337.927 | 836.890 | `NOISY + OUTLIER_DETECTED` |
| `protectedPath` (`strict`) | 4 | 588.502 | 1916.217 | 4996.839 | 821.344 | `NOISY + OUTLIER_DETECTED` |

Absolute overhead is computed as the independently aggregated
`protectedPath - baselinePath` percentiles:

| Mode | Workers | Δp50 | Δp95 | Δp99 | Δmean |
|---|---:|---:|---:|---:|---:|
| `best-effort` | 1 | 600.702 | 1837.307 | 4986.836 | 838.633 |
| `strict` | 1 | 565.802 | 1077.204 | 3927.717 | 721.211 |
| `best-effort` | 4 | 564.803 | 1906.108 | 5233.127 | 809.860 |
| `strict` | 4 | 569.602 | 1888.517 | 4892.039 | 794.315 |

Per-run protected-path p50 values were:

| Mode | Workers | Five p50 observations (µs) |
|---|---:|---|
| `best-effort` | 1 | 616.202, 608.402, 614.803, 607.602, 587.102 |
| `strict` | 1 | 573.002, 574.102, 566.002, 573.502, 574.902 |
| `best-effort` | 4 | 583.703, 582.902, 587.903, 592.703, 583.002 |
| `strict` | 4 | 592.302, 594.203, 587.903, 588.502, 581.602 |

## Stability assessment

The protected-path p50 observations cluster within each configuration, but
three of four protected configurations are classified `NOISY`, every protected
configuration contains an outlier warning, and both baselines are classified
`EXTREMELY_NOISY`. Tail deltas vary substantially. The one `OK` aggregate
(`strict`, one worker) still contains an outlier warning and does not make the
overall evidence stable.

Consequently, this run is suitable for exposing the current order of magnitude
and for finding benchmark regressions. It is not suitable for publishing a
stable numeric overhead range. In particular, it does not support the former
public numeric range or a narrower replacement range.

## Reproduction and limitations

Run the exact command above on an otherwise idle host and retain all five
repetitions, including noisy or unfavorable results. Compare raw scenario
latencies and absolute deltas; percentage deltas are misleading when the
synthetic baseline is very small.

Important limitations:

- Results are specific to this CPU, Node version, WSL2 kernel, code revision,
  fixture, and scenario order.
- The recorded run necessarily used an uncommitted benchmark compatibility
  patch. A clean-worktree run should be recorded after that patch is merged and
  before any numeric result is promoted externally.
- The synthetic tool workload cannot establish that authorization overhead is
  negligible relative to a deployment's model, network, or application work.
- Envelope signature verification is disabled, so these figures do not include
  Ed25519 envelope-signature verification.
- Percentile deltas subtract independently aggregated percentiles; they are not
  a distribution of paired per-invocation latency differences.
- The worker implementation does not currently dispatch `verifyDelegation`
  separately, so multi-worker delegation-labeled rows from `--scenario=all`
  are not delegation evidence. This does not affect the explicit baseline and
  protected worker branches used for the overhead table.
