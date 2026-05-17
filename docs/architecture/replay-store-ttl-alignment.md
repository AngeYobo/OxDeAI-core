# OxDeAI Replay-Store TTL Alignment

**Status:** Non-normative (developer documentation)
**Scope:** Replay-store TTL requirements, durability tiers, timing constraints, and operational guidance for production deployments

---

This document complements:

- [`docs/architecture/threat-model-external-providers.md`](./threat-model-external-providers.md) — threat model (see T-1: Replay Attack)
- [`docs/architecture/key-custody-and-rotation.md`](./key-custody-and-rotation.md) — key lifecycle (replay retention relates to authorization expiry)
- [`packages/guard/src/replayStore.ts`](../../packages/guard/src/replayStore.ts) — `ReplayStore` interface and in-memory implementation
- [`packages/guard/src/replayStore.redis.ts`](../../packages/guard/src/replayStore.redis.ts) — Redis implementation and `computeTtl`

**Core invariant:**

```text
replay retention ambiguity → DENY → no execution
```

---

## 1. What TTL Alignment Means

An authorization artifact has a **validity window** — the period between `issued_at` and `expiry` (or `expires_at`) during which it can be presented for execution. A replay store entry marks an `auth_id` as consumed. The entry must persist for at least as long as the authorization remains valid, or the same `auth_id` could be re-used after the store entry is evicted — a replay attack.

The alignment rule is:

```text
replay store entry retention ≥ authorization validity window
```

`authorization validity window = expiry − issued_at`

An entry that is evicted while the authorization is still unexpired creates a **replay window**: an attacker who captured the authorization before its first use could re-submit it after eviction.

**Expiry and replay retention are independent concepts:**

- `expiry` / `expires_at` — the guard rejects the authorization after this time (`AUTH_EXPIRED`)
- Replay TTL — the guard rejects re-use of `auth_id` for this duration

If the replay TTL is too short, the authorization expires naturally before any replay window opens. If the authorization's expiry window is long, the replay TTL must match.

---

## 2. Replay Lifecycle

```text
                                      ┌── replay store entry evicted
                                      │
 issued_at        first use      eviction?     expiry
    │                │               │            │
────┼────────────────┼───────────────┼────────────┼──────────►  time
    │                │               │            │
    │◄──────────────►│               │            │
    │  validity      │               │            │
    │  window        │               │            │
    │                │◄─────────────►│            │
    │                │  replay TTL   │            │
    │                │  (minimum)    │            │
    │
    │ LIFECYCLE STATES:
    │
    │  [ISSUABLE] issued_at → first use
    │      auth_id not yet consumed; authorization is valid
    │
    │  [CONSUMED] first use → eviction / expiry (whichever is later)
    │      auth_id consumed; replay attempts denied
    │
    │  [EXPIRED-CONSUMED] expiry reached, entry still in store
    │      authorization rejected by expiry check before replay check
    │      (belt-and-suspenders; no replay window)
    │
    │  [EVICTED-VALID] entry evicted before expiry  ← DANGER ZONE
    │      auth_id no longer in store; authorization still valid
    │      replay is possible if expiry check alone is not sufficient
    │
    │  [EVICTED-EXPIRED] entry evicted at or after expiry
    │      safe: auth rejected by expiry check before store lookup
    │      (or store would have returned true — still safe)
```

**The only dangerous state is EVICTED-VALID.** Correct TTL alignment eliminates it.

---

## 3. Formal TTL Rules

### Rule 1 — Minimum TTL

```text
replay_ttl(auth) ≥ auth.expiry − now_at_consume
```

Where `now_at_consume` is the clock time at the moment `consumeAuthId` is called (the first execution). Equivalently, since `consumeAuthId` is called before expiry:

```text
replay_ttl(auth) ≥ auth.expiry − auth.issued_at   (conservative bound)
```

Using `auth.expiry − now_at_consume` produces a tighter and correct TTL. Using `auth.expiry − auth.issued_at` is a safe over-estimate — the entry persists slightly longer than strictly necessary but eliminates all replay windows.

The Redis implementation uses the tighter bound:

```typescript
function computeTtl(expiry: number): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(1, expiry - now);     // seconds remaining until expiry
}
```

The minimum of 1 second prevents zero-TTL or negative-TTL conditions for already-expired artifacts (which are rejected by the expiry check before the store lookup, but the minimum guards against edge cases at exact expiry boundaries).

### Rule 2 — Clock Skew Buffer

Clock skew between the issuer, guard host, and replay store can cause the guard's `now` to differ from the issuer's clock at signing time. A skew of ±30 seconds is typical for NTP-synchronized hosts.

To account for skew, add a buffer:

```text
replay_ttl(auth) ≥ (auth.expiry − now_at_consume) + clock_skew_buffer
```

Recommended buffer: **60 seconds** for standard deployments; **120 seconds** for distributed multi-region deployments.

The Redis implementation does not add a buffer — it relies on the expiry check in `verifyAuthorization` being the primary expiry gate, and uses TTL only for garbage collection. Deployers requiring strict skew tolerance should set a longer authorization expiry window rather than relying on store TTL.

### Rule 3 — Minimum Retention Regardless of Expiry

Even if `expiry − now` evaluates to zero or negative (already-expired artifact), the store entry must be retained for at least 1 second. This prevents edge cases at exact expiry boundaries where a race between eviction and a concurrent replay attempt could permit a brief window.

```text
replay_ttl ≥ max(1, expiry − now_at_consume)
```

This is exactly what `computeTtl` enforces.

### Rule 4 — Delegation ID TTL

`consumeDelegationId` follows the same rules as `consumeAuthId`. The `opts.expiry` passed is the delegation's expiry, not the parent authorization's. The stricter of the two (parent auth expiry or delegation expiry) governs the effective validity window. In practice, delegations must not exceed the parent authorization's expiry (`DELEGATION_EXPIRY_EXCEEDS_PARENT`), so delegation TTL ≤ parent auth TTL.

### Summary Formula

```text
replay_ttl_seconds = max(1, auth.expiry − floor(Date.now() / 1000)) + optional_buffer
```

For a 5-minute authorization window with 60-second buffer:

```text
issued_at = T
expiry    = T + 300
TTL at T  = max(1, 300) + 60 = 360 seconds
TTL at T+150 (mid-window) = max(1, 150) + 60 = 210 seconds
```

---

## 4. Replay-Store Implementations

### 4.1 In-Memory Store (`createInMemoryReplayStore`)

```typescript
const store = createInMemoryReplayStore();
```

| Property | Value |
|---|---|
| Atomicity | Yes — JS single-threaded; no TOCTOU in-process |
| Persistence | No — `Set` is in-memory; cleared on process exit |
| TTL / eviction | No — entries persist until process ends (no GC) |
| Multi-process | No — each process has an independent `Set` |
| Restart durability | No |
| Production-ready | Development and single-process testing only |

**Limitations:**
- Grows unboundedly — `auth_id` entries are never evicted. For long-lived processes handling high volume, memory pressure accumulates.
- Does not prevent replay across process restarts or across multiple guard instances.
- The `opts.expiry` parameter is accepted but ignored.

**When it is safe to use:**
- Single-process deployments where replay risk is acceptable if the process restarts.
- Development and test environments.
- Short-lived processes (e.g., a Lambda function handling a single request).

### 4.2 Redis Store (`createRedisReplayStore`)

```typescript
const store = createRedisReplayStore({ client: redis });
```

| Property | Value |
|---|---|
| Atomicity | Yes — `SET NX EX` is a single atomic Redis command |
| Persistence | Configurable — AOF/RDB persistence survives restarts |
| TTL / eviction | Yes — key expires at `max(1, expiry − now)` seconds |
| Multi-process | Yes — all instances share one Redis cluster |
| Restart durability | Yes (with Redis persistence enabled) |
| Production-ready | Yes |

**Key schema:**
```text
replay:auth:<auth_id>             → "1" with TTL
replay:delegation:<delegation_id> → "1" with TTL
```

**Atomicity mechanism:** `SET key value NX EX ttl` either sets the key and returns `"OK"` (first use) or returns `null` (key exists — replay). No TOCTOU window exists; the check and set are one operation.

**Persistence configuration:**
- Enable AOF (`appendonly yes`) or RDB snapshots for restart durability.
- Without persistence, a Redis restart drops all replay state — equivalent to an in-memory store for the post-restart window.
- For regulated or high-security deployments, enable AOF with `appendfsync always`.

**Cluster behavior:**
- Redis Cluster: keys are sharded by slot. `auth_id` values are distributed across slots by default. All `SET NX EX` operations remain atomic per-slot; cross-slot TOCTOU is not a concern because each `auth_id` maps to exactly one slot.
- Redis Sentinel: automatic failover; short window during failover where store may be unavailable → guard throws → DENY (fail-closed).

**Client compatibility:**
- ioredis: native positional argument style — compatible directly.
- node-redis v4: requires a thin adapter (see [`replayStore.redis.ts`](../../packages/guard/src/replayStore.redis.ts) header comment).

### 4.3 PostgreSQL / Relational Store

Not provided in this release. The `ReplayStore` interface supports it.

```typescript
// Sketch — not production code
const store: ReplayStore = {
  async consumeAuthId(authId, { expiry }) {
    const result = await db.query(
      `INSERT INTO replay_auth (auth_id, expires_at)
       VALUES ($1, to_timestamp($2))
       ON CONFLICT (auth_id) DO NOTHING
       RETURNING auth_id`,
      [authId, expiry]
    );
    return result.rowCount === 1;
  },
};
```

| Property | Value |
|---|---|
| Atomicity | Yes — `INSERT ... ON CONFLICT DO NOTHING` is atomic per row |
| Persistence | Yes — full ACID guarantees |
| TTL / eviction | Manual — requires a scheduled cleanup job (e.g., `DELETE WHERE expires_at < now()`) |
| Multi-process | Yes |
| Restart durability | Yes |
| Production-ready | Yes, with proper index on `(auth_id)` and periodic eviction |

**TTL note:** Relational databases do not have native per-row TTL. An eviction job must run at interval to remove expired entries. The eviction interval should be short enough that the table does not grow unboundedly, but this is a maintenance concern — entries are rejected by the expiry check before the store lookup regardless.

### 4.4 DynamoDB Store

Not provided in this release. The `ReplayStore` interface supports it.

```typescript
// Sketch — not production code
const store: ReplayStore = {
  async consumeAuthId(authId, { expiry }) {
    try {
      await dynamoDb.putItem({
        TableName: "replay_auth",
        Item: {
          auth_id: { S: authId },
          ttl:     { N: String(expiry) },  // DynamoDB TTL attribute
        },
        ConditionExpression: "attribute_not_exists(auth_id)",
      });
      return true;
    } catch (err) {
      if (err.name === "ConditionalCheckFailedException") return false;
      throw err;  // fail-closed
    }
  },
};
```

| Property | Value |
|---|---|
| Atomicity | Yes — conditional `PutItem` with `attribute_not_exists` is atomic |
| Persistence | Yes — DynamoDB is durable by default |
| TTL / eviction | Yes — native DynamoDB TTL attribute (eventual eviction, up to 48h lag) |
| Multi-process | Yes |
| Restart durability | Yes |
| Production-ready | Yes |

**DynamoDB TTL note:** DynamoDB TTL eviction is eventual — items may persist for up to 48 hours after the TTL timestamp. This is safe: items are only evicted after they expire, never before. A consumed `auth_id` will not be evicted while the authorization is still valid; the authorization's expiry check fires first.

### 4.5 Shared `Map` (test / multi-instance simulation)

A `Map` instance shared across guard instances in the same process simulates cross-instance replay prevention without a backend:

```typescript
const shared = new Map<string, boolean>();
const store: ReplayStore = {
  async consumeAuthId(authId) {
    if (shared.has(authId)) return false;
    shared.set(authId, true);
    return true;
  },
};
```

- Suitable for testing multi-instance behavior within a single process.
- Same restart and persistence limitations as in-memory store.
- No TTL — grows unboundedly.

---

## 5. Timing and Clock Behavior

### 5.1 Clock Skew

Clock skew between the issuer (signing time), the guard host (verification time), and the Redis server (TTL base) can cause subtle misalignments:

```text
Issuer clock: T
Guard clock:  T + Δ   (Δ = skew, typically ±30s for NTP-synced hosts)
Redis clock:  T + δ   (δ = skew relative to guard host, typically <1s for co-located Redis)
```

**Effect on TTL:**
- If guard clock is ahead of issuer (`Δ > 0`): computed TTL = `expiry − (T + Δ)` is shorter than `expiry − T`. The store entry is evicted slightly earlier than the issuer intended.
- If guard clock is behind issuer (`Δ < 0`): computed TTL is longer. Entry persists slightly longer — no security impact.

**Mitigation:**
- Keep guard hosts NTP-synchronized (±1 second typical).
- Add a clock skew buffer to the authorization expiry window (e.g., issue authorizations with `expiry = now + window + 60s`). This is an issuer-side concern.
- Do not rely on replay store eviction for security — the expiry check in `verifyAuthorization` is the primary gate.

### 5.2 Delayed Delivery

An authorization issued at time T but not presented until T + delay:

```text
Replay store TTL at T+delay = max(1, expiry − (T + delay))
                             = max(1, (T + window) − (T + delay))
                             = max(1, window − delay)
```

If `delay ≥ window`, the authorization has already expired — rejected by expiry check before store lookup. If `delay < window`, the remaining TTL is shorter but still positive. No replay window is opened.

### 5.3 Late Execution / Expiry Race

A request arrives just before expiry:

```text
Presentation time: expiry − ε   (ε = small positive interval)
Expiry check: now < expiry → passes
Store consume: TTL = max(1, expiry − now) = max(1, ε) ≥ 1 second
```

The `max(1, ...)` floor ensures the store entry is set even in this boundary case. If `ε < 1s`, the TTL is 1 second — the entry persists for 1 second after expiry. Any replay attempt during that 1-second window is rejected by the expiry check first (`AUTH_EXPIRED`). No replay window.

### 5.4 Eviction Timing for Eventual-Eviction Stores

For stores with eventual eviction (DynamoDB, relational DB with batch cleanup):

- Store entries are not evicted immediately at expiry — they may persist for minutes to hours.
- This is strictly safer than early eviction: entries are never removed before their authorization expires.
- The store entry's logical `expired` state is enforced by the expiry check in `verifyAuthorization`, not by store eviction.

For stores with TTL-based eviction (Redis):

- Redis evicts keys lazily (on next access after TTL) and via background sweep.
- A key may persist for a brief period past its TTL before eviction occurs.
- This is safe: the key is in the "expired" logical state (expiry check fires), and the extra store presence does not permit replay.

### 5.5 Distributed Clock Drift

In multi-region deployments, guard instances in different regions may have clocks drifted by up to several seconds even with NTP. The computed TTL at each instance will differ by this drift amount.

**Safe direction:** If one instance computes a shorter TTL and evicts the key while another instance would not have evicted it yet, the expiry check provides the backstop — the authorization's `expiry` field is an absolute timestamp verified independently.

**Unsafe direction:** Clock drift could in theory cause one guard instance to accept an authorization (its clock says `now < expiry`) while another rejects it (`now ≥ expiry`). This is an expiry-consistency concern, not a replay-store concern. Mitigate with NTP synchronization and a short expiry grace period.

---

## 6. Failure Scenarios

### RT-1: Replay Entry Evicted Too Early

| Field | Detail |
|---|---|
| **Description** | The replay store TTL was set shorter than the authorization validity window; the `auth_id` entry is evicted while the authorization is still valid |
| **Enforcement point** | None — the expired entry means `consumeAuthId` returns `true` (first-use) on replay |
| **Expected verifier behavior** | Replay succeeds; guard executes the action again |
| **Operational impact** | Authorization reuse within the original expiry window is possible |
| **Fail-closed outcome** | Not fail-closed — this is the primary misconfiguration risk |
| **Mitigation** | Enforce Rule 1: TTL ≥ authorization validity window. Add skew buffer. |

### RT-2: Authorization Still Valid After Replay Eviction

| Field | Detail |
|---|---|
| **Description** | Same as RT-1, restated from the attacker's perspective: authorization has not expired, but its replay entry has been evicted |
| **Enforcement point** | Expiry check still rejects if `now ≥ expiry`; but if `now < expiry`, replay succeeds |
| **Expected verifier behavior** | Second execution allowed |
| **Fail-closed outcome** | No — depends on TTL alignment correctness |
| **Mitigation** | Use `computeTtl(expiry) = max(1, expiry − now)` (as the Redis implementation does). Never set TTL shorter than `expiry − issued_at`. |

### RT-3: Process Restart Loses Replay State

| Field | Detail |
|---|---|
| **Description** | In-memory replay store is cleared on process restart; consumed `auth_id` entries are lost |
| **Enforcement point** | None post-restart — `consumeAuthId` returns `true` for previously consumed IDs |
| **Expected verifier behavior** | Replayed authorizations succeed after restart |
| **Operational impact** | Any authorization consumed before restart can be replayed until its expiry |
| **Fail-closed outcome** | Not fail-closed for the restart window |
| **Mitigation** | Use a durable backend-backed store (Redis with persistence, PostgreSQL, DynamoDB) for production. In-memory store is explicitly development-only. |

### RT-4: Distributed Store Inconsistency

| Field | Detail |
|---|---|
| **Description** | Multiple guard instances use separate, unsynchronized in-memory stores; an `auth_id` consumed by instance A is not known to instance B |
| **Enforcement point** | None on instance B |
| **Expected verifier behavior** | Replay succeeds on instance B |
| **Fail-closed outcome** | Not fail-closed across instances |
| **Mitigation** | Share a single backend replay store (Redis cluster, DynamoDB table, PostgreSQL instance) across all guard instances. |

### RT-5: Replay Store Unavailable

| Field | Detail |
|---|---|
| **Description** | The replay store throws an exception (Redis down, DynamoDB timeout, network partition) |
| **Enforcement point** | Guard step 4 — `consumeAuthId` throws; guard catches and re-raises as `OxDeAIAuthorizationError` |
| **Expected verifier behavior** | DENY — execution blocked |
| **Operational impact** | All authorization requests denied during store outage |
| **Fail-closed outcome** | Yes — store unavailability → DENY. No fail-open path. |
| **Note** | This is an explicit availability/security trade-off. Deploy the replay store with appropriate availability SLA for the use case. |

### RT-6: TTL Shorter Than Expiry Window

| Field | Detail |
|---|---|
| **Description** | The replay store is configured with a fixed TTL (e.g., 60 seconds) but authorizations have a longer validity window (e.g., 5 minutes) |
| **Enforcement point** | None — fixed TTL does not track authorization expiry |
| **Expected verifier behavior** | Replay possible after 60 seconds for authorizations that expire at T+300 |
| **Fail-closed outcome** | Not fail-closed |
| **Mitigation** | Always derive TTL from `opts.expiry` (the authorization's actual expiry), not from a static configuration constant. |

### RT-7: Clock Skew

| Field | Detail |
|---|---|
| **Description** | Guard host clock is ahead of issuer clock by Δ seconds; computed TTL = `expiry − (T + Δ)` is shorter than intended |
| **Enforcement point** | Expiry check still fires at `expiry` per guard clock; replay store entry expires at `expiry − Δ` per guard clock |
| **Expected verifier behavior** | Window of replay risk = `Δ` seconds before expiry (entry evicted before expiry check fires) |
| **Fail-closed outcome** | Partially — replay is possible within the skew window |
| **Mitigation** | Add a skew buffer to TTL: `TTL = max(1, expiry − now + skew_buffer)`. Sync clocks with NTP. |

### RT-8: Delayed Execution

| Field | Detail |
|---|---|
| **Description** | Authorization is issued at T, not consumed until T+delay; compute TTL = `expiry − (T + delay) = window − delay` |
| **Enforcement point** | If `delay < window`: store entry TTL = `window − delay` (positive) — still safe. If `delay ≥ window`: authorization expired, rejected before store lookup. |
| **Expected verifier behavior** | Fail-closed in both cases |
| **Fail-closed outcome** | Yes — no replay window from delayed execution |

### RT-9: Retention Mismatch (Hybrid Stores)

| Field | Detail |
|---|---|
| **Description** | A deployment uses different replay stores for different guard instances (e.g., Redis on one, in-memory on another), and the stores are not synchronized |
| **Enforcement point** | Per-instance; no cross-instance consistency |
| **Expected verifier behavior** | Replay possible on instance with weaker store |
| **Fail-closed outcome** | Not fail-closed on the weaker instance |
| **Mitigation** | All instances sharing an execution boundary must use the same backend store. |

### RT-10: Partial Persistence

| Field | Detail |
|---|---|
| **Description** | Redis AOF/RDB persistence is enabled but not fully synced at the time of a crash; some consumed `auth_id` entries are lost from the persistence log |
| **Enforcement point** | Post-restart, lost entries are unknown to the store; replay is possible |
| **Operational impact** | Window of vulnerability = entries consumed since last persistence sync |
| **Fail-closed outcome** | Not fully fail-closed for lost entries |
| **Mitigation** | Use `appendfsync always` for maximum durability (performance trade-off). For most deployments, `appendfsync everysec` is an acceptable balance — at most 1 second of entries may be lost on crash. |

---

## 7. Operational Recommendations

### 7.1 Recommended TTL Formula

Always compute TTL from the authorization's absolute expiry, not from a static constant:

```text
TTL = max(1, auth.expiry − floor(now_seconds)) + clock_skew_buffer
```

Recommended clock skew buffers by deployment type:

| Deployment | Skew buffer |
|---|---|
| Single-host | 0 (NTP-synced clocks) |
| Multi-host same region | 30 seconds |
| Multi-host multi-region | 60–120 seconds |

### 7.2 Monitoring Signals

| Signal | Threshold | Meaning |
|---|---|---|
| `auth_id` consume rate (true) | Baseline | Normal execution flow |
| `auth_id` consume rate (false) | > 0 | Replay attempts detected |
| Store error rate | > 0 | Replay store degraded; executions being denied |
| Store latency (P99) | > 50ms | Store under load; risk of timeout → DENY |
| TTL set failures | > 0 | Redis rejecting SET NX EX (capacity/config issue) |
| Key count | Unbounded growth | Missing eviction (in-memory or no GC in relational) |

### 7.3 Deployment Examples

#### Small Deployment (Single Process)

```text
Guard: 1 instance
Replay store: createInMemoryReplayStore()
Durability: none (process restart resets)
Risk: replay after restart (acceptable for low-risk, short-lived deployments)
```

**Checklist:**
- [ ] Authorization expiry window is short (< 5 minutes recommended)
- [ ] Process restarts are infrequent and audited
- [ ] Not used for high-value or regulated actions

#### HA Deployment (Multi-Instance, Same Region)

```text
Guard: N instances behind a load balancer
Replay store: createRedisReplayStore({ client: redis })
Redis: single-primary with replica(s) + Sentinel for failover
Durability: AOF persistence (appendfsync everysec)
```

**Checklist:**
- [ ] Redis persistence enabled (`appendonly yes`)
- [ ] Sentinel or Cluster for HA
- [ ] TTL = `max(1, expiry − now)` (default `computeTtl`)
- [ ] Clock skew buffer: 30 seconds added to authorization expiry window (issuer-side)
- [ ] Guard handles Redis errors by DENY (no fallback to in-memory)
- [ ] Monitor: replay rate, store error rate, P99 latency

#### Offline Verifier Deployment

```text
Guard: not used for offline verification
Verifier: createVerifier({ trustedKeySets })
Replay store: N/A — verifyAuthorization does not check replay store
```

Offline verification (`createVerifier` / `verifyAuthorization`) does not enforce replay protection — it is stateless. Replay protection is a stateful enforcement concern at the guard/PEP layer. Do not use offline verification as a replay protection mechanism.

#### Multi-Region Deployment

```text
Guard: instances in region A and region B
Replay store: Redis Cluster with cross-region replication, or DynamoDB global tables
Durability: full persistence
Clock skew buffer: 120 seconds
```

**Checklist:**
- [ ] Cross-region replication lag is accounted for in authorization expiry window
- [ ] DynamoDB global tables or Redis Enterprise active-active for multi-region atomic SET NX
- [ ] Clock skew buffer 120 seconds (issuer-side expiry extension)
- [ ] Replay entries in region A are visible to region B within replication lag window
- [ ] Accept brief replay window equal to replication lag if using eventually-consistent replication

### 7.4 Production Checklist

```
REPLAY STORE SELECTION
[ ] Use createRedisReplayStore or equivalent durable backend in production
[ ] createInMemoryReplayStore is limited to development/test

ATOMICITY
[ ] consumeAuthId uses atomic check-and-set (SET NX EX for Redis; INSERT ON CONFLICT for SQL)
[ ] No read-then-write patterns

PERSISTENCE
[ ] Redis: appendonly yes + appendfsync everysec (or always for regulated deployments)
[ ] All guard instances share the same store

TTL
[ ] TTL derived from auth.expiry, not a static constant
[ ] TTL = max(1, expiry − now)
[ ] Optional clock skew buffer added at the issuer (authorization expiry window)

FAIL-CLOSED
[ ] Store errors propagate as throws — no silent fallback
[ ] Guard config does not set replayStore to an in-memory fallback on Redis error

MONITORING
[ ] Alert on false consumeAuthId rate (replay detection)
[ ] Alert on store error rate
[ ] Alert on store P99 latency > 50ms
```

---

## 8. Future Considerations

The following are potential future improvements. None are proposed as protocol changes.

- **TTL validation hook:** A startup check that verifies the configured replay store will produce TTLs correctly for a sample authorization. Surfaces misconfiguration before the first real execution.
- **Replay diagnostics:** Structured logging of `auth_id`, `expiry`, and computed `ttl` at consume time to support forensic analysis of replay attempts.
- **Deployment linting:** A CLI tool that validates `replayStore` configuration against the authorization expiry window configured in the policy engine.
- **Replay audit trail:** An optional append-only log of consumed `auth_id` values and timestamps for compliance and post-incident analysis.

---

## 9. Non-Goals

This document does NOT:

| Non-goal | Implication |
|---|---|
| Modify replay semantics | `consumeAuthId` behavior and `ReplayStore` interface are unchanged |
| Change `AuthorizationV1` | No new fields; `expiry` / `expires_at` handling is unchanged |
| Introduce coordination services | No control plane, no key server, no distributed locking service |
| Add online dependencies | Verification remains stateless offline-capable at the protocol level |
| Alter verification flow | Guard steps 1–8 are unchanged; this document only formalizes TTL requirements |

---

## 10. References

- [`packages/guard/src/replayStore.ts`](../../packages/guard/src/replayStore.ts) — `ReplayStore` interface; `createInMemoryReplayStore`
- [`packages/guard/src/replayStore.redis.ts`](../../packages/guard/src/replayStore.redis.ts) — `createRedisReplayStore`; `computeTtl`
- [`docs/architecture/threat-model-external-providers.md`](./threat-model-external-providers.md) — T-1: Replay Attack; T-8: Replay-store outage
- [`docs/architecture/key-custody-and-rotation.md`](./key-custody-and-rotation.md) — §7.4: replay TTL ≥ authorization expiry window
