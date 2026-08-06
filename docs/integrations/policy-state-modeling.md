# Policy And State Modeling Guidance

## Status

Non-normative (developer documentation)






This guide illustrates how an operator *could* model external policy and state
inputs against the current OxDeAI intent and state model.

It is downstream of [State Provider Requirements](../spec/state-provider-requirements.md),
which is normative and owns the trust contract around `getState()`, the
compare-and-set obligation, and the Profile A/B/C split. This document
references that specification rather than restating it, so the two cannot drift
apart. Where the two appear to disagree, the specification governs.

Every pattern below is an illustration of what an operator might express. None
of it is a recommendation from OxDeAI, and none of it defines protocol
semantics. OxDeAI defines the authorization boundary; operators own their
business rules.

Patterns that the current model cannot express are recorded in
[Recorded gaps](#recorded-gaps) rather than omitted or approximated.

## How To Read This Guide

Each pattern states what an operator wants, which fields carry it today, and
what the boundary does *not* decide. Field names refer to `State` and `Intent`
in `@oxdeai/core`, and to the guard configuration in `@oxdeai/guard`.

## Trusted Inputs And Agent-Supplied Inputs

The single most useful distinction when modeling policy is which inputs the
agent controls.

The repository already draws this line explicitly. `ToolAmplificationModule`
documents that `intent.tool_call` is *"a self-declared, agent-controlled field
and MUST NOT influence this decision (an agent can omit or falsify it to bypass
enforcement)"*, and that `intent.tool` is used *"only as a lookup key"* which
"must also resolve against trusted state". `AllowlistModule` resolves
`intent.action_type` and `intent.target` against `state.allowlists` the same
way.

Using an agent-supplied field as a lookup key does not by itself make that field
safe. A lookup key is security-relevant whenever it selects an agent-specific
policy bucket, tenant namespace, tool-specific quota, privilege profile,
allowlist entry, or any other state partition. Such a key is safe for that
purpose only when it is authenticated, derived from trusted execution context,
or checked against an authoritative closed mapping.

Trusted state does not authenticate the key used to select within it. For
example, a self-declared `agent_id` can select a more privileged agent profile,
and a self-declared `tool` can select an unconfigured or differently configured
tool quota bucket. Resolving either value against operator-maintained state
proves nothing about whether the agent was entitled to use that key. By
contrast, a target or other lookup key that has first been authenticated or
checked against an authoritative closed mapping can safely select the
corresponding trusted-state entry.

## State And Lifecycle

### Compare-and-set on a budget counter

This is the worked example, because it exercises state versioning, stale-write
rejection, retry behaviour, the retry/replay distinction, and why trusted state
provenance matters — in one flow.

The concurrency mechanism lives in the guard configuration
(`@oxdeai/guard`), and it is distinct from the semantic `state_hash` binding:

- `getState()` returns a `VersionedState`, that is `{ state, version }`, where
  `StateVersion` is `string | number` — "a monotonically-increasing integer,
  ETag, or any comparable value".
- `setState(state, expectedVersion)` must atomically verify that the persisted
  version still equals `expectedVersion` before committing, returning `true` on
  success and `false` on a version mismatch.
- On `false` the guard raises `OxDeAIConflictError` and blocks execution, with
  no execution side effects.

Several different properties are involved, and it is worth keeping them apart
when reasoning about a deployment:

| Property | Mechanism and limit |
|---|---|
| Snapshot integrity or consistency | `state_hash` (`computeStateHash`) shows only that the state snapshot supplied to verification matches the hash bound into the authorization. |
| Provider authority | Comes from deployment selection and authentication of the `StateProvider`, not from `state_hash`. |
| Freshness | Comes from the provider's consistency and freshness guarantees; a matching hash does not show that a snapshot was current or latest. |
| Version consistency | `StateVersion` identifies the version read and lets `setState` detect that it is no longer current. |
| Atomic state transition | The compare-and-set operation ensures that the write commits only if the expected version still holds. |

In particular, a matching `state_hash` does not independently prove that the
snapshot came from an authoritative provider, that the provider identity was
trusted, that the snapshot was current or the latest version, or that no
concurrent update occurred after evaluation. Likewise, CAS detects conflicting
state transitions but does not authenticate the source of the state supplied
to `getState()`.

A budget counter is the clearest case. `state.budget.budget_limit[agent]` and
`state.budget.spent_in_period[agent]` are keyed per agent. Two evaluators can
read the same remaining budget and each conclude there is room for one more
action. The CAS write is what makes only one of them win; the
loser sees `OxDeAIConflictError` and never executes.

Non-normative sketch:

```js
const { state, version } = await getState();

const out = engine.evaluatePure(intent, state, evaluationTime, { mode: "fail-fast" });
if (out.decision !== "ALLOW") {
  return refuse(out.reasons);
}

// Commit only if nobody advanced the state since the read.
if (!(await setState(out.nextState, version))) {
  // Concurrent modification. Nothing executed; the caller may re-read and retry.
  return conflict();
}
```

`evaluatePure(intent, state, evaluationTime, opts?)` is pure: it returns the
proposed `nextState` rather than mutating, which is what makes the read →
evaluate → CAS-write sequence expressible at all.

§2.2 of the specification adds a point worth surfacing here because it is easy
to get wrong: trusted-time velocity accounting **does not** remove the CAS
obligation. Window progression being derived from the trusted `evaluation_time`
does not stop two evaluators racing for the same remaining slot.

### Retries versus replay

An operator usually wants a retry after a network failure to succeed, and a
duplicate submission of an already-consumed action to be refused. These look
identical from the outside.

`state.replay` carries `window_seconds`, `max_nonces_per_agent`, and `nonces`
per agent. The discriminator is `intent.nonce`, keyed by `agent_id` — an intent
presented twice with the same nonce inside the window is refused. `intent_id`
plays no part in replay detection; if an operator wants to correlate a retry
with its original attempt, that is a convention they maintain in their own
records, not something the boundary reads.

Retry handling depends on how far the operation progressed. Before
authorization, CAS, or execution, submitting a new proposal with a new nonce
may be appropriate. After a definitive denial, the caller should follow the
denial semantics rather than treating it as a transient error.

After an ambiguous or unknown execution outcome, minting a fresh nonce may
cause the action to execute twice. That case requires an application-level
idempotency strategy: for example, reuse the same idempotency key, query the
execution status, replay the same protected request only through an idempotent
executor, or otherwise reconcile the outcome before issuing a new nonce. This
does not give `intent_id` replay-protection semantics; it remains an
application-level correlation convention.

A known CAS conflict occurs before protected execution in the guard path. The
losing operation should re-read authoritative state and its new version before
attempting a new authorization. That state-transition retry is distinct from
blindly retrying an operation whose execution outcome is unknown, and does not
by itself require minting a new execution nonce.

This is also the sharpest illustration of the trusted-input principle above.
`ReplayModule` documents that window eviction is driven exclusively by the
trusted evaluation clock and never by `intent.timestamp`, because entries are
retained while `entry.ts >= windowStart` — so an agent that postdates its intent
would push `windowStart` forward, prune its own previously recorded nonce, and
walk its replay straight through. The field is agent-controlled, so it cannot be
what decides.

### Budget counters

`state.budget.budget_limit` and `state.budget.spent_in_period` are keyed per
agent. `state.max_amount_per_action` is a per-action hard cap independent of the
remaining balance, so "no single action above X, and no more than Y in total"
is two separate controls rather than one.

`state.period_id` is worth being explicit about, because its name invites an
assumption the code does not support: **no policy module reads it.** Outside the
type definition it appears only in `stateGuards.ts`, which requires it to be
present and to be a string. Nothing resets `spent_in_period` when it changes.
Rolling a period is therefore an operator action, and `period_id` serves as the
label that makes two epochs distinguishable in canonical state rather than as a
trigger. Updating `period_id` and resetting `spent_in_period` describes one
logical mutation; it is not permission to overwrite provider storage directly.

Under the accepted Tier 1 architecture, rollover uses an authenticated
privileged operation against the same authoritative provider and version domain
as guard transitions:

```text
read current authoritative state and version
→ construct one atomic rollover mutation
→ update period_id and reset spent_in_period together
→ commit with the expected version
→ reject and retry from a fresh read on conflict
```

Administrative correction and other operator-initiated state changes follow
the same pattern. A separate authenticated administrative entry point may be
used, but direct or out-of-band rewrites that bypass provider versioning do not
satisfy Tier 1. This guide does not prescribe an operator identity technology,
role model, provider API, or administrative wire format.

### Concurrency limits

`state.concurrency` carries `max_concurrent` and `active` per agent, plus
`active_auths` keyed by authorization id with an `expires_at`. An `EXECUTE`
intent takes a slot; a `RELEASE` intent carrying `authorization_id` returns it.

`RELEASE` deliberately runs a narrower module set than `EXECUTE` — kill switch,
replay and concurrency only — so release paths are not gated on the same policy
surface as execution, and a release cannot be starved by, say, an exhausted
budget.

One property to model around: **`active_auths[...].expires_at` is stored and
validated, but nothing evicts on it.** It is carried through the state codec and
contributes to the state hash, and no module reads it to reclaim a slot. A
long-running action whose `RELEASE` never arrives therefore retains its
concurrency slot under current runtime behavior.

Expired-lease reclamation is tracked separately by
[#227](https://github.com/oxdeai/oxdeai/issues/227); its final owner and algorithm
remain unresolved. Any future automatic, operator-driven, or provider-managed
reclamation uses trusted `evaluationTime` and the same authoritative provider
and version domain as guard transitions. It must commit with an exact expected
version through CAS or equivalent conflict rejection. This guidance does not
implement reclamation, and the lease problem remains distinct from the
approval/workflow gap tracked by #218.

### State versioning

Covered by the CAS pattern above. The specification's §2 and §6 own the
normative requirements — including that a version token is never null, and is
not decremented or reset except through an audited rollback.

For Tier 1, the guard and privileged operator mutations share that one
authoritative version domain. `state_hash` binds an authorization to a snapshot;
it does not establish provider authority, freshness, or successful mutation.
CAS establishes atomic conflict handling; it does not authenticate the provider
or establish authorization provenance.

### Failure handling

`evaluatePure` accepts `{ mode: "collect-all" | "fail-fast" }`, defaulting to
`"fail-fast"`, and returns `reasons[]` alongside the decision. `"collect-all"`
suits a policy console where an operator wants every reason an action was
refused; `"fail-fast"` suits the enforcement path, where the first refusal is
sufficient and the remaining checks are wasted work.

A refusal is not an error. The decision path returns `DENY` with reasons, and
the tool does not run.

### Approval state

Not expressible today — see [Recorded gaps](#recorded-gaps).

## Scope And Binding

### Action target binding

`state.allowlists` carries `action_types`, `targets`, and `assets`, resolved
against `intent.action_type`, `intent.target`, and `intent.asset`.

Two properties are worth being precise about, because "allowlist" suggests
default-deny and the behaviour is narrower than that:

- **Each list constrains only when it is non-empty.** `AllowlistModule` checks a
  list only if it is present and has entries, so an unset or empty
  `allowlists.targets` permits every target rather than refusing all of them.
  Default-deny holds *within* a configured list, not at the configuration level.
- **The asset check requires the intent to carry an asset.** `intent.asset` is
  optional, and the asset comparison is skipped when it is absent — so an intent
  that omits `asset` is not measured against a populated `allowlists.assets`.

An operator relying on allowlists for isolation should therefore treat "the list
is configured and non-empty" as part of the policy, not as a given.

### Tool allowlists

Partially expressible, and the shape of the limitation matters — see
[Recorded gaps](#recorded-gaps). `state.tool_limits` expresses *rate*:
`max_calls` per agent and `max_calls_by_tool` per agent per tool, over
`window_seconds`. Setting a per-tool cap to `0` refuses that tool outright, so
a denylist is expressible by enumeration.

What is not expressible is the default-deny direction, because `state.allowlists`
has no tool axis.

### Credential provenance and scope binding

Not expressible today — see [Recorded gaps](#recorded-gaps).

### Argument provenance

Not expressible today — see [Recorded gaps](#recorded-gaps). `intent.metadata_hash`
binds arguments as an opaque digest. It can detect argument changes only when a
trusted component computes or recomputes the digest using a defined,
deterministic representation, compares it with the exact arguments that will
be executed, and ensures that the execution adapter cannot substitute different
arguments afterward. A proposer-controlled digest over proposer-controlled
arguments provides no independent argument provenance, and the digest cannot
say which arguments the operator fixed. Structured argument provenance remains
the gap tracked in #217; this guide does not redefine `metadata_hash`.

### Per-user and per-tenant limits

Partially expressible. Every enforcement counter — budget, velocity,
concurrency, tool limits, recursion — is keyed by `agent_id`. A tenant
dimension can be encoded into the agent identifier by convention, for example
`tenant-a/agent-1`, and this can partition accounting records, but it remains
only a naming convention.

What it does not give is a checked property: nothing in the enforcement path
verifies that an agent belongs to the tenant its identifier claims.
`DelegationV1` can bind signed delegation claims through its `delegatee`,
`issuer`, `audience`, and `scope` fields, but it does not independently prove
tenant membership. That requires an issuer authorized to assert the tenant
relationship, an authenticated principal-to-tenant mapping, and state and
policy namespaces that enforce the same tenant boundary. The counters that gate
the decision do not read such a mapping. Verified per-tenant enforcement
remains the gap tracked in #219.

## Recorded Gaps

Recorded rather than approximated, per the acceptance criteria of #166. Each is
tracked as its own issue, linked below.

| Gap | Why it is not expressible today |
|---|---|
| [Default-deny tool allowlist](https://github.com/oxdeai/oxdeai/issues/214) | `state.allowlists` has no tool axis; `AllowlistModule` reads `action_types`, `assets` and `targets` only. Per-tool refusal exists via `tool_limits.max_calls_by_tool[agent][tool] = 0`, but that is a denylist requiring enumeration, and a tool absent from configuration is permitted when `max_calls[agent]` is unset. |
| [Operator-defined action types](https://github.com/oxdeai/oxdeai/issues/215) | `ActionType` is a closed union of `PAYMENT`, `PURCHASE`, `PROVISION` and `ONCHAIN_TX`. An action outside that set cannot be named. |
| [Credential provenance and scope binding](https://github.com/oxdeai/oxdeai/issues/216) | Neither `Intent` nor `State` carries a credential identifier or scope, so a rule cannot require that an action was taken with a specific credential. |
| [Argument provenance](https://github.com/oxdeai/oxdeai/issues/217) | `metadata_hash` is a single opaque digest over arguments. Operator-fixed and agent-generated arguments cannot be distinguished. |
| [Approval state](https://github.com/oxdeai/oxdeai/issues/218) | There is no pending/approved/rejected concept in the policy state. `concurrency.active_auths` records granted authorizations with an `expires_at`, which is a lease rather than a workflow. |
| [Per-tenant limits as a verified property](https://github.com/oxdeai/oxdeai/issues/219) | Enforcement counters are keyed by `agent_id`; tenancy is a naming convention at that layer. |

## Related

- [State Provider Requirements](../spec/state-provider-requirements.md) — normative
- [Trusted Time](../spec/core/trusted-time-v1.md) — normative
- [Shared demo scenario](./shared-demo-scenario.md)
- [Production PEP wiring guide](../architecture/pep-production-guide.md)
