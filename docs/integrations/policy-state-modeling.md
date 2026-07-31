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

The generalisation an operator can carry into their own rules: **an
agent-supplied field is safe as a lookup key into trusted state, and unsafe as
a decision by itself.** A rule shaped like "allow when the intent says it is
low-risk" places the decision in the agent's hands. A rule shaped like "look up
the intent's declared target in an operator-maintained allowlist" does not.

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

Two different things are therefore being checked, and it is worth keeping them
apart when reasoning about a deployment:

| Mechanism | Question it answers |
|---|---|
| `state_hash` (`computeStateHash`) | Is the live state the same logical state the authorization was minted against? |
| `StateVersion` (`getState`/`setState`) | Did anyone else advance the state between read and write? |

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

The consequence for operators: retry logic mints a fresh nonce, and a replay
refusal is not a transient error to be retried harder.

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
Rolling a period is therefore an operator action — write the new `period_id` and
zero the counters in the same state mutation — and `period_id` serves as the
label that makes the two epochs distinguishable in the canonical state, not as
a trigger.

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
long-running action whose `RELEASE` never arrives therefore holds its
concurrency slot until an operator writes the state to reclaim it. An operator
modeling long-running work owns that sweep; `expires_at` is the timestamp such a
sweep would key on, not a mechanism that acts on its own.

### State versioning

Covered by the CAS pattern above. The specification's §2 and §6 own the
normative requirements — including that a version token is never null, and is
not decremented or reset except through an audited rollback.

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
binds arguments as an opaque digest, which is enough to detect that arguments
changed, and not enough to say which of them the operator fixed.

### Per-user and per-tenant limits

Partially expressible. Every enforcement counter — budget, velocity,
concurrency, tool limits, recursion — is keyed by `agent_id`. A tenant
dimension can be encoded into the agent identifier by convention, for example
`tenant-a/agent-1`, and this works for accounting.

What it does not give is a checked property: nothing in the enforcement path
verifies that an agent belongs to the tenant its identifier claims. `DelegationV1`
carries `delegatee`, `issuer`, `audience` and a `scope` at the artifact layer,
so tenancy can be represented and verified there; the counters that gate the
decision do not read it. An operator relying on identifier conventions for
tenant isolation should know the boundary is a naming convention rather than a
verified one.

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
