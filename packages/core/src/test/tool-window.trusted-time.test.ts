// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { ToolAmplificationModule } from "../policy/modules/ToolAmplificationModule.js";
import type { Intent } from "../types/intent.js";
import type { PolicyResult } from "../types/policy.js";
import type { State } from "../types/state.js";

const AGENT = "agent-tool-window";
const TOOL = "search";
const T0 = 1_730_000_000;
const WINDOW = 60;

function intentAt(timestamp: number, nonce = 1n): Intent {
  return {
    intent_id: `tool-window-${nonce}`, agent_id: AGENT, action_type: "PAYMENT",
    type: "EXECUTE", amount: 1n, asset: "tool", target: "tool-1", timestamp,
    metadata_hash: "0".repeat(64), nonce, signature: "sig", depth: 0,
    tool: TOOL, tool_call: true,
  };
}

function toolState(
  calls: Array<{ ts: number; tool?: string }> = [],
  overrides: Record<string, unknown> = {},
): State {
  return {
    tool_limits: {
      window_seconds: WINDOW,
      max_calls: { [AGENT]: 1 },
      calls: { [AGENT]: calls },
      ...overrides,
    },
  } as unknown as State;
}

function eventsFrom(result: PolicyResult): Array<{ ts: number; tool?: string }> {
  assert.equal(result.decision, "ALLOW");
  const events = result.stateDelta?.tool_limits?.calls[AGENT];
  assert.ok(events);
  return events;
}

test("#213 first call starts the tool window at evaluationTime", () => {
  const result = ToolAmplificationModule(intentAt(T0 + 30), toolState(), { evaluationTime: T0 });
  assert.deepEqual(eventsFrom(result), [{ ts: T0, tool: TOOL }]);
});

test("#213 active window preserves its trusted start and exhausted calls deny without a delta", () => {
  const state = toolState([{ ts: T0, tool: TOOL }]);
  const before = structuredClone(state);
  const result = ToolAmplificationModule(intentAt(T0 + 30), state, { evaluationTime: T0 + 59 });
  assert.deepEqual(result, { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] });
  assert.ok(!("stateDelta" in result));
  assert.deepEqual(state, before);
});

for (const [label, evaluationTime, decision] of [
  ["just before", T0 + WINDOW - 1, "DENY"],
  ["at", T0 + WINDOW, "ALLOW"],
  ["after", T0 + WINDOW + 1, "ALLOW"],
] as const) {
  test(`#213 trusted tool window ${label} the exact boundary`, () => {
    const result = ToolAmplificationModule(
      intentAt(T0 + 10),
      toolState([{ ts: T0, tool: TOOL }]),
      { evaluationTime },
    );
    assert.equal(result.decision, decision);
    if (result.decision === "ALLOW") {
      assert.deepEqual(eventsFrom(result), [{ ts: evaluationTime, tool: TOOL }]);
    }
  });
}

test("#213 future and backdated intent timestamps cannot alter or bypass an exhausted window", () => {
  const state = toolState([{ ts: T0, tool: TOOL }]);
  const baseline = ToolAmplificationModule(intentAt(T0), state, { evaluationTime: T0 + 10 });
  for (const timestamp of [T0 - 290, T0 + 310]) {
    assert.deepEqual(
      ToolAmplificationModule(intentAt(timestamp), state, { evaluationTime: T0 + 10 }),
      baseline,
    );
  }
});

test("#213 only evaluationTime controls pruning and emitted timestamps", () => {
  const state = toolState([{ ts: T0, tool: TOOL }]);
  const before = ToolAmplificationModule(intentAt(T0 + WINDOW + 30), state, { evaluationTime: T0 + WINDOW - 1 });
  const exact = ToolAmplificationModule(intentAt(T0 - 240), state, { evaluationTime: T0 + WINDOW });
  assert.equal(before.decision, "DENY");
  assert.deepEqual(eventsFrom(exact), [{ ts: T0 + WINDOW, tool: TOOL }]);
});

test("#213 backward evaluationTime fails closed and preserves state", () => {
  const state = toolState([{ ts: T0, tool: TOOL }]);
  const before = structuredClone(state);
  const result = ToolAmplificationModule(intentAt(T0 - 1), state, { evaluationTime: T0 - 1 });
  assert.deepEqual(result, { decision: "DENY", reasons: ["STATE_INVALID"] });
  assert.deepEqual(state, before);
});

test("#213 malformed configuration matrix fails closed without coercion", () => {
  const malformed: State[] = [
    { tool_limits: undefined } as unknown as State,
    toolState([], { window_seconds: undefined }),
    toolState([], { window_seconds: "60" }),
    toolState([], { window_seconds: 1.5 }),
    toolState([], { window_seconds: 0 }),
    toolState([], { window_seconds: -1 }),
    toolState([], { window_seconds: NaN }),
    toolState([], { window_seconds: Infinity }),
    toolState([], { window_seconds: Number.MAX_SAFE_INTEGER + 1 }),
    toolState([], { max_calls: {} }),
    toolState([], { max_calls: { [AGENT]: "1" } }),
    toolState([], { max_calls: { [AGENT]: 1.5 } }),
    toolState([], { max_calls: { [AGENT]: -1 } }),
    toolState([], { max_calls: { [AGENT]: NaN } }),
    toolState([], { max_calls: { [AGENT]: Infinity } }),
    toolState([], { max_calls: { [AGENT]: Number.MAX_SAFE_INTEGER + 1 } }),
    toolState([], { max_calls: { [AGENT]: 1 }, max_calls_by_tool: { [AGENT]: { [TOOL]: 2 } } }),
    toolState([], { max_calls_by_tool: { [AGENT]: { [TOOL]: -1 } } }),
  ];
  for (const state of malformed) {
    assert.deepEqual(
      ToolAmplificationModule(intentAt(T0), state, { evaluationTime: T0 }),
      { decision: "DENY", reasons: ["STATE_INVALID"] },
    );
  }
});

test("#213 malformed persisted call state matrix fails closed and remains unchanged", () => {
  const malformed: State[] = [
    toolState([], { calls: undefined }),
    toolState([], { calls: { [AGENT]: {} } }),
    toolState([{ ts: "1" as unknown as number, tool: TOOL }]),
    toolState([{ ts: 1.5, tool: TOOL }]),
    toolState([{ ts: -1, tool: TOOL }]),
    toolState([{ ts: NaN, tool: TOOL }]),
    toolState([{ ts: Infinity, tool: TOOL }]),
    toolState([{ ts: Number.MAX_SAFE_INTEGER + 1, tool: TOOL }]),
    toolState([{ ts: T0, tool: "" }]),
    toolState([{ ts: T0, tool: TOOL }, { ts: T0, tool: TOOL }]),
    toolState([{ ts: T0, tool: TOOL }], {
      max_calls: { [AGENT]: 2 },
      max_calls_by_tool: { [AGENT]: { [TOOL]: 0 } },
    }),
  ];
  for (const state of malformed) {
    const before = structuredClone(state);
    assert.deepEqual(
      ToolAmplificationModule(intentAt(T0), state, { evaluationTime: T0 }),
      { decision: "DENY", reasons: ["STATE_INVALID"] },
    );
    assert.deepEqual(state, before);
  }
});

test("#213 safe-integer limits refuse unsafe configuration and never increment before checking capacity", () => {
  const exhausted = toolState([{ ts: Number.MAX_SAFE_INTEGER, tool: TOOL }], {
    window_seconds: Number.MAX_SAFE_INTEGER,
  });
  assert.deepEqual(
    ToolAmplificationModule(intentAt(T0), exhausted, { evaluationTime: Number.MAX_SAFE_INTEGER }),
    { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] },
  );
  const unsafe = toolState([], { max_calls: { [AGENT]: Number.MAX_SAFE_INTEGER + 1 } });
  assert.deepEqual(
    ToolAmplificationModule(intentAt(T0), unsafe, { evaluationTime: T0 }),
    { decision: "DENY", reasons: ["STATE_INVALID"] },
  );
});

test("#213 repeated evaluation is deterministic and does not mutate intent or state", () => {
  const intent = intentAt(T0 + 30);
  const state = toolState([{ ts: T0 - 10, tool: TOOL }], { max_calls: { [AGENT]: 2 } });
  const intentBefore = structuredClone(intent);
  const stateBefore = structuredClone(state);
  const first = ToolAmplificationModule(intent, state, { evaluationTime: T0 });
  const second = ToolAmplificationModule(intent, state, { evaluationTime: T0 });
  assert.deepEqual(first, second);
  assert.deepEqual(intent, intentBefore);
  assert.deepEqual(state, stateBefore);
});

test("#213 property: freshness-valid intent timestamps are tool-window noninterfering", () => {
  fc.assert(fc.property(
    fc.integer({ min: T0 - 300, max: T0 + 300 }),
    fc.integer({ min: T0 - 300, max: T0 + 300 }),
    (firstTimestamp, secondTimestamp) => {
      const state = toolState([{ ts: T0 - 10, tool: TOOL }]);
      assert.deepEqual(
        ToolAmplificationModule(intentAt(firstTimestamp), state, { evaluationTime: T0 }),
        ToolAmplificationModule(intentAt(secondTimestamp), state, { evaluationTime: T0 }),
      );
    },
  ));
});

test("#213 property: only trusted exact-boundary progression resets exhausted windows", () => {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 3_600 }),
    fc.integer({ min: 0, max: 3_600 }),
    (windowSeconds, elapsed) => {
      const state = toolState([{ ts: T0, tool: TOOL }], { window_seconds: windowSeconds });
      const result = ToolAmplificationModule(intentAt(T0 + 300), state, { evaluationTime: T0 + elapsed });
      if (elapsed < windowSeconds) {
        assert.deepEqual(result, { decision: "DENY", reasons: ["TOOL_CALL_LIMIT_EXCEEDED"] });
      } else {
        assert.deepEqual(eventsFrom(result), [{ ts: T0 + elapsed, tool: TOOL }]);
      }
    },
  ));
});
