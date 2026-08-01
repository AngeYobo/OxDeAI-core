// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTrustedTimeFile, runTrustedTimeConformance, trustedTimeExitCode } from "./trustedTimeConformance.js";

const root = fileURLToPath(new URL("../../../../", import.meta.url));
const source = JSON.parse(readFileSync(resolve(root, "packages/conformance/vectors/trusted-time.json"), "utf8"));
const clone = <T>(value: T): T => structuredClone(value);

test("trusted-time schema accepts the normative vector file", () => {
  const parsed = parseTrustedTimeFile(source);
  assert.equal(parsed.schema_version, "1.0.0");
  assert.equal(parsed.vectors.length, 44);
});

test("trusted-time schema rejects duplicate IDs with the exact ID", () => {
  const raw = clone(source);
  raw.vectors.push(clone(raw.vectors[0]));
  assert.throws(() => parseTrustedTimeFile(raw), /tt-issuance-before: duplicate vector ID/);
});

test("trusted-time schema rejects unknown categories", () => {
  const raw = clone(source);
  raw.vectors[0].category = "unknown_clock";
  assert.throws(() => parseTrustedTimeFile(raw), /tt-issuance-before: unknown category unknown_clock/);
});

test("trusted-time schema rejects unknown public reason codes", () => {
  const raw = clone(source);
  raw.vectors.find((v: any) => v.id === "tt-neg-001").expected.reasons = ["NOT_A_REASON"];
  assert.throws(() => parseTrustedTimeFile(raw), /tt-neg-001.*unsupported ReasonCode NOT_A_REASON/);
});

test("trusted-time schema rejects malformed status", () => {
  const raw = clone(source);
  raw.vectors[0].status = "skipped";
  assert.throws(() => parseTrustedTimeFile(raw), /tt-issuance-before: malformed status skipped/);
});

test("trusted-time schema requires blocked_by on pending vectors", () => {
  const raw = clone(source);
  raw.vectors[0].status = "pending";
  assert.throws(() => parseTrustedTimeFile(raw), /tt-issuance-before blocked_by/);
});

for (const [label, value] of [["fractional", 1.5], ["negative", -1], ["unsafe", Number.MAX_SAFE_INTEGER + 1], ["non-finite", Infinity], ["string", "10"]] as const) {
  test(`trusted-time schema rejects ${label} protocol seconds`, () => {
    const raw = clone(source);
    raw.vectors.find((v: any) => v.id === "tt-issuance-before").input.evaluation_time = value;
    assert.throws(() => parseTrustedTimeFile(raw), /tt-issuance-before input.evaluation_time/);
  });
}

test("an active expectation regression is a failing result with actionable ID", () => {
  const raw = clone(source);
  const vector = raw.vectors.find((v: any) => v.id === "tt-neg-001");
  vector.expected = { decision: "ALLOW", reasons: [] };
  const lines: string[] = [];
  const summary = runTrustedTimeConformance(raw, line => lines.push(line));
  assert.equal(summary.failed, 1);
  assert.equal(trustedTimeExitCode(summary), 1);
  assert.match(summary.failures[0]!, /^tt-neg-001:/);
  assert.ok(lines.some(line => line.startsWith("FAIL tt-neg-001:")));
});

test("pending vectors are reported separately and never counted as passing", () => {
  const raw = clone(source);
  raw.vectors[0].status = "pending";
  raw.vectors[0].blocked_by = "test-only blocker";
  const summary = runTrustedTimeConformance(raw, () => {});
  assert.equal(summary.active, 43);
  assert.equal(summary.passed, 43);
  assert.equal(summary.pending, 1);
});

test("replay sequence propagates nextState and detects corrupted step-two state", () => {
  const raw = clone(source);
  const vector = raw.vectors.find((v: any) => v.id === "tt-neg-002");
  vector.expected.steps[1].nonce_state = [];
  const summary = runTrustedTimeConformance(raw, () => {});
  assert.ok(summary.failures.some(f => f.startsWith("tt-neg-002:")));
  assert.match(summary.failures.find(f => f.startsWith("tt-neg-002:"))!, /step 2 intent_timestamp=1730000005 evaluation_time=1730000005/);
});

test("velocity sequence propagates nextState and preserves it on DENY", () => {
  const raw = clone(source);
  const vector = raw.vectors.find((v: any) => v.id === "tt-velocity-limit-active");
  vector.expected.steps[1].velocity_count = 2;
  const summary = runTrustedTimeConformance(raw, () => {});
  assert.ok(summary.failures.some(f => f.startsWith("tt-velocity-limit-active:")));
});

test("tool-window sequence propagates exact nextState and reports the failing step", () => {
  const raw = clone(source);
  const vector = raw.vectors.find((v: any) => v.id === "tt-tool-window-trusted-time");
  vector.expected.steps[1].tool_calls = [];
  const summary = runTrustedTimeConformance(raw, () => {});
  const failure = summary.failures.find(f => f.startsWith("tt-tool-window-trusted-time:"));
  assert.ok(failure);
  assert.match(failure, /step 2 intent_timestamp=1730000300 evaluation_time=1730000000/);
});

test("exact velocity time boundaries and deterministic repetition pass", () => {
  const ids = new Set(["tt-velocity-before-boundary", "tt-velocity-exact-boundary", "tt-velocity-after-boundary", "tt-velocity-deterministic"]);
  const raw = clone(source);
  raw.vectors = raw.vectors.filter((v: any) => ids.has(v.id));
  const summary = runTrustedTimeConformance(raw, () => {});
  assert.deepEqual({ active: summary.active, passed: summary.passed, failed: summary.failed }, { active: 4, passed: 4, failed: 0 });
});
