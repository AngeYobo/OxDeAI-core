import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { PolicyEngine, encodeCanonicalState, encodeEnvelope } from "@oxdeai/core";
import type { State } from "@oxdeai/core";

import { runCli } from "./main.js";

function baseState(): State {
  return {
    policy_version: "v1",
    period_id: "2026-03",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PROVISION"],
      assets: ["a100"],
      targets: ["us-east-1"]
    },
    budget: {
      budget_limit: { "agent-1": 1_000_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 1_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 4 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 60, max_calls: { "agent-1": 100 }, max_calls_by_tool: {}, calls: {} }
  };
}

function jsonWithBigInt(v: unknown): string {
  return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? `${x.toString()}n` : x), 2);
}

async function setup() {
  const dir = await mkdtemp(join(tmpdir(), "oxdeai-cli-test-"));
  const policyFile = join(dir, "policy.json");
  const stateFile = join(dir, "state.json");
  const auditFile = join(dir, "audit.ndjson");
  await writeFile(policyFile, jsonWithBigInt(baseState()), "utf8");
  return { dir, policyFile, stateFile, auditFile };
}

function ioCapture(now = 1_770_000_000) {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      out: (line: string) => out.push(line),
      err: (line: string) => err.push(line),
      now: () => now
    }
  };
}

test("init writes state and clears audit", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  await writeFile(auditFile, "{\"junk\":1}\n", "utf8");

  const cap = ioCapture();
  const code = await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 0);

  const stateText = await readFile(stateFile, "utf8");
  assert.ok(stateText.length > 0);
  const auditText = await readFile(auditFile, "utf8");
  assert.equal(auditText, "");
  assert.equal(cap.err.length, 0);
});

test("launch allow path mutates state and appends audit", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(
    ["launch", "PROVISION", "320", "us-east-1", "--agent", "agent-1", "--nonce", "42", "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(code, 0);

  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.decision, "ALLOW");
  assert.equal(typeof latest.authorization_id, "string");

  const stateText = await readFile(stateFile, "utf8");
  assert.ok(stateText.includes("\"spent_in_period\":{\"agent-1\":\"320n\"}"));
  const auditText = await readFile(auditFile, "utf8");
  assert.ok(auditText.trim().split("\n").length >= 3);
});

test("launch deny path keeps state unchanged", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const denyState = baseState();
  denyState.kill_switch.global = true;
  await writeFile(policyFile, jsonWithBigInt(denyState), "utf8");

  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const before = await readFile(stateFile, "utf8");

  const code = await runCli(
    ["launch", "PROVISION", "320", "us-east-1", "--agent", "agent-1", "--nonce", "77", "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(code, 0);

  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.decision, "DENY");
  const after = await readFile(stateFile, "utf8");
  assert.equal(after, before);
});

test("audit command reports verify=true on valid chain", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "9", "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["audit", "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.verify, true);
  assert.equal(Array.isArray(latest.events), true);
});

test("state command prints valid json state", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["state", "--state", stateFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.policy_version, "v1");
  assert.ok(latest.velocity?.config);
});

test("verify-audit returns strict result for current audit file", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "11", "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["verify-audit", "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(Array.isArray(latest.violations), true);
});

test("snapshot-hash returns policyId and stateHash", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["snapshot-hash", "--state", stateFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.policyId, "string");
  assert.equal(typeof latest.stateHash, "string");
  assert.equal(latest.status, "ok");
});

test("verify-envelope reads file and verifies", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_123);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "12", "--state", stateFile, "--audit", auditFile], cap.io);

  const state = JSON.parse(await readFile(stateFile, "utf8"), (_k, v) => {
    if (typeof v === "string" && /^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    return v;
  }) as State;
  const events = (await readFile(auditFile, "utf8"))
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "dev-secret",
    authorization_ttl_seconds: 120
  });
  const snapshotBytes = encodeCanonicalState(engine.exportState(state));
  const envelope = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const envelopePath = join(dir, "envelope.bin");
  await writeFile(envelopePath, Buffer.from(envelope));

  const code = await runCli(["verify-envelope", envelopePath, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(Array.isArray(latest.violations), true);
});

test("make-envelope writes envelope file that verify-envelope accepts", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_222);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "13", "--state", stateFile, "--audit", auditFile], cap.io);

  const envelopePath = join(dir, "made-envelope.bin");
  const makeCode = await runCli(
    ["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(makeCode, 0);

  const verifyCode = await runCli(["verify-envelope", envelopePath, "--json"], cap.io);
  assert.equal(verifyCode, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(Array.isArray(latest.violations), true);
});
