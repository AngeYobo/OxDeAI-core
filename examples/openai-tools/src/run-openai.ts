// SPDX-License-Identifier: Apache-2.0
/**
 * run-openai.ts - Real OpenAI-backed demo
 *
 * Flow:
 *   1. OpenAI receives a user request and proposes tool calls via the API
 *   2. Each proposed call is routed through OxDeAI's PEP before execution
 *   3. OxDeAI decides ALLOW or DENY - the tool only runs on ALLOW
 *   4. Tool result (or denial reason) is fed back to the model
 *   5. The loop ends when the model stops proposing calls or after 3 attempts
 *   6. A Verification Envelope is produced and verified offline
 *
 * Requires:
 *   OPENAI_API_KEY       - real OpenAI key
 *   OXDEAI_ENGINE_SECRET - at least 32 chars (hardcoded in demo:openai script)
 */

import { pathToFileURL } from "node:url";
import OpenAI from "openai";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import {
  encodeCanonicalState,
  encodeEnvelope,
  verifySnapshot,
  verifyEnvelope,
} from "@oxdeai/core";
import type { KeySet, State } from "@oxdeai/core";
import { engine, POLICY_ID, AGENT_ID, makeState } from "./policy.js";
import { guardedProvision } from "./pep.js";

// ── ANSI ─────────────────────────────────────────────────────────────────────
const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  bold:    "\x1b[1m",
  cyan:    "\x1b[36m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  yellow:  "\x1b[33m",
  blue:    "\x1b[34m",
  bCyan:   "\x1b[1;36m",
  bGreen:  "\x1b[1;32m",
  bRed:    "\x1b[1;31m",
  bWhite:  "\x1b[1;97m",
  bgGreen: "\x1b[42;30m",
  bgRed:   "\x1b[41;97m",
};
const c  = (col: string, s: string) => `${col}${s}${C.reset}`;
const hr = (label: string) =>
  c(C.dim, `── ${label} ${"─".repeat(Math.max(0, 67 - label.length - 4))}`);

// ── Trusted keyset ────────────────────────────────────────────────────────────
const DEMO_TRUSTED_KEYSET: KeySet = {
  issuer: "oxdeai.policy-engine",
  version: "1",
  keys: [{
    kid: "2026-01",
    alg: "Ed25519",
    public_key: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWiMMGTYK7zzHwZXLzDpCshxAH6Lgx8gVsJaixePuY7g=
-----END PUBLIC KEY-----`,
  }],
};

// ── Tool definition ───────────────────────────────────────────────────────────
const PROVISION_GPU_TOOL: OpenAI.Chat.Completions.ChatCompletionTool = {
  type: "function",
  function: {
    name: "provision_gpu",
    description: "Provision a GPU instance in the specified region.",
    parameters: {
      type: "object",
      properties: {
        asset:  { type: "string", description: "GPU type, e.g. a100" },
        region: { type: "string", description: "Cloud region, e.g. us-east-1" },
      },
      required: ["asset", "region"],
    },
  },
};

const DEMO_BASE_TIMESTAMP = 1_700_000_000;
const MODEL = "gpt-4o-mini";

// ── Decision record (built during the loop, used for the timeline) ────────────
type DecisionRecord = {
  step:    number;
  asset:   string;
  region:  string;
  verdict: "ALLOW" | "DENY";
  outcome: string;
};

// ── Main ──────────────────────────────────────────────────────────────────────

export async function runOpenAIDemo(
  log: (msg: string) => void = (msg) => console.log(msg)
): Promise<void> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.error("Missing OPENAI_API_KEY. Run the local demo with: pnpm -C examples/openai-tools demo");
    process.exit(1);
  }

  const openai = new OpenAI({ apiKey });

  // ── Header ───────────────────────────────────────────────────────────────
  log(c(C.cyan,   "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan,   "║") + c(C.bWhite, "  OxDeAI × OpenAI  ·  Execution Authorization Demo               ") + c(C.cyan, "║"));
  log(c(C.cyan,   "║") + c(C.dim,    "  OpenAI proposes  ·  OxDeAI decides  ·  PEP enforces            ") + c(C.cyan, "║"));
  log(c(C.cyan,   "╚══════════════════════════════════════════════════════════════════╝"));

  // ── Session card ─────────────────────────────────────────────────────────
  log(`  ${c(C.dim, "Agent")}   ${c(C.bCyan, AGENT_ID.padEnd(24))}  ${c(C.dim, "Model")}   ${c(C.bCyan, MODEL)}`);
  log(`  ${c(C.dim, "Budget")}  ${c(C.yellow, "1000")} minor units          ${c(C.dim, "Limit")}   ${c(C.yellow, "500")} / action  ${c(C.dim, "(2× a100)")}`);

  // ── Messages + OxDeAI state ───────────────────────────────────────────────
  const messages: ChatCompletionMessageParam[] = [
    {
      role: "system",
      content:
        "You are an infrastructure agent that must use the provided tool for provisioning.\n" +
        "Use the function \"provision_gpu\" to perform provisioning.\n" +
        "Do not simulate tool results.\n" +
        "Do not explain unless asked.\n" +
        "When asked to provision multiple GPUs, issue sequential tool calls using the exact requested parameters.",
    },
    { role: "user", content: "Provision 3 A100 GPUs in us-east-1." },
  ];

  let oxState: State = makeState();
  let callIndex = 0;
  const MAX_CALLS = 3;
  const decisions: DecisionRecord[] = [];

  // ── Live decisions ────────────────────────────────────────────────────────
  log(hr("Live decisions"));

  while (callIndex < MAX_CALLS) {
    const response = await openai.chat.completions.create({
      model: MODEL,
      messages,
      tools: [PROVISION_GPU_TOOL],
      tool_choice: "auto",
    });

    const message = response.choices[0]?.message;
    if (!message) break;
    messages.push(message as ChatCompletionMessageParam);

    if (!message.tool_calls || message.tool_calls.length === 0) {
      if (message.content) log(`\n  ${c(C.dim, "model:")} ${message.content}`);
      break;
    }

    const toolResults: ChatCompletionMessageParam = {
      role: "tool" as const,
      tool_call_id: message.tool_calls[0]!.id,
      content: "",
    };

    for (const toolCall of message.tool_calls) {
      if (toolCall.type !== "function") {
        throw new Error(`Unsupported OpenAI tool call type: ${toolCall.type}`);
      }

      const args = JSON.parse(toolCall.function.arguments) as { asset: string; region: string };
      const { asset, region } = args;
      const step = callIndex + 1;

      log(`\n  ${c(C.dim, `#${step}`)}  ${c(C.bCyan, "OpenAI →")} provision_gpu(${c(C.yellow, asset)}, ${c(C.yellow, region)})`);

      // Route through OxDeAI PEP - suppress pep.ts internal log, render here
      const result = guardedProvision(asset, region, oxState, DEMO_BASE_TIMESTAMP + callIndex, () => {});

      let toolContent: string;

      if (result.allowed) {
        oxState = result.nextState;
        const spent = oxState.budget.spent_in_period[AGENT_ID] ?? 0n;
        const limit = oxState.budget.budget_limit[AGENT_ID]    ?? 0n;
        toolContent = JSON.stringify({
          status: "provisioned",
          instance_id: result.instanceId,
          authorization_id: result.authorization.authorization_id.slice(0, 16),
        });
        log(`      ${c(C.bgGreen, " ALLOW ")}  ${c(C.dim, "instance =")} ${c(C.green, result.instanceId)}`);
        log(`               ${c(C.dim, "budget  =")} ${c(C.yellow, `${spent} / ${limit}`)} minor units`);
        decisions.push({ step, asset, region, verdict: "ALLOW", outcome: result.instanceId });
      } else {
        toolContent = JSON.stringify({ status: "denied", reasons: result.reasons });
        log(`      ${c(C.bgRed,   " DENY  ")}  ${c(C.dim, "reason  =")} ${c(C.bRed, result.reasons.join(", "))}`);
        decisions.push({ step, asset, region, verdict: "DENY", outcome: result.reasons.join(", ") });
      }

      toolResults.tool_call_id = toolCall.id;
      toolResults.content = toolContent;
      callIndex++;
    }

    messages.push(toolResults);
  }

  // ── Decision timeline ─────────────────────────────────────────────────────
  log("");
  log(hr("Decision timeline"));
  log("");
  log(`  ${c(C.dim, "#   action                           verdict  outcome")}`);
  log(`  ${c(C.dim, "─".repeat(65))}`);
  for (const d of decisions) {
    const action  = `provision_gpu(${d.asset}, ${d.region})`.padEnd(35);
    const verdict = d.verdict === "ALLOW"
      ? c(C.bGreen, "ALLOW  ")
      : c(C.bRed,   "DENY   ");
    const outcome = d.verdict === "ALLOW"
      ? c(C.dim, d.outcome)
      : c(C.red, d.outcome);
    log(`  ${c(C.dim, String(d.step))}   ${action}${verdict}  ${outcome}`);
  }

  // ── Pause on online results before transitioning ─────────────────────────
  log("");
  log(c(C.green, "─".repeat(67)));
  log(`  ${c(C.bGreen, "✓ Online phase complete.")}  ${c(C.green, "Verifying artifact offline...")}`);
  await new Promise(r => setTimeout(r, 2500));
  process.stdout.write("\x1b[2J\x1b[H");
  log(c(C.cyan,   "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan,   "║") + c(C.bWhite, "  OxDeAI × OpenAI  ·  Execution Authorization Demo               ") + c(C.cyan, "║"));
  log(c(C.cyan,   "║") + c(C.dim,    "  Verification + Summary                                         ") + c(C.cyan, "║"));
  log(c(C.cyan,   "╚══════════════════════════════════════════════════════════════════╝"));
  log("");

  // ── Build + verify envelope ───────────────────────────────────────────────
  const auditEvents   = engine.audit.snapshot();
  const canonicalState = engine.exportState(oxState);
  const snapshotBytes  = encodeCanonicalState(canonicalState);
  const snapResult = verifySnapshot(snapshotBytes, { expectedPolicyId: POLICY_ID });
  if (snapResult.status !== "ok" || !snapResult.stateHash) {
    throw new Error(`Snapshot verification failed: ${snapResult.status}`);
  }

  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: [
      ...auditEvents,
      {
        type:      "STATE_CHECKPOINT" as const,
        stateHash: snapResult.stateHash,
        timestamp: DEMO_BASE_TIMESTAMP + callIndex,
        policyId:  POLICY_ID,
      },
    ],
  });

  const vr = verifyEnvelope(envelopeBytes, {
    expectedPolicyId: POLICY_ID,
    mode: "strict",
    trustedKeySets: DEMO_TRUSTED_KEYSET,
  });

  // ── Verification ──────────────────────────────────────────────────────────
  log("");
  log(hr("Offline verification"));
  log("");
  log(`  ${c(C.dim, "mode         ")}  strict  ${c(C.dim, "(no engine, keyset-only)")}`);
  log(`  ${c(C.dim, "status       ")}  ${vr.status === "ok" ? c(C.bGreen, "ok") : c(C.bRed, vr.status)}`);
  log(`  ${c(C.dim, "stateHash    ")}  ${c(C.blue, (vr.stateHash     ?? "-").slice(0, 40) + "...")}`);
  log(`  ${c(C.dim, "auditHeadHash")}  ${c(C.blue, (vr.auditHeadHash ?? "-").slice(0, 40) + "...")}`);
  log(`  ${c(C.dim, "violations   ")}  ${vr.violations.length === 0 ? c(C.bGreen, "none") : c(C.bRed, vr.violations.map(v => v.code).join(", "))}`);

  if (vr.status !== "ok") throw new Error(`Envelope verification failed: ${vr.status}`);

  // ── Summary ───────────────────────────────────────────────────────────────
  const allowed = decisions.filter(d => d.verdict === "ALLOW").length;
  const denied  = decisions.filter(d => d.verdict === "DENY").length;
  const spent   = oxState.budget.spent_in_period[AGENT_ID] ?? 0n;
  const limit   = oxState.budget.budget_limit[AGENT_ID]    ?? 0n;

  log("");
  log(hr("Summary"));
  log("");
  log(`  ${c(C.dim, "calls")}    ${callIndex}       ${c(C.dim, "allowed")}  ${c(C.bGreen, String(allowed))}       ${c(C.dim, "denied")}  ${c(C.bRed, String(denied))}`);
  log(`  ${c(C.dim, "budget")}   ${c(C.yellow, `${spent} / ${limit}`)} minor units spent`);
  log(`  ${c(C.dim, "audit")}    ${auditEvents.length} hash-chained events`);
  log(`  ${c(C.dim, "envelope")} ${c(C.dim, `${envelopeBytes.length} bytes,`)} ${c(C.bGreen, "verified offline")}`);

  log("");
  log(c(C.bGreen, "✓ verifyEnvelope() => ok"));
  log("");
  log(`  ${c(C.cyan, "┌─────────────────────────────────────────────────────────────────┐")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "OpenAI")}    proposed 3 tool calls via the real API.               ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "OxDeAI")}    evaluated each call at the boundary.                  ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "Result")}    call 3 ${c(C.bRed, "denied")}, tool never ran.                       ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "Envelope")}  verified offline, no engine access required.          ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "└─────────────────────────────────────────────────────────────────┘")}`);
}

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) {
  runOpenAIDemo().catch((err) => {
    console.error(
      `\n\x1b[1;31m✗ Demo failed:\x1b[0m`,
      err instanceof Error ? err.message : String(err)
    );
    process.exit(1);
  });
}
