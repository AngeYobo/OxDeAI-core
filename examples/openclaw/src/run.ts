// SPDX-License-Identifier: Apache-2.0
/**
 * run.ts — Demo entry point
 *
 * Simulates an agent proposing GPU provisioning calls.
 * OxDeAI enforces the economic boundary before each execution.
 *
 * Scenario (deterministic):
 *   Call 1: a100 / us-east-1 → ALLOW  (500 spent,  500 remaining)
 *   Call 2: a100 / us-east-1 → ALLOW  (1000 spent,   0 remaining)
 *   Call 3: a100 / us-east-1 → DENY   (BUDGET_EXCEEDED)
 *
 * Usage:
 *   node dist/run.js
 */

import { pathToFileURL } from "node:url";
import {
  encodeCanonicalState,
  encodeEnvelope,
  verifySnapshot,
  verifyEnvelope,
} from "@oxdeai/core";
import type { State } from "@oxdeai/core";
import { engine, POLICY_ID, AGENT_ID, makeState } from "./policy.js";
import { guardedProvision } from "./pep.js";
import { DEMO_KEYSET } from "./crypto.js";

// ── ANSI color helpers ────────────────────────────────────────────────────────
const C = {
  reset:      "\x1b[0m",
  bold:       "\x1b[1m",
  dim:        "\x1b[2m",
  // foreground
  cyan:       "\x1b[36m",
  green:      "\x1b[32m",
  red:        "\x1b[31m",
  yellow:     "\x1b[33m",
  blue:       "\x1b[34m",
  magenta:    "\x1b[35m",
  white:      "\x1b[97m",
  // bold shortcuts
  bCyan:      "\x1b[1;36m",
  bGreen:     "\x1b[1;32m",
  bRed:       "\x1b[1;31m",
  bYellow:    "\x1b[1;33m",
  bWhite:     "\x1b[1;97m",
  bMagenta:   "\x1b[1;35m",
};

const c = (color: string, text: string) => `${color}${text}${C.reset}`;

// ── Planned calls (simulates OpenAI tool-call proposals) ──────────────────────

const PLANNED_CALLS = [
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" }, // will be DENIED — budget exhausted
];

// ── Main ──────────────────────────────────────────────────────────────────────

export async function runDemo(log: (msg: string) => void = (msg) => console.log(msg)): Promise<void> {
  const decisions: string[] = [];

  // Header box — cyan border, white title
  log(c(C.cyan, "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan, "║") + c(C.bWhite, "  OxDeAI — Pre-Execution Economic Boundary Demo                  ") + c(C.cyan, "║"));
  log(c(C.cyan, "║") + c(C.dim,    "  Scenario: GPU provisioning — budget for exactly 2 calls        ") + c(C.cyan, "║"));
  log(c(C.cyan, "╚══════════════════════════════════════════════════════════════════╝"));

  log(`\n${c(C.dim, "Agent:")}   ${c(C.bCyan, AGENT_ID)}`);
  log(`${c(C.dim, "Policy:")}  budget=${c(C.yellow, "1000")} minor units  max_per_action=${c(C.yellow, "500")}  (2× a100 allowed)`);

  // ── State setup ──────────────────────────────────────────────────────────
  const baseTimestamp = Math.floor(Date.now() / 1000);
  let state: State = makeState();
  let callIndex = 0;

  let allowedCount = 0;
  let deniedCount  = 0;

  // ── Agent loop ───────────────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Agent proposals ─────────────────────────────────────────────────")}`);

  for (const call of PLANNED_CALLS) {
    // Keep the intent clock stable across this synchronous demo run. Authorization
    // issuance is stamped from the engine's evaluation clock, not this client time.
    const timestamp = baseTimestamp;

    const result = await guardedProvision(
      call.asset,
      call.region,
      state,
      timestamp,
      log
    );

    if (result.allowed) {
      decisions.push("ALLOW");
      allowedCount++;
      state = result.nextState;

      const spent = state.budget.spent_in_period[AGENT_ID] ?? 0n;
      const limit = state.budget.budget_limit[AGENT_ID]    ?? 0n;
      log(`   ${c(C.dim, "budget after:")} ${c(C.yellow, `${spent}/${limit}`)} minor units spent`);
    } else {
      decisions.push("DENY");
      deniedCount++;
    }

    callIndex++;
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Summary ──────────────────────────────────────────────────────────")}`);
  log(`   Allowed: ${c(C.bGreen, String(allowedCount))}   Denied: ${c(C.bRed, String(deniedCount))}`);

  // ── Audit events ─────────────────────────────────────────────────────────
  const auditEvents = engine.audit.snapshot();
  log(`\n${c(C.dim, `── Audit events (${auditEvents.length}) ──────────────────────────────────────────`)}`);
  for (const event of auditEvents) {
    const e      = event as Record<string, unknown>;
    const type   = String(e["type"]      ?? "UNKNOWN");
    const ts     = String(e["timestamp"] ?? "?");
    const ih     = e["intent_hash"] as string | undefined;
    const dec    = e["decision"]    as string | undefined;
    const detail = ih  ? `  intent=${c(C.dim, ih.slice(0, 16) + "...")}` : "";

    let decStr = "";
    if (dec === "ALLOW") decStr = `  decision=${c(C.bGreen, "ALLOW")}`;
    if (dec === "DENY")  decStr = `  decision=${c(C.bRed,   "DENY")}`;

    let typeColored = type;
    if (type === "INTENT_RECEIVED") typeColored = c(C.cyan,    type);
    if (type === "DECISION")        typeColored = c(C.white,   type);
    if (type === "AUTH_EMITTED")    typeColored = c(C.green,   type);

    log(`   ${c(C.dim, `[${ts}]`)} ${typeColored}${detail}${decStr}`);
  }

  // ── Snapshot ──────────────────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Snapshot ─────────────────────────────────────────────────────────")}`);
  const canonicalState = engine.exportState(state);
  const snapshotBytes  = encodeCanonicalState(canonicalState);

  const snapResult = verifySnapshot(snapshotBytes, { expectedPolicyId: POLICY_ID });
  if (snapResult.status !== "ok" || !snapResult.stateHash) {
    throw new Error(`Snapshot verification failed: ${snapResult.status}`);
  }
  log(`   ${c(C.dim, "stateHash:")} ${c(C.blue, snapResult.stateHash.slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "size:")}      ${snapshotBytes.length} bytes`);

  // ── Verification envelope ─────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Verification envelope ────────────────────────────────────────────")}`);

  const eventsWithCheckpoint = [
    ...auditEvents,
    {
      type:      "STATE_CHECKPOINT" as const,
      stateHash: snapResult.stateHash,
      timestamp: baseTimestamp + callIndex,
      policyId:  POLICY_ID,
    },
  ];

  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events:   eventsWithCheckpoint,
  });
  log(`   ${c(C.dim, "Envelope size:")} ${envelopeBytes.length} bytes`);

  // ── Offline verification ──────────────────────────────────────────────────
  log(`\n${c(C.dim, "── verifyEnvelope (strict mode) ─────────────────────────────────────")}`);

  const vr = verifyEnvelope(envelopeBytes, {
    expectedPolicyId: POLICY_ID,
    mode: "strict",
    trustedKeySets: DEMO_KEYSET,
  });

  const statusColor = vr.status === "ok" ? c(C.bGreen, vr.status) : c(C.bRed, vr.status);
  log(`   ${c(C.dim, "status:")}        ${statusColor}`);
  log(`   ${c(C.dim, "policyId:")}      ${c(C.blue, (vr.policyId      ?? "—").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "stateHash:")}     ${c(C.blue, (vr.stateHash     ?? "—").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "auditHeadHash:")} ${c(C.blue, (vr.auditHeadHash ?? "—").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "violations:")}    ${vr.violations.length === 0 ? c(C.bGreen, "none") : c(C.bRed, vr.violations.map((v) => v.code).join(", "))}`);

  if (vr.status !== "ok") {
    throw new Error(`Envelope verification failed: ${vr.status}`);
  }

  // ── Cross-adapter summary ─────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Cross-adapter demo scenario ──────────────────────────────────────")}`);
  decisions.forEach((decision, index) => {
    const col = decision === "ALLOW" ? c(C.bGreen, decision) : c(C.bRed, decision);
    log(`   decision ${index + 1}: ${col}`);
  });
  log(`   verifyEnvelope() => ${c(C.bGreen, vr.status)}`);

  // ── Final "What just happened" box ────────────────────────────────────────
  log(`\n${c(C.bGreen, "✓ Verification passed.")}`);
  log("");
  log(`  ${c(C.bWhite, "What just happened:")}`);
  log(`  ${c(C.cyan, "┌─────────────────────────────────────────────────────────────────┐")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PDP")}  OxDeAI evaluated each intent before any tool ran.          ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}      Call 3 was ${c(C.bRed, "denied")} at the boundary — tool never touched.    ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PEP")}  Tool only executed after Authorization was confirmed.      ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}      No Authorization = no execution, even on ${c(C.bGreen, "ALLOW")}.            ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "AUDIT")}  ${auditEvents.length} hash-chained events record the full execution history. ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "ENVELOPE")}  Independently verifiable without re-running the engine. ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "└─────────────────────────────────────────────────────────────────┘")}`);
}

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) {
  runDemo().catch((err) => {
    console.error(`\n${"\x1b[1;31m"}✗ Demo failed:${"\x1b[0m"}`, err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
