import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";

import { PolicyEngine, encodeCanonicalState, encodeEnvelope, verifyAuditEvents, verifyEnvelope, verifySnapshot } from "@oxdeai/core";
import type { ActionType, Intent, State } from "@oxdeai/core";

import { appendAuditEvents, normalizeStateBigInts, readAuditEvents, readStateFile, resetAuditFile, writeStateFile } from "./store.js";

type Flags = {
  json?: boolean;
  state?: string;
  audit?: string;
  file?: string;
  out?: string;
  agent?: string;
  nonce?: string;
  asset?: string;
};

type Io = {
  out: (line: string) => void;
  err: (line: string) => void;
  now: () => number;
};

const DEFAULT_STATE_PATH = ".oxdeai/state.json";
const DEFAULT_AUDIT_PATH = ".oxdeai/audit.ndjson";
const ACTION_TYPES = new Set<ActionType>(["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"]);

function usage(): string {
  return `oxdeai CLI

Usage:
  oxdeai init --file <policy.json> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai launch <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai make-envelope --out <file> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai verify-envelope <file> [--json]
  oxdeai verify-audit [--audit <audit.ndjson>] [--json]
  oxdeai snapshot-hash [--state <state.json>] [--json]
  oxdeai audit [--audit <audit.ndjson>] [--json]
  oxdeai state [--state <state.json>] [--json]`;
}

function parseFlags(argv: string[]): { args: string[]; flags: Flags } {
  const args: string[] = [];
  const flags: Flags = {};

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") continue;
    if (!a.startsWith("--")) {
      args.push(a);
      continue;
    }

    if (a === "--json") {
      flags.json = true;
      continue;
    }

    const next = () => {
      const v = argv[++i];
      if (!v) throw new Error(`Missing value for ${a}`);
      return v;
    };

    if (a === "--state") {
      flags.state = next();
      continue;
    }
    if (a === "--audit") {
      flags.audit = next();
      continue;
    }
    if (a === "--file") {
      flags.file = next();
      continue;
    }
    if (a === "--out") {
      flags.out = next();
      continue;
    }
    if (a === "--agent") {
      flags.agent = next();
      continue;
    }
    if (a === "--nonce") {
      flags.nonce = next();
      continue;
    }
    if (a === "--asset") {
      flags.asset = next();
      continue;
    }

    if (a.startsWith("--state=")) {
      flags.state = a.slice(8);
      continue;
    }
    if (a.startsWith("--audit=")) {
      flags.audit = a.slice(8);
      continue;
    }
    if (a.startsWith("--file=")) {
      flags.file = a.slice(7);
      continue;
    }
    if (a.startsWith("--out=")) {
      flags.out = a.slice(6);
      continue;
    }
    if (a.startsWith("--agent=")) {
      flags.agent = a.slice(8);
      continue;
    }
    if (a.startsWith("--nonce=")) {
      flags.nonce = a.slice(8);
      continue;
    }
    if (a.startsWith("--asset=")) {
      flags.asset = a.slice(8);
      continue;
    }

    throw new Error(`Unknown flag: ${a}`);
  }

  return { args, flags };
}

function toJson(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `${v.toString()}n` : v), 2);
}

function parseBigIntArg(input: string): bigint {
  const s = input.endsWith("n") ? input.slice(0, -1) : input;
  return BigInt(s);
}

function buildValidationIntent(state: State): Intent {
  const agent = Object.keys(state.budget.budget_limit)[0] ?? "agent";
  const action_type = state.allowlists.action_types?.[0] ?? "PAYMENT";
  const target = state.allowlists.targets?.[0] ?? "target:probe";
  return {
    intent_id: "validate-intent",
    type: "EXECUTE",
    agent_id: agent,
    action_type,
    amount: 0n,
    asset: state.allowlists.assets?.[0],
    target,
    timestamp: 0,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 0n,
    signature: "validate-signature"
  };
}

function validateStateStructure(state: State): void {
  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "validate-secret",
    authorization_ttl_seconds: 1
  });
  const probe = buildValidationIntent(state);
  const out = engine.evaluatePure(probe, structuredClone(state), { mode: "fail-fast" });
  if (out.decision === "DENY" && out.reasons.includes("STATE_INVALID")) {
    throw new Error("STATE_INVALID");
  }
}

function buildEngine(state: State): PolicyEngine {
  const secret = process.env["OXDEAI_ENGINE_SECRET"] ?? "dev-secret";
  const ttl = Number(process.env["OXDEAI_AUTH_TTL_SECONDS"] ?? "120");
  return new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: secret,
    authorization_ttl_seconds: Number.isFinite(ttl) ? ttl : 120
  });
}

export async function runCli(argv: string[], io?: Partial<Io>): Promise<number> {
  const out = io?.out ?? ((line: string) => console.log(line));
  const err = io?.err ?? ((line: string) => console.error(line));
  const now = io?.now ?? (() => Math.floor(Date.now() / 1000));

  let parsed: { args: string[]; flags: Flags };
  try {
    parsed = parseFlags(argv);
  } catch (e) {
    err((e as Error).message);
    err(usage());
    return 2;
  }

  const { args, flags } = parsed;
  const cmd = args[0];
  if (!cmd) {
    err(usage());
    return 2;
  }

  const statePath = flags.state ?? DEFAULT_STATE_PATH;
  const auditPath = flags.audit ?? DEFAULT_AUDIT_PATH;

  try {
    if (cmd === "init") {
      if (!flags.file) throw new Error("Missing --file <policy.json>");
      const text = await readFile(flags.file, "utf8");
      const state = normalizeStateBigInts(JSON.parse(text));
      validateStateStructure(state);
      await writeStateFile(statePath, state);
      await resetAuditFile(auditPath);
      out(flags.json ? toJson({ ok: true }) : "OK");
      return 0;
    }

    if (cmd === "state") {
      const state = await readStateFile(statePath);
      out(flags.json ? toJson(state) : toJson(state));
      return 0;
    }

    if (cmd === "audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "best-effort" });
      const payload = {
        headHash: verified.auditHeadHash && verified.auditHeadHash.length > 0 ? verified.auditHeadHash : "GENESIS",
        verify: verified.ok,
        events
      };
      out(flags.json ? toJson(payload) : toJson(payload));
      return 0;
    }

    if (cmd === "verify-audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "strict" });
      out(flags.json ? toJson(verified) : toJson(verified));
      return 0;
    }

    if (cmd === "verify-envelope") {
      const file = args[1] ?? flags.file;
      if (!file) throw new Error("Usage: verify-envelope <file>");
      const bytes = Uint8Array.from(await readFile(file));
      const verified = verifyEnvelope(bytes, { mode: "strict" });
      out(flags.json ? toJson(verified) : toJson(verified));
      return 0;
    }

    if (cmd === "make-envelope") {
      if (!flags.out) throw new Error("Usage: make-envelope --out <file>");
      const state = await readStateFile(statePath);
      const events = await readAuditEvents(auditPath);
      const engine = buildEngine(state);
      const snapshotBytes = encodeCanonicalState(engine.exportState(state));
      const envelope = encodeEnvelope({
        formatVersion: 1,
        snapshot: snapshotBytes,
        events: events as Parameters<typeof encodeEnvelope>[0]["events"]
      });

      await mkdir(dirname(flags.out), { recursive: true });
      await writeFile(flags.out, Buffer.from(envelope));
      const payload = { ok: true, file: flags.out };
      out(flags.json ? toJson(payload) : `OK: ${flags.out}`);
      return 0;
    }

    if (cmd === "snapshot-hash") {
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const snapshot = engine.exportState(state);
      const bytes = encodeCanonicalState(snapshot);
      const verified = verifySnapshot(bytes);
      const payload = {
        policyId: snapshot.policyId,
        stateHash: verified.stateHash,
        status: verified.status,
        violations: verified.violations
      };
      out(flags.json ? toJson(payload) : toJson(payload));
      return 0;
    }

    if (cmd === "launch") {
      const action = args[1] as ActionType | undefined;
      const amountRaw = args[2];
      const target = args[3];
      if (!action || !amountRaw || !target) throw new Error("Usage: launch <actionType> <amount> <target> --agent <id> --nonce <n>");
      if (!ACTION_TYPES.has(action)) throw new Error(`Invalid actionType: ${action}`);
      if (!flags.agent) throw new Error("Missing --agent <id>");
      if (!flags.nonce) throw new Error("Missing --nonce <n>");

      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const ts = now();

      const intent: Intent = {
        intent_id: `intent:${flags.agent}:${flags.nonce}`,
        type: "EXECUTE",
        agent_id: flags.agent,
        action_type: action,
        amount: parseBigIntArg(amountRaw),
        asset: flags.asset,
        target,
        timestamp: ts,
        metadata_hash: "0x" + "0".repeat(64),
        nonce: parseBigIntArg(flags.nonce),
        signature: "cli-signature-placeholder"
      };

      const outEval = engine.evaluatePure(intent, state, { mode: "fail-fast" });
      const emitted = engine.audit.snapshot();
      await appendAuditEvents(auditPath, emitted);

      if (outEval.decision === "ALLOW") {
        await writeStateFile(statePath, outEval.nextState);
        const payload = { decision: "ALLOW" as const, authorization_id: outEval.authorization.authorization_id, reasons: [] as string[] };
        out(flags.json ? toJson(payload) : `ALLOW: ${payload.authorization_id}`);
        return 0;
      }

      const payload = { decision: "DENY" as const, reasons: outEval.reasons };
      out(flags.json ? toJson(payload) : `DENY: ${toJson(payload.reasons)}`);
      return 0;
    }

    err(usage());
    return 2;
  } catch (e) {
    err((e as Error).message);
    return 1;
  }
}

async function main(): Promise<void> {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main();
}
