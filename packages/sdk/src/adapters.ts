import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

import type { State } from "@oxdeai/core";

import type { AuditAdapter, StateAdapter } from "./types.js";

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (typeof value === "bigint") return `${value.toString()}n`;
  if (Array.isArray(value)) return value.map((v) => canonicalize(v));
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) out[key] = canonicalize(obj[key]);
    return out;
  }
  return String(value);
}

function stringifyCanonical(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function parseBigIntLike(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") {
    const s = value.endsWith("n") ? value.slice(0, -1) : value;
    return BigInt(s);
  }
  throw new Error("invalid bigint-like value");
}

function mapRecordBigInt(input: unknown): Record<string, bigint> {
  const rec = (input ?? {}) as Record<string, unknown>;
  const out: Record<string, bigint> = {};
  for (const key of Object.keys(rec)) out[key] = parseBigIntLike(rec[key]);
  return out;
}

function normalizeStateBigInts(raw: unknown): State {
  const s = raw as State;
  return {
    ...s,
    budget: {
      ...s.budget,
      budget_limit: mapRecordBigInt((s as any).budget?.budget_limit),
      spent_in_period: mapRecordBigInt((s as any).budget?.spent_in_period)
    },
    max_amount_per_action: mapRecordBigInt((s as any).max_amount_per_action)
  };
}

export class InMemoryStateAdapter implements StateAdapter {
  private state: State;

  constructor(initial: State) {
    this.state = structuredClone(initial);
  }

  load(): State {
    return structuredClone(this.state);
  }

  save(state: State): void {
    this.state = structuredClone(state);
  }
}

export class InMemoryAuditAdapter implements AuditAdapter {
  private readonly events: unknown[] = [];

  append(events: readonly unknown[]): void {
    for (const event of events) this.events.push(structuredClone(event));
  }

  snapshot(): unknown[] {
    return structuredClone(this.events);
  }
}

export class JsonFileStateAdapter implements StateAdapter {
  constructor(private readonly path: string) {}

  async load(): Promise<State> {
    const txt = await readFile(this.path, "utf8");
    return normalizeStateBigInts(JSON.parse(txt));
  }

  async save(state: State): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp-${randomUUID()}`;
    await writeFile(tmp, `${stringifyCanonical(state)}\n`, "utf8");
    await rename(tmp, this.path);
  }
}

export class NdjsonFileAuditAdapter implements AuditAdapter {
  constructor(private readonly path: string) {}

  async append(events: readonly unknown[]): Promise<void> {
    if (events.length === 0) return;
    await mkdir(dirname(this.path), { recursive: true });
    const body = events.map((e) => stringifyCanonical(e)).join("\n") + "\n";
    await appendFile(this.path, body, "utf8");
  }
}
