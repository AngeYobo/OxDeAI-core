import { mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { State } from "@oxdeai/core";

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

function canonicalize(value: unknown): JsonValue {
  if (value === null) return null;
  if (typeof value === "bigint") return `${value.toString()}n`;
  if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((v) => canonicalize(v));
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: { [k: string]: JsonValue } = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = canonicalize(obj[key]);
    }
    return out;
  }
  return String(value);
}

export function canonicalStringify(value: unknown): string {
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

export function normalizeStateBigInts(raw: unknown): State {
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

export async function readStateFile(path: string): Promise<State> {
  const txt = await readFile(path, "utf8");
  return normalizeStateBigInts(JSON.parse(txt));
}

export async function writeStateFile(path: string, state: State): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${canonicalStringify(state)}\n`, "utf8");
}

export async function resetAuditFile(path: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, "", "utf8");
}

export async function appendAuditEvents(path: string, events: readonly unknown[]): Promise<void> {
  if (events.length === 0) return;
  await mkdir(dirname(path), { recursive: true });
  const body = events.map((e) => canonicalStringify(e)).join("\n") + "\n";
  await appendFile(path, body, "utf8");
}

export async function readAuditEvents(path: string): Promise<unknown[]> {
  try {
    const txt = await readFile(path, "utf8");
    const lines = txt.split("\n").map((l) => l.trim()).filter(Boolean);
    return lines.map((line) => JSON.parse(line));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}
