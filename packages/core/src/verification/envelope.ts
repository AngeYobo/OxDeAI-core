import { canonicalJson } from "../crypto/hashes.js";
import type { AuditEntry } from "../audit/AuditLog.js";

/** @public */
export type VerificationEnvelopeV1 = {
  formatVersion: 1;
  snapshot: Uint8Array;
  events: AuditEntry[];
};

type EnvelopeWire = {
  formatVersion: 1;
  snapshot: string;
  events: AuditEntry[];
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function assertEnvelope(value: unknown): EnvelopeWire {
  if (!isObject(value) || Array.isArray(value)) {
    throw new Error("invalid verification envelope");
  }

  if (!("formatVersion" in value) || value.formatVersion !== 1) {
    throw new Error("invalid verification envelope: unsupported formatVersion");
  }

  if (typeof value.snapshot !== "string") {
    throw new Error("invalid verification envelope: snapshot");
  }

  if (!Array.isArray(value.events)) {
    throw new Error("invalid verification envelope: events");
  }

  for (let i = 0; i < value.events.length; i++) {
    const e = value.events[i];
    if (!isObject(e) || Array.isArray(e)) {
      throw new Error(`invalid verification envelope: events[${i}]`);
    }
  }

  return {
    formatVersion: 1,
    snapshot: value.snapshot,
    events: value.events as AuditEntry[]
  };
}

/** @public */
export function encodeEnvelope(envelope: VerificationEnvelopeV1): Uint8Array {
  if (envelope.formatVersion !== 1) {
    throw new Error("invalid verification envelope: unsupported formatVersion");
  }
  if (!(envelope.snapshot instanceof Uint8Array)) {
    throw new Error("invalid verification envelope: snapshot");
  }
  if (!Array.isArray(envelope.events)) {
    throw new Error("invalid verification envelope: events");
  }

  const wire: EnvelopeWire = {
    formatVersion: 1,
    snapshot: Buffer.from(envelope.snapshot).toString("base64"),
    events: envelope.events.map((e) => structuredClone(e))
  };

  return new TextEncoder().encode(canonicalJson(wire));
}

/** @public */
export function decodeEnvelope(bytes: Uint8Array): VerificationEnvelopeV1 {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  const wire = assertEnvelope(parsed);

  return {
    formatVersion: 1,
    snapshot: Uint8Array.from(Buffer.from(wire.snapshot, "base64")),
    events: wire.events.map((e) => structuredClone(e))
  };
}
