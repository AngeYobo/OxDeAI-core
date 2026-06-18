// SPDX-License-Identifier: Apache-2.0
/**
 * Boundary test matrix — 11 adversarial scenarios.
 *
 * Invariant under test: No valid AuthorizationV1 → no execution.
 *
 * Every DENY scenario asserts:
 *   - HTTP 403 from the enforcement boundary
 *   - Frappe adapter never called
 *
 * Test matrix:
 *   1.  ALLOW (enforce, Low)       — happy path, Frappe called
 *   2.  ALLOW (enforce, Medium)    — second allowed priority, Frappe called
 *   3.  ALLOW (observe)            — would-ALLOW, Frappe NOT called
 *   4.  DENY (policy, Urgent)      — policy-denied priority
 *   5.  DENY (missing auth)        — no authorization on /execute
 *   6.  DENY (invalid signature)   — tampered signature
 *   7.  DENY (expired)             — expired authorization
 *   8.  DENY (replay)              — auth_id reused
 *   9.  DENY (wrong audience)      — audience mismatch
 *   10. DENY (modified payload)    — intent hash mismatch
 *   11. DENY (unsupported action)  — wrong tool name
 */

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import { createInMemoryReplayStore } from "@oxdeai/guard";
import type { PepConfig } from "../src/config.js";
import type { FrappeAdapter, FrappeCreateTicketParams, ActionEnvelope } from "../src/types.js";
import { createPepServer } from "../src/server.js";
import { POLICY_ID } from "../src/policy.js";

// ─── Test infrastructure ────────────────────────────────────────────────────

type TestHarness = {
  baseUrl: string;
  config: PepConfig;
  frappeCallCount: () => number;
  frappeLastCall: () => FrappeCreateTicketParams | null;
  resetFrappe: () => void;
  privateKeyPem: string;
  close: () => Promise<void>;
};

function makeEnvelope(overrides?: {
  tool?: string;
  priority?: string;
  subject?: string;
}): ActionEnvelope {
  return {
    source_bench: "openwebui-dev",
    target_bench: "frappe",
    agent_or_tool_context: "erp-assistant",
    user_identity: "user@example.com",
    session_id: "test-session",
    action: {
      type: "EXECUTE",
      tool: overrides?.tool ?? "frappe.helpdesk.create_ticket",
      params: {
        subject: overrides?.subject ?? "Test ticket",
        description: "Created by boundary test",
        priority: overrides?.priority ?? "Low",
      },
    },
  };
}

async function startHarness(modeOverride?: "enforce" | "observe"): Promise<TestHarness> {
  const keyPair = generateKeyPairSync("ed25519");
  const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }) as string;

  let callCount = 0;
  let lastCall: FrappeCreateTicketParams | null = null;

  const mockFrappe: FrappeAdapter = {
    async createTicket(params) {
      callCount++;
      lastCall = params;
      return { ticket_id: `HD-TICKET-${callCount}`, name: `HD-TICKET-${callCount}` };
    },
  };

  const config: PepConfig = {
    mode: modeOverride ?? "enforce",
    expectedAudience: "PEP-frappe.lgf.oxdeai.dev",
    frappeBaseUrl: "https://frappe.lgf.oxdeai.dev",
    frappeApiKey: "test-key",
    frappeApiSecret: "test-secret",
    replayStore: "memory",
    port: 0,
    signingPrivateKey: keyPair.privateKey,
    signingPublicKeyPem: publicKeyPem,
    signingKid: "test-key-1",
    issuer: "oxdeai.lgf-frappe-pep",
    authorizationTtlSeconds: 60,
  };

  const server = createPepServer({
    config,
    replayStore: createInMemoryReplayStore(),
    frappeAdapter: mockFrappe,
  });

  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("Unexpected server address");

  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    config,
    frappeCallCount: () => callCount,
    frappeLastCall: () => lastCall,
    resetFrappe: () => { callCount = 0; lastCall = null; },
    privateKeyPem,
    close: () => {
      server.closeAllConnections();
      return new Promise((res, rej) => server.close((e) => (e ? rej(e) : res())));
    },
  };
}

async function postJson(url: string, body: unknown): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

function issueAuthorization(
  envelope: ActionEnvelope,
  privateKeyPem: string,
  overrides?: Partial<{
    audience: string;
    expiry: number;
    issued_at: number;
    intent_hash: string;
    kid: string;
    issuer: string;
  }>,
): AuthorizationV1 {
  const now = Math.floor(Date.now() / 1000);
  const intentHash = overrides?.intent_hash ?? sha256HexFromJson(envelope.action);
  const stateHash = sha256HexFromJson({});

  return signAuthorizationEd25519(
    {
      auth_id: randomUUID(),
      issuer: overrides?.issuer ?? "oxdeai.lgf-frappe-pep",
      audience: overrides?.audience ?? "PEP-frappe.lgf.oxdeai.dev",
      intent_hash: intentHash,
      state_hash: stateHash,
      policy_id: POLICY_ID,
      decision: "ALLOW",
      issued_at: overrides?.issued_at ?? now,
      expiry: overrides?.expiry ?? now + 60,
      kid: overrides?.kid ?? "test-key-1",
      nonce: randomUUID(),
    },
    privateKeyPem,
  );
}

// ─── Test suite ──────────────────────────────────────────────────────────────

describe("LGF Frappe PEP boundary", () => {
  let h: TestHarness;

  before(async () => {
    h = await startHarness("enforce");
  });

  after(async () => {
    await h.close();
  });

  // ── 1. ALLOW (enforce, Low) ────────────────────────────────────────────────

  test("ALLOW: valid authorization in enforce mode creates ticket (priority=Low)", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Low" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 200, `Expected 200, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["decision"], "ALLOW");
    assert.equal(body["mode"], "enforce");
    assert.equal(typeof body["frappe_ticket_id"], "string");
    assert.equal(h.frappeCallCount(), 1, "Frappe adapter must be called exactly once");
  });

  // ── 2. ALLOW (enforce, Medium) ─────────────────────────────────────────────

  test("ALLOW: valid authorization in enforce mode creates ticket (priority=Medium)", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Medium" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 200, `Expected 200, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["decision"], "ALLOW");
    assert.equal(h.frappeCallCount(), 1, "Frappe adapter must be called exactly once");
  });

  // ── 3. DENY: policy-denied priority ────────────────────────────────────────

  test("DENY: policy-denied priority (Urgent) returns no AuthorizationV1", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Urgent" });

    const result = await postJson(`${h.baseUrl}/authorize`, envelope);
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["reason"], "POLICY_DENIED_PRIORITY");
    assert.equal(body["authorization"], undefined, "No authorization artifact on DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called on policy DENY");
  });

  // ── 4. DENY: missing authorization ─────────────────────────────────────────

  test("DENY: missing authorization on /execute", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope();

    const result = await postJson(`${h.baseUrl}/execute`, { envelope });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called without authorization");
  });

  // ── 5. DENY: invalid signature ─────────────────────────────────────────────

  test("DENY: tampered signature is rejected", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope();
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const tampered: AuthorizationV1 = {
      ...authorization,
      signature: "AAAA" + (typeof authorization.signature === "string"
        ? authorization.signature.slice(4)
        : "invalid"),
    };

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization: tampered });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called with invalid signature");
  });

  // ── 6. DENY: expired authorization ─────────────────────────────────────────

  test("DENY: expired authorization is rejected", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope();
    const pastNow = Math.floor(Date.now() / 1000) - 120;
    const authorization = issueAuthorization(envelope, h.privateKeyPem, {
      issued_at: pastNow,
      expiry: pastNow + 30,
    });

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called with expired authorization");
  });

  // ── 7. DENY: replayed authorization ────────────────────────────────────────

  test("DENY: replayed authorization is rejected on second use", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ subject: "replay-test" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const first = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(first.status, 200, `First use must succeed — got ${first.status}`);
    assert.equal(h.frappeCallCount(), 1, "First use must call Frappe");

    h.resetFrappe();
    const second = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(second.status, 403, `Replay must return 403 — got ${second.status}`);

    const body = second.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.match(body["reason"] as string, /REPLAY/);
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called on replay");
  });

  // ── 8. DENY: wrong audience ────────────────────────────────────────────────

  test("DENY: wrong audience is rejected", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope();
    const authorization = issueAuthorization(envelope, h.privateKeyPem, {
      audience: "PEP-wrong-audience",
    });

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called with wrong audience");
  });

  // ── 9. DENY: modified payload (intent hash mismatch) ──────────────────────

  test("DENY: modified payload after authorization is rejected", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Low" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const tampered = makeEnvelope({ priority: "Low", subject: "Tampered subject" });

    const result = await postJson(`${h.baseUrl}/execute`, {
      envelope: tampered,
      authorization,
    });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called with tampered payload");
  });

  // ── 10. DENY: unsupported protected action ─────────────────────────────────

  test("DENY: unsupported action name is rejected", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ tool: "frappe.helpdesk.delete_ticket" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["reason"], "UNSUPPORTED_ACTION");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called for unsupported action");
  });

  // ── 11. /authorize emits AuthorizationV1 for allowed action ────────────────

  test("ALLOW: /authorize emits AuthorizationV1 for allowed action (Low)", async () => {
    const envelope = makeEnvelope({ priority: "Low" });
    const result = await postJson(`${h.baseUrl}/authorize`, envelope);
    assert.equal(result.status, 200, `Expected 200, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["decision"], "ALLOW");
    assert.notEqual(body["authorization"], undefined, "Must include authorization artifact");

    const auth = body["authorization"] as AuthorizationV1;
    assert.equal(auth.decision, "ALLOW");
    assert.equal(auth.audience, "PEP-frappe.lgf.oxdeai.dev");
    assert.equal(auth.alg, "Ed25519");
    assert.equal(typeof auth.signature, "string");
    assert.equal(typeof auth.intent_hash, "string");
  });

  // ── 12. /healthz returns healthy ───────────────────────────────────────────

  test("healthz returns healthy status", async () => {
    const res = await fetch(`${h.baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["status"], "healthy");
    assert.equal(body["mode"], "enforce");
  });

  // ── 13. DENY: oversized request body ──────────────────────────────────────

  test("DENY: oversized request body is rejected", async () => {
    h.resetFrappe();
    const oversized = JSON.stringify({ junk: "x".repeat(2 * 1024 * 1024) });
    const res = await fetch(`${h.baseUrl}/execute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversized,
    });
    assert.equal(res.status, 413, `Expected 413, got ${res.status}`);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["reason"], "BODY_TOO_LARGE");
    assert.equal(h.frappeCallCount(), 0, "Frappe must not be called on oversized body");
  });
});

// ─── Observe mode suite ──────────────────────────────────────────────────────

describe("LGF Frappe PEP observe mode", () => {
  let h: TestHarness;

  before(async () => {
    h = await startHarness("observe");
  });

  after(async () => {
    await h.close();
  });

  test("OBSERVE: valid authorization returns would-ALLOW without calling Frappe", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Low" });
    const authorization = issueAuthorization(envelope, h.privateKeyPem);

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 200, `Expected 200, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["decision"], "ALLOW");
    assert.equal(body["mode"], "observe");
    assert.equal(body["frappe_ticket_id"], undefined, "Observe mode must not produce ticket");
    assert.equal(h.frappeCallCount(), 0, "Frappe must NOT be called in observe mode");
  });

  test("OBSERVE: /authorize returns would-ALLOW with authorization artifact", async () => {
    const envelope = makeEnvelope({ priority: "Medium" });
    const result = await postJson(`${h.baseUrl}/authorize`, envelope);
    assert.equal(result.status, 200);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], true);
    assert.equal(body["decision"], "ALLOW");
    assert.equal(body["mode"], "observe");
    assert.notEqual(body["authorization"], undefined);
  });

  test("OBSERVE: /authorize returns would-DENY for Urgent priority", async () => {
    const envelope = makeEnvelope({ priority: "Urgent" });
    const result = await postJson(`${h.baseUrl}/authorize`, envelope);
    assert.equal(result.status, 403);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["mode"], "observe");
  });

  test("OBSERVE: expired authorization on /execute returns DENY without calling Frappe", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope({ priority: "Low" });
    const pastNow = Math.floor(Date.now() / 1000) - 120;
    const authorization = issueAuthorization(envelope, h.privateKeyPem, {
      issued_at: pastNow,
      expiry: pastNow + 30,
    });

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["mode"], "observe");
    assert.equal(h.frappeCallCount(), 0, "Frappe must NOT be called on observe-mode DENY");
  });

  test("OBSERVE: wrong audience on /execute returns DENY without calling Frappe", async () => {
    h.resetFrappe();
    const envelope = makeEnvelope();
    const authorization = issueAuthorization(envelope, h.privateKeyPem, {
      audience: "PEP-wrong-audience",
    });

    const result = await postJson(`${h.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 403, `Expected 403, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["mode"], "observe");
    assert.equal(h.frappeCallCount(), 0, "Frappe must NOT be called on observe-mode audience mismatch");
  });

  test("OBSERVE: healthz shows observe mode", async () => {
    const res = await fetch(`${h.baseUrl}/healthz`);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body["mode"], "observe");
  });
});

// ─── Frappe upstream error diagnostic suite ──────────────────────────────────

describe("LGF Frappe PEP upstream error handling", () => {
  let baseUrl: string;
  let privateKeyPem: string;
  let close: () => Promise<void>;

  before(async () => {
    const keyPair = generateKeyPairSync("ed25519");
    privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }) as string;

    const failingFrappe: FrappeAdapter = {
      async createTicket() {
        throw new Error("Frappe API returned non-JSON content-type=text/html status=200");
      },
    };

    const config: PepConfig = {
      mode: "enforce",
      expectedAudience: "PEP-frappe.lgf.oxdeai.dev",
      frappeBaseUrl: "https://frappe.lgf.oxdeai.dev",
      frappeApiKey: "test-key",
      frappeApiSecret: "test-secret",
      replayStore: "memory",
      port: 0,
      signingPrivateKey: keyPair.privateKey,
      signingPublicKeyPem: publicKeyPem,
      signingKid: "test-key-1",
      issuer: "oxdeai.lgf-frappe-pep",
      authorizationTtlSeconds: 60,
    };

    const server = createPepServer({
      config,
      replayStore: createInMemoryReplayStore(),
      frappeAdapter: failingFrappe,
    });

    await new Promise<void>((resolve, reject) => {
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });

    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("Unexpected address");

    baseUrl = `http://127.0.0.1:${(addr as { port: number }).port}`;
    close = () => {
      server.closeAllConnections();
      return new Promise((res, rej) => server.close((e) => (e ? rej(e) : res())));
    };
  });

  after(async () => {
    await close();
  });

  test("upstream error returns 502 DENY with FRAPPE_UPSTREAM_ERROR and does not leak error detail to caller", async () => {
    const envelope = makeEnvelope({ priority: "Low" });
    const authorization = issueAuthorization(envelope, privateKeyPem);

    const result = await postJson(`${baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 502, `Expected 502, got ${result.status}`);

    const body = result.body as Record<string, unknown>;
    assert.equal(body["ok"], false);
    assert.equal(body["decision"], "DENY");
    assert.equal(body["reason"], "FRAPPE_UPSTREAM_ERROR");
    // The HTTP response must NOT contain the internal error detail
    assert.equal(
      (body["reason"] as string).includes("content-type"),
      false,
      "Internal error detail must not leak to caller",
    );
  });
});
