// SPDX-License-Identifier: Apache-2.0
/**
 * KRL integrity mode tests for SiftHttpKeyStore.
 *
 * Tests the three KRL modes (signed_required, signed_preferred, unsigned_legacy)
 * and their interaction with the verifyKrl callback, now injection, version
 * watermark tracking, and the getKrlStatus() surface.
 *
 * All tests use mock fetch and mock verifyKrl callbacks.  No real cryptographic
 * signing is needed here — the verifyKrl mock simulates the responses that
 * verifySignedKrl from @oxdeai/core would produce, and the routing logic of
 * SiftHttpKeyStore is what is under test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SiftHttpKeyStore,
  KeyStoreError,
  type KrlVerifyFn,
} from "../src/siftKeyStore.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const JWKS_URL = "https://sift-test.example/sift-jwks.json";
const KRL_URL  = "https://sift-test.example/sift-krl.json";

// RFC 8037 Appendix A test vector (32-byte Ed25519 public key)
const RFC8037_X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "key-rfc8037";

const VALID_JWKS = {
  keys: [{ kty: "OKP", crv: "Ed25519", kid: RFC8037_KID, x: RFC8037_X }],
};

// Fixed clock — 2026-04-14T12:00:00Z in unix seconds.
const TEST_NOW = 1744632000;

// ─── KRL body fixtures ────────────────────────────────────────────────────────

// Unsigned KRL — no "signature" key.  Used for unsigned_legacy and
// signed_preferred unsigned-fallback paths.
const UNSIGNED_KRL_EMPTY = {
  version: 1,
  issuer: "sift-staging",
  revoked_kids: [] as string[],
};

const UNSIGNED_KRL_WITH_REVOKED = {
  ...UNSIGNED_KRL_EMPTY,
  revoked_kids: ["revoked-kid-1"],
};

// Signed KRL shape — has a "signature" key, triggering the signed path.
// The actual sig bytes are placeholders; verifyKrl is always mocked.
const SIGNED_KRL_EMPTY = {
  version: "SignedKRLV1",
  issuer: "krl-issuer",
  krl_version: 1,
  issued_at: TEST_NOW - 60,
  not_after: TEST_NOW + 3600,
  revoked_kids: [] as string[],
  signature: { alg: "Ed25519", kid: "krl-key-1", sig: "placeholder-sig" },
};

const SIGNED_KRL_WITH_REVOKED = {
  ...SIGNED_KRL_EMPTY,
  revoked_kids: ["revoked-kid-1"],
};

const SIGNED_KRL_VERSION_5 = {
  ...SIGNED_KRL_EMPTY,
  krl_version: 5,
};

// KRL with a partial/malformed signature field — still triggers signed path
const KRL_PARTIAL_SIG = {
  ...UNSIGNED_KRL_EMPTY,
  signature: {},  // has the key "signature" → signed path
};

// ─── Mock factories ───────────────────────────────────────────────────────────

type MockResponse = { status: number; body: unknown } | { status: number; error: string };

function makeFetch(routes: Record<string, MockResponse>): typeof globalThis.fetch {
  return async (input: string | URL | Request) => {
    const url =
      typeof input === "string" ? input
      : input instanceof URL ? input.toString()
      : input.url;
    const route = routes[url];
    if (!route) return new Response(null, { status: 404 }) as Response;
    if ("error" in route) throw new Error(route.error);
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    }) as Response;
  };
}

function happyJwks(): Record<string, MockResponse> {
  return { [JWKS_URL]: { status: 200, body: VALID_JWKS } };
}

function routesFor(krlBody: unknown): Record<string, MockResponse> {
  return {
    ...happyJwks(),
    [KRL_URL]: { status: 200, body: krlBody },
  };
}

/** Creates a verifyKrl spy that records calls and returns a fixed result. */
function makeKrlSpy(
  result: { ok: boolean; violations: Array<{ code: string; message?: string }> }
): { spy: KrlVerifyFn; calls: { n: number } } {
  const calls = { n: 0 };
  const spy: KrlVerifyFn = (_payload, _ctx) => {
    calls.n++;
    return result;
  };
  return { spy, calls };
}

// Successful verifyKrl result including accepted metadata.
// accepted is required by SiftHttpKeyStore to advance the krl_version watermark.
const KRL_OK = {
  ok:         true as const,
  violations: [] as Array<{ code: string; message?: string }>,
  accepted:   { issuer: "krl-issuer", krl_version: 1 },   // matches SIGNED_KRL_EMPTY
};

// Variant for SIGNED_KRL_VERSION_5 (krl_version=5) — used in KM-21
const KRL_OK_V5 = {
  ...KRL_OK,
  accepted: { issuer: "krl-issuer", krl_version: 5 },
};

function krlFail(code: string, message = "verification failed") {
  return { ok: false, violations: [{ code, message }] };
}

// ─── KM-1: signed_required without verifyKrl fails at construction ─────────────

test("KM-1: signed_required without verifyKrl throws TypeError at construction", () => {
  assert.throws(
    () => new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL, krlMode: "signed_required" }),
    (err: unknown) => {
      assert.ok(err instanceof TypeError, `expected TypeError, got ${err}`);
      assert.ok((err as TypeError).message.includes("verifyKrl"), `unexpected message: ${(err as TypeError).message}`);
      return true;
    }
  );
});

// ─── KM-2: unsigned_legacy emits deprecation status ──────────────────────────

test("KM-2: unsigned_legacy accepted with unsigned_legacy integrity status", async () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    fetch: makeFetch(routesFor(UNSIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await store.refresh();
  const status = store.getKrlStatus();
  assert.strictEqual(status.mode, "unsigned_legacy");
  assert.strictEqual(status.lastIntegrity, "unsigned_legacy");
  assert.strictEqual(status.unsignedFallbackActive, false);
  assert.strictEqual(status.lastReason, undefined);
  assert.strictEqual(status.lastVerifiedAt, TEST_NOW);
});

// ─── KM-3: valid signed KRL accepted in signed_required ──────────────────────

test("KM-3: valid signed KRL accepted in signed_required", async () => {
  const { spy, calls } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await store.refresh();
  assert.strictEqual(calls.n, 1, "verifyKrl must be called once");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "signed");
  assert.strictEqual(store.getKrlStatus().lastReason, undefined);
});

// ─── KM-4: invalid signed KRL rejected (KRL_SIG_INVALID) ─────────────────────

test("KM-4: invalid signed KRL rejected with KRL_SIG_INVALID in signed_required", async () => {
  const { spy, calls } = makeKrlSpy(krlFail("KRL_SIG_INVALID", "signature mismatch"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_SIG_INVALID"));
      return true;
    }
  );
  assert.strictEqual(calls.n, 1, "verifyKrl must be called");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_SIG_INVALID");
});

// ─── KM-5: expired signed KRL rejected ───────────────────────────────────────

test("KM-5: expired signed KRL rejected with KRL_EXPIRED", async () => {
  const { spy } = makeKrlSpy(krlFail("KRL_EXPIRED", "KRL has expired"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_EXPIRED");
});

// ─── KM-6: unsupported alg rejected ──────────────────────────────────────────

test("KM-6: unsupported alg rejected with KRL_UNSUPPORTED_ALG in signed_preferred", async () => {
  const { spy } = makeKrlSpy(krlFail("KRL_UNSUPPORTED_ALG", "only Ed25519 is supported"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_UNSUPPORTED_ALG");
});

// ─── KM-7: unknown signing kid rejected ──────────────────────────────────────

test("KM-7: unknown signing kid rejected with KRL_UNKNOWN_SIGNING_KID", async () => {
  const { spy } = makeKrlSpy(krlFail("KRL_UNKNOWN_SIGNING_KID", "kid not found"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_UNKNOWN_SIGNING_KID");
});

// ─── KM-8: inactive signing key rejected ─────────────────────────────────────

test("KM-8: inactive signing key rejected with KRL_SIGNING_KEY_INACTIVE", async () => {
  const { spy } = makeKrlSpy(krlFail("KRL_SIGNING_KEY_INACTIVE", "key is revoked"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_SIGNING_KEY_INACTIVE");
});

// ─── KM-9: version regression rejected ───────────────────────────────────────

test("KM-9: version regression rejected with KRL_VERSION_REGRESSION", async () => {
  const { spy } = makeKrlSpy(krlFail("KRL_VERSION_REGRESSION", "version went backwards"));
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_VERSION_REGRESSION");
});

// ─── KM-10: unsigned KRL in signed_required rejected WITHOUT calling verifyKrl ─

test("KM-10: unsigned KRL in signed_required rejected before verifyKrl is consulted", async () => {
  const { spy, calls } = makeKrlSpy(KRL_OK);  // spy that would pass if called
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(UNSIGNED_KRL_EMPTY)),  // no signature field
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_UNSIGNED_IN_SIGNED_REQUIRED"),
        `expected KRL_UNSIGNED_IN_SIGNED_REQUIRED in message, got: ${err.message}`);
      return true;
    }
  );

  // CRITICAL: verifyKrl must NOT have been called — unsigned detection happens first
  assert.strictEqual(calls.n, 0, "verifyKrl must NOT be called when unsigned KRL is rejected in signed_required");

  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_UNSIGNED_IN_SIGNED_REQUIRED");
});

// ─── KM-11: signed KRL in signed_preferred with no verifyKrl fails closed ────

test("KM-11: signed KRL in signed_preferred with no verifyKrl fails closed", async () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    // No verifyKrl configured
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_MISSING_VERIFY_CALLBACK") ||
                err.message.toLowerCase().includes("no verifyKrl"),
        `unexpected message: ${(err as Error).message}`);
      return true;
    }
  );

  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
});

// ─── KM-12: unsigned KRL accepted in signed_preferred WITHOUT calling verifyKrl

test("KM-12: unsigned KRL in signed_preferred uses unsigned fallback, verifyKrl spy not called", async () => {
  // Configure a spy even though the KRL is unsigned — to prove it is NOT called.
  const { spy, calls } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(UNSIGNED_KRL_EMPTY)),  // no signature field
    now: () => TEST_NOW,
  });

  await store.refresh();

  // CRITICAL: verifyKrl must NOT be called — unsigned fallback routes around it
  assert.strictEqual(calls.n, 0,
    "verifyKrl must NOT be called for unsigned KRL in signed_preferred unsigned fallback");

  const status = store.getKrlStatus();
  assert.strictEqual(status.lastIntegrity, "unsigned_fallback");
  assert.strictEqual(status.unsignedFallbackActive, true);
  assert.strictEqual(status.lastReason, undefined);
  assert.strictEqual(status.lastVerifiedAt, TEST_NOW);
});

// ─── KM-13: partial/malformed signature field in signed_preferred fails closed

test("KM-13: partial signature field ({}) in signed_preferred fails closed (no unsigned fallback)", async () => {
  // KRL_PARTIAL_SIG has `signature: {}` — has the key "signature" → signed path.
  // No verifyKrl configured → KRL_MISSING_VERIFY_CALLBACK.
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    // No verifyKrl
    fetch: makeFetch(routesFor(KRL_PARTIAL_SIG)),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      return true;
    }
  );
  // Must NOT fall back to unsigned even though the KRL body is "unsigned-like"
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
});

// ─── KM-14: unsigned_legacy preserves current behavior ────────────────────────

test("KM-14: unsigned_legacy mode parses revoked_kids, non-strings silently skipped", async () => {
  const krlBody = {
    version: 1,
    issuer: "sift-staging",
    revoked_kids: ["kid-string-1", 42, null, "kid-string-2"],  // mixed types
  };
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    fetch: makeFetch(routesFor(krlBody)),
    now: () => TEST_NOW,
  });

  await store.refresh();

  // String entries added; non-strings skipped (legacy behavior)
  assert.strictEqual(await store.isKidRevoked("kid-string-1"), true);
  assert.strictEqual(await store.isKidRevoked("kid-string-2"), true);
  assert.strictEqual(await store.isKidRevoked("42"), false);

  const status = store.getKrlStatus();
  assert.strictEqual(status.lastIntegrity, "unsigned_legacy");
  assert.strictEqual(status.lastReason, undefined);
});

// ─── KM-15: revoked kid blocked in signed_required ────────────────────────────

test("KM-15: revoked kid blocked after signed KRL accepted in signed_required", async () => {
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_WITH_REVOKED)),
    now: () => TEST_NOW,
  });

  await store.refresh();
  assert.strictEqual(await store.isKidRevoked("revoked-kid-1"), true);
  assert.strictEqual(await store.isKidRevoked("other-kid"), false);
});

// ─── KM-16: revoked kid blocked in signed_preferred (signed path) ─────────────

test("KM-16: revoked kid blocked after signed KRL accepted in signed_preferred", async () => {
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_WITH_REVOKED)),
    now: () => TEST_NOW,
  });

  await store.refresh();
  assert.strictEqual(await store.isKidRevoked("revoked-kid-1"), true);
});

// ─── KM-17: revoked kid blocked in signed_preferred unsigned fallback ──────────

test("KM-17: revoked kid blocked in signed_preferred unsigned fallback, verifyKrl spy not called", async () => {
  // Configure a spy even though the KRL is unsigned — to prove it is NOT called.
  const { spy, calls } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(UNSIGNED_KRL_WITH_REVOKED)),  // no signature field
    now: () => TEST_NOW,
  });

  await store.refresh();

  // CRITICAL: verifyKrl must NOT be called on the unsigned fallback path
  assert.strictEqual(calls.n, 0,
    "verifyKrl must NOT be called for unsigned fallback revocation path");

  assert.strictEqual(await store.isKidRevoked("revoked-kid-1"), true);
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "unsigned_fallback");
});

// ─── KM-18: revoked kid blocked in unsigned_legacy ───────────────────────────

test("KM-18: revoked kid blocked in unsigned_legacy mode", async () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    fetch: makeFetch(routesFor(UNSIGNED_KRL_WITH_REVOKED)),
    now: () => TEST_NOW,
  });

  await store.refresh();
  assert.strictEqual(await store.isKidRevoked("revoked-kid-1"), true);
});

// ─── KM-19: now injection is passed to verifyKrl ─────────────────────────────

test("KM-19: now provider value is passed to verifyKrl ctx.now", async () => {
  const CUSTOM_NOW = 1744550000;
  let capturedNow: number | undefined;

  const verifyKrl: KrlVerifyFn = (_payload, ctx) => {
    capturedNow = ctx.now;
    return { ok: true, violations: [], accepted: { issuer: "krl-issuer", krl_version: 1 } };
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => CUSTOM_NOW,
  });

  await store.refresh();
  assert.strictEqual(capturedNow, CUSTOM_NOW, "ctx.now must match the injected now provider");
});

// ─── KM-20: previousKrlVersionByIssuer watermark is passed to verifyKrl ──────

test("KM-20: krl_version watermark is passed to verifyKrl on second refresh", async () => {
  const capturedPrev: Array<Record<string, number>> = [];
  let callCount = 0;

  const verifyKrl: KrlVerifyFn = (_payload, ctx) => {
    callCount++;
    capturedPrev.push({ ...ctx.previousKrlVersionByIssuer });
    return { ok: true, violations: [], accepted: { issuer: "krl-issuer", krl_version: 1 } };
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),  // krl_version=1, issuer="krl-issuer"
    now: () => TEST_NOW,
  });

  // First refresh: no prior version known → empty previousKrlVersionByIssuer
  await store.refresh();
  assert.deepStrictEqual(capturedPrev[0], {},
    "first refresh should have empty previousKrlVersionByIssuer");

  // Second refresh: previous version=1 should be passed
  await store.refresh();
  assert.strictEqual(capturedPrev[1]["krl-issuer"], 1,
    "second refresh should pass krl_version=1 as previous version for krl-issuer");

  assert.strictEqual(callCount, 2);
});

// ─── KM-21: krlVersionByIssuer updated after successful signed KRL ─────────────

test("KM-21: getKrlStatus().lastKrlVersionByIssuer updated after successful signed KRL", async () => {
  // Use KRL_OK_V5 so result.accepted.krl_version=5, matching SIGNED_KRL_VERSION_5 body.
  const { spy } = makeKrlSpy(KRL_OK_V5);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_VERSION_5)),  // krl_version=5 in body
    now: () => TEST_NOW,
  });

  // Before refresh: empty
  assert.deepStrictEqual(store.getKrlStatus().lastKrlVersionByIssuer, {});

  await store.refresh();

  assert.strictEqual(
    store.getKrlStatus().lastKrlVersionByIssuer["krl-issuer"],
    5,
    "lastKrlVersionByIssuer must reflect the accepted krl_version"
  );
});

// ─── KM-22: lastIntegrity is "signed" after successful signed path ─────────────

test("KM-22: getKrlStatus().lastIntegrity is \"signed\" after signed KRL success", async () => {
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "signed");
  assert.strictEqual(store.getKrlStatus().unsignedFallbackActive, false);
});

// ─── KM-23: lastVerifiedAt is set to nowFn() after success ────────────────────

test("KM-23: lastVerifiedAt is set to the current time on successful refresh", async () => {
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  assert.strictEqual(store.getKrlStatus().lastVerifiedAt, undefined, "should be undefined before refresh");

  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastVerifiedAt, TEST_NOW);
});

// ─── lastReason cleared on success after failure ──────────────────────────────

test("lastReason is cleared to undefined when a later refresh succeeds", async () => {
  let shouldFail = true;

  const verifyKrl: KrlVerifyFn = (_payload, _ctx) => {
    if (shouldFail) {
      return { ok: false, violations: [{ code: "KRL_SIG_INVALID", message: "bad signature" }] };
    }
    return { ok: true, violations: [], accepted: { issuer: "krl-issuer", krl_version: 1 } };
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  // First refresh: fails → lastReason set
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_SIG_INVALID",
    "lastReason must be set after failure");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");

  // Second refresh: succeeds → lastReason MUST be cleared
  shouldFail = false;
  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastReason, undefined,
    "lastReason must be cleared to undefined after successful refresh");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "signed");
});

// ─── lastReason cleared on unsigned fallback success ─────────────────────────

test("lastReason is cleared on unsigned fallback success after prior failure", async () => {
  // Build store in signed_preferred mode, no verifyKrl.
  // First attempt: signed KRL (has signature) → fails (no verifyKrl).
  // Second attempt: unsigned KRL (no signature) → unsigned fallback succeeds.
  let serveSignedKrl = true;

  const mockFetch: typeof globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    if (url === JWKS_URL) {
      return new Response(JSON.stringify(VALID_JWKS), {
        status: 200, headers: { "content-type": "application/json" },
      }) as Response;
    }
    const body = serveSignedKrl ? SIGNED_KRL_EMPTY : UNSIGNED_KRL_EMPTY;
    return new Response(JSON.stringify(body), {
      status: 200, headers: { "content-type": "application/json" },
    }) as Response;
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    // No verifyKrl — will fail for signed KRL, succeed for unsigned fallback
    fetch: mockFetch,
    now: () => TEST_NOW,
  });

  // First: fail (signed KRL, no verifyKrl)
  await assert.rejects(() => store.refresh());
  assert.ok(store.getKrlStatus().lastReason !== undefined, "lastReason must be set after failure");

  // Second: succeed via unsigned fallback
  serveSignedKrl = false;
  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastReason, undefined,
    "lastReason must be cleared even on unsigned fallback success");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "unsigned_fallback");
});

// ─── lastReason cleared on unsigned_legacy success ───────────────────────────

test("lastReason remains undefined after unsigned_legacy refresh success", async () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    fetch: makeFetch(routesFor(UNSIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastReason, undefined);
});

// ─── getKrlStatus() returns a snapshot (not mutable shared state) ─────────────

test("getKrlStatus() returns an independent snapshot of lastKrlVersionByIssuer", async () => {
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),  // krl_version=1
    now: () => TEST_NOW,
  });

  await store.refresh();
  const snap1 = store.getKrlStatus();
  assert.strictEqual(snap1.lastKrlVersionByIssuer["krl-issuer"], 1);

  // Mutate the snapshot — store must not be affected
  snap1.lastKrlVersionByIssuer["krl-issuer"] = 999;
  const snap2 = store.getKrlStatus();
  assert.strictEqual(snap2.lastKrlVersionByIssuer["krl-issuer"], 1,
    "mutating the returned snapshot must not affect internal state");
});

// ─── signed_preferred + no now provider uses real clock (smoke test) ──────────

test("signed_preferred with no now option uses real clock (smoke: lastVerifiedAt is positive integer)", async () => {
  const before = Math.floor(Date.now() / 1000);
  const { spy } = makeKrlSpy(KRL_OK);
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    // No `now` override — uses real clock
  });

  await store.refresh();
  const after = Math.floor(Date.now() / 1000);
  const verifiedAt = store.getKrlStatus().lastVerifiedAt;

  assert.ok(verifiedAt !== undefined, "lastVerifiedAt must be set");
  assert.ok(verifiedAt >= before, "lastVerifiedAt must be >= time before refresh");
  assert.ok(verifiedAt <= after, "lastVerifiedAt must be <= time after refresh");
});

// ─── Existing behavior: default mode is signed_preferred (smoke) ───────────────

test("default krlMode is signed_preferred", () => {
  const store = new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL });
  assert.strictEqual(store.getKrlStatus().mode, "signed_preferred");
});

// ─── KRL_VERIFY_RESULT_INCOMPLETE: ok: true without accepted fails closed ─────

test("verifyKrl returning ok: true without accepted fails closed with KRL_VERIFY_RESULT_INCOMPLETE", async () => {
  // verifyKrl returns ok: true but omits accepted — contract violation
  const verifyKrl: KrlVerifyFn = () => ({ ok: true, violations: [] });

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_VERIFY_RESULT_INCOMPLETE"),
        `expected KRL_VERIFY_RESULT_INCOMPLETE in message, got: ${err.message}`);
      return true;
    }
  );

  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_VERIFY_RESULT_INCOMPLETE");
});

// ─── Watermark sourced from result.accepted, not body re-parse ───────────────

test("watermark advances from result.accepted, not an independent body re-parse", async () => {
  // verifyKrl returns accepted.krl_version=99 while the body has krl_version=1.
  // SiftHttpKeyStore must use result.accepted, so the watermark should be 99.
  const verifyKrl: KrlVerifyFn = () => ({
    ok: true,
    violations: [],
    accepted: { issuer: "krl-issuer", krl_version: 99 },  // differs from body krl_version=1
  });

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl,
    fetch: makeFetch(routesFor(SIGNED_KRL_EMPTY)),  // body has krl_version=1
    now: () => TEST_NOW,
  });

  await store.refresh();

  // Watermark must come from result.accepted (99), not from independent body re-parse (1)
  assert.strictEqual(
    store.getKrlStatus().lastKrlVersionByIssuer["krl-issuer"],
    99,
    "watermark must be sourced from result.accepted.krl_version, not body krl_version"
  );
});
