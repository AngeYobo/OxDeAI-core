// SPDX-License-Identifier: Apache-2.0
/**
 * Phase B (#117): Last-known-good signed-KRL cache tests for SiftHttpKeyStore.
 *
 * Tests LKG lifecycle, mode behavior, trust-rule enforcement, LKG write
 * sequencing, and the status surface.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { unlink } from "node:fs/promises";

import {
  SiftHttpKeyStore,
  KeyStoreError,
  type KrlVerifyFn,
} from "../src/siftKeyStore.js";
import {
  createInMemorySignedKrlCache,
  type SignedKrlCache,
} from "../src/signedKrlCache.js";
import { createFileBackedSignedKrlCache } from "../src/signedKrlCache.file.js";
import { createInMemoryKrlWatermarkStore } from "../src/krlWatermarkStore.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const JWKS_URL   = "https://sift-lkg-test.example/sift-jwks.json";
const KRL_URL    = "https://sift-lkg-test.example/sift-krl.json";
const KRL_ISSUER = "krl-issuer";
const TEST_NOW   = 1744632000;

const RFC8037_X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "key-rfc8037";
const VALID_JWKS  = { keys: [{ kty: "OKP", crv: "Ed25519", kid: RFC8037_KID, x: RFC8037_X }] };

const SIGNED_KRL_V1 = {
  version: "SignedKRLV1", issuer: KRL_ISSUER, krl_version: 1,
  issued_at: TEST_NOW - 60, not_after: TEST_NOW + 3600,
  revoked_kids: [] as string[],
  signature: { alg: "Ed25519", kid: "krl-key-1", sig: "placeholder" },
};

const SIGNED_KRL_WITH_REVOKED = {
  ...SIGNED_KRL_V1,
  revoked_kids: ["revoked-from-lkg"],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

type MockResponse = { status: number; body: unknown } | { status: number; error: string };

function makeFetch(routes: Record<string, MockResponse>): typeof globalThis.fetch {
  return async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const route = routes[url];
    if (!route) return new Response(null, { status: 404 }) as Response;
    if ("error" in route) throw new Error(route.error);
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    }) as Response;
  };
}

function happyRoutes(krlBody: unknown): Record<string, MockResponse> {
  return {
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: krlBody },
  };
}

function failingFetch(): typeof globalThis.fetch {
  return async () => { throw new Error("network down"); };
}

function krlOk(accepted?: { issuer: string; krl_version: number }): ReturnType<KrlVerifyFn> {
  return {
    ok: true,
    violations: [],
    accepted: accepted ?? { issuer: KRL_ISSUER, krl_version: 1 },
  };
}

function krlFail(code: string): ReturnType<KrlVerifyFn> {
  return { ok: false, violations: [{ code, message: `${code} (test)` }] };
}

function tmpCachePath(): string {
  return join(tmpdir(), `lkg-test-${randomBytes(6).toString("hex")}.json`);
}

// ─── LKG-1: No constructor I/O ────────────────────────────────────────────

test("LKG-1: SignedKrlCache.get and .set are not called at construction time", () => {
  const calls = { get: 0, set: 0 };
  const spy: SignedKrlCache = {
    async get() { calls.get++; return undefined; },
    async set() { calls.set++; },
  };

  new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: () => krlOk(),
    signedKrlCache: spy,
  });

  assert.strictEqual(calls.get, 0, "get must not be called at construction");
  assert.strictEqual(calls.set, 0, "set must not be called at construction");
});

// ─── LKG-2: LKG skipped in unsigned_legacy ───────────────────────────────

test("LKG-2a: unsigned_legacy successful refresh does not call LKG set", async () => {
  const spy: SignedKrlCache = {
    async get() { return undefined; },
    async set() { assert.fail("set must not be called in unsigned_legacy mode"); },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    signedKrlCache: spy,
    fetch: makeFetch(happyRoutes({ version: 1, issuer: "s", revoked_kids: [] })),
    now: () => TEST_NOW,
  });

  await store.refresh(); // must succeed without calling spy.set
});

test("LKG-2b: unsigned_legacy failing fetch does not call LKG get", async () => {
  const spy: SignedKrlCache = {
    async get() { assert.fail("get must not be called in unsigned_legacy mode"); return undefined; },
    async set() {},
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    signedKrlCache: spy,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(() => store.refresh());
});

// ─── LKG-3: Valid LKG in signed_required populates revokedKids ───────────

test("LKG-3: valid LKG populates revokedKids after fresh fetch fails in signed_required", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_WITH_REVOKED, TEST_NOW - 60);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await store.refresh(); // succeeds via LKG

  assert.strictEqual(await store.isKidRevoked("revoked-from-lkg"), true,
    "LKG revoked kids must be active after successful LKG fallback");
  assert.strictEqual(await store.isKidRevoked("other-kid"), false);

  const status = store.getKrlStatus();
  assert.strictEqual(status.lkgCacheActive, true);
  assert.ok(status.lkgVerifiedAt !== undefined, "lkgVerifiedAt must be set");
  assert.strictEqual(status.lastIntegrity, "signed");
  assert.strictEqual(status.lastReason, undefined);
});

// ─── LKG-4: Expired LKG fails closed ────────────────────────────────────

test("LKG-4: expired LKG fails closed in signed_required with KRL_EXPIRED", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, TEST_NOW - 100);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlFail("KRL_EXPIRED"),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.ok(err.message.includes("KRL_EXPIRED"));
      return true;
    }
  );

  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_EXPIRED");
  assert.strictEqual(store.getKrlStatus().lkgCacheActive, false);
  assert.strictEqual(await store.isKidRevoked("revoked-from-lkg"), false,
    "revokedKids must not be populated from a rejected LKG entry");
});

// ─── LKG-5: Signature-invalid LKG fails closed ──────────────────────────

test("LKG-5: signature-invalid LKG fails closed in signed_required with KRL_SIG_INVALID", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, TEST_NOW - 60);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlFail("KRL_SIG_INVALID"),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_SIG_INVALID");
  assert.strictEqual(store.getKrlStatus().lkgCacheActive, false);
});

// ─── LKG-6: Signing-key-inactive LKG fails closed ───────────────────────

test("LKG-6: signing-key-inactive LKG fails closed in signed_required", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, TEST_NOW - 60);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlFail("KRL_SIGNING_KEY_INACTIVE"),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_SIGNING_KEY_INACTIVE");
});

// ─── LKG-7: Version-regressed LKG fails closed ──────────────────────────

test("LKG-7: version-regressed LKG fails closed with KRL_VERSION_REGRESSION", async () => {
  const wm = createInMemoryKrlWatermarkStore();
  await wm.set(KRL_ISSUER, 10); // persisted watermark says version 10

  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set({ ...SIGNED_KRL_V1, krl_version: 5 }, TEST_NOW - 60); // LKG version is 5

  let capturedPrev: Record<string, number> = {};
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: (_payload, ctx) => {
      capturedPrev = { ...ctx.previousKrlVersionByIssuer };
      return krlFail("KRL_VERSION_REGRESSION");
    },
    krlWatermarkStore: wm,
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(() => store.refresh());

  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_VERSION_REGRESSION");
  assert.strictEqual(capturedPrev[KRL_ISSUER], 10,
    "LKG re-verification must use persisted watermark version 10");
});

// ─── LKG-8: Malformed LKG fails closed ──────────────────────────────────

test("LKG-8: malformed LKG fails closed in signed_required with KRL_MALFORMED", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  // Store an invalid payload that verifyKrl would consider malformed
  await lkgCache.set({ not_a_krl: true }, TEST_NOW - 60);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlFail("KRL_MALFORMED"),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_MALFORMED");
  assert.strictEqual(store.getKrlStatus().lkgCacheActive, false);
});

// ─── LKG-9: Invalid LKG in signed_preferred preserves compatibility ───────

test("LKG-9: invalid LKG in signed_preferred rethrows original fetch error", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, TEST_NOW - 60);

  // verifyKrl says signature invalid
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: () => krlFail("KRL_SIG_INVALID"),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      // Should be the original network error, not LKG error
      assert.ok(err.message.includes("network down"),
        `expected original fetch error, got: ${(err as Error).message}`);
      return true;
    }
  );

  assert.strictEqual(store.getKrlStatus().lkgCacheActive, false);
  assert.strictEqual(await store.isKidRevoked("any-kid"), false,
    "revokedKids must not be populated from a rejected LKG in signed_preferred");
});

// ─── LKG-10: LKG write occurs after successful signed verification ────────

test("LKG-10: LKG set() called after successful signed verification and watermark persistence", async () => {
  const wm = createInMemoryKrlWatermarkStore();
  const writtenPayloads: unknown[] = [];
  const cache: SignedKrlCache = {
    async get() { return undefined; },
    async set(payload) { writtenPayloads.push(payload); },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: wm,
    signedKrlCache: cache,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });

  await store.refresh();

  assert.strictEqual(writtenPayloads.length, 1,
    "LKG set() must be called exactly once after successful signed refresh");
  // Payload should be the signed KRL body
  assert.deepStrictEqual(writtenPayloads[0], SIGNED_KRL_V1);
});

// ─── LKG-11: LKG write failure is non-fatal ──────────────────────────────

test("LKG-11: LKG set() failure does not fail the refresh", async () => {
  const failingCache: SignedKrlCache = {
    async get() { return undefined; },
    async set() { throw new Error("disk full"); },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    signedKrlCache: failingCache,
    fetch: makeFetch(happyRoutes({ ...SIGNED_KRL_V1, revoked_kids: ["a-kid"] })),
    now: () => TEST_NOW,
  });

  // Refresh must succeed despite LKG write failure
  await store.refresh();

  // keyCache and revokedKids must be updated
  assert.strictEqual(await store.isKidRevoked("a-kid"), true,
    "revokedKids must be populated despite LKG write failure");

  // lkgCacheActive remains false (did not come from LKG)
  assert.strictEqual(store.getKrlStatus().lkgCacheActive, false);
  // No failure reason set
  assert.strictEqual(store.getKrlStatus().lastReason, undefined);
});

// ─── LKG-12: Status fields are correct ───────────────────────────────────

test("LKG-12a: after LKG-sourced refresh: lkgCacheActive true, lkgVerifiedAt set", async () => {
  const LKG_VERIFIED_AT = TEST_NOW - 300;
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, LKG_VERIFIED_AT);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await store.refresh();

  const status = store.getKrlStatus();
  assert.strictEqual(status.lkgCacheActive, true);
  assert.strictEqual(status.lkgVerifiedAt, LKG_VERIFIED_AT);
});

test("LKG-12b: after normal fresh refresh: lkgCacheActive false, lkgVerifiedAt cleared", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  await lkgCache.set(SIGNED_KRL_V1, TEST_NOW - 300);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  // LKG refresh sets lkgCacheActive
  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lkgCacheActive, true);

  // A separate store that does a normal fresh refresh must show lkgCacheActive false.
  const freshStore = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    signedKrlCache: lkgCache,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });
  await freshStore.refresh();

  const freshStatus = freshStore.getKrlStatus();
  assert.strictEqual(freshStatus.lkgCacheActive, false,
    "lkgCacheActive must be false after normal fresh refresh");
  assert.strictEqual(freshStatus.lkgVerifiedAt, undefined,
    "lkgVerifiedAt must be cleared after normal fresh refresh");
});

// ─── LKG-13: Status does not expose sensitive material ───────────────────

test("LKG-13: krlStatus JSON does not contain payload, signature, PEM, or key material", async () => {
  const lkgCache = createInMemorySignedKrlCache();
  const sensitivePayload = {
    version: "SignedKRLV1",
    issuer: "krl-issuer",
    krl_version: 1,
    issued_at: TEST_NOW - 60,
    not_after: TEST_NOW + 3600,
    revoked_kids: [],
    signature: {
      alg: "Ed25519",
      kid: "krl-key-1",
      sig: "SENSITIVE_SIGNATURE_BYTES_THAT_MUST_NOT_APPEAR_IN_STATUS",
    },
  };
  await lkgCache.set(sensitivePayload, TEST_NOW - 60);

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => krlOk({ issuer: "krl-issuer", krl_version: 1 }),
    signedKrlCache: lkgCache,
    fetch: failingFetch(),
    now: () => TEST_NOW,
  });

  await store.refresh(); // LKG path

  const statusJson = JSON.stringify(store.getKrlStatus());

  assert.ok(
    !statusJson.includes("SENSITIVE_SIGNATURE_BYTES_THAT_MUST_NOT_APPEAR_IN_STATUS"),
    "signature bytes must not appear in status"
  );
  assert.ok(!statusJson.includes("BEGIN PUBLIC KEY"), "PEM must not appear in status");
  assert.ok(!statusJson.includes("revoked_kids"), "full payload must not appear in status");
});

// ─── LKG-14: File-backed cache round-trip ────────────────────────────────

test("LKG-14a: file-backed cache stores and retrieves payload + verifiedAt", async () => {
  const path = tmpCachePath();
  const cache = createFileBackedSignedKrlCache(path);

  try {
    assert.strictEqual(await cache.get(), undefined, "missing file returns undefined");

    await cache.set({ foo: "bar", krl_version: 7 }, 1744000000);
    const entry = await cache.get();

    assert.ok(entry !== undefined);
    assert.strictEqual(entry.verifiedAt, 1744000000);
    assert.deepStrictEqual(entry.payload, { foo: "bar", krl_version: 7 });
  } finally {
    await unlink(path).catch(() => {});
  }
});

test("LKG-14b: file-backed cache with malformed content throws on get", async () => {
  const path = tmpCachePath();
  const cache = createFileBackedSignedKrlCache(path);

  const { writeFile } = await import("node:fs/promises");
  try {
    await writeFile(path, "not valid json!", "utf8");
    await assert.rejects(
      () => cache.get(),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes("Malformed LKG cache file"),
          `expected malformed message, got: ${err.message}`);
        return true;
      }
    );
  } finally {
    await unlink(path).catch(() => {});
  }
});

// ─── LKG-15: LKG cache writes only signed KRLs ───────────────────────────

test("LKG-15: signed_preferred unsigned fallback does not write to LKG cache", async () => {
  let setCalled = false;
  const spy: SignedKrlCache = {
    async get() { return undefined; },
    async set() { setCalled = true; },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    signedKrlCache: spy,
    // No verifyKrl — unsigned fallback path
    fetch: makeFetch(happyRoutes({ version: 1, issuer: "s", revoked_kids: [] })),
    now: () => TEST_NOW,
  });

  await store.refresh(); // unsigned fallback

  assert.strictEqual(store.getKrlStatus().lastIntegrity, "unsigned_fallback");
  assert.strictEqual(setCalled, false,
    "LKG set must not be called for unsigned fallback KRLs");
});
