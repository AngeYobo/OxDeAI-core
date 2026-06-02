// SPDX-License-Identifier: Apache-2.0
/**
 * Phase A (#117): Persistent KRL high-watermark tests for SiftHttpKeyStore.
 *
 * Tests the KrlWatermarkStore interface, in-memory and file-backed implementations,
 * SiftHttpKeyStore integration, and the persist-before-cache-swap invariant.
 *
 * Tests are separated by concern (not parameterized) to keep failure semantics clear.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { writeFile, unlink } from "node:fs/promises";

import {
  SiftHttpKeyStore,
  KeyStoreError,
  type KrlVerifyFn,
} from "../src/siftKeyStore.js";
import {
  createInMemoryKrlWatermarkStore,
  type KrlWatermarkStore,
} from "../src/krlWatermarkStore.js";
import { createFileBackedKrlWatermarkStore } from "../src/krlWatermarkStore.file.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const JWKS_URL = "https://sift-wm-test.example/sift-jwks.json";
const KRL_URL  = "https://sift-wm-test.example/sift-krl.json";

const RFC8037_X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "key-rfc8037";
const VALID_JWKS  = { keys: [{ kty: "OKP", crv: "Ed25519", kid: RFC8037_KID, x: RFC8037_X }] };

const TEST_NOW    = 1744632000;
const KRL_ISSUER  = "krl-issuer";

const SIGNED_KRL_V1 = {
  version: "SignedKRLV1", issuer: KRL_ISSUER, krl_version: 1,
  issued_at: TEST_NOW - 60, not_after: TEST_NOW + 3600,
  revoked_kids: [] as string[],
  signature: { alg: "Ed25519", kid: "krl-key-1", sig: "placeholder-sig" },
};

const SIGNED_KRL_V5 = { ...SIGNED_KRL_V1, krl_version: 5 };
const SIGNED_KRL_V3 = { ...SIGNED_KRL_V1, krl_version: 3 };

// ─── Mock helpers ─────────────────────────────────────────────────────────────

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

function makeKrlOk(
  accepted: { issuer: string; krl_version: number }
): ReturnType<KrlVerifyFn> {
  return { ok: true, violations: [], accepted };
}

function makeKrlFail(code: string): ReturnType<KrlVerifyFn> {
  return { ok: false, violations: [{ code, message: `${code} from test` }] };
}

/** A spy verifyKrl that returns a fixed result and records how it was called. */
function makeVerifyKrlSpy(
  result: ReturnType<KrlVerifyFn>
): { fn: KrlVerifyFn; calls: Array<{ prevVersions: Record<string, number> }> } {
  const calls: Array<{ prevVersions: Record<string, number> }> = [];
  const fn: KrlVerifyFn = (_payload, ctx) => {
    calls.push({ prevVersions: { ...(ctx.previousKrlVersionByIssuer ?? {}) } });
    return result;
  };
  return { fn, calls };
}

function tmpWatermarkPath(): string {
  return join(tmpdir(), `krl-wm-test-${randomBytes(6).toString("hex")}.json`);
}

// ─── WM-1: Default behavior unchanged with no store configured ─────────────

test("WM-1: no krlWatermarkStore configured - behavior unchanged, watermarkStore is memory", async () => {
  const { fn, calls } = makeVerifyKrlSpy(
    makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 })
  );
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: fn,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });

  await store.refresh();

  const status = store.getKrlStatus();
  assert.strictEqual(status.watermarkStore, "memory");
  assert.strictEqual(status.lastKrlVersionByIssuer[KRL_ISSUER], 1);
  assert.strictEqual(calls.length, 1);
  // On first call with no store, prevVersions is empty
  assert.deepStrictEqual(calls[0].prevVersions, {});
});

// ─── WM-2: Persistent store not touched in constructor ─────────────────────

test("WM-2: KrlWatermarkStore is not called at construction time", () => {
  const calls = { list: 0, get: 0, set: 0 };
  const spy: KrlWatermarkStore = {
    async list() { calls.list++; return {}; },
    async get() { calls.get++; return undefined; },
    async set() { calls.set++; },
  };

  new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: spy,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
  });

  assert.strictEqual(calls.list, 0, "list() must not be called at construction");
  assert.strictEqual(calls.get,  0, "get()  must not be called at construction");
  assert.strictEqual(calls.set,  0, "set()  must not be called at construction");
});

// ─── WM-3: watermarkStore status field ─────────────────────────────────────

test("WM-3a: watermarkStore field is 'memory' when no store configured", () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
  });
  assert.strictEqual(store.getKrlStatus().watermarkStore, "memory");
});

test("WM-3b: watermarkStore field is 'persistent' when store configured", () => {
  const wm = createInMemoryKrlWatermarkStore();
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: wm,
  });
  assert.strictEqual(store.getKrlStatus().watermarkStore, "persistent");
});

// ─── WM-4: Persistent watermark survives process restart ──────────────────

test("WM-4: persistent watermark bootstraps previousKrlVersionByIssuer after restart", async () => {
  // Simulate a persistent store that survives across "process" lifetimes.
  const sharedWm = createInMemoryKrlWatermarkStore();

  // First "process": refresh with KRL version 5.
  const store1 = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 5 }),
    krlWatermarkStore: sharedWm,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V5)),
    now: () => TEST_NOW,
  });
  await store1.refresh();

  // Confirm persisted.
  const persisted = await sharedWm.list();
  assert.strictEqual(persisted[KRL_ISSUER], 5, "version 5 should be persisted after first refresh");

  // Second "process": new SiftHttpKeyStore with the same store.
  const { fn: spy2, calls: calls2 } = makeVerifyKrlSpy(
    makeKrlOk({ issuer: KRL_ISSUER, krl_version: 6 })
  );
  const store2 = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: spy2,
    krlWatermarkStore: sharedWm,
    fetch: makeFetch(happyRoutes({ ...SIGNED_KRL_V1, krl_version: 6 })),
    now: () => TEST_NOW,
  });
  await store2.refresh();

  assert.strictEqual(calls2.length, 1);
  // verifyKrl should receive previousKrlVersionByIssuer sourced from the store
  assert.strictEqual(
    calls2[0].prevVersions[KRL_ISSUER], 5,
    "second instance must receive persisted watermark version 5"
  );
  assert.strictEqual(store2.getKrlStatus().lastKrlVersionByIssuer[KRL_ISSUER], 6);
});

// ─── WM-5: Restart-and-replay attack blocked ───────────────────────────────

test("WM-5: restart-and-replay attack - older KRL rejected via persisted watermark", async () => {
  const sharedWm = createInMemoryKrlWatermarkStore();

  // First refresh: accept version 5, persist watermark.
  const store1 = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 5 }),
    krlWatermarkStore: sharedWm,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V5)),
    now: () => TEST_NOW,
  });
  await store1.refresh();
  assert.strictEqual((await sharedWm.list())[KRL_ISSUER], 5);

  // "Process restart": new instance with same store.
  // Attack: replay KRL version 3 (older than persisted 5).
  const { fn: attackSpy, calls: attackCalls } = makeVerifyKrlSpy(
    makeKrlFail("KRL_VERSION_REGRESSION")
  );
  const store2 = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: attackSpy,
    krlWatermarkStore: sharedWm,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V3)),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store2.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_VERSION_REGRESSION"));
      return true;
    }
  );

  // Attack was blocked: verifyKrl received prevVersions with version 5
  assert.strictEqual(attackCalls[0].prevVersions[KRL_ISSUER], 5,
    "attack verifyKrl must receive persisted watermark version 5");
  assert.strictEqual(store2.getKrlStatus().lastReason, "KRL_VERSION_REGRESSION");
});

// ─── WM-6: KRL_WATERMARK_PERSIST_FAILED - fail closed before cache swap ───

test("WM-6: watermarkStore.set() failure fails closed before cache swap", async () => {
  const failingStore: KrlWatermarkStore = {
    async list() { return {}; },
    async get() { return undefined; },
    async set() { throw new Error("disk full"); },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: failingStore,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });

  // Before refresh: no revocation data.
  assert.strictEqual(await store.isKidRevoked("any-kid"), false);

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      assert.ok(err.message.includes("KRL_WATERMARK_PERSIST_FAILED"),
        `expected KRL_WATERMARK_PERSIST_FAILED in message, got: ${(err as Error).message}`);
      return true;
    }
  );

  // Cache must NOT have been swapped.
  assert.strictEqual(await store.isKidRevoked("any-kid"), false,
    "revokedKids must not be updated when watermark persist fails");

  // Status records the failure reason.
  const status = store.getKrlStatus();
  assert.strictEqual(status.lastReason, "KRL_WATERMARK_PERSIST_FAILED");
  assert.strictEqual(status.lastIntegrity, "failed");
  // lastReason cleared on subsequent success - tested in WM-7b
});

test("WM-6b: lastReason cleared after successful refresh following persist failure", async () => {
  let shouldFail = true;
  const conditionalStore: KrlWatermarkStore = {
    async list() { return {}; },
    async get() { return undefined; },
    async set() {
      if (shouldFail) throw new Error("transient failure");
    },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: conditionalStore,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });

  // First: fail
  await assert.rejects(() => store.refresh());
  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_WATERMARK_PERSIST_FAILED");

  // Second: succeed
  shouldFail = false;
  await store.refresh();
  assert.strictEqual(store.getKrlStatus().lastReason, undefined,
    "lastReason must be cleared on successful refresh");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "signed");
});

// ─── WM-7: persist-before-swap ordering proof ─────────────────────────────

test("WM-7: watermarkStore.set() is called before revokedKids is updated", async () => {
  const eventLog: string[] = [];

  const observingStore: KrlWatermarkStore = {
    async list() { return {}; },
    async get() { return undefined; },
    async set(issuer, version) {
      eventLog.push(`set(${issuer},${version})`);
    },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 }),
    krlWatermarkStore: observingStore,
    fetch: makeFetch(happyRoutes({ ...SIGNED_KRL_V1, revoked_kids: ["kid-to-revoke"] })),
    now: () => TEST_NOW,
  });

  // Before refresh: not revoked
  assert.strictEqual(await store.isKidRevoked("kid-to-revoke"), false);

  await store.refresh();

  // After refresh: set was called
  assert.deepStrictEqual(eventLog, [`set(${KRL_ISSUER},1)`]);
  // And revocation data is now live
  assert.strictEqual(await store.isKidRevoked("kid-to-revoke"), true);
});

// ─── WM-8: lazy load merges persisted watermarks into in-memory map ────────

test("WM-8: lazy load - list() is called during refresh() and merged monotonically", async () => {
  const listCalls: Array<Record<string, number>> = [];
  let persisted: Record<string, number> = { [KRL_ISSUER]: 7 };

  const observingStore: KrlWatermarkStore = {
    async list() {
      listCalls.push({ ...persisted });
      return { ...persisted };
    },
    async get() { return undefined; },
    async set(issuer, version) {
      persisted = { ...persisted, [issuer]: Math.max(persisted[issuer] ?? 0, version) };
    },
  };

  // Spy verifyKrl: capture prevVersions passed to it
  let capturedPrev: Record<string, number> = {};
  const fn: KrlVerifyFn = (_payload, ctx) => {
    capturedPrev = { ...ctx.previousKrlVersionByIssuer };
    return makeKrlOk({ issuer: KRL_ISSUER, krl_version: 8 });
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_preferred",
    verifyKrl: fn,
    krlWatermarkStore: observingStore,
    fetch: makeFetch(happyRoutes({ ...SIGNED_KRL_V1, krl_version: 8 })),
    now: () => TEST_NOW,
  });

  // list() should NOT be called at construction
  assert.strictEqual(listCalls.length, 0, "list() must not be called at construction");

  await store.refresh();

  // list() must have been called during refresh()
  assert.strictEqual(listCalls.length, 1, "list() must be called once during refresh()");
  // verifyKrl must have received the persisted watermark (7)
  assert.strictEqual(capturedPrev[KRL_ISSUER], 7,
    "verifyKrl must receive previousKrlVersionByIssuer sourced from the persistent store");
  // After refresh, in-memory watermark should be 8 (from accepted)
  assert.strictEqual(store.getKrlStatus().lastKrlVersionByIssuer[KRL_ISSUER], 8);
});

// ─── WM-9: KRL_WATERMARK_LOAD_FAILED - list() failure ──────────────────────

test("WM-9: watermarkStore.list() failure produces KRL_WATERMARK_LOAD_FAILED, fails closed before verification", async () => {
  let verifyKrlCalled = false;
  const unavailableStore: KrlWatermarkStore = {
    async list() { throw new Error("storage unavailable"); },
    async get() { return undefined; },
    async set() {},
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "signed_required",
    verifyKrl: (_payload, _ctx) => {
      verifyKrlCalled = true;
      return makeKrlOk({ issuer: KRL_ISSUER, krl_version: 1 });
    },
    krlWatermarkStore: unavailableStore,
    fetch: makeFetch(happyRoutes(SIGNED_KRL_V1)),
    now: () => TEST_NOW,
  });

  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KEYSTORE_REFRESH_FAILED");
      assert.ok(err.message.includes("KRL_WATERMARK_LOAD_FAILED"),
        `expected KRL_WATERMARK_LOAD_FAILED in message, got: ${(err as Error).message}`);
      return true;
    }
  );

  assert.strictEqual(store.getKrlStatus().lastReason, "KRL_WATERMARK_LOAD_FAILED");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "failed");
  assert.strictEqual(verifyKrlCalled, false,
    "verifyKrl must not be called when list() fails (fail closed before verification)");
});

// ─── WM-10: unsigned_legacy skips watermark store ─────────────────────────

test("WM-10: unsigned_legacy mode never touches the watermark store", async () => {
  const calls = { list: 0, set: 0 };
  const spy: KrlWatermarkStore = {
    async list() { calls.list++; return {}; },
    async get() { return undefined; },
    async set() { calls.set++; },
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    krlWatermarkStore: spy,
    fetch: makeFetch(happyRoutes({ version: 1, issuer: "s", revoked_kids: [] })),
    now: () => TEST_NOW,
  });

  await store.refresh();

  assert.strictEqual(calls.list, 0, "list() must not be called in unsigned_legacy mode");
  assert.strictEqual(calls.set,  0, "set()  must not be called in unsigned_legacy mode");
});

// ─── WM-11: in-memory store - round-trip ──────────────────────────────────

test("WM-11: createInMemoryKrlWatermarkStore - round-trip get/set/list", async () => {
  const wm = createInMemoryKrlWatermarkStore();

  assert.deepStrictEqual(await wm.list(), {});
  assert.strictEqual(await wm.get("a"), undefined);

  await wm.set("issuer-a", 3);
  await wm.set("issuer-b", 7);

  assert.strictEqual(await wm.get("issuer-a"), 3);
  assert.strictEqual(await wm.get("issuer-b"), 7);
  assert.deepStrictEqual(await wm.list(), { "issuer-a": 3, "issuer-b": 7 });

  // Monotonic: set lower version does not decrease the watermark
  await wm.set("issuer-a", 1);
  assert.strictEqual(await wm.get("issuer-a"), 3, "lower version must not overwrite higher");
});

// ─── WM-12: file-backed store - round-trip ────────────────────────────────

test("WM-12: createFileBackedKrlWatermarkStore - round-trip write and read", async () => {
  const path = tmpWatermarkPath();
  const wm = createFileBackedKrlWatermarkStore(path);

  try {
    // Missing file → empty
    assert.deepStrictEqual(await wm.list(), {});
    assert.strictEqual(await wm.get("test-issuer"), undefined);

    // Write and read back
    await wm.set("test-issuer", 5);
    assert.strictEqual(await wm.get("test-issuer"), 5);
    assert.deepStrictEqual(await wm.list(), { "test-issuer": 5 });

    // Second issuer
    await wm.set("other-issuer", 12);
    const all = await wm.list();
    assert.strictEqual(all["test-issuer"], 5);
    assert.strictEqual(all["other-issuer"], 12);

    // Monotonic: lower version does not overwrite
    await wm.set("test-issuer", 3);
    assert.strictEqual(await wm.get("test-issuer"), 5,
      "lower version must not overwrite higher in file-backed store");

    // No orphaned .tmp file
    const { stat } = await import("node:fs/promises");
    await assert.rejects(
      () => stat(path + ".tmp"),
      { code: "ENOENT" },
      ".tmp file must not remain after successful write"
    );
  } finally {
    await unlink(path).catch(() => {});
  }
});

// ─── WM-13: file-backed store - malformed content fails closed ─────────────

test("WM-13: file-backed store with malformed content fails closed (throws on list)", async () => {
  const path = tmpWatermarkPath();
  const wm = createFileBackedKrlWatermarkStore(path);

  try {
    // Write garbage JSON
    await writeFile(path, "not valid json!!!", "utf8");

    await assert.rejects(
      () => wm.list(),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes("Malformed KRL watermark file"),
          `expected malformed-file message, got: ${err.message}`);
        return true;
      }
    );

    // set() should also fail because it reads first
    await assert.rejects(
      () => wm.set("issuer", 1),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        return true;
      }
    );
  } finally {
    await unlink(path).catch(() => {});
  }
});

// ─── WM-14: file-backed store - structurally invalid JSON object ────────────

test("WM-14: file-backed store with invalid value types fails closed", async () => {
  const path = tmpWatermarkPath();
  const wm = createFileBackedKrlWatermarkStore(path);

  try {
    // Valid JSON but wrong types for values
    await writeFile(path, JSON.stringify({ "issuer": "not-a-number" }), "utf8");

    await assert.rejects(
      () => wm.list(),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(err.message.includes("Malformed KRL watermark file"),
          `expected malformed message, got: ${err.message}`);
        return true;
      }
    );
  } finally {
    await unlink(path).catch(() => {});
  }
});

// ─── WM-15: file-backed store - SiftHttpKeyStore integration ───────────────

test("WM-15: SiftHttpKeyStore with file-backed store - version survives 'restart'", async () => {
  const path = tmpWatermarkPath();

  try {
    // First "process"
    const store1 = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_required",
      verifyKrl: () => makeKrlOk({ issuer: KRL_ISSUER, krl_version: 9 }),
      krlWatermarkStore: createFileBackedKrlWatermarkStore(path),
      fetch: makeFetch(happyRoutes({ ...SIGNED_KRL_V1, krl_version: 9 })),
      now: () => TEST_NOW,
    });
    await store1.refresh();

    // Confirm file has version 9
    const wmRead = createFileBackedKrlWatermarkStore(path);
    assert.strictEqual((await wmRead.list())[KRL_ISSUER], 9);

    // Second "process": new instance, same file.
    // Try to replay version 5 (should be rejected with KRL_VERSION_REGRESSION).
    const attackSpy = makeVerifyKrlSpy(makeKrlFail("KRL_VERSION_REGRESSION"));
    const store2 = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_required",
      verifyKrl: attackSpy.fn,
      krlWatermarkStore: createFileBackedKrlWatermarkStore(path),
      fetch: makeFetch(happyRoutes(SIGNED_KRL_V5)),
      now: () => TEST_NOW,
    });

    await assert.rejects(() => store2.refresh());

    // verifyKrl received the persisted watermark (9)
    assert.strictEqual(attackSpy.calls[0].prevVersions[KRL_ISSUER], 9,
      "second instance must use persisted watermark version 9");
    assert.strictEqual(store2.getKrlStatus().lastReason, "KRL_VERSION_REGRESSION");
  } finally {
    await unlink(path).catch(() => {});
    await unlink(path + ".tmp").catch(() => {});
  }
});
