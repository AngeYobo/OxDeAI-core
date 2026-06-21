// SPDX-License-Identifier: Apache-2.0
import { Redis } from "ioredis";
import { createInMemoryReplayStore } from "@oxdeai/guard";
import type { ReplayStore } from "@oxdeai/guard";
import type { ReplayStoreConfig } from "./config.js";

export type RedisClientLike = {
  set(
    key: string,
    value: string,
    nx: "NX",
    ex: "EX",
    seconds: number,
  ): Promise<"OK" | null>;
};

export type CreateReplayStoreOptions = {
  config: ReplayStoreConfig;
  issuer: string;
  audience: string;
  authorizationTtlSeconds: number;
  redisClient?: RedisClientLike;
};

export type ReplayStoreHandle = {
  store: ReplayStore;
  disconnect: () => Promise<void>;
};

export function createReplayStoreHandle(options: CreateReplayStoreOptions): ReplayStoreHandle {
  const { config } = options;

  if (config.type === "memory") {
    return { store: createInMemoryReplayStore(), disconnect: async () => {} };
  }

  if (config.type === "redis") {
    let client: RedisClientLike;
    let ownedRedis: Redis | undefined;
    let connectPromise: Promise<void> | null = null;

    if (options.redisClient) {
      client = options.redisClient;
    } else {
      ownedRedis = new Redis(config.redisUrl, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
      });
      ownedRedis.on("error", () => {});
      client = ownedRedis as unknown as RedisClientLike;
    }

    const ensureConnected = async (): Promise<void> => {
      if (!ownedRedis) return;
      if (ownedRedis.status === "ready") return;
      if (!connectPromise) {
        connectPromise = ownedRedis.connect().finally(() => {
          connectPromise = null;
        });
      }
      await connectPromise;
    };

    const { keyPrefix, ttlSkewSeconds } = config;
    const issuer = options.issuer;
    const audience = options.audience;

    const store: ReplayStore = {
      async consumeAuthId(authId: string, opts: { expiry: number }): Promise<boolean> {
        const key = `${keyPrefix}:${issuer}:${audience}:${authId}`;
        const now = Math.floor(Date.now() / 1000);
        const ttl = Math.max(1, opts.expiry - now + ttlSkewSeconds);
        const value = JSON.stringify({
          claimed_at: new Date(now * 1000).toISOString(),
          issuer,
          audience,
        });
        await ensureConnected();
        const result = await client.set(key, value, "NX", "EX", ttl);
        return result === "OK";
      },
    };

    const disconnect = async () => {
      if (ownedRedis) {
        ownedRedis.disconnect();
      }
    };

    return { store, disconnect };
  }

  throw new Error(`Unsupported replay store type: "${(config as { type: string }).type}"`);
}

export function createReplayStore(options: CreateReplayStoreOptions): ReplayStore {
  return createReplayStoreHandle(options).store;
}
