import { assert, describe, it } from "@effect/vitest"
import { Effect, Option, Redacted, Ref, Schema } from "effect"
import { KvTokenCache, type KvClient } from "../../src/adapters/cache/KvTokenCache.ts"
import { CredentialId, TenantId, TokenSet } from "../../src/domain/Model.ts"
import { TokenCache } from "../../src/ports/TokenCache.ts"

const tenant = Schema.decodeUnknownSync(TenantId)("tenant-a")
const credId = Schema.decodeUnknownSync(CredentialId)("cred-1")

interface Written {
  readonly key: string
  readonly value: string
  readonly ttl: number
}

const makeKv = Effect.gen(function*() {
  const store = yield* Ref.make(new Map<string, string>())
  const writes = yield* Ref.make<ReadonlyArray<Written>>([])

  const client: KvClient = {
    get: (key) => Ref.get(store).pipe(Effect.map((m) => m.get(key) ?? null)),
    put: (key, value, ttl) =>
      Effect.gen(function*() {
        yield* Ref.update(store, (m) => new Map(m).set(key, value))
        yield* Ref.update(writes, (all) => [...all, { key, value, ttl }])
      }),
    delete: (key) =>
      Ref.update(store, (m) => {
        const next = new Map(m)
        next.delete(key)
        return next
      })
  }

  return { store, writes, layer: KvTokenCache.layerWith(client) } as const
})

const tokens = (expiresAt: number) =>
  new TokenSet({
    accessToken: Redacted.make("the-access-token"),
    refreshToken: Redacted.make("the-refresh-token"),
    expiresAt
  })

describe("KvTokenCache", () => {
  it.effect("round-trips a token set", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const found = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
        yield* cache.set(tenant, credId, tokens(now + 300_000))
        return yield* cache.get(tenant, credId)
      }).pipe(Effect.provide(kv.layer))

      assert.isTrue(Option.isSome(found))
      if (Option.isNone(found)) return
      assert.strictEqual(Redacted.value(found.value.accessToken), "the-access-token")
      assert.isTrue(found.value.refreshToken !== undefined)
    }))

  it.effect("reports a missing key as a miss, not an error", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const found = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        return yield* cache.get(tenant, credId)
      }).pipe(Effect.provide(kv.layer))

      assert.isTrue(Option.isNone(found))
    }))

  it.effect("treats unreadable content as a miss rather than failing", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      yield* Ref.update(kv.store, (m) => new Map(m).set(`tok:${tenant}:${credId}`, "not json"))

      const found = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        return yield* cache.get(tenant, credId)
      }).pipe(Effect.provide(kv.layer))

      // A corrupt cache entry must degrade to a re-mint, not an outage.
      assert.isTrue(Option.isNone(found))
    }))

  it.effect("derives the TTL from the token's own expiry", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const writes = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
        yield* cache.set(tenant, credId, tokens(now + 300_000))
        return yield* Ref.get(kv.writes)
      }).pipe(Effect.provide(kv.layer))

      assert.strictEqual(writes[0]?.ttl, 300)
    }))

  it.effect("raises a short TTL to Cloudflare's 60-second floor", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const writes = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
        // 10s of life left; KV would reject a TTL below 60.
        yield* cache.set(tenant, credId, tokens(now + 10_000))
        return yield* Ref.get(kv.writes)
      }).pipe(Effect.provide(kv.layer))

      assert.strictEqual(writes[0]?.ttl, 60)
    }))

  it.effect("scopes keys by tenant so two tenants cannot collide", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const other = Schema.decodeUnknownSync(TenantId)("tenant-b")

      const found = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
        yield* cache.set(tenant, credId, tokens(now + 300_000))
        // Same credential id, different tenant.
        return yield* cache.get(other, credId)
      }).pipe(Effect.provide(kv.layer))

      assert.isTrue(Option.isNone(found))
    }))

  it.effect("invalidates a cached token", () =>
    Effect.gen(function*() {
      const kv = yield* makeKv
      const found = yield* Effect.gen(function*() {
        const cache = yield* TokenCache
        const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
        yield* cache.set(tenant, credId, tokens(now + 300_000))
        yield* cache.invalidate(tenant, credId)
        return yield* cache.get(tenant, credId)
      }).pipe(Effect.provide(kv.layer))

      assert.isTrue(Option.isNone(found))
    }))
})
