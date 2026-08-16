import { Effect, Layer, Option, Redacted, Schema } from "effect"
import type { CredentialId, TenantId } from "../../domain/Model.ts"
import { TokenSet } from "../../domain/Model.ts"
import { TokenCache } from "../../ports/TokenCache.ts"

/**
 * The narrow seam over a key-value store, mirroring `SqlExecutor`.
 *
 * Same reason: it lets the serialization and TTL logic be tested without a
 * Cloudflare binding, leaving only the trivial translation unverified.
 */
export interface KvClient {
  get(key: string): Effect.Effect<string | null>
  put(key: string, value: string, ttlSeconds: number): Effect.Effect<void>
  delete(key: string): Effect.Effect<void>
}

/**
 * How a token set is stored.
 *
 * Written as plain strings rather than `Redacted`, because `Redacted` refuses
 * to encode — deliberately. The values are re-wrapped the moment they are read
 * back, so the window in which they exist unwrapped is this function and the
 * KV write itself.
 *
 * Cloudflare KV is encrypted at rest and this cache holds short-lived tokens,
 * not the credentials that mint them; a leak here costs minutes of access, not
 * an account.
 */
const CachedTokens = Schema.Struct({
  accessToken: Schema.String,
  refreshToken: Schema.optional(Schema.String),
  expiresAt: Schema.Number
})

const encode = Schema.encodeSync(Schema.fromJsonString(CachedTokens))
const decode = Schema.decodeUnknownEffect(Schema.fromJsonString(CachedTokens))

/**
 * A floor on the KV TTL.
 *
 * Cloudflare rejects TTLs under 60 seconds. A token expiring sooner than that
 * is written with the floor and filtered on read instead — the broker already
 * treats anything within its expiry skew as stale, so a slightly over-long TTL
 * can never cause a dead token to be served.
 */
const MIN_TTL_SECONDS = 60

const keyOf = (tenantId: TenantId, id: CredentialId): string => `tok:${tenantId}:${id}`

export class KvTokenCache {
  static readonly make = (kv: KvClient): TokenCache["Service"] => {
    const get = Effect.fn("KvTokenCache.get")(function*(
      tenantId: TenantId,
      id: CredentialId
    ) {
      const raw = yield* kv.get(keyOf(tenantId, id))
      if (raw === null) return Option.none<TokenSet>()

      const decoded = yield* Effect.result(decode(raw))
      // A cache is not a source of truth: unreadable content is a miss, not a
      // failure. Failing here would turn a bad write into an outage.
      if (decoded._tag === "Failure") return Option.none<TokenSet>()

      return Option.some(
        new TokenSet({
          accessToken: Redacted.make(decoded.success.accessToken),
          ...(decoded.success.refreshToken === undefined
            ? {}
            : { refreshToken: Redacted.make(decoded.success.refreshToken) }),
          expiresAt: decoded.success.expiresAt
        })
      )
    })

    const set = Effect.fn("KvTokenCache.set")(function*(
      tenantId: TenantId,
      id: CredentialId,
      tokens: TokenSet
    ) {
      const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis)
      const ttl = Math.max(
        MIN_TTL_SECONDS,
        Math.ceil((tokens.expiresAt - now) / 1000)
      )

      yield* kv.put(
        keyOf(tenantId, id),
        encode({
          accessToken: Redacted.value(tokens.accessToken),
          ...(tokens.refreshToken === undefined
            ? {}
            : { refreshToken: Redacted.value(tokens.refreshToken) }),
          expiresAt: tokens.expiresAt
        }),
        ttl
      )
    })

    const invalidate = (tenantId: TenantId, id: CredentialId) =>
      kv.delete(keyOf(tenantId, id))

    return TokenCache.of({ get, set, invalidate })
  }

  static readonly layerWith = (kv: KvClient): Layer.Layer<TokenCache> =>
    Layer.succeed(TokenCache, KvTokenCache.make(kv))
}
