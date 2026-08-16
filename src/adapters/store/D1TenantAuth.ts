import { Effect, Layer, Option, Redacted, Schema } from "effect"
import { TenantId } from "../../domain/Model.ts"
import { TenantAuth } from "../../ports/TenantAuth.ts"
import { SqlExecutor } from "./SqlExecutor.ts"

const KeyRow = Schema.Struct({ tenant_id: TenantId })
const decodeKeyRow = Schema.decodeUnknownEffect(KeyRow)

/**
 * SHA-256 of the presented key, hex-encoded.
 *
 * Keys are stored hashed and never in plaintext, so a database dump yields
 * nothing usable. This is a plain digest rather than a password KDF on
 * purpose: an API key is high-entropy random data, not a human-chosen
 * password, so there is no dictionary to defend against and a slow KDF would
 * only add latency to every request.
 */
const hashKey = (key: string): Effect.Effect<string> =>
  Effect.promise(async () => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key))
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
  })

/**
 * `TenantAuth` over the `api_keys` table.
 *
 * A lookup failure resolves to `none` rather than an error: at an
 * internet-facing edge, an unknown key is routine traffic, and turning it into
 * a failure would make the logs useless and the metrics alarming.
 */
export class D1TenantAuth {
  static readonly layer: Layer.Layer<TenantAuth, never, SqlExecutor> = Layer.effect(
    TenantAuth,
    Effect.gen(function*() {
      const sql = yield* SqlExecutor

      const resolve = Effect.fn("D1TenantAuth.resolve")(
        function*(apiKey: Redacted.Redacted<string>) {
          const hash = yield* hashKey(Redacted.value(apiKey))
          const rows = yield* sql.all(
            `SELECT tenant_id FROM api_keys
              WHERE key_hash = ? AND revoked_at IS NULL
              LIMIT 1`,
            [hash]
          ).pipe(
            // A database outage must not read as "your key is invalid", which
            // would send operators hunting a credential problem that does not
            // exist. Fail loudly instead.
            Effect.orDie
          )

          const first = rows[0]
          if (first === undefined) return Option.none<TenantId>()
          const row = yield* decodeKeyRow(first).pipe(Effect.orDie)
          return Option.some(row.tenant_id)
        }
      )

      return TenantAuth.of({ resolve })
    })
  )

  /** Exposed for enrollment tooling and tests, so both hash identically. */
  static readonly hashKey = hashKey
}
