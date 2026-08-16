import { Effect, Layer, Option, Redacted, Schema } from "effect"
import { TenantId } from "../../domain/Model.ts"
import { TenantAuth } from "../../ports/TenantAuth.ts"
import { hashApiKey } from "./hashApiKey.ts"
import { SqlExecutor } from "./SqlExecutor.ts"

const KeyRow = Schema.Struct({ tenant_id: TenantId })
const decodeKeyRow = Schema.decodeUnknownEffect(KeyRow)

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
          const hash = yield* hashApiKey(Redacted.value(apiKey))
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
}
