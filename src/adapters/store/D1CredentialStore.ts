import { Effect, Layer, Option, Schema } from "effect"
import { Sealed } from "../../crypto/Envelope.ts"
import {
  CredentialId,
  CredentialStatus,
  TenantId,
  type CredentialStatus as Status,
  type TenantId as Tenant
} from "../../domain/Model.ts"
import { CredentialRow, CredentialStore, StoreUnavailable } from "../../ports/CredentialStore.ts"
import { SqlExecutor } from "./SqlExecutor.ts"

/**
 * A row exactly as SQLite returns it: snake_case columns, integers for
 * booleans, nulls for absent values.
 *
 * Decoding through a schema rather than casting means a column that drifts —
 * renamed, retyped, or nulled by a bad migration — fails loudly at the read
 * instead of producing a `Credential` with `undefined` where a secret should
 * be.
 */
const DbRow = Schema.Struct({
  tenant_id: TenantId,
  id: CredentialId,
  label: Schema.String,
  cpf_masked: Schema.String,
  has_totp: Schema.Number,
  status: CredentialStatus,
  sealed_ciphertext: Schema.String,
  sealed_iv: Schema.String,
  last_login_at: Schema.optional(Schema.NullOr(Schema.Number)),
  last_error: Schema.optional(Schema.NullOr(Schema.String))
})

const decodeRow = Schema.decodeUnknownEffect(DbRow)

const toDomain = (row: typeof DbRow.Type): CredentialRow =>
  new CredentialRow({
    tenantId: row.tenant_id,
    id: row.id,
    label: row.label,
    cpfMasked: row.cpf_masked,
    // SQLite has no boolean type; anything non-zero is true.
    hasTotp: row.has_totp !== 0,
    status: row.status,
    sealed: new Sealed({ ciphertext: row.sealed_ciphertext, iv: row.sealed_iv }),
    ...(row.last_login_at === undefined || row.last_login_at === null
      ? {}
      : { lastLoginAt: row.last_login_at }),
    ...(row.last_error === undefined || row.last_error === null
      ? {}
      : { lastError: row.last_error })
  })

const SELECT = `
  SELECT tenant_id, id, label, cpf_masked, has_totp, status,
         sealed_ciphertext, sealed_iv, last_login_at, last_error
    FROM credentials
`

/**
 * `CredentialStore` over D1 (or any SQLite), through the `SqlExecutor` seam.
 *
 * Every statement is parameterized. That matters more than usual here: a
 * tenant id reaching the query as text rather than a bound parameter would
 * turn tenant scoping — the one boundary keeping customers apart — into a
 * string-concatenation bug.
 */
export class D1CredentialStore {
  static readonly layer: Layer.Layer<CredentialStore, never, SqlExecutor> = Layer.effect(
    CredentialStore,
    Effect.gen(function*() {
      const sql = yield* SqlExecutor

      const decodeAll = Effect.fn("D1CredentialStore.decodeAll")(
        function*(rows: ReadonlyArray<unknown>) {
          return yield* Effect.forEach(rows, (row) =>
            decodeRow(row).pipe(
              Effect.mapError((cause) =>
                new StoreUnavailable({ detail: "credential row failed to decode", cause })
              ),
              Effect.map(toDomain)
            ))
        }
      )

      const find = Effect.fn("D1CredentialStore.find")(
        function*(tenantId: Tenant, id: CredentialId) {
          const rows = yield* sql.all(
            `${SELECT} WHERE tenant_id = ? AND id = ? LIMIT 1`,
            [tenantId, id]
          )
          const decoded = yield* decodeAll(rows)
          return Option.fromNullishOr(decoded[0])
        }
      )

      const all = Effect.fn("D1CredentialStore.all")(function*(tenantId: Tenant) {
        const rows = yield* sql.all(
          `${SELECT} WHERE tenant_id = ? ORDER BY label`,
          [tenantId]
        )
        return yield* decodeAll(rows)
      })

      const upsert = Effect.fn("D1CredentialStore.upsert")(function*(row: CredentialRow) {
        yield* sql.run(
          `INSERT INTO credentials
             (tenant_id, id, label, cpf_masked, has_totp, status,
              sealed_ciphertext, sealed_iv, last_login_at, last_error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id, id) DO UPDATE SET
             label             = excluded.label,
             cpf_masked        = excluded.cpf_masked,
             has_totp          = excluded.has_totp,
             status            = excluded.status,
             sealed_ciphertext = excluded.sealed_ciphertext,
             sealed_iv         = excluded.sealed_iv`,
          [
            row.tenantId,
            row.id,
            row.label,
            row.cpfMasked,
            row.hasTotp ? 1 : 0,
            row.status,
            row.sealed.ciphertext,
            row.sealed.iv,
            row.lastLoginAt ?? null,
            row.lastError ?? null
          ]
        )
      })

      const patchStatus = Effect.fn("D1CredentialStore.patchStatus")(
        function*(tenantId: Tenant, id: CredentialId, status: Status, detail?: string) {
          yield* sql.run(
            `UPDATE credentials
                SET status = ?, last_error = ?
              WHERE tenant_id = ? AND id = ?`,
            [status, detail ?? null, tenantId, id]
          )
        }
      )

      return CredentialStore.of({ find, all, upsert, patchStatus })
    })
  )
}
