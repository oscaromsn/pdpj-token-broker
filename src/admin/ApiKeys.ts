import { Effect, Redacted, Schema } from "effect"
import { hashApiKey } from "../adapters/store/hashApiKey.ts"
import type { TenantId } from "../domain/Model.ts"
import { SqlExecutor } from "../adapters/store/SqlExecutor.ts"
import type { StoreUnavailable } from "../ports/CredentialStore.ts"

/**
 * Provisioning for tenant API keys.
 *
 * Deliberately *not* an HTTP endpoint. An endpoint that mints credentials for
 * arbitrary tenants is the most dangerous surface a multi-tenant service can
 * expose, and it would need its own bootstrap credential to protect — the same
 * chicken-and-egg one rung up. Running it as an operator tool against the
 * database keeps that surface off the network entirely.
 */

/**
 * A recognizable prefix.
 *
 * Costs nothing and buys two things: a human can tell at a glance what a
 * leaked string is, and secret scanners can be taught the pattern.
 */
const PREFIX = "pdpj_"

/** 32 bytes of CSPRNG output — the entropy this whole scheme rests on. */
const KEY_BYTES = 32

const toBase64Url = Schema.encodeSync(Schema.Uint8ArrayFromBase64Url)

/**
 * The plaintext key, returned exactly once.
 *
 * `Redacted` so it cannot be logged on its way to being displayed; the caller
 * unwraps it deliberately at the point of printing.
 */
export class MintedKey extends Schema.Class<MintedKey>("broker/admin/MintedKey")({
  key: Schema.RedactedFromValue(Schema.String, { disallowEncode: true }),
  keyHash: Schema.String,
  tenantId: Schema.String,
  label: Schema.String
}) {}

export class ApiKeySummary extends Schema.Class<ApiKeySummary>("broker/admin/ApiKeySummary")({
  keyHash: Schema.String,
  tenantId: Schema.String,
  label: Schema.String,
  revokedAt: Schema.optional(Schema.NullOr(Schema.Number))
}) {}

const KeyRow = Schema.Struct({
  key_hash: Schema.String,
  tenant_id: Schema.String,
  label: Schema.String,
  revoked_at: Schema.optional(Schema.NullOr(Schema.Number))
})

const decodeRows = Schema.decodeUnknownEffect(Schema.Array(KeyRow))

/**
 * Generate a key, store only its hash, and hand back the plaintext once.
 *
 * The plaintext is never written anywhere: not to the row, not to a log. If
 * the operator loses it, the remedy is to mint another and revoke this one —
 * which is the property that makes a database dump worthless.
 */
export const mint = Effect.fn("ApiKeys.mint")(function*(
  tenantId: TenantId,
  label: string
) {
  const bytes = crypto.getRandomValues(new Uint8Array(KEY_BYTES))
  const key = `${PREFIX}${toBase64Url(bytes)}`
  const keyHash = yield* hashApiKey(key)

  const sql = yield* SqlExecutor
  yield* sql.run(
    `INSERT INTO api_keys (key_hash, tenant_id, label, revoked_at)
     VALUES (?, ?, ?, NULL)`,
    [keyHash, tenantId, label]
  )

  return new MintedKey({
    key: Redacted.make(key),
    keyHash,
    tenantId,
    label
  })
})

/**
 * Revoke by hash rather than by plaintext.
 *
 * An operator revoking a key usually does not have it — that is often *why*
 * they are revoking it. The hash is visible in `list`, so it is the handle
 * that is actually available.
 *
 * A soft revoke, not a delete: the row stays so the audit trail keeps pointing
 * at something real.
 */
export const revoke = Effect.fn("ApiKeys.revoke")(function*(keyHash: string) {
  const sql = yield* SqlExecutor
  const at = yield* Effect.clockWith((clock) => clock.currentTimeMillis)
  yield* sql.run(
    `UPDATE api_keys SET revoked_at = ? WHERE key_hash = ? AND revoked_at IS NULL`,
    [at, keyHash]
  )
})

/** Hashes and metadata only — there is no plaintext to list. */
export const list = Effect.fn("ApiKeys.list")(function*(
  tenantId?: TenantId
): Effect.fn.Return<ReadonlyArray<ApiKeySummary>, StoreUnavailable, SqlExecutor> {
  const sql = yield* SqlExecutor
  const rows = yield* (tenantId === undefined
    ? sql.all(`SELECT key_hash, tenant_id, label, revoked_at FROM api_keys ORDER BY tenant_id, label`, [])
    : sql.all(
      `SELECT key_hash, tenant_id, label, revoked_at FROM api_keys WHERE tenant_id = ? ORDER BY label`,
      [tenantId]
    ))

  const decoded = yield* decodeRows(rows).pipe(Effect.orDie)
  return decoded.map((row) =>
    new ApiKeySummary({
      keyHash: row.key_hash,
      tenantId: row.tenant_id,
      label: row.label,
      ...(row.revoked_at === undefined ? {} : { revokedAt: row.revoked_at })
    })
  )
})
