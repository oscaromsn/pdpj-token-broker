import { assert, describe, it } from "@effect/vitest"
import { readFileSync } from "node:fs"
import { DatabaseSync } from "node:sqlite"
import { fileURLToPath } from "node:url"
import { Effect, Layer, Option, Redacted, Schema } from "effect"
import * as ApiKeys from "../../src/admin/ApiKeys.ts"
import { D1TenantAuth } from "../../src/adapters/store/D1TenantAuth.ts"
import { SqlExecutor } from "../../src/adapters/store/SqlExecutor.ts"
import { TenantId } from "../../src/domain/Model.ts"
import { StoreUnavailable } from "../../src/ports/CredentialStore.ts"
import { TenantAuth } from "../../src/ports/TenantAuth.ts"

/**
 * The whole point of these tests is the round trip: a key minted by the
 * operator tool must authenticate through the *production* code path. Minting
 * and resolving live in different modules and are invoked months apart, so a
 * drift between them would surface as "the key I just made doesn't work" with
 * nothing obviously broken in either half.
 */

const MIGRATION = readFileSync(
  fileURLToPath(new URL("../../migrations/0001_init.sql", import.meta.url)),
  "utf8"
)

const tenantA = Schema.decodeUnknownSync(TenantId)("tenant-a")
const tenantB = Schema.decodeUnknownSync(TenantId)("tenant-b")

const harness = Effect.sync(() => {
  const db = new DatabaseSync(":memory:")
  db.exec(MIGRATION)

  const sqlLayer = Layer.succeed(
    SqlExecutor,
    SqlExecutor.of({
      all: <T>(sql: string, params: ReadonlyArray<unknown>) =>
        Effect.try({
          // SAFETY: node:sqlite returns untyped column records; every caller
          // decodes them through a Schema before use.
          try: () =>
            db.prepare(sql).all(...(params as ReadonlyArray<never>)) as ReadonlyArray<
              unknown
            > as ReadonlyArray<T>,
          catch: (cause) => new StoreUnavailable({ detail: "sqlite query failed", cause })
        }),
      run: (sql: string, params: ReadonlyArray<unknown>) =>
        Effect.try({
          try: () => {
            db.prepare(sql).run(...(params as ReadonlyArray<never>))
          },
          catch: (cause) => new StoreUnavailable({ detail: "sqlite statement failed", cause })
        })
    })
  )

  return {
    db,
    sqlLayer,
    authLayer: D1TenantAuth.layer.pipe(Layer.provide(sqlLayer))
  } as const
})

describe("ApiKeys", () => {
  it.effect("mints a key that authenticates through the real auth path", () =>
    Effect.gen(function*() {
      const h = yield* harness

      const minted = yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))

      const resolved = yield* Effect.gen(function*() {
        const auth = yield* TenantAuth
        return yield* auth.resolve(minted.key)
      }).pipe(Effect.provide(h.authLayer))

      // The property that matters: mint and resolve agree.
      assert.isTrue(Option.isSome(resolved))
      if (Option.isNone(resolved)) return
      assert.strictEqual(resolved.value, tenantA)
    }))

  it.effect("never writes the plaintext key to the database", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const minted = yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))
      const plaintext = Redacted.value(minted.key)

      const rows = h.db.prepare("SELECT * FROM api_keys").all()
      const atRest = JSON.stringify(rows)

      // A database dump must yield nothing usable.
      assert.isFalse(atRest.includes(plaintext))
      assert.isTrue(atRest.includes(minted.keyHash))
    }))

  it.effect("issues a distinct key every time", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const a = yield* ApiKeys.mint(tenantA, "one").pipe(Effect.provide(h.sqlLayer))
      const b = yield* ApiKeys.mint(tenantA, "two").pipe(Effect.provide(h.sqlLayer))

      assert.notStrictEqual(Redacted.value(a.key), Redacted.value(b.key))
      assert.notStrictEqual(a.keyHash, b.keyHash)
    }))

  it.effect("produces a recognizable, high-entropy key", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const minted = yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))
      const plaintext = Redacted.value(minted.key)

      assert.isTrue(plaintext.startsWith("pdpj_"))
      // 32 bytes base64url ≈ 43 chars, plus the prefix.
      assert.isTrue(plaintext.length >= 45, `too short: ${plaintext.length}`)
      assert.match(plaintext, /^pdpj_[A-Za-z0-9_-]+$/)
    }))

  it.effect("stops honouring a revoked key", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const minted = yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))

      const before = yield* Effect.gen(function*() {
        const auth = yield* TenantAuth
        return yield* auth.resolve(minted.key)
      }).pipe(Effect.provide(h.authLayer))
      assert.isTrue(Option.isSome(before))

      yield* ApiKeys.revoke(minted.keyHash).pipe(Effect.provide(h.sqlLayer))

      const after = yield* Effect.gen(function*() {
        const auth = yield* TenantAuth
        return yield* auth.resolve(minted.key)
      }).pipe(Effect.provide(h.authLayer))

      assert.isTrue(Option.isNone(after))
    }))

  it.effect("keeps a revoked key's row, so the audit trail still resolves", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const minted = yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))
      yield* ApiKeys.revoke(minted.keyHash).pipe(Effect.provide(h.sqlLayer))

      const listed = yield* ApiKeys.list().pipe(Effect.provide(h.sqlLayer))
      assert.strictEqual(listed.length, 1)
      assert.isTrue(
        listed[0]?.revokedAt !== undefined && listed[0]?.revokedAt !== null,
        "revocation must be recorded, not erased"
      )
    }))

  it.effect("rejects a key that was never issued", () =>
    Effect.gen(function*() {
      const h = yield* harness
      yield* ApiKeys.mint(tenantA, "CI").pipe(Effect.provide(h.sqlLayer))

      const resolved = yield* Effect.gen(function*() {
        const auth = yield* TenantAuth
        return yield* auth.resolve(Redacted.make("pdpj_not-a-real-key"))
      }).pipe(Effect.provide(h.authLayer))

      assert.isTrue(Option.isNone(resolved))
    }))

  it.effect("resolves each key to its own tenant", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const a = yield* ApiKeys.mint(tenantA, "A").pipe(Effect.provide(h.sqlLayer))
      const b = yield* ApiKeys.mint(tenantB, "B").pipe(Effect.provide(h.sqlLayer))

      const resolve = (key: typeof a.key) =>
        Effect.gen(function*() {
          const auth = yield* TenantAuth
          return yield* auth.resolve(key)
        }).pipe(Effect.provide(h.authLayer))

      assert.deepStrictEqual(yield* resolve(a.key), Option.some(tenantA))
      assert.deepStrictEqual(yield* resolve(b.key), Option.some(tenantB))
    }))

  it.effect("lists only the requested tenant's keys", () =>
    Effect.gen(function*() {
      const h = yield* harness
      yield* ApiKeys.mint(tenantA, "A one").pipe(Effect.provide(h.sqlLayer))
      yield* ApiKeys.mint(tenantA, "A two").pipe(Effect.provide(h.sqlLayer))
      yield* ApiKeys.mint(tenantB, "B one").pipe(Effect.provide(h.sqlLayer))

      const listed = yield* ApiKeys.list(tenantA).pipe(Effect.provide(h.sqlLayer))
      assert.strictEqual(listed.length, 2)
      assert.deepStrictEqual(listed.map((k) => k.label), ["A one", "A two"])
    }))
})
