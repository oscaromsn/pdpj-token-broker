import { assert, describe, it } from "@effect/vitest"
import { readFileSync } from "node:fs"
import { DatabaseSync } from "node:sqlite"
import { fileURLToPath } from "node:url"
import { Effect, Layer, Option, Schema } from "effect"
import { D1CredentialStore } from "../../src/adapters/store/D1CredentialStore.ts"
import { SqlExecutor } from "../../src/adapters/store/SqlExecutor.ts"
import { Sealed } from "../../src/crypto/Envelope.ts"
import { CredentialId, TenantId } from "../../src/domain/Model.ts"
import { CredentialRow, CredentialStore, StoreUnavailable } from "../../src/ports/CredentialStore.ts"

/**
 * Exercised against real SQLite — the same engine D1 runs — so the schema,
 * the SQL and the row mapping are genuinely verified rather than mocked. Only
 * the few lines translating `SqlExecutor` onto Cloudflare's `PreparedStatement`
 * remain unproven until a deploy.
 */

const MIGRATION = readFileSync(
  fileURLToPath(new URL("../../migrations/0001_init.sql", import.meta.url)),
  "utf8"
)

const tenantA = Schema.decodeUnknownSync(TenantId)("tenant-a")
const tenantB = Schema.decodeUnknownSync(TenantId)("tenant-b")
const credId = Schema.decodeUnknownSync(CredentialId)("cred-1")

/** A SqlExecutor backed by an in-memory SQLite database. */
const sqliteExecutor = Effect.sync(() => {
  const db = new DatabaseSync(":memory:")
  db.exec(MIGRATION)

  const layer = Layer.succeed(
    SqlExecutor,
    SqlExecutor.of({
      all: <T>(sql: string, params: ReadonlyArray<unknown>) =>
        Effect.try({
          // SAFETY: node:sqlite returns untyped column records; the adapter
          // decodes them through a Schema immediately, which is where any
          // mismatch is actually caught.
          try: () =>
            db.prepare(sql).all(...(params as ReadonlyArray<never>)) as ReadonlyArray<unknown> as ReadonlyArray<T>,
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

  return { db, layer } as const
})

const harness = Effect.gen(function*() {
  const sqlite = yield* sqliteExecutor
  return {
    db: sqlite.db,
    layer: D1CredentialStore.layer.pipe(Layer.provide(sqlite.layer))
  } as const
})

const rowFor = (tenantId: TenantId, id: CredentialId, label: string) =>
  new CredentialRow({
    tenantId,
    id,
    label,
    cpfMasked: "529******25",
    hasTotp: true,
    status: "validating",
    sealed: new Sealed({ ciphertext: "Y2lwaGVy", iv: "aXZpdml2aXY=" })
  })

describe("D1CredentialStore", () => {
  it.effect("round-trips a row through the real schema", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const found = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "Dr. Silva"))
        return yield* store.find(tenantA, credId)
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(Option.isSome(found))
      if (Option.isNone(found)) return
      assert.strictEqual(found.value.label, "Dr. Silva")
      assert.strictEqual(found.value.cpfMasked, "529******25")
      // SQLite stores booleans as integers; the mapping must restore them.
      assert.strictEqual(found.value.hasTotp, true)
      assert.strictEqual(found.value.sealed.ciphertext, "Y2lwaGVy")
      assert.strictEqual(found.value.lastLoginAt, undefined)
    }))

  it.effect("does not find another tenant's row", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const found = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "Dr. Silva"))
        return yield* store.find(tenantB, credId)
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(Option.isNone(found))
    }))

  it.effect("lets two tenants hold the same credential id", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const { a, b } = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "A's"))
        // The composite primary key must not treat this as a duplicate.
        yield* store.upsert(rowFor(tenantB, credId, "B's"))
        return { a: yield* store.find(tenantA, credId), b: yield* store.find(tenantB, credId) }
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(Option.isSome(a) && Option.isSome(b))
      if (Option.isNone(a) || Option.isNone(b)) return
      assert.strictEqual(a.value.label, "A's")
      assert.strictEqual(b.value.label, "B's")
    }))

  it.effect("updates in place on conflict rather than failing", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const found = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "Old label"))
        yield* store.upsert(
          new CredentialRow({
            ...rowFor(tenantA, credId, "New label"),
            sealed: new Sealed({ ciphertext: "bmV3", iv: "bmV3aXY=" })
          })
        )
        return yield* store.find(tenantA, credId)
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(Option.isSome(found))
      if (Option.isNone(found)) return
      assert.strictEqual(found.value.label, "New label")
      // Re-enrolling must actually replace the ciphertext, not keep the old.
      assert.strictEqual(found.value.sealed.ciphertext, "bmV3")
    }))

  it.effect("lists only the requested tenant's rows", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const listed = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "A one"))
        yield* store.upsert(
          rowFor(tenantA, Schema.decodeUnknownSync(CredentialId)("cred-2"), "A two")
        )
        yield* store.upsert(rowFor(tenantB, credId, "B one"))
        return yield* store.all(tenantA)
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(listed.length, 2)
      assert.deepStrictEqual(listed.map((r) => r.label), ["A one", "A two"])
    }))

  it.effect("records a status change and its detail", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const found = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "Dr. Silva"))
        yield* store.patchStatus(tenantA, credId, "error", "Usuário ou senha inválido")
        return yield* store.find(tenantA, credId)
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(Option.isSome(found))
      if (Option.isNone(found)) return
      assert.strictEqual(found.value.status, "error")
      assert.strictEqual(found.value.lastError, "Usuário ou senha inválido")
    }))

  it.effect("never lets a tenant id reach the query as text", () =>
    Effect.gen(function*() {
      const h = yield* harness
      const injected = Schema.decodeUnknownSync(TenantId)("' OR '1'='1")

      const found = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        yield* store.upsert(rowFor(tenantA, credId, "Dr. Silva"))
        // If the tenant were concatenated rather than bound, this would
        // match every row and quietly break tenant isolation.
        return yield* store.all(injected)
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(found.length, 0)
    }))

  it.effect("reports a corrupted row as unavailable instead of decoding garbage", () =>
    Effect.gen(function*() {
      const h = yield* harness
      // Write a row whose status is not a value the domain recognizes.
      h.db
        .prepare(
          `INSERT INTO credentials
             (tenant_id, id, label, cpf_masked, has_totp, status,
              sealed_ciphertext, sealed_iv)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run("tenant-a", "bad", "Bad row", "529******25", 1, "not-a-status", "Y2lwaGVy", "aXY=")

      const result = yield* Effect.gen(function*() {
        const store = yield* CredentialStore
        return yield* Effect.result(store.all(tenantA))
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "StoreUnavailable")
    }))
})
