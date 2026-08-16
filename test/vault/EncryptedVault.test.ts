import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Ref, Schema } from "effect"
import { EncryptedVault } from "../../src/adapters/vault/EncryptedVault.ts"
import { Envelope } from "../../src/crypto/Envelope.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { CredentialRow } from "../../src/ports/CredentialStore.ts"
import { CredentialVault } from "../../src/ports/CredentialVault.ts"
import { KeyRing } from "../../src/ports/KeyRing.ts"
import { makeStoreFake } from "../fakes/Fakes.ts"

/**
 * The vault is where a breach would happen, so these tests assert the
 * properties that make a breach survivable: what sits on disk is opaque, one
 * tenant cannot read another's rows, and listing credentials cannot leak
 * secrets because it never unseals anything.
 */

const PASSWORD = "correct-horse-battery-staple"
const SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
const CPF_DIGITS = "52998224725"

const tenantA = Schema.decodeUnknownSync(TenantId)("tenant-a")
const tenantB = Schema.decodeUnknownSync(TenantId)("tenant-b")
const credId = Schema.decodeUnknownSync(CredentialId)("cred-1")

const credentialFor = (tenantId: TenantId) =>
  new Credential({
    id: credId,
    tenantId,
    cpf: Schema.decodeUnknownSync(Cpf)(CPF_DIGITS),
    password: Redacted.make(PASSWORD),
    totpSeed: Schema.decodeUnknownSync(TotpSeed)(SEED)
  })

/** One real AES key shared by both tenants unless a test says otherwise. */
const makeKeyRingFake = (perTenant: boolean) =>
  Effect.gen(function*() {
    const cache = yield* Ref.make(new Map<string, CryptoKey>())
    const layer = Layer.succeed(
      KeyRing,
      KeyRing.of({
        dekFor: (tenantId) =>
          Effect.gen(function*() {
            const slot = perTenant ? tenantId : "shared"
            const existing = (yield* Ref.get(cache)).get(slot)
            if (existing !== undefined) return existing
            const key = yield* Envelope.generateKey.pipe(Effect.orDie)
            yield* Ref.update(cache, (m) => new Map(m).set(slot, key))
            return key
          })
      })
    )
    return { layer } as const
  })

const harness = (opts?: { readonly perTenantKeys?: boolean }) =>
  Effect.gen(function*() {
    const store = yield* makeStoreFake
    const keyring = yield* makeKeyRingFake(opts?.perTenantKeys ?? false)
    const layer = EncryptedVault.layer.pipe(
      Layer.provide(Layer.mergeAll(store.layer, keyring.layer))
    )
    return { store, layer } as const
  })

describe("EncryptedVault", () => {
  it.effect("round-trips a credential through put and get", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const got = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(credentialFor(tenantA), "Dr. Silva — TRF5")
        return yield* vault.get(tenantA, id)
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(got.cpf, CPF_DIGITS)
      assert.strictEqual(Redacted.value(got.password), PASSWORD)
      assert.isTrue(got.totpSeed !== undefined)
      if (got.totpSeed !== undefined) {
        assert.strictEqual(Redacted.value(got.totpSeed), SEED)
      }
    }))

  it.effect("writes nothing readable to storage", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        yield* vault.put(credentialFor(tenantA), "Dr. Silva")
      }).pipe(Effect.provide(h.layer))

      // Serialize the whole row exactly as it would be persisted, then look
      // for any of the secrets. This is the assertion that a database dump is
      // worthless on its own.
      const atRest = JSON.stringify(yield* Ref.get(h.store.rows))
      assert.isFalse(atRest.includes(PASSWORD))
      assert.isFalse(atRest.includes(SEED))
      assert.isFalse(atRest.includes(CPF_DIGITS))
      // The masked form is present, because operators need to recognize it.
      assert.isTrue(atRest.includes("529******25"))
    }))

  it.effect("refuses to read another tenant's credential", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const result = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(credentialFor(tenantA), "Dr. Silva")
        // Same credential id, wrong tenant.
        return yield* Effect.result(vault.get(tenantB, id))
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.strictEqual(result.failure._tag, "CredentialNotFound")
      }
    }))

  it.effect("reports tampered ciphertext as corruption, not as a wrong password", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const result = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(credentialFor(tenantA), "Dr. Silva")

        // Simulate storage corruption or a malicious edit.
        yield* Ref.update(h.store.rows, (all) =>
          all.map((r) =>
            new CredentialRow({
              ...r,
              sealed: { ...r.sealed, ciphertext: r.sealed.ciphertext.replace(/^./, "Z") }
            })
          ))

        return yield* Effect.result(vault.get(tenantA, id))
      }).pipe(Effect.provide(h.layer))

      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.strictEqual(result.failure._tag, "VaultCorrupt")
      }
    }))

  it.effect("cannot decrypt across tenants when keys are per tenant", () =>
    Effect.gen(function*() {
      const h = yield* harness({ perTenantKeys: true })
      const result = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(credentialFor(tenantA), "Dr. Silva")

        // Move the row to tenant B, as a stolen-row scenario would.
        yield* Ref.update(h.store.rows, (all) =>
          all.map((r) => new CredentialRow({ ...r, tenantId: tenantB })))

        return yield* Effect.result(vault.get(tenantB, id))
      }).pipe(Effect.provide(h.layer))

      // B's key cannot open A's ciphertext: the blast radius of one key is
      // one tenant.
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.strictEqual(result.failure._tag, "VaultCorrupt")
      }
    }))

  it.effect("lists credentials as views that structurally cannot carry secrets", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const views = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        yield* vault.put(credentialFor(tenantA), "Dr. Silva — TRF5")
        return yield* vault.list(tenantA)
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(views.length, 1)
      const [view] = views
      assert.isTrue(view !== undefined)
      if (view === undefined) return
      assert.strictEqual(view.cpfMasked, "529******25")
      assert.isTrue(view.hasTotp)
      assert.strictEqual(view.label, "Dr. Silva — TRF5")
      assert.isFalse(JSON.stringify(view).includes(PASSWORD))
      assert.isFalse(JSON.stringify(view).includes(SEED))
    }))

  it.effect("lists without ever unsealing, so listing cannot leak", () =>
    Effect.gen(function*() {
      const store = yield* makeStoreFake
      const keys = yield* Ref.make(0)
      // A KeyRing that fails outright. If `list` needed a key it would error;
      // succeeding proves the read path never touches key material.
      const brokenKeyRing = Layer.succeed(
        KeyRing,
        KeyRing.of({
          dekFor: () => Ref.update(keys, (n) => n + 1).pipe(Effect.andThen(Effect.die("list must not need a key")))
        })
      )

      const seeded = yield* harness()
      const id = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        return yield* vault.put(credentialFor(tenantA), "Dr. Silva")
      }).pipe(Effect.provide(seeded.layer))

      // Move the sealed row into a store whose KeyRing is unusable.
      yield* Ref.set(store.rows, yield* Ref.get(seeded.store.rows))

      const views = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        return yield* vault.list(tenantA)
      }).pipe(
        Effect.provide(
          EncryptedVault.layer.pipe(Layer.provide(Layer.mergeAll(store.layer, brokenKeyRing)))
        )
      )

      assert.strictEqual(views.length, 1)
      assert.strictEqual(views[0]?.id, id)
      assert.strictEqual(yield* Ref.get(keys), 0)
    }))

  it.effect("stores a credential without a second factor", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const { got, view } = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(
          new Credential({
            id: credId,
            tenantId: tenantA,
            cpf: Schema.decodeUnknownSync(Cpf)(CPF_DIGITS),
            password: Redacted.make(PASSWORD)
          }),
          "No 2FA"
        )
        const got = yield* vault.get(tenantA, id)
        const [view] = yield* vault.list(tenantA)
        return { got, view }
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(got.totpSeed, undefined)
      assert.strictEqual(view?.hasTotp, false)
    }))

  it.effect("records a status transition so credential rot is visible", () =>
    Effect.gen(function*() {
      const h = yield* harness()
      const view = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        const id = yield* vault.put(credentialFor(tenantA), "Dr. Silva")
        yield* vault.setStatus(tenantA, id, "error", "Usuário ou senha inválido")
        const [view] = yield* vault.list(tenantA)
        return view
      }).pipe(Effect.provide(h.layer))

      assert.strictEqual(view?.status, "error")
      assert.strictEqual(view?.lastError, "Usuário ou senha inválido")
    }))
})
