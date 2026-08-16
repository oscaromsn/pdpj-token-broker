import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Ref, Schema } from "effect"
import { TokenBroker } from "../../src/broker/TokenBroker.ts"
import { DerivedKeyRing, Kek } from "../../src/adapters/vault/DerivedKeyRing.ts"
import { EncryptedVault } from "../../src/adapters/vault/EncryptedVault.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { SsoUnavailable } from "../../src/domain/Errors.ts"
import { Credential } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import type { CredentialStore } from "../../src/ports/CredentialStore.ts"
import { CredentialVault } from "../../src/ports/CredentialVault.ts"
import {
  credentialId,
  makeAuditFake,
  makeBrowserFake,
  makeCacheFake,
  makeSsoFake,
  makeStoreFake,
  tenant,
  testKek,
  tokenSet,
  TotpFake
} from "../fakes/Fakes.ts"

/**
 * The hexagon's payoff, demonstrated rather than asserted in prose: the same
 * `TokenBroker` from the unit tests runs here over the *real* encrypted vault
 * — real AES-GCM, real HKDF key derivation — with no change to the broker.
 * Only the layer wiring differs.
 *
 * The SSO stays a fake, deliberately. Reaching a live Keycloak from a unit
 * suite would make these tests slow, flaky, and — for the failure paths —
 * actively harmful to a real account.
 */

const FAR_FUTURE = 9_999_999_999_999
const PASSWORD = "correct-horse-battery-staple"
const SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

/** Real vault (AES-GCM + HKDF) behind the CredentialVault port. */
const encryptedVaultLayer = (store: Layer.Layer<CredentialStore>) =>
  EncryptedVault.layer.pipe(
    Layer.provide(
      Layer.mergeAll(
        store,
        DerivedKeyRing.layer.pipe(Layer.provide(Layer.succeed(Kek, Redacted.make(testKek))))
      )
    )
  )

describe("broker over the encrypted vault", () => {
  it.effect("issues a token for a credential that only exists as ciphertext", () =>
    Effect.gen(function*() {
      const store = yield* makeStoreFake
      const cache = yield* makeCacheFake
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )

      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "minted", expiresAt: FAR_FUTURE }))
      })

      const vaultLayer = encryptedVaultLayer(store.layer)

      const infra = Layer.mergeAll(
        vaultLayer,
        cache.layer,
        sso.layer,
        browser.layer,
        TotpFake,
        audit.layer
      )

      const token = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        yield* vault.put(
          new Credential({
            id: credentialId,
            tenantId: tenant,
            cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
            password: Redacted.make(PASSWORD),
            totpSeed: Schema.decodeUnknownSync(TotpSeed)(SEED)
          }),
          "Dr. Silva — TRF5"
        )

        const broker = yield* TokenBroker
        return yield* broker.issue(tenant, credentialId)
      }).pipe(
        Effect.provide(TokenBroker.layer.pipe(Layer.provide(infra))),
        Effect.provide(infra)
      )

      assert.strictEqual(Redacted.value(token.accessToken), "minted")

      // Nothing readable ever reached storage, even though a login succeeded.
      const atRest = JSON.stringify(yield* Ref.get(store.rows))
      assert.isFalse(atRest.includes(PASSWORD))
      assert.isFalse(atRest.includes(SEED))
    }))

  it.effect("marks the stored credential active once a login proves it works", () =>
    Effect.gen(function*() {
      const store = yield* makeStoreFake
      const cache = yield* makeCacheFake
      const audit = yield* makeAuditFake
      const browser = yield* makeBrowserFake(() =>
        Effect.fail(new SsoUnavailable({ detail: "unused" }))
      )
      const sso = yield* makeSsoFake({
        onLogin: () => Effect.succeed(tokenSet({ access: "minted", expiresAt: FAR_FUTURE }))
      })

      const vaultLayer = encryptedVaultLayer(store.layer)
      const infra = Layer.mergeAll(
        vaultLayer,
        cache.layer,
        sso.layer,
        browser.layer,
        TotpFake,
        audit.layer
      )

      const { before, after } = yield* Effect.gen(function*() {
        const vault = yield* CredentialVault
        yield* vault.put(
          new Credential({
            id: credentialId,
            tenantId: tenant,
            cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
            password: Redacted.make(PASSWORD)
          }),
          "Dr. Silva"
        )
        const [before] = yield* vault.list(tenant)

        const broker = yield* TokenBroker
        yield* broker.issue(tenant, credentialId)

        const [after] = yield* vault.list(tenant)
        return { before, after }
      }).pipe(
        Effect.provide(TokenBroker.layer.pipe(Layer.provide(infra))),
        Effect.provide(infra)
      )

      // A credential is never trusted on write, only after a real login.
      assert.strictEqual(before?.status, "validating")
      assert.strictEqual(after?.status, "active")
    }))
})
