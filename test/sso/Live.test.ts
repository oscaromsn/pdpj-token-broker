import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted, Schema } from "effect"
import { KeycloakSso, layerHttp, SsoConfig } from "../../src/adapters/sso/KeycloakSso.ts"
import { OtplibTotp } from "../../src/adapters/sso/OtplibTotp.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { SsoClient } from "../../src/ports/SsoClient.ts"

/**
 * Opt-in test against the real PDPJ SSO.
 *
 * Skipped unless `PJE_ENABLE_LIVE_TESTS=1` and real credentials are present,
 * following PJePA's convention. The gate is not politeness — a live login
 * suite that runs by default would spend a real account's lockout budget on
 * every CI run, and a few failed attempts in a row is what gets an account
 * blocked at the SSO.
 *
 * Only the success path is exercised. There is deliberately no "wrong
 * password" live test: deliberately failing a login against a real account is
 * exactly the behaviour the broker's circuit breaker exists to prevent.
 *
 *   PJE_ENABLE_LIVE_TESTS=1 \
 *   PDPJ_CPF=... PDPJ_PASSWORD=... PDPJ_TOTP_SEED=... \
 *   bunx vitest run test/sso/Live.test.ts
 */

const enabled = process.env["PJE_ENABLE_LIVE_TESTS"] === "1"
const cpf = process.env["PDPJ_CPF"]
const password = process.env["PDPJ_PASSWORD"]
const seed = process.env["PDPJ_TOTP_SEED"]

const configured = enabled &&
  cpf !== undefined &&
  password !== undefined &&
  password.length > 0

const liveLayer = KeycloakSso.layer.pipe(
  Layer.provide(
    Layer.mergeAll(
      layerHttp,
      OtplibTotp.layer,
      Layer.succeed(
        SsoConfig,
        SsoConfig.of({
          realmUrl: "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect",
          clientId: "portalexterno-frontend",
          redirectUri: "https://portaldeservicos.pdpj.jus.br/consulta"
        })
      )
    )
  )
)

describe.skipIf(!configured)("KeycloakSso (live)", () => {
  it.live("mints a real access token from real credentials", () =>
    Effect.gen(function*() {
      const credential = new Credential({
        id: Schema.decodeUnknownSync(CredentialId)("live"),
        tenantId: Schema.decodeUnknownSync(TenantId)("live"),
        cpf: Schema.decodeUnknownSync(Cpf)(cpf ?? ""),
        password: Redacted.make(password ?? ""),
        ...(seed === undefined || seed.length === 0
          ? {}
          : { totpSeed: Schema.decodeUnknownSync(TotpSeed)(seed) })
      })

      const tokens = yield* Effect.gen(function*() {
        const sso = yield* SsoClient
        return yield* sso.login(credential)
      }).pipe(Effect.provide(liveLayer))

      const token = Redacted.value(tokens.accessToken)
      // A Keycloak access token is a JWT: three dot-separated segments.
      assert.strictEqual(token.split(".").length, 3)
      const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
      assert.isTrue(tokens.expiresAt > now)
    }), { timeout: 60_000 })

  it.live("renews through the refresh grant without a second login", () =>
    Effect.gen(function*() {
      const credential = new Credential({
        id: Schema.decodeUnknownSync(CredentialId)("live"),
        tenantId: Schema.decodeUnknownSync(TenantId)("live"),
        cpf: Schema.decodeUnknownSync(Cpf)(cpf ?? ""),
        password: Redacted.make(password ?? ""),
        ...(seed === undefined || seed.length === 0
          ? {}
          : { totpSeed: Schema.decodeUnknownSync(TotpSeed)(seed) })
      })

      const renewed = yield* Effect.gen(function*() {
        const sso = yield* SsoClient
        const first = yield* sso.login(credential)
        assert.isTrue(first.refreshToken !== undefined)
        if (first.refreshToken === undefined) return first
        // This is the property the whole design rests on: renewing must not
        // ask for the second factor again.
        return yield* sso.refresh(first.refreshToken)
      }).pipe(Effect.provide(liveLayer))

      assert.strictEqual(Redacted.value(renewed.accessToken).split(".").length, 3)
    }), { timeout: 60_000 })
})
