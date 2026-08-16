import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Ref, Schema } from "effect"
import { HttpRouter, HttpServer } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { DerivedKeyRing, Kek } from "../../src/adapters/vault/DerivedKeyRing.ts"
import { EncryptedVault } from "../../src/adapters/vault/EncryptedVault.ts"
import { BrokerApi } from "../../src/api/Credentials.ts"
import { TokenBroker } from "../../src/broker/TokenBroker.ts"
import { SsoUnavailable } from "../../src/domain/Errors.ts"
import { TenantId, type TokenSet } from "../../src/domain/Model.ts"
import { TenantAuth } from "../../src/ports/TenantAuth.ts"
import {
  AuthorizationLayer,
  CredentialsHandlersNoDeps,
  SystemHandlers
} from "../../src/server/Handlers.ts"
import {
  makeAuditFake,
  makeBrowserFake,
  makeCacheFake,
  makeSsoFake,
  makeStoreFake,
  testKek,
  tokenSet
} from "../fakes/Fakes.ts"

/**
 * The API is exercised through a real web handler — actual `Request`s in,
 * actual `Response`s out — rather than by calling handlers directly. Status
 * codes, payload decoding and the auth middleware are the parts most likely
 * to be wrong, and none of them exist below the handler boundary.
 */

const FAR_FUTURE = 9_999_999_999_999
const KEY = "tenant-a-key"
const tenantA = Schema.decodeUnknownSync(TenantId)("tenant-a")

const enrollBody = {
  label: "Dr. Silva — TRF5",
  cpf: "529.982.247-25",
  password: "correct-horse-battery-staple",
  totpSeed: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
}

/** One API key maps to one tenant; anything else is unknown. */
const TenantAuthFake = Layer.succeed(
  TenantAuth,
  TenantAuth.of({
    resolve: (apiKey) =>
      Effect.succeed(
        Redacted.value(apiKey) === KEY ? Option.some(tenantA) : Option.none()
      )
  })
)

const makeHandler = (opts?: {
  readonly onLogin?: ((attempt: number) => Effect.Effect<TokenSet, SsoUnavailable>) | undefined
}) =>
  Effect.gen(function*() {
    const store = yield* makeStoreFake
    const cache = yield* makeCacheFake
    const audit = yield* makeAuditFake
    const browser = yield* makeBrowserFake(() =>
      Effect.fail(new SsoUnavailable({ detail: "unused" }))
    )
    const sso = yield* makeSsoFake({
      onLogin: opts?.onLogin ??
        (() => Effect.succeed(tokenSet({ access: "minted-token", expiresAt: FAR_FUTURE })))
    })

    const vault = EncryptedVault.layer.pipe(
      Layer.provide(
        Layer.mergeAll(
          store.layer,
          DerivedKeyRing.layer.pipe(Layer.provide(Layer.succeed(Kek, Redacted.make(testKek))))
        )
      )
    )

    const infra = Layer.mergeAll(vault, cache.layer, sso.layer, browser.layer, audit.layer)
    const brokerLayer = TokenBroker.layer.pipe(Layer.provide(infra))

    const routes = HttpApiBuilder.layer(BrokerApi).pipe(
      Layer.provide(
        CredentialsHandlersNoDeps.pipe(
          Layer.provide(
            Layer.mergeAll(
              infra,
              brokerLayer,
              // TenantAuth must be provided *into* the middleware. Merging it
              // alongside leaves the requirement unsatisfied, which shows up
              // as `toWebHandler` demanding a context argument.
              AuthorizationLayer.pipe(Layer.provide(TenantAuthFake))
            )
          )
        )
      ),
      Layer.provide(SystemHandlers)
    )

    const { handler } = HttpRouter.toWebHandler(
      routes.pipe(Layer.provide(HttpServer.layerServices))
    )

    return { handler, store } as const
  })

const authed = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: {
    authorization: `Bearer ${KEY}`,
    ...(body === undefined ? {} : { "content-type": "application/json" })
  },
  ...(body === undefined ? {} : { body: JSON.stringify(body) })
})

describe("BrokerApi", () => {
  it.effect("reports health without a key", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(new Request("http://broker/health"))
      )
      assert.strictEqual(response.status, 200)
    }))

  it.effect("rejects a request with no API key", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials"))
      )
      assert.strictEqual(response.status, 401)
    }))

  it.effect("rejects an unknown API key", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(
          new Request("http://broker/credentials", {
            headers: { authorization: "Bearer not-a-real-key" }
          })
        )
      )
      assert.strictEqual(response.status, 401)
    }))

  it.effect("enrolls a credential and returns a view carrying no secrets", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials", authed(enrollBody)))
      )

      assert.strictEqual(response.status, 200)
      const text = yield* Effect.promise(() => response.text())

      assert.isFalse(text.includes(enrollBody.password))
      assert.isFalse(text.includes(enrollBody.totpSeed))
      // The full CPF must not come back either — only the masked form.
      assert.isFalse(text.includes("52998224725"))
      assert.include(text, "529******25")
      assert.include(text, "\"hasTotp\":true")
      // Nothing has proven this credential yet, so it must not read as active.
      assert.include(text, "\"status\":\"validating\"")
    }))

  it.effect("rejects an invalid CPF at the edge, before anything is stored", () =>
    Effect.gen(function*() {
      const { handler, store } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(
          new Request(
            "http://broker/credentials",
            authed({ ...enrollBody, cpf: "11111111111" })
          )
        )
      )

      assert.strictEqual(response.status, 400)
      assert.strictEqual((yield* Ref.get(store.rows)).length, 0)
    }))

  it.effect("rejects a TOTP seed below the usable floor", () =>
    Effect.gen(function*() {
      const { handler, store } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(
          new Request(
            "http://broker/credentials",
            authed({ ...enrollBody, totpSeed: "JBSWY3DPEHPK3PXP" })
          )
        )
      )

      assert.strictEqual(response.status, 400)
      assert.strictEqual((yield* Ref.get(store.rows)).length, 0)
    }))

  it.effect("issues a token and withholds the refresh token", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()

      const enrolled = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials", authed(enrollBody)))
      )
      const view = yield* Effect.promise(() => enrolled.json())
      const id = (view as { id: string }).id

      const response = yield* Effect.promise(() =>
        handler(new Request(`http://broker/credentials/${id}/token`, authed()))
      )

      assert.strictEqual(response.status, 200)
      const body = yield* Effect.promise(() => response.json())
      const issued = body as { accessToken: string; expiresAt: number }

      assert.strictEqual(issued.accessToken, "minted-token")
      assert.strictEqual(issued.expiresAt, FAR_FUTURE)
      // A refresh token would turn a leaked response into long-lived access.
      assert.isFalse(Object.hasOwn(issued, "refreshToken"))
    }))

  it.effect("returns 404 for a credential that does not exist", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      const response = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials/no-such-id/token", authed()))
      )
      assert.strictEqual(response.status, 404)
    }))

  it.effect("surfaces an upstream SSO failure as 502, not 500", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler({
        onLogin: () => Effect.fail(new SsoUnavailable({ detail: "keycloak down" }))
      })

      const enrolled = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials", authed(enrollBody)))
      )
      const id = ((yield* Effect.promise(() => enrolled.json())) as { id: string }).id

      const response = yield* Effect.promise(() =>
        handler(new Request(`http://broker/credentials/${id}/token`, authed()))
      )

      // The failure is upstream; 500 would wrongly blame this service.
      assert.strictEqual(response.status, 502)
    }))

  it.effect("returns 429 once the breaker opens", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler({
        onLogin: () => Effect.fail(new SsoUnavailable({ detail: "keycloak down" }))
      })

      const enrolled = yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials", authed(enrollBody)))
      )
      const id = ((yield* Effect.promise(() => enrolled.json())) as { id: string }).id

      const statuses: Array<number> = []
      for (let attempt = 0; attempt < 5; attempt++) {
        const response = yield* Effect.promise(() =>
          handler(new Request(`http://broker/credentials/${id}/token`, authed()))
        )
        statuses.push(response.status)
      }

      // The transition itself is the assertion: upstream failures surface as
      // 502 until the breaker trips, and every attempt after that is 429
      // without the SSO being touched again.
      assert.strictEqual(statuses[0], 502)
      const firstOpen = statuses.indexOf(429)
      assert.isTrue(firstOpen > 0, `expected a 502→429 transition, saw ${statuses.join(",")}`)
      assert.isTrue(
        statuses.slice(firstOpen).every((status) => status === 429),
        `breaker must stay open, saw ${statuses.join(",")}`
      )
    }))

  it.effect("scopes listing to the authenticated tenant only", () =>
    Effect.gen(function*() {
      const { handler } = yield* makeHandler()
      yield* Effect.promise(() =>
        handler(new Request("http://broker/credentials", authed(enrollBody)))
      )

      const listed = yield* Effect.promise(() =>
        handler(
          new Request("http://broker/credentials", { headers: { authorization: `Bearer ${KEY}` } })
        )
      )
      assert.strictEqual(listed.status, 200)
      const views = yield* Effect.promise(() => listed.json())
      assert.strictEqual((views as ReadonlyArray<unknown>).length, 1)
    }))
})
