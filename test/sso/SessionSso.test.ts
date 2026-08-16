import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Ref, Schema } from "effect"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import { SessionSso, SessionSsoConfig } from "../../src/adapters/sso/SessionSso.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../../src/domain/Model.ts"
import { SessionStore } from "../../src/ports/SessionStore.ts"
import { SsoClient } from "../../src/ports/SsoClient.ts"

/**
 * The session adapter's job is to keep a gov.br session alive by refresh, so
 * the tests centre on the two things that make that safe: a rotated refresh
 * token is persisted before the call returns, and an expired session fails
 * terminally rather than looping.
 */

const REALM = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect"

const tenant = Schema.decodeUnknownSync(TenantId)("tenant-1")
const credId = Schema.decodeUnknownSync(CredentialId)("cred-1")

const credential = new Credential({
  id: credId,
  tenantId: tenant,
  cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
  // A session account has no meaningful password; the adapter never reads it.
  password: Redacted.make("unused")
})

const configLayer = Layer.succeed(
  SessionSsoConfig,
  SessionSsoConfig.of({ realmUrl: REALM, clientId: "portalexterno-frontend" })
)

/** In-memory SessionStore, exposing what it holds so tests can assert rotation. */
const makeStore = (seed?: string) =>
  Effect.gen(function*() {
    const cell = yield* Ref.make(
      seed === undefined ? Option.none<string>() : Option.some(seed)
    )
    const clears = yield* Ref.make(0)
    const layer = Layer.succeed(
      SessionStore,
      SessionStore.of({
        get: () => Ref.get(cell).pipe(Effect.map(Option.map((v) => Redacted.make(v)))),
        put: (_t, _i, rt) => Ref.set(cell, Option.some(Redacted.value(rt))),
        clear: (_t, _i) => Ref.update(clears, (n) => n + 1).pipe(Effect.andThen(Ref.set(cell, Option.none())))
      })
    )
    return { cell, clears, layer } as const
  })

/** A token endpoint scripted per attempt, recording the refresh tokens it received. */
const makeSso = (replies: ReadonlyArray<{ status: number; body: string }>) =>
  Effect.gen(function*() {
    const seen = yield* Ref.make<ReadonlyArray<string>>([])
    const cursor = yield* Ref.make(0)
    const layer = Layer.succeed(
      HttpClient.HttpClient,
      HttpClient.make((request) =>
        Effect.gen(function*() {
          const i = yield* Ref.getAndUpdate(cursor, (n) => n + 1)
          const body = request.body._tag === "Uint8Array"
            ? new TextDecoder().decode(request.body.body)
            : ""
          const match = /refresh_token=([^&]+)/.exec(body)
          if (match?.[1] !== undefined) {
            yield* Ref.update(seen, (all) => [...all, decodeURIComponent(match[1]!)])
          }
          const reply = replies[i] ?? { status: 500, body: "no scripted reply" }
          return HttpClientResponse.fromWeb(
            request,
            new Response(reply.body, { status: reply.status })
          )
        })
      )
    )
    return { seen, layer } as const
  })

const tokenJson = (access: string, refresh: string, expiresIn = 300) =>
  JSON.stringify({ access_token: access, refresh_token: refresh, expires_in: expiresIn })

describe("SessionSso", () => {
  it.effect("mints an access token from the stored gov.br refresh token", () =>
    Effect.gen(function*() {
      const store = yield* makeStore("seed-refresh")
      const sso = yield* makeSso([{ status: 200, body: tokenJson("access-1", "rotated-1") }])

      const { token, sent } = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        const token = yield* client.login(credential)
        return { token, sent: yield* Ref.get(sso.seen) }
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      assert.strictEqual(Redacted.value(token.accessToken), "access-1")
      // It presented the seeded refresh token to the SSO.
      assert.deepStrictEqual(sent, ["seed-refresh"])
    }))

  it.effect("persists the rotated refresh token before returning", () =>
    Effect.gen(function*() {
      const store = yield* makeStore("seed-refresh")
      const sso = yield* makeSso([{ status: 200, body: tokenJson("access-1", "rotated-1") }])

      const stored = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        yield* client.login(credential)
        return yield* Ref.get(store.cell)
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      // The old token is now dead at the SSO; the store must hold the new one,
      // or the next cold start authenticates with a retired token.
      assert.isTrue(Option.isSome(stored))
      if (Option.isSome(stored)) assert.strictEqual(stored.value, "rotated-1")
    }))

  it.effect("uses the rotated token on the next login, not the original", () =>
    Effect.gen(function*() {
      const store = yield* makeStore("seed-refresh")
      const sso = yield* makeSso([
        { status: 200, body: tokenJson("access-1", "rotated-1") },
        { status: 200, body: tokenJson("access-2", "rotated-2") }
      ])

      const sent = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        yield* client.login(credential)
        yield* client.login(credential)
        return yield* Ref.get(sso.seen)
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      // Second call must present the token the first call stored.
      assert.deepStrictEqual(sent, ["seed-refresh", "rotated-1"])
    }))

  it.effect("fails terminally when no session is on file", () =>
    Effect.gen(function*() {
      const store = yield* makeStore() // empty
      const sso = yield* makeSso([])

      const result = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        return yield* Effect.result(client.login(credential))
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // Terminal, so the broker marks the credential and does not retry.
      assert.strictEqual(result.failure._tag, "InvalidPassword")
    }))

  it.effect("treats an expired session as terminal and clears it", () =>
    Effect.gen(function*() {
      const store = yield* makeStore("dead-refresh")
      // Keycloak returns 400 for an invalid_grant (expired/rotated-away token).
      const sso = yield* makeSso([{ status: 400, body: "{\"error\":\"invalid_grant\"}" }])

      const { result, cleared, remaining } = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        const result = yield* Effect.result(client.login(credential))
        return {
          result,
          cleared: yield* Ref.get(store.clears),
          remaining: yield* Ref.get(store.cell)
        }
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") assert.strictEqual(result.failure._tag, "InvalidPassword")
      // The dead session is cleared, so the stored state stops claiming a
      // usable session exists.
      assert.strictEqual(cleared, 1)
      assert.isTrue(Option.isNone(remaining))
    }))

  it.effect("refreshes directly without touching the session store", () =>
    Effect.gen(function*() {
      const store = yield* makeStore("seed-refresh")
      const sso = yield* makeSso([{ status: 200, body: tokenJson("access-r", "rotated-r") }])

      const token = yield* Effect.gen(function*() {
        const client = yield* SsoClient
        return yield* client.refresh(Redacted.make("some-refresh"))
      }).pipe(
        Effect.provide(SessionSso.layer.pipe(Layer.provide(Layer.mergeAll(sso.layer, store.layer, configLayer))))
      )

      assert.strictEqual(Redacted.value(token.accessToken), "access-r")
      // Direct refresh is the broker's cache-warm path; the seeded session is
      // untouched.
      const stored = yield* Ref.get(store.cell)
      assert.isTrue(Option.isSome(stored) && stored.value === "seed-refresh")
    }))
})
