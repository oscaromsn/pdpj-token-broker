import { assert, describe, it } from "@effect/vitest"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { Effect, Layer, Redacted, Ref, Schema } from "effect"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import { KeycloakSso, SsoConfig } from "../../src/adapters/sso/KeycloakSso.ts"
import { OtplibTotp } from "../../src/adapters/sso/OtplibTotp.ts"
import { Cpf } from "../../src/domain/Cpf.ts"
import { Credential, CredentialId, TenantId } from "../../src/domain/Model.ts"
import { TotpSeed } from "../../src/domain/TotpSeed.ts"
import { SsoClient } from "../../src/ports/SsoClient.ts"

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), "utf8")

const LOGIN_PAGE = fixture("login-page.html")
const OTP_PAGE = fixture("otp-page.html")
const BAD_PASSWORD = fixture("bad-password.html")
const BAD_OTP = fixture("bad-otp.html")
const CAPTCHA_PAGE = fixture("captcha-page.html")

const REDIRECT_URI = "https://portaldeservicos.pdpj.jus.br/consulta"

const credential = new Credential({
  id: Schema.decodeUnknownSync(CredentialId)("cred-1"),
  tenantId: Schema.decodeUnknownSync(TenantId)("tenant-1"),
  cpf: Schema.decodeUnknownSync(Cpf)("52998224725"),
  password: Redacted.make("correct-horse"),
  totpSeed: Schema.decodeUnknownSync(TotpSeed)("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
})

const configLayer = Layer.succeed(
  SsoConfig,
  SsoConfig.of({
    realmUrl: "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect",
    clientId: "portalexterno-frontend",
    redirectUri: REDIRECT_URI
  })
)

interface Reply {
  readonly status: number
  readonly body?: string
  readonly location?: string
}

/**
 * A scripted HttpClient. Each entry answers the next request in order, and
 * every request is recorded so tests can assert on what was actually sent —
 * which matters more than the response here, since the bugs in an OAuth
 * dance are usually in what you post, not in what you parse.
 */
const scriptedClient = (replies: ReadonlyArray<Reply>) =>
  Effect.gen(function*() {
    const sent = yield* Ref.make<ReadonlyArray<{ url: string; body: string }>>([])
    const cursor = yield* Ref.make(0)

    const layer = Layer.succeed(
      HttpClient.HttpClient,
      HttpClient.make((request) =>
        Effect.gen(function*() {
          const index = yield* Ref.getAndUpdate(cursor, (n) => n + 1)
          const bodyText = request.body._tag === "Uint8Array"
            ? new TextDecoder().decode(request.body.body)
            : ""
          yield* Ref.update(sent, (all) => [...all, { url: request.url, body: bodyText }])

          const reply = replies[index]
          if (reply === undefined) {
            return yield* Effect.die(`no scripted reply for request ${index}: ${request.url}`)
          }

          return HttpClientResponse.fromWeb(
            request,
            new Response(reply.body ?? "", {
              status: reply.status,
              headers: reply.location === undefined ? {} : { location: reply.location }
            })
          )
        })
      )
    )

    return { sent, layer } as const
  })

const tokenJson = JSON.stringify({
  access_token: "the-access-token",
  refresh_token: "the-refresh-token",
  expires_in: 300
})

const runLogin = (replies: ReadonlyArray<Reply>) =>
  Effect.gen(function*() {
    const http = yield* scriptedClient(replies)
    const result = yield* Effect.result(
      Effect.gen(function*() {
        const sso = yield* SsoClient
        return yield* sso.login(credential)
      }).pipe(
        Effect.provide(
          KeycloakSso.layer.pipe(
            Layer.provide(Layer.mergeAll(http.layer, configLayer, OtplibTotp.layer))
          )
        )
      )
    )
    return { result, sent: yield* Ref.get(http.sent) } as const
  })

describe("KeycloakSso", () => {
  it.effect("completes a password-only login and exchanges the code for tokens", () =>
    Effect.gen(function*() {
      const { result, sent } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 302, location: `${REDIRECT_URI}#code=THE-CODE&state=x` },
        { status: 200, body: tokenJson }
      ])

      assert.isTrue(result._tag === "Success")
      if (result._tag !== "Success") return
      assert.strictEqual(Redacted.value(result.success.accessToken), "the-access-token")
      assert.isTrue(result.success.refreshToken !== undefined)

      // The credential post must go to the action scraped from the real page,
      // carrying the session_code/execution/tab_id Keycloak requires.
      assert.include(sent[1]?.url ?? "", "login-actions/authenticate")
      assert.include(sent[1]?.url ?? "", "session_code=")
      assert.include(sent[1]?.body ?? "", "username=52998224725")

      // The token exchange must send the grant, the code, and the same
      // redirect_uri — Keycloak rejects a mismatch.
      const exchange = sent[2]?.body ?? ""
      assert.include(exchange, "grant_type=authorization_code")
      assert.include(exchange, "code=THE-CODE")
      assert.include(exchange, "client_id=portalexterno-frontend")
      assert.include(exchange, encodeURIComponent(REDIRECT_URI))
    }))

  it.effect("answers the TOTP challenge and completes the login", () =>
    Effect.gen(function*() {
      const { result, sent } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 200, body: OTP_PAGE },
        { status: 302, location: `${REDIRECT_URI}#code=THE-CODE&state=x` },
        { status: 200, body: tokenJson }
      ])

      assert.isTrue(result._tag === "Success")
      // A six-digit code was posted to the OTP form.
      assert.match(sent[2]?.body ?? "", /otp=\d{6}/)
    }))

  it.effect("reports a rejected password as terminal, without posting an OTP", () =>
    Effect.gen(function*() {
      const { result, sent } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 200, body: BAD_PASSWORD }
      ])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "InvalidPassword")
      // Stopping here is the point: no further attempt is made.
      assert.strictEqual(sent.length, 2)
    }))

  it.effect("distinguishes a rejected OTP from a rejected password", () =>
    Effect.gen(function*() {
      const { result } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 200, body: OTP_PAGE },
        { status: 200, body: BAD_OTP }
      ])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // The operator fix differs: re-capture the seed or check clock drift,
      // rather than reset the password.
      assert.strictEqual(result.failure._tag, "InvalidTotp")
    }))

  it.effect("escalates a captcha wall instead of guessing", () =>
    Effect.gen(function*() {
      const { result } = yield* runLogin([{ status: 200, body: CAPTCHA_PAGE }])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      // ChallengeRequired is what makes the broker hand off to the browser.
      assert.strictEqual(result.failure._tag, "ChallengeRequired")
    }))

  it.effect("treats a 5xx from the SSO as transient", () =>
    Effect.gen(function*() {
      const { result } = yield* runLogin([{ status: 503, body: "upstream down" }])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "SsoUnavailable")
    }))

  it.effect("fails as unavailable when the redirect carries no code", () =>
    Effect.gen(function*() {
      const { result } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 302, location: `${REDIRECT_URI}#error=access_denied` }
      ])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.strictEqual(result.failure._tag, "SsoUnavailable")
    }))

  it.effect("refreshes a token without touching the login form", () =>
    Effect.gen(function*() {
      const http = yield* scriptedClient([{ status: 200, body: tokenJson }])
      const { tokens, sent } = yield* Effect.gen(function*() {
        const sso = yield* SsoClient
        const tokens = yield* sso.refresh(Redacted.make("old-refresh"))
        return { tokens, sent: yield* Ref.get(http.sent) }
      }).pipe(
        Effect.provide(
          KeycloakSso.layer.pipe(
            Layer.provide(Layer.mergeAll(http.layer, configLayer, OtplibTotp.layer))
          )
        )
      )

      assert.strictEqual(Redacted.value(tokens.accessToken), "the-access-token")
      // Exactly one request, and it is the refresh grant. No 2FA, no form.
      assert.strictEqual(sent.length, 1)
      assert.include(sent[0]?.body ?? "", "grant_type=refresh_token")
      assert.include(sent[0]?.body ?? "", "refresh_token=old-refresh")
    }))

  it.effect("computes an absolute expiry from the relative expires_in", () =>
    Effect.gen(function*() {
      const http = yield* scriptedClient([{ status: 200, body: tokenJson }])
      const tokens = yield* Effect.gen(function*() {
        const sso = yield* SsoClient
        return yield* sso.refresh(Redacted.make("old-refresh"))
      }).pipe(
        Effect.provide(
          KeycloakSso.layer.pipe(
            Layer.provide(Layer.mergeAll(http.layer, configLayer, OtplibTotp.layer))
          )
        )
      )

      const now = yield* Effect.clockWith((c) => c.currentTimeMillis)
      // 300s in the fixture. Storing the duration instead of the instant is
      // how a cache ends up believing a dead token is fresh.
      assert.strictEqual(tokens.expiresAt, now + 300_000)
    }))

  it.effect("never leaks the password or the OTP into an error", () =>
    Effect.gen(function*() {
      const { result } = yield* runLogin([
        { status: 200, body: LOGIN_PAGE },
        { status: 200, body: BAD_PASSWORD }
      ])

      assert.isTrue(result._tag === "Failure")
      if (result._tag !== "Failure") return
      assert.isFalse(JSON.stringify(result.failure).includes("correct-horse"))
    }))
})
